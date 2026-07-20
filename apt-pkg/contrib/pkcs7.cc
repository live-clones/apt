// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7.cc - X.509 trust store and detached CMS signature verifier.
 *
 * Implementation of X509Store (pImpl via std::unique_ptr<Impl>) and
 * Constrained (private X509Store subclass with caller-supplied
 * CertificateConstraints).  All OpenSSL state is held inside
 * X509Store::Impl (defined below); the header exposes only a single
 * std::unique_ptr<Impl> member, keeping the ABI stable.
 */
									/*}}}*/
// Include Files						/*{{{*/
#include <config.h>

#include <apt-pkg/pkcs7.h>
#include <apt-pkg/pkcs7-constraints.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace APT
{
namespace Internal
{

// OpenSSL deleter types for unique_ptr (local to this TU).
struct X509Deleter { void operator()(X509 *p) const { X509_free(p); } };
struct X509StoreDeleter { void operator()(X509_STORE *p) const { X509_STORE_free(p); } };
struct CMSDeleter { void operator()(CMS_ContentInfo *p) const { CMS_ContentInfo_free(p); } };
struct BIODeleter { void operator()(BIO *p) const { BIO_free(p); } };
using X509UP = std::unique_ptr<X509, X509Deleter>;
using X509StoreUP = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using CMSUP = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using BIOUP = std::unique_ptr<BIO, BIODeleter>;

// Internal helpers (not exported).						/*{{{*/
static std::string FormatOpenSSLErrorQueue()
{
   std::string errstr;
   unsigned long e;
   while ((e = ERR_get_error()) != 0)
   {
      if (not errstr.empty())
	 errstr += "; ";
      errstr += ERR_reason_error_string(e);
   }
   return errstr;
}

static std::string HexDigest(unsigned char const *data, std::size_t len)
{
   static char const hex[] = "0123456789abcdef";
   std::string out;
   out.reserve(len * 2);
   for (std::size_t i = 0; i < len; ++i)
   {
      out += hex[(data[i] >> 4) & 0xf];
      out += hex[data[i] & 0xf];
   }
   return out;
}

static std::string CertFingerprint(X509 *cert)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;
   if (X509_digest(cert, EVP_sha256(), md, &len) != 1)
      return "";
   return HexDigest(md, len);
}
									/*}}}*/

// X509Store::Impl (pImpl — defined here, forward-declared in header)	/*{{{*/
class X509Store::Impl
{
public:
   X509StoreUP store;                           // X509_STORE (trust anchor container)
   std::vector<X509UP> certs;                   // loaded bundle certs (owned)
   CMSUP cms;                                   // parsed CMS structure (owned)
   X509 *pendingSigner = nullptr;               // non-owning; set during VerifyDetach

   bool LoadCertPath(std::string const &path);
   bool ParseAndCMSVerify(FileFd &signature, FileFd &data);
   bool ApplyToAllCerts(CertificateConstraints &policy);
};

bool X509Store::Impl::LoadCertPath(std::string const &path)
{
   FILE *fp = fopen(path.c_str(), "r");
   if (fp == nullptr)
      return _error->Error("LoadCert: cannot open %s", path.c_str());

   // Create the store on first load.
   if (store == nullptr)
   {
      store.reset(X509_STORE_new());
      if (store == nullptr)
      {
	 fclose(fp);
	 return _error->Error("LoadCert: X509_STORE_new failed: %s",
			      FormatOpenSSLErrorQueue().c_str());
      }
      X509_VERIFY_PARAM *const param = X509_STORE_get0_param(store.get());
      X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY);
   }

   std::string err;
   bool loaded = false;
   for (;;)
   {
      X509UP cert(PEM_read_X509(fp, nullptr, nullptr, nullptr));
      if (cert == nullptr)
	 break;
      loaded = true;
      if (X509_STORE_add_cert(store.get(), cert.get()) != 1)
      {
	 err = FormatOpenSSLErrorQueue();
	 fclose(fp);
	 goto fail;
      }
      certs.push_back(std::move(cert));
   }
   fclose(fp);
   ERR_clear_error();

   if (not loaded)
      return _error->Error("LoadCert: no certificates found in bundle");
   return true;

fail:
   return _error->Error("LoadCert: failed to parse certificate: %s", err.c_str());
}

bool X509Store::Impl::ApplyToAllCerts(CertificateConstraints &policy)
{
   for (auto const &cert : certs)
   {
      if (not policy.Apply(cert.get()))
	 return false;
   }
   return true;
}

bool X509Store::Impl::ParseAndCMSVerify(FileFd &signature, FileFd &data)
{
   if (store == nullptr)
      return _error->Error("VerifyDetach: no trust store loaded");

   // Read the signature file via BIO_new_file.
   BIOUP sigBio(BIO_new_file(signature.Name().c_str(), "r"));
   if (sigBio == nullptr)
      return _error->Error("VerifyDetach: BIO_new_file for signature failed: %s",
			   FormatOpenSSLErrorQueue().c_str());

   cms.reset(PEM_read_bio_CMS(sigBio.get(), nullptr, nullptr, nullptr));
   if (cms == nullptr)
      return _error->Error("VerifyDetach: PEM_read_bio_CMS failed: %s",
			   FormatOpenSSLErrorQueue().c_str());

   // Read the data file via BIO_new_file for CMS_verify.
   BIOUP dataBio(BIO_new_file(data.Name().c_str(), "r"));
   if (dataBio == nullptr)
      return _error->Error("VerifyDetach: BIO_new_file for data failed: %s",
			   FormatOpenSSLErrorQueue().c_str());

   // CMS_verify (the cryptographic signature verification step).
   int const rc = CMS_verify(cms.get(), nullptr, store.get(), dataBio.get(), nullptr,
			     CMS_DETACHED | CMS_BINARY);
   if (rc != 1)
   {
      std::string const err = FormatOpenSSLErrorQueue();
      return _error->Error("VerifyDetach: CMS signature verification failed: %s", err.c_str());
   }

   return true;
}
									/*}}}*/
// X509Store public API							/*{{{*/

X509Store::X509Store() : d(std::make_unique<Impl>()) {}
X509Store::~X509Store() = default; // Impl is complete in this TU

bool X509Store::LoadCert(FileFd &fd)
{
   return d->LoadCertPath(fd.Name());
}

bool X509Store::LoadCert(std::string const &path)
{
   return d->LoadCertPath(path);
}

X509 *X509Store::PendingSigner()
{
   return d->pendingSigner;
}

bool X509Store::ApplyToAllCerts(CertificateConstraints &policy)
{
   return d->ApplyToAllCerts(policy);
}

bool X509Store::VerifyDetach(FileFd &signature, FileFd &data,
			     VerificationResult &result)
{
   result.success = false;

   // 1. Parse CMS and run CMS_verify (raw cryptographic check).
   if (not d->ParseAndCMSVerify(signature, data))
      return false;

   // 2. Virtual hook: signature-level / trust-anchor constraints.
   //    Base: no-op.  Constrained: validate all bundle certs.
   if (not VerifySignature())
      return false;

   // 3. Walk signers, applying per-signer cert policy via VerifyCert().
   STACK_OF(X509) *const signers = CMS_get0_signers(d->cms.get());
   if (signers == nullptr)
      return _error->Error("VerifyDetach: CMS_get0_signers returned null");

   bool accepted = false;
   int const n = sk_X509_num(signers);
   for (int i = 0; i < n; ++i)
   {
      X509 *const cert = sk_X509_value(signers, i);
      if (cert == nullptr)
	 continue;
      d->pendingSigner = cert;
      if (VerifyCert())
      {
	 accepted = true;
	 char subjectbuf[256];
	 X509_NAME_oneline(X509_get_subject_name(cert), subjectbuf, sizeof(subjectbuf));
	 result.signerSubject = subjectbuf;
	 result.signerFingerprint = CertFingerprint(cert);
	 break;
      }
   }
   d->pendingSigner = nullptr;

   if (not accepted)
      return _error->Error("VerifyDetach: no signer passed the certificate policy");

   result.success = true;
   return true;
}
									/*}}}*/

// Constrained								/*{{{*/

Constrained::Constrained(CertificateConstraints signer, CertificateConstraints anchor)
   : X509Store(), signerPolicy(std::move(signer)), anchorPolicy(std::move(anchor)) {}

Constrained::~Constrained() = default; // base dtor needs Impl complete

bool Constrained::VerifyCert()
{
   return signerPolicy.Apply(PendingSigner());
}

bool Constrained::VerifySignature()
{
   return ApplyToAllCerts(anchorPolicy);
}
									/*}}}*/

} // namespace Internal
} // namespace APT
