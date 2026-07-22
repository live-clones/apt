// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* pkcs7.cc - X.509 trust store and detached CMS signature verifier.
 *
 * Implementation of X509Store (pImpl via std::unique_ptr<Impl>).
 * All OpenSSL state is held inside X509Store::Impl (defined below);
 * the header exposes only a single std::unique_ptr<Impl> member,
 * keeping the ABI stable.
 */
									/*}}}*/
// Include Files						/*{{{*/
#include <config.h>

#include <apt-pkg/pkcs7.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/strutl.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstdio>

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
struct X509StackDeleter { void operator()(STACK_OF(X509) *p) const { sk_X509_pop_free(p, X509_free); } };
using X509UP = std::unique_ptr<X509, X509Deleter>;
using X509StoreUP = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using CMSUP = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using BIOUP = std::unique_ptr<BIO, BIODeleter>;
using X509StackUP = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;

// Internal helpers (not exported).						/*{{{*/
static std::string FormatOpenSSLErrorQueue()
{
   std::string errstr;
   unsigned long e;
   while ((e = ERR_get_error()) != 0)
   {
      if (not errstr.empty())
	 errstr += "; ";
      // ERR_reason_error_string returns nullptr for unknown reason codes.
      if (char const * const reason = ERR_reason_error_string(e))
	 errstr += reason;
      else
      {
	 char buf[40];
	 snprintf(buf, sizeof(buf), "unknown error 0x%lx", e);
	 errstr += buf;
      }
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

enum class DigestTrust { Trusted, Weak, Untrusted };

// Classify a CMS signer digest algorithm per APT hash policy, mirroring
// the gpgv method's APT::Hashes::<name>::{Untrusted,Weak} knobs.
// Checked order: Untrusted option, Weak option, built-in default.
static DigestTrust ClassifyDigest(X509_ALGOR const *alg, std::string &name)
{
   static constexpr int untrustedNids[] = {
      NID_md2, NID_md4, NID_md5, NID_sha1, NID_ripemd160,
   };
   int nid = NID_undef;
   if (alg != nullptr && alg->algorithm != nullptr)
      nid = OBJ_obj2nid(alg->algorithm);
   char const *sn = (nid == NID_undef) ? nullptr : OBJ_nid2sn(nid);
   name = (sn != nullptr) ? sn : "unknown";

   std::string opt;
   strprintf(opt, "APT::Hashes::%s::Untrusted", name.c_str());
   if (_config != nullptr && _config->FindB(opt, false))
      return DigestTrust::Untrusted;
   strprintf(opt, "APT::Hashes::%s::Weak", name.c_str());
   if (_config != nullptr && _config->FindB(opt, false))
      return DigestTrust::Weak;

   if (nid == NID_undef)
      return DigestTrust::Untrusted;
   for (int const u : untrustedNids)
      if (nid == u)
	 return DigestTrust::Untrusted;
   return DigestTrust::Trusted;
}
									/*}}}*/

// X509Store::Impl (pImpl - defined here, forward-declared in header)	/*{{{*/
class X509Store::Impl
{
public:
   X509StoreUP store;                           // X509_STORE (trust anchor container)
   std::vector<X509UP> certs;                   // loaded bundle certs (owned)
   CMSUP cms;                                   // parsed CMS structure (owned)
   X509 *pendingSigner = nullptr;               // non-owning; set during VerifyDetach

   bool LoadCertPath(std::string const &path);
   bool ParseAndCMSVerify(FileFd &signature, FileFd &data);
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
      // Chain validation is intentionally purpose-agnostic: APT's
      // repo-signing EKU is not a standard X509_PURPOSE, so OpenSSL's
      // purpose mechanism (keyUsage/EKU/SAN checks) is skipped and any
      // signing-purpose constraints are enforced per-signer by the
      // policy layer (VerifyCert() hook) instead.  Setting the purpose
      // to X509_PURPOSE_ANY makes this explicit; it is equivalent to
      // leaving the purpose unset, as chain building is independent of
      // the purpose (purpose checks only run for purpose >=
      // X509_PURPOSE_MIN, and X509_PURPOSE_ANY is a no-op check).
      X509_VERIFY_PARAM *const param = X509_STORE_get0_param(store.get());
      X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY);
   }

   std::string err;
   bool loaded = false;
   for (;;)
   {
      // Scope the error-queue entries of each read: only the benign
      // end-of-bundle error (PEM_R_NO_START_LINE) may be discarded; any
      // other parse error is real and must abort the load instead of
      // silently accepting a partial bundle.
      ERR_set_mark();
      X509UP cert(PEM_read_X509(fp, nullptr, nullptr, nullptr));
      if (cert == nullptr)
      {
	 if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE)
	 {
	    ERR_pop_to_mark();
	    break;
	 }
	 err = FormatOpenSSLErrorQueue();
	 fclose(fp);
	 goto fail;
      }
      ERR_pop_to_mark();
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

   if (not loaded)
      return _error->Error("LoadCert: no certificates found in bundle");
   return true;

fail:
   return _error->Error("LoadCert: failed to parse certificate: %s", err.c_str());
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

   // Trusted-digest floor (gpgv parity): reject signers using untrusted
   // digest algorithms.  OpenSSL security level 1 still accepts SHA-1
   // and the gpgv path explicitly rejects it by default.
   // CMS_get0_SignerInfos returns an internal pointer — no free.
   STACK_OF(CMS_SignerInfo) *const sinfos = CMS_get0_SignerInfos(cms.get());
   if (sinfos == nullptr)
      return _error->Error("VerifyDetach: CMS_get0_SignerInfos returned null");
   for (int i = 0; i < sk_CMS_SignerInfo_num(sinfos); ++i)
   {
      CMS_SignerInfo *const si = sk_CMS_SignerInfo_value(sinfos, i);
      if (si == nullptr)
	 continue;
      X509_ALGOR *digestAlg = nullptr;
      CMS_SignerInfo_get0_algs(si, nullptr, nullptr, &digestAlg, nullptr);
      std::string digestName;
      switch (ClassifyDigest(digestAlg, digestName))
      {
      case DigestTrust::Untrusted:
	 return _error->Error("VerifyDetach: signer %d uses untrusted digest algorithm: %s",
			      i, digestName.c_str());
      case DigestTrust::Weak:
	 _error->Warning("VerifyDetach: signer %d uses weak digest algorithm: %s",
			 i, digestName.c_str());
	 break;
      case DigestTrust::Trusted:
	 break;
      }
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

bool X509Store::VerifyDetach(FileFd &signature, FileFd &data,
			     VerificationResult &result)
{
   result.success = false;

   // 1. Parse CMS and run CMS_verify (raw cryptographic check).
   if (not d->ParseAndCMSVerify(signature, data))
      return false;

   // 2. Virtual hook: signature-level / trust-anchor constraints.
   //    Base: no-op.
   if (not VerifySignature())
      return false;

   // 3. Walk signers, applying per-signer cert policy via VerifyCert().
   //    CMS_get0_signers returns a new stack of up-ref'd certs; must be
   //    freed with sk_X509_pop_free(..., X509_free).
   X509StackUP signersUP(CMS_get0_signers(d->cms.get()));
   STACK_OF(X509) *const signers = signersUP.get();
   if (signers == nullptr)
      return _error->Error("VerifyDetach: CMS_get0_signers returned null");

   bool accepted = false;
   int const n = sk_X509_num(signers);
   for (int i = 0; i < n; ++i)
   {
      X509 *const cert = sk_X509_value(signers, i);
      if (cert == nullptr)
	 continue;
      // Baseline signing-capability check (gpgv parity: gpg only accepts
      // signatures from keys whose flags include "sign").  An absent
      // KeyUsage extension means unrestricted use (RFC 5280), reported by
      // X509_get_key_usage as UINT32_MAX; only reject when the extension
      // is present and lacks digitalSignature.
      uint32_t const ku = X509_get_key_usage(cert);
      if (ku != UINT32_MAX && (ku & KU_DIGITAL_SIGNATURE) == 0)
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

} // namespace Internal
} // namespace APT
