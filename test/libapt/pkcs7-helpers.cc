#include <config.h>

#include "pkcs7-helpers.h"

#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/pkcs7.h>

#include <cstring>
#include <string>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace APT::Test::PKI
{
// Internal helpers							/*{{{*/
static bool AddExtension(X509 *x, int nid, int crit, void *value)
{
   X509_EXTENSION *ext = X509V3_EXT_i2d(nid, crit, value);
   if (ext == nullptr)
      return false;
   bool ok = X509_add_ext(x, ext, -1) == 1;
   X509_EXTENSION_free(ext);
   return ok;
}

static bool AddSKI(X509 *x)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;
   if (X509_pubkey_digest(x, EVP_sha1(), md, &len) != 1)
      return false;
   ASN1_OCTET_STRING *ski = ASN1_OCTET_STRING_new();
   if (ski == nullptr || ASN1_OCTET_STRING_set(ski, md, static_cast<int>(len)) != 1)
   {
      ASN1_OCTET_STRING_free(ski);
      return false;
   }
   bool ok = AddExtension(x, NID_subject_key_identifier, 0, ski);
   ASN1_OCTET_STRING_free(ski);
   return ok;
}

static bool AddAKI(X509 *x, X509 *issuer)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;
   if (X509_pubkey_digest(issuer, EVP_sha1(), md, &len) != 1)
      return false;
   ASN1_OCTET_STRING *keyid = ASN1_OCTET_STRING_new();
   if (keyid == nullptr || ASN1_OCTET_STRING_set(keyid, md, static_cast<int>(len)) != 1)
   {
      ASN1_OCTET_STRING_free(keyid);
      return false;
   }
   AUTHORITY_KEYID *aki = AUTHORITY_KEYID_new();
   if (aki == nullptr)
   {
      ASN1_OCTET_STRING_free(keyid);
      return false;
   }
   aki->keyid = keyid;
   bool ok = AddExtension(x, NID_authority_key_identifier, 0, aki);
   AUTHORITY_KEYID_free(aki);
   return ok;
}

static void SetSubject(X509 *x, char const *cn)
{
   X509_NAME *name = X509_get_subject_name(x);
   X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                              reinterpret_cast<unsigned char const *>(cn),
                              -1, -1, 0);
}

static void SetKeyUsageBits(ASN1_BIT_STRING *ku, int mask)
{
   for (int i = 0; i < 8; ++i)
      if (mask & (1 << i))
	 ASN1_BIT_STRING_set_bit(ku, 7 - i, 1);
}
									/*}}}*/

EVP_PKEY *MakeKey()
{
   return EVP_RSA_gen(2048);
}

X509 *MakeCACert(EVP_PKEY *key, char const *cn)
{
   X509 *x = X509_new();
   if (x == nullptr)
      return nullptr;
   X509_set_version(x, X509_VERSION_3);
   ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
   X509_gmtime_adj(X509_get_notBefore(x), -60);
   X509_gmtime_adj(X509_get_notAfter(x), 86400L);
   X509_set_pubkey(x, key);
   SetSubject(x, cn);
   X509_set_issuer_name(x, X509_get_subject_name(x));

   BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
   bc->ca = 1;
   if (AddExtension(x, NID_basic_constraints, 1, bc) == false)
   {
      BASIC_CONSTRAINTS_free(bc);
      X509_free(x);
      return nullptr;
   }
   BASIC_CONSTRAINTS_free(bc);

   ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
   if (ku == nullptr)
   {
      X509_free(x);
      return nullptr;
   }
   SetKeyUsageBits(ku, KU_KEY_CERT_SIGN | KU_CRL_SIGN);
   if (AddExtension(x, NID_key_usage, 1, ku) == false)
   {
      ASN1_BIT_STRING_free(ku);
      X509_free(x);
      return nullptr;
   }
   ASN1_BIT_STRING_free(ku);

   if (AddSKI(x) == false)
   {
      X509_free(x);
      return nullptr;
   }

   X509_sign(x, key, EVP_sha256());
   return x;
}

X509 *MakeLeafCert(EVP_PKEY *key, EVP_PKEY *caKey, X509 *caCert,
		   char const *cn, char const *suite)
{
   X509 *x = X509_new();
   if (x == nullptr)
      return nullptr;
   X509_set_version(x, X509_VERSION_3);
   ASN1_INTEGER_set(X509_get_serialNumber(x), 2);
   X509_gmtime_adj(X509_get_notBefore(x), -60);
   X509_gmtime_adj(X509_get_notAfter(x), 86400L);
   X509_set_pubkey(x, key);
   SetSubject(x, cn);
   X509_set_issuer_name(x, X509_get_subject_name(caCert));

   BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
   bc->ca = 0;
   if (AddExtension(x, NID_basic_constraints, 1, bc) == false)
   {
      BASIC_CONSTRAINTS_free(bc);
      X509_free(x);
      return nullptr;
   }
   BASIC_CONSTRAINTS_free(bc);

   ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
   if (ku == nullptr)
   {
      X509_free(x);
      return nullptr;
   }
   SetKeyUsageBits(ku, KU_DIGITAL_SIGNATURE);
   if (AddExtension(x, NID_key_usage, 1, ku) == false)
   {
      ASN1_BIT_STRING_free(ku);
      X509_free(x);
      return nullptr;
   }
   ASN1_BIT_STRING_free(ku);

   GENERAL_NAMES *sans = sk_GENERAL_NAME_new_null();
   ASN1_IA5STRING *sanValue = ASN1_IA5STRING_new();
   if (sans == nullptr || sanValue == nullptr ||
       ASN1_STRING_set(sanValue, suite, -1) != 1)
   {
      ASN1_IA5STRING_free(sanValue);
      sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
      X509_free(x);
      return nullptr;
   }
   GENERAL_NAME *gn = GENERAL_NAME_new();
   if (gn == nullptr)
   {
      ASN1_IA5STRING_free(sanValue);
      sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
      X509_free(x);
      return nullptr;
   }
   gn->type = GEN_DNS;
   gn->d.dNSName = sanValue;
   if (sk_GENERAL_NAME_push(sans, gn) != 1)
   {
      GENERAL_NAME_free(gn);
      sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
      X509_free(x);
      return nullptr;
   }
   bool ok = AddExtension(x, NID_subject_alt_name, 0, sans);
   sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
   if (ok == false)
   {
      X509_free(x);
      return nullptr;
   }

   if (AddSKI(x) == false || AddAKI(x, caCert) == false)
   {
      X509_free(x);
      return nullptr;
   }

   X509_sign(x, caKey, EVP_sha256());
   return x;
}

X509 *MakeSelfSignedLeaf(EVP_PKEY *key, char const *cn)
{
   X509 *x = X509_new();
   if (x == nullptr)
      return nullptr;
   X509_set_version(x, X509_VERSION_3);
   ASN1_INTEGER_set(X509_get_serialNumber(x), 3);
   X509_gmtime_adj(X509_get_notBefore(x), -60);
   X509_gmtime_adj(X509_get_notAfter(x), 86400L);
   X509_set_pubkey(x, key);
   SetSubject(x, cn);
   X509_set_issuer_name(x, X509_get_subject_name(x));
   X509_sign(x, key, EVP_sha256());
   return x;
}

CMS_ContentInfo *SignData(std::string const &data, X509 *signcert,
			  EVP_PKEY *signkey, X509 *includeCA)
{
   STACK_OF(X509) *certs = sk_X509_new_null();
   if (certs == nullptr)
      return nullptr;
   sk_X509_push(certs, signcert);
   if (includeCA != nullptr)
      sk_X509_push(certs, includeCA);
   BIO *bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
   CMS_ContentInfo *cms = CMS_sign(signcert, signkey, certs, bio,
				   CMS_DETACHED | CMS_BINARY);
   sk_X509_free(certs);
   BIO_free(bio);
   return cms;
}

ScopedFileDeleter WriteCertPEM(X509 *x)
{
   auto out = createTemporaryFile("pki_cert");
   BIO *bio = BIO_new_file(out.Name().c_str(), "w");
   if (bio != nullptr)
   {
      PEM_write_bio_X509(bio, x);
      BIO_free(bio);
   }
   return out;
}

ScopedFileDeleter WriteCMSPEM(CMS_ContentInfo *cms)
{
   auto out = createTemporaryFile("pki_cms");
   BIO *bio = BIO_new_file(out.Name().c_str(), "w");
   if (bio != nullptr)
   {
      PEM_write_bio_CMS(bio, cms);
      BIO_free(bio);
   }
   return out;
}

ScopedFileDeleter WriteDataFile(std::string const &data)
{
   auto out = createTemporaryFile("pki_data");
   BIO *bio = BIO_new_file(out.Name().c_str(), "w");
   if (bio != nullptr)
   {
      BIO_write(bio, data.data(), static_cast<int>(data.size()));
      BIO_free(bio);
   }
   return out;
}

bool VerifyCMSFiles(std::string const &cmsPath, std::string const &dataPath,
		    std::string const &caPath)
{
   APT::Internal::X509Store store;
   if (not store.LoadCert(caPath))
   {
      _error->Discard();
      return false;
   }

   FileFd sigFd, dataFd;
   if (not sigFd.Open(cmsPath, FileFd::ReadOnly))
      return false;
   if (not dataFd.Open(dataPath, FileFd::ReadOnly))
      return false;

   APT::Internal::VerificationResult result;
   bool const ok = store.VerifyDetach(sigFd, dataFd, result);
   _error->Discard();
   return ok;
}

int VerifyCMS(CMS_ContentInfo *cms, std::string const &data,
	      std::string const &caPath)
{
   auto cmsTmp = WriteCMSPEM(cms);
   auto dataTmp = WriteDataFile(data);

   APT::Internal::X509Store store;
   if (not store.LoadCert(caPath))
   {
      _error->Discard();
      return -1;
   }

   FileFd sigFd, dataFd;
   if (not sigFd.Open(cmsTmp.Name(), FileFd::ReadOnly))
      return -1;
   if (not dataFd.Open(dataTmp.Name(), FileFd::ReadOnly))
      return -1;

   APT::Internal::VerificationResult result;
   if (not store.VerifyDetach(sigFd, dataFd, result))
   {
      _error->Discard();
      return 0;
   }

   _error->Discard();
   return result.success ? 1 : 0;
}

} // namespace APT::Test::PKI
