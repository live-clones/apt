#include <config.h>

#include "pkcs7-helpers.h"

#include <atomic>
#include <cstddef>
#include <string>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

namespace APT::Test::PKI
{
// Internal helpers
static bool AddExtension(X509 *x, int nid, int crit, void *value)
{
   X509_EXTENSION *ext = X509V3_EXT_i2d(nid, crit, value);
   if (ext == nullptr)
      return false;
   bool const ok = X509_add_ext(x, ext, -1) == 1;
   X509_EXTENSION_free(ext);
   return ok;
}

static bool AddBasicConstraints(X509 *x, bool ca)
{
   BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
   if (bc == nullptr)
      return false;
   bc->ca = ca ? 1 : 0;
   bool const ok = AddExtension(x, NID_basic_constraints, 1, bc);
   BASIC_CONSTRAINTS_free(bc);
   return ok;
}

static bool AddKeyUsage(X509 *x, int mask)
{
   ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
   if (ku == nullptr)
      return false;
   // KU_* are the DER bit values; ASN1_BIT_STRING_set_bit counts from the most
   // significant bit of the first octet, hence the 7 - i.
   for (int i = 0; i < 8; ++i)
      if (mask & (1 << i))
	 ASN1_BIT_STRING_set_bit(ku, 7 - i, 1);
   bool const ok = AddExtension(x, NID_key_usage, 1, ku);
   ASN1_BIT_STRING_free(ku);
   return ok;
}

static bool AddKeyID(X509 *x, int nid, X509 *source)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;

   // X.509 SKI/AKI traditionally uses the SHA-1 digest of the public key.
   // This is an identifier, not a security-sensitive signature digest.
   if (X509_pubkey_digest(source, EVP_sha1(), md, &len) != 1)
      return false;

   ASN1_OCTET_STRING *keyid = ASN1_OCTET_STRING_new();
   if (keyid == nullptr ||
       ASN1_OCTET_STRING_set(keyid, md, static_cast<int>(len)) != 1)
   {
      ASN1_OCTET_STRING_free(keyid);
      return false;
   }

   bool ok = false;
   if (nid == NID_subject_key_identifier)
   {
      ok = AddExtension(x, nid, 0, keyid);
      ASN1_OCTET_STRING_free(keyid);
      return ok;
   }

   AUTHORITY_KEYID *aki = AUTHORITY_KEYID_new();
   if (aki == nullptr)
   {
      ASN1_OCTET_STRING_free(keyid);
      return false;
   }
   aki->keyid = keyid; // ownership moves into aki
   ok = AddExtension(x, nid, 0, aki);
   AUTHORITY_KEYID_free(aki);
   return ok;
}

static bool AddEKU(X509 *x, char const *oid)
{
   EXTENDED_KEY_USAGE *eku = sk_ASN1_OBJECT_new_null();
   ASN1_OBJECT *obj = OBJ_txt2obj(oid, 0);
   if (eku == nullptr || obj == nullptr || sk_ASN1_OBJECT_push(eku, obj) != 1)
   {
      ASN1_OBJECT_free(obj);
      EXTENDED_KEY_USAGE_free(eku);
      return false;
   }
   bool const ok = AddExtension(x, NID_ext_key_usage, 0, eku);
   EXTENDED_KEY_USAGE_free(eku); // frees the pushed object too
   return ok;
}

// X509_get_subject_name returns a const pointer, so build a fresh name and
// install it rather than mutating the certificate's own.
static bool SetCommonName(X509 *x, char const *cn)
{
   X509_NAME *name = X509_NAME_new();
   if (name == nullptr)
      return false;
   bool ok = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					reinterpret_cast<unsigned char const *>(cn),
					-1, -1, 0) == 1;
   if (ok)
      ok = X509_set_subject_name(x, name) == 1;
   X509_NAME_free(name);
   return ok;
}

// Every certificate needs its own serial: CMS identifies a signer by issuer
// name and serial number by default, and that is also what
// CMS_SignerInfo_cert_cmp() compares, so reusing a serial within one issuer
// would make the SignerInfo/certificate pairing ambiguous.
//
// Uses atomic for thread-safety.
static long NextSerial()
{
   static std::atomic<long> serial{0};
   return ++serial;
}

static std::string BIOToString(BIO *bio)
{
   char *data = nullptr;
   long const len = BIO_get_mem_data(bio, &data);
   if (len <= 0 || data == nullptr)
      return "";
   return std::string(data, static_cast<size_t>(len));
}

EVP_PKEY *MakeKey()
{
   return EVP_EC_gen("P-256");
}

X509 *MakeCACert(EVP_PKEY *key, char const *cn)
{
   X509 *x = X509_new();
   if (x == nullptr)
      return nullptr;

   // These shouldn't fail really, but the test helper must be
   // robust enough to surface these errors.
   if (X509_set_version(x, X509_VERSION_3) != 1 ||
       ASN1_INTEGER_set(X509_get_serialNumber(x), NextSerial()) != 1 ||
       X509_set_pubkey(x, key) != 1 ||
       X509_gmtime_adj(X509_getm_notBefore(x), -60) == nullptr ||
       X509_gmtime_adj(X509_getm_notAfter(x), 86400L) == nullptr)
   {
      X509_free(x);
      return nullptr;
   }

   if (not SetCommonName(x, cn) ||
       X509_set_issuer_name(x, X509_get_subject_name(x)) != 1)
   {
      X509_free(x);
      return nullptr;
   }

   if (not AddBasicConstraints(x, true) ||
       not AddKeyUsage(x, KU_KEY_CERT_SIGN | KU_CRL_SIGN) ||
       not AddKeyID(x, NID_subject_key_identifier, x) ||
       X509_sign(x, key, EVP_sha256()) == 0)
   {
      X509_free(x);
      return nullptr;
   }
   return x;
}

X509 *MakeLeafCert(EVP_PKEY *key, EVP_PKEY *caKey, X509 *caCert,
		   char const *cn, char const *eku,
		   long notBeforeOffset, long notAfterOffset, int kuMask)
{
   X509 *x = X509_new();
   if (x == nullptr)
      return nullptr;

   if (X509_set_version(x, X509_VERSION_3) != 1 ||
       ASN1_INTEGER_set(X509_get_serialNumber(x), NextSerial()) != 1 ||
       X509_set_pubkey(x, key) != 1 ||
       X509_gmtime_adj(X509_getm_notBefore(x), notBeforeOffset) == nullptr ||
       X509_gmtime_adj(X509_getm_notAfter(x), notAfterOffset) == nullptr)
   {
      X509_free(x);
      return nullptr;
   }

   if (not SetCommonName(x, cn) ||
       X509_set_issuer_name(x, X509_get_subject_name(caCert)) != 1)
   {
      X509_free(x);
      return nullptr;
   }

   if (AddBasicConstraints(x, false) == false ||
       AddKeyUsage(x, kuMask) == false ||
       AddKeyID(x, NID_subject_key_identifier, x) == false ||
       AddKeyID(x, NID_authority_key_identifier, caCert) == false ||
       (eku != nullptr && AddEKU(x, eku) == false) ||
       X509_sign(x, caKey, EVP_sha256()) == 0)
   {
      X509_free(x);
      return nullptr;
   }
   return x;
}

CMS_ContentInfo *SignData(std::string const &data, X509 *signcert,
			  EVP_PKEY *signkey, X509 *ca)
{
   STACK_OF(X509) *certs = sk_X509_new_null();
   if (certs == nullptr)
      return nullptr;
   sk_X509_push(certs, signcert);
   if (ca != nullptr)
      sk_X509_push(certs, ca);

   BIO *bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
   CMS_ContentInfo *cms = nullptr;
   if (bio != nullptr)
      cms = CMS_sign(signcert, signkey, certs, bio,
		     CMS_DETACHED | CMS_BINARY);

   BIO_free(bio);
   sk_X509_free(certs); // non-owning stack
   return cms;
}

CMS_ContentInfo *SignDataTwoSigners(std::string const &data,
				    X509 *cert1, EVP_PKEY *key1,
				    X509 *cert2, EVP_PKEY *key2)
{
   BIO *bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
   if (bio == nullptr)
      return nullptr;

   CMS_ContentInfo *cms = CMS_sign(cert1, key1, nullptr, bio,
                                   CMS_DETACHED | CMS_BINARY | CMS_PARTIAL);
   if (cms == nullptr ||
       CMS_add1_signer(cms, cert2, key2, nullptr, 0) == nullptr ||
       BIO_reset(bio) != 1 ||
       CMS_final(cms, bio, nullptr, CMS_DETACHED | CMS_BINARY) != 1)
   {
      CMS_ContentInfo_free(cms);
      BIO_free(bio);
      return nullptr;
   }

   BIO_free(bio);
   return cms;
}

std::string CertToPEM(X509 *x)
{
   BIO *bio = BIO_new(BIO_s_mem());
   if (bio == nullptr)
      return "";
   std::string out;
   if (PEM_write_bio_X509(bio, x) == 1)
      out = BIOToString(bio);
   BIO_free(bio);
   return out;
}

std::string CMSToPEM(CMS_ContentInfo *cms)
{
   return CMSToPEMWithLabel(cms, PEM_STRING_CMS);
}

// Go through i2d + the generic PEM_write_bio rather than PEM_write_bio_CMS so
// that the label is ours to pick. The output for the "CMS" label is identical.
std::string CMSToPEMWithLabel(CMS_ContentInfo *cms, char const *label)
{
   unsigned char *der = nullptr;
   int const derLen = i2d_CMS_ContentInfo(cms, &der);
   if (derLen <= 0 || der == nullptr)
      return "";

   BIO *bio = BIO_new(BIO_s_mem());
   std::string out;
   if (bio != nullptr && PEM_write_bio(bio, label, "", der, derLen) > 0)
      out = BIOToString(bio);

   BIO_free(bio);
   OPENSSL_free(der);
   return out;
}

std::string Fingerprint(X509 *x)
{
   unsigned char md[EVP_MAX_MD_SIZE];
   unsigned int len = 0;
   if (X509_digest(x, EVP_sha256(), md, &len) != 1)
      return "";

   static char const hex[] = "0123456789abcdef";
   std::string out;
   out.reserve(len * 2);
   for (unsigned int i = 0; i < len; ++i)
   {
      out += hex[(md[i] >> 4) & 0xf];
      out += hex[md[i] & 0xf];
   }
   return out;
}

std::string SubjectOf(X509 *x)
{
   BIO *bio = BIO_new(BIO_s_mem());
   if (bio == nullptr)
      return "";
   std::string out;
   if (X509_NAME_print_ex(bio, X509_get_subject_name(x), 0, XN_FLAG_ONELINE) >= 0)
      out = BIOToString(bio);
   BIO_free(bio);
   return out;
}
} // namespace APT::Test::PKI
