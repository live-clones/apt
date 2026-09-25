#ifndef APT_TESTS_PKCS7_HELPERS
#define APT_TESTS_PKCS7_HELPERS

#include <string>

#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace APT::Test::PKI
{
EVP_PKEY *MakeKey();
// Produce minimal certificates to test the chain validation.
// Lacks extensions that are typically seen in real certificates like SAN.
X509 *MakeCACert(EVP_PKEY *key, const char *cn);
X509 *MakeLeafCert(EVP_PKEY *key, EVP_PKEY *caKey, X509 *caCert,
		   const char *cn, const char *eku = nullptr,
		   long notBeforeOffset = -60, long notAfterOffset = 86400,
		   int kuMask = KU_DIGITAL_SIGNATURE);

CMS_ContentInfo *SignData(const std::string &data, X509 *signcert,
			  EVP_PKEY *signkey, X509 *ca = nullptr);
CMS_ContentInfo *SignDataTwoSigners(const std::string &data,
				    X509 *cert1, EVP_PKEY *key1,
				    X509 *cert2, EVP_PKEY *key2);
std::string CertToPEM(X509 *x);
std::string CMSToPEM(CMS_ContentInfo *cms);
std::string CMSToPEMWithLabel(CMS_ContentInfo *cms, const char *label);

// SHA-256 over the DER encoding, hex encoded to assert against
// SignerIdentity::fingerprint.
std::string Fingerprint(X509 *x);
// Subject rendered as a single line, for a test policy that matches on it.
std::string SubjectOf(X509 *x);
} // namespace APT::Test::PKI

#endif
