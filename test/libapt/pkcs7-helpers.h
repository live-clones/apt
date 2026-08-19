#ifndef APT_TESTS_PKCS7_HELPERS
#define APT_TESTS_PKCS7_HELPERS

#include <string>

// pem.h must come before cms.h so that DECLARE_PEM_rw(CMS,...) resolves
// PEM_write_bio_CMS / PEM_read_bio_CMS correctly.
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/cms.h>

#include "file-helpers.h"

namespace APT::Test::PKI
{
   // Generate a fresh 2048-bit RSA key.
   EVP_PKEY *MakeKey();

   // Self-signed root CA: BasicConstraints CA:TRUE (critical),
   // KeyUsage keyCertSign+crlSign (critical), SKI.
   X509 *MakeCACert(EVP_PKEY *key, char const *cn);

   // Leaf cert signed by caCert/caKey.  All policy-relevant extensions
   // are parameterised so negative tests can inject violations without
   // re-invoking the full OpenSSL boilerplate.
   X509 *MakeLeafCert(EVP_PKEY *key, EVP_PKEY *caKey, X509 *caCert,
		      char const *cn, char const *suite,
		      bool addEKU = true,
		      int extraKeyUsage = 0,
		      bool makeCA = false,
		      bool includeDigitalSignature = true,
		      long notBeforeOffset = -60,
		      long notAfterOffset = 86400L,
		      bool bcCritical = true,
		      bool kuCritical = true,
		      int sanType = GEN_DNS);

   // Bare self-signed cert with no extensions (not a valid trust anchor).
   X509 *MakeSelfSignedLeaf(EVP_PKEY *key, char const *cn);

   // Sign `data` as a detached binary CMS including the signer cert and
   // optionally the CA cert in the SignedData certificates field.
   CMS_ContentInfo *SignData(std::string const &data, X509 *signcert,
			     EVP_PKEY *signkey, X509 *includeCA = nullptr);

   // Write cert(s) / CMS / data to PEM temp files (ScopedFileDeleter keeps
   // them alive until it goes out of scope).
   ScopedFileDeleter WriteCertPEM(X509 *x);
   ScopedFileDeleter WriteCMSPEM(CMS_ContentInfo *cms);
   ScopedFileDeleter WriteDataFile(std::string const &data);

   // Verify an in-memory CMS against a CA bundle with the default APT
   // repo-signing policy.  Writes CMS+data to temp files then calls
   // VerifyCMSFiles.  Returns 1=pass, 0=policy fail, -1=infra error.
   int VerifyCMS(CMS_ContentInfo *cms, std::string const &data,
		 std::string const &caPath, std::string const &suite);

   // Verify on-disk CMS+data files (as ReVerifyTrust does).
   // Returns true on success, false on any failure.
   bool VerifyCMSFiles(std::string const &cmsPath, std::string const &dataPath,
		       std::string const &caPath, std::string const &suite);

   // Verify an in-memory CMS directly (no PEM round-trip).  This is needed
   // for multi-signer CMS on OpenSSL 3.5.x where PEM serialization corrupts
   // the second signer's signature.  Returns 1=pass, 0=policy fail, -1=error.
   // Uses CMS_verify + signer iteration, mirroring X509Store::VerifyDetach.
   int VerifyCMSInMemory(CMS_ContentInfo *cms, std::string const &data,
			 std::string const &caPath, std::string const &suite);
}

#endif
