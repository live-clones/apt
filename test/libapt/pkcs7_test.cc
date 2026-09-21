#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/pkcs7.h>

#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/err.h>

#include "file-helpers.h"
#include "pkcs7-helpers.h"

using APT::Internal::BaseX509Store;
using APT::Internal::SignerIdentity;
using APT::Internal::VerificationResult;
namespace PKI = APT::Test::PKI;

namespace
{
constexpr char const *SIGNED_DATA = "Origin: Debian\nSuite: stable\n";
// Any EKU that is not emailProtection. OpenSSL's smime_sign purpose rejects a
// leaf whose EKU extension is present but lacks emailProtection, so this is
// what proves the trust store stays purpose-agnostic.
constexpr char const *CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3";
// Mirrors the limits in pkcs7.cc.
constexpr size_t MAX_SIGNATURE_BYTES = 1024 * 1024;
constexpr size_t MAX_SIGNATURE_BLOCKS = 32;

// Join and clear whatever is on the error list, so a test can assert on why a
// verification failed rather than merely that it did.
std::string DrainErrors()
{
   std::string out;
   while (_error->empty(GlobalError::DEBUG) == false)
   {
      std::string message;
      _error->PopMessage(message);
      if (out.empty() == false)
	 out += "\n";
      out += message;
   }
   return out;
}

// Exposes the protected surface so the tests can drive and observe the hooks.
class PolicyStore : public BaseX509Store
{
   public:
   using BaseX509Store::LoadedCerts;

   // Reject any signer whose subject contains this, when non-empty.
   std::string rejectSubjectContaining;
   // Emulate a subclass that reports its rejection with _error->Error().
   bool reportWithError = false;
   // Host the policy in VerifySignature() instead of VerifyCert().
   bool rejectInSignatureHook = false;

   int certCalls = 0;
   int signatureCalls = 0;
   // Set when a hook is handed a null argument, or a SignerInfo that does not
   // describe the certificate passed alongside it.
   bool sawBadHookArguments = false;
   // What LoadedCerts() reported the last time a hook asked.
   size_t loadedCertsInHook = 0;
   // Subjects passed to VerifyCert(), in call order.
   std::vector<std::string> seenSubjects;

   protected:
   bool VerifySignature(CMS_SignerInfo *si, X509 *cert) override
   {
      ++signatureCalls;
      // The pairing is the library's job; prove it got it right.
      if (si == nullptr || cert == nullptr ||
	  CMS_SignerInfo_cert_cmp(si, cert) != 0)
      {
	 sawBadHookArguments = true;
	 return false;
      }
      loadedCertsInHook = LoadedCerts().size();
      return rejectInSignatureHook ? Accepts(cert) : true;
   }

   bool VerifyCert(X509 *cert) override
   {
      ++certCalls;
      if (cert == nullptr)
      {
	 sawBadHookArguments = true;
	 return false;
      }
      seenSubjects.push_back(PKI::SubjectOf(cert));
      return rejectInSignatureHook ? true : Accepts(cert);
   }

   private:
   // The policy body itself, so either hook can host it.
   bool Accepts(X509 *cert)
   {
      if (rejectSubjectContaining.empty())
	 return true;

      std::string const subject = PKI::SubjectOf(cert);
      if (subject.find(rejectSubjectContaining) == std::string::npos)
	 return true;

      if (reportWithError)
	 _error->Error("PolicyStore rejects %s", subject.c_str());
      return false;
   }
};

class PKCS7Test : public ::testing::Test
{
   protected:
   // Minted once: keygen and self-signing are the expensive part.
   static EVP_PKEY *caKey;
   static EVP_PKEY *leafKeyA;
   static EVP_PKEY *leafKeyB;
   static EVP_PKEY *otherCaKey;
   static EVP_PKEY *otherLeafKey;
   static X509 *caCert;
   static X509 *leafA;	      // chains to caCert
   static X509 *leafB;	      // chains to caCert, different CN
   static X509 *leafEKU;      // chains to caCert, carries a non-SMIME EKU
   static X509 *leafKU;	      // chains to caCert, KeyUsage without digitalSignature
   static X509 *leafExpired;  // chains to caCert, notAfter in the past
   static X509 *leafNotYetOk; // chains to caCert, notBefore in the future
   static X509 *otherCa;      // never loaded into any trust store
   static X509 *otherLeaf;

   static void SetUpTestSuite()
   {
      caKey = PKI::MakeKey();
      leafKeyA = PKI::MakeKey();
      leafKeyB = PKI::MakeKey();
      otherCaKey = PKI::MakeKey();
      otherLeafKey = PKI::MakeKey();
      ASSERT_NE(nullptr, caKey);
      ASSERT_NE(nullptr, leafKeyA);
      ASSERT_NE(nullptr, leafKeyB);
      ASSERT_NE(nullptr, otherCaKey);
      ASSERT_NE(nullptr, otherLeafKey);

      caCert = PKI::MakeCACert(caKey, "APT Test CA");
      otherCa = PKI::MakeCACert(otherCaKey, "APT Untrusted CA");
      ASSERT_NE(nullptr, caCert);
      ASSERT_NE(nullptr, otherCa);

      leafA = PKI::MakeLeafCert(leafKeyA, caKey, caCert, "signer-a");
      leafB = PKI::MakeLeafCert(leafKeyB, caKey, caCert, "signer-b");
      leafEKU = PKI::MakeLeafCert(leafKeyA, caKey, caCert, "signer-eku",
				  CODE_SIGNING_EKU);
      // KeyUsage without digitalSignature: chain validation must not care.
      leafKU = PKI::MakeLeafCert(leafKeyA, caKey, caCert, "signer-ku", nullptr,
				 -60, 86400, KU_KEY_ENCIPHERMENT);
      leafExpired = PKI::MakeLeafCert(leafKeyA, caKey, caCert, "signer-expired",
				      nullptr, -7200, -3600);
      leafNotYetOk = PKI::MakeLeafCert(leafKeyA, caKey, caCert, "signer-future",
				       nullptr, 3600, 7200);
      otherLeaf = PKI::MakeLeafCert(otherLeafKey, otherCaKey, otherCa,
				    "signer-untrusted");
      ASSERT_NE(nullptr, leafA);
      ASSERT_NE(nullptr, leafB);
      ASSERT_NE(nullptr, leafEKU);
      ASSERT_NE(nullptr, leafKU);
      ASSERT_NE(nullptr, leafExpired);
      ASSERT_NE(nullptr, leafNotYetOk);
      ASSERT_NE(nullptr, otherLeaf);
   }

   static void TearDownTestSuite()
   {
      for (X509 *x : {caCert, leafA, leafB, leafEKU, leafKU, leafExpired,
		      leafNotYetOk, otherCa, otherLeaf})
	 X509_free(x);
      for (EVP_PKEY *k : {caKey, leafKeyA, leafKeyB, otherCaKey, otherLeafKey})
	 EVP_PKEY_free(k);
   }

   void SetUp() override
   {
      _error->Discard();
      // This process owns OpenSSL's error queue, so start each test from a
      // known state regardless of what the previous one planted in it.
      ERR_clear_error();
      // Make the queue-hygiene note observable, which also turns an unexpected
      // one in any of the other tests into visible output.
      _config->Set("Debug::Pkcs7", true);
   }

   void TearDown() override { _config->Set("Debug::Pkcs7", false); }

   // Detached CMS over SIGNED_DATA as a PEM block.
   static std::string SignBlock(X509 *cert, EVP_PKEY *key,
				char const *data = SIGNED_DATA)
   {
      CMS_ContentInfo *cms = PKI::SignData(data, cert, key);
      if (cms == nullptr)
	 return "";
      std::string const pem = PKI::CMSToPEM(cms);
      CMS_ContentInfo_free(cms);
      return pem;
   }

   // As SignBlock, but under an arbitrary PEM label.
   static std::string SignBlockLabelled(X509 *cert, EVP_PKEY *key,
					char const *label)
   {
      CMS_ContentInfo *cms = PKI::SignData(SIGNED_DATA, cert, key);
      if (cms == nullptr)
	 return "";
      std::string const pem = PKI::CMSToPEMWithLabel(cms, label);
      CMS_ContentInfo_free(cms);
      return pem;
   }

   // A single block holding two SignerInfos and both signer certificates.
   static std::string SignBlockTwoSigners(X509 *c1, EVP_PKEY *k1, X509 *c2,
					  EVP_PKEY *k2)
   {
      CMS_ContentInfo *cms = PKI::SignDataTwoSigners(SIGNED_DATA, c1, k1, c2, k2);
      if (cms == nullptr)
	 return "";
      std::string const pem = PKI::CMSToPEM(cms);
      CMS_ContentInfo_free(cms);
      return pem;
   }

   // LoadCert() does not retain the fd, so a temporary is enough.
   static bool LoadAnchors(PolicyStore &store, std::string const &pem)
   {
      FileFd bundle;
      openTemporaryFile("pkcs7-ca", bundle, pem.c_str());
      return store.LoadCert(bundle);
   }

   static bool Verify(PolicyStore &store, std::string const &signature,
		      VerificationResult &result,
		      char const *data = SIGNED_DATA)
   {
      FileFd sig;
      openTemporaryFile("pkcs7-sig", sig, signature.c_str());
      FileFd dataFd;
      openTemporaryFile("pkcs7-data", dataFd, data);
      return store.VerifyDetach(sig, dataFd, result);
   }
};

EVP_PKEY *PKCS7Test::caKey = nullptr;
EVP_PKEY *PKCS7Test::leafKeyA = nullptr;
EVP_PKEY *PKCS7Test::leafKeyB = nullptr;
EVP_PKEY *PKCS7Test::otherCaKey = nullptr;
EVP_PKEY *PKCS7Test::otherLeafKey = nullptr;
X509 *PKCS7Test::caCert = nullptr;
X509 *PKCS7Test::leafA = nullptr;
X509 *PKCS7Test::leafB = nullptr;
X509 *PKCS7Test::leafEKU = nullptr;
X509 *PKCS7Test::leafKU = nullptr;
X509 *PKCS7Test::leafExpired = nullptr;
X509 *PKCS7Test::leafNotYetOk = nullptr;
X509 *PKCS7Test::otherCa = nullptr;
X509 *PKCS7Test::otherLeaf = nullptr;
} // namespace

// LoadCert - here we test that the method...
// * can load a PEM bundle
// * can load a *concatenated* PEM bundle
// * returns false on an empty bundle (it's not valid)
// * returns false if we get any garbage input
// * rewinds the fd rather than reading from wherever it happens to be
// * replaces the previously loaded store instead of adding to it
TEST_F(PKCS7Test, LoadCert)
{
   {
      PolicyStore store;
      FileFd bundle;
      openTemporaryFile("pkcs7-bundle", bundle, PKI::CertToPEM(caCert).c_str());
      EXPECT_TRUE(store.LoadCert(bundle));
      EXPECT_EQ(1u, store.LoadedCerts().size());
   }
   {
      // A concatenated bundle loads every certificate it holds.
      PolicyStore store;
      std::string const two = PKI::CertToPEM(caCert) + PKI::CertToPEM(otherCa);
      FileFd bundle;
      openTemporaryFile("pkcs7-bundle2", bundle, two.c_str());
      EXPECT_TRUE(store.LoadCert(bundle));
      EXPECT_EQ(2u, store.LoadedCerts().size());
   }
   {
      PolicyStore store;
      FileFd empty;
      openTemporaryFile("pkcs7-empty", empty, "");
      EXPECT_FALSE(store.LoadCert(empty));
      EXPECT_TRUE(store.LoadedCerts().empty());
   }
   {
      PolicyStore store;
      FileFd garbage;
      openTemporaryFile("pkcs7-garbage", garbage, "not a certificate at all\n");
      EXPECT_FALSE(store.LoadCert(garbage));
   }
   {
      // An fd left at EOF by a previous reader still loads.
      PolicyStore store;
      FileFd bundle;
      openTemporaryFile("pkcs7-seek", bundle, PKI::CertToPEM(caCert).c_str());
      ASSERT_TRUE(bundle.Seek(bundle.FileSize()));
      EXPECT_TRUE(store.LoadCert(bundle));
      EXPECT_EQ(1u, store.LoadedCerts().size());
   }
   {
      // Loading again replaces the store rather than adding to it.
      PolicyStore store;
      ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert) +
					PKI::CertToPEM(otherCa)));
      ASSERT_EQ(2u, store.LoadedCerts().size());
      ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));
      EXPECT_EQ(1u, store.LoadedCerts().size());

      // ... and a failed load leaves the working store alone.
      FileFd garbage;
      openTemporaryFile("pkcs7-garbage2", garbage, "still not a certificate\n");
      EXPECT_FALSE(store.LoadCert(garbage));
      EXPECT_EQ(1u, store.LoadedCerts().size());
      VerificationResult result;
      EXPECT_TRUE(Verify(store, SignBlock(leafA, leafKeyA), result));
   }
   _error->Discard();
}

// VerifyDetach - happy path, including the reported signer identity and the
// arguments both hooks are handed.
TEST_F(PKCS7Test, VerifyDetachAcceptsTrustedSigner)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   VerificationResult result;
   EXPECT_TRUE(Verify(store, SignBlock(leafA, leafKeyA), result));
   EXPECT_FALSE(_error->PendingError());
   ASSERT_EQ(1u, result.signers.size());
   EXPECT_EQ(PKI::Fingerprint(leafA), result.signers[0].fingerprint);
   EXPECT_NE(std::string::npos, result.signers[0].subject.find("signer-a"));
   EXPECT_EQ(1, store.certCalls);
   EXPECT_EQ(1, store.signatureCalls);
   EXPECT_FALSE(store.sawBadHookArguments);
   // LoadedCerts() is the documented way for a hook to reach the anchors.
   EXPECT_EQ(1u, store.loadedCertsInHook);
}

// VerifyDetach - without anchors there is nothing to verify against.
TEST_F(PKCS7Test, VerifyDetachRequiresTrustStore)
{
   PolicyStore store;
   VerificationResult result;
   EXPECT_FALSE(Verify(store, SignBlock(leafA, leafKeyA), result));
   EXPECT_TRUE(result.signers.empty());
   EXPECT_EQ(0, store.certCalls);
   EXPECT_NE(std::string::npos, DrainErrors().find("no trust store loaded"));
}

// VerifyDetach - data has been changed after signature was made
TEST_F(PKCS7Test, VerifyDetachRejectsTamperedData)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   VerificationResult result;
   EXPECT_FALSE(Verify(store, SignBlock(leafA, leafKeyA), result,
		       "Origin: Debian\nSuite: unstable\n"));
   EXPECT_TRUE(result.signers.empty());
   _error->Discard();
}

// VerifyDetach - signer uses an unloaded trust-anchor.
TEST_F(PKCS7Test, VerifyDetachRejectsUntrustedAnchor)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   VerificationResult result;
   EXPECT_FALSE(Verify(store, SignBlock(otherLeaf, otherLeafKey), result));
   EXPECT_TRUE(result.signers.empty());
   // CMS_verify() only ever raises CMS_R_CERTIFICATE_VERIFY_ERROR. The X.509
   // reason it stands for stays in the X509_STORE_CTX that CMS_verify creates
   // and frees internally, so every chain failure reads the same from here.
   EXPECT_NE(std::string::npos, DrainErrors().find("certificate verify error"));
}

// VerifyDetach - a certificate outside its validity period is rejected.
//
// As with an untrusted anchor, the reported reason is only CMS_verify's generic
// "certificate verify error", so these assert on the rejection rather than on
// being told that the certificate expired.
TEST_F(PKCS7Test, VerifyDetachRejectsCertificateOutsideValidity)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   {
      VerificationResult result;
      EXPECT_FALSE(Verify(store, SignBlock(leafExpired, leafKeyA), result));
      EXPECT_TRUE(result.signers.empty());
      EXPECT_NE(std::string::npos, DrainErrors().find("certificate verify error"));
   }
   {
      VerificationResult result;
      EXPECT_FALSE(Verify(store, SignBlock(leafNotYetOk, leafKeyA), result));
      EXPECT_TRUE(result.signers.empty());
      EXPECT_NE(std::string::npos, DrainErrors().find("certificate verify error"));
   }
   // A rejected certificate must not have reached the policy hooks.
   EXPECT_EQ(0, store.certCalls);
}

// Neither a non-emailProtection EKU nor a KeyUsage without digitalSignature may
// defeat chain validation. Without the X509_PURPOSE_ANY pin in LoadCert,
// CMS_verify's smime_sign default rejects both of these signers before any hook
// runs.
TEST_F(PKCS7Test, VerifyDetachIsPurposeAgnostic)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   {
      VerificationResult result;
      EXPECT_TRUE(Verify(store, SignBlock(leafEKU, leafKeyA), result));
      ASSERT_EQ(1u, result.signers.size());
      EXPECT_EQ(PKI::Fingerprint(leafEKU), result.signers[0].fingerprint);
   }
   {
      VerificationResult result;
      EXPECT_TRUE(Verify(store, SignBlock(leafKU, leafKeyA), result));
      ASSERT_EQ(1u, result.signers.size());
      EXPECT_EQ(PKI::Fingerprint(leafKU), result.signers[0].fingerprint);
   }
   EXPECT_FALSE(_error->PendingError());
}

// All of SignatureLabels is accepted, not just "CMS".
TEST_F(PKCS7Test, VerifyDetachAcceptsEveryKnownLabel)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   for (char const *label : {"CMS", "PKCS7", "PKCS #7 SIGNED DATA"})
   {
      VerificationResult result;
      EXPECT_TRUE(Verify(store, SignBlockLabelled(leafA, leafKeyA, label),
			 result))
	 << "label " << label;
      EXPECT_EQ(1u, result.signers.size()) << "label " << label;
   }
   EXPECT_FALSE(_error->PendingError());
}

// An unknown label is fatal: the file is not fully understood.
TEST_F(PKCS7Test, VerifyDetachRejectsUnexpectedLabel)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   VerificationResult result;
   EXPECT_FALSE(Verify(store, SignBlockLabelled(leafA, leafKeyA, "CERTIFICATE"),
		       result));
   EXPECT_TRUE(result.signers.empty());
   EXPECT_NE(std::string::npos, DrainErrors().find("unexpected PEM label"));
}

// One unverifiable block alongside a good one still verifies, and leaves no
// hard error behind.
TEST_F(PKCS7Test, VerifyDetachAcceptsAnyVerifyingBlock)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   std::string const blocks = SignBlock(otherLeaf, otherLeafKey) +
			      SignBlock(leafA, leafKeyA);
   VerificationResult result;
   EXPECT_TRUE(Verify(store, blocks, result));
   EXPECT_FALSE(_error->PendingError());
   ASSERT_EQ(1u, result.signers.size());
   EXPECT_EQ(PKI::Fingerprint(leafA), result.signers[0].fingerprint);
   _error->Discard(); // the rejected block left a warning
}

// A single block with two SignerInfos: the only case that exercises pairing a
// SignerInfo with its certificate.
TEST_F(PKCS7Test, VerifyDetachPairsEverySignerInABlock)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   std::string const block = SignBlockTwoSigners(leafA, leafKeyA, leafB, leafKeyB);
   ASSERT_FALSE(block.empty());

   VerificationResult result;
   EXPECT_TRUE(Verify(store, block, result));
   EXPECT_FALSE(_error->PendingError());
   // Both signers pass, and each hook call saw a SignerInfo that matches the
   // certificate handed alongside it.
   EXPECT_FALSE(store.sawBadHookArguments);
   EXPECT_EQ(2, store.signatureCalls);
   EXPECT_EQ(2, store.certCalls);
   ASSERT_EQ(2u, result.signers.size());
   std::vector<std::string> fingerprints{result.signers[0].fingerprint,
					 result.signers[1].fingerprint};
   std::sort(fingerprints.begin(), fingerprints.end());
   std::vector<std::string> expected{PKI::Fingerprint(leafA),
				     PKI::Fingerprint(leafB)};
   std::sort(expected.begin(), expected.end());
   EXPECT_EQ(expected, fingerprints);
}

// The same certificate signing two blocks is reported once.
TEST_F(PKCS7Test, VerifyDetachDeduplicatesSigners)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   std::string const blocks = SignBlock(leafA, leafKeyA) +
			      SignBlock(leafA, leafKeyA);
   VerificationResult result;
   EXPECT_TRUE(Verify(store, blocks, result));
   EXPECT_FALSE(_error->PendingError());
   // Both blocks verified, so both hooks ran twice ...
   EXPECT_EQ(2, store.certCalls);
   // ... but the signer is the same certificate.
   ASSERT_EQ(1u, result.signers.size());
   EXPECT_EQ(PKI::Fingerprint(leafA), result.signers[0].fingerprint);
}

// A block that cannot be parsed is fatal even when another block would pass.
TEST_F(PKCS7Test, VerifyDetachRejectsUnparsableBlock)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   // Valid PEM framing and valid base64, but not a CMS structure.
   std::string const blocks = SignBlock(leafA, leafKeyA) +
			      "-----BEGIN CMS-----\n"
			      "bm90IGEgQ01TIHN0cnVjdHVyZSBhdCBhbGw=\n"
			      "-----END CMS-----\n";
   VerificationResult result;
   EXPECT_FALSE(Verify(store, blocks, result));
   EXPECT_TRUE(result.signers.empty());
   EXPECT_NE(std::string::npos, DrainErrors().find("failed to parse the CMS block"));
}

// Whatever OpenSSL had queued before we were called is the caller's, and must
// come back out untouched: it may not be reported as though it were ours, and
// it may not be consumed either. ERR_get_error() pops the *oldest* entry while
// ERR_count_to_mark() counts down from the newest, so a diagnostic that drains
// the queue reports the caller's errors and destroys them in the process.
TEST_F(PKCS7Test, VerifyDetachLeavesAPreexistingErrorQueueAlone)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   // Something unrelated failed earlier and left its error behind.
   BIO *junk = BIO_new_mem_buf("not a certificate at all\n", -1);
   ASSERT_NE(nullptr, junk);
   EXPECT_EQ(nullptr, PEM_read_bio_X509(junk, nullptr, nullptr, nullptr));
   BIO_free(junk);
   unsigned long const planted = ERR_peek_error();
   ASSERT_NE(0ul, planted); // the residue really is queued

   // Valid PEM framing and valid base64, but not a CMS structure.
   std::string const block = "-----BEGIN CMS-----\n"
			     "bm90IGEgQ01TIHN0cnVjdHVyZSBhdCBhbGw=\n"
			     "-----END CMS-----\n";
   VerificationResult result;
   EXPECT_FALSE(Verify(store, block, result));

   // The caller's error is still there, and still first in line.
   EXPECT_EQ(planted, ERR_peek_error());

   std::string const errors = DrainErrors();
   // The ASN.1 failure that actually happened ...
   EXPECT_NE(std::string::npos, errors.find("failed to parse the CMS block"));
   // ... never the PEM error planted above ...
   EXPECT_EQ(std::string::npos, errors.find("no start line"));
   // ... and the degraded reporting path says so.
   EXPECT_NE(std::string::npos, errors.find("error queue was not empty"));

   ERR_clear_error();
}

// With a queue of its own to work with, every entry is attributable, so the full
// OpenSSL detail gets rendered and nothing is left behind afterwards.
TEST_F(PKCS7Test, VerifyDetachReportsOpenSSLDetailAndLeavesNoResidue)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));
   ASSERT_EQ(0ul, ERR_peek_error()); // LoadCert cleaned up after itself

   std::string const block = "-----BEGIN CMS-----\n"
			     "bm90IGEgQ01TIHN0cnVjdHVyZSBhdCBhbGw=\n"
			     "-----END CMS-----\n";
   VerificationResult result;
   EXPECT_FALSE(Verify(store, block, result));

   // Nothing of ours escapes to whoever calls OpenSSL next.
   EXPECT_EQ(0ul, ERR_peek_error());

   std::string const errors = DrainErrors();
   EXPECT_NE(std::string::npos, errors.find("failed to parse the CMS block"));
   // Real detail rather than the placeholder ...
   EXPECT_EQ(std::string::npos, errors.find("no OpenSSL error details"));
   // ... and no note about a dirty queue, because there was not one.
   EXPECT_EQ(std::string::npos, errors.find("error queue was not empty"));
}

// A signature file without any PEM block at all.
TEST_F(PKCS7Test, VerifyDetachRejectsSignatureWithoutBlocks)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   for (char const *content : {"", "nothing to see here\n"})
   {
      VerificationResult result;
      EXPECT_FALSE(Verify(store, content, result));
      EXPECT_TRUE(result.signers.empty());
      EXPECT_NE(std::string::npos, DrainErrors().find("no signature blocks found"));
   }
}

// Bytes outside of a PEM block are ignored rather than rejected - pinning the
// documented behaviour, which is PEM_read_bio's rather than a choice of ours.
TEST_F(PKCS7Test, VerifyDetachIgnoresBytesOutsideBlocks)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   std::string const padded = "leading junk\n" + SignBlock(leafA, leafKeyA) +
			      "trailing junk\n";
   VerificationResult result;
   EXPECT_TRUE(Verify(store, padded, result));
   EXPECT_FALSE(_error->PendingError());
   EXPECT_EQ(1u, result.signers.size());
}

// The two DoS guards.
TEST_F(PKCS7Test, VerifyDetachRejectsOversizedSignature)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   {
      std::string oversized(MAX_SIGNATURE_BYTES + 1, 'x');
      VerificationResult result;
      EXPECT_FALSE(Verify(store, oversized, result));
      EXPECT_NE(std::string::npos, DrainErrors().find("signature file exceeds"));
   }
   {
      std::string const one = SignBlock(leafA, leafKeyA);
      std::string many;
      for (size_t i = 0; i <= MAX_SIGNATURE_BLOCKS; ++i)
	 many += one;
      ASSERT_LT(many.size(), MAX_SIGNATURE_BYTES); // the byte guard must not fire

      VerificationResult result;
      EXPECT_FALSE(Verify(store, many, result));
      EXPECT_NE(std::string::npos, DrainErrors().find("signature blocks"));
   }
}

// A result handed in dirty is cleared, whether the verification works out or not.
TEST_F(PKCS7Test, VerifyDetachClearsResult)
{
   PolicyStore store;
   ASSERT_TRUE(LoadAnchors(store, PKI::CertToPEM(caCert)));

   VerificationResult result;
   result.signers.push_back(SignerIdentity{"CN=stale", "deadbeef"});
   EXPECT_TRUE(Verify(store, SignBlock(leafA, leafKeyA), result));
   ASSERT_EQ(1u, result.signers.size());
   EXPECT_EQ(PKI::Fingerprint(leafA), result.signers[0].fingerprint);

   result.signers.push_back(SignerIdentity{"CN=stale", "deadbeef"});
   EXPECT_FALSE(Verify(store, SignBlock(otherLeaf, otherLeafKey), result));
   EXPECT_TRUE(result.signers.empty());
   _error->Discard();
}

// The VerifyCert() hook, and the guarantee that a rejection reported with
// _error->Error() cannot poison an otherwise successful verification.
TEST_F(PKCS7Test, VerifyCertHookRejection)
{
   std::string const ca = PKI::CertToPEM(caCert);
   std::string const blocks = SignBlock(leafA, leafKeyA) +
			      SignBlock(leafB, leafKeyB);

   {
      // Rejecting every signer fails the verification.
      PolicyStore store;
      store.rejectSubjectContaining = "signer-";
      ASSERT_TRUE(LoadAnchors(store, ca));

      VerificationResult result;
      EXPECT_FALSE(Verify(store, blocks, result));
      EXPECT_TRUE(result.signers.empty());
      EXPECT_EQ(2, store.certCalls);
      EXPECT_NE(std::string::npos, DrainErrors().find("certificate rejected by policy"));
   }
   {
      // Rejecting one signer with _error->Error() while another is accepted
      // must still succeed, with a clean error list.
      PolicyStore store;
      store.rejectSubjectContaining = "signer-a";
      store.reportWithError = true;
      ASSERT_TRUE(LoadAnchors(store, ca));

      VerificationResult result;
      EXPECT_TRUE(Verify(store, blocks, result));
      EXPECT_FALSE(_error->PendingError());
      ASSERT_EQ(1u, result.signers.size());
      EXPECT_EQ(PKI::Fingerprint(leafB), result.signers[0].fingerprint);
      // What the hook said survives as a warning, attributed to the signer.
      EXPECT_NE(std::string::npos, DrainErrors().find("PolicyStore rejects"));
   }
}

// The VerifySignature() hook gates on the same terms, and skips VerifyCert()
// for a signer it rejects.
TEST_F(PKCS7Test, VerifySignatureHookRejection)
{
   std::string const ca = PKI::CertToPEM(caCert);

   {
      PolicyStore store;
      store.rejectInSignatureHook = true;
      store.rejectSubjectContaining = "signer-a";
      ASSERT_TRUE(LoadAnchors(store, ca));

      VerificationResult result;
      EXPECT_FALSE(Verify(store, SignBlock(leafA, leafKeyA), result));
      EXPECT_TRUE(result.signers.empty());
      EXPECT_EQ(1, store.signatureCalls);
      // VerifySignature() runs first and short-circuits the other hook.
      EXPECT_EQ(0, store.certCalls);
      EXPECT_NE(std::string::npos, DrainErrors().find("signature rejected by policy"));
   }
   {
      // A signer the hook does not object to passes through to VerifyCert().
      PolicyStore store;
      store.rejectInSignatureHook = true;
      store.rejectSubjectContaining = "signer-a";
      ASSERT_TRUE(LoadAnchors(store, ca));

      VerificationResult result;
      EXPECT_TRUE(Verify(store, SignBlock(leafB, leafKeyB), result));
      EXPECT_FALSE(_error->PendingError());
      EXPECT_EQ(1, store.signatureCalls);
      EXPECT_EQ(1, store.certCalls);
      ASSERT_EQ(1u, store.seenSubjects.size());
      EXPECT_NE(std::string::npos, store.seenSubjects[0].find("signer-b"));
   }
}
