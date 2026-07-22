// -*- mode: cpp; mode: fold -*-
// Description							/*{{{*/
/* Unit tests for the CMS PKCS#7 Release file verification feature.
 *
 * Three test suites:
 *   CMSURIDerivation - URL construction logic (mirrors pkgAcqMetaCMS::Done)
 *   CMSKeepPattern   - KeepPattern regex (mirrors acquire.cc CleanLists logic)
 *   CMSVerify        - libssl CMS sign/verify round-trip with CA-signed leaf
 *                      certs and the X509Store verifier from apt-pkg/contrib/pkcs7.
 *
 * PKI generation and verification helpers live in pkcs7-helpers.{h,cc}.
 */
									/*}}}*/
// Include Files						/*{{{*/
#include <config.h>

#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/strutl.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/pkcs7.h>

#include <regex>
#include <string>
#include <fstream>
#include <sstream>

// pem.h must come before cms.h so that DECLARE_PEM_rw(CMS,...) resolves
// PEM_read_bio_CMS correctly.
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "common.h"
#include "file-helpers.h"
#include "pkcs7-helpers.h"
									/*}}}*/

// ---------------------------------------------------------------------------
// Suite A: CMSURIDerivation
//
// Mirrors the logic in pkgAcqMetaCMS::Done():
//   std::string const baseURI = Target.URI.substr(0, Target.URI.rfind('/') + 1);
//   std::string const p7sURI  = baseURI + "signed-by/SHA256/" + sha256hex + ".p7s";
// ---------------------------------------------------------------------------

static std::string DeriveP7SURI(std::string const &releaseURI, std::string const &sha256hex)
{
   std::string const baseURI = releaseURI.substr(0, releaseURI.rfind('/') + 1);
   return baseURI + "signed-by/SHA256/" + sha256hex + ".p7s";
}

static std::string SHA256OfFile(std::string const &path)
{
   ::Hashes hasher(::Hashes::SHA256SUM);
   FileFd fd;
   if (fd.Open(path, FileFd::ReadOnly) == false || hasher.AddFD(fd) == false)
      return "";
   HashStringList const hsl = hasher.GetHashStringList();
   HashString const * const entry = hsl.find("SHA256");
   return entry ? entry->HashValue() : "";
}

TEST(CMSURIDerivation, KnownContent)
{
   auto tmp = createTemporaryFile("cms_uri_known");
   FileFd fd;
   ASSERT_TRUE(fd.Open(tmp.Name(), FileFd::WriteOnly | FileFd::Empty));
   std::string const content = "Origin: Test\nSuite: stable\n";
   ASSERT_TRUE(fd.Write(content.data(), content.size()));
   fd.Close();

   std::string const sha256 = SHA256OfFile(tmp.Name());
   EXPECT_EQ(sha256, "052fe8069ea7789c77aaa32df9ff81c3fc5752db5f38a9288af1f007c35c513e");

   EXPECT_EQ(DeriveP7SURI(
      "http://deb.debian.org/debian/dists/stable/Release", sha256),
      "http://deb.debian.org/debian/dists/stable/"
      "signed-by/SHA256/052fe8069ea7789c77aaa32df9ff81c3fc5752db5f38a9288af1f007c35c513e.p7s");
}

TEST(CMSURIDerivation, DifferentContentDifferentURI)
{
   auto tmp1 = createTemporaryFile("cms_uri_a");
   auto tmp2 = createTemporaryFile("cms_uri_b");
   FileFd f1, f2;
   ASSERT_TRUE(f1.Open(tmp1.Name(), FileFd::WriteOnly | FileFd::Empty));
   ASSERT_TRUE(f1.Write("Origin: Test\n", 14));
   f1.Close();
   ASSERT_TRUE(f2.Open(tmp2.Name(), FileFd::WriteOnly | FileFd::Empty));
   ASSERT_TRUE(f2.Write("Origin: Other\n", 15));
   f2.Close();

   std::string const base = "http://localhost:8080/dists/bookworm/Release";
   EXPECT_NE(DeriveP7SURI(base, SHA256OfFile(tmp1.Name())),
	     DeriveP7SURI(base, SHA256OfFile(tmp2.Name())));
}

TEST(CMSURIDerivation, EmptyFile)
{
   auto tmp = createTemporaryFile("cms_uri_empty");
   std::string const sha256 = SHA256OfFile(tmp.Name());
   EXPECT_EQ(sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

   EXPECT_EQ(DeriveP7SURI("http://localhost/Release", sha256),
      "http://localhost/"
      "signed-by/SHA256/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.p7s");
}

TEST(CMSURIDerivation, BaseURIExtractionNested)
{
   EXPECT_EQ(DeriveP7SURI(
      "http://deb.debian.org/debian/dists/stable/Release", "aabbcc"),
      "http://deb.debian.org/debian/dists/stable/signed-by/SHA256/aabbcc.p7s");
}

TEST(CMSURIDerivation, BaseURIExtractionFlatArchive)
{
   EXPECT_EQ(DeriveP7SURI("http://localhost:8080/Release", "deadbeef"),
      "http://localhost:8080/signed-by/SHA256/deadbeef.p7s");
}

TEST(CMSURIDerivation, BaseURIExtractionPort)
{
   EXPECT_EQ(DeriveP7SURI(
      "http://localhost:8080/dists/bookworm/Release", "1234"),
      "http://localhost:8080/dists/bookworm/signed-by/SHA256/1234.p7s");
}

// ---------------------------------------------------------------------------
// Suite B: CMSKeepPattern
//
// Mirrors the regex in apt-pkg/acquire.cc used by CleanLists to decide which
// cached list files to keep.
// ---------------------------------------------------------------------------

static const std::regex KeepPattern(
   ".*_(Release|Release\\.gpg|InRelease|Release\\.p7s)");

TEST(CMSKeepPattern, MatchesReleaseP7S)
{
   EXPECT_TRUE(std::regex_match(
      "deb.debian.org_debian_dists_stable_Release.p7s", KeepPattern));
}

TEST(CMSKeepPattern, DoesNotMatchByHashP7S)
{
   EXPECT_FALSE(std::regex_match(
      "deb.debian.org_debian_dists_stable_signed-by_SHA256_aabbcc.p7s",
      KeepPattern));
}

TEST(CMSKeepPattern, DoesNotMatchFprSidecar)
{
   EXPECT_FALSE(std::regex_match(
      "deb.debian.org_debian_dists_stable_Release.p7s.fpr", KeepPattern));
}

TEST(CMSKeepPattern, DoesNotMatchWrongExtension)
{
   EXPECT_FALSE(std::regex_match("repo_Release.gpg.p7s", KeepPattern));
}

TEST(CMSKeepPattern, DoesNotMatchPlainPackagesFile)
{
   EXPECT_FALSE(std::regex_match(
      "deb.debian.org_debian_dists_stable_main_binary-amd64_Packages",
      KeepPattern));
}

TEST(CMSKeepPattern, StillMatchesRelease)
{
   EXPECT_TRUE(std::regex_match(
      "deb.debian.org_debian_dists_stable_Release", KeepPattern));
}

TEST(CMSKeepPattern, StillMatchesReleaseGpg)
{
   EXPECT_TRUE(std::regex_match(
      "deb.debian.org_debian_dists_stable_Release.gpg", KeepPattern));
}

TEST(CMSKeepPattern, StillMatchesInRelease)
{
   EXPECT_TRUE(std::regex_match(
      "deb.debian.org_debian_dists_stable_InRelease", KeepPattern));
}

// ---------------------------------------------------------------------------
// Suite C: CMSVerify
//
// Generates a small PKI (root CA + signing leaf), signs data with CMS_sign(),
// and verifies the chain exactly as the cms method does.
// ---------------------------------------------------------------------------

class CMSVerifyTest : public ::testing::Test
{
protected:
   EVP_PKEY *caKey = nullptr;
   X509     *caCert = nullptr;
   EVP_PKEY *leafKey = nullptr;
   X509     *leafCert = nullptr;
   EVP_PKEY *otherKey = nullptr;
   X509     *otherCert = nullptr;

   void SetUp() override
   {
      caKey = APT::Test::PKI::MakeKey();
      ASSERT_NE(caKey, nullptr);
      caCert = APT::Test::PKI::MakeCACert(caKey, "APT Test CMS CA");
      ASSERT_NE(caCert, nullptr);

      leafKey = APT::Test::PKI::MakeKey();
      ASSERT_NE(leafKey, nullptr);
      leafCert = APT::Test::PKI::MakeLeafCert(leafKey, caKey, caCert,
					       "APT Test CMS Leaf", "resolute");
      ASSERT_NE(leafCert, nullptr);

      otherKey = APT::Test::PKI::MakeKey();
      ASSERT_NE(otherKey, nullptr);
      otherCert = APT::Test::PKI::MakeSelfSignedLeaf(otherKey, "APT Other CMS Signer");
      ASSERT_NE(otherCert, nullptr);
   }

   void TearDown() override
   {
      X509_free(caCert);      caCert = nullptr;
      EVP_PKEY_free(caKey);   caKey = nullptr;
      X509_free(leafCert);    leafCert = nullptr;
      EVP_PKEY_free(leafKey); leafKey = nullptr;
      X509_free(otherCert);   otherCert = nullptr;
      EVP_PKEY_free(otherKey); otherKey = nullptr;
      // Negative tests push expected errors to the global _error
      // singleton.  Drain them so they don't leak into subsequent
      // tests in the shared test binary (e.g. ExtractTar).
      _error->Discard();
      // The OpenSSL error queue must be empty between tests: a leaked
      // error is a bug in the code that produced it — it must be handled
      // there, not silently discarded by an unrelated later consumer.
      std::string leaked;
      for (unsigned long e; (e = ERR_get_error()) != 0;)
      {
	 if (not leaked.empty())
	    leaked += "; ";
	 char const * const r = ERR_reason_error_string(e);
	 leaked += (r != nullptr) ? r : "unknown";
      }
      EXPECT_TRUE(leaked.empty()) << "leaked OpenSSL errors: " << leaked;
   }
};

TEST_F(CMSVerifyTest, ValidChainAndPolicyVerifies)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_EQ(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, TamperedDataFails)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

    auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
    EXPECT_NE(APT::Test::PKI::VerifyCMS(cms, "TAMPERED CONTENT\n", caTmp.Name()), 1);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, WrongTrustAnchorFails)
{
   std::string const data = "Origin: Test\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto otherTmp = APT::Test::PKI::WriteCertPEM(otherCert);
   EXPECT_NE(APT::Test::PKI::VerifyCMS(cms, data, otherTmp.Name()), 1);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, MissingCertFileReturnsError)
{
   std::string const data = "Origin: Test\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

    EXPECT_EQ(APT::Test::PKI::VerifyCMS(cms, data, "/nonexistent/ca.pem"), -1);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, MalformedSignatureFileFailsPEMRead)
{
   auto garbage = createTemporaryFile("cms_garbage");
   FileFd fd;
   ASSERT_TRUE(fd.Open(garbage.Name(), FileFd::WriteOnly | FileFd::Empty));
   ASSERT_TRUE(fd.Write("THIS IS NOT A VALID CMS PEM FILE\n", 34));
   fd.Close();

   BIO *bio = BIO_new_file(garbage.Name().c_str(), "r");
   ASSERT_NE(bio, nullptr);
   // Expected to fail; scope and discard the parse errors it pushes.
   ERR_set_mark();
   CMS_ContentInfo *cms = PEM_read_bio_CMS(bio, nullptr, nullptr, nullptr);
   ERR_pop_to_mark();
   BIO_free(bio);
   EXPECT_EQ(cms, nullptr);
}

TEST_F(CMSVerifyTest, SignerSubjectExtracted)
{
   std::string const data = "Origin: Test\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   ASSERT_EQ(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);

   STACK_OF(X509) *signers = CMS_get0_signers(cms);
   ASSERT_NE(signers, nullptr);
   ASSERT_GE(sk_X509_num(signers), 1);
   X509 *signer = sk_X509_value(signers, 0);
   ASSERT_NE(signer, nullptr);

   char subjectbuf[256];
   X509_NAME_oneline(X509_get_subject_name(signer), subjectbuf, sizeof(subjectbuf));
   std::string const subject(subjectbuf);
   EXPECT_NE(subject.find("APT Test CMS Leaf"), std::string::npos)
       << "Subject was: " << subject;

   sk_X509_pop_free(signers, X509_free);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, IntermediateChainVerifies)
{
   EVP_PKEY *interKey = APT::Test::PKI::MakeKey();
   ASSERT_NE(interKey, nullptr);
   X509 *interCert = APT::Test::PKI::MakeCACert(interKey, "APT Test Intermediate CA");
   ASSERT_NE(interCert, nullptr);
   X509_set_issuer_name(interCert, X509_get_subject_name(caCert));
   X509_sign(interCert, caKey, EVP_sha256());

   EVP_PKEY *leaf2Key = APT::Test::PKI::MakeKey();
   ASSERT_NE(leaf2Key, nullptr);
   X509 *leaf2Cert = APT::Test::PKI::MakeLeafCert(leaf2Key, interKey, interCert,
						   "Intermediate Leaf", "resolute");
   ASSERT_NE(leaf2Cert, nullptr);

   std::string const data = "Origin: Test\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leaf2Cert, leaf2Key, interCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_EQ(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);

   CMS_ContentInfo_free(cms);
   X509_free(leaf2Cert);
   EVP_PKEY_free(leaf2Key);
   X509_free(interCert);
   EVP_PKEY_free(interKey);
}

TEST_F(CMSVerifyTest, SHA1DigestRejected)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignDataWithDigest(data, leafCert, leafKey, EVP_sha1(), caCert);
   if (cms == nullptr)
      GTEST_SKIP() << "SHA-1 CMS signing rejected by host OpenSSL security level";

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_NE(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, SHA1DigestWeakConfigAccepted)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignDataWithDigest(data, leafCert, leafKey, EVP_sha1(), caCert);
   if (cms == nullptr)
      GTEST_SKIP() << "SHA-1 CMS signing rejected by host OpenSSL security level";

   _config->Set("APT::Hashes::SHA1::Weak", true);
   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_EQ(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);
   _config->Clear("APT::Hashes::SHA1::Weak");
   CMS_ContentInfo_free(cms);
}

TEST_F(CMSVerifyTest, SHA256DigestUntrustedConfigRejected)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   _config->Set("APT::Hashes::SHA256::Untrusted", true);
   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_NE(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);
   _config->Clear("APT::Hashes::SHA256::Untrusted");
   CMS_ContentInfo_free(cms);
}

// Baseline signing-capability check (gpgv parity): a signer whose
// KeyUsage extension lacks digitalSignature (e.g. a keyEncipherment-only
// TLS cert chaining to the pinned CA) must not be accepted.
TEST_F(CMSVerifyTest, SignerLackingDigitalSignatureRejected)
{
   EVP_PKEY *tlsKey = APT::Test::PKI::MakeKey();
   ASSERT_NE(tlsKey, nullptr);
   X509 *tlsCert = APT::Test::PKI::MakeLeafCert(tlsKey, caKey, caCert,
						"TLS-Only Leaf", "resolute",
						KU_KEY_ENCIPHERMENT);
   ASSERT_NE(tlsCert, nullptr);

   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, tlsCert, tlsKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   EXPECT_NE(APT::Test::PKI::VerifyCMS(cms, data, caTmp.Name()), 1);
   CMS_ContentInfo_free(cms);
   X509_free(tlsCert);
   EVP_PKEY_free(tlsKey);
}

// ---------------------------------------------------------------------------
// Cached-file re-verification (as ReVerifyTrust does).
// ---------------------------------------------------------------------------

TEST_F(CMSVerifyTest, VerifyCachedSucceeds)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   auto cmsTmp = APT::Test::PKI::WriteCMSPEM(cms);
   auto dataTmp = APT::Test::PKI::WriteDataFile(data);
   CMS_ContentInfo_free(cms);

   EXPECT_TRUE(APT::Test::PKI::VerifyCMSFiles(
      cmsTmp.Name(), dataTmp.Name(), caTmp.Name()));
}

TEST_F(CMSVerifyTest, VerifyCachedTamperedDataFails)
{
   std::string const data = "Origin: Test\nSuite: resolute\n";
   CMS_ContentInfo *cms = APT::Test::PKI::SignData(data, leafCert, leafKey, caCert);
   ASSERT_NE(cms, nullptr);

   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   auto cmsTmp = APT::Test::PKI::WriteCMSPEM(cms);
   auto dataTmp = APT::Test::PKI::WriteDataFile("TAMPERED DATA\n");
   CMS_ContentInfo_free(cms);

   EXPECT_FALSE(APT::Test::PKI::VerifyCMSFiles(
      cmsTmp.Name(), dataTmp.Name(), caTmp.Name()));
}

// A bundle containing a malformed certificate must fail loudly instead
// of silently loading only the certificates before it.
TEST_F(CMSVerifyTest, MalformedCertInBundleFails)
{
   auto caTmp = APT::Test::PKI::WriteCertPEM(caCert);
   std::ifstream pem(caTmp.Name());
   std::stringstream content;
   content << pem.rdbuf();
   content << "-----BEGIN CERTIFICATE-----\n!invalid-base64!\n-----END CERTIFICATE-----\n";
   std::string const bundleText = content.str();

   auto bundle = createTemporaryFile("pki_bundle_bad");
   FileFd fd;
   ASSERT_TRUE(fd.Open(bundle.Name(), FileFd::WriteOnly | FileFd::Empty));
   ASSERT_TRUE(fd.Write(bundleText.data(), bundleText.size()));
   fd.Close();

   APT::Internal::X509Store store;
   EXPECT_FALSE(store.LoadCert(bundle.Name()));
   _error->Discard();
}
