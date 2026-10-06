#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/strutl.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include <dlfcn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "common.h"

#include "file-helpers.h"

/* OpenSSL offers no way to make a digest operation fail on demand, so this
   binary defines the functions itself. The dynamic linker searches the
   executable before libcrypto, so the calls in libapt-pkg land here and are
   passed on to the real functions unless a test asked for a failure. A
   failing OpenSSL function leaves a record on the error queue, so the
   stand-ins do the same. A test must set a flag around exactly one call, so
   the code under test reports exactly once, and check that report with
   expectReportedFailure() before forcing the next failure. */
static bool failDigestInit = false;
static bool failDigestUpdate = false;
static bool failDigestCopy = false;
static bool failDigestFinal = false;

static int failOpenSSL()
{
   ERR_put_error(ERR_LIB_EVP, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
   return 0;
}
extern "C" int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
   if (failDigestInit)
      return failOpenSSL();
   static auto const real = reinterpret_cast<decltype(&EVP_DigestInit_ex)>(dlsym(RTLD_NEXT, "EVP_DigestInit_ex"));
   return real(ctx, type, impl);
}
extern "C" int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
   if (failDigestUpdate)
      return failOpenSSL();
   static auto const real = reinterpret_cast<decltype(&EVP_DigestUpdate)>(dlsym(RTLD_NEXT, "EVP_DigestUpdate"));
   return real(ctx, d, cnt);
}
extern "C" int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
   if (failDigestCopy)
      return failOpenSSL();
   static auto const real = reinterpret_cast<decltype(&EVP_MD_CTX_copy)>(dlsym(RTLD_NEXT, "EVP_MD_CTX_copy"));
   return real(out, in);
}
extern "C" int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
   if (failDigestFinal)
      return failOpenSSL();
   static auto const real = reinterpret_cast<decltype(&EVP_DigestFinal_ex)>(dlsym(RTLD_NEXT, "EVP_DigestFinal_ex"));
   return real(ctx, md, s);
}
/* The failure must reach the caller through _error, naming the algorithm and
   OpenSSL's reason. The error stack must be exactly as it was prior to the
   failing call being made. */
static void expectReportedFailure(char const * const algo, unsigned long const remaining = 0)
{
   std::string msg;
   EXPECT_TRUE(_error->PopMessage(msg));
   EXPECT_TRUE(msg.contains(algo)) << msg;
   // the text OpenSSL gives for the record, which failOpenSSL() pushes
   char const *const reason = ERR_reason_error_string(ERR_PACK(ERR_LIB_EVP, 0, ERR_R_INTERNAL_ERROR));
   EXPECT_TRUE(msg.contains(reason)) << msg;
   EXPECT_TRUE(_error->empty());
   EXPECT_EQ(remaining, ERR_peek_error());
   EXPECT_EQ(remaining, ERR_peek_last_error());
}
template <class T> void Test(const char *In,const char *Out)
{
   T Sum;
   Sum.Add(In);
   equals(Sum.Result().Value(), Out);
}



static void getSummationString(char const * const type, std::string &sum)
{
   /* to compare our result with an independent source we call the specific binaries
      and read their result back. We do this with a little trick by claiming that the
      summation is a compressor – and open the 'compressed' file later on directly to
      read out the summation sum calculated by it */
   APT::Configuration::Compressor compress(type, ".ext", type, NULL, NULL, 99);

   FileFd fd;
   auto const file = createTemporaryFile("hashsums");
   ASSERT_TRUE(fd.Open(file.Name(), FileFd::WriteOnly | FileFd::Empty, compress));
   ASSERT_TRUE(fd.IsOpen());
   FileFd input("/etc/os-release", FileFd::ReadOnly);
   ASSERT_TRUE(input.IsOpen());
   ASSERT_NE(0u, input.FileSize());
   ASSERT_TRUE(CopyFile(input, fd));
   ASSERT_TRUE(input.IsOpen());
   ASSERT_TRUE(fd.IsOpen());
   ASSERT_FALSE(fd.Failed());
   input.Close();
   fd.Close();
   ASSERT_TRUE(fd.Open(file.Name(), FileFd::ReadOnly, FileFd::None));
   ASSERT_TRUE(fd.IsOpen());
   ASSERT_NE(0u, fd.FileSize());
   ASSERT_FALSE(fd.Failed());
   char readback[2000];
   unsigned long long actual;
   ASSERT_TRUE(fd.Read(readback, sizeof(readback)/sizeof(readback[0]), &actual));
   actual -= 4;
   readback[actual] = '\0';
   sum = readback;
}
TEST(HashSumsTest, FileBased)
{
   std::string summation;

   getSummationString("md5sum", summation);
   HashString md5("MD5Sum", summation);
   EXPECT_EQ(md5.HashValue(), summation);

   getSummationString("sha1sum", summation);
   HashString sha1("SHA1", summation);
   EXPECT_EQ(sha1.HashValue(), summation);

   getSummationString("sha256sum", summation);
   HashString sha256("SHA256", summation);
   EXPECT_EQ(sha256.HashValue(), summation);

   getSummationString("sha512sum", summation);
   HashString sha512("SHA512", summation);
   EXPECT_EQ(sha512.HashValue(), summation);

   FileFd fd("/etc/os-release", FileFd::ReadOnly);
   EXPECT_TRUE(fd.IsOpen());
   std::string FileSize;
   strprintf(FileSize, "%llu", fd.FileSize());

   {
      Hashes hashes;
      hashes.AddFD(fd.Fd());
      HashStringList list = hashes.GetHashStringList();
      EXPECT_FALSE(list.empty());
      EXPECT_EQ(5u, list.size());
      EXPECT_EQ(md5.HashValue(), list.find("MD5Sum")->HashValue());
      EXPECT_EQ(sha1.HashValue(), list.find("SHA1")->HashValue());
      EXPECT_EQ(sha256.HashValue(), list.find("SHA256")->HashValue());
      EXPECT_EQ(sha512.HashValue(), list.find("SHA512")->HashValue());
      EXPECT_EQ(FileSize, list.find("Checksum-FileSize")->HashValue());
   }
   unsigned long long sz = fd.FileSize();
   fd.Seek(0);
   {
      Hashes hashes;
      hashes.AddFD(fd.Fd(), sz);
      HashStringList list = hashes.GetHashStringList();
      EXPECT_FALSE(list.empty());
      EXPECT_EQ(5u, list.size());
      EXPECT_EQ(md5.HashValue(), list.find("MD5Sum")->HashValue());
      EXPECT_EQ(sha1.HashValue(), list.find("SHA1")->HashValue());
      EXPECT_EQ(sha256.HashValue(), list.find("SHA256")->HashValue());
      EXPECT_EQ(sha512.HashValue(), list.find("SHA512")->HashValue());
      EXPECT_EQ(FileSize, list.find("Checksum-FileSize")->HashValue());
   }
   fd.Seek(0);
   {
      Hashes hashes(Hashes::MD5SUM | Hashes::SHA512SUM);
      hashes.AddFD(fd);
      HashStringList list = hashes.GetHashStringList();
      EXPECT_FALSE(list.empty());
      EXPECT_EQ(3u, list.size());
      EXPECT_EQ(md5.HashValue(), list.find("MD5Sum")->HashValue());
      EXPECT_EQ(NULL, list.find("SHA1"));
      EXPECT_EQ(NULL, list.find("SHA256"));
      EXPECT_EQ(sha512.HashValue(), list.find("SHA512")->HashValue());
      EXPECT_EQ(FileSize, list.find("Checksum-FileSize")->HashValue());
      fd.Seek(0);
      Hashes hashes2(list);
      hashes2.AddFD(fd);
      list = hashes2.GetHashStringList();
      EXPECT_FALSE(list.empty());
      EXPECT_EQ(3u, list.size());
      EXPECT_EQ(md5.HashValue(), list.find("MD5Sum")->HashValue());
      EXPECT_EQ(NULL, list.find("SHA1"));
      EXPECT_EQ(NULL, list.find("SHA256"));
      EXPECT_EQ(sha512.HashValue(), list.find("SHA512")->HashValue());
      EXPECT_EQ(FileSize, list.find("Checksum-FileSize")->HashValue());
   }
   fd.Seek(0);
   {
      Hashes MD5(Hashes::MD5SUM);
      MD5.AddFD(fd.Fd());
      EXPECT_EQ(md5, MD5.GetHashString(Hashes::MD5SUM));
   }
   fd.Seek(0);
   {
      Hashes SHA1(Hashes::SHA1SUM);
      SHA1.AddFD(fd.Fd());
      EXPECT_EQ(sha1, SHA1.GetHashString(Hashes::SHA1SUM));
   }
   fd.Seek(0);
   {
      Hashes SHA2(Hashes::SHA256SUM);
      SHA2.AddFD(fd.Fd());
      EXPECT_EQ(sha256, SHA2.GetHashString(Hashes::SHA256SUM));
   }
   fd.Seek(0);
   {
      Hashes SHA2(Hashes::SHA512SUM);
      SHA2.AddFD(fd.Fd());
      EXPECT_EQ(sha512, SHA2.GetHashString(Hashes::SHA512SUM));
   }
   fd.Close();

   HashString sha2file("SHA512", sha512.HashValue());
   EXPECT_TRUE(sha2file.VerifyFile("/etc/os-release"));
   HashString sha2wrong("SHA512", "00000000000");
   EXPECT_FALSE(sha2wrong.VerifyFile("/etc/os-release"));
   EXPECT_EQ(sha2file, sha2file);
   EXPECT_TRUE(sha2file == sha2file);
   EXPECT_NE(sha2file, sha2wrong);
   EXPECT_TRUE(sha2file != sha2wrong);

   HashString sha2big("SHA256", sha256.HashValue());
   EXPECT_TRUE(sha2big.VerifyFile("/etc/os-release"));
   HashString sha2small("sha256:" + sha256.HashValue());
   EXPECT_TRUE(sha2small.VerifyFile("/etc/os-release"));
   EXPECT_EQ(sha2big, sha2small);
   EXPECT_TRUE(sha2big == sha2small);
   EXPECT_FALSE(sha2big != sha2small);

   HashStringList hashes;
   EXPECT_TRUE(hashes.empty());
   EXPECT_TRUE(hashes.push_back(sha2file));
   EXPECT_FALSE(hashes.empty());
   EXPECT_EQ(1u, hashes.size());

   HashStringList wrong;
   EXPECT_TRUE(wrong.push_back(sha2wrong));
   EXPECT_NE(wrong, hashes);
   EXPECT_FALSE(wrong == hashes);
   EXPECT_TRUE(wrong != hashes);

   HashStringList similar;
   EXPECT_TRUE(similar.push_back(sha2big));
   EXPECT_NE(similar, hashes);
   EXPECT_FALSE(similar == hashes);
   EXPECT_TRUE(similar != hashes);

   EXPECT_TRUE(hashes.push_back(sha2big));
   EXPECT_EQ(2u, hashes.size());
   EXPECT_TRUE(hashes.push_back(sha2small));
   EXPECT_EQ(2u, hashes.size());
   EXPECT_FALSE(hashes.push_back(sha2wrong));
   EXPECT_EQ(2u, hashes.size());
   EXPECT_TRUE(hashes.VerifyFile("/etc/os-release"));

   EXPECT_EQ(similar, hashes);
   EXPECT_TRUE(similar == hashes);
   EXPECT_FALSE(similar != hashes);
   similar.clear();
   EXPECT_TRUE(similar.empty());
   EXPECT_EQ(0u, similar.size());
   EXPECT_NE(similar, hashes);
   EXPECT_FALSE(similar == hashes);
   EXPECT_TRUE(similar != hashes);
}
TEST(HashSumsTest, UnavailableDigestFailsVerify)
{
   auto const file = createTemporaryFile("unavailable", "abc");
   HashStringList expected;
   EXPECT_TRUE(expected.push_back(HashString("SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
   EXPECT_TRUE(expected.FileSize(3));
   EXPECT_TRUE(expected.usable());
   EXPECT_TRUE(expected.VerifyFile(file.Name()));

   // OpenSSL cannot provide SHA256, so apt cannot check the one hash it has
   failDigestInit = true;
   bool const verified = expected.VerifyFile(file.Name());
   failDigestInit = false;
   EXPECT_FALSE(verified);
   EXPECT_TRUE(_error->empty());
   EXPECT_EQ(0u, ERR_peek_error());
}
TEST(HashSumsTest, FailingDigestUpdate)
{
   Hashes hashes(Hashes::SHA256SUM);
   EXPECT_TRUE(hashes.Add("abc"));

   auto const file = createTemporaryFile("failingupdate", "abc");
   FileFd fd(file.Name(), FileFd::ReadOnly);
   failDigestUpdate = true;
   bool const added = hashes.Add("abc");
   failDigestUpdate = false;
   EXPECT_FALSE(added);
   expectReportedFailure("SHA256");

   failDigestUpdate = true;
   bool const addedFD = hashes.AddFD(fd);
   failDigestUpdate = false;
   EXPECT_FALSE(addedFD);
   expectReportedFailure("SHA256");
   // rejected data is not counted as hashed bytes.
   EXPECT_EQ(3u, hashes.GetHashStringList().FileSize());
}
TEST(HashSumsTest, FailingDigestFinal)
{
   std::string const abc256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
   Hashes hashes(Hashes::SHA256SUM);
   EXPECT_TRUE(hashes.Add("abc"));
   EXPECT_EQ(abc256, hashes.GetHashString(Hashes::SHA256SUM).HashValue());

   failDigestCopy = true;
   HashString const failedCopy = hashes.GetHashString(Hashes::SHA256SUM);
   failDigestCopy = false;
   EXPECT_EQ("", failedCopy.HashValue());
   expectReportedFailure("SHA256");

   failDigestFinal = true;
   HashStringList const failedFinal = hashes.GetHashStringList();
   failDigestFinal = false;
   EXPECT_EQ(nullptr, failedFinal.find("SHA256"));
   EXPECT_EQ(3u, failedFinal.FileSize());
   expectReportedFailure("SHA256");

   // the failures were on copies, the digest itself is intact
   EXPECT_EQ(abc256, hashes.GetHashString(Hashes::SHA256SUM).HashValue());
}
/* A failure in hashing is allowed to remove only the error stack entries it
   raised, not those that were there before. Whatever was on the OpenSSL error
   stack before the failed hashing call was pushed by something else, e.g. TLS
   in the same process, or a hashing call that did not handle its errors.
   This test verifies that Write() and HexDigest() remove only the records
   from the failed call. */
TEST(HashSumsTest, FailureLeavesOlderErrorsOnQueue)
{
   Hashes hashes(Hashes::SHA256SUM);
   EXPECT_TRUE(hashes.Add("abc"));

   // a record from someone else, distinct from what the stand-ins push
   ERR_put_error(ERR_LIB_SYS, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
   unsigned long remaining = ERR_peek_last_error();
   failDigestUpdate = true;
   bool const added = hashes.Add("abc");
   failDigestUpdate = false;
   EXPECT_FALSE(added);
   expectReportedFailure("SHA256", remaining);
   // the record was the test's own, clear it before next test
   ERR_clear_error();

   ERR_put_error(ERR_LIB_SYS, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
   remaining = ERR_peek_last_error();
   failDigestCopy = true;
   HashString const failedCopy = hashes.GetHashString(Hashes::SHA256SUM);
   failDigestCopy = false;
   EXPECT_EQ("", failedCopy.HashValue());
   expectReportedFailure("SHA256", remaining);
   ERR_clear_error();

   ERR_put_error(ERR_LIB_SYS, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
   remaining = ERR_peek_last_error();
   failDigestFinal = true;
   HashString const failedFinal = hashes.GetHashString(Hashes::SHA256SUM);
   failDigestFinal = false;
   EXPECT_EQ("", failedFinal.HashValue());
   expectReportedFailure("SHA256", remaining);
   ERR_clear_error();
}
TEST(HashSumsTest, HashStringList)
{
   _config->Clear("Acquire::ForceHash");

   HashStringList list;
   EXPECT_TRUE(list.empty());
   EXPECT_FALSE(list.usable());
   EXPECT_EQ(0u, list.size());
   EXPECT_EQ(NULL, list.find(NULL));
   EXPECT_EQ(NULL, list.find(""));
   EXPECT_EQ(NULL, list.find("MD5Sum"));
   EXPECT_EQ(NULL, list.find("ROT26"));
   EXPECT_EQ(NULL, list.find("SHA1"));
   EXPECT_EQ(0u, list.FileSize());

   // empty lists aren't equal
   HashStringList list2;
   EXPECT_FALSE(list == list2);
   EXPECT_TRUE(list != list2);

   // some hashes don't really contribute to usability
   list.push_back(HashString("Checksum-FileSize", "29"));
   EXPECT_FALSE(list.empty());
   EXPECT_FALSE(list.usable());
   EXPECT_EQ(1u, list.size());
   EXPECT_EQ(29u, list.FileSize());
   list.push_back(HashString("MD5Sum", "d41d8cd98f00b204e9800998ecf8427e"));
   EXPECT_FALSE(list.empty());
   EXPECT_FALSE(list.usable());
   EXPECT_EQ(2u, list.size());
   EXPECT_EQ(29u, list.FileSize());
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   list.push_back(HashString("SHA1", "cacecbd74968bc90ea3342767e6b94f46ddbcafc"));
   EXPECT_FALSE(list.usable());
   EXPECT_EQ(3u, list.size());
   EXPECT_EQ(29u, list.FileSize());
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   EXPECT_TRUE(NULL != list.find("SHA1"));
   list.push_back(HashString("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
   EXPECT_TRUE(list.usable());
   EXPECT_EQ(4u, list.size());
   EXPECT_EQ(29u, list.FileSize());
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   EXPECT_TRUE(NULL != list.find("SHA1"));
   EXPECT_TRUE(NULL != list.find("SHA256"));

   Hashes hashes;
   hashes.Add("The quick brown fox jumps over the lazy dog");
   list = hashes.GetHashStringList();
   EXPECT_FALSE(list.empty());
   EXPECT_TRUE(list.usable());
   EXPECT_EQ(5u, list.size());
   EXPECT_TRUE(NULL != list.find(NULL));
   EXPECT_TRUE(NULL != list.find(""));
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   EXPECT_TRUE(NULL != list.find("Checksum-FileSize"));
   EXPECT_TRUE(NULL == list.find("ROT26"));

   _config->Set("Acquire::ForceHash", "MD5Sum");
   EXPECT_FALSE(list.empty());
   EXPECT_TRUE(list.usable());
   EXPECT_EQ(5u, list.size());
   EXPECT_TRUE(NULL != list.find(NULL));
   EXPECT_TRUE(NULL != list.find(""));
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   EXPECT_TRUE(NULL != list.find("Checksum-FileSize"));
   EXPECT_TRUE(NULL == list.find("ROT26"));

   _config->Set("Acquire::ForceHash", "ROT26");
   EXPECT_FALSE(list.empty());
   EXPECT_FALSE(list.usable());
   EXPECT_EQ(5u, list.size());
   EXPECT_TRUE(NULL == list.find(NULL));
   EXPECT_TRUE(NULL == list.find(""));
   EXPECT_TRUE(NULL != list.find("MD5Sum"));
   EXPECT_TRUE(NULL != list.find("Checksum-FileSize"));
   EXPECT_TRUE(NULL == list.find("ROT26"));

   _config->Clear("Acquire::ForceHash");

   list2.push_back(*list.find("MD5Sum"));
   EXPECT_TRUE(list == list2);
   EXPECT_FALSE(list != list2);

   // introduce a mismatch to the list
   list2.push_back(HashString("SHA1", "cacecbd74968bc90ea3342767e6b94f46ddbcafc"));
   EXPECT_FALSE(list == list2);
   EXPECT_TRUE(list != list2);

   _config->Set("Acquire::ForceHash", "MD5Sum");
   EXPECT_TRUE(list == list2);
   EXPECT_FALSE(list != list2);

   _config->Clear("Acquire::ForceHash");
}
