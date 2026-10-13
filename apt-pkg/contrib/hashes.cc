// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   Hashes - Simple wrapper around the hash functions

   This is just used to make building the methods simpler, this is the
   only interface required..

   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>
#include <apt-pkg/tagfile-keys.h>
#include <apt-pkg/tagfile.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <apti18n.h>
									/*}}}*/

HashString::HashString()
{
}

HashString::HashString(std::string Type, std::string Hash) : Type(Type), Hash(Hash)
{
}

HashString::HashString(std::string_view StringedHash)			/*{{{*/
{
   if (StringedHash.find(":") == std::string::npos)
   {
      // legacy: md5sum without "MD5Sum:" prefix
      if (StringedHash.size() == 32)
      {
	 Type = "MD5Sum";
	 Hash = StringedHash;
      }
      if(_config->FindB("Debug::Hashes",false) == true)
	 std::clog << "HashString(string): invalid StringedHash " << StringedHash << std::endl;
      return;
   }
   auto pos = StringedHash.find(":");
   Type = StringedHash.substr(0,pos);
   Hash = StringedHash.substr(pos+1, StringedHash.size() - pos);

   if(_config->FindB("Debug::Hashes",false) == true)
      std::clog << "HashString(string): " << Type << " : " << Hash << std::endl;
}
									/*}}}*/
bool HashString::VerifyFile(std::string filename) const			/*{{{*/
{
   std::string fileHash = GetHashForFile(filename);

   if(_config->FindB("Debug::Hashes",false) == true)
      std::clog << "HashString::VerifyFile: got: " << fileHash << " expected: " << toStr() << std::endl;

   return (fileHash == Hash);
}
									/*}}}*/
bool HashString::FromFile(std::string filename)          		/*{{{*/
{
   // pick the strongest hash
   if (Type == "")
      Type = _SupportedHashes[0];

   Hash = GetHashForFile(filename);
   return true;
}
									/*}}}*/
const char** HashString::SupportedHashes()				/*{{{*/
{
   return _SupportedHashes;
}
									/*}}}*/
APT_PURE bool HashString::empty() const					/*{{{*/
{
   return (Type.empty() || Hash.empty());
}
									/*}}}*/

APT_PURE static bool IsConfigured(const char *name, const char *what)
{
   std::string option;
   strprintf(option, "APT::Hashes::%s::%s", name, what);
   return _config->FindB(option, false);
}

APT_PURE bool HashString::usable() const				/*{{{*/
{
   return (
      (Type != "Checksum-FileSize") &&
      (Type != "MD5Sum") &&
      (Type != "SHA1") &&
      !IsConfigured(Type.c_str(), "Untrusted")
   );
}
									/*}}}*/
std::string HashString::toStr() const					/*{{{*/
{
   return Type + ":" + Hash;
}
									/*}}}*/
APT_PURE bool HashString::operator==(HashString const &other) const	/*{{{*/
{
   return (strcasecmp(Type.c_str(), other.Type.c_str()) == 0 && Hash == other.Hash);
}
APT_PURE bool HashString::operator!=(HashString const &other) const
{
   return !(*this == other);
}
									/*}}}*/

bool HashStringList::usable() const					/*{{{*/
{
   if (empty() == true)
      return false;
   std::string const forcedType = _config->Find("Acquire::ForceHash", "");
   if (forcedType.empty() == true)
   {
      // See if there is at least one usable hash
      return std::any_of(list.begin(), list.end(), [](auto const &hs) { return hs.usable(); });
   }
   return find(forcedType) != NULL;
}
									/*}}}*/
HashString const * HashStringList::find(char const * const type) const /*{{{*/
{
   if (type == NULL || type[0] == '\0')
   {
      std::string const forcedType = _config->Find("Acquire::ForceHash", "");
      if (forcedType.empty() == false)
	 return find(forcedType.c_str());
      for (char const * const * t = HashString::SupportedHashes(); *t != NULL; ++t)
	 for (std::vector<HashString>::const_iterator hs = list.begin(); hs != list.end(); ++hs)
	    if (strcasecmp(hs->HashType().c_str(), *t) == 0)
	       return &*hs;
      return NULL;
   }
   for (std::vector<HashString>::const_iterator hs = list.begin(); hs != list.end(); ++hs)
      if (strcasecmp(hs->HashType().c_str(), type) == 0)
	 return &*hs;
   return NULL;
}
									/*}}}*/
unsigned long long HashStringList::FileSize() const			/*{{{*/
{
   HashString const * const hsf = find("Checksum-FileSize");
   if (hsf == NULL)
      return 0;
   std::string const hv = hsf->HashValue();
   return strtoull(hv.c_str(), NULL, 10);
}
									/*}}}*/
bool HashStringList::FileSize(unsigned long long const Size)		/*{{{*/
{
   return push_back(HashString("Checksum-FileSize", std::to_string(Size)));
}
									/*}}}*/
bool HashStringList::supported(char const * const type)			/*{{{*/
{
   for (char const * const * t = HashString::SupportedHashes(); *t != NULL; ++t)
      if (strcasecmp(*t, type) == 0)
	 return true;
   return false;
}
									/*}}}*/
bool HashStringList::push_back(const HashString &hashString)		/*{{{*/
{
   if (hashString.HashType().empty() == true ||
	 hashString.HashValue().empty() == true ||
	 supported(hashString.HashType().c_str()) == false)
      return false;

   // ensure that each type is added only once
   HashString const * const hs = find(hashString.HashType().c_str());
   if (hs != NULL)
      return *hs == hashString;

   list.push_back(hashString);
   return true;
}
									/*}}}*/
bool HashStringList::VerifyFile(std::string filename) const		/*{{{*/
{
   if (usable() == false)
      return false;

   Hashes hashes(*this);
   FileFd file(filename, FileFd::ReadOnly);
   HashString const * const hsf = find("Checksum-FileSize");
   if (hsf != NULL)
   {
      std::string fileSize;
      strprintf(fileSize, "%llu", file.FileSize());
      if (hsf->HashValue() != fileSize)
	 return false;
   }
   hashes.AddFD(file);
   HashStringList const hsl = hashes.GetHashStringList();
   // operator== skips types only one side has, so a list without any usable
   // hash (OpenSSL could not provide it) would match on the file size alone
   if (hsl.usable() == false)
      return false;
   return hsl == *this;
}
									/*}}}*/
bool HashStringList::operator==(HashStringList const &other) const	/*{{{*/
{
   std::string const forcedType = _config->Find("Acquire::ForceHash", "");
   if (forcedType.empty() == false)
   {
      HashString const * const hs = find(forcedType);
      HashString const * const ohs = other.find(forcedType);
      if (hs == NULL || ohs == NULL)
	 return false;
      return *hs == *ohs;
   }
   short matches = 0;
   for (const_iterator hs = begin(); hs != end(); ++hs)
   {
      HashString const * const ohs = other.find(hs->HashType());
      if (ohs == NULL)
	 continue;
      if (*hs != *ohs)
	 return false;
      ++matches;
   }
   if (matches == 0)
      return false;
   return true;
}
bool HashStringList::operator!=(HashStringList const &other) const
{
   return !(*this == other);
}
									/*}}}*/
static APT_PURE std::string HexDigest(std::span<unsigned char> const &Sum)
{
   char Conv[16] =
      {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
       'c', 'd', 'e', 'f'};
   std::string Result(Sum.size() * 2, 0);

   // Convert each char into two letters
   size_t J = 0;
   size_t I = 0;
   for (; I != (Sum.size()) * 2; J++, I += 2)
   {
      Result[I] = Conv[Sum[J] >> 4];
      Result[I + 1] = Conv[Sum[J] & 0xF];
   }
   return Result;
};

// Report an OpenSSL failure through _error with the reason of the newest
// record on the thread's error queue. The caller removes only the records
// the failed call raised so nothing older on the queue is lost.
static void ReportOpenSSLError(char const *const algo)
{
   auto const err = ERR_peek_last_error();
   char const *const reason = err == 0 ? nullptr : ERR_reason_error_string(err);
   _error->Error(_("Computing the %s hash failed: %s"), algo, reason == nullptr ? "unknown error" : reason);
}

// PrivateHashes							/*{{{*/
class PrivateHashes
{
   public:
   unsigned long long FileSize{0};

   private:
   std::array<EVP_MD_CTX *, 6> contexts{};

   public:
   struct HashAlgo
   {
      size_t index;
      const char *name;
      const EVP_MD *(*evpLink)(void);
      Hashes::SupportedHashes ourAlgo;
      pkgTagSection::Key namekey;
      const char *chksumsname;
      pkgTagSection::Key chksumskey;
   };

   // Ordered strongest first: _SupportedHashes and SupportedHashesInfo()
   // are built from this order and their readers rely on it.
   static constexpr std::array<HashAlgo, 6> Algorithms{
      HashAlgo{0, "SHA3-512", EVP_sha3_512, Hashes::SHA3_512SUM, pkgTagSection::Key::SHA3_512, "Checksums-Sha3-512", pkgTagSection::Key::Checksums_Sha3_512},
      HashAlgo{1, "SHA3-256", EVP_sha3_256, Hashes::SHA3_256SUM, pkgTagSection::Key::SHA3_256, "Checksums-Sha3-256", pkgTagSection::Key::Checksums_Sha3_256},
      HashAlgo{2, "SHA512", EVP_sha512, Hashes::SHA512SUM, pkgTagSection::Key::SHA512, "Checksums-Sha512", pkgTagSection::Key::Checksums_Sha512},
      HashAlgo{3, "SHA256", EVP_sha256, Hashes::SHA256SUM, pkgTagSection::Key::SHA256, "Checksums-Sha256", pkgTagSection::Key::Checksums_Sha256},
      HashAlgo{4, "SHA1", EVP_sha1, Hashes::SHA1SUM, pkgTagSection::Key::SHA1, "Checksums-Sha1", pkgTagSection::Key::Checksums_Sha1},
      HashAlgo{5, "MD5Sum", EVP_md5, Hashes::MD5SUM, pkgTagSection::Key::MD5sum, "Files", pkgTagSection::Key::Files},
   };

   bool Write(unsigned char const *Data, size_t Size)
   {
      ERR_set_mark();
      DEFER([] { ERR_pop_to_mark(); });
      for (auto const &algo : Algorithms)
      {
	 auto const context = contexts[algo.index];
	 if (context != nullptr && EVP_DigestUpdate(context, Data, Size) != 1)
	 {
	    ReportOpenSSLError(algo.name);
	    return false;
	 }
      }
      return true;
   }

   std::string HexDigest(HashAlgo const &algo)
   {
      // The digest may be unavailable, e.g. MD5 under an OpenSSL FIPS provider.
      // Enable() then left the context nullptr and EVP_MD_CTX_copy() below would
      // dereference it, so bail out with an empty digest instead of crashing.
      if (contexts[algo.index] == nullptr)
	 return std::string();

      ERR_set_mark();
      DEFER([] { ERR_pop_to_mark(); });
      auto Size = EVP_MD_size(algo.evpLink());
      unsigned char Sum[Size];

      // We need to work on a copy, as we update the hash after creating a digest...
      auto tmpContext = EVP_MD_CTX_create();
      if (tmpContext == nullptr)
      {
	 ReportOpenSSLError(algo.name);
	 return std::string();
      }
      bool const finished = EVP_MD_CTX_copy(tmpContext, contexts[algo.index]) == 1 &&
			    EVP_DigestFinal_ex(tmpContext, Sum, nullptr) == 1;
      EVP_MD_CTX_destroy(tmpContext);
      if (not finished)
      {
	 ReportOpenSSLError(algo.name);
	 return std::string();
      }

      return ::HexDigest(std::span<unsigned char>(Sum, Size));
   }

   bool Enable(HashAlgo const &algo)
   {
      // Discard errors from disabled algorithms.
      // SECURITY: Enabling a digest may fail. If no secure digests are available,
      // security is not compromised.
      ERR_set_mark();
      DEFER([] { ERR_pop_to_mark(); });

      contexts[algo.index] = EVP_MD_CTX_new();
      if (contexts[algo.index] == nullptr)
	 return false;
      if (EVP_DigestInit_ex(contexts[algo.index], algo.evpLink(), NULL))
	 return true;
      EVP_MD_CTX_destroy(contexts[algo.index]);
      contexts[algo.index] = nullptr;
      return false;
   }
   bool IsEnabled(HashAlgo const &algo)
   {
      return contexts[algo.index] != nullptr;
   }

   explicit PrivateHashes() {}
   ~PrivateHashes()
   {
      for (auto ctx : contexts)
	 if (ctx != nullptr)
	    EVP_MD_CTX_free(ctx);
   }

   explicit PrivateHashes(unsigned int const CalcHashes) : PrivateHashes()
   {
      for (auto & Algo : Algorithms)
      {
	 if ((CalcHashes & Algo.ourAlgo) == Algo.ourAlgo)
	    Enable(Algo);
      }
   }

   explicit PrivateHashes(HashStringList const &Hashes) : PrivateHashes()
   {
      for (auto & Algo : Algorithms)
      {
	 if (not Hashes.usable() || Hashes.find(Algo.name) != NULL)
	    Enable(Algo);
      }
   }
};
									/*}}}*/
static_assert(PrivateHashes::Algorithms.size() == 6,
	      "add the new algorithm to _SupportedHashes below");
const char * HashString::_SupportedHashes[] =
{
   PrivateHashes::Algorithms[0].name,
   PrivateHashes::Algorithms[1].name,
   PrivateHashes::Algorithms[2].name,
   PrivateHashes::Algorithms[3].name,
   PrivateHashes::Algorithms[4].name,
   PrivateHashes::Algorithms[5].name,
   "Checksum-FileSize", NULL
};
std::vector<HashString::HashSupportInfo> HashString::SupportedHashesInfo()
{
   std::vector<HashSupportInfo> result;
   result.reserve(PrivateHashes::Algorithms.size());
   for (auto const &algo : PrivateHashes::Algorithms)
      result.push_back({algo.name, algo.namekey, algo.chksumsname, algo.chksumskey});
   return result;
}
std::string HashString::GetHashForFile(std::string filename) const      /*{{{*/
{
   std::string fileHash;

   FileFd Fd(filename, FileFd::ReadOnly);
   if (strcasecmp(Type.c_str(), "Checksum-FileSize") == 0)
      strprintf(fileHash, "%llu", Fd.FileSize());
   else
      for (auto const &Algo : PrivateHashes::Algorithms)
	 if (strcasecmp(Type.c_str(), Algo.name) == 0)
	 {
	    Hashes hashes(Algo.ourAlgo);
	    if (hashes.AddFD(Fd))
	       fileHash = hashes.GetHashString(Algo.ourAlgo).Hash;
	    break;
	 }
   Fd.Close();

   return fileHash;
}
									/*}}}*/
// Hashes::Add* - Add the contents of data or FD			/*{{{*/
bool Hashes::Add(const unsigned char * const Data, unsigned long long const Size)
{
   if (Size != 0)
   {
      if (not d->Write(Data, Size))
	 return false;
      d->FileSize += Size;
   }
   return true;
}
bool Hashes::AddFD(int const Fd,unsigned long long Size)
{
   std::array<unsigned char, APT_BUFFER_SIZE> Buf;
   bool const ToEOF = (Size == UntilEOF);
   while (Size != 0 || ToEOF)
   {
      decltype(Size) n = Buf.size();
      if (!ToEOF) n = std::min(Size, n);
      ssize_t const Res = read(Fd,Buf.data(),n);
      if (Res < 0 || (!ToEOF && Res != (ssize_t) n)) // error, or short read
	 return false;
      if (ToEOF && Res == 0) // EOF
	 break;
      Size -= Res;
      if (Add(Buf.data(), Res) == false)
	 return false;
   }
   return true;
}
bool Hashes::AddFD(FileFd &Fd,unsigned long long Size)
{
   std::array<unsigned char, APT_BUFFER_SIZE> Buf;
   bool const ToEOF = (Size == 0);
   while (Size != 0 || ToEOF)
   {
      decltype(Size) n = Buf.size();
      if (!ToEOF) n = std::min(Size, n);
      decltype(Size) a = 0;
      if (Fd.Read(Buf.data(), n, &a) == false) // error
	 return false;
      if (ToEOF == false)
      {
	 if (a != n) // short read
	    return false;
      }
      else if (a == 0) // EOF
	 break;
      Size -= a;
      if (Add(Buf.data(), a) == false)
	 return false;
   }
   return true;
}
									/*}}}*/

HashStringList Hashes::GetHashStringList()
{
   HashStringList hashes;
   for (auto &Algo : d->Algorithms)
      if (d->IsEnabled(Algo))
	 hashes.push_back(HashString(Algo.name, d->HexDigest(Algo)));
   hashes.FileSize(d->FileSize);

   return hashes;
}

HashString Hashes::GetHashString(SupportedHashes hash)
{
   for (auto &Algo : d->Algorithms)
      if (hash == Algo.ourAlgo)
	 return d->IsEnabled(Algo) ? HashString(Algo.name, d->HexDigest(Algo)) : HashString();

   abort();
}
Hashes::Hashes() : d(new PrivateHashes(~0)) { }
Hashes::Hashes(unsigned int const Hashes) : d(new PrivateHashes(Hashes)) {}
Hashes::Hashes(HashStringList const &Hashes) : d(new PrivateHashes(Hashes)) {}
Hashes::~Hashes() { delete d; }
