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
#include <string>
#include <unistd.h>

#include <openssl/evp.h>
									/*}}}*/

static const constexpr struct HashAlgo
{
   const char *name;
   const EVP_MD *(*evpLink)(void);
   Hashes::SupportedHashes ourAlgo;
} Algorithms[] = {
   {"MD5Sum", EVP_md5, Hashes::MD5SUM},
   {"SHA1", EVP_sha1, Hashes::SHA1SUM},
   {"SHA256", EVP_sha256, Hashes::SHA256SUM},
   {"SHA512", EVP_sha512, Hashes::SHA512SUM},
};

const char * HashString::_SupportedHashes[] =
{
   "SHA512", "SHA256", "SHA1", "MD5Sum", "Checksum-FileSize", NULL
};
std::vector<HashString::HashSupportInfo> HashString::SupportedHashesInfo()
{
   return {{
      { "SHA512",  pkgTagSection::Key::SHA512,"Checksums-Sha512", pkgTagSection::Key::Checksums_Sha512},
      { "SHA256", pkgTagSection::Key::SHA256, "Checksums-Sha256", pkgTagSection::Key::Checksums_Sha256},
      { "SHA1", pkgTagSection::Key::SHA1, "Checksums-Sha1", pkgTagSection::Key::Checksums_Sha1 },
      { "MD5Sum", pkgTagSection::Key::MD5sum, "Files", pkgTagSection::Key::Files },
   }};
}

HashString::HashString()
{
}

HashString::HashString(std::string Type, std::string Hash) : Type(Type), Hash(Hash)
{
}

#if APT_PKG_ABI > 600
HashString::HashString(std::string_view StringedHash)			/*{{{*/
#else
HashString::HashString(std::string StringedHash)        /*{{{*/
#endif
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
std::string HashString::GetHashForFile(std::string filename) const      /*{{{*/
{
   std::string fileHash;

   FileFd Fd(filename, FileFd::ReadOnly);
   if(strcasecmp(Type.c_str(), "MD5Sum") == 0)
   {
      Hashes MD5(Hashes::MD5SUM);
      MD5.AddFD(Fd);
      fileHash = MD5.GetHashString(Hashes::MD5SUM).Hash;
   }
   else if (strcasecmp(Type.c_str(), "SHA1") == 0)
   {
      Hashes SHA1(Hashes::SHA1SUM);
      SHA1.AddFD(Fd);
      fileHash = SHA1.GetHashString(Hashes::SHA1SUM).Hash;
   }
   else if (strcasecmp(Type.c_str(), "SHA256") == 0)
   {
      Hashes SHA256(Hashes::SHA256SUM);
      SHA256.AddFD(Fd);
      fileHash = SHA256.GetHashString(Hashes::SHA256SUM).Hash;
   }
   else if (strcasecmp(Type.c_str(), "SHA512") == 0)
   {
      Hashes SHA512(Hashes::SHA512SUM);
      SHA512.AddFD(Fd);
      fileHash = SHA512.GetHashString(Hashes::SHA512SUM).Hash;
   }
   else if (strcasecmp(Type.c_str(), "Checksum-FileSize") == 0)
      strprintf(fileHash, "%llu", Fd.FileSize());
   Fd.Close();

   return fileHash;
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

// PrivateHashes							/*{{{*/
class PrivateHashes {
public:
   unsigned long long FileSize;
   std::array<EVP_MD_CTX *, APT_ARRAY_SIZE(Algorithms)> contexts{};

   explicit PrivateHashes(unsigned int const CalcHashes) : FileSize(0)
   {
      for (size_t i = 0; i < APT_ARRAY_SIZE(Algorithms); ++i)
      {
	 if ((CalcHashes & Algorithms[i].ourAlgo) == Algorithms[i].ourAlgo)
	 {
	    contexts[i] = EVP_MD_CTX_new();
	    if (contexts[i] == nullptr)
	       continue;
	    if (not EVP_DigestInit_ex(contexts[i], Algorithms[i].evpLink(), NULL))
	       EVP_MD_CTX_destroy(contexts[i]), contexts[i] = nullptr;
	 }
      }
   }

   explicit PrivateHashes(HashStringList const &Hashes) : FileSize(0) {
      for (size_t i = 0; i < APT_ARRAY_SIZE(Algorithms); ++i)
      {
	 if (not Hashes.usable() || Hashes.find(Algorithms[i].name) != NULL)
	 {
	    contexts[i] = EVP_MD_CTX_new();
	    if (contexts[i] == nullptr)
	       continue;
	    if (not EVP_DigestInit_ex(contexts[i], Algorithms[i].evpLink(), NULL))
	       EVP_MD_CTX_destroy(contexts[i]), contexts[i] = nullptr;
	 }
      }
   }
   ~PrivateHashes()
   {
      for (auto ctx : contexts)
	 if (ctx != nullptr)
	    EVP_MD_CTX_free(ctx);
   }
};
									/*}}}*/
// Hashes::Add* - Add the contents of data or FD			/*{{{*/
bool Hashes::Add(const unsigned char * const Data, unsigned long long const Size)
{
   if (Size != 0)
   {
      for (size_t i = 0; i < APT_ARRAY_SIZE(Algorithms); ++i)
	 if (d->contexts[i] && not EVP_DigestUpdate(d->contexts[i], Data, Size))
	    return _error->Error("Could not update digest %s", Algorithms[i].name);

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

static APT_PURE std::string HexDigest(EVP_MD_CTX *context, size_t algo)
{
   char Conv[16] =
      {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
       'c', 'd', 'e', 'f'};

   int Size = EVP_MD_size(Algorithms[algo].evpLink());
   assert(Size <= 512/8);
   char Result[((Size)*2) + 1];
   unsigned char Sum[Size];
   Result[(Size)*2] = 0;

   // We need to work on a copy, as we update the hash after creating a digest...
   auto tmpContext = EVP_MD_CTX_create();
   EVP_MD_CTX_copy(tmpContext, context);
   EVP_DigestFinal_ex(tmpContext, Sum, nullptr);
   EVP_MD_CTX_destroy(tmpContext);

   // Convert each char into two letters
   size_t J = 0;
   size_t I = 0;
   for (; I != (Size)*2; J++, I += 2)
   {
      Result[I] = Conv[Sum[J] >> 4];
      Result[I + 1] = Conv[Sum[J] & 0xF];
   }
   return std::string(Result);
};

HashStringList Hashes::GetHashStringList()
{
   HashStringList hashes;
   for (size_t i = 0; i < d->contexts.size(); ++i)
      if (d->contexts[i])
	 hashes.push_back(HashString(Algorithms[i].name, HexDigest(d->contexts[i], i)));
   hashes.FileSize(d->FileSize);

   return hashes;
}

HashString Hashes::GetHashString(SupportedHashes hash)
{
   for (size_t i = 0; i < d->contexts.size(); ++i)
      if (hash == Algorithms[i].ourAlgo && d->contexts[i])
	 return HashString(Algorithms[i].name, HexDigest(d->contexts[i], i));

   abort();
}
Hashes::Hashes() : d(new PrivateHashes(~0)) { }
Hashes::Hashes(unsigned int const Hashes) : d(new PrivateHashes(Hashes)) {}
Hashes::Hashes(HashStringList const &Hashes) : d(new PrivateHashes(Hashes)) {}
Hashes::~Hashes() { delete d; }
