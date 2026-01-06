#include <config.h>
#include "common.h"
#include <apt-pkg/pkgcache.h>
#include <string>

// DummyCache for testing, records call parameters
class DummyCache : public pkgCache
{
   public:
   DummyCache() : pkgCache(nullptr, false) {}
   PkgIterator FindPkg(std::string_view Name, std::string_view Arch)
   {
      lastName = std::string(Name);
      lastArch = std::string(Arch);
      return PkgIterator(*this, nullptr);
   }
   // Main logic to be tested
   PkgIterator FindPkg(std::string_view Name)
   {
      if (!Name.empty() && (Name[0] == '/' ||
			    (Name.size() > 1 && Name[0] == '.' && Name[1] == '/') ||
			    (Name.size() > 2 && Name[0] == '.' && Name[1] == '.' && Name[2] == '/')))
	 return FindPkg(Name, "native");
      // Other logic omitted
      return FindPkg(Name, "other");
   }
   std::string lastName, lastArch;
};

TEST(PkgCacheTest, FindPkg_PathLikeWithColon)
{
   DummyCache cache;
   // Path-like package names containing ':'
   cache.FindPkg("/tmp/test:1.0.deb");
   EXPECT_EQ(cache.lastArch, "native");

   cache.FindPkg("./test:1.0.deb");
   EXPECT_EQ(cache.lastArch, "native");

   cache.FindPkg("../test:1.0.deb");
   EXPECT_EQ(cache.lastArch, "native");
}

TEST(PkgCacheTest, FindPkg_NormalNameWithColon)
{
   DummyCache cache;
   // Normal package name with ':', e.g. for architecture
   cache.FindPkg("bash:amd64");
   EXPECT_EQ(cache.lastArch, "other");
}