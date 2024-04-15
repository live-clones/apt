#ifndef APT_PRIVATE_OUTPUT_H
#define APT_PRIVATE_OUTPUT_H

#include <apt-pkg/cacheset.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/pkgcache.h>

#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

// forward declaration
class pkgCacheFile;
class CacheFile;
class pkgDepCache;
class pkgRecords;


APT_PUBLIC extern std::ostream c0out;
APT_PUBLIC extern std::ostream c1out;
APT_PUBLIC extern std::ostream c2out;
APT_PUBLIC extern std::ofstream devnull;
APT_PUBLIC extern unsigned int ScreenWidth;

APT_PUBLIC bool InitOutput(std::basic_streambuf<char> * const out = std::cout.rdbuf());

void ListSingleVersion(pkgCacheFile &CacheFile, pkgRecords &records,
                       pkgCache::VerIterator const &V, std::ostream &out,
                       std::string const &format);


// helper to describe global state
APT_PUBLIC void ShowBroken(std::ostream &out, CacheFile &Cache, bool const Now);
APT_PUBLIC void ShowBroken(std::ostream &out, pkgCacheFile &Cache, bool const Now);

APT_PUBLIC void ShowWithColumns(std::ostream &out, const std::vector<std::string> &List, size_t Indent, size_t ScreenWidth);

template<class T0, class... Ts> constexpr bool is_same_as_one_of = std::disjunction_v<std::is_same<T0, Ts>...>;
template<class T> constexpr bool is_a_string_type = is_same_as_one_of<T, std::string, char const*>;
template<class Container, class PredicateC, class DisplayP, class DisplayV> bool ShowList(std::ostream &out, std::string const &Title,
      Container const &cont,
      PredicateC Predicate,
      DisplayP PkgDisplay,
      DisplayV VerboseDisplay,
      std::string colorName = "APT::Color::Neutral")
{
   size_t const ScreenWidth = (::ScreenWidth > 3) ? ::ScreenWidth - 3 : 0;
   size_t ScreenUsed = 0;
   bool const ShowVersions = _config->FindB("APT::Get::Show-Versions", false);
   bool const ShowDetails = ShowVersions || not is_a_string_type<std::decay_t<decltype(VerboseDisplay({}))>>;
   bool const ListColumns = _config->FindB("APT::Get::List-Columns", _config->FindI("APT::Output-Version") >= 30);
   bool printedTitle = false;
   std::vector<std::string> PackageList;

   auto setColor = _config->FindI("APT::Output-Version") >= 30 ? _config->Find(colorName) : "";
   auto resetColor = _config->FindI("APT::Output-Version") >= 30 ? _config->Find("APT::Color::Neutral") : "";

   for (auto const &Pkg: cont)
   {
      if (Predicate(Pkg) == false)
	 continue;

      if (printedTitle == false)
      {
	 out << Title;
	 printedTitle = true;
      }

      std::string details;
      if (ShowDetails)
      {
	 auto const verbose = VerboseDisplay(Pkg);
	 if constexpr (is_a_string_type<std::decay_t<decltype(VerboseDisplay({}))>>)
	    details = std::move(verbose);
	 else
	 {
	    if (ShowVersions && not verbose.first.empty())
	       details = verbose.first;
	    if (not verbose.second.empty())
	    {
	       if (details.empty())
		  details = verbose.second;
	       else
		  details.append(", ").append(verbose.second);
	    }
	 }
      }
      if (ShowVersions)
      {
	 out << std::endl << "   " << setColor << PkgDisplay(Pkg) << resetColor;
	 if (not details.empty())
	    out << " (" << details << ')';
      }
      else
      {
	 std::string const PkgName = PkgDisplay(Pkg);
	 if (ListColumns)
	    PackageList.push_back(PkgName);
	 else
	 {
	    auto infoLen = PkgName.length();
	    if (not details.empty())
	       infoLen += details.length() + 3;
	    if (ScreenUsed == 0 || (ScreenUsed + infoLen) >= ScreenWidth)
	    {
	       out << std::endl
		   << "  ";
	       ScreenUsed = 0;
	    }
	    else if (ScreenUsed != 0)
	    {
	       out << " ";
	       ++ScreenUsed;
	    }
	    out << setColor << PkgName << resetColor;
	    if (not details.empty())
	       out << " (" << details << ')';
	    ScreenUsed += infoLen;
	 }
      }
   }

   if (printedTitle == true)
   {
      out << std::endl;
      if (ListColumns && not PackageList.empty()) {
	 out << setColor;
	 ShowWithColumns(out, PackageList, 2, ScreenWidth);
	 out << resetColor;
      }
      if (_config->FindI("APT::Output-Version") >= 30)
	 out << std::endl;
      return false;
   }
   return true;
}


struct PrettyFullNameWithDue
{
   std::map<map_id_t, pkgCache::PkgIterator> due;
   char const * const msgformat;
   explicit PrettyFullNameWithDue(char const * msgstr);
   std::string operator() (pkgCache::PkgIterator const &Pkg) const;
};
struct RenameDelNewData
{
   APT::PackageVector New, Del, NewName;
   PrettyFullNameWithDue Renames;

   RenameDelNewData(CacheFile &Cache, bool ShowRenames);
};
void ShowAutoRemove(std::ostream &out, CacheFile &Cache, unsigned long autoRemoveCount);
void ShowNew(std::ostream &out, CacheFile &Cache, RenameDelNewData const &data);
void ShowExtraPackages(std::ostream &out, CacheFile &Cache, APT::VersionVector const &explicitInst);
void ShowDel(std::ostream &out, CacheFile &Cache, RenameDelNewData const &data);
void ShowRenames(std::ostream &out, CacheFile &Cache, RenameDelNewData const &data);
void ShowKept(std::ostream &out,CacheFile &Cache, APT::PackageVector const &HeldBackPackages);
void ShowPhasing(std::ostream &out, CacheFile &Cache, APT::PackageVector const &HeldBackPackages);
void ShowUpgraded(std::ostream &out,CacheFile &Cache);
bool ShowDowngraded(std::ostream &out,CacheFile &Cache);
bool ShowHold(std::ostream &out,CacheFile &Cache);

bool ShowEssential(std::ostream &out,CacheFile &Cache);

void Stats(std::ostream &out, pkgDepCache &Dep, APT::PackageVector const &HeldBackPackages);

// prompting
APT_PUBLIC bool YnPrompt(char const *const Question, bool Default = true);
bool YnPrompt(char const * const Question, bool const Default, bool const ShowGlobalErrors, std::ostream &c1o, std::ostream &c2o);

APT_PUBLIC std::string PrettyFullName(pkgCache::PkgIterator const &Pkg);
std::string CandidateVersion(pkgCacheFile * const Cache, pkgCache::PkgIterator const &Pkg);
std::string CurrentToCandidateVersion(pkgCacheFile * const Cache, pkgCache::PkgIterator const &Pkg);
std::string EmptyString(pkgCache::PkgIterator const &);
bool AlwaysTrue(pkgCache::PkgIterator const &);

#endif
