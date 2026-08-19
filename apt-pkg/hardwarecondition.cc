// -*- mode: cpp; mode: fold -*-
// Description                                                       /*{{{*/
/* ######################################################################

   Hardware condition evaluation helpers.

   ##################################################################### */
                                                                        /*}}}*/
// Include Files                                                        /*{{{*/
#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hardwarecondition.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <string_view>

#include <fnmatch.h>
                                                                        /*}}}*/

namespace fs = std::filesystem;

namespace
{
std::string NormalizePCIId(std::string_view id)
{
   auto begin = id.find_first_not_of('0');
   if (begin == std::string_view::npos)
      return "0";

   std::string normalized(id.substr(begin));
   std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                  [](unsigned char c) { return std::tolower(c); });
   return normalized;
}

bool MatchPCICondition(std::string const &pattern, std::string_view alias)
{
   if (not alias.starts_with("pci:"))
      return false;

   auto vendorStart = alias.find('v', 4);
   if (vendorStart == std::string_view::npos)
      return false;

   auto deviceStart = alias.find('d', vendorStart + 1);
   if (deviceStart == std::string_view::npos)
      return false;

   auto vendorEnd = deviceStart;
   auto deviceEnd = alias.find("sv", deviceStart + 1);
   if (deviceEnd == std::string_view::npos)
      return false;

   std::string match = NormalizePCIId(alias.substr(vendorStart + 1, vendorEnd - vendorStart - 1)) +
                       ":" + NormalizePCIId(alias.substr(deviceStart + 1, deviceEnd - deviceStart - 1));
   return fnmatch(pattern.c_str(), match.c_str(), 0) == 0;
}
}

namespace APT::HardwareCondition
{
bool Evaluate(std::string_view field)
{
   struct DiscardErrors
   {
      DiscardErrors() { _error->PushToStack(); }
      ~DiscardErrors() { _error->RevertToStack(); }
   } discardErrors;

   // Parse: "<type> <pattern>"
   auto sep = field.find(' ');
   if (sep == std::string_view::npos)
      return true; // Unrecognized format: treat as met

   std::string_view type = field.substr(0, sep);
   std::string pattern(field.substr(sep + 1));

   bool wantMatch = (type == "modalias" || type == "pci");
   if (not wantMatch && type != "modalias-not" && type != "pci-not")
      return true; // Unknown type: treat as met

   std::string sysfsBase = _config->Find("APT::HardwareCondition::SysfsBase", "/sys/bus");

   std::error_code ec;
   fs::directory_iterator const end;
   fs::directory_iterator busDir(sysfsBase, fs::directory_options::skip_permission_denied, ec);
   if (ec)
      return wantMatch ? false : true;

   for (; busDir != end; busDir.increment(ec))
   {
      if (ec)
         break;

      fs::path const busPath = busDir->path();
      if (not busDir->is_directory(ec))
         continue;

      fs::path const devicesPath = busPath / "devices";
      fs::directory_iterator devDir(devicesPath, fs::directory_options::skip_permission_denied, ec);
      if (ec)
      {
         ec.clear();
         continue;
      }

      for (; devDir != end; devDir.increment(ec))
      {
         if (ec)
            break;

         if (not devDir->is_directory(ec))
            continue;

         fs::path const aliasPath = devDir->path() / "modalias";
         FileFd aliasFile(aliasPath.string(), FileFd::ReadOnly);
         if (not aliasFile.IsOpen() || aliasFile.Failed())
            continue;

         std::string alias;
         if (aliasFile.ReadLine(alias))
         {
            bool const aliasMatch = (type == "pci" || type == "pci-not")
                                       ? MatchPCICondition(pattern, alias)
                                       : (fnmatch(pattern.c_str(), alias.c_str(), 0) == 0);
            if (aliasMatch)
               return wantMatch;
         }
      }

      ec.clear();
   }

   return wantMatch ? false : true;
}

bool IsSatisfied(pkgCache::VerIterator const &Ver)
{
   auto const condition = Ver.HardwareCondition();
   if (condition.empty())
      return true;
   return Evaluate(condition);
}
}
