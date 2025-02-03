// Includes								/*{{{*/
#include <config.h>

#include <apt-pkg/cmndline.h>
#include <apt-pkg/cacheset.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/upgrade.h>

#include <apt-private/private-cachefile.h>
#include <apt-private/private-install.h>
#include <apt-private/private-json-hooks.h>
#include <apt-private/private-output.h>
#include <apt-private/private-update.h>
#include <apt-private/private-upgrade.h>

#include <iostream>

#include <apti18n.h>
									/*}}}*/

// this is actually performing the various upgrade operations 
static bool UpgradeHelper(CommandLine &CmdL, int UpgradeFlags)
{
   if (_config->FindB("APT::Update") && not DoUpdate())
      return false;

   CacheFile Cache;
   auto VolatileCmdL = GetPseudoPackages(Cache.GetSourceList(), CmdL, AddVolatileBinaryFile, "");

   if (Cache.OpenForInstall() == false || Cache.CheckDeps() == false)
      return false;

   std::map<unsigned short, APT::VersionVector> verset;
   std::set<std::string> UnknownPackages;
   APT::PackageVector HeldBackPackages;
   if (not DoCacheManipulationFromCommandLine(CmdL, VolatileCmdL, Cache, verset, UpgradeFlags, UnknownPackages, HeldBackPackages))
   {
      RunJsonHook("AptCli::Hooks::Upgrade", "org.debian.apt.hooks.install.fail", CmdL.FileList, Cache, UnknownPackages);
      return false;
   }
   RunJsonHook("AptCli::Hooks::Upgrade", "org.debian.apt.hooks.install.pre-prompt", CmdL.FileList, Cache);
   if (InstallPackages(Cache, HeldBackPackages, true, true, true, "AptCli::Hooks::Upgrade", CmdL))
      return RunJsonHook("AptCli::Hooks::Upgrade", "org.debian.apt.hooks.install.post", CmdL.FileList, Cache);
   else
      return RunJsonHook("AptCli::Hooks::Upgrade", "org.debian.apt.hooks.install.fail", CmdL.FileList, Cache);
}

// DoDistUpgrade - Upgrade all packages				/*{{{*/
// ---------------------------------------------------------------------
/* Upgrade all packages and install and remove packages as needed */
bool DoDistUpgrade(CommandLine &CmdL)
{
   return UpgradeHelper(CmdL, APT::Upgrade::ALLOW_EVERYTHING);
}

// Upgrade - Upgrade all packages, safely				/*}}}*/
// ---------------------------------------------------------------------
/* Upgrade all packages, disallowing installation and/or removal per user-
   specified parameters */
bool DoUpgrade(CommandLine &CmdL)					/*{{{*/
{
   if (_config->FindB("APT::Get::Upgrade-Allow-New", false) == true)
      // If APT::Get::Upgrade-Allow-New is set to `true', then use the
      // DoUpgradeWithAllowNewPackages() method (only installation of new
      // packages is allowed during upgrade).
      return DoUpgradeWithAllowNewPackages(CmdL);
   else
      // Otherwise, use the DoUpgradeNoNewPackages() method (no installation
      // of new packages, nor removal of old packages during upgrade).
      return DoUpgradeNoNewPackages(CmdL);
}
									/*}}}*/
// DoUpgradeNoNewPackages - Upgrade all packages			/*{{{*/
// ---------------------------------------------------------------------
/* Upgrade all packages without installing new packages or removing old
   packages. This is the default method behind `apt/apt-get upgrade'. */
bool DoUpgradeNoNewPackages(CommandLine &CmdL)
{
   // Do the upgrade
   return UpgradeHelper(CmdL, 
                        APT::Upgrade::FORBID_REMOVE_PACKAGES|
                        APT::Upgrade::FORBID_INSTALL_NEW_PACKAGES);
}
									/*}}}*/
// DoUpgradeWithAllowNewPackages - Upgrade all packages, allow only	/*{{{*/
// install but not remove						/*{{{*/
bool DoUpgradeWithAllowNewPackages(CommandLine &CmdL)
{
   return UpgradeHelper(CmdL, APT::Upgrade::FORBID_REMOVE_PACKAGES);
}
									/*}}}*/
