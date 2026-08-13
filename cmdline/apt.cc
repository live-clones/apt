// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################
   
   apt - CLI UI for apt
   
   Returns 100 on failure, 0 on success.
   
   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/cmndline.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/solver3.h>
#include <apt-pkg/strutl.h>

#include <apt-private/private-cmndline.h>
#include <apt-private/private-depends.h>
#include <apt-private/private-download.h>
#include <apt-private/private-history.h>
#include <apt-private/private-install.h>
#include <apt-private/private-list.h>
#include <apt-private/private-main.h>
#include <apt-private/private-moo.h>
#include <apt-private/private-output.h>
#include <apt-private/private-search.h>
#include <apt-private/private-show.h>
#include <apt-private/private-source.h>
#include <apt-private/private-sources.h>
#include <apt-private/private-update.h>
#include <apt-private/private-upgrade.h>

#include <iostream>
#include <vector>
#include <unistd.h>

#include <apti18n.h>
									/*}}}*/

static bool ShowHelp(CommandLine &)					/*{{{*/
{
   std::cout <<
      _("Usage: apt [options] command\n"
	    "\n"
	    "apt is a commandline package manager and provides commands for\n"
	    "searching and managing as well as querying information about packages.\n"
	    "It provides the same functionality as the specialized APT tools,\n"
	    "like apt-get and apt-cache, but enables options more suitable for\n"
	    "interactive use by default.\n");
   return true;
}
									/*}}}*/

static bool ShowListHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] list [pattern(s)]\n"
		  "\n"
		  "Display packages matching the given names, glob patterns, or\n"
		  "apt-patterns. Similar to dpkg-query --list but with filtering.\n");
   return true;
}
									/*}}}*/
static bool ShowSearchHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] search <regex>\n"
		  "\n"
		  "Search package names and descriptions for the given regex terms\n"
		  "and display matches.\n");
   return true;
}
									/*}}}*/
static bool ShowShowHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] show <package(s)>\n"
		  "\n"
		  "Show detailed information about the given package(s), including\n"
		  "dependencies, install/download size, available sources, and the\n"
		  "package description.\n");
   return true;
}
									/*}}}*/
static bool ShowInstallHelp(CommandLine &CmdL) /*{{{*/
{
   char const *cmd = "install";
   char const *requested = CmdL.FileSize() > 0
			      ? CmdL.FileList[0]
			      : nullptr;

   if (requested != nullptr &&
       strcmp(requested, "help") == 0 &&
       CmdL.FileSize() > 1)
      requested = CmdL.FileList[1];

   if (requested != nullptr)
   {
      if (strcmp(requested, "reinstall") == 0)
	 cmd = "reinstall";
      else if (strcmp(requested, "remove") == 0)
	 cmd = "remove";
      else if (strcmp(requested, "purge") == 0)
	 cmd = "purge";
   }

   ioprintf(std::cout,
	    _("Usage: apt [options] %s <package(s)>\n\n"), cmd);
   std::cout << _("Install, reinstall, remove, or purge packages specified by name,\n"
		  "glob, or regex. Append + to a name to install it, or - to remove it.\n"
		  "Select a version with pkg=version, or a release with pkg/codename.\n");
   return true;
}
									/*}}}*/
static bool ShowAutoremoveHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] autoremove\n"
		  "\n"
		  "Remove packages that were automatically installed to satisfy\n"
		  "dependencies and are no longer needed.\n");
   return true;
}
									/*}}}*/
static bool ShowUpdateHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] update\n"
		  "\n"
		  "Download package information from all configured sources.\n"
		  "Run this before upgrade or install to ensure you have the latest\n"
		  "package lists.\n");
   return true;
}
									/*}}}*/
static bool ShowUpgradeHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] upgrade [package(s)]\n"
		  "\n"
		  "Install available upgrades for all installed packages. New packages\n"
		  "may be installed to satisfy dependencies, but no installed packages\n"
		  "are removed. If a package is given as an argument, it is installed\n"
		  "before the upgrade.\n");
   return true;
}
									/*}}}*/
static bool ShowFullUpgradeHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] full-upgrade [package(s)]\n"
		  "\n"
		  "Upgrade the system, removing installed packages if needed to\n"
		  "upgrade the system as a whole. If a package is given as an\n"
		  "argument, it is installed before the upgrade.\n");
   return true;
}
									/*}}}*/
static bool ShowSatisfyHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] satisfy <dependency-string(s)>\n"
		  "\n"
		  "Satisfy the given dependency strings, as used in Build-Depends.\n"
		  "Prefix an argument with \"Conflicts: \" to handle conflicts.\n"
		  "\n"
		  "Example: apt satisfy \"foo, bar (>= 1.0)\" \"Conflicts: baz\"\n");
   return true;
}
									/*}}}*/
static bool ShowWhyHelp(CommandLine &CmdL) /*{{{*/
{
   char const *cmd = "why";
   char const *requested = CmdL.FileSize() > 0
			      ? CmdL.FileList[0]
			      : nullptr;

   if (requested != nullptr &&
       strcmp(requested, "help") == 0 &&
       CmdL.FileSize() > 1)
      requested = CmdL.FileList[1];

   if (requested != nullptr &&
       strcmp(requested, "why-not") == 0)
      cmd = "why-not";

   ioprintf(std::cout,
	    _("Usage: apt [options] %s <package>\n\n"), cmd);
   std::cout << _("Explain why a package is or is not installed. The why command\n"
		  "shows why an installed package is present; why-not shows why a\n"
		  "package cannot be installed. Takes a single package name.\n");
   return true;
}
									/*}}}*/
static bool ShowEditSourcesHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] edit-sources\n"
		  "\n"
		  "Edit sources.list files in your preferred text editor, with basic\n"
		  "sanity checks.\n");
   return true;
}
									/*}}}*/
static bool ShowModernizeSourcesHelp(CommandLine &) /*{{{*/
{
   std::cout << _("Usage: apt [options] modernize-sources\n"
		  "\n"
		  "Convert .list files to the .sources format, adding Signed-By\n"
		  "values where possible. Old files are saved as .list.bak.\n");
   return true;
}
									/*}}}*/
static bool DoWhy(CommandLine &CmdL) /*{{{*/
{
   pkgCacheFile CacheFile;
   APT::PackageList pkgset = APT::PackageList::FromCommandLine(CacheFile, CmdL.FileList + 1);
   bool const decision = strcmp(CmdL.FileList[0], "why") == 0;
   if (pkgset.size() != 1)
      return _error->PendingError() ? false : _error->Error("Only a single argument is supported at this time.");
   if (unlikely(not CacheFile.BuildDepCache()))
      return false;
   for (auto pkg : pkgset)
      std::cout << APT::Solver::DependencySolver::InternalCliWhy(CacheFile, pkg, decision) << std::flush;
   return not _error->PendingError();
}
static std::vector<aptDispatchWithHelp> GetCommands()			/*{{{*/
{
   // advanced commands are left undocumented on purpose
   return {
      // query
      {"list", &DoList, _("list packages based on package names"), &ShowListHelp},
      {"search", &DoSearch, _("search in package descriptions"), &ShowSearchHelp},
      {"show", &ShowPackage, _("show package details"), &ShowShowHelp},

      // package stuff
      {"install", &DoInstall, _("install packages"), &ShowInstallHelp},
      {"reinstall", &DoInstall, _("reinstall packages"), &ShowInstallHelp},
      {"remove", &DoInstall, _("remove packages"), &ShowInstallHelp},
      {"autoremove", &DoInstall, _("automatically remove all unused packages"), &ShowAutoremoveHelp},
      {"auto-remove", &DoInstall, nullptr, nullptr},
      {"autopurge", &DoInstall, nullptr, nullptr},
      {"purge", &DoInstall, nullptr, &ShowInstallHelp},

      // system wide stuff
      {"update", &DoUpdate, _("update list of available packages"), &ShowUpdateHelp},
      {"upgrade", &DoUpgrade, _("upgrade the system by installing/upgrading packages"), &ShowUpgradeHelp},
      {"full-upgrade", &DoDistUpgrade, _("upgrade the system by removing/installing/upgrading packages"), &ShowFullUpgradeHelp},

      // history stuff
      {"history-list", &DoHistoryList, _("show list of history"), nullptr},
      {"history-info", &DoHistoryInfo, _("show info on specific transactions"), nullptr},
      {"history-redo", &DoHistoryRedo, _("redo transactions"), nullptr},
      {"history-undo", &DoHistoryUndo, _("undo transactions"), nullptr},
      {"history-rollback", &DoHistoryRollback, _("rollback transactions"), nullptr},

      // misc
      {"edit-sources", &EditSources, _("edit the source information file"), &ShowEditSourcesHelp},
      {"modernize-sources", &ModernizeSources, _("modernize .list files to .sources files"), &ShowModernizeSourcesHelp},
      {"moo", &DoMoo, nullptr, nullptr},
      {"satisfy", &DoBuildDep, _("satisfy dependency strings"), &ShowSatisfyHelp},
      {"why", &DoWhy, _("produce a reason trace for the current state of the package"), &ShowWhyHelp},
      {"why-not", &DoWhy, _("produce a reason trace for the current state of the package"), &ShowWhyHelp},

      // for compat with muscle memory
      {"dist-upgrade", &DoDistUpgrade, nullptr, nullptr},
      {"showsrc", &ShowSrcPackage, nullptr, nullptr},
      {"depends", &Depends, nullptr, nullptr},
      {"rdepends", &RDepends, nullptr, nullptr},
      {"policy", &Policy, nullptr, nullptr},
      {"build-dep", &DoBuildDep, nullptr, nullptr},
      {"clean", &DoClean, nullptr, nullptr},
      {"distclean", &DoDistClean, nullptr, nullptr},
      {"dist-clean", &DoDistClean, nullptr, nullptr},
      {"autoclean", &DoAutoClean, nullptr, nullptr},
      {"auto-clean", &DoAutoClean, nullptr, nullptr},
      {"source", &DoSource, nullptr, nullptr},
      {"download", &DoDownload, nullptr, nullptr},
      {"changelog", &DoChangelog, nullptr, nullptr},
      {"info", &ShowPackage, nullptr, nullptr},

      {nullptr, nullptr, nullptr, nullptr}};
}
									/*}}}*/
int main(int argc, const char *argv[])					/*{{{*/
{
   CommandLine CmdL;
   auto const Cmds = ParseCommandLine(CmdL, APT_CMD::APT, &_config, &_system, argc, argv, &ShowHelp, &GetCommands);

   int const quiet = _config->FindI("quiet", 0);
   if (quiet == 2)
   {
      _config->CndSet("quiet::NoProgress", true);
      _config->Set("quiet", 1);
   }

   InitSignals();
   InitOutput();

   CheckIfSimulateMode(CmdL);

   return DispatchCommandLine(CmdL, Cmds);
}
									/*}}}*/
