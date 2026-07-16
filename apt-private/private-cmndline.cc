// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/cmndline.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/debversion.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/strutl.h>

#include <apt-private/private-cmndline.h>
#include <apt-private/private-main.h>

#include <cassert>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <optional>
#include <utility>
#include <vector>

#include <apti18n.h>
									/*}}}*/

APT_NONNULL(1, 2)
static bool CmdMatches_fn(char const *const Cmd, char const *const Match)
{
   return strcmp(Cmd, Match) == 0;
}
template <typename... Tail>
APT_NONNULL(1, 2)
static bool CmdMatches_fn(char const *const Cmd, char const *const Match, Tail... MoreMatches)
{
   return CmdMatches_fn(Cmd, Match) || CmdMatches_fn(Cmd, MoreMatches...);
}
#define addArg(w, x, y, z) Args.emplace_back(CommandLine::MakeArgs(w, x, y, z))
#define CmdMatches(...) (Cmd != nullptr && CmdMatches_fn(Cmd, __VA_ARGS__))

struct option
{
   const char shrt;
   const char *lng;
   const char *option;
   const char *description = nullptr;
   const char flag = 0;
};
struct command
{
   const std::initializer_list<std::string_view> commands;
   const std::initializer_list<option> options;
};
struct binary
{
   APT_CMD binary;
   const std::initializer_list<command> commands;
   const std::initializer_list<option> options;
};

using commands = std::initializer_list<command>;
using options = std::initializer_list<option>;

constexpr std::initializer_list<binary> binaries{
   binary{
      APT_CMD::APT_CACHE,
      {
	 command{
	    {"depends", "rdepends"},
	    {
	       {'i', "important", "APT::Cache::Important", "Print only important dependencies"},
	       {0, "installed", "APT::Cache::Installed", "Print only installed dependencies"},
	       {0, "pre-depends", "APT::Cache::ShowPre-Depends", "Print Pre-Depends"},
	       {0, "depends", "APT::Cache::ShowDepends", "Print Depends"},
	       {0, "recommends", "APT::Cache::ShowRecommends", "Print Recommends"},
	       {0, "suggests", "APT::Cache::ShowSuggests", "Print Suggests"},
	       {0, "replaces", "APT::Cache::ShowReplaces", "Print Replaces"},
	       {0, "breaks", "APT::Cache::ShowBreaks", "Print Breaks"},
	       {0, "conflicts", "APT::Cache::ShowConflicts", "Print Conflicts"},
	       {0, "enhances", "APT::Cache::ShowEnhances", "Print Enhances"},
	       {0, "recurse", "APT::Cache::RecurseDepends", "Print dependencies recursively"},
	       {0, "implicit", "APT::Cache::ShowImplicit", "Print implicit dependencies"},
	    },
	 },
	 command{
	    {"search"},
	    {
	       {'n', "names-only", "APT::Cache::NamesOnly", "Only search names"},
	       {'f', "full", "APT::Cache::ShowFull", "Show the full record"},
	    },
	 },
	 command{
	    {"show", "info"},
	    {
	       {'a', "all-versions", "APT::Cache::AllVersions", "Show all versions"},
	    },
	 },
	 command{
	    {"pkgnames"},
	    {
	       {0, "all-names", "APT::Cache::AllNames", "Show virtual packages and missing dependencies"},
	    },
	 },
	 command{
	    {"unmet"},
	    {
	       {'i', "important", "APT::Cache::Important", "Print only important dependencies"},
	    },
	 },
	 command{
	    {"showsrc"},
	    {
	       {0, "only-source", "APT::Cache::Only-Source", "Only query source package names"},
	    },
	 },
	 command{
	    {"gencaches", "showpkg", "stats", "dump", "dumpavail", "showauto", "policy", "madison"},
	    {},
	 },
      },
      options{
	 {'g', "generate", "APT::Cache::Generate", "Generate the cache"},
	 {'t', "target-release", "APT::Default-Release", "Set the target release", CommandLine::HasArg},
	 {'t', "default-release", "APT::Default-Release", nullptr, CommandLine::HasArg},
	 {'S', "snapshot", "APT::Snapshot", "Snapshot to use", CommandLine::HasArg},

	 {'p', "pkg-cache", "Dir::Cache::pkgcache", "Set the location of the pkgcache.bin", CommandLine::HasArg},
	 {'s', "src-cache", "Dir::Cache::srcpkgcache", "Set the location of the srcpkgcache.bin", CommandLine::HasArg},
	 {0, "with-source", "APT::Sources::With::", "Configure an ephemeral source file", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_CDROM,
      commands{
	 {
	    {"add", "ident"},
	    {
	       {0, "auto-detect", "Acquire::cdrom::AutoDetect", "Auto detect the CD", CommandLine::Boolean},
	       {'d', "cdrom", "Acquire::cdrom::mount", "CD mount point", CommandLine::HasArg},
	       {'r', "rename", "APT::CDROM::Rename", "Rename the CD"},
	       {'m', "no-mount", "APT::CDROM::NoMount", "Do not mount automatically"},
	       {'f', "fast", "APT::CDROM::Fast", "Do a fast operation"},
	       {'n', "just-print", "APT::CDROM::NoAct", "Just print, do not act"},
	       {'n', "recon", "APT::CDROM::NoAct", "Just print, do not act"},
	       {'n', "no-act", "APT::CDROM::NoAct", "Just print, do not act"},
	       {'a', "thorough", "APT::CDROM::Thorough", "Be thorough"},
	    },
	 },
      },
      options{},
   },
   binary{
      APT_CMD::APT_DUMP_SOLVER,
      commands{},
      options{
	 {0, "user", "APT::Solver::RunAsUser", "Run solver as the specified user", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_INTERNAL_PLANNER,
      commands{},
      options{},
   },
   binary{
      APT_CMD::APT_INTERNAL_SOLVER,
      commands{},
      options{},
   },
   binary{
      APT_CMD::APT_CONFIG,
      {
	 command{
	    {"dump"},
	    {
	       {0, "empty", "APT::Config::Dump::EmptyValue", "Include empty values in output", CommandLine::Boolean},
	       {0, "format", "APT::Config::Dump::Format", "Output format (shell, ...)", CommandLine::HasArg},
	    },
	 },
	 command{
	    {"shell"},
	    {},
	 },
      },
      options{},
   },
   binary{
      APT_CMD::APT_EXTRACTTEMPLATES,
      commands{},
      options{
	 {'t', "tempdir", "APT::ExtractTemplates::TempDir", "Temporary directory for extracted templates", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_FTPARCHIVE,
      commands{},
      options{
	 {0, "md5", "APT::FTPArchive::MD5", "Generate MD5 checksums", 0},
	 {0, "sha1", "APT::FTPArchive::SHA1", "Generate SHA1 checksums", 0},
	 {0, "sha256", "APT::FTPArchive::SHA256", "Generate SHA256 checksums", 0},
	 {0, "sha512", "APT::FTPArchive::SHA512", "Generate SHA512 checksums", 0},
	 {'d', "db", "APT::FTPArchive::DB", "Cache database", CommandLine::HasArg},
	 {'s', "source-override", "APT::FTPArchive::SourceOverride", "Source override file", CommandLine::HasArg},
	 {0, "delink", "APT::FTPArchive::DeLinkAct", "Enable delinking of files", 0},
	 {0, "readonly", "APT::FTPArchive::ReadOnlyDB", "Make cache read-only", 0},
	 {0, "contents", "APT::FTPArchive::Contents", "Generate the contents file", 0},
	 {'a', "arch", "APT::FTPArchive::Architecture", "Only accept files for the given architecture", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_SORTPKG,
      commands{},
      options{
	 {'s', "source", "APT::SortPkgs::Source", "Sort source package files", 0},
      },
   },
   binary{
      APT_CMD::RRED,
      commands{},
      options{
	 {'t', nullptr, "Rred::T", nullptr, 0},
	 {'f', nullptr, "Rred::F", nullptr, 0},
	 {'C', "compress", "Rred::Compress", "Set compression algorithm", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_HELPER,
      {
	 command{
	    {"cat-file"},
	    {
	       {'C', "compress", "Apt-Helper::Cat-File::Compress", "Set compression algorithm", CommandLine::HasArg},
	    },
	 },
      },
      options{},
   },
   binary{
      APT_CMD::APT_MARK,
      {
	 command{
	    {"auto", "manual", "hold", "unhold", "markauto", "unmarkauto", "minimize-manual",
	     "showauto", "showmanual", "showhold", "showholds", "showheld"},
	    {
	       {'f', "file", "Dir::State::extended_states", "Read/write states from the given file", CommandLine::HasArg},
	    },
	 },
	 command{
	    {"showinstall", "showinstalls", "showremove", "showremoves",
	     "showdeinstall", "showdeinstalls", "showpurge", "showpurges"},
	    {},
	 },
	 command{
	    {"markauto", "unmarkauto"},
	    {
	       {'v', "verbose", "APT::MarkAuto::Verbose", "Verbose output", 0},
	    },
	 },
	 command{
	    {"minimize-manual"},
	    {
	       {'y', "yes", "APT::Get::Assume-Yes", "Automatic yes to prompts", 0},
	       {'y', "assume-yes", "APT::Get::Assume-Yes", nullptr, 0},
	       {0, "assume-no", "APT::Get::Assume-No", "Automatic no to prompts", 0},
	    },
	 },
	 command{
	    {"auto", "manual", "hold", "unhold", "markauto", "unmarkauto", "minimize-manual",
	     "install", "reinstall", "remove", "deinstall", "purge"},
	    {
	       {'s', "simulate", "APT::Mark::Simulate", "No action; perform a simulation", 0},
	       {'s', "just-print", "APT::Mark::Simulate", nullptr, 0},
	       {'s', "recon", "APT::Mark::Simulate", nullptr, 0},
	       {'s', "dry-run", "APT::Mark::Simulate", nullptr, 0},
	       {'s', "no-act", "APT::Mark::Simulate", nullptr, 0},
	    },
	 },
      },
      options{
	 {0, "with-source", "APT::Sources::With::", "Configure an ephemeral source file", CommandLine::HasArg},
      },
   },
   binary{
      APT_CMD::APT_GET,
      {
	 command{
	    {"install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade",
	     "dselect-upgrade", "autoremove", "auto-remove", "autopurge", "full-upgrade"},
	    {
	       {0, "show-progress", "DpkgPM::Progress", "Show user-friendly progress information", 0},
	       {'f', "fix-broken", "APT::Get::Fix-Broken", "Fix broken dependencies", 0},
	       {0, "purge", "APT::Get::Purge", "Use purge instead of remove", 0},
	       {'V', "verbose-versions", "APT::Get::Show-Versions", "Show verbose version information", 0},
	       {0, "list-columns", "APT::Get::List-Columns", "Show list columns", 0},
	       {0, "autoremove", "APT::Get::AutomaticRemove", "Remove automatically installed packages no longer needed", 0},
	       {0, "auto-remove", "APT::Get::AutomaticRemove", nullptr, 0},
	       {0, "reinstall", "APT::Get::ReInstall", "Reinstall packages", 0},
	       {0, "solver", "APT::Solver", "Set the dependency solver", CommandLine::HasArg},
	       {0, "strict-pinning", "APT::Solver::Strict-Pinning", "Apply strict pinning", 0},
	       {0, "planner", "APT::Planner", "Set the dependency planner", CommandLine::HasArg},
	       {0, "comment", "APT::History::Comment", "Add a comment to history", CommandLine::HasArg},
	       {'U', "update", "APT::Update", "Update package lists", 0},
	    },
	 },
	 command{
	    {"upgrade"},
	    {
	       {0, "new-pkgs", "APT::Get::Upgrade-Allow-New", "Allow installing new packages for upgraded dependencies", CommandLine::Boolean},
	    },
	 },
	 command{
	    {"update"},
	    {
	       {0, "list-cleanup", "APT::Get::List-Cleanup", "Clean up old list files", 0},
	       {0, "allow-insecure-repositories", "Acquire::AllowInsecureRepositories", "Allow insecure repositories", 0},
	       {0, "allow-weak-repositories", "Acquire::AllowWeakRepositories", "Allow weak repositories", 0},
	       {0, "allow-releaseinfo-change", "Acquire::AllowReleaseInfoChange", "Allow Release info changes", 0},
	       {0, "allow-releaseinfo-change-origin", "Acquire::AllowReleaseInfoChange::Origin", "Allow changes to Origin field", 0},
	       {0, "allow-releaseinfo-change-label", "Acquire::AllowReleaseInfoChange::Label", "Allow changes to Label field", 0},
	       {0, "allow-releaseinfo-change-version", "Acquire::AllowReleaseInfoChange::Version", "Allow changes to Version field", 0},
	       {0, "allow-releaseinfo-change-codename", "Acquire::AllowReleaseInfoChange::Codename", "Allow changes to Codename field", 0},
	       {0, "allow-releaseinfo-change-suite", "Acquire::AllowReleaseInfoChange::Suite", "Allow changes to Suite field", 0},
	       {0, "allow-releaseinfo-change-defaultpin", "Acquire::AllowReleaseInfoChange::DefaultPin", "Allow changes to DefaultPin field", 0},
	       {'e', "error-on", "APT::Update::Error-Mode", "Fail on the specified error", CommandLine::HasArg},
	    },
	 },
	 command{
	    {"source"},
	    {
	       {'a', "host-architecture", "APT::Get::Host-Architecture", "Set host architecture", CommandLine::HasArg},
	       {'b', "compile", "APT::Get::Compile", "Compile source packages", 0},
	       {'b', "build", "APT::Get::Compile", nullptr, 0},
	       {'P', "build-profiles", "APT::Build-Profiles", "Set build profiles", CommandLine::HasArg},
	       {0, "diff-only", "APT::Get::Diff-Only", "Download only the diff", 0},
	       {0, "debian-only", "APT::Get::Diff-Only", nullptr, 0},
	       {0, "tar-only", "APT::Get::Tar-Only", "Download only the tar", 0},
	       {0, "dsc-only", "APT::Get::Dsc-Only", "Download only the dsc", 0},
	    },
	 },
	 command{
	    {"build-dep", "satisfy"},
	    {
	       {'a', "host-architecture", "APT::Get::Host-Architecture", "Set host architecture", CommandLine::HasArg},
	       {'P', "build-profiles", "APT::Build-Profiles", "Set build profiles", CommandLine::HasArg},
	       {0, "purge", "APT::Get::Purge", "Use purge instead of remove", 0},
	       {0, "solver", "APT::Solver", "Set the dependency solver", CommandLine::HasArg},
	       {0, "strict-pinning", "APT::Solver::Strict-Pinning", "Apply strict pinning", 0},
	       {'f', "fix-broken", "APT::Get::Fix-Broken", "Fix broken dependencies", 0},
	    },
	 },
	 command{
	    {"build-dep"},
	    {
	       {0, "arch-only", "APT::Get::Arch-Only", "Only process architecture-dependent build dependencies", 0},
	       {0, "indep-only", "APT::Get::Indep-Only", "Only process architecture-independent build dependencies", 0},
	    },
	 },
	 command{
	    {"indextargets"},
	    {
	       {0, "format", "APT::Get::IndexTargets::Format", "Output format", CommandLine::HasArg},
	       {0, "release-info", "APT::Get::IndexTargets::ReleaseInfo", "Show release info", 0},
	    },
	 },
	 command{
	    {"download", "changelog", "markauto", "unmarkauto"},
	    {},
	 },
	 command{
	    {"install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade",
	     "dselect-upgrade", "autoremove", "auto-remove", "autopurge", "full-upgrade",
	     "source", "build-dep", "satisfy",
	     "clean", "autoclean", "auto-clean", "distclean", "dist-clean", "check"},
	    {
	       {'s', "simulate", "APT::Get::Simulate", "No action; perform a simulation", 0},
	       {'s', "just-print", "APT::Get::Simulate", nullptr, 0},
	       {'s', "recon", "APT::Get::Simulate", nullptr, 0},
	       {'s', "dry-run", "APT::Get::Simulate", nullptr, 0},
	       {'s', "no-act", "APT::Get::Simulate", nullptr, 0},
	    },
	 },
      },
      options{
	 {'d', "download-only", "APT::Get::Download-Only", "Download only; do not install or unpack", 0},
	 {'y', "yes", "APT::Get::Assume-Yes", "Automatic yes to prompts", 0},
	 {'y', "assume-yes", "APT::Get::Assume-Yes", nullptr, 0},
	 {0, "assume-no", "APT::Get::Assume-No", "Automatic no to prompts", 0},
	 {'u', "show-upgraded", "APT::Get::Show-Upgraded", "Show upgraded packages", 0},
	 {'m', "ignore-missing", "APT::Get::Fix-Missing", nullptr, 0},
	 {'t', "target-release", "APT::Default-Release", "Set the target release", CommandLine::HasArg},
	 {'t', "default-release", "APT::Default-Release", nullptr, CommandLine::HasArg},
	 {'S', "snapshot", "APT::Snapshot", "Snapshot to use", CommandLine::HasArg},
	 {0, "download", "APT::Get::Download", "Download packages", 0},
	 {0, "fix-missing", "APT::Get::Fix-Missing", "Ignore packages that cannot be retrieved", 0},
	 {0, "ignore-hold", "APT::Ignore-Hold", "Ignore held packages", 0},
	 {0, "upgrade", "APT::Get::upgrade", "Upgrade packages", 0},
	 {0, "only-upgrade", "APT::Get::Only-Upgrade", "Only upgrade packages", 0},
	 {0, "allow-change-held-packages", "APT::Get::allow-change-held-packages", "Allow changing held packages", CommandLine::Boolean},
	 {0, "allow-remove-essential", "APT::Get::allow-remove-essential", "Allow removing essential packages", CommandLine::Boolean},
	 {0, "allow-downgrades", "APT::Get::allow-downgrades", "Allow downgrading packages", CommandLine::Boolean},
	 {0, "force-yes", "APT::Get::force-yes", "Force yes (deprecated)", 0},
	 {0, "print-uris", "APT::Get::Print-URIs", "Print URIs", 0},
	 {0, "trivial-only", "APT::Get::Trivial-Only", "Only perform trivial operations", 0},
	 {0, "mark-auto", "APT::Get::Mark-Auto", "Mark packages as automatically installed", 0},
	 {0, "remove", "APT::Get::Remove", "Remove packages", 0},
	 {0, "only-source", "APT::Get::Only-Source", "Only query source package names", 0},
	 {0, "allow-unauthenticated", "APT::Get::AllowUnauthenticated", "Allow unauthenticated packages", 0},
	 {0, "install-recommends", "APT::Install-Recommends", "Install recommended packages", CommandLine::Boolean},
	 {0, "install-suggests", "APT::Install-Suggests", "Install suggested packages", CommandLine::Boolean},
	 {0, "fix-policy", "APT::Get::Fix-Policy-Broken", "Fix broken policy dependencies", 0},
	 {0, "with-source", "APT::Sources::With::", "Configure an ephemeral source file", CommandLine::HasArg},
      },
   },
};

static bool addArguments(APT_CMD Binary, std::vector<CommandLine::Args> &Args, char const *const Cmd) /*{{{*/
{
   auto binary = std::ranges::find_if(binaries, [Binary](auto b) noexcept
				      { return b.binary == Binary; });
   if (binary == binaries.end())
      return false;

   if (Cmd)
   {
      for (auto &command : binary->commands)
	 if (std::ranges::contains(command.commands, std::string_view(Cmd)))
	 {
	    for (auto &option : command.options)
	       addArg(option.shrt, option.lng, option.option, option.flag);
	 }
   }

   bool addedArgs = not Args.empty();
   for (auto &option : binary->options)
      addArg(option.shrt, option.lng, option.option, option.flag);

   return addedArgs;
}
									/*}}}*/
static bool addArgumentsAPT(std::vector<CommandLine::Args> &Args, char const * const Cmd)/*{{{*/
{
   if (CmdMatches("list"))
   {
      addArg('i',"installed","APT::Cmd::Installed",0);
      addArg(0,"upgradeable","APT::Cmd::Upgradable",0);
      addArg('u',"upgradable","APT::Cmd::Upgradable",0);
      addArg(0,"manual-installed","APT::Cmd::Manual-Installed",0);
      addArg('v', "verbose", "APT::Cmd::List-Include-Summary", 0);
      addArg('a', "all-versions", "APT::Cmd::All-Versions", 0);
      addArg('t', "target-release", "APT::Default-Release", CommandLine::HasArg);
      addArg('t', "default-release", "APT::Default-Release", CommandLine::HasArg);
      addArg('S', "snapshot", "APT::Snapshot", CommandLine::HasArg);
   }
   else if (CmdMatches("show") || CmdMatches("info"))
   {
      addArg('a', "all-versions", "APT::Cache::AllVersions", 0);
      addArg('f', "full", "APT::Cache::ShowFull", 0);
      addArg('S', "snapshot", "APT::Snapshot", CommandLine::HasArg);
   }
   else if (addArguments(APT_CMD::APT_GET, Args, Cmd) || addArguments(APT_CMD::APT_CACHE, Args, Cmd))
   {
       // we have no (supported) command-name overlaps so far, so we call
       // specifics in order until we find one which adds arguments
   }
   else
      return false;

   addArg(0, "with-source", "APT::Sources::With::", CommandLine::HasArg);

   return true;
}
									/*}}}*/
std::vector<CommandLine::Args> getCommandArgs(APT_CMD const Program, char const * const Cmd)/*{{{*/
{
   std::vector<CommandLine::Args> Args;
   Args.reserve(50);
   if (Cmd != nullptr && strcmp(Cmd, "help") == 0)
      ; // no options for help so no need to implement it in each
   else
      switch (Program)
      {
      case APT_CMD::APT:
	 addArgumentsAPT(Args, Cmd);
	 break;
      case APT_CMD::APT_CACHE:
      case APT_CMD::APT_CDROM:
      case APT_CMD::APT_CONFIG:
      case APT_CMD::APT_DUMP_SOLVER:
      case APT_CMD::APT_EXTRACTTEMPLATES:
      case APT_CMD::APT_FTPARCHIVE:
      case APT_CMD::APT_GET:
      case APT_CMD::APT_HELPER:
      case APT_CMD::APT_INTERNAL_PLANNER:
      case APT_CMD::APT_INTERNAL_SOLVER:
      case APT_CMD::APT_MARK:
      case APT_CMD::APT_SORTPKG:
      case APT_CMD::RRED:
	 addArguments(Program, Args, Cmd);
	 break;
      }

   // options without a command
   addArg('h', "help", "help", 0);
   addArg('v', "version", "version", 0);
   // general options
   addArg(0, "color", "APT::Color", 0);
   addArg('q', "quiet", "quiet", CommandLine::IntLevel);
   addArg(0, "audit", "APT::Audit", 0);
   addArg('q', "silent", "quiet", CommandLine::IntLevel);
   addArg('c', "config-file", 0, CommandLine::ConfigFile);
   addArg('o', "option", 0, CommandLine::ArbItem);
   addArg(0, "cli-version", "APT::Version", CommandLine::HasArg);
   addArg(0, NULL, NULL, 0);

   return Args;
}
									/*}}}*/
#undef addArg
static void ShowHelpListCommands(std::vector<aptDispatchWithHelp> const &Cmds)/*{{{*/
{
   if (Cmds.empty() || Cmds[0].Match == nullptr)
      return;
   std::cout << std::endl << _("Most used commands:") << std::endl;
   for (auto const &c: Cmds)
   {
      if (c.Help == nullptr)
	 continue;
      std::cout << "  " << c.Match << " - " << c.Help << std::endl;
   }
}
									/*}}}*/
static bool ShowCommonHelp(APT_CMD const Binary, CommandLine &CmdL, std::vector<aptDispatchWithHelp> const &Cmds,/*{{{*/
      bool (*ShowHelp)(CommandLine &))
{
   std::cout << PACKAGE << " " << PACKAGE_VERSION << " (" << COMMON_ARCH << ")" << std::endl;
   if (_config->FindB("version") == true && Binary != APT_CMD::APT_GET)
      return true;
   if (ShowHelp(CmdL) == false)
      return false;
   if (_config->FindB("version") == true || Binary == APT_CMD::APT_FTPARCHIVE)
      return true;
   ShowHelpListCommands(Cmds);
   std::cout << std::endl;
   char const * cmd = nullptr;
   switch (Binary)
   {
      case APT_CMD::APT: cmd = "apt(8)"; break;
      case APT_CMD::APT_CACHE: cmd = "apt-cache(8)"; break;
      case APT_CMD::APT_CDROM: cmd = "apt-cdrom(8)"; break;
      case APT_CMD::APT_CONFIG: cmd = "apt-config(8)"; break;
      case APT_CMD::APT_DUMP_SOLVER: cmd = nullptr; break;
      case APT_CMD::APT_EXTRACTTEMPLATES: cmd = "apt-extracttemplates(1)"; break;
      case APT_CMD::APT_FTPARCHIVE: cmd = "apt-ftparchive(1)"; break;
      case APT_CMD::APT_GET: cmd = "apt-get(8)"; break;
      case APT_CMD::APT_HELPER: cmd = nullptr; break;
      case APT_CMD::APT_INTERNAL_PLANNER: cmd = nullptr; break;
      case APT_CMD::APT_INTERNAL_SOLVER: cmd = nullptr; break;
      case APT_CMD::APT_MARK: cmd = "apt-mark(8)"; break;
      case APT_CMD::APT_SORTPKG: cmd = "apt-sortpkgs(1)"; break;
      case APT_CMD::RRED: cmd = nullptr; break;
   }
   if (cmd != nullptr)
      ioprintf(std::cout, _("See %s for more information about the available commands."), cmd);
   if (Binary != APT_CMD::APT_DUMP_SOLVER && Binary != APT_CMD::APT_INTERNAL_SOLVER &&
	 Binary != APT_CMD::APT_INTERNAL_PLANNER && Binary != APT_CMD::RRED)
      std::cout << std::endl <<
	 _("Configuration options and syntax is detailed in apt.conf(5).\n"
	       "Information about how to configure sources can be found in sources.list(5).\n"
	       "Package and version choices can be expressed via apt_preferences(5).\n"
	       "Security details are available in apt-secure(8).\n");
   if (Binary == APT_CMD::APT_GET || Binary == APT_CMD::APT)
      std::cout << std::right << std::setw(70) << _("This APT has Super Cow Powers.") << std::endl;
   else if (Binary == APT_CMD::APT_HELPER || Binary == APT_CMD::APT_DUMP_SOLVER)
      std::cout << std::right << std::setw(70) << _("This APT helper has Super Meep Powers.") << std::endl;
   return true;
}
									/*}}}*/
static void BinarySpecificConfiguration(char const * const Binary)	/*{{{*/
{
   auto const binary = flNotDir(Binary);
   if (binary == "apt-cdrom" || binary == "apt-config")
   {
      _config->CndSet("Binary::apt-cdrom::APT::Internal::OpProgress::EraseLines", false);
   }
   _config->Set("Binary", binary);

   // Version specific configuration
   _config->CndSet("Version::1.2::APT::Color",
		   getenv("NO_COLOR") == nullptr && getenv("APT_NO_COLOR") == nullptr);
   _config->CndSet("Version::3.0::APT::Output-Version", 30);
   _config->CndSet("Version::1.1::APT::Cache::Show::Version", 2);
   _config->CndSet("Version::1.1::APT::Cache::AllVersions", false);
   _config->CndSet("Version::1.1::APT::Cache::ShowVirtuals", true);
   _config->CndSet("Version::1.1::APT::Cache::Search::Version", 2);
   _config->CndSet("Version::1.1::APT::Cache::ShowDependencyType", true);
   _config->CndSet("Version::1.1::APT::Cache::ShowVersion", true);
   _config->CndSet("Version::1.1::APT::Get::Upgrade-Allow-New", true);
   _config->CndSet("Version::1.1::APT::Cmd::Show-Update-Stats", true);
   _config->CndSet("Version::1.2::DPkg::Progress-Fancy", true);
   _config->CndSet("Version::1.2::APT::Keep-Downloaded-Packages", false);
   _config->CndSet("Version::1.5::APT::Get::Update::InteractiveReleaseInfoChanges", true);
   _config->CndSet("Version::2.0::APT::Cmd::Pattern-Only", true);
   _config->CndSet("Version::3.0::Pager", true);
   _config->CndSet("Version::0.31::APT::Solver", "3.0");
   _config->CndSet("Version::1.21::APT::Solver", "3.0");
   _config->CndSet("Version::2.11::APT::Solver", "3.0");
   _config->CndSet("Version::3.1::APT::Solver", "3.0");

   if (isatty(STDIN_FILENO))
      _config->CndSet("Version::2.0::Dpkg::Lock::Timeout", -1);
   else
      _config->CndSet("Version::2.0::Dpkg::Lock::Timeout", 120);
}
									/*}}}*/
static void BinaryCommandSpecificConfiguration(char const * const Binary, char const * const Cmd)/*{{{*/
{
   auto const binary = flNotDir(Binary);
   if ((binary == "apt" || binary == "apt-get") && CmdMatches("upgrade", "dist-upgrade", "full-upgrade"))
   {
      //FIXME: the option is documented to apply only for install/remove, so
      // we force it false for configuration files where users can be confused if
      // we support it anyhow, but allow it on the commandline to take effect
      // even through it isn't documented as a user who doesn't want it wouldn't
      // ask for it
      _config->Set("APT::Get::AutomaticRemove", "");
   }
}
#undef CmdMatches
									/*}}}*/

static std::pair<std::optional<long unsigned int>, std::optional<long unsigned int>> parseCliVersion(std::string_view version)
{
   auto level = VectorizeString(version, '.');
   long unsigned int first = 0, second = 0;
   if (not StrToNum(level[0].data(), first, level[0].size(), 10))
      return {};
   if (level.size() <= 1)
      return {first, {}};
   if (not StrToNum(level[1].data(), second, level[1].size(), 10))
      return {};

   return {first, second};
}

bool cliVersionIsCompatible(std::string_view rawLevel, std::string_view rawPattern)
{
   auto level = parseCliVersion(rawLevel);
   auto pattern = parseCliVersion(rawPattern);

   assert(level.first);
   assert(level.second);

   // Requested an earlier major version
   if (pattern.first && *level.first > *pattern.first)
      return false;
   // Requested a latter major version
   if (pattern.first && *level.first < *pattern.first)
      return (*level.second < 10); // Keep in mind 2.10 follows 2.8, not 2.9, but 3.0 follows 2.9
   // Same major version, requested a higher pattern version (compatible usually)
   if (pattern.second && *level.second < *pattern.second)
      return (*level.second != 9); // X.9 is not compatible with X.10 onward
   // Special case for short pattern, X.9 does not migrate to X+1
   if (not pattern.second && level.second == 9)
      return false;
   // Same major version, requested a lower major version.
   if (pattern.second && *level.second > *pattern.second)
      return false;

   return true;
}

std::vector<CommandLine::Dispatch> ParseCommandLine(CommandLine &CmdL, APT_CMD const Binary,/*{{{*/
      Configuration * const * const Cnf, pkgSystem ** const Sys, int const argc, const char *argv[],
      bool (*ShowHelp)(CommandLine &), std::vector<aptDispatchWithHelp> (*GetCommands)(void))
{
   InitLocale(Binary);
   if (Cnf != NULL && pkgInitConfig(**Cnf) == false)
   {
      _error->DumpErrors();
      exit(100);
   }

   if (likely(argc != 0 && argv[0] != NULL))
      BinarySpecificConfiguration(argv[0]);

   std::vector<CommandLine::Dispatch> Cmds;
   std::vector<aptDispatchWithHelp> const CmdsWithHelp = GetCommands();
   if (CmdsWithHelp.empty() == false)
   {
      CommandLine::Dispatch const help = { "help", [](CommandLine &){return false;} };
      Cmds.push_back(std::move(help));
   }
   std::transform(CmdsWithHelp.begin(), CmdsWithHelp.end(), std::back_inserter(Cmds),
		  [](auto &&cmd) { return CommandLine::Dispatch{cmd.Match, cmd.Handler}; });

   char const * CmdCalled = nullptr;
   if (Cmds.empty() == false && Cmds[0].Handler != nullptr)
      CmdCalled = CommandLine::GetCommand(Cmds.data(), argc, argv);
   if (CmdCalled != nullptr)
      BinaryCommandSpecificConfiguration(argv[0], CmdCalled);

   std::string const conf = "Binary::" + _config->Find("Binary");
   _config->MoveSubTree(conf.c_str(), nullptr);

   // Args running out of scope invalidates the pointer stored in CmdL,
   // but we don't use the pointer after this function, so we ignore
   // this problem for now and figure something out if we have to.
   auto Args = getCommandArgs(Binary, CmdCalled);
   CmdL = CommandLine(Args.data(), _config);

   auto initVersion = []() -> bool
   {
      auto defaultVersion = parseCliVersion(PACKAGE_VERSION);
      std::string requestedVersion = _config->Find("APT::Version");
      if (requestedVersion.empty())
      {
	 if (_config->Find("Binary", "") == "apt")
	    requestedVersion = PACKAGE_VERSION;
	 else
	    strprintf(requestedVersion, "0.%lu", *defaultVersion.first * 10 + *defaultVersion.second);
      }
      else
      {
	 // Check that the requested version is compatible with our version
	 auto parsedRequestedVersion = parseCliVersion(requestedVersion);
	 // This appends a 0 to the requested version if not specified.
	 std::string cleanRequestedVersion;
	 strprintf(cleanRequestedVersion, "%lu.%lu", *parsedRequestedVersion.first, parsedRequestedVersion.second ? *parsedRequestedVersion.second : 0);
	 // Supported version "lowers" say 3.1 to 0.31, 1.21, 2.11 depending on requested major
	 std::string supportedVersion;
	 strprintf(supportedVersion, "%lu.%lu", *parsedRequestedVersion.first, (*defaultVersion.first - *parsedRequestedVersion.first) * 10 + *defaultVersion.second);
	 if (not cliVersionIsCompatible(cleanRequestedVersion, supportedVersion))
	    return _error->Error("Requested version %s is not supported in version %s (%s is)", requestedVersion.c_str(), PACKAGE_VERSION, supportedVersion.c_str());
      }
      if (auto Versions = _config->Tree("Version"))
      {
	 for (auto I = Versions->Child; I != NULL; I = I->Next)
	 {
	    auto sub = "Version::" + I->Tag;
	    if (not cliVersionIsCompatible(I->Tag, requestedVersion))
	       continue;
	    // FIXME: 2.10 should not flow into 3.0
	    _config->MoveSubTree(sub.c_str(), nullptr, false);
	 }
      }
      return true;
   };

   if (CmdL.Parse(argc,argv) == false ||
       initVersion() == false ||
       (Sys != NULL && pkgInitSystem(*_config, *Sys) == false))
   {
      if (_config->FindB("version") == true)
	 ShowCommonHelp(Binary, CmdL, CmdsWithHelp, ShowHelp);

      _error->DumpErrors();
      exit(100);
   }

   if (_config->FindB("APT::Get::Force-Yes", false) == true)
   {
      _error->Warning(_("--force-yes is deprecated, use one of the options starting with --allow instead."));
   }

   if (not _config->FindB("APT::Solver::Strict-Pinning", true) && _config->Find("APT::Solver", "internal") == "internal")
   {
      _config->Set("APT::Solver", "3.0");
      _error->Notice("Automatically enabled --solver 3.0 for --no-strict-pinning");
   }

   // See if the help should be shown
   if (_config->FindB("help") == true || _config->FindB("version") == true ||
	 (CmdL.FileSize() > 0 && strcmp(CmdL.FileList[0], "help") == 0))
   {
      ShowCommonHelp(Binary, CmdL, CmdsWithHelp, ShowHelp);
      exit(0);
   }
   if (Cmds.empty() == false && CmdL.FileSize() == 0)
   {
      ShowCommonHelp(Binary, CmdL, CmdsWithHelp, ShowHelp);
      exit(1);
   }
   return Cmds;
}
									/*}}}*/
unsigned short DispatchCommandLine(CommandLine &CmdL, std::vector<CommandLine::Dispatch> const &Cmds)	/*{{{*/
{
   // Match the operation
   bool const returned = Cmds.empty() ? true : CmdL.DispatchArg(Cmds.data());

   // Print any errors or warnings found during parsing
   bool const Errors = _error->PendingError();
   if (_config->FindB("APT::Audit"))
      _error->DumpErrors(GlobalError::AUDIT);
   else if (_config->FindI("quiet",0) > 0)
      _error->DumpErrors();
   else
      _error->DumpErrors(GlobalError::NOTICE);
   if (returned == false || std::cout.bad() || std::cerr.bad() || std::clog.bad())
      return 100;
   return Errors == true ? 100 : 0;
}
									/*}}}*/
