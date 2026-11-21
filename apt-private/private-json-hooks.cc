/*
 * private-json-hooks.cc - 2nd generation, JSON-RPC, hooks for APT
 *
 * Copyright (c) 2018 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#include <config.h>

#include <apt-core/json/json.h>
#include <apt-pkg/debsystem.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>
#include <apt-private/private-json-hooks.h>
#include <apt-private/private-output.h>

#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <csignal>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace JSON = APT::JSON;

namespace Hook
{
struct Origin
{
   std::optional<std::string> archive;
   std::optional<std::string> codename;
   std::optional<std::string> version;
   std::optional<std::string> origin;
   std::optional<std::string> label;
   std::optional<std::string> site;
};

struct Version
{
   unsigned int id;
   std::string version;
   std::string architecture;
   signed short pin;
   std::vector<Origin> origins;
};

struct Versions
{
   std::optional<Version> candidate;
   std::optional<Version> install;
   std::optional<Version> current;
};

struct Package
{
   unsigned int id;
   std::string name;
   std::string architecture;
   std::string_view mode;
   bool automatic;
   Versions versions;
};

struct Notification
{
   struct Params
   {
      std::optional<std::string> command;
      std::optional<std::vector<std::string>> searchTerms;
      std::vector<std::string> unknownPackages;
      std::vector<Package> packages;
   };

   std::string_view jsonRPC = "2.0";
   std::string method;
   Params params;
};

struct Hello
{
   struct Params
   {
      struct Option
      {
	 std::string name;
	 std::string value;
      };

      std::vector<std::string_view> versions = {"0.1", "0.2"};
      std::vector<Option> options;
   };
   struct Reply
   {
      std::string_view jsonRPC;
      std::optional<int> id;
      struct Result
      {
	 std::string_view version;
      };
      std::optional<Result> result;
   };

   std::string_view jsonRPC = "2.0";
   std::string_view method = "org.debian.apt.hooks.hello";
   unsigned id = 0;
   Params params;
};

struct Bye
{
   struct Params
   {
   };

   std::string_view jsonRPC = "2.0";
   std::string_view method = "org.debian.apt.hooks.bye";
   Params params;
};
} // namespace Hook

template <>
struct JSON::Reflect<Hook::Origin>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"archive", std::ref(val.archive)},
	 std::pair{"codename", std::ref(val.codename)},
	 std::pair{"version", std::ref(val.version)},
	 std::pair{"origin", std::ref(val.origin)},
	 std::pair{"label", std::ref(val.label)},
	 std::pair{"site", std::ref(val.site)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Version>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"id", std::ref(val.id)},
	 std::pair{"version", std::ref(val.version)},
	 std::pair{"architecture", std::ref(val.architecture)},
	 std::pair{"pin", std::ref(val.pin)},
	 std::pair{"origins", std::ref(val.origins)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Versions>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"candidate", std::ref(val.candidate)},
	 std::pair{"install", std::ref(val.install)},
	 std::pair{"current", std::ref(val.current)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Package>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"id", std::ref(val.id)},
	 std::pair{"name", std::ref(val.name)},
	 std::pair{"architecture", std::ref(val.architecture)},
	 std::pair{"mode", std::ref(val.mode)},
	 std::pair{"automatic", std::ref(val.automatic)},
	 std::pair{"versions", std::ref(val.versions)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Notification::Params>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"command", std::ref(val.command)},
	 std::pair{"search-terms", std::ref(val.searchTerms)},
	 std::pair{"unknown-packages", std::ref(val.unknownPackages)},
	 std::pair{"packages", std::ref(val.packages)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Notification>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"jsonrpc", std::ref(val.jsonRPC)},
	 std::pair{"method", std::ref(val.method)},
	 std::pair{"params", std::ref(val.params)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Hello::Params::Option>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"name", std::ref(val.name)},
	 std::pair{"value", std::ref(val.value)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Hello::Params>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"versions", std::ref(val.versions)},
	 std::pair{"options", std::ref(val.options)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Hello>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"jsonrpc", std::ref(val.jsonRPC)},
	 std::pair{"method", std::ref(val.method)},
	 std::pair{"id", std::ref(val.id)},
	 std::pair{"params", std::ref(val.params)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Hello::Reply>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"jsonrpc", std::ref(val.jsonRPC)},
	 std::pair{"id", std::ref(val.id)},
	 std::pair{"result", std::ref(val.result)},
      };
   }
};

template <>
struct JSON::Reflect<Hook::Hello::Reply::Result>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::make_tuple(
	 std::pair{"version", std::ref(val.version)});
   }
};

template <>
struct JSON::Reflect<Hook::Bye::Params>
{
   static constexpr auto operator()(auto &) noexcept
   {
      return std::tuple{};
   }
};

template <>
struct JSON::Reflect<Hook::Bye>
{
   static constexpr auto operator()(auto &val) noexcept
   {
      return std::tuple{
	 std::pair{"jsonrpc", std::ref(val.jsonRPC)},
	 std::pair{"method", std::ref(val.method)},
	 std::pair{"params", std::ref(val.params)},
      };
   }
};

/** Build the origin object for a VerFileIterator. */
static Hook::Origin verFileToHook(pkgCache::VerFileIterator const &vf)
{
   auto pf = vf.File();
   auto rf = pf.ReleaseFile();
   Hook::Origin origin;

   if (not rf.end())
   {
      if (rf->Archive != 0)
	 origin.archive = rf.Archive();
      if (rf->Codename != 0)
	 origin.codename = rf.Codename();
      if (rf->Version != 0)
	 origin.version = rf.Version();
      if (rf->Origin != 0)
	 origin.origin = rf.Origin();
      if (rf->Label != 0)
	 origin.label = rf.Label();
      if (rf->Site != 0)
	 origin.site = rf.Site();
   }
   return origin;
}

/** Build the version object for a VerIterator. */
static Hook::Version verIterToHook(CacheFile &Cache, pkgCache::VerIterator const &Ver)
{
   Hook::Version version;
   version.id = Ver->ID;
   version.version = Ver.VerStr();
   version.architecture = Ver.Arch();
   version.pin = Cache->GetPolicy().GetPriority(Ver);

   for (auto vf = Ver.FileList(); not vf.end(); ++vf)
      if ((vf.File()->Flags & pkgCache::Flag::NotSource) == 0)
	 version.origins.push_back(verFileToHook(vf));
   return version;
}

/**
 * @brief Copy of debSystem::DpkgChrootDirectory()
 * @todo Remove
 */
static void DpkgChrootDirectory()
{
   std::string const chrootDir = _config->FindDir("DPkg::Chroot-Directory");
   if (chrootDir == "/")
      return;
   std::cerr << "Chrooting into " << chrootDir << std::endl;
   if (chroot(chrootDir.c_str()) != 0)
      _exit(100);
   if (chdir("/") != 0)
      _exit(100);
}

/** Build and serialize a notification for the hook's stream. */
static std::string NotifyHook(std::string const &method, const char **FileList, CacheFile &Cache, std::set<std::string> const &UnknownPackages, int hookVersion)
{
   SortedPackageUniverse Universe(Cache);

   Hook::Notification notification;
   notification.method = method;
   auto &params = notification.params;

   if (FileList != nullptr)
   {
      if (FileList[0] != nullptr)
	 params.command = FileList[0];
      params.searchTerms.emplace();
      for (int i = 1; FileList[i] != nullptr; ++i)
	 params.searchTerms->emplace_back(FileList[i]);
   }

   for (auto const &packageName : UnknownPackages)
      params.unknownPackages.push_back(packageName);

   for (auto const &Pkg : Universe)
   {
      switch (Cache[Pkg].Mode)
      {
      case pkgDepCache::ModeInstall:
      case pkgDepCache::ModeDelete:
	 break;
      default:
	 continue;
      }

      Hook::Package package;
      package.id = Pkg->ID;
      package.name = Pkg.Name();
      package.architecture = Pkg.Arch();

      switch (Cache[Pkg].Mode)
      {
      case pkgDepCache::ModeInstall:
	 if (Pkg->CurrentVer != 0 && Cache[Pkg].Upgrade() && hookVersion >= 0x020)
	    package.mode = "upgrade";
	 else if (Pkg->CurrentVer != 0 && Cache[Pkg].Downgrade() && hookVersion >= 0x020)
	    package.mode = "downgrade";
	 else if (Pkg->CurrentVer != 0 && Cache[Pkg].ReInstall() && hookVersion >= 0x020)
	    package.mode = "reinstall";
	 else
	    package.mode = "install";
	 break;
      case pkgDepCache::ModeDelete:
	 package.mode = Cache[Pkg].Purge() ? "purge" : "deinstall";
	 break;
      default:
	 std::unreachable();
      }
      package.automatic = (Cache[Pkg].Flags & pkgCache::Flag::Auto) != 0;

      if (Cache[Pkg].CandidateVer != nullptr)
	 package.versions.candidate = verIterToHook(Cache, Cache[Pkg].CandidateVerIter(Cache));
      if (Cache[Pkg].InstallVer != nullptr)
	 package.versions.install = verIterToHook(Cache, Cache[Pkg].InstVerIter(Cache));
      if (Pkg->CurrentVer != 0)
	 package.versions.current = verIterToHook(Cache, Pkg.CurrentVer());
      params.packages.push_back(std::move(package));
   }

   return JSON::Value::encode(notification).value().stringify();
}

static std::vector<Hook::Hello::Params::Option> BuildOptions()
{
   std::vector<Hook::Hello::Params::Option> options;
   const Configuration::Item *Top = _config->Tree(nullptr);
   if (Top == nullptr)
      return options;

   do
   {
      if (not Top->Value.empty())
	 options.push_back(Hook::Hello::Params::Option{Top->FullTag(), Top->Value});
      if (Top->Child != nullptr)
      {
	 Top = Top->Child;
	 continue;
      }

      while (Top != nullptr && Top->Next == nullptr)
	 Top = Top->Parent;
      if (Top != nullptr)
	 Top = Top->Next;

   } while (Top != nullptr);

   return options;
}

/// Build the hello handshake message for the 0.1 protocol.
static std::string BuildHelloMessage()
{
   Hook::Hello hello;
   hello.params.options = BuildOptions();
   return JSON::Value::encode(hello).value().stringify();
}

/// Build the bye notification for the 0.1 protocol.
static std::string BuildByeMessage()
{
   return JSON::Value::encode(Hook::Bye{}).value().stringify();
}

/// @brief Run the Json hook processes in the given option.
bool RunJsonHook(std::string const &option, std::string const &method, const char **FileList, CacheFile &Cache, std::set<std::string> const &UnknownPackages)
{
   std::unordered_map<int, std::string> notifications;
   std::string HelloData = BuildHelloMessage();
   std::string ByeData = BuildByeMessage();
   int hookVersion;

   bool result = true;

   Configuration::Item const *Opts = _config->Tree(option.c_str());
   if (Opts == 0 || Opts->Child == 0)
      return true;
   Opts = Opts->Child;

   // Flush output before calling hooks
   std::clog.flush();
   std::cerr.flush();
   std::cout.flush();
   c2out.flush();
   c1out.flush();

   sighandler_t old_sigpipe = signal(SIGPIPE, SIG_IGN);
   sighandler_t old_sigint = signal(SIGINT, SIG_IGN);
   sighandler_t old_sigquit = signal(SIGQUIT, SIG_IGN);
   DEFER([&] {
      signal(SIGINT, old_sigint);
      signal(SIGPIPE, old_sigpipe);
      signal(SIGQUIT, old_sigquit); });

   unsigned int Count = 1;
   for (; Opts != 0; Opts = Opts->Next, Count++)
   {
      if (Opts->Value.empty() == true)
	 continue;

      if (_config->FindB("Debug::RunScripts", false) == true)
	 std::clog << "Running external script with list of all .deb file: '"
		   << Opts->Value << "'" << std::endl;

      // Create the pipes
      std::set<int> KeepFDs;
      MergeKeepFdsFromConfiguration(KeepFDs);
      int Pipes[2];
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, Pipes) != 0)
      {
	 result = _error->Errno("pipe", "Failed to create IPC pipe to subprocess");
	 break;
      }

      int InfoFD = 3;

      if (InfoFD != Pipes[0])
	 SetCloseExec(Pipes[0], true);
      else
	 KeepFDs.insert(Pipes[0]);

      SetCloseExec(Pipes[1], true);

      // Purified Fork for running the script
      pid_t Process = ExecFork(KeepFDs);
      if (Process == 0)
      {
	 // Setup the FDs
	 dup2(Pipes[0], InfoFD);
	 SetCloseExec(STDOUT_FILENO, false);
	 SetCloseExec(STDIN_FILENO, false);
	 SetCloseExec(STDERR_FILENO, false);

	 std::string hookfd;
	 strprintf(hookfd, "%d", InfoFD);
	 setenv("APT_HOOK_SOCKET", hookfd.c_str(), 1);

	 DpkgChrootDirectory();
	 const char *Args[4];
	 Args[0] = "/bin/sh";
	 Args[1] = "-c";
	 Args[2] = Opts->Value.c_str();
	 Args[3] = 0;
	 execv(Args[0], (char **)Args);
	 _exit(100);
      }
      bool processWaited = false;
      DEFER([&] {
         if (not processWaited)
            ExecWait(Process, Opts->Value.c_str()); });
      close(Pipes[0]);
      FILE *F = fdopen(Pipes[1], "w+");
      if (F == 0)
      {
	 close(Pipes[1]);
	 result = _error->Errno("fdopen", "Failed to open new FD");
	 break;
      }

      DEFER([&] {
         if (F != nullptr)
            fclose(F); });
      fwrite(HelloData.data(), HelloData.size(), 1, F);
      fwrite("\n\n", 2, 1, F);
      fflush(F);

      char *line = nullptr;
      DEFER([&] { free(line); });
      size_t linesize = 0;
      ssize_t size = getline(&line, &linesize, F);

      if (size < 0)
      {
	 if (errno != ECONNRESET && errno != EPIPE)
	    _error->Error("Could not read response to hello message from hook %s: %s", Opts->Value.c_str(), strerror(errno));
	 goto out;
      }
      {
	 auto responseObj = JSON::Value::parse(std::string_view(line, static_cast<std::size_t>(size)));
	 if (not responseObj)
	 {
	    _error->Error("Could not parse response to hello message from hook %s: %s", Opts->Value.c_str(), responseObj.error().message.c_str());
	    goto out;
	 }
	 auto response = responseObj->get<Hook::Hello::Reply>();
	 if (not response || not response->result)
	 {
	    _error->Error("Hook %s reported an error during hello: %s", Opts->Value.c_str(), line);
	    goto out;
	 }

	 if (response->result->version == "0.1")
	    hookVersion = 0x010;
	 else if (response->result->version == "0.2")
	    hookVersion = 0x020;
	 else
	 {
	    _error->Error("Unknown hook version in handshake from hook %s: %s", Opts->Value.c_str(), line);
	    goto out;
	 }
      }

      size = getline(&line, &linesize, F);
      if (size < 0)
      {
	 _error->Error("Could not read message separator line after handshake from %s: %s", Opts->Value.c_str(), feof(F) ? "end of file" : strerror(errno));
	 goto out;
      }
      else if (size == 0 || line[0] != '\n')
      {
	 _error->Error("Expected empty line after handshake from %s, received %s", Opts->Value.c_str(), line);
	 goto out;
      }
      {
	 std::string &data = notifications[hookVersion];
	 if (data.empty())
	 {
	    data = NotifyHook(method, FileList, Cache, UnknownPackages, hookVersion);
	 }
	 fwrite(data.data(), data.size(), 1, F);
	 fwrite("\n\n", 2, 1, F);
      }

      fwrite(ByeData.data(), ByeData.size(), 1, F);
      fwrite("\n\n", 2, 1, F);
   out:
      fclose(F);
      F = nullptr;
      // Clean up the sub process
      const bool waitResult = ExecWait(Process, Opts->Value.c_str());
      processWaited = true;
      if (waitResult == false)
      {
	 result = _error->Error("Failure running hook %s", Opts->Value.c_str());
	 break;
      }
   }

   return result;
}
