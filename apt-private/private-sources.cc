#include <config.h>

#include <apt-pkg/acquire-item.h>
#include <apt-pkg/acquire.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/cmndline.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/strutl.h>

#include <apt-private/private-download.h>
#include <apt-private/private-output.h>
#include <apt-private/private-sources.h>
#include <apt-private/private-utils.h>

#include <iostream>
#include <string>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <apti18n.h>

/* Interface discussion with donkult (for the future):
  apt [add-{archive,release,component}|edit|change-release|disable]-sources
 and be clever and work out stuff from the Release file
*/

// EditSource - EditSourcesList						/*{{{*/
class APT_HIDDEN ScopedGetLock {
public:
   int fd;
   explicit ScopedGetLock(std::string const &filename) : fd(GetLock(filename)) {}
   ~ScopedGetLock() { close(fd); }
};
bool AddSources(CommandLine &CmdL)
{
   std::string fromPath;
   bool deleteFrom = false;
   if (CmdL.FileList[1] == nullptr)
   {
      return _error->Error("add-sources needs exactly one argument");
   }
   if (not APT::String::Endswith(CmdL.FileList[1], ".sources"))
   {
      return _error->Error("argument to add-sources must end in .sources");
   }

   if (APT::String::Startswith(CmdL.FileList[1], "https://"))
   {
      fromPath = flCombine(flCombine(_config->FindDir("Dir::Cache::archives"), "partial"), flNotDir(CmdL.FileList[1]));
      deleteFrom = true;
      aptAcquireWithTextStatus acq;
      pkgAcqFile file(&acq, CmdL.FileList[1], HashStringList(), 0, std::string("Sources file ") + CmdL.FileList[1], ".sources file", "", fromPath);
      bool Failed = false;
      if (AcquireRun(acq, 0, &Failed, NULL) == false || Failed == true)
	 return _error->Error(_("Download Failed"));
      if (FileExists(file.DestFile) == false)
	 return _error->Error(_("Download Failed"));
   }
   else if (APT::String::Startswith(CmdL.FileList[1], "/") || APT::String::Startswith(CmdL.FileList[1], "./"))
   {
      fromPath = CmdL.FileList[1];
   }
   else
   {
      return _error->Error("add-sources takes exactly one https URL or filename");
   }
   FileFd from;
   FileFd to;
   std::string toPath = flCombine(_config->FindDir("Dir::Etc::sourceparts"), flNotDir(fromPath));
   pkgSourceList list;

   if (not list.ParseFileDeb822(flAbsPath(fromPath)))
      return false;

   if (FileExists(toPath) && not _config->FindB("APT::Cmd::Force-Override"))
      return _error->Error("%s already exists and --force-override not specified", toPath.c_str());
   if (not from.Open(fromPath, FileFd::ReadOnly, FileFd::None, 0644))
      return false;
   if (not to.Open(toPath, FileFd::Create | FileFd::WriteOnly, FileFd::None, 0644))
      return false;
   ScopedGetLock lock(to.Name());
   if (lock.fd < 0)
      return false;
   if (not CopyFile(from, to))
      return false;
   if (deleteFrom && not RemoveFile("AddSources", fromPath))
      return false;

   return true;
}

bool EditSources(CommandLine &CmdL)
{
   std::string sourceslist;
   if (CmdL.FileList[1] != NULL)
   {
      sourceslist = _config->FindDir("Dir::Etc::sourceparts") + CmdL.FileList[1];
      if (!APT::String::Endswith(sourceslist, ".list"))
         sourceslist += ".list";
   } else {
      sourceslist = _config->FindFile("Dir::Etc::sourcelist");
   }
   HashString before;
   if (FileExists(sourceslist))
       before.FromFile(sourceslist);
   else
   {
      FileFd filefd;
      if (filefd.Open(sourceslist, FileFd::Create | FileFd::WriteOnly, FileFd::None, 0644) == false)
	 return false;
   }

   ScopedGetLock lock(sourceslist);
   if (lock.fd < 0)
      return false;

   bool res;
   bool file_changed = false;
   do {
      if (EditFileInSensibleEditor(sourceslist) == false)
	 return false;
      if (before.empty())
      {
	 struct stat St;
	 if (stat(sourceslist.c_str(), &St) == 0 && St.st_size == 0)
	       RemoveFile("edit-sources", sourceslist);
      }
      else if (FileExists(sourceslist) && !before.VerifyFile(sourceslist))
      {
	 file_changed = true;
	 pkgCacheFile::RemoveCaches();
      }
      pkgCacheFile CacheFile;
      res = CacheFile.BuildCaches(nullptr);
      if (res == false || _error->empty(GlobalError::WARNING) == false) {
	 std::string outs;
	 strprintf(outs, _("Failed to parse %s. Edit again? "), sourceslist.c_str());
         // FIXME: should we add a "restore previous" option here?
         if (YnPrompt(outs.c_str(), true) == false)
	 {
	    if (res == false && _error->PendingError() == false)
	    {
	       CacheFile.Close();
	       pkgCacheFile::RemoveCaches();
	       res = CacheFile.BuildCaches(nullptr);
	    }
	    break;
	 }
      }
   } while (res == false);

   if (res == true && file_changed == true)
   {
      ioprintf(
         std::cout, _("Your '%s' file changed, please run 'apt-get update'.\n"),
         sourceslist.c_str());
   }
   return res;
}
									/*}}}*/
