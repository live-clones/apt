// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   CacheDB
   
   Simple uniform interface to a cache database.
   
   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/debfile.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/gpgv.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/strutl.h>

#include <cctype>
#include <cstddef>
#include <netinet/in.h> // htonl, etc
#include <strings.h>
#include <sys/stat.h>

#include "cachedb.h"

#include <apti18n.h>
									/*}}}*/

CacheDB::CacheDB(std::string const &DB)
   : Fd(NULL), DebFile(0)
{
   ReadyDB(DB);
}

CacheDB::~CacheDB()
{
   ReadyDB();
   delete DebFile;
   CloseFile();
}

// CacheDB::ReadyDB - Ready the DB2					/*{{{*/
// ---------------------------------------------------------------------
/* This opens the DB2 file for caching package information */
bool CacheDB::ReadyDB(std::string const &DB)
{

   ReadOnly = _config->FindB("APT::FTPArchive::ReadOnlyDB",false);
   
   // Close the old DB
   if (Dbm.IsOpen())
       Dbm.Close();

   DBLoaded = false;
   DBFile = std::string();
   
   if (DB.empty())
      return true;

   // Tkrzw defaults are Ok:
   // - lock-for-write, shared-for-read access
   // - 1048583 buckets, which is ~4MiB size for an empty file
   // - No truncate, so we don't override bdb file
   // If opening errors, assume it's a Bdb file and die for now:
   // TODO: Deal with bdb files: warn and die, migrate, ?
   tkrzw::Status ret = Dbm.Open(DB, !ReadOnly, tkrzw::File::OPEN_DEFAULT);
   if (ret != tkrzw::Status::SUCCESS)
   {
      if (FileExists(DB)) {
	     _error->Error(_("DB format is invalid. If you upgraded from an older version of apt, please remove and re-create the database."));

      }
       return _error->Error(_("Unable to open DB file %s: %s"),DB.c_str(),ret.GetMessage().c_str());
   }

   DBFile = DB;
   DBLoaded = true;
   return true;
}
									/*}}}*/
// CacheDB::OpenFile - Open the file					/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::OpenFile()
{
   // always close existing file first
   CloseFile();

   // open a new file
   Fd = new FileFd(FileName,FileFd::ReadOnly);
   if (_error->PendingError() == true)
   {
      CloseFile();
      return false;
   }
   return true;
}
									/*}}}*/
// CacheDB::CloseFile - Close the file					/*{{{*/
void CacheDB::CloseFile()
{
   if(Fd != NULL)
   {
      delete Fd;
      Fd = NULL;
   }
}
									/*}}}*/
// CacheDB::OpenDebFile - Open a debfile				/*{{{*/
bool CacheDB::OpenDebFile()
{
   // always close existing file first
   CloseDebFile();

   // first open the fd, then pass it to the debDebFile
   if(OpenFile() == false)
      return false;
   DebFile = new debDebFile(*Fd);
   if (_error->PendingError() == true)
      return false;
   return true;
}
									/*}}}*/
// CacheDB::CloseDebFile - Close a debfile again 			/*{{{*/
void CacheDB::CloseDebFile()
{
   CloseFile();

   if(DebFile != NULL)
   {
      delete DebFile;
      DebFile = NULL;
   }
}
									/*}}}*/
// CacheDB::GetFileStat - Get stats from the file 			/*{{{*/
// ---------------------------------------------------------------------
/* This gets the size from the database if it's there.  If we need
 * to look at the file, also get the mtime from the file. */
bool CacheDB::GetFileStat(bool const &doStat)
{
   if ((CurStat.Flags & FlSize) == FlSize && doStat == false)
      return true;

   /* Get it from the file. */
   if (OpenFile() == false)
      return false;
   
   // Stat the file
   struct stat St;
   if (fstat(Fd->Fd(),&St) != 0)
   {
      CloseFile();
      return _error->Errno("fstat",
                           _("Failed to stat %s"),FileName.c_str());
   }
   CurStat.FileSize = St.st_size;
   CurStat.mtime = htonl(St.st_mtime);
   CurStat.Flags |= FlSize;
   
   return true;
}
									/*}}}*/
// CacheDB::GetCurStatNewFormat           			/*{{{*/
// ---------------------------------------------------------------------
/* Read the new StateStore format from Tkrzw HashDB value */
bool CacheDB::GetCurStatNewFormat()
{
   InitQueryStats();
   if (Get() == false)
   {
      CurStat.Flags = 0;
   }
   //deserialize Data as a map<string, string> and copy to CurStat
   std::map<std::string,std::string> tempMap = tkrzw::DeserializeStrMap(Data);
   CurStat.Flags = std::stoul(tempMap[MAP_Flags]);
   CurStat.mtime = std::stoul(tempMap[MAP_MTime]);
   CurStat.FileSize = std::stoull(tempMap[MAP_FileSize]);
   CurStat.MD5 = tempMap[MAP_MD5];
   CurStat.SHA1 = tempMap[MAP_SHA1];
   CurStat.SHA256 = tempMap[MAP_SHA256];
   CurStat.SHA512 = tempMap[MAP_SHA512];
   return true;
}
									/*}}}*/
// CacheDB::GetCurStat - Set the CurStat variable.			/*{{{*/
// ---------------------------------------------------------------------
/* Sets the CurStat variable.  Either to 0 if no database is used
 * or to the value in the database if one is used */
bool CacheDB::GetCurStat()
{
   //memset(&CurStat,0,sizeof(CurStat));
   CurStat.Flags = 0;
   CurStat.mtime = 0;
   CurStat.FileSize = 0;
   CurStat.MD5.clear();
   CurStat.SHA1.clear();
   CurStat.SHA256.clear();
   CurStat.SHA512.clear();
   
   if (DBLoaded)
   {
      // do a first query to just get the size of the data on disk
      InitQueryStats();
      Get();

      if (Data.length() > 0)
          GetCurStatNewFormat();
   }      
   return true;
}
									/*}}}*/
// CacheDB::GetFileInfo - Get all the info about the file		/*{{{*/
// ---------------------------------------------------------------------
bool CacheDB::GetFileInfo(std::string const &FileName, bool const &DoControl, bool const &DoContents,
				bool const &GenContentsOnly, bool const DoSource, unsigned int const DoHashes,
                          bool const &checkMtime)
{
   this->FileName = FileName;

   if (GetCurStat() == false)
      return false;
   //Skip copying all hash strings
   OldStat.Flags = CurStat.Flags;
   OldStat.mtime = CurStat.mtime;
   OldStat.FileSize = CurStat.FileSize;

   if (GetFileStat(checkMtime) == false)
      return false;

   /* if mtime changed, update CurStat from disk */
   if (checkMtime == true && OldStat.mtime != CurStat.mtime)
      CurStat.Flags = FlSize;

   Stats.Bytes += CurStat.FileSize;
   ++Stats.Packages;

   if ((DoControl && LoadControl() == false)
	 || (DoContents && LoadContents(GenContentsOnly) == false)
	 || (DoSource && LoadSource() == false)
	 || (DoHashes != 0 && GetHashes(false, DoHashes) == false)
      )
   {
      return false;
   }

   return true;
}
									/*}}}*/
bool CacheDB::LoadSource()						/*{{{*/
{
   // Try to read the control information out of the DB.
   if ((CurStat.Flags & FlSource) == FlSource)
   {
      // Lookup the control information
      InitQuerySource();
      if (Get() == true && Dsc.TakeDsc(Data.data(), Data.size()) == true)
      {
	    return true;
      }
      CurStat.Flags &= ~FlSource;
   }
   if (OpenFile() == false)
      return false;

   Stats.Misses++;
   if (Dsc.Read(FileName) == false)
      return false;

   if (Dsc.Length == 0)
      return _error->Error(_("Failed to read .dsc"));

   // Write back the control information
   InitQuerySource();
   if (Put(Dsc.Data) == true)
      CurStat.Flags |= FlSource;

   return true;
}
									/*}}}*/
// CacheDB::LoadControl - Load Control information			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::LoadControl()
{
   // Try to read the control information out of the DB.
   if ((CurStat.Flags & FlControl) == FlControl)
   {
      // Lookup the control information
      InitQueryControl();
      if (Get() == true && Control.TakeControl(Data.data(),Data.length()) == true)
	    return true;
      CurStat.Flags &= ~FlControl;
   }
   
   if(OpenDebFile() == false)
      return false;
   
   Stats.Misses++;
   if (Control.Read(*DebFile) == false)
      return false;

   if (Control.Control == 0)
      return _error->Error(_("Archive has no control record"));
   
   // Write back the control information
   InitQueryControl();
   //TODO: is MemControlExtract.Data a c string or fixed len? string_view?
   if (Put(std::string(Control.Control,Control.Length)) == true)
      CurStat.Flags |= FlControl;
   return true;
}
									/*}}}*/
// CacheDB::LoadContents - Load the File Listing			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::LoadContents(bool const &GenOnly)
{
   // Try to read the control information out of the DB.
   if ((CurStat.Flags & FlContents) == FlContents)
   {
      if (GenOnly == true)
	 return true;
      
      // Lookup the contents information
      InitQueryContent();
      if (Get() == true)
      {
	 if (Contents.TakeContents(Data.data(),Data.length()) == true)
	    return true;
      }
      
      CurStat.Flags &= ~FlContents;
   }
   
   if(OpenDebFile() == false)
      return false;

   Stats.Misses++;
   if (Contents.Read(*DebFile) == false)
      return false;	    
   
   // Write back the control information
   InitQueryContent();
   //TODO: is ContentsExtract.Data a c string or fixed len? string_view?
   if (Put(std::string(Contents.Data,Contents.CurSize)) == true)
      CurStat.Flags |= FlContents;
   return true;
}
									/*}}}*/
// // CacheDB::GetHashes - Get the hashes					/*{{{*/
bool CacheDB::GetHashes(bool const GenOnly, unsigned int const DoHashes)
{
   unsigned int notCachedHashes = 0;
   if ((CurStat.Flags & FlMD5) != FlMD5)
   {
      notCachedHashes = notCachedHashes | Hashes::MD5SUM;
   }
   if ((CurStat.Flags & FlSHA1) != FlSHA1)
   {
      notCachedHashes = notCachedHashes | Hashes::SHA1SUM;
   }
   if ((CurStat.Flags & FlSHA256) != FlSHA256)
   {
      notCachedHashes = notCachedHashes | Hashes::SHA256SUM;
   }
   if ((CurStat.Flags & FlSHA512) != FlSHA512)
   {
      notCachedHashes = notCachedHashes | Hashes::SHA512SUM;
   }
   unsigned int FlHashes = DoHashes & notCachedHashes;
   HashesList.clear();

   if (FlHashes != 0)
   {
      if (OpenFile() == false)
	 return false;

      Hashes hashes(FlHashes);
      if (Fd->Seek(0) == false || hashes.AddFD(*Fd, CurStat.FileSize) == false)
	 return false;

      HashStringList hl = hashes.GetHashStringList();
      for (HashStringList::const_iterator hs = hl.begin(); hs != hl.end(); ++hs)
      {
	 HashesList.push_back(*hs);
	 if (strcasecmp(hs->HashType().c_str(), "SHA512") == 0)
	 {
	    Stats.SHA512Bytes += CurStat.FileSize;
        CurStat.SHA512 = hs->HashValue();
	    CurStat.Flags |= FlSHA512;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA256") == 0)
	 {
	    Stats.SHA256Bytes += CurStat.FileSize;
        CurStat.SHA256 = hs->HashValue();
	    CurStat.Flags |= FlSHA256;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA1") == 0)
	 {
	    Stats.SHA1Bytes += CurStat.FileSize;
        CurStat.SHA1 = hs->HashValue();
	    CurStat.Flags |= FlSHA1;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "MD5Sum") == 0)
	 {
	    Stats.MD5Bytes += CurStat.FileSize;
        CurStat.MD5 = hs->HashValue();
	    CurStat.Flags |= FlMD5;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "Checksum-FileSize") == 0)
	 {
	    // we store it in a different field already
	 }
	 else
	    return _error->Error("Got unknown unrequested hashtype %s", hs->HashType().c_str());
      }
   }
   if (GenOnly == true)
      return true;

   bool ret = true;
#define PUSH_BACK_HASH(FLAG, TYPE, VALUE) \
   if ((CurStat.Flags & FLAG) == FLAG) \
      ret &= HashesList.push_back(HashString(TYPE, VALUE));
   PUSH_BACK_HASH(FlMD5, "MD5Sum", CurStat.MD5);
   PUSH_BACK_HASH(FlSHA1, "SHA1", CurStat.SHA1);
   PUSH_BACK_HASH(FlSHA256, "SHA256", CurStat.SHA256);
   PUSH_BACK_HASH(FlSHA512, "SHA512", CurStat.SHA512);
   return ret;
}
									/*}}}*/
// CacheDB::Finish - Write back the cache structure			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::Finish()
{
   // Optimize away some writes.
   if (CurStat.Flags == OldStat.Flags &&
       CurStat.mtime == OldStat.mtime)
      return true;

   // Write the stat information
   InitQueryStats();
   //Serialize CurStat as a map<string, string> and copy to Data
   std::map<std::string,std::string> tempMap;
   tempMap[MAP_Flags] = std::to_string(CurStat.Flags);
   tempMap[MAP_MTime] = std::to_string(CurStat.mtime);
   tempMap[MAP_FileSize] = std::to_string(CurStat.FileSize);
   tempMap[MAP_MD5] = CurStat.MD5;
   tempMap[MAP_SHA1] = CurStat.SHA1;
   tempMap[MAP_SHA256] = CurStat.SHA256;
   tempMap[MAP_SHA512] = CurStat.SHA512;
   Data = tkrzw::SerializeStrMap(tempMap);
   Put(Data);

   return true;
}
									/*}}}*/
// CacheDB::Clean - Clean the Database					/*{{{*/
// ---------------------------------------------------------------------
/* Tidy the database by removing files that no longer exist at all. */
bool CacheDB::Clean()
{
   if (DBLoaded == false)
      return true;

   auto dbmIter = Dbm.MakeIterator();
   if (dbmIter->First() != tkrzw::Status::SUCCESS) {
       //TODO: explain better and translate
       return _error->Error(_("Unable to get a cursor"));
   }
   
   std::string tempKey, tempData;
   std::map<std::string,std::string> tempMap;
   while (dbmIter->Step(&tempKey, &tempData) == tkrzw::Status::SUCCESS)
   {
      int ColonAt = Key.rfind(':');
      if (ColonAt)
      {
         if (Key.compare(ColonAt + 1, 2, "st") == 0 || Key.compare(ColonAt + 1, 2, "cl") == 0 ||
             Key.compare(ColonAt + 1, 2, "cs") == 0 || Key.compare(ColonAt + 1, 2, "cn") == 0)
	 {
            std::string FileName = Key.substr(0, ColonAt);
            if (FileExists(FileName) == true) {
		continue;
            }
	 }
      }
      dbmIter->Remove();
   }

   //After key removals, check for fragmentation
   bool shouldRebuild = false;
   tkrzw::Status ret = Dbm.ShouldBeRebuilt(&shouldRebuild);
   if (ret.IsOK() && shouldRebuild) {
      ret = Dbm.Rebuild();
      if (!ret.IsOK())
         _error->Warning("compact failed with result %s", ret.GetMessage().c_str());
   }

   //TODO: Print something useful from inspect()?
   // if(_config->FindB("Debug::APT::FTPArchive::Clean", false) == true)
   //    Dbp->stat_print(Dbp, 0);


   return true;
}
									/*}}}*/
