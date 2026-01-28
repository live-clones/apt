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
{
   TmpKey[0]='\0';
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
   int err;

   ReadOnly = _config->FindB("APT::FTPArchive::ReadOnlyDB",false);
   
   // Close the old DB
   if (DbTxn != NULL)
   {
      err = mdb_txn_commit(DbTxn);
      if (err)
        _error->Warning(_("DB transaction ran into an error while saving/closing: %s"),mdb_strerror(err));

      DbTxn = NULL;
      //mdb_dbi_close(DbEnv, Dbi);
      mdb_env_close(DbEnv);
      Dbi = 0;
      DbEnv = NULL;
   }

   //TODO: we just set DbTxn to NULL, this will never run.
   // Besides, lmdb doesn't save if anything serious happens, so the
   // above commit() will fail.
   // /* Check if the DB was disabled while running and deal with a 
   //    corrupted DB */
   // if (DBFailed() == true)
   // {
   //    _error->Warning(_("DB was corrupted, file renamed to %s.old"),DBFile.c_str());
   //    rename(DBFile.c_str(),(DBFile+".old").c_str());
   // }
   
   DBLoaded = false;
   Dbi = 0;
   DBFile = std::string();
   
   if (DB.empty())
      return true;

   if ((err = mdb_env_create(&DbEnv)))
      return _error->Error(_("Unable to open DB file %s: %s"),DB.c_str(), mdb_strerror(err));

   // if lmdb runs out of space, it won't save the transaction at the mdb_txn_commit() above.
   if ((err = mdb_env_set_mapsize(DbEnv, DB_MAPSIZE)) != 0)
   {
      _error->Warning(_("DB virtual memory sizing failed at '%li', trying lower value. %s"), DB_MAPSIZE, mdb_strerror(err));
      if ((err = mdb_env_set_mapsize(DbEnv, DB_MAPSIZE / 4)) != 0)
      {
         //TODO: what to do?
         return _error->Error(_("DB virtual memory sizing failed at '%li', please... . %s"), DB_MAPSIZE / 4, mdb_strerror(err));
      }
   }

   if ((err = mdb_env_open(DbEnv,DB.c_str(),MDB_NOSUBDIR | (ReadOnly ? MDB_RDONLY : 0),0664)))
   {
      mdb_env_close(DbEnv);
      if (err == MDB_INVALID || err == MDB_VERSION_MISMATCH)
         _error->Error(_("DB format is invalid. If you upgraded from an older version of apt, please remove and re-create the database."));

      return _error->Error(_("Unable to open DB file %s: %s"),DB.c_str(), mdb_strerror(err));
   }

   if ((err = mdb_txn_begin(DbEnv, NULL, 0, &DbTxn)))
   {
      mdb_env_close(DbEnv);
      return _error->Error(_("Unable to open DB transaction for %s: %s"),DB.c_str(), mdb_strerror(err));
   }

   if ((err = mdb_dbi_open(DbTxn, NULL, 0, &Dbi)))
   {
      mdb_txn_abort(DbTxn);
      DbTxn = NULL;
      mdb_env_close(DbEnv);
      return _error->Error(_("Unable to open DB transaction for %s: %s"),DB.c_str(), mdb_strerror(err));
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
   CurStat.mtime = St.st_mtime;
   CurStat.Flags |= FlSize;
   
   return true;
}
									/*}}}*/
// CacheDB::GetCurStat - Set the CurStat variable.			/*{{{*/
// ---------------------------------------------------------------------
/* Sets the CurStat variable.  Either to 0 if no database is used
 * or to the value in the database if one is used */
bool CacheDB::GetCurStat()
{
   memset(&CurStat,0,sizeof(CurStat));
   
   if (DBLoaded)
   {
      // do a first query to just get the size of the data on disk
      InitQueryStats();

      if (!Get())
         return true;

      if (Data.mv_size != sizeof(CurStat))
         return _error->Error("Cache record size mismatch (%lu)", Data.mv_size);

      memcpy(&CurStat, Data.mv_data, sizeof(CurStat));

      //TODO: Can you cache on 1 machine and reuse on a different arch?
      // just store in host endian - FileSize was always wrong anyway (u64).
      CurStat.Flags = ntohl(CurStat.Flags);
      CurStat.FileSize = ntohl(CurStat.FileSize);
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
   OldStat = CurStat;

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
      if (Get() == true && Dsc.TakeDsc(Data.mv_data, Data.mv_size) == true)
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
   if (Put(Dsc.Data.c_str(), Dsc.Length) == true)
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
      if (Get() == true && Control.TakeControl(Data.mv_data,Data.mv_size) == true)
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
   if (Put(Control.Control,Control.Length) == true)
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
	 if (Contents.TakeContents(Data.mv_data,Data.mv_size) == true)
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
   if (Put(Contents.Data,Contents.CurSize) == true)
      CurStat.Flags |= FlContents;
   return true;
}
									/*}}}*/
// CacheDB::GetHashes - Get the hashes					/*{{{*/
static std::string bytes2hex(uint8_t *bytes, size_t length) {
   char buf[3];
   std::string space;

   space.reserve(length*2 + 1);
   for (size_t i = 0; i < length; i++) {
      snprintf(buf, sizeof(buf), "%02x", bytes[i]);
      space.append(buf);
   }
   return space;
}

static inline unsigned char xdig2num(char const &dig) {
   if (isdigit(dig)) return dig - '0';
   if ('a' <= dig && dig <= 'f') return dig - 'a' + 10;
   if ('A' <= dig && dig <= 'F') return dig - 'A' + 10;
   return 0;
}

static void hex2bytes(uint8_t *bytes, const char *hex, int length) {
   while (length-- > 0) {
      *bytes = 0;
      if (isxdigit(hex[0]) && isxdigit(hex[1])) {
	  *bytes = xdig2num(hex[0]) * 16 + xdig2num(hex[1]);
	  hex += 2;
      }
      bytes++;
   } 
}
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
	    hex2bytes(CurStat.SHA512, hs->HashValue().data(), sizeof(CurStat.SHA512));
	    CurStat.Flags |= FlSHA512;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA256") == 0)
	 {
	    Stats.SHA256Bytes += CurStat.FileSize;
	    hex2bytes(CurStat.SHA256, hs->HashValue().data(), sizeof(CurStat.SHA256));
	    CurStat.Flags |= FlSHA256;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA1") == 0)
	 {
	    Stats.SHA1Bytes += CurStat.FileSize;
	    hex2bytes(CurStat.SHA1, hs->HashValue().data(), sizeof(CurStat.SHA1));
	    CurStat.Flags |= FlSHA1;
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "MD5Sum") == 0)
	 {
	    Stats.MD5Bytes += CurStat.FileSize;
	    hex2bytes(CurStat.MD5, hs->HashValue().data(), sizeof(CurStat.MD5));
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
      ret &= HashesList.push_back(HashString(TYPE, bytes2hex(VALUE, sizeof(VALUE))));
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
   CurStat.Flags = htonl(CurStat.Flags);
   CurStat.FileSize = htonl(CurStat.FileSize);
   InitQueryStats();
   if (!Put(&CurStat,sizeof(CurStat)))
      _error->Warning(_("Put ran into an issue"));
   CurStat.Flags = ntohl(CurStat.Flags);
   CurStat.FileSize = ntohl(CurStat.FileSize);

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

   int err;
   MDB_cursor *Cursor;

   if ((err = mdb_cursor_open(DbTxn, Dbi, &Cursor)))
      return _error->Error(_("Unable to get a cursor"));
   
   while ((err = mdb_cursor_get(Cursor, &Key, &Data, MDB_NEXT)) == 0)
   {
      const char *Colon = (char*)memrchr(Key.mv_data, ':', Key.mv_size);
      if (Colon)
      {
         if (stringcmp(Colon + 1, (char *)Key.mv_data+Key.mv_size,"st") == 0 ||
               stringcmp(Colon + 1, (char *)Key.mv_data+Key.mv_size,"cl") == 0 ||
               stringcmp(Colon + 1, (char *)Key.mv_data+Key.mv_size,"cs") == 0 ||
               stringcmp(Colon + 1, (char *)Key.mv_data+Key.mv_size,"cn") == 0)
         {
            std::string FileName = std::string((const char *)Key.mv_data,Colon);
            if (FileExists(FileName) == true) {
               continue;
            }
         }
      }
      mdb_cursor_del(Cursor, 0);
   }
   //It's a mem-mapped Btreee, no compaction or fragmentation

   if(_config->FindB("Debug::APT::FTPArchive::Clean", false) == true)
   {
      //simulate output of mdb_stat
      MDB_stat stats;
      memset(&stats, 0, sizeof(stats));
      if (mdb_stat(DbTxn, Dbi, &stats) == 0)
      {
         std::cout << "Status of Main DB"    << std::endl;
         std::cout << "  Tree depth: "       << stats.ms_depth << std::endl;
         std::cout << "  Branch pages: "     << stats.ms_branch_pages << std::endl;
         std::cout << "  Leaf pages: "       << stats.ms_leaf_pages << std::endl;
         std::cout << "  Overflow pages: "   << stats.ms_overflow_pages << std::endl;
         std::cout << "  Entries: "          << stats.ms_entries << std::endl;
      }
   }

   return true;
}
									/*}}}*/
