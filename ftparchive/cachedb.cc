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
// Database DML/DDL						/*{{{*/
#define DBCACHE_TABLE "filecache"

#define DBCACHE_SQL_TABLE "" \
   "SELECT name " \
   "FROM sqlite_master " \
   "WHERE type = 'table' and name = '" DBCACHE_TABLE "'"

#define DBCACHE_SQL_CREATE "" \
   "CREATE TABLE " DBCACHE_TABLE "(" \
   "name TEXT PRIMARY KEY NOT NULL, " \
   "fmtime INT DEFAULT -1, " \
   "fsize INT DEFAULT -1, " \
   "control TEXT, " \
   "content TEXT," \
   "md5hash TEXT, " \
   "sha1hash TEXT, " \
   "sha256hash TEXT, " \
   "sha512hash TEXT);"

#define DBCACHE_SQL_SELECT "" \
   "SELECT fmtime, fsize, control, content, " \
   "md5hash, sha1hash, sha256hash, sha512hash " \
   "FROM " DBCACHE_TABLE " " \
   "WHERE name = ?"

#define DBCACHE_SQL_INSERT "" \
   "INSERT INTO " DBCACHE_TABLE " " \
   "(fmtime, fsize, control, content, " \
   "md5hash, sha1hash, sha256hash, sha512hash, name) " \
   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "

#define DBCACHE_SQL_UPDATE "" \
   "UPDATE " DBCACHE_TABLE " " \
   "set fmtime = ?, fsize = ?, control = ?, content = ?, " \
   "md5hash = ?, sha1hash = ?, sha256hash = ?, sha512hash = ? " \
   "WHERE name = ?"

#define DBCACHE_SQL_SELECT_ALLFILES "" \
   "SELECT name " \
   "FROM " DBCACHE_TABLE

#define DBCACHE_SQL_DELETE_FILE "" \
   "DELETE FROM " DBCACHE_TABLE " " \
   "WHERE name = ?"
									/*}}}*/

CacheDB::CacheDB(std::string const &DBFile)
   : DB(NULL), DBSelectStmt(NULL), Fd(NULL), DebFile(0)
{
   ReadyDB(DBFile);
}

CacheDB::~CacheDB()
{
   CloseDB();
   delete DebFile;
   CloseFile();
}

// CacheDB::ReadyDB - Ready the DB					/*{{{*/
// ---------------------------------------------------------------------
/* This opens the Sqlite3 file for caching package information */
bool CacheDB::ReadyDB(std::string const &DBFile)
{
   int err;

   ReadOnly = _config->FindB("APT::FTPArchive::ReadOnlyDB",false);

   // Close the old DB
   if (DB != NULL && !CloseDB()){
      return _error->Error(_("Unable to open ready DB file %s"), DBFile.c_str());
   }

   DBLoaded = false;
   DB = NULL;

   if (DBFile.empty())
      return true;

   //TODO: first, check if it's an old db5 file (or not sqlite3 easier)
   // then do something about it...
   // a. migrate? b. stash as *.old? c. replace completely
   if ((err = sqlite3_open_v2(DBFile.c_str(), &DB,
      (ReadOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE) | SQLITE_OPEN_CREATE, NULL)) != SQLITE_OK)
   {
      DB = NULL;
      return _error->Error(_("Unable to open DB file %s: %s"), DBFile.c_str(), sqlite3_errstr(err));
   }

   //check that cache table is there
   char *errmsg = NULL;
   sqlite3_stmt *statement;
   err = sqlite3_prepare_v2(DB, DBCACHE_SQL_TABLE, -1, &statement, NULL);
   if (err != SQLITE_OK)
   {
      CloseDB();
      return _error->Error(_("Unable to query DB %s: %s"), DBFile.c_str(), sqlite3_errstr(err));
   }
   err = sqlite3_step(statement);
   sqlite3_finalize(statement);
   if(err != SQLITE_ROW)
   {
      //create the table
      err = sqlite3_exec(DB, DBCACHE_SQL_CREATE, NULL, NULL, &errmsg);
      if(err != SQLITE_OK ){
         _error->Error(_("Unable to create DB table %s: %s"), DBCACHE_TABLE, errmsg);
         sqlite3_free(errmsg);
         return false;
      }
   }

   //prepare the common select query
   err = sqlite3_prepare_v2(DB, DBCACHE_SQL_SELECT, -1, &DBSelectStmt, NULL);
   if (err != SQLITE_OK)
      return _error->Error(_("Unable to prepare DB query %s: %s"), DBFile.c_str(), sqlite3_errstr(err));

   DBLoaded = true;
   return true;
}

bool CacheDB::CloseDB()
{
   int err;
   if (DBSelectStmt != NULL)
   {
      sqlite3_finalize(DBSelectStmt);
   }

   if (DB != NULL)
   {
      err = sqlite3_close(DB);
      if(err != SQLITE_OK)
      {
         _error->Error(_("Unable to close DB file: %s"), sqlite3_errstr(err));
         return false;
      }
      DB = NULL;
   }
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
   if (CurrFileSize > -1 && doStat == false)
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
   CurrFileSize = St.st_size;
   CurrFileMtime = St.st_mtime;

   return true;
}
									/*}}}*/
// CacheDB::GetCurStat - Set the CurStat variable.			/*{{{*/
// ---------------------------------------------------------------------
/* Sets the CurStat variable.  Either to 0 if no database is used
 * or to the value in the database if one is used */
bool CacheDB::GetCurStat()
{
   int err;

   CurrFileMtime = PrevFileMtime = CurrFileSize =-1;
   CurrFileFields.clear();
   CurrFileChanged = false;
   CurrFileLoaded = false;

   if (!DBLoaded)
      return true;


   sqlite3_reset(DBSelectStmt);
   sqlite3_clear_bindings(DBSelectStmt);
   err = sqlite3_bind_text(DBSelectStmt, 1, FileName.c_str(), -1, SQLITE_STATIC);
   if (err != SQLITE_OK)
      return _error->Error(_("Unable to prepare DB query %s: %s"), FileName.c_str(), sqlite3_errstr(err));

   err = sqlite3_step(DBSelectStmt);
   if (err == SQLITE_ROW)
   {
      //row found, load it
      CurrFileMtime = PrevFileMtime = sqlite3_column_int(DBSelectStmt, 0);
      CurrFileSize   = sqlite3_column_int64(DBSelectStmt, 1);
      FieldInitText(DBSelectStmt, 2, "control");
      FieldInitBlob(DBSelectStmt, 3, "content"); //null-separated list
      FieldInitText(DBSelectStmt, 4, "MD5");
      FieldInitText(DBSelectStmt, 5, "SHA1");
      FieldInitText(DBSelectStmt, 6, "SHA256");
      FieldInitText(DBSelectStmt, 7, "SHA512");
      CurrFileLoaded = true;
   }

   return true;
}

bool CacheDB::PutCurStat()
{
   int err;
   sqlite3_stmt *statement;


   if (CurrFileLoaded)
   {
      //update existing record
      err = sqlite3_prepare_v2(DB, DBCACHE_SQL_UPDATE, -1, &statement, NULL);
      if (err != SQLITE_OK)
         return _error->Error(_("Unable to prepare DB update %s: %s"), FileName.c_str(), sqlite3_errstr(err));
   } else
   {
      //insert new record
      err = sqlite3_prepare_v2(DB, DBCACHE_SQL_INSERT, -1, &statement, NULL);
      if (err != SQLITE_OK)
         return _error->Error(_("Unable to prepare DB insert %s: %s"), FileName.c_str(), sqlite3_errstr(err));
   }

   //bind columns common to INSERT/UPDATE
   sqlite3_bind_int(statement, 1, CurrFileMtime);
   sqlite3_bind_int(statement, 2, CurrFileSize);
   FieldBindText(statement, 3, "control");
   FieldBindText(statement, 4, "content");
   FieldBindText(statement, 5, "MD5");
   FieldBindText(statement, 6, "SHA1");
   FieldBindText(statement, 7, "SHA256");
   FieldBindText(statement, 8, "SHA512");
   sqlite3_bind_text(statement, 9, FileName.c_str(), -1, SQLITE_STATIC);

   err = sqlite3_step(statement);
   if (err != SQLITE_DONE)
      return _error->Error(_("Unable to update/insert DB %s: %s"), FileName.c_str(), sqlite3_errstr(err));

   CurrFileChanged = false;
   CurrFileLoaded = true;
   sqlite3_finalize(statement);

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
   if (GetFileStat(checkMtime) == false)
      return false;

   /* if mtime changed, update CurStat from disk */
   if (checkMtime == true && CurrFileMtime != PrevFileMtime)
      CurrFileChanged = true;

   Stats.Bytes += CurrFileSize;
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
   if (CurrFileFields.count("control"))
   {
      std::string ctrl = CurrFileFields["control"];
      return Dsc.TakeDsc(ctrl.c_str(), ctrl.length());
   }

   if (OpenFile() == false)
      return false;

   Stats.Misses++;
   if (Dsc.Read(FileName) == false)
      return false;

   if (Dsc.Length == 0)
      return _error->Error(_("Failed to read .dsc"));

   // Write back the control information
   CurrFileFields["control"]= std::string(Dsc.Data.c_str(), Dsc.Length);
   CurrFileChanged = true;

   return true;
}
									/*}}}*/
// CacheDB::LoadControl - Load Control information			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::LoadControl()
{
   // Try to read the control information out of the DB.
   if (CurrFileFields.count("control"))
   {
      std::string ctrl = CurrFileFields["control"];
      return Control.TakeControl(ctrl.c_str(), ctrl.length());
   }
   
   if(OpenDebFile() == false)
      return false;
   
   Stats.Misses++;
   if (Control.Read(*DebFile) == false)
      return false;

   if (Control.Control == 0)
      return _error->Error(_("Archive has no control record"));
   
   // Write back the control information
   auto tmp = std::string(Control.Control, Control.Length);
   CurrFileFields["control"] = tmp;
   CurrFileChanged = true;

   return true;
}
									/*}}}*/
// CacheDB::LoadContents - Load the File Listing			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::LoadContents(bool const &GenOnly)
{
   // Try to read the control information out of the DB.
   if (CurrFileFields.count("content"))
   {
      if (GenOnly == true)
         return true;
      std::string cont = CurrFileFields["content"];
      return Contents.TakeContents(cont.c_str(), cont.length());
   }

   if(OpenDebFile() == false)
      return false;

   Stats.Misses++;
   if (Contents.Read(*DebFile) == false)
      return false;	    
   
   // Write back the control information
   CurrFileFields["content"]= std::string(Contents.Data, Contents.CurSize);
   CurrFileChanged = true;

   return true;
}
									/*}}}*/
// CacheDB::GetHashes - Get the hashes					/*{{{*/
bool CacheDB::GetHashes(bool const GenOnly, unsigned int const DoHashes)
{
   unsigned int notCachedHashes = 0;
   if (!CurrFileFields.count("MD5"))
   {
      notCachedHashes = notCachedHashes | Hashes::MD5SUM;
   }
   if (!CurrFileFields.count("SHA1"))
   {
      notCachedHashes = notCachedHashes | Hashes::SHA1SUM;
   }
   if (!CurrFileFields.count("SHA256"))
   {
      notCachedHashes = notCachedHashes | Hashes::SHA256SUM;
   }
   if (!CurrFileFields.count("SHA512"))
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
      if (Fd->Seek(0) == false || hashes.AddFD(*Fd, CurrFileSize) == false)
	 return false;

      HashStringList hl = hashes.GetHashStringList();
      for (HashStringList::const_iterator hs = hl.begin(); hs != hl.end(); ++hs)
      {
	 HashesList.push_back(*hs);
	 if (strcasecmp(hs->HashType().c_str(), "SHA512") == 0)
	 {
	    Stats.SHA512Bytes += CurrFileSize;
        CurrFileFields["SHA512"] = hs->HashValue();
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA256") == 0)
	 {
	    Stats.SHA256Bytes += CurrFileSize;
        CurrFileFields["SHA256"] = hs->HashValue();
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "SHA1") == 0)
	 {
	    Stats.SHA1Bytes += CurrFileSize;
        CurrFileFields["SHA1"] = hs->HashValue();
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "MD5Sum") == 0)
	 {
	    Stats.MD5Bytes += CurrFileSize;
        CurrFileFields["MD5"] = hs->HashValue();
	 }
	 else if (strcasecmp(hs->HashType().c_str(), "Checksum-FileSize") == 0)
	 {
	    // we store it in a different field already
	 }
	 else
	    return _error->Error("Got unknown unrequested hashtype %s", hs->HashType().c_str());
      }

      CurrFileChanged = true;
   }
   if (GenOnly == true)
      return true;

   HashesList.push_back(HashString("MD5Sum", CurrFileFields["MD5"].c_str()));
   HashesList.push_back(HashString("SHA1", CurrFileFields["SHA1"].c_str()));
   HashesList.push_back(HashString("SHA256", CurrFileFields["SHA256"].c_str()));
   HashesList.push_back(HashString("SHA512", CurrFileFields["SHA512"].c_str()));

   return true;
}
									/*}}}*/
// CacheDB::Finish - Write back the cache structure			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool CacheDB::Finish()
{
   //writeback to database
   if (CurrFileChanged)
      PutCurStat();

   return true;
}
									/*}}}*/
// CacheDB::Clean - Clean the Database					/*{{{*/
// ---------------------------------------------------------------------
/* Tidy the database by removing files that no longer exist at all. */
//TODO: test with a real config file
bool CacheDB::Clean()
{
   if (DBLoaded == false)
      return true;

   int err;
   sqlite3_stmt *statement, *delstmt;
   err = sqlite3_prepare_v2(DB, DBCACHE_SQL_SELECT_ALLFILES, -1, &statement, NULL);
   if (err != SQLITE_OK)
      return _error->Error(_("Unable to prepare DB all query: %s"), sqlite3_errstr(err));

   err = sqlite3_prepare_v2(DB, DBCACHE_SQL_DELETE_FILE, -1, &delstmt, NULL);
   if (err != SQLITE_OK)
      return _error->Error(_("Unable to prepare DB delete: %s"), sqlite3_errstr(err));

   while (sqlite3_step(statement) == SQLITE_ROW)
   {
      const unsigned char *value = sqlite3_column_text(statement, 0);
      std::string FileName = std::string(reinterpret_cast<char const*>(value));
      if (FileExists(FileName) == true) {
         continue;
      }
      //delete record
      sqlite3_reset(delstmt);
      sqlite3_clear_bindings(delstmt);
      err = sqlite3_bind_text(delstmt, 1, FileName.c_str(), -1, SQLITE_STATIC);
      if (err != SQLITE_OK)
         continue;
      if (sqlite3_step(delstmt) != SQLITE_DONE)
      {
         _error->Warning(_("Unable to delete DB file: %s : %s"), FileName.c_str(), sqlite3_errstr(err));
         continue;
      }
   }
   sqlite3_finalize(statement);
   sqlite3_finalize(delstmt);

   //vacuum up any free space, i.e. compact
   char *errmsg = NULL;
   err = sqlite3_exec(DB, "vacuum;", NULL, NULL, &errmsg);
   if (err != SQLITE_OK)
   {
      _error->Warning(_("Unable to vacuum DB: %s"), errmsg);
      sqlite3_free(errmsg);
   }

   return true;
}
									/*}}}*/
