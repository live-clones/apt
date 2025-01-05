// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   CacheDB
   
   Simple uniform interface to a cache database.
   
   ##################################################################### */
									/*}}}*/
#ifndef CACHEDB_H
#define CACHEDB_H

#include <apt-pkg/debfile.h>
#include <apt-pkg/hashes.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <sqlite3.h>

#include "contents.h"
#include "sources.h"

class FileFd;


class CacheDB
{
   protected:
      
   // Database state/access
   sqlite3 *DB;
   sqlite3_stmt *DBSelectStmt;
   bool DBLoaded;
   bool ReadOnly;


   bool OpenFile();
   void CloseFile();

   bool OpenDebFile();
   void CloseDebFile();

   // GetCurStat needs some compat code, see lp #1274466)
   bool GetCurStat();
   bool PutCurStat();

   bool GetFileStat(bool const &doStat = false);
   bool LoadControl();
   bool LoadContents(bool const &GenOnly);
   bool LoadSource();
   bool GetHashes(bool const GenOnly, unsigned int const DoHashes);

   // 'set' state
   std::string FileName;
   FileFd *Fd;
   debDebFile *DebFile;

   bool CurrFileChanged;
   bool CurrFileLoaded;
   long CurrFileMtime;
   long CurrFileSize;
   long PrevFileMtime;
   std::map<std::string, std::string> CurrFileFields;

   inline void FieldInitText(sqlite3_stmt *stmt, int colindex, const char *fieldname)
   {
      const unsigned char *value = sqlite3_column_text(stmt, colindex);
      if(value)
         CurrFileFields[fieldname]= std::string(reinterpret_cast<char const*>(value));
   }

   inline void FieldInitBlob(sqlite3_stmt *stmt, int colindex, const char *fieldname)
   {
      const void *value = sqlite3_column_blob(stmt, colindex);
      int size = sqlite3_column_bytes(stmt, colindex);
      if(value)
         CurrFileFields[fieldname]= std::string(reinterpret_cast<char const*>(value), size);
   }

   inline void FieldBindText(sqlite3_stmt *stmt, int colindex, const char *fieldname)
   {
      if (CurrFileFields.count(fieldname))
      {
         std::string value = CurrFileFields[fieldname];
         sqlite3_bind_text(stmt, colindex, value.c_str(), value.length(), SQLITE_TRANSIENT);
      } else
      {
         sqlite3_bind_null(stmt, colindex);
      }
   }

   public:

   // Data collection helpers
   debDebFile::MemControlExtract Control;
   ContentsExtract Contents;
   DscExtract Dsc;
   HashStringList HashesList;

   // Runtime statistics
   struct Stats
   {
      double Bytes;
      double MD5Bytes;
      double SHA1Bytes;
      double SHA256Bytes;
      double SHA512Bytes;
      unsigned long Packages;
      unsigned long Misses;  
      unsigned long long DeLinkBytes;
      
      inline void Add(const Stats &S) {
	 Bytes += S.Bytes; 
         MD5Bytes += S.MD5Bytes; 
         SHA1Bytes += S.SHA1Bytes; 
	 SHA256Bytes += S.SHA256Bytes;
	 SHA512Bytes += S.SHA512Bytes;
	 Packages += S.Packages;
         Misses += S.Misses; 
         DeLinkBytes += S.DeLinkBytes;
      };
      Stats() : Bytes(0), MD5Bytes(0), SHA1Bytes(0), SHA256Bytes(0),
		SHA512Bytes(0),Packages(0), Misses(0), DeLinkBytes(0) {};
   } Stats;
   
   bool ReadyDB(std::string const &DB = "");
   bool CloseDB();
   inline bool DBFailed() {return DB != NULL && DBLoaded == false;};
   inline bool Loaded() {return DBLoaded == true;};
   
   inline unsigned long long GetFileSize(void) {return CurrFileSize;}
   
   bool SetFile(std::string const &FileName,struct stat St,FileFd *Fd);

   // terrible old overloaded interface
   bool GetFileInfo(std::string const &FileName,
	 bool const &DoControl,
	 bool const &DoContents,
	 bool const &GenContentsOnly,
	 bool const DoSource,
	 unsigned int const DoHashes,
	 bool const &checkMtime = false);

   bool Finish();   
   
   bool Clean();
   
   explicit CacheDB(std::string const &DB);
   ~CacheDB();
};
    
#endif
