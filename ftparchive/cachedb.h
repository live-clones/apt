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
#include <lmdb.h>
#include <string>

#include "contents.h"
#include "sources.h"

// Memory map size to use for LMDB - virtual, not physical.
//    Has to be pagesize multiples, 4KiB or getpagesize()?
//    Should probably do an async flush every X puts
//    1 dist repo 'packages' database needs roughly 1GB - allow several.
#define DB_MAPSIZE      10240L * (256 * 4096)     // 10GiB

class FileFd;


class CacheDB
{
   protected:
      
   // Database state/access
   MDB_val Key;
   MDB_val Data;
   std::string TmpKey;
   MDB_dbi Dbi {};
   MDB_txn *DbTxn {};
   MDB_env *DbEnv {};
   bool DBLoaded;
   bool ReadOnly;
   std::string DBFile;

   // Generate a key for the DB of a given type
   void _InitQuery(const char *Type)
   {
      TmpKey.assign(FileName).append(":").append(Type);
      Key.mv_data = TmpKey.data();
      Key.mv_size = TmpKey.size();
   }
   
   void InitQueryStats() {
      _InitQuery("st");
   }
   void InitQuerySource() {
      _InitQuery("cs");
   }
   void InitQueryControl() {
      _InitQuery("cl");
   }
   void InitQueryContent() {
      _InitQuery("cn");
   }

   inline bool Get() 
   {
      return mdb_get(DbTxn, Dbi, &Key, &Data) == 0;
   };
   inline bool Put(const void *In,unsigned long const &Length) 
   {
      if (ReadOnly == true)
         return true;
      Data.mv_size = Length;
      Data.mv_data = (void *)In;
      int err = mdb_put(DbTxn,Dbi,&Key,&Data,0);
      if (DBLoaded == true && err != 0)
      {
         //TODO: not translated, move to source file, maybe stop inlining?
         _error->Warning("DB put failed to store a record: %s",mdb_strerror(err));
         DBLoaded = false;
         return false;
      }
      return true;
   }
   bool OpenFile();
   void CloseFile();

   bool OpenDebFile();
   void CloseDebFile();

   bool GetCurStat();
   bool GetFileStat(bool const &doStat = false);
   bool LoadControl();
   bool LoadContents(bool const &GenOnly);
   bool LoadSource();
   bool GetHashes(bool const GenOnly, unsigned int const DoHashes);

   // Stat info stored in the DB, Fixed types since it is written to disk.
   enum FlagList {FlControl = (1<<0),FlMD5=(1<<1),FlContents=(1<<2),
                  FlSize=(1<<3), FlSHA1=(1<<4), FlSHA256=(1<<5),
                  FlSHA512=(1<<6), FlSource=(1<<7)
   };

   // WARNING: this struct is read/written to the DB so do not change the
   //          layout of the fields (see lp #1274466), only append to it
   struct StatStore
   {
      uint32_t Flags;
      uint32_t mtime;          
      uint64_t FileSize;
      uint8_t  MD5[16];
      uint8_t  SHA1[20];
      uint8_t  SHA256[32];
      uint8_t  SHA512[64];
   } CurStat;
   struct StatStore OldStat;
   
   // 'set' state
   std::string FileName;
   FileFd *Fd {};
   debDebFile *DebFile {};
   
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
   inline bool DBFailed() {return DbTxn && DbEnv && Dbi != 0 && DBLoaded == false;};
   inline bool Loaded() {return DBLoaded == true;};
   
   inline unsigned long long GetFileSize(void) {return CurStat.FileSize;}
   
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
