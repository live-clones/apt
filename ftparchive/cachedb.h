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
#include <string>
#include <tkrzw_dbm_hash.h>
#include <tkrzw_str_util.h>

#include "contents.h"
#include "sources.h"

#define MAP_Flags    "Flags"
#define MAP_MTime    "MTime"
#define MAP_FileSize "FileSize"
#define MAP_MD5      "MD5"
#define MAP_SHA1     "SHA1"
#define MAP_SHA256   "SHA256"
#define MAP_SHA512   "SHA512"
#define DBFILE_MAGIC "TkrzwHDB"

class FileFd;


class CacheDB
{
   protected:
      
   // Database state/access
   std::string Key;
   std::string Data;
   tkrzw::HashDBM Dbm;
   bool DBLoaded;
   bool ReadOnly;
   std::string DBFile;

   // Generate a key for the DB of a given type
   void _InitQuery(const char *Type)
   {
      Key.clear();
      Data.clear();
      Key = FileName + ":" + Type;
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
      return Dbm.Get(Key,&Data).IsOK();
   };
   inline bool Put(std::string In)
   {
      if (ReadOnly == true)
	 return true;
      Data = In;
      if (DBLoaded == true && (Dbm.Set(Key,Data,true,NULL)) != tkrzw::Status::SUCCESS)
      {
	 DBLoaded = false;
	 return false;
      }
      return true;
   }
   bool OpenFile();
   void CloseFile();

   bool OpenDebFile();
   void CloseDebFile();

   bool GetCurStatNewFormat();
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


   struct StatStore
   {
      uint32_t Flags;
      uint32_t mtime;          
      uint64_t FileSize;
      std::string MD5;
      std::string SHA1;
      std::string SHA256;
      std::string SHA512;
   } CurStat;
   // OldStat only for Flags,mtime comparison
   struct StatStore OldStat;
   
   // 'set' state
   std::string FileName;
   FileFd *Fd;
   debDebFile *DebFile;
   
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
   inline bool DBFailed() {return Dbm.IsOpen() && DBLoaded == false;};
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
