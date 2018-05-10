// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   SRV record support

   ##################################################################### */
									/*}}}*/
#include <config.h>

#include <netdb.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdint.h>
#include <time.h>

#include <algorithm>
#include <map>
#include <random>
#include <tuple>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/strutl.h>

#include "srvrec.h"

class APT_HIDDEN SrvRecPriorityKey
{
   public:
      const uint16_t priority;
      const bool weight_zero;

      SrvRecPriorityKey(const uint16_t &priority, const bool &weight_zero)
         : priority(priority), weight_zero(weight_zero)
      { }

      bool operator<(const SrvRecPriorityKey &other) const
      {
         if (priority < other.priority)
            return true;
         if (priority == other.priority)
            return weight_zero < other.weight_zero;
         return false;
      }
};

bool SrvRec::operator==(SrvRec const &other) const
{
   return (std::tie(target, priority, weight, port) ==
           std::tie(other.target, other.priority, other.weight, other.port));
}

bool GetSrvRecords(std::string host, int port, std::vector<SrvRec> &Result)
{
   // try SRV only for hostnames, not for IP addresses
   {
      struct in_addr addr4;
      struct in6_addr addr6;
      if (inet_pton(AF_INET, host.c_str(), &addr4) == 1 ||
	  inet_pton(AF_INET6, host.c_str(), &addr6) == 1)
	 return true;
   }

   std::string target;
   int res;
   struct servent s_ent_buf;
   struct servent *s_ent = nullptr;
   std::vector<char> buf(1024);

   res = getservbyport_r(htons(port), "tcp", &s_ent_buf, buf.data(), buf.size(), &s_ent);
   if (res != 0 || s_ent == nullptr)
      return false;

   strprintf(target, "_%s._tcp.%s", s_ent->s_name, host.c_str());
   return GetSrvRecords(target, Result);
}

bool GetSrvRecords(std::string name, std::vector<SrvRec> &Result)
{
   unsigned char answer[PACKETSZ];
   int answer_len, compressed_name_len;
   int answer_count;
   std::map<SrvRecPriorityKey, std::vector<SrvRec> > result_by_prio;
   std::mt19937 generator(clock());

   if (res_init() != 0)
      return _error->Errno("res_init", "Failed to init resolver");

   answer_len = res_query(name.c_str(), C_IN, T_SRV, answer, sizeof(answer));
   if (answer_len == -1)
      return false;
   if (answer_len < (int)sizeof(HEADER))
      return _error->Warning("Not enough data from res_query (%i)", answer_len);

   // check the header
   HEADER *header = (HEADER*)answer;
   if (header->rcode != NOERROR)
      return _error->Warning("res_query returned rcode %i", header->rcode);
   answer_count = ntohs(header->ancount);
   if (answer_count <= 0)
      return _error->Warning("res_query returned no answers (%i) ", answer_count);

   // skip the header
   compressed_name_len = dn_skipname(answer+sizeof(HEADER), answer+answer_len);
   if(compressed_name_len < 0)
      return _error->Warning("dn_skipname failed %i", compressed_name_len);

   // pt points to the first answer record, go over all of them now
   unsigned char *pt = answer+sizeof(HEADER)+compressed_name_len+QFIXEDSZ;
   while ((int)Result.size() < answer_count && pt < answer+answer_len)
   {
      u_int16_t type, klass, priority, weight, port, dlen;
      char buf[MAXDNAME];

      compressed_name_len = dn_skipname(pt, answer+answer_len);
      if (compressed_name_len < 0)
         return _error->Warning("dn_skipname failed (2): %i",
                                compressed_name_len);
      pt += compressed_name_len;
      if (((answer+answer_len) - pt) < 16)
         return _error->Warning("packet too short");

      // extract the data out of the result buffer
      #define extract_u16(target, p) target = *p++ << 8; target |= *p++;

      extract_u16(type, pt);
      if(type != T_SRV)
         return _error->Warning("Unexpected type excepted %x != %x",
                                T_SRV, type);
      extract_u16(klass, pt);
      if(klass != C_IN)
         return _error->Warning("Unexpected class excepted %x != %x",
                                C_IN, klass);
      pt += 4;  // ttl
      extract_u16(dlen, pt);
      extract_u16(priority, pt);
      extract_u16(weight, pt);
      extract_u16(port, pt);

      #undef extract_u16

      compressed_name_len = dn_expand(answer, answer+answer_len, pt, buf, sizeof(buf));
      if(compressed_name_len < 0)
         return _error->Warning("dn_expand failed %i", compressed_name_len);
      pt += compressed_name_len;

      // add it to our intermediate result
      result_by_prio[SrvRecPriorityKey(priority, weight == 0)].emplace_back(buf, priority, weight, port);
   }

   // add them by priority into result
   for (auto &rec_by_prio : result_by_prio)
   {
      if (rec_by_prio.first.weight_zero) {
         Result.insert(Result.end(), rec_by_prio.second.begin(), rec_by_prio.second.end());
      }
      else
      {
         // sort weight according to RFC2782:
         // (records with weight zero are excluded, as they are always sorted to the end)
         // - arrange all not yet sorted entries of same priority
         while (rec_by_prio.second.size())
         {
            std::multimap<int, std::vector<SrvRec>::iterator> rec_by_weight;
            int sum = 0;
            for (auto it_rec = rec_by_prio.second.begin(); it_rec != rec_by_prio.second.end(); ++it_rec)
            {
               // compute sum of weights
               sum += it_rec->weight;
               // assign running sum to record
               rec_by_weight.insert(std::make_pair(sum, it_rec));
            }

            // select uniform random number up to calculated sum
            std::uniform_int_distribution<int> distribution(0, sum);
            int lower = distribution(generator);
            // select record whose running sum is >= random number
            auto rec = rec_by_weight.lower_bound(lower);
            Result.push_back(*rec->second);
            // remove entry
            rec_by_prio.second.erase(rec->second);
         }
      }
   }

   for(std::vector<SrvRec>::iterator I = Result.begin();
      I != Result.end(); ++I)
   {
      if (_config->FindB("Debug::Acquire::SrvRecs", false) == true)
      {
         std::cerr << "SrvRecs: got " << I->target
                   << " prio: " << I->priority
                   << " weight: " << I->weight
                   << std::endl;
      }
   }

   return true;
}

SrvRec PopFromSrvRecs(std::vector<SrvRec> &Recs)
{
   std::vector<SrvRec>::iterator I = Recs.begin();
   SrvRec const selected = std::move(*I);
   Recs.erase(I);

   if (_config->FindB("Debug::Acquire::SrvRecs", false) == true)
      std::cerr << "PopFromSrvRecs: selecting " << selected.target << std::endl;

   return selected;
}
