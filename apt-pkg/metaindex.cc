// Include Files                                                       /*{{{*/
#include <apt-pkg/indexfile.h>
#include <apt-pkg/metaindex.h>
#include <apt-pkg/pkgcachegen.h>

#include <apt-pkg/debmetaindex.h>

#include <algorithm>
#include <string>
#include <vector>
									/*}}}*/

class metaIndexPrivate							/*{{{*/
{
   public:
   std::string Origin;
   std::string Label;
   std::string Version;
   signed short DefaultPin;
   std::string ReleaseNotes;

   std::string FutureOrigin;
   std::string FutureLabel;
   std::string FutureVersion;
   std::string FutureCodename;
   std::string FutureSuite;
   signed short FutureDefaultPin;
   std::string FutureReleaseNotes;
};
									/*}}}*/

std::string metaIndex::Describe() const
{
   return "Release";
}

pkgCache::RlsFileIterator metaIndex::FindInCache(pkgCache &Cache, bool const) const
{
   return pkgCache::RlsFileIterator(Cache);
}

bool metaIndex::Merge(pkgCacheGenerator &Gen,OpProgress *) const
{
   return Gen.SelectReleaseFile("", "");
}

metaIndex::metaIndex(std::string const &URI, std::string const &Dist,
      char const * const Type)
: d(new metaIndexPrivate()), Indexes(NULL), Type(Type), URI(URI), Dist(Dist), Trusted(TRI_UNSET),
   Date(0), ValidUntil(0), SupportsAcquireByHash(false), LoadedSuccessfully(TRI_UNSET)
{
   /* nothing */
}

metaIndex::~metaIndex()
{
   if (Indexes != 0)
   {
      for (std::vector<pkgIndexFile *>::iterator I = (*Indexes).begin();
	    I != (*Indexes).end(); ++I)
	 delete *I;
      delete Indexes;
   }
   for (auto const &E: Entries)
      delete E.second;
   delete d;
}

// one line Getters for public fields					/*{{{*/
APT_PURE std::string metaIndex::GetURI() const { return URI; }
APT_PURE std::string metaIndex::GetDist() const { return Dist; }
APT_PURE const char* metaIndex::GetType() const { return Type; }
APT_PURE metaIndex::TriState metaIndex::GetTrusted() const { return Trusted; }
APT_PURE std::string metaIndex::GetSignedBy() const { return SignedBy; }
APT_PURE std::string metaIndex::GetOrigin() const { return d->Origin; }
APT_PURE std::string metaIndex::GetLabel() const { return d->Label; }
APT_PURE std::string metaIndex::GetVersion() const { return d->Version; }
APT_PURE std::string metaIndex::GetCodename() const { return Codename; }
APT_PURE std::string metaIndex::GetSuite() const { return Suite; }
APT_PURE std::string metaIndex::GetReleaseNotes() const { return d->ReleaseNotes; }
APT_PURE signed short metaIndex::GetDefaultPin() const { return d->DefaultPin; }
APT_PURE std::string metaIndex::GetFutureOrigin() const { return d->FutureOrigin; }
APT_PURE std::string metaIndex::GetFutureLabel() const { return d->FutureLabel; }
APT_PURE std::string metaIndex::GetFutureVersion() const { return d->FutureVersion; }
APT_PURE std::string metaIndex::GetFutureCodename() const { return d->FutureCodename; }
APT_PURE std::string metaIndex::GetFutureSuite() const { return d->FutureSuite; }
APT_PURE std::string metaIndex::GetFutureReleaseNotes() const { return d->FutureReleaseNotes; }
APT_PURE signed short metaIndex::GetFutureDefaultPin() const { return d->FutureDefaultPin; }
APT_PURE bool metaIndex::GetSupportsAcquireByHash() const { return SupportsAcquireByHash; }
APT_PURE time_t metaIndex::GetValidUntil() const { return ValidUntil; }
APT_PURE time_t metaIndex::GetNotBefore() const
{
   debReleaseIndex const *const deb = dynamic_cast<debReleaseIndex const *>(this);
   if (deb != nullptr)
      return deb->GetNotBefore();
   return 0;
}
APT_PURE time_t metaIndex::GetDate() const { return this->Date; }
APT_PURE metaIndex::TriState metaIndex::GetLoadedSuccessfully() const { return LoadedSuccessfully; }
APT_PURE std::string metaIndex::GetExpectedDist() const { return Dist; }
									/*}}}*/
bool metaIndex::CheckDist(std::string const &MaybeDist) const		/*{{{*/
{
   if (MaybeDist.empty() || this->Codename == MaybeDist || this->Suite == MaybeDist)
      return true;

   std::string Transformed = MaybeDist;
   if (Transformed == "../project/experimental")
      Transformed = "experimental";

   auto const pos = Transformed.rfind('/');
   if (pos != std::string::npos)
      Transformed = Transformed.substr(0, pos);

   if (Transformed == ".")
      Transformed.clear();

   return Transformed.empty() || this->Codename == Transformed || this->Suite == Transformed;
}
									/*}}}*/
APT_PURE metaIndex::checkSum *metaIndex::Lookup(std::string const &MetaKey) const /*{{{*/
{
   std::map<std::string, metaIndex::checkSum* >::const_iterator sum = Entries.find(MetaKey);
   if (sum == Entries.end())
      return NULL;
   return sum->second;
}
									/*}}}*/
APT_PURE bool metaIndex::Exists(std::string const &MetaKey) const		/*{{{*/
{
   return Entries.find(MetaKey) != Entries.end();
}
									/*}}}*/
std::vector<std::string> metaIndex::MetaKeys() const			/*{{{*/
{
   std::vector<std::string> keys;
   std::map<std::string, checkSum *>::const_iterator I = Entries.begin();
   while(I != Entries.end()) {
      keys.push_back((*I).first);
      ++I;
   }
   return keys;
}
									/*}}}*/
void metaIndex::swapLoad(metaIndex * const OldMetaIndex)		/*{{{*/
{
   std::swap(SignedBy, OldMetaIndex->SignedBy);
   std::swap(Suite, OldMetaIndex->Suite);
   std::swap(Codename, OldMetaIndex->Codename);
   std::swap(Date, OldMetaIndex->Date);
   std::swap(ValidUntil, OldMetaIndex->ValidUntil);
   std::swap(SupportsAcquireByHash, OldMetaIndex->SupportsAcquireByHash);
   std::swap(Entries, OldMetaIndex->Entries);
   std::swap(LoadedSuccessfully, OldMetaIndex->LoadedSuccessfully);

   struct SwapperStruct
   {
      decltype(d->Origin) &Member;
      decltype(&metaIndex::GetOrigin) Getter;
   } dswapper[] = {
      {d->Origin, &metaIndex::GetOrigin},
      {d->Label, &metaIndex::GetLabel},
      {d->Version, &metaIndex::GetVersion},
      {d->ReleaseNotes, &metaIndex::GetReleaseNotes},

      {d->FutureOrigin, &metaIndex::GetFutureOrigin},
      {d->FutureLabel, &metaIndex::GetFutureLabel},
      {d->FutureVersion, &metaIndex::GetFutureVersion},
      {d->FutureCodename, &metaIndex::GetFutureCodename},
      {d->FutureSuite, &metaIndex::GetFutureSuite},
      {d->FutureReleaseNotes, &metaIndex::GetFutureReleaseNotes},
   };
   std::for_each(std::begin(dswapper), std::end(dswapper),
		 [&](SwapperStruct const &swp) { swp.Member = (OldMetaIndex->*swp.Getter)(); });

   d->DefaultPin = OldMetaIndex->GetDefaultPin();
   d->FutureDefaultPin = OldMetaIndex->GetFutureDefaultPin();
}
									/*}}}*/

bool metaIndex::IsArchitectureSupported(std::string const &arch) const	/*{{{*/
{
   debReleaseIndex const * const deb = dynamic_cast<debReleaseIndex const *>(this);
   if (deb != NULL)
      return deb->IsArchitectureSupported(arch);
   return true;
}
									/*}}}*/
bool metaIndex::IsArchitectureAllSupportedFor(IndexTarget const &target) const/*{{{*/
{
   debReleaseIndex const * const deb = dynamic_cast<debReleaseIndex const *>(this);
   if (deb != NULL)
      return deb->IsArchitectureAllSupportedFor(target);
   return true;
}
									/*}}}*/
bool metaIndex::HasSupportForComponent(std::string const &component) const/*{{{*/
{
   debReleaseIndex const * const deb = dynamic_cast<debReleaseIndex const *>(this);
   if (deb != NULL)
      return deb->HasSupportForComponent(component);
   return true;
}
									/*}}}*/

void metaIndex::SetOrigin(std::string const &origin) { d->Origin = origin; }
void metaIndex::SetLabel(std::string const &label) { d->Label = label; }
void metaIndex::SetVersion(std::string const &version) { d->Version = version; }
void metaIndex::SetDefaultPin(signed short const defaultpin) { d->DefaultPin = defaultpin; }
void metaIndex::SetReleaseNotes(std::string const &notes) { d->ReleaseNotes = notes; }

void metaIndex::SetFutureOrigin(std::string const &origin) { d->FutureOrigin = origin; }
void metaIndex::SetFutureLabel(std::string const &label) { d->FutureLabel = label; }
void metaIndex::SetFutureVersion(std::string const &version) { d->FutureVersion = version; }
void metaIndex::SetFutureCodename(std::string const &codename) { d->FutureCodename = codename; }
void metaIndex::SetFutureSuite(std::string const &suite) { d->FutureSuite = suite; }
void metaIndex::SetFutureDefaultPin(signed short const defaultpin) { d->FutureDefaultPin = defaultpin; }
void metaIndex::SetFutureReleaseNotes(std::string const &notes) { d->FutureReleaseNotes = notes; }
