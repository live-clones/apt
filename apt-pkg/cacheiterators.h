// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
/* ######################################################################

   Cache Iterators - Iterators for navigating the cache structure

   The iterators all provides ++,==,!=,->,* and end for their type.
   The end function can be used to tell if the list has been fully
   traversed.

   Unlike STL iterators these contain helper functions to access the data
   that is being iterated over. This is because the data structures can't
   be formed in a manner that is intuitive to use and also mmapable.

   For each variable in the target structure that would need a translation
   to be accessed correctly a translating function of the same name is
   present in the iterator. If applicable the translating function will
   return an iterator.

   The DepIterator can iterate over two lists, a list of 'version depends'
   or a list of 'package reverse depends'. The type is determined by the
   structure passed to the constructor, which should be the structure
   that has the depends pointer as a member. The provide iterator has the
   same system.

   This header is not user includable, please use apt-pkg/pkgcache.h

   ##################################################################### */
									/*}}}*/
#ifndef PKGLIB_CACHEITERATORS_H
#define PKGLIB_CACHEITERATORS_H
#ifndef __PKGLIB_IN_PKGCACHE_H
#warning apt-pkg/cacheiterators.h should not be included directly, include apt-pkg/pkgcache.h instead
#endif
#include <apt-pkg/macros.h>

#include <iosfwd>
#include <iterator>
#include <string>
#include <string_view>

#include <cstring>

// abstract Iterator template						/*{{{*/
/* This template provides the very basic iterator methods we
   need to have for doing some walk-over-the-cache magic */
template<typename Str, typename Itr> class APT_PUBLIC pkgCache::Iterator {
	/** \brief Returns the Pointer for this struct in the owner
	 *  The implementation of this method should be pretty short
	 *  as it will only return the Pointer into the mmap stored
	 *  in the owner but the name of this pointer is different for
	 *  each structure and we want to abstract here at least for the
	 *  basic methods from the actual structure.
	 *  \return Pointer to the first structure of this type
	 */
	constexpr Str* OwnerPointer() const noexcept { return static_cast<Itr const*>(this)->OwnerPointer(); }

	protected:
	Str *S;
	pkgCache *Owner;

	public:
	// iterator_traits
	using iterator_category = std::forward_iterator_tag;
	using value_type = Str;
	using difference_type = std::ptrdiff_t;
	using pointer = Str*;
	using reference = Str&;
	// Iteration
	constexpr bool end() const noexcept {return Owner == 0 || S == OwnerPointer();}

	// Comparison
	constexpr bool operator ==(const Itr &B) const noexcept {return S == B.S;}
	constexpr bool operator !=(const Itr &B) const noexcept {return S != B.S;}

	// Accessors
	constexpr Str *operator ->() noexcept {return S;}
	constexpr Str const *operator ->() const noexcept {return S;}
	constexpr operator Str *() noexcept {return S == OwnerPointer() ? 0 : S;}
	constexpr operator Str const *() const noexcept {return S == OwnerPointer() ? 0 : S;}
	constexpr Str &operator *() noexcept {return *S;}
	constexpr Str const &operator *() const noexcept {return *S;}
	constexpr pkgCache *Cache() const noexcept {return Owner;}

	// Mixed stuff
	constexpr bool IsGood() const noexcept { return S && Owner && ! end();}
	constexpr unsigned long Index() const noexcept {return S - OwnerPointer();}
	constexpr map_pointer<Str> MapPointer() const noexcept {return map_pointer<Str>(Index()) ;}

	void ReMap(void const * const oldMap, void * const newMap) {
		if (Owner == 0 || S == 0)
			return;
		S = static_cast<Str *>(newMap) + (S - static_cast<Str const *>(oldMap));
	}

	// Constructors - look out for the variable assigning
	constexpr Iterator() noexcept : S(0), Owner(0) {}
	constexpr Iterator(pkgCache &Owner,Str *T = 0) noexcept : S(T), Owner(&Owner) {}
};
									/*}}}*/
// Group Iterator							/*{{{*/
/* Packages with the same name are collected in a Group so someone only
   interest in package names can iterate easily over the names, so the
   different architectures can be treated as of the "same" package
   (apt internally treat them as totally different packages) */
class APT_PUBLIC pkgCache::GrpIterator: public Iterator<Group, GrpIterator> {
	long HashIndex;

	public:
	constexpr Group* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->GrpP : 0;
	}

	// This constructor is the 'begin' constructor, never use it.
	explicit inline GrpIterator(pkgCache &Owner) noexcept : Iterator<Group, GrpIterator>(Owner), HashIndex(-1) {
		S = OwnerPointer();
		operator++();
	}

	GrpIterator& operator++();
	inline GrpIterator operator++(int) { GrpIterator const tmp(*this); operator++(); return tmp; }

	constexpr const char *Name() const noexcept {return S->Name == 0?0:Owner->StrP + S->Name;}
	constexpr PkgIterator PackageList() const noexcept;
	constexpr VerIterator VersionsInSource() const noexcept;
	PkgIterator FindPkg(std::string_view Arch = {"any", 3}) const;
	/** \brief find the package with the "best" architecture

	    The best architecture is either the "native" or the first
	    in the list of Architectures which is not an end-Pointer

	    \param PreferNonVirtual tries to respond with a non-virtual package
		   and only if this fails returns the best virtual package */
	PkgIterator FindPreferredPkg(bool const &PreferNonVirtual = true) const;
	PkgIterator NextPkg(PkgIterator const &Pkg) const;

	// Constructors
	constexpr GrpIterator(pkgCache &Owner, Group *Trg) noexcept : Iterator<Group, GrpIterator>(Owner, Trg), HashIndex(0) {
		if (S == 0)
			S = OwnerPointer();
	}
	constexpr GrpIterator() noexcept : Iterator<Group, GrpIterator>(), HashIndex(0) {}

};
									/*}}}*/
// Package Iterator							/*{{{*/
class APT_PUBLIC pkgCache::PkgIterator: public Iterator<Package, PkgIterator> {
	long HashIndex;

	public:
	inline Package* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->PkgP : 0;
	}

	// This constructor is the 'begin' constructor, never use it.
	explicit inline PkgIterator(pkgCache &Owner) noexcept : Iterator<Package, PkgIterator>(Owner), HashIndex(-1) {
		S = OwnerPointer();
		operator++();
	}

	PkgIterator& operator++();
	inline PkgIterator operator++(int) { PkgIterator const tmp(*this); operator++(); return tmp; }

	enum OkState {NeedsNothing,NeedsUnpack,NeedsConfigure};

	// Accessors
	constexpr const char *Name() const noexcept { return Group().Name(); }
	constexpr bool Purge() const noexcept {return S->CurrentState == pkgCache::State::Purge ||
		(S->CurrentVer == 0 && S->CurrentState == pkgCache::State::NotInstalled);}
	constexpr const char *Arch() const noexcept {return S->Arch == 0?0:Owner->StrP + S->Arch;}
	constexpr APT_PURE GrpIterator Group() const noexcept { return GrpIterator(*Owner, Owner->GrpP + S->Group);}

	constexpr VerIterator VersionList() const noexcept APT_PURE;
	constexpr VerIterator CurrentVer() const noexcept APT_PURE;
	constexpr DepIterator RevDependsList() const noexcept APT_PURE;
	constexpr PrvIterator ProvidesList() const noexcept APT_PURE;
	OkState State() const APT_PURE;
	const char *CurVersion() const APT_PURE;

	// for a nice printable representation you likely want APT::PrettyPkg instead
	friend std::ostream& operator<<(std::ostream& out, PkgIterator i);
	std::string FullName(bool const &Pretty = false) const;

	// Constructors
	constexpr PkgIterator(pkgCache &Owner,Package *Trg) noexcept : Iterator<Package, PkgIterator>(Owner, Trg), HashIndex(0) {
		if (S == 0)
			S = OwnerPointer();
	}
	constexpr PkgIterator() noexcept : Iterator<Package, PkgIterator>(), HashIndex(0) {}
};
									/*}}}*/
// SourceVersion Iterator						/*{{{*/
class APT_PUBLIC pkgCache::SrcVerIterator : public Iterator<SourceVersion, SrcVerIterator>
{
   public:
   constexpr SourceVersion *OwnerPointer() const noexcept
   {
      return (Owner != 0) ? Owner->SrcVerP : 0;
   }
#if 0
	// Iteration
	inline SrcVerIterator& operator++() {if (S != Owner->SrcVerP) S = Owner->SrcVerP + S->NextSourceVersion; return *this;}
	inline SrcVerIterator operator++(int) { SrcVerIterator const tmp(*this); operator++(); return tmp; }
#endif
   constexpr APT_PURE GrpIterator Group() const noexcept { return GrpIterator(*Owner, Owner->GrpP + S->Group); }
   constexpr const char *VerStr() const noexcept { return S->VerStr == 0 ? 0 : Owner->StrP + S->VerStr; }

   constexpr SrcVerIterator(pkgCache &Owner, SourceVersion *Trg = 0) noexcept : Iterator<SourceVersion, SrcVerIterator>(Owner, Trg)
   {
      if (S == 0)
	 S = OwnerPointer();
   }
   constexpr SrcVerIterator() noexcept : Iterator<SourceVersion, SrcVerIterator>() {}
};
									/*}}}*/

// Version Iterator							/*{{{*/
class APT_PUBLIC pkgCache::VerIterator : public Iterator<Version, VerIterator> {
	public:
	inline Version* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->VerP : 0;
	}

	// Iteration
	inline VerIterator& operator++() {if (S != Owner->VerP) S = Owner->VerP + S->NextVer; return *this;}
	inline VerIterator operator++(int) { VerIterator const tmp(*this); operator++(); return tmp; }

	constexpr VerIterator NextInSource() noexcept
	{
	   if (S != Owner->VerP)
	      S = Owner->VerP + S->NextInSource;
	   return *this;
	}

	// Comparison
	int CompareVer(const VerIterator &B) const;
	/** \brief compares two version and returns if they are similar

	    This method should be used to identify if two pseudo versions are
	    referring to the same "real" version */
	 constexpr bool SimilarVer(const VerIterator &B) const noexcept {
		return (B.end() == false && S->Hash == B->Hash && strcmp(VerStr(), B.VerStr()) == 0);
	}

	// Accessors
	constexpr const char *VerStr() const noexcept {return S->VerStr == 0?0:Owner->StrP + S->VerStr;}
	constexpr const char *Section() const noexcept {return S->Section == 0?0:Owner->StrP + S->Section;}
	/** \brief source version this version comes from
	   Always contains the version string, even if it is the same as the binary version */
	constexpr SrcVerIterator SourceVersion() const noexcept { return SrcVerIterator(*Owner, Owner->SrcVerP + S->SourceVersion); }
	/** \brief source package name this version comes from
	   Always contains the name, even if it is the same as the binary name */
	constexpr const char *SourcePkgName() const noexcept { return SourceVersion().Group().Name(); }
	/** \brief source version this version comes from
	   Always contains the version string, even if it is the same as the binary version */
	constexpr const char *SourceVerStr() const noexcept { return SourceVersion().VerStr(); }
	constexpr const char *Arch() const noexcept {
		if ((S->MultiArch & pkgCache::Version::All) == pkgCache::Version::All)
			return "all";
		return S->ParentPkg == 0?0:Owner->StrP + ParentPkg()->Arch;
	}
	constexpr PkgIterator ParentPkg() const noexcept {return PkgIterator(*Owner,Owner->PkgP + S->ParentPkg);}

	constexpr DescIterator DescriptionList() const noexcept;
	DescIterator TranslatedDescriptionForLanguage(std::string_view lang) const;
	DescIterator TranslatedDescription() const;
	constexpr DepIterator DependsList() const noexcept;
	constexpr PrvIterator ProvidesList() const noexcept;
	constexpr VerFileIterator FileList() const noexcept;
	bool Downloadable() const;
	inline const char *PriorityType() const {return Owner->Priority(S->Priority);}
	const char *MultiArchType() const APT_PURE;
	std::string RelStr() const;

	bool Automatic() const;
	VerFileIterator NewestFile() const;
	bool IsSecurityUpdate() const;

#ifdef APT_COMPILING_APT
	inline unsigned int PhasedUpdatePercentage() const
	{
	   return (static_cast<Version::Extra *>(Owner->Map.Data()) + S->d)->PhasedUpdatePercentage;
	}
	inline void ArchVariant(map_stringitem_t variant) const
	{
	   (static_cast<Version::Extra *>(Owner->Map.Data()) + S->d)->ArchVariant = variant;
	}
	inline std::string_view ArchVariant() const
	{
	   if (auto I = (static_cast<Version::Extra *>(Owner->Map.Data()) + S->d)->ArchVariant)
	      return Owner->ViewString(I);
	   return {};
	}
	inline bool PhasedUpdatePercentage(unsigned int percentage)
	{
	   if (percentage > 100)
	      return false;
	   (static_cast<Version::Extra *>(Owner->Map.Data()) + S->d)->PhasedUpdatePercentage = static_cast<uint8_t>(percentage);
	   return true;
	}
#endif

	constexpr VerIterator(pkgCache &Owner,Version *Trg = 0) noexcept : Iterator<Version, VerIterator>(Owner, Trg) {
		if (S == 0)
			S = OwnerPointer();
	}
	constexpr VerIterator() noexcept : Iterator<Version, VerIterator>() {}
};
									/*}}}*/
// Description Iterator							/*{{{*/
class APT_PUBLIC pkgCache::DescIterator : public Iterator<Description, DescIterator> {
	public:
	constexpr Description* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->DescP : 0;
	}

	// Iteration
	inline DescIterator& operator++() {if (S != Owner->DescP) S = Owner->DescP + S->NextDesc; return *this;}
	inline DescIterator operator++(int) { DescIterator const tmp(*this); operator++(); return tmp; }

	// Comparison
	int CompareDesc(const DescIterator &B) const;

	// Accessors
	constexpr const char *LanguageCode() const noexcept {return Owner->StrP + S->language_code;}
	constexpr const char *md5() const noexcept {return Owner->StrP + S->md5sum;}
	constexpr DescFileIterator FileList() const noexcept;

	constexpr DescIterator() noexcept : Iterator<Description, DescIterator>() {}
	constexpr DescIterator(pkgCache &Owner,Description *Trg = 0) noexcept : Iterator<Description, DescIterator>(Owner, Trg) {
		if (S == 0)
			S = Owner.DescP;
	}
};
									/*}}}*/
// Dependency iterator							/*{{{*/
class APT_PUBLIC pkgCache::DepIterator : public Iterator<Dependency, DepIterator> {
	enum {DepVer, DepRev} Type;
	DependencyData * S2;

	public:
	constexpr Dependency* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->DepP : 0;
	}

	// Iteration
	DepIterator& operator++();
	inline DepIterator operator++(int) { DepIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr const char *TargetVer() const noexcept {return S2->Version == 0?0:Owner->StrP + S2->Version;}
	constexpr PkgIterator TargetPkg() const noexcept {return PkgIterator(*Owner,Owner->PkgP + S2->Package);}
	inline PkgIterator SmartTargetPkg() const noexcept {PkgIterator R(*Owner,0);SmartTargetPkg(R);return R;}
	constexpr VerIterator ParentVer() const noexcept {return VerIterator(*Owner,Owner->VerP + S->ParentVer);}
	constexpr PkgIterator ParentPkg() const noexcept {return PkgIterator(*Owner,Owner->PkgP + Owner->VerP[uint32_t(S->ParentVer)].ParentPkg);}
	constexpr bool Reverse() const noexcept {return Type == DepRev;}
	bool IsCritical() const APT_PURE;
	bool IsNegative() const APT_PURE;
	bool IsIgnorable(PrvIterator const &Prv) const APT_PURE;
	bool IsIgnorable(PkgIterator const &Pkg) const APT_PURE;
	/* MultiArch can be translated to SingleArch for an resolver and we did so,
	   by adding dependencies to help the resolver understand the problem, but
	   sometimes it is needed to identify these to ignore them… */
	constexpr bool IsMultiArchImplicit() const APT_PURE {
		return (S2->CompareOp & pkgCache::Dep::MultiArchImplicit) == pkgCache::Dep::MultiArchImplicit;
	}
	/* This covers additionally negative dependencies, which aren't arch-specific,
	   but change architecture nonetheless as a Conflicts: foo does applies for all archs */
	bool IsImplicit() const APT_PURE;

	bool IsSatisfied(PkgIterator const &Pkg) const APT_PURE;
	bool IsSatisfied(VerIterator const &Ver) const APT_PURE;
	bool IsSatisfied(PrvIterator const &Prv) const APT_PURE;
	void GlobOr(DepIterator &Start,DepIterator &End);
	Version **AllTargets() const;
	bool SmartTargetPkg(PkgIterator &Result) const;
	inline const char *CompType() const {return Owner->CompType(S2->CompareOp);}
	inline const char *DepType() const {return Owner->DepType(S2->Type);}

	// overrides because we are special
	struct DependencyProxy
	{
	   map_stringitem_t &Version;
	   map_pointer<pkgCache::Package> &Package;
	   map_id_t &ID;
	   unsigned char &Type;
	   unsigned char &CompareOp;
	   map_pointer<pkgCache::Version> &ParentVer;
	   map_pointer<pkgCache::DependencyData> &DependencyData;
	   map_pointer<Dependency> &NextRevDepends;
	   map_pointer<Dependency> &NextDepends;
	   map_pointer<pkgCache::DependencyData> &NextData;
	   constexpr DependencyProxy const * operator->() const noexcept { return this; }
	   constexpr DependencyProxy * operator->() noexcept { return this; }
	};
	constexpr DependencyProxy operator->() const noexcept {return (DependencyProxy) { S2->Version, S2->Package, S->ID, S2->Type, S2->CompareOp, S->ParentVer, S->DependencyData, S->NextRevDepends, S->NextDepends, S2->NextData };}
	constexpr DependencyProxy operator->() {return (DependencyProxy) { S2->Version, S2->Package, S->ID, S2->Type, S2->CompareOp, S->ParentVer, S->DependencyData, S->NextRevDepends, S->NextDepends, S2->NextData };}
	void ReMap(void const * const oldMap, void * const newMap)
	{
		Iterator<Dependency, DepIterator>::ReMap(oldMap, newMap);
		if (Owner == 0 || S == 0 || S2 == 0)
			return;
		S2 = static_cast<DependencyData *>(newMap) + (S2 - static_cast<DependencyData const *>(oldMap));
	}

	// for a nice printable representation you likely want APT::PrettyDep instead
	friend std::ostream& operator<<(std::ostream& out, DepIterator D);

	constexpr DepIterator(pkgCache &Owner, Dependency *Trg, Version* = 0) noexcept :
		Iterator<Dependency, DepIterator>(Owner, Trg), Type(DepVer), S2(Trg == 0 ? Owner.DepDataP : (Owner.DepDataP + Trg->DependencyData)) {
		if (S == 0)
			S = Owner.DepP;
	}
	constexpr DepIterator(pkgCache &Owner, Dependency *Trg, Package*) noexcept :
		Iterator<Dependency, DepIterator>(Owner, Trg), Type(DepRev), S2(Trg == 0 ? Owner.DepDataP : (Owner.DepDataP + Trg->DependencyData)) {
		if (S == 0)
			S = Owner.DepP;
	}
	constexpr DepIterator() noexcept : Iterator<Dependency, DepIterator>(), Type(DepVer), S2(0) {}
};
									/*}}}*/
// Provides iterator							/*{{{*/
class APT_PUBLIC pkgCache::PrvIterator : public Iterator<Provides, PrvIterator> {
	enum {PrvVer, PrvPkg} Type;

	public:
	constexpr Provides* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->ProvideP : 0;
	}

	// Iteration
	inline PrvIterator& operator ++() {
		if (S != Owner->ProvideP)
			S = Owner->ProvideP + (Type == PrvVer ? S->NextPkgProv : S->NextProvides);
		return *this;
	}
	inline PrvIterator operator++(int) { PrvIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr const char *Name() const noexcept {return ParentPkg().Name();}
	constexpr const char *ProvideVersion() const noexcept {return S->ProvideVersion == 0?0:Owner->StrP + S->ProvideVersion;}
	constexpr PkgIterator ParentPkg() const noexcept {return PkgIterator(*Owner,Owner->PkgP + S->ParentPkg);}
	constexpr VerIterator OwnerVer() const noexcept {return VerIterator(*Owner,Owner->VerP + S->Version);}
	constexpr PkgIterator OwnerPkg() const noexcept {return PkgIterator(*Owner,Owner->PkgP + Owner->VerP[uint32_t(S->Version)].ParentPkg);}

	/* MultiArch can be translated to SingleArch for an resolver and we did so,
	   by adding provides to help the resolver understand the problem, but
	   sometimes it is needed to identify these to ignore them… */
	bool IsMultiArchImplicit() const APT_PURE
	{ return (S->Flags & pkgCache::Flag::MultiArchImplicit) == pkgCache::Flag::MultiArchImplicit; }


	constexpr PrvIterator() noexcept : Iterator<Provides, PrvIterator>(), Type(PrvVer) {}
	constexpr PrvIterator(pkgCache &Owner, Provides *Trg, Version*) noexcept :
		Iterator<Provides, PrvIterator>(Owner, Trg), Type(PrvVer) {
		if (S == 0)
			S = Owner.ProvideP;
	}
	constexpr PrvIterator(pkgCache &Owner, Provides *Trg, Package*) noexcept :
		Iterator<Provides, PrvIterator>(Owner, Trg), Type(PrvPkg) {
		if (S == 0)
			S = Owner.ProvideP;
	}
};
									/*}}}*/
// Release file								/*{{{*/
class APT_PUBLIC pkgCache::RlsFileIterator : public Iterator<ReleaseFile, RlsFileIterator> {
	public:
	constexpr ReleaseFile* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->RlsFileP : 0;
	}

	// Iteration
	inline RlsFileIterator& operator++() {if (S != Owner->RlsFileP) S = Owner->RlsFileP + S->NextFile;return *this;}
	inline RlsFileIterator operator++(int) { RlsFileIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr const char *FileName() const noexcept {return S->FileName == 0?0:Owner->StrP + S->FileName;}
	constexpr const char *Archive() const noexcept {return S->Archive == 0?0:Owner->StrP + S->Archive;}
	constexpr const char *Version() const noexcept {return S->Version == 0?0:Owner->StrP + S->Version;}
	constexpr const char *Origin() const noexcept {return S->Origin == 0?0:Owner->StrP + S->Origin;}
	constexpr const char *Codename() const noexcept {return S->Codename ==0?0:Owner->StrP + S->Codename;}
	constexpr const char *Label() const noexcept {return S->Label == 0?0:Owner->StrP + S->Label;}
	constexpr const char *Site() const noexcept {return S->Site == 0?0:Owner->StrP + S->Site;}
	constexpr bool Flagged(pkgCache::Flag::ReleaseFileFlags const flag) const noexcept {return (S->Flags & flag) == flag; }

	std::string RelStr();

	// Constructors
	constexpr RlsFileIterator() noexcept : Iterator<ReleaseFile, RlsFileIterator>() {}
	explicit constexpr RlsFileIterator(pkgCache &Owner) noexcept : Iterator<ReleaseFile, RlsFileIterator>(Owner, Owner.RlsFileP) {}
	constexpr RlsFileIterator(pkgCache &Owner,ReleaseFile *Trg) noexcept : Iterator<ReleaseFile, RlsFileIterator>(Owner, Trg) {}
};
									/*}}}*/
// Package file								/*{{{*/
class APT_PUBLIC pkgCache::PkgFileIterator : public Iterator<PackageFile, PkgFileIterator> {
	public:
	constexpr PackageFile* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->PkgFileP : 0;
	}

	// Iteration
	inline PkgFileIterator& operator++() {if (S != Owner->PkgFileP) S = Owner->PkgFileP + S->NextFile; return *this;}
	inline PkgFileIterator operator++(int) { PkgFileIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr const char *FileName() const noexcept {return S->FileName == 0?0:Owner->StrP + S->FileName;}
	constexpr pkgCache::RlsFileIterator ReleaseFile() const noexcept {return RlsFileIterator(*Owner, Owner->RlsFileP + S->Release);}
	constexpr const char *Archive() const noexcept {return S->Release == 0 ? Component() : ReleaseFile().Archive();}
	constexpr const char *Version() const noexcept {return S->Release == 0 ? NULL : ReleaseFile().Version();}
	constexpr const char *Origin() const noexcept {return S->Release == 0 ? NULL : ReleaseFile().Origin();}
	constexpr const char *Codename() const noexcept {return S->Release == 0 ? NULL : ReleaseFile().Codename();}
	constexpr const char *Label() const noexcept {return S->Release == 0 ? NULL : ReleaseFile().Label();}
	constexpr const char *Site() const noexcept {return S->Release == 0 ? NULL : ReleaseFile().Site();}
	constexpr bool Flagged(pkgCache::Flag::ReleaseFileFlags const flag) const noexcept {return S->Release== 0 ? false : ReleaseFile().Flagged(flag);}
	constexpr bool Flagged(pkgCache::Flag::PkgFFlags const flag) const noexcept {return (S->Flags & flag) == flag;}
	constexpr const char *Component() const noexcept {return S->Component == 0?0:Owner->StrP + S->Component;}
	constexpr const char *Architecture() const noexcept {return S->Architecture == 0?0:Owner->StrP + S->Architecture;}
	constexpr const char *IndexType() const noexcept {return S->IndexType == 0?0:Owner->StrP + S->IndexType;}

	std::string RelStr();

	// Constructors
	constexpr PkgFileIterator() noexcept : Iterator<PackageFile, PkgFileIterator>() {}
	explicit constexpr PkgFileIterator(pkgCache &Owner) noexcept : Iterator<PackageFile, PkgFileIterator>(Owner, Owner.PkgFileP) {}
	constexpr PkgFileIterator(pkgCache &Owner,PackageFile *Trg) noexcept : Iterator<PackageFile, PkgFileIterator>(Owner, Trg) {}
};
									/*}}}*/
// Version File								/*{{{*/
class APT_PUBLIC pkgCache::VerFileIterator : public pkgCache::Iterator<VerFile, VerFileIterator> {
	public:
	constexpr VerFile* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->VerFileP : 0;
	}

	// Iteration
	inline VerFileIterator& operator++() {if (S != Owner->VerFileP) S = Owner->VerFileP + S->NextFile; return *this;}
	inline VerFileIterator operator++(int) { VerFileIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr PkgFileIterator File() const noexcept {return PkgFileIterator(*Owner, Owner->PkgFileP + S->File);}

	constexpr VerFileIterator() noexcept : Iterator<VerFile, VerFileIterator>() {}
	constexpr VerFileIterator(pkgCache &Owner,VerFile *Trg) noexcept : Iterator<VerFile, VerFileIterator>(Owner, Trg) {}
};
									/*}}}*/
// Description File							/*{{{*/
class APT_PUBLIC pkgCache::DescFileIterator : public Iterator<DescFile, DescFileIterator> {
	public:
	constexpr DescFile* OwnerPointer() const noexcept {
		return (Owner != 0) ? Owner->DescFileP : 0;
	}

	// Iteration
	inline DescFileIterator& operator++() {if (S != Owner->DescFileP) S = Owner->DescFileP + S->NextFile; return *this;}
	inline DescFileIterator operator++(int) { DescFileIterator const tmp(*this); operator++(); return tmp; }

	// Accessors
	constexpr PkgFileIterator File() const noexcept {return PkgFileIterator(*Owner, Owner->PkgFileP + S->File);}

	constexpr DescFileIterator() noexcept : Iterator<DescFile, DescFileIterator>() {}
	constexpr DescFileIterator(pkgCache &Owner,DescFile *Trg) noexcept : Iterator<DescFile, DescFileIterator>(Owner, Trg) {}
};
									/*}}}*/
// Inlined Begin functions can't be in the class because of order problems /*{{{*/
constexpr pkgCache::PkgIterator pkgCache::GrpIterator::PackageList() const noexcept
       {return PkgIterator(*Owner,Owner->PkgP + S->FirstPackage);}
       constexpr pkgCache::VerIterator pkgCache::GrpIterator::VersionsInSource() const noexcept
       {
	  return VerIterator(*Owner, Owner->VerP + S->VersionsInSource);
       }
constexpr pkgCache::VerIterator pkgCache::PkgIterator::VersionList() const noexcept
       {return VerIterator(*Owner,Owner->VerP + S->VersionList);}
constexpr pkgCache::VerIterator pkgCache::PkgIterator::CurrentVer() const noexcept
       {return VerIterator(*Owner,Owner->VerP + S->CurrentVer);}
constexpr pkgCache::DepIterator pkgCache::PkgIterator::RevDependsList() const noexcept
       {return DepIterator(*Owner,Owner->DepP + S->RevDepends,S);}
constexpr pkgCache::PrvIterator pkgCache::PkgIterator::ProvidesList() const noexcept
       {return PrvIterator(*Owner,Owner->ProvideP + S->ProvidesList,S);}
constexpr pkgCache::DescIterator pkgCache::VerIterator::DescriptionList() const noexcept
       {return DescIterator(*Owner,Owner->DescP + S->DescriptionList);}
constexpr pkgCache::PrvIterator pkgCache::VerIterator::ProvidesList() const noexcept
       {return PrvIterator(*Owner,Owner->ProvideP + S->ProvidesList,S);}
constexpr pkgCache::DepIterator pkgCache::VerIterator::DependsList() const noexcept
       {return DepIterator(*Owner,Owner->DepP + S->DependsList,S);}
constexpr pkgCache::VerFileIterator pkgCache::VerIterator::FileList() const noexcept
       {return VerFileIterator(*Owner,Owner->VerFileP + S->FileList);}
constexpr pkgCache::DescFileIterator pkgCache::DescIterator::FileList() const noexcept
       {return DescFileIterator(*Owner,Owner->DescFileP + S->FileList);}
									/*}}}*/
#endif
