/*
 * depsolver.h - The APT 3.0 dependency solver
 *
 * Copyright (c) 2023 Julian Andres Klode
 * Copyright (c) 2023 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef APT_DEPSOLVER_H
#define APT_DEPSOLVER_H
// Keep first we don't want other includes
#include <apt-pkg/header-is-private.h>
#include <apt-pkg/solver.h>

// Dependency specific headers
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/edsp.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/policy.h>

template <typename T> struct always_false : std::false_type {};

namespace APT::Solver
{

/**
 * \brief A simple mapping from objects in the cache to user-defined types.
 *
 * This default initializes an array with the specified value type for each
 * object in the cache of that type.
 */
template <typename K, typename V, bool fast = false>
class ContiguousCacheMap
{
   V *data_; // Avoid std::unique_ptr() as it may check that it's non-null.

   public:
   ContiguousCacheMap(pkgCache &cache)
   {
      static_assert(std::is_constructible_v<V>);
      if constexpr (fast)
      {
	 static_assert(std::is_trivially_constructible_v<V>);
	 static_assert(std::is_trivially_destructible_v<V>);
      }

      size_t size;
      if constexpr (std::is_same_v<K, pkgCache::Version>)
	 size = cache.Head().VersionCount;
      else if constexpr (std::is_same_v<K, pkgCache::Package>)
	 size = cache.Head().PackageCount;
      else
	 static_assert(always_false<K>::value, "Cannot construct map for key type");

      data_ = new V[size]();
   }
   constexpr V &operator[](const K *key) noexcept { return data_[key->ID]; }
   constexpr const V &operator[](const K *key) const noexcept { return data_[key->ID]; }
   ~ContiguousCacheMap() { delete[] data_; }

   // Delete copy constructors for memory safety (rule of 3)
   ContiguousCacheMap(const ContiguousCacheMap &) = delete;
   ContiguousCacheMap &operator=(const ContiguousCacheMap &) = delete;
};

/**
 * \brief A version of ContiguousCacheMap that ensures allocation and deallocation is trivial.
 */
template <typename K, typename V>
using FastContiguousCacheMap = ContiguousCacheMap<K, V, true>;

/*
 * \brief APT 3.0 solver
 *
 * This is a simple solver focused on understandability and sensible results, it
 * will not generally find all solutions to the problem but will try to find the best
 * ones.
 *
 * It is a brute force solver with heuristics, conflicts learning, and 2**32 levels
 * of backtracking.
 */
class DependencySolver final : public Solver
{
   friend class CompareProviders3;

   // Cache is needed to construct iterators for the objects variables refer to
   pkgCache &cache;
   // Policy is needed for determining candidate version.
   pkgDepCache::Policy &policy;
   // Request flags determine the behavior of the options below, make sure it comes first.
   EDSP::Request::Flags requestFlags;

   // Configuration options for the dependency solver
   bool KeepAuto{version == "3.0" || not _config->FindB("APT::Get::AutomaticRemove")};
   bool IsUpgrade{_config->FindB("APT::Solver::Upgrade", requestFlags &EDSP::Request::UPGRADE_ALL)};
   bool AllowRemove{_config->FindB("APT::Solver::Remove", not(requestFlags & EDSP::Request::FORBID_REMOVE))};
   bool AllowRemoveManual{AllowRemove && _config->FindB("APT::Solver::RemoveManual", true)};
   bool AllowInstall{_config->FindB("APT::Solver::Install", not(requestFlags & EDSP::Request::FORBID_NEW_INSTALL))};
   bool StrictPinning{_config->FindB("APT::Solver::Strict-Pinning", true)};
   bool FixPolicyBroken{_config->FindB("APT::Get::Fix-Policy-Broken")};
   bool DeferVersionSelection{_config->FindB("APT::Solver::Defer-Version-Selection", true)};
   bool KeepRecommends{_config->FindB("APT::AutoRemove::RecommendsImportant", true)};
   bool KeepSuggests{_config->FindB("APT::AutoRemove::SuggestsImportant", true)};
   bool UpgradeBySourcePackage{_config->FindB("APT::Get::Upgrade-By-Source-Package", true)};

   // Helper functions for detecting obsolete packages
   mutable FastContiguousCacheMap<pkgCache::Package, LiftedBool> pkgObsolete;
   bool Obsolete(pkgCache::PkgIterator pkg, bool AllowManual = false) const;
   bool ObsoletedByNewerSourceVersion(pkgCache::VerIterator cand) const;

   // GetPriority() with caching
   mutable FastContiguousCacheMap<pkgCache::Version, short> priorities;
   short GetPriority(pkgCache::VerIterator ver) const
   {
      if (priorities[ver] == 0)
	 priorities[ver] = policy.GetPriority(ver);
      return priorities[ver];
   }

   // GetCandidateVer() with caching
   mutable FastContiguousCacheMap<pkgCache::Package, pkgCache::Version *> candidates;
   pkgCache::VerIterator GetCandidateVer(pkgCache::PkgIterator pkg) const
   {
      if (candidates[pkg] == 0)
	 candidates[pkg] = policy.GetCandidateVer(pkg);
      return pkgCache::VerIterator(cache, candidates[pkg]);
   }

   // \brief Discover variables
   std::queue<Var> discoverQ;

   // \brief Mapping from packages and versions to variables and back.
   ContiguousCacheMap<pkgCache::Package, Var> pkgVars;
   ContiguousCacheMap<pkgCache::Version, Var> verVars;
   VarVector<map_pointer<pkgCache::Package>> varPkg;
   VarVector<map_pointer<pkgCache::Version>> varVer;

   /// \brief Register a new variable, keeping the variable mappings in sync
   Var newVar() override;
   /// \brief Return the variable for a package, registering it if necessary
   Var GetVar(pkgCache::PkgIterator const &Pkg);
   /// \brief Return the variable for a version, registering it if necessary
   Var GetVar(pkgCache::VerIterator const &Ver);
   /// \brief Return the variable for a package if one was registered, an empty Var otherwise
   constexpr Var FindVar(pkgCache::PkgIterator const &Pkg) const noexcept { return pkgVars[Pkg]; }
   /// \brief Return the variable for a version if one was registered, an empty Var otherwise
   constexpr Var FindVar(pkgCache::VerIterator const &Ver) const noexcept { return verVars[Ver]; }
   /// \brief Return the package the variable refers to, or an empty iterator
   constexpr pkgCache::PkgIterator GetPkg(Var var) const noexcept
   {
      return varPkg[var] ? pkgCache::PkgIterator(cache, cache.PkgP + varPkg[var]) : pkgCache::PkgIterator();
   }
   /// \brief Return the version the variable refers to, or an empty iterator
   constexpr pkgCache::VerIterator GetVer(Var var) const noexcept
   {
      return varVer[var] ? pkgCache::VerIterator(cache, cache.VerP + varVer[var]) : pkgCache::VerIterator();
   }
   /// \brief Return the package of the variable, cast from version if needed
   constexpr pkgCache::PkgIterator AsPkg(Var var) const noexcept
   {
      if (varVer[var])
	 return GetVer(var).ParentPkg();
      return GetPkg(var);
   }

   // \brief Render a variable as a package or version name
   std::string toString(Var var) const override;
   // \brief Render a literal as a (negated) package or version name
   std::string toString(Lit lit) const override;
   // \brief Render a clause, e.g. for debugging output
   std::string toString(const ClauseHeader &clause, std::span<const Var> solutions, bool pretty = false, bool showMerged = true) const override;
   constexpr bool IsPackage(Var var) const noexcept override { return varPkg[var] != nullptr; }
   using Solver::toString;
   std::string DescribeSelection(Var var, bool assignment) const override;

   /// \brief Discover the dependencies of the variable
   void Discover(Var var) override;
   /// \brief Link a clause into the watchers
   CRef RegisterClause(Clause &clause);
   /// \brief Enqueue dependencies shared by all versions of the package.
   void RegisterCommonDependencies(pkgCache::PkgIterator Pkg);

   /// \brief Translate an or group into a clause object
   [[nodiscard]] std::optional<Clause> TranslateOrGroup(pkgCache::DepIterator start, pkgCache::DepIterator end, Var reason);

   public:
   // \brief Basic solver initializer. This cannot fail.
   DependencySolver(pkgCache &Cache, pkgDepCache::Policy &Policy, EDSP::Request::Flags requestFlags);
   ~DependencySolver() override;

   /// \brief Apply the selections from the dep cache to the solver
   [[nodiscard]] bool FromDepCache(pkgDepCache &depcache);
   /// \brief Apply the solver result to the depCache
   [[nodiscard]] bool ToDepCache(pkgDepCache &depcache) const;
   /// \brief Temporary internal API with external linkage for the `apt why` and `apt why-not` commands.
   APT_PUBLIC static std::string InternalCliWhy(pkgDepCache &depcache, pkgCache::PkgIterator Pkg, bool assignment);
};
}; // namespace APT::Solver
#endif // APT_DEPSOLVER_H
