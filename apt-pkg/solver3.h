/*
 * solver3.h - The APT 3.0 solver
 *
 * Copyright (c) 2023 Julian Andres Klode
 * Copyright (c) 2023 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <cassert>
#include <memory>
#include <optional>
#include <queue>
#include <type_traits>
#include <vector>

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

      data_ = new V[size]{};
   }
   V &operator[](const K *key) { return data_[key->ID]; }
   const V &operator[](const K *key) const { return data_[key->ID]; }
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

struct Lit;

// \brief Groups of works, these are ordered.
//
// Later items will be skipped if they are optional, or we will when backtracking,
// try a different choice for them.
enum class Group : uint8_t
{
   HoldOrDelete,

   // Satisfying dependencies on entirely new packages first is a good idea because
   // it may contain replacement packages like libfoo1t64 whereas we later will see
   // Depends: libfoo1 where libfoo1t64 Provides libfoo1 and we'd have to choose.
   SatisfyNew,
   Satisfy,
   // On a similar note as for SatisfyNew, if the dependency contains obsolete packages
   // try it last.
   SatisfyObsolete,

   // Select a version of a package chosen for install.
   SelectVersion,

   // My intuition tells me that we should try to schedule upgrades first, then
   // any non-obsolete installed packages, and only finally obsolete ones, such
   // that newer packages guide resolution of dependencies for older ones, they
   // may have more stringent dependencies, like a (>> 2) whereas an obsolete
   // package may have a (>> 1), for example.
   UpgradeManual,
   InstallManual,
   ObsoleteManual,

   // Automatically installed packages must come last in the group, this allows
   // us to see if they were installed as a dependency of a manually installed package,
   // allowing a simple implementation of an autoremoval code.
   UpgradeAuto,
   KeepAuto,
   ObsoleteAuto,

   // Satisfy optional dependencies that were previously satisfied but won't otherwise be installed
   SatisfySuggests,
};

// \brief This essentially describes the install state in RFC2119 terms.
enum class LiftedBool : uint8_t
{
   // \brief We have not made a choice about the package yet
   Undefined,
   // \brief We need to install this package
   True,
   // \brief We cannot install this package (need conflicts with it)
   False,
};

/**
 * \brief Tagged union holding either a package, version, or nothing; representing the reason for installing something.
 *
 * We want to keep track of the reason why things are being installed such that
 * we can have sensible debugging abilities; and we want to generically refer to
 * both packages and versions as variables, hence this class was added.
 *
 */
struct Var
{
   uint32_t value;

   explicit constexpr Var(uint32_t value = 0) : value{value} {}
   explicit Var(pkgCache::PkgIterator const &Pkg) : value(uint32_t(Pkg.MapPointer()) << 1) {}
   explicit Var(pkgCache::VerIterator const &Ver) : value(uint32_t(Ver.MapPointer()) << 1 | 1) {}

   inline constexpr bool isVersion() const { return value & 1; }
   inline constexpr uint32_t mapPtr() const { return value >> 1; }

   // \brief Return the package, if any, otherwise 0.
   map_pointer<pkgCache::Package> Pkg() const
   {
      return isVersion() ? 0 : map_pointer<pkgCache::Package>{mapPtr()};
   }
   // \brief Return the version, if any, otherwise 0.
   map_pointer<pkgCache::Version> Ver() const
   {
      return isVersion() ? map_pointer<pkgCache::Version>{mapPtr()} : 0;
   }
   // \brief Return the package iterator if storing a package, or an empty one
   pkgCache::PkgIterator Pkg(pkgCache &cache) const
   {
      return isVersion() ? pkgCache::PkgIterator() : pkgCache::PkgIterator(cache, cache.PkgP + Pkg());
   }
   // \brief Return the version iterator if storing a package, or an empty end.
   pkgCache::VerIterator Ver(pkgCache &cache) const
   {
      return isVersion() ? pkgCache::VerIterator(cache, cache.VerP + Ver()) : pkgCache::VerIterator();
   }
   // \brief Return a package, cast from version if needed
   pkgCache::PkgIterator CastPkg(pkgCache &cache) const
   {
      return isVersion() ? Ver(cache).ParentPkg() : Pkg(cache);
   }
   // \brief Check if there is no reason.
   constexpr bool empty() const { return value == 0; }
   constexpr bool operator!=(Var const other) const noexcept { return value != other.value; }
   constexpr bool operator==(Var const other) const noexcept { return value == other.value; }

   /// \brief Negate
   constexpr Lit operator~() const;

   std::string toString(pkgCache &cache) const
   {
      if (auto P = Pkg(cache); not P.end())
	 return P.FullName();
      if (auto V = Ver(cache); not V.end())
	 return V.ParentPkg().FullName() + "=" + V.VerStr();
      return "(root)";
   }
};

/**
 * \brief A literal is a variable with a sign.
 *
 * A literal 'A' means 'install A' whereas a literal '-A' means 'do not install A'.
 */
struct Lit
{
   private:
   friend struct std::hash<Lit>;
   // Private constructor from a number, to be used with operator~
   explicit constexpr Lit(int32_t value) : value{value} {}
   int32_t value;

   public:
   // SAFETY: value must be 31 bit, one bit is needed for the sign.
   constexpr Lit(Var var) : value{static_cast<int32_t>(var.value)} {}

   // Accessors
   constexpr Var var() const { return Var(std::abs(value)); }
   constexpr bool sign() const { return value < 0; }
   constexpr Lit operator~() const { return Lit(-value); }

   // Properties
   constexpr bool empty() const { return value == 0; }
   constexpr bool operator!=(Lit const other) const noexcept { return value != other.value; }
   constexpr bool operator==(Lit const other) const noexcept { return value == other.value; }

   std::string toString(pkgCache &cache) const { return (sign() ? "not " : "") + var().toString(cache); }
};

/**
 * \brief A single clause
 *
 * A clause is a normalized, expanded dependency, translated into an implication
 * in terms of Var objects, that is, `reason -> solutions[0] | ... | solutions[n]`
 */
struct Clause
{
   // \brief Underyling dependency
   pkgCache::Dependency *dep = nullptr;
   // \brief Var for the work
   Var reason;
   // \brief The group we are in
   Group group;
   // \brief Possible solutions to this task, ordered in order of preference.
   std::vector<Var> solutions{};
   // \brief An optional clause does not need to be satisfied
   bool optional;

   // \brief A negative clause negates the solutions, that is X->A|B you get X->!(A|B), aka X->!A&!B
   bool negative;

   // \brief An optional clause may be eager
   bool eager;

   // Clauses merged with this clause
   std::forward_list<Clause> merged;

   inline Clause(Var reason, Group group, bool optional = false, bool negative = false) : reason(reason), group(group), optional(optional), negative(negative), eager(not optional) {}

   std::string toString(pkgCache &cache, bool pretty = false, bool showMerged = true) const;
};

constexpr Lit Solver::Var::operator~() const
{
   return ~Lit(*this);
}

inline LiftedBool operator~(LiftedBool value)
{
   switch (value)
   {
   case LiftedBool::Undefined:
      return LiftedBool::Undefined;
   case LiftedBool::True:
      return LiftedBool::False;
   case LiftedBool::False:
      return LiftedBool::True;
   }
   abort();
}

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
class Solver
{
   protected:
   struct State;
   struct Work;
   struct Trail;

   // \brief Type to record decision level at. This may very well be a 16-bit
   // unsigned integer, then change Solver::State::LiftedBool to be a
   // uint16_t class enum as well to get a more compact space.
   using level_type = unsigned int;

   // Documentation
   template <typename T>
   using heap = std::vector<T>;

   static_assert(sizeof(level_type) >= sizeof(map_id_t));

   // Cache is needed to construct Iterators from Version objects we see
   pkgCache &cache;
   // Root state
   std::unique_ptr<State> rootState;
   // States for packages
   ContiguousCacheMap<pkgCache::Package, State> pkgStates;
   // States for versions
   ContiguousCacheMap<pkgCache::Version, State> verStates;

   // \brief Helper function for safe access to package state.
   inline State &operator[](const pkgCache::Package *P)
   {
      return pkgStates[P];
   }
   inline const State &operator[](const pkgCache::Package *P) const
   {
      return pkgStates[P];
   }

   // \brief Helper function for safe access to version state.
   inline State &operator[](const pkgCache::Version *V)
   {
      return verStates[V];
   }
   inline const State &operator[](const pkgCache::Version *V) const
   {
      return verStates[V];
   }
   // \brief Helper function for safe access to either state.
   inline State &operator[](Var r);
   inline const State &operator[](Var r) const;

   // \brief Heap of the remaining work.
   //
   // In contrast to MiniSAT which picks undecided literals and decides them,
   // we keep track of unsolved active clauses in a priority queue. This allows
   // us to for example, solve Depends before Recommends (see Group).
   heap<Work> work;

   /// \brief Trail of assignments done, and clauses solved.
   ///
   /// Record past assignments and solved clauses such that we can revert them when
   /// backtracking.
   std::vector<Trail> trail;

   /// \brief Separator indices for different decision levels in trail
   std::vector<level_type> trailLim{};

   // \brief Propagation queue
   std::queue<Var> propQ;

   // \brief The time we called Solve()
   time_t startTime{};

   /// Various configuration options
   std::string version{_config->Find("APT::Solver", "3.0")};
   // \brief Debug level
   int debug{_config->FindI("Debug::APT::Solver")};
   // \brief If set, we use strict pinning.
   int Timeout{_config->FindI("APT::Solver::Timeout", 10)};

   // \brief Discover a variable, translating the underlying dependencies to the SAT presentation
   //
   // This does a breadth-first search of the entire dependency tree of var,
   // utilizing the discoverQ above.
   virtual void Discover(Var var) = 0;
   // \brief Propagate all pending propagations
   [[nodiscard]] bool Propagate();

   // \brief Return the current level (.size() with casting)
   level_type decisionLevel()
   {
      return static_cast<level_type>(trailLim.size());
   }
   inline Var bestReason(Clause const *clause, Var var) const;
   inline LiftedBool value(Lit lit) const;

   public:
   // \brief Revert to the previous decision level.
   [[nodiscard]] bool Pop();
   // \brief Undo a single assignment / trail work item
   void UndoOne();
   // \brief Add work to our work queue.
   [[nodiscard]] bool AddWork(Work &&work);

   // \brief Basic solver initializer. This cannot fail.
   Solver(pkgCache &Cache);
   virtual ~Solver();

   // Assume a literal
   [[nodiscard]] bool Assume(Lit lit, const Clause *reason = nullptr);
   // Enqueue a fact
   [[nodiscard]] bool Enqueue(Lit lit, const Clause *reason = nullptr);

   // \brief Solve the dependencies
   [[nodiscard]] bool Solve();

   // Print dependency chain
   virtual std::string WhyStr(Var reason) const;

   /**
    * \brief Print a long reason string
    *
    * Print a reason as to why `rclause` implies `assignment` for the variable `var`.
    *
    * \param var The variable to print the reason for
    * \param assignment The assumed assignment to print the reason for (may be different from actual assignment if rclause is specified)
    * \param rclause The clause that caused this variable to be marked (or would be marked)
    * \param prefix A prefix, for indentation purposes, as this is recursive
    * \param seen A set of seen objects such that the output does not repeat itself (not for safety, it is acyclic)
    */
   virtual std::string LongWhyStr(Var var, bool assignment, const Clause *rclause, std::string prefix, std::unordered_set<Var> &seen) const;
};

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
class DependencySolver : public Solver
{
   friend class CompareProviders3;

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
   mutable ContiguousCacheMap<pkgCache::Package, pkgCache::VerIterator> candidates;
   pkgCache::VerIterator GetCandidateVer(pkgCache::PkgIterator pkg) const
   {
      if (candidates[pkg].end())
	 candidates[pkg] = policy.GetCandidateVer(pkg);
      return candidates[pkg];
   }

   // \brief Discover variables
   std::queue<Var> discoverQ;
   /// \brief Discover the dependencies of the variable
   void Discover(Var var) override;
   /// \brief Link a clause into the watchers
   const Clause *RegisterClause(Clause &&clause);
   /// \brief Enqueue dependencies shared by all versions of the package.
   void RegisterCommonDependencies(pkgCache::PkgIterator Pkg);

   /// \brief Translate an or group into a clause object
   [[nodiscard]] Clause TranslateOrGroup(pkgCache::DepIterator start, pkgCache::DepIterator end, Var reason);

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
/**
 * \brief A single work item
 *
 * A work item is a positive dependency that still needs to be resolved. Work
 * is ordered, by level, length of solutions, and optionality.
 *
 * The work can always be recalculated from the state by iterating over dependencies
 * of all packages in there, finding solutions to them, and then adding all dependencies
 * not yet resolved to the work queue.
 */
struct APT::Solver::Solver::Work
{
   const Clause *clause;

   // \brief The level at which the item has been added
   level_type level;

   /// Number of valid choices at insertion time
   size_t size{0};

   // \brief This item should be removed from the queue.
   bool erased{false};

   bool operator<(APT::Solver::Solver::Work const &b) const;
   std::string toString(pkgCache &cache) const;
   inline Work(const Clause *clause, level_type level) : clause(clause), level(level) {}
};

/**
 * \brief The solver state
 *
 * For each version, the solver records a assignment at a certain level. It
 * maintains an array mapping from version ID to state.
 */
struct APT::Solver::Solver::State
{
   // \brief The reason for causing this state (invalid for Undefined).
   //
   // Rejects may have been caused by a later state. Consider we select
   // between x1 and x2 in level = N. If we now find dependencies of x1
   // leading to a conflict with a package in K < N, we will record all
   // of them as REJECT in level = K.
   //
   // You can follow the reason chain upwards as long as the level
   // doesn't increase to unwind.
   //
   // Vars < 0 are package ID, reasons > 0 are version IDs.
   const Clause *reason{};

   const char *reasonStr{};

   // \brief The level at which the value has been assigned
   level_type level{0};

   LiftedBool assignment{LiftedBool::Undefined};

   // \brief Flags.
   struct
   {
      bool discovered{};
      bool manual{};
   } flags;

   static_assert(sizeof(flags) <= sizeof(int));

   // \brief Clauses owned by this package/version
   std::vector<std::unique_ptr<Clause>> clauses;
   // \brief Reverse clauses, that is dependencies (or conflicts) from other packages on this one
   std::vector<const Clause *> rclauses;
};

/**
 * \brief A trail item.
 *
 * In MiniSAT, a trail item is an assigned literal. However, we store an assigned variable instead,
 * since the assignment is still recorded when we need to access the trail; there does not appear
 * to be a substantial value in recording the sign here; but it produces a risk for a disagreement
 * between the actual state and the sign recorded in the trail.
 *
 * In addition to MiniSAT's trail, we also need to keep a trail of solved Work items; that is
 * clauses that were being solved, as when undoing the trail, we need to mark those clauses
 * active again by putting them back on the work heap.
 */
struct APT::Solver::Solver::Trail
{
   /// \brief A variable that got assigned True or False. May be reset to Undefined on backtracking.
   Var assigned;
   /// \brief A work item (a clause) that was solved. Needs to be put back on the work heap on backtracking.
   std::optional<Work> work;
};

inline APT::Solver::Solver::State &APT::Solver::Solver::operator[](APT::Solver::Var r)
{
   if (auto P = r.Pkg())
      return (*this)[cache.PkgP + P];
   if (auto V = r.Ver())
      return (*this)[cache.VerP + V];
   return *rootState.get();
}

inline const APT::Solver::Solver::State &APT::Solver::Solver::operator[](APT::Solver::Var r) const
{
   return const_cast<Solver &>(*this)[r];
}

// Custom specialization of std::hash can be injected in namespace std.
template <>
struct std::hash<APT::Solver::Var>
{
   std::hash<decltype(APT::Solver::Var::value)> hash_value;
   std::size_t operator()(const APT::Solver::Var &v) const noexcept { return hash_value(v.value); }
};

// Custom specialization of std::hash can be injected in namespace std.
template <>
struct std::hash<APT::Solver::Lit>
{
   std::hash<decltype(APT::Solver::Lit::value)> hash_value;
   std::size_t operator()(const APT::Solver::Lit &v) const noexcept { return hash_value(v.value); }
};
