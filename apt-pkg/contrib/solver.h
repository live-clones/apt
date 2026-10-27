/*
 * solver.h - APT General purpose SAT solver
 *
 * Copyright (c) 2023 Julian Andres Klode
 * Copyright (c) 2023 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This solver started from scratch but turns slowly into a variant of
 * MiniSat as documented in the paper
 *    "An extensible SAT-solver [extended version 1.2]."
 * by Niklas Eén, and Niklas Sörensson.
 *
 * It extends MiniSAT with support for optional clauses, and differs
 * in that it removes non-deterministic aspects like the activity based
 * ordering. Instead it uses a more nuanced static ordering that, to
 * some extend, preserves some greediness and sub-optimality of the
 * classic APT solver.
 */

#ifndef APT_SOLVER_H
#define APT_SOLVER_H
#include <apt-pkg/configuration.h>
#include <apt-pkg/header-is-private.h>

#include <cassert>
#include <cstddef> // required for nullptr_t
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace APT::Solver
{

struct Lit;
class Solver;

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

   // Satisfy optional dependencies that were previously satisfied but won't otherwise be installed
   SatisfySuggests,

   // Automatically installed packages must come last in the group, this allows
   // us to see if they were installed as a dependency of a manually installed package,
   // allowing a simple implementation of an autoremoval code.
   UpgradeAuto,
   KeepAuto,
   ObsoleteAuto,
};

// \brief This essentially describes the install state in RFC2119 terms.
enum class LiftedBool : int8_t
{
   // \brief We cannot install this package (need conflicts with it)
   False = -1,
   // \brief We have not made a choice about the package yet
   Undefined = 0,
   // \brief We need to install this package
   True = 1,
};

/**
 * \brief A variable in the solver, identified by a small integer.
 *
 * Variables are registered explicitly with the solver via Solver::newVar();
 * the variable 0 is reserved for the root. Any mapping from variables to objects
 * of interest, such as packages and versions, is maintained by the concrete
 * solver implementation.
 */
struct Var
{
   uint32_t value;

   // \brief The root variable.
   constexpr Var() noexcept : value{0} {}

   // \brief Check if there is no reason.
   constexpr bool empty() const noexcept { return value == 0; }
   constexpr bool operator!=(Var const other) const noexcept { return value != other.value; }
   constexpr bool operator==(Var const other) const noexcept { return value == other.value; }

   /// \brief Negate
   constexpr Lit operator~() const noexcept;

   private:
   friend class Solver;
   friend struct Lit;
   // \brief Construct a variable from its numeric identifier.
   //
   // Only the solver hands out variables (via Solver::newVar()), such that
   // using a variable as an index cannot refer to unregistered state.
   explicit constexpr Var(uint32_t value) noexcept : value{value} {}
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
   // Private constructor from a raw number, to be used with operator~
   explicit constexpr Lit(uint32_t raw) noexcept : value{raw} {}
   // \brief The variable shifted left by one bit, with the sign in the lowest bit.
   uint32_t value;

   public:
   constexpr Lit() noexcept : value{0} {}
   // SAFETY: var.value must be 31 bit, one bit is needed for the sign.
   constexpr Lit(Var var) noexcept : value{var.value << 1} {}
   constexpr Lit(Var var, bool sign) noexcept : value{(var.value << 1) | uint32_t(sign)} {}

   // Accessors
   constexpr Var var() const noexcept { return Var{value >> 1}; }
   constexpr bool sign() const noexcept { return value & 1; }
   constexpr Lit operator~() const noexcept { return Lit{value ^ 1}; }

   // Properties
   constexpr bool empty() const noexcept { return value == 0; }
   constexpr bool operator!=(Lit const other) const noexcept { return value != other.value; }
   constexpr bool operator==(Lit const other) const noexcept { return value == other.value; }
};

/**
 * \brief A reference to a clause in the solver's clause store.
 *
 * All clauses live in a single VarVector (Solver::clauses); a CRef stores the
 * index of a clause there, so references remain valid as the store grows.
 * A null reference (constructed from nullptr) does not refer to a clause.
 */
struct CRef
{
   uint32_t value = UINT32_MAX;

   // \brief Construct a null reference.
   constexpr CRef() noexcept = default;
   // \brief Construct a null reference.
   constexpr CRef(std::nullptr_t) noexcept {}
   // \brief Construct a reference to the clause at the given index.
   constexpr explicit CRef(uint32_t value) noexcept : value{value} {}

   // \brief Check if there is a referenced clause.
   constexpr explicit operator bool() const noexcept { return value != UINT32_MAX; }
   constexpr bool operator!=(CRef const other) const noexcept { return value != other.value; }
   constexpr bool operator==(CRef const other) const noexcept { return value == other.value; }
};

/**
 * \brief A single clause
 *
 * A clause is a normalized, expanded dependency, translated into an implication
 * in terms of Var objects, that is, `guard -> solutions[0] | ... | solutions[n]`
 */
struct Clause
{
   // \brief Underlying dependency, opaque to the solver (a pkgCache::Dependency in practice)
   void *dep = nullptr;
   // \brief Possible solutions to this task, ordered in order of preference.
   std::vector<Var> solutions{};
   // Clauses merged with this clause, next node in linked list
   CRef merged;
   // \brief Var guarding the implication
   Var guard;
   // \brief The group we are in
   Group group;
   // \brief An optional clause does not need to be satisfied
   bool optional;

   // \brief A negative clause negates the solutions, that is X->A|B you get X->!(A|B), aka X->!A&!B
   bool negative;

   // \brief An optional clause may be eager
   bool eager;

   inline Clause(Var guard, Group group, bool optional = false, bool negative = false) : guard(guard), group(group), optional(optional), negative(negative), eager(not optional) {}
};

constexpr Lit Var::operator~() const noexcept
{
   return ~Lit(*this);
}

constexpr LiftedBool operator~(LiftedBool value) noexcept
{
   // Negation: Undefined stays Undefined, True and False are exchanged.
   return static_cast<LiftedBool>(-static_cast<int8_t>(value));
}

/**
 * \brief A minimal, grow-only vector indexed by index objects.
 *
 * Bypass bounds-checking done by _GLIBCXX_ASSERTIONS in a typed manner.
 * Index objects such as Var or CRef are only handed out by the solver,
 * so accessing them is safe.
 */
template <typename T, typename K = Var>
class VarVector : private std::vector<T>
{
   public:
   // This is a fairly sensible lower bound for a Debian install
   VarVector() { std::vector<T>::reserve(64 * 1024); }
   // Bypass bounds checking in libstdc++ using data() as explained above
   constexpr T &operator[](K k) noexcept { return std::vector<T>::data()[k.value]; }
   constexpr const T &operator[](K k) const noexcept { return std::vector<T>::data()[k.value]; }
   // Safe functionality we can expose directly
   using std::vector<T>::size;
   using std::vector<T>::push_back;
   using std::vector<T>::emplace_back;
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
class Solver
{
   protected:
   class Watches;
   struct State;
   struct Work;

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
   using Trail = std::variant<Var, Work>;

   // \brief Type to record decision level at. This may very well be a 16-bit
   // unsigned integer, then change Solver::State::LiftedBool to be a
   // uint16_t class enum as well to get a more compact space.
   using level_type = unsigned int;

   // Documentation
   template <typename T>
   using heap = std::vector<T>;

   // \brief State for each registered variable; the root is at index 0.
   VarVector<State> states;

   // \brief Store owning all clauses of the solver; clauses are referenced
   // by CRef (their index here), which stays valid as the store grows.
   VarVector<Clause, CRef> clauses;

   // \brief Add a clause to the store, register it with its guard's state,
   // and set up its watchers, returning its reference.
   CRef newClause(Clause &&clause);
   // \brief Register clause as a duplicate
   CRef duplicateClause(CRef primaryCRef, Clause &&clause);

   // \brief Register a new variable, returning its identifier.
   //
   // Concrete solvers may override this to keep auxiliary data structures
   // indexed by variables in sync.
   virtual Var newVar();

   constexpr std::span<const CRef> watches(Lit lit) const noexcept;
   constexpr auto clausesOf(Var var) const noexcept;

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
   // \brief Solver timeout in seconds.
   int Timeout{_config->FindI("APT::Solver::Timeout", 10)};

   // \brief Discover a variable, translating the underlying dependencies to the SAT presentation
   //
   // This does a breadth-first search of the entire dependency tree of var,
   // utilizing the discoverQ above.
   virtual void Discover(Var var) = 0;
   // \brief Propagate all pending propagations
   [[nodiscard]] bool Propagate();
   // \brief Propagate all pending propagations
   [[nodiscard]] bool Propagate(CRef clause, Lit lit);

   // \brief Return the current level (.size() with casting)
   level_type decisionLevel()
   {
      return static_cast<level_type>(trailLim.size());
   }
   Var bestReason(CRef clause, Var var) const noexcept;
   constexpr LiftedBool value(Lit lit) const noexcept;

   public:
   // \brief Revert to the previous decision level.
   [[nodiscard]] bool Pop();
   // \brief Undo a single assignment / trail work item
   void UndoOne();
   // \brief This function determines if a work item is less important than another.
   bool workLess(Work const &a, Work const &b) const noexcept;
   // \brief Add work to our work queue.
   [[nodiscard]] bool AddWork(Work &&work);

   // \brief Basic solver initializer. This cannot fail.
   Solver();
   virtual ~Solver();

   // Assume a literal
   [[nodiscard]] bool Assume(Lit lit, CRef reason = nullptr);
   // Enqueue a fact
   [[nodiscard]] bool Enqueue(Lit lit, CRef reason = nullptr);

   // \brief Solve the dependencies
   [[nodiscard]] bool Solve();

   // \brief Render a variable, e.g. for debugging output
   virtual std::string toString(Var var) const;
   // \brief Render a literal, e.g. for debugging output
   virtual std::string toString(Lit lit) const;
   // \brief Render a clause, e.g. for debugging output
   virtual std::string toString(const Clause &clause, bool pretty = false, bool showMerged = true) const;
   // \brief Render a work item, e.g. for debugging output
   std::string toString(const Work &work) const;

   // \brief Whether the variable is a package, used to elide version selection clauses in reasons.
   virtual constexpr bool IsPackage(Var) const noexcept { return false; }
   // \brief Describe the selection state of a variable, e.g. "x1 is selected for install"
   virtual std::string DescribeSelection(Var var, bool assignment) const;

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
   virtual std::string LongWhyStr(Var var, bool assignment, CRef rclause, std::string prefix, std::unordered_set<Var> &seen) const;
};

/**
 * \brief Compact presentation of watchers
 */
class Solver::Watches
{
   std::vector<CRef> watches;
   // [0, split) are positive, [split, end) are negative.
   size_t split{0};

   public:
   void add(CRef clause, bool sign)
   {
      watches.push_back(clause);
      if (not sign)
      {
	 // Bypass bounds-checking in vector.
	 std::swap(watches.data()[split], watches.data()[watches.size() - 1]);
	 ++split;
      }
   }

   std::span<const CRef> get(bool sign) const
   {
      if (not sign)
	 return {watches.begin(), watches.begin() + split};
      else
	 return {watches.begin() + split, watches.end()};
   }
};

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
struct Solver::Work
{
   CRef clause;

   // \brief The level at which the item has been added
   level_type level;

   /// Number of valid choices at insertion time
   uint32_t size{0};

   constexpr Work(CRef clause, level_type level) noexcept : clause(clause), level(level) {}
};

/**
 * \brief The solver state
 *
 * For each version, the solver records a assignment at a certain level. It
 * maintains an array mapping from version ID to state.
 */
struct Solver::State
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
   CRef reason{};

   // \brief The level at which the value has been assigned
   level_type level{0};

   LiftedBool assignment{LiftedBool::Undefined};

   // \brief Flags.
   struct
   {
      bool discovered{};
      bool manual{};
      bool backtracked{};
   } flags;

   static_assert(sizeof(flags) <= sizeof(int));
   // \brief Watches watching a clause by sign
   Watches watches;
};

constexpr std::span<const CRef> Solver::watches(Lit lit) const noexcept
{
   return states[lit.var()].watches.get(lit.sign());
}

constexpr auto Solver::clausesOf(Var var) const noexcept
{
   return watches(Lit(var, false)) | std::ranges::views::filter([this, var](CRef ref) noexcept
								{ return clauses[ref].guard == var; });
}

constexpr LiftedBool Solver::value(Lit lit) const noexcept
{
   return lit.sign() ? ~states[lit.var()].assignment : states[lit.var()].assignment;
}

}; // namespace APT::Solver

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

#endif /* APT_SOLVER_H */
