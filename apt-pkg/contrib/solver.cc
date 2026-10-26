/*
 * solver.cc - APT General purpose SAT solver - implementation
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

#include <config.h>

#include <apt-pkg/solver.h>

#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <new>
#include <sstream>

namespace APT::Solver
{

Solver::Solver()
{
   // Ensure the work and trail items are trivially destructible
   static_assert(std::is_trivially_destructible_v<Work>);
   static_assert(std::is_trivially_destructible_v<Trail>);
   // The root state is "true".
   states.emplace_back();
   seen.push_back(0);
   states[Var{}].assignment = LiftedBool::True;
}

Solver::~Solver() = default;

Var Solver::newVar()
{
   states.emplace_back();
   seen.push_back(0);
   return Var{static_cast<uint32_t>(states.size() - 1)};
}

static CRef makeClause(VarVector<StoredClause, CRef, uint32_t> &clauses, Clause const &clause)
{
   static_assert(sizeof(StoredClause) % sizeof(uint32_t) == 0);
   static_assert(alignof(StoredClause) == sizeof(uint32_t));
   size_t words = sizeof(StoredClause) / sizeof(uint32_t) + clause.solutions.size();
   size_t offset = clauses.size();
   auto cref = CRef{static_cast<uint32_t>(offset)};
   clauses.resize(offset + words);

   new (&clauses[cref]) StoredClause{clause};
   return cref;
}

CRef Solver::duplicateClause(CRef primaryCRef, Clause &clause)
{
   clause.merged = clauses[primaryCRef].merged;
   auto cref = makeClause(clauses, clause);
   clauses[primaryCRef].merged = cref;
   return cref;
}

CRef Solver::newClause(Clause const &clause)
{
   auto cref = makeClause(clauses, clause);
   auto &inserted = clauses[cref];

   // Insert all our watches: the guard is watched positively such that
   // activating the guard queues the clause, solutions are watched
   // negatively unless the clause itself is negative.
   states[inserted.guard].watches.add(cref, false);
   for (auto sol : inserted.solutions())
   {
      auto lit = inserted.negative ? sol : ~sol;
      states[lit.var()].watches.add(cref, lit.sign());
   }
   return cref;
}

// This function determines if a work item is less important than another.
bool Solver::workLess(Solver::Work const &a, Solver::Work const &b) const noexcept
{
   auto const &ca = clauses[a.clause];
   auto const &cb = clauses[b.clause];
   if ((not ca.optional && a.size < 2) != (not cb.optional && b.size < 2))
      return not cb.optional && b.size < 2;
   if (ca.eager != cb.eager)
      return not ca.eager;
   if (ca.group != cb.group)
      return ca.group > cb.group;
   if ((a.size < 2) != (b.size < 2))
      return b.size < 2;
   if (a.size < 2 && b.size < 2) // Special case: 'shortcircuit' optional packages
      return ca.solutions().size() < cb.solutions().size();
   return false;
}

std::string Solver::toString(Var var) const
{
   return "x" + std::to_string(var.value);
}

std::string Solver::toString(Lit lit) const
{
   return (lit.sign() ? "~" : "") + toString(lit.var());
}

std::string Solver::toString(const ClauseHeader &clause, std::span<const Lit> solutions, [[maybe_unused]] bool pretty, bool showMerged) const
{
   // Render the implication in a DIMACS-like form, e.g. A -> B | C becomes ~xA | xB | xC
   std::string out;
   if (showMerged && not clause.guard.empty())
      out.append(toString(~clause.guard));
   for (auto sol : solutions)
   {
      if (not out.empty())
	 out.append(" | ");
      out.append(toString(clause.negative ? ~sol : sol));
   }
   if (showMerged && clause.merged)
   {
      for (auto merged = clause.merged; merged; merged = clauses[merged].merged)
      {
	 out.append(" and ");
	 out.append(toString(clauses[merged], pretty, false));
      }
   }
   return out;
}

std::string Solver::DescribeSelection(Lit lit) const
{
   std::string s;
   if (lit.sign())
      strprintf(s, "%s is not selected for install", toString(lit.var()).c_str());
   else
      strprintf(s, "%s is selected for install", toString(lit.var()).c_str());
   return s;
}

std::string Solver::toString(const Work &work) const
{
   auto const &clause = clauses[work.clause];
   std::ostringstream out;
   if (clause.optional)
      out << "Optional ";
   out << "Item (" << ssize_t(work.size <= clause.solutions().size() ? work.size : -1) << "@" << work.generation << ") ";
   out << toString(clause);
   return out.str();
}

Lit Solver::bestReason(CRef cref, Lit lit) const noexcept
{
   if (not cref)
      return Lit{};
   auto const &clause = clauses[cref];
   if (clause.guard == lit.var())
      for (auto choice : clause.solutions())
      {
	 if (clause.negative && value(choice) == LiftedBool::True)
	    return choice;
	 if (not clause.negative && value(choice) == LiftedBool::False)
	    return choice;
      }
   return clause.guard;
}

void Solver::calcReason(CRef reason, Lit p, std::vector<Lit> &out_reason) const
{
   // Optional clauses never record hard reasons: propagation is guarded by
   // Clause::optional throughout, and assumptions record their (possibly
   // optional) clause as a soft reason, see State::flags::soft_reason. A
   // hard reason must be entailed, an optional clause is not.
   auto const &rclause = clauses[reason];
   assert(not rclause.optional);

   // The reason for p is the set of (true) assignment literals that implied
   // it, excluding p itself, like the paper: invariantly, every literal is
   // false under the current assignment except the implied one.
   if (rclause.negative)
   {
      if (p.var() == rclause.guard)
      {
	 // The guard was rejected because a solution is installed; the earliest
	 // installed solution (in trail order) is the antecedent.
	 Var best{};
	 for (auto sol : rclause.solutions())
	    if (value(sol) == LiftedBool::True && (best.empty() || states[sol.var()].trailPos < states[best].trailPos))
	       best = sol.var();
	 assert(not best.empty());
	 out_reason.push_back(Lit(best));
      }
      else
      {
	 // The solution was rejected because the guard is installed.
	 out_reason.push_back(Lit(rclause.guard));
      }
      return;
   }

   // A positive clause implies a solution because the guard is installed and
   // the other solutions are rejected, and rejects its guard because all
   // solutions are rejected.
   if (not rclause.guard.empty() && p.var() != rclause.guard)
      out_reason.push_back(Lit(rclause.guard));
   for (auto sol : rclause.solutions())
      if (sol != p)
	 out_reason.push_back(~sol);
}

// Conflict analysis after the MiniSAT paper (Eén and Sörensson, "An
// extensible SAT-solver"), with deliberate deviations noted inline.
void Solver::analyze(std::vector<Lit> confl, std::vector<Lit> &out_learnt, level_type &out_btlevel)
{
   // Clear the marks of the previous analysis; they remain available for
   // inspection until the next analysis.
   for (auto var : seenLits)
      seen[var] = 0;
   seenLits.clear();

   int counter = 0;
   Lit p{};			// The literal resolved last
   size_t index = trail.size(); // Trail walker, going backwards
   out_learnt.push_back(Lit{}); // Leave room for the asserting literal
   out_btlevel = 0;

   while (true)
   {
      // Trace reason for p; the first iteration traces the conflict itself.
      //
      // Deviation: the paper fetches reason[var(p)] unconditionally while
      // selecting p, relying on the invariant that there is exactly one
      // reason-less literal (the decision) per level; we fetch lazily, which
      // is what guarantees that a decision's null reason is never read.
      p_reason.clear();
      if (p.empty())
	 // The conflict is given as the falsified literals of a clause; like
	 // the paper's calcReason, we want the true assignment literals that
	 // falsify them.
	 for (auto q : confl)
	    p_reason.push_back(~q);
      else if (auto reason = states[p.var()].hardReason())
	 calcReason(reason, p, p_reason);
      else
	 // A root of the graph without a hard reason to resolve. This cannot
	 // be a decision or an assumption: those are the oldest assignment of
	 // their level and are selected last, when counter == 1. It can only
	 // be a literal backtracked by Pop(), which gets no reason. Keeping
	 // the literal in the clause leaves it a sound resolvent, though no
	 // longer necessarily an asserting one; once learning is wired in,
	 // backtracked literals should get the learnt clause of the failed
	 // branch as their reason (see the FIXME in Pop()) and this case
	 // goes away.
	 out_learnt.push_back(~p);

      for (auto q : p_reason)
      {
	 if (not seen[q.var()])
	 {
	    seen[q.var()] = 1;
	    seenLits.push_back(q.var());
	    if (states[q.var()].level == decisionLevel())
	       ++counter;
	    else if (states[q.var()].level > 0) // Exclude variables from decision level 0
	    {
	       out_learnt.push_back(~q);
	       out_btlevel = std::max(out_btlevel, states[q.var()].level);
	    }
	 }
      }

      // Select next literal to look at: the most recently assigned seen
      // literal; there is always one as long as counter > 0.
      //
      // Deviation: the paper consumes the trail with undoOne() as it goes;
      // we walk an index instead, leaving the trail and the assignments
      // untouched (our trail also carries work items, which have no
      // assignment).
      while (true)
      {
	 assert(index > 0);
	 auto choicePtr = std::get_if<Var>(&trail[--index]);
	 if (choicePtr && not choicePtr->empty() && seen[*choicePtr])
	 {
	    p = Lit(*choicePtr, states[*choicePtr].assignment == LiftedBool::False);
	    break;
	 }
      }
      if (--counter == 0)
	 break;
   }

   out_learnt[0] = ~p;
}

// Prints an implication graph part of the form A -> B -> C, possibly with "not"
std::string Solver::WhyStr(Lit lit) const
{
   std::vector<std::string> out;
   while (not lit.empty())
   {
      // Print the literal that holds in reality: bestReason() may return a
      // solution that is false, which we print negated to keep its meaning.
      out.push_back(toString(value(lit) == LiftedBool::False ? ~lit : lit));
      // States are per-variable; the literal itself keeps its sign.
      lit = bestReason(states[lit.var()].reason, lit);
   }

   std::string outstr;
   for (auto I = out.rbegin(); I != out.rend(); ++I)
   {
      outstr += (outstr.size() == 0 ? "" : " -> ") + *I;
   }
   return outstr;
}

std::string Solver::LongWhyStr(Lit lit, CRef rclause, std::string prefix, std::unordered_set<Var> &seen) const
{
   std::ostringstream out;

   // Helper: Recurse into all of the children of the clause and print the assignment for them.
   auto recurseChildren = [&](CRef cref, Var skip = Var())
   {
      auto const &clause = clauses[cref];
      if (clause.solutions().empty())
	 out << prefix << "[no choices]\n";
      for (auto choice : clause.solutions())
      {
	 if (choice.var() == skip)
	    continue;

	 if (value(choice) == LiftedBool::Undefined)
	    out << prefix << "- " << toString(choice) << " is undecided\n";
	 else
	    // Explain the literal that holds in reality, not the one stated in the clause.
	    out << prefix << "- " << LongWhyStr(value(choice) == LiftedBool::True ? choice : ~choice, states[choice.var()].reason, prefix + "  ", seen).substr(prefix.size() + 2);
      }
   };

   // Inverse version selection clauses that select the package if the version is selected,
   // such as pkg=ver -> pkg, are irrelevant for the user, skip them
   if (IsPackage(lit.var()) && not lit.sign() && rclause && clauses[rclause].group == Group::SelectVersion)
   {
      lit = clauses[rclause].guard;
      rclause = states[lit.var()].reason;
   }

   // No reason given, probably a user request or manually installed or essential or whatnot.
   if (not rclause)
   {
      out << prefix << DescribeSelection(lit) << "\n";
      return out.str();
   }

   // We could be called with a assignment we tried to make but failed due to a conflict;
   // this checks if it is the real assignment.
   if (value(lit.var()) != LiftedBool::Undefined && (not lit.sign()) == (value(lit.var()) == LiftedBool::True) && states[lit.var()].reason == rclause)
   {
      // If we have seen the real assignment before; we dont't need to print it again.
      if (seen.find(lit.var()) != seen.end())
      {
	 out << prefix << DescribeSelection(lit) << " as above\n";
	 return out.str();
      }
      seen.insert(lit.var());
   }

   // A package was decided "not install" due to a positive clause, so the clause is unsat.
   if (lit.sign() && rclause && not clauses[rclause].negative)
   {
      out << prefix << toString(clauses[rclause], true) << "\n";
      out << prefix << "but none of the choices are installable:\n";
      recurseChildren(rclause);
      return out.str();
   }

   // Build the strongest path from a root to our assignment leaf
   // The path holds variables; signs are re-derived from the stored assignment when printing.
   std::vector<Var> path;
   for (auto reason = bestReason(rclause, lit); not reason.empty(); reason = bestReason(states[reason.var()].reason, reason))
      path.push_back(reason.var());

   // Render the strong reasoning path
   out << prefix << DescribeSelection(lit) << " because:\n";
   auto w = std::to_string(path.size() + 1).size();
   size_t i = 1;
   for (auto it = path.rbegin(); it != path.rend(); ++it, ++i)
   {
      auto const &state = states[*it];
      // Don't print version selection clauses
      if (IsPackage(*it) && state.reason && clauses[state.reason].group == Group::SelectVersion)
      {
	 --i;
	 continue;
      }
      if (seen.find(*it) != seen.end())
      {
	 if ((it + 1) == path.rend() || seen.find(*(it + 1)) == seen.end())
	 {
	    out << prefix << (i == 1 ? "" : "1-") << i << ". " << DescribeSelection(Lit(*it, state.assignment == LiftedBool::False)) << " as above\n";
	 }
	 continue;
      }
      seen.insert(*it);
      if (state.reason)
      {
	 out << prefix << std::setw(w) << i << ". " << toString(clauses[state.reason], true) << "\n";
	 if (clauses[state.reason].solutions().size() > 1)
	    out << prefix << std::setw(w) << " " << "  [selected " << toString(*it) << " for " << (state.assignment == LiftedBool::True ? "install" : "remove") << "]\n";
      }
      else
	 out << prefix << std::setw(w) << i << ". " << DescribeSelection(Lit(*it, state.assignment == LiftedBool::False)) << "\n";
   }

   // Print the leaf. We can't have the leaf in the path because we might be called for an attempted assignment
   // that conflicts with the actual assignment (to simplify: we marked X for not install, then we process Y depends X
   // and try to mark X and reach the conflict, we are called with "X" and the "Y depends X" clause).
   out << prefix << std::setw(w) << i << ". " << toString(clauses[rclause], true) << "\n";
   if (clauses[rclause].solutions().size() > 1)
      out << prefix << std::setw(w) << " " << "  " << "[selected " << toString(bestReason(rclause, lit)) << "]\n";

   bool firstContext = true;
   // Show alternative paths not taken. Consider you have Y depends X|Z; and you mark X
   // for it; we show above Y -> X as the path, but here we go show why Z was not considered in "Y depends X|Z".
   for (auto it = path.rbegin(); it != path.rend(); ++it)
   {
      auto const &state = states[*it];
      if (not state.reason) // If we have no reason, we don't have alternatives
	 continue;
      if (clauses[state.reason].solutions().size() <= 1) // Nothing to print if we no alternatives
	 continue;
      if (clauses[state.reason].negative) // We only actually need one conflicting choice, ignore others
	 continue;

      if (firstContext)
      {
	 out << prefix << "For context, additional choices that could not be installed:" << "\n";
      }

      firstContext = false;
      out << prefix << "* In " << toString(clauses[state.reason], true) << ":\n";
      prefix += "  ";
      recurseChildren(state.reason, *it);
      prefix.resize(prefix.size() - 2);
   }
   if (clauses[rclause].solutions().size() > 1 && not clauses[rclause].negative)
   {
      if (firstContext)
      {
	 out << prefix << "For context, additional choices that could not be installed:" << "\n";
      }
      firstContext = false;
      out << prefix << "* In " << toString(clauses[rclause], true) << ":\n";
      prefix += "  ";
      recurseChildren(rclause, lit.var());
      prefix.resize(prefix.size() - 2);
   }

   return out.str();
}

bool Solver::Assume(Lit lit, CRef reason)
{
   trailLim.push_back(trail.size());
   if (not Enqueue(lit, reason))
      return false;
   // An assumption is a heuristic choice, not a logical implication; record
   // the reason as soft such that conflict analysis treats it as not available.
   states[lit.var()].flags.soft_reason = true;
   return true;
}

bool Solver::Enqueue(Lit lit, CRef reason)
{
   assert(not lit.empty());

   auto &state = states[lit.var()];
   auto assignment = lit.sign() ? LiftedBool::False : LiftedBool::True;

   if (state.assignment != LiftedBool::Undefined)
   {
      if (state.assignment != assignment)
      {
	 // Rendering the why chains is expensive and the error is discarded
	 // when backtracking, so only bother once backtracking is impossible.
	 if (decisionLevel() != 0)
	    return _error->Error("Unable to satisfy dependencies. Reached two conflicting assignments");
	 std::ostringstream err;
	 err << "Unable to satisfy dependencies. Reached two conflicting assignments:" << "\n";
	 std::unordered_set<Var> seen;
	 err << "1. " << LongWhyStr(Lit(lit.var(), state.assignment == LiftedBool::False), state.reason, "   ", seen).substr(3) << "\n";
	 err << "2. " << LongWhyStr(lit, reason, "   ", seen).substr(3);
	 return _error->Error("%s", err.str().c_str());
      }
      return true;
   }

   state.assignment = assignment;
   state.level = decisionLevel();
   state.reason = reason;

   if (unlikely(debug >= 1))
      std::cerr << "[" << decisionLevel() << "] " << (lit.sign() ? "Reject" : "Install") << ":" << toString(lit.var()) << " (" << WhyStr(bestReason(reason, lit)) << ")\n";

   trail.push_back(Trail{lit.var()});
   state.trailPos = static_cast<uint32_t>(trail.size() - 1);
   propQ.push(lit.var());

   return true;
}

bool Solver::Propagate()
{
   while (not propQ.empty())
   {
      Var var = propQ.front();
      propQ.pop();

      // Stale propagation. These do not happen in MiniSat, because it clears the propQ on
      // conflict, however, we simply keep the item in here and skip it.
      if (value(var) == LiftedBool::Undefined)
	 continue;

      Lit lit = value(var) == LiftedBool::False ? ~var : var;
      if (not lit.sign())
	 Discover(lit.var());

      for (auto clause : watches(lit))
	 if (not Propagate(clause, lit))
	    return false;
   }
   return true;
}

bool Solver::Propagate(CRef cref, Lit p)
{
   auto const &clause = clauses[cref];
   if (debug >= 3)
      std::cerr << "Propagate " << toString(p) << " to " << toString(clause) << std::endl;
   // Negative clauses are trivial
   if (clause.negative)
   {
      // One of the solutions was set, so reject the reason
      if (p != clause.guard)
	 return Enqueue(~clause.guard, cref);

      // Here we need to reject all conflicting solutions (reason -> none of solutions)
      for (auto sol : clause.solutions())
	 if (not Enqueue(~sol, cref))
	    return false;

      return true;
   }

   // Check if the clause is unit, conflict, or undecided
   auto not_false = [&](auto lit) noexcept
   { return value(lit) != LiftedBool::False; };
   auto head = std::ranges::find_if(clause.solutions(), not_false);
   auto find_tail = [&]() noexcept
   { return std::ranges::find_last_if(clause.solutions(), not_false); };
   if (head == clause.solutions().end())
   {
      // Conflict clause. If this clause is non-optional; reject its "reason".
      if (not clause.optional)
	 return Enqueue(~clause.guard, cref);
   }
   else if (value(clause.guard) != LiftedBool::True)
   {
      // Inactive clause, nothing to do
   }
   else if (not clause.optional && head == find_tail().begin())
   {
      // Unit clause. Enqueue the only possible solution
      return Enqueue(*head, cref);
   }
   else
   {
      // Undecided clause. If this is an activation, queue it for solving
      if (p == clause.guard)
	 return AddWork(Work{cref, clause.generation});
   }
   return true;
}

void Solver::UndoOne()
{
   auto trailItem = trail.back();

   if (unlikely(debug >= 4))
      std::cerr << "Undoing a single assignment\n";

   std::visit([this](auto &&item)
	      {
      if constexpr (std::is_same_v<std::decay_t<decltype(item)>, Var>) {
	 if (unlikely(debug >= 4))
	    std::cerr << "Unassign " << toString(item) << "\n";
	 auto &state = states[item];
	 state.assignment = LiftedBool::Undefined;
	 state.reason = nullptr;
	 state.flags.backtracked = false;
	 state.flags.soft_reason = false;
	 state.level = 0;
	 state.trailPos = UINT32_MAX;
	 // Work queued for the clauses this variable guards is now stale; bump
	 // their generation so the heap forgets them lazily once they are popped.
	 for (auto cref : clausesOf(item))
	    ++clauses[cref].generation;
      }
      else
      {
	 if (unlikely(debug >= 4))
	    std::cerr << "Adding work item " << toString(item) << std::endl;

         must_succeed(AddWork(std::move(item)));
	 } }, trailItem);

   trail.pop_back();

   // FIXME: Add the undo handling here once we have watchers.
}

bool Solver::Pop()
{
   if (decisionLevel() == 0)
      return false;

   time_t now = time(nullptr);
   if (startTime == 0)
      startTime = now;
   if (now - startTime >= Timeout)
      return _error->Error("Solver timed out.");

   if (unlikely(debug >= 2))
      for (std::string msg; _error->PopMessage(msg);)
	 std::cerr << "Branch failed: " << msg << std::endl;

   _error->Discard();

   // Assume() actually failed to enqueue anything, abort here
   if (trailLim.back() == trail.size())
   {
      trailLim.pop_back();
      return true;
   }

   assert(trailLim.back() < trail.size());
   int itemsToUndo = trail.size() - trailLim.back();
   auto choicePtr = std::get_if<Var>(&trail[trailLim.back()]);
   auto choice = choicePtr ? *choicePtr : Var{};

   for (; itemsToUndo; --itemsToUndo)
      UndoOne();

   trailLim.pop_back();

   if (unlikely(debug >= 2))
      std::cerr << "Backtracking to choice " << toString(choice) << "\n";

   // FIXME: There should be a reason!
   if (not choice.empty() && not Enqueue(~choice, {}))
      return false;

   states[choice].flags.backtracked = true;

   if (unlikely(debug >= 2))
      std::cerr << "Backtracked to choice " << toString(choice) << "\n";

   return true;
}

bool Solver::AddWork(Work &&w)
{
   auto const &clause = clauses[w.clause];
   if (clause.negative)
   {
      for (auto var : clause.solutions())
	 if (not Enqueue(~var, w.clause))
	    return false;
   }
   else
   {
      if (unlikely(debug >= 3 && clause.optional))
	 std::cerr << "Enqueuing Recommends " << toString(clause) << std::endl;
      if (clause.solutions().size() == 1 && not clause.optional)
	 return Enqueue(clause.solutions()[0], w.clause);

      w.size = static_cast<uint32_t>(std::count_if(clause.solutions().begin(), clause.solutions().end(), [this](auto V)
						   { return value(V) != LiftedBool::False; }));
      work.push_back(std::move(w));
      std::push_heap(work.begin(), work.end(), [this](Work const &a, Work const &b)
		     { return workLess(a, b); });
   }
   return true;
}

bool Solver::Solve()
{
   _error->PushToStack();
   DEFER([&]()
	 { _error->MergeWithStack(); });
   startTime = time(nullptr);
   while (true)
   {
      while (_error->PendingError() || not Propagate())
      {
	 if (not Pop())
	    return false;
      }

      if (work.empty())
	 break;

      auto item = work.front();
      std::pop_heap(work.begin(), work.end(), [this](Work const &a, Work const &b)
		    { return workLess(a, b); });
      work.pop_back();

      // The clause was requeued since this work item was queued; the item is stale
      if (item.generation != clauses[item.clause].generation)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "STALE " << toString(item) << std::endl;
	 continue;
      }

      auto const &clause = clauses[item.clause];
      if (std::any_of(clause.solutions().begin(), clause.solutions().end(), [this](auto ver)
		      { return value(ver) == LiftedBool::True; }))
      {
	 if (unlikely(debug >= 2))
	    std::cerr << "ELIDED " << toString(item) << std::endl;
      }
      else if (auto candidate = std::find_if(clause.solutions().begin(), clause.solutions().end(), [this](auto ver)
					     { return value(ver) == LiftedBool::Undefined; });
	       candidate != clause.solutions().end())
      {
	 if (unlikely(debug >= 3))
	    std::cerr << toString(item) << "\n"
		      << "(try it: " << toString(*candidate) << ")\n";
	 must_succeed(Assume(*candidate, item.clause));
      }
      else
      {
	 assert(clause.optional);
	 if (unlikely(debug >= 1))
	    std::cerr << toString(item) << "\n";
      }
      // Must push to trail after any Assume() above.
      trail.push_back(Trail{item});
   }

   return true;
}
} // namespace APT::Solver
