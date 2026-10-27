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
   states[Var{}].assignment = LiftedBool::True;
}

Solver::~Solver() = default;

Var Solver::newVar()
{
   states.emplace_back();
   return Var{static_cast<uint32_t>(states.size() - 1)};
}

CRef Solver::newClause(Clause &&clause)
{
   clauses.push_back(std::move(clause));
   auto cref = CRef{static_cast<uint32_t>(clauses.size() - 1)};
   auto const &inserted = clauses[cref];

   // Insert all our watches: the guard is watched positively such that
   // activating the guard queues the clause, solutions are watched
   // negatively unless the clause itself is negative.
   states[inserted.guard].watches.add(cref, false);
   for (auto sol : inserted.solutions)
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
   if (a.size == 1 && b.size == 1) // Special case: 'shortcircuit' optional packages
      return ca.solutions.size() < cb.solutions.size();
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

std::string Solver::toString(const Clause &clause, [[maybe_unused]] bool pretty, bool showMerged) const
{
   // Render the implication in a DIMACS-like form, e.g. A -> B | C becomes ~xA | xB | xC
   std::string out;
   if (showMerged && not clause.guard.empty())
      out.append(toString(~clause.guard));
   for (auto sol : clause.solutions)
   {
      if (not out.empty())
	 out.append(" | ");
      out.append(toString(clause.negative ? ~sol : Lit(sol)));
   }
   if (showMerged && not clause.merged.empty())
   {
      for (auto &merged : clause.merged)
      {
	 out.append(" and ");
	 out.append(toString(merged, pretty, false));
      }
   }
   return out;
}

std::string Solver::DescribeSelection(Var var, bool assignment) const
{
   std::string s;
   if (not assignment)
      strprintf(s, "%s is not selected for install", toString(var).c_str());
   else
      strprintf(s, "%s is selected for install", toString(var).c_str());
   return s;
}

std::string Solver::toString(const Work &work) const
{
   auto const &clause = clauses[work.clause];
   std::ostringstream out;
   if (clause.optional)
      out << "Optional ";
   out << "Item (" << ssize_t(work.size <= clause.solutions.size() ? work.size : -1) << "@" << work.level << ") ";
   out << toString(clause);
   return out.str();
}

Var Solver::bestReason(CRef cref, Var var) const noexcept
{
   if (not cref)
      return Var{};
   auto const &clause = clauses[cref];
   if (clause.guard == var)
      for (auto choice : clause.solutions)
      {
	 if (clause.negative && value(choice) == LiftedBool::True)
	    return choice;
	 if (not clause.negative && value(choice) == LiftedBool::False)
	    return choice;
      }
   return clause.guard;
}

// Prints an implication graph part of the form A -> B -> C, possibly with "not"
std::string Solver::WhyStr(Var reason) const
{
   std::vector<std::string> out;
   while (not reason.empty())
   {
      if (value(reason) == LiftedBool::False)
	 out.push_back(std::string("not ") + toString(reason));
      else
	 out.push_back(toString(reason));
      reason = bestReason(states[reason].reason, reason);
   }

   std::string outstr;
   for (auto I = out.rbegin(); I != out.rend(); ++I)
   {
      outstr += (outstr.size() == 0 ? "" : " -> ") + *I;
   }
   return outstr;
}

std::string Solver::LongWhyStr(Var var, bool assignment, CRef rclause, std::string prefix, std::unordered_set<Var> &seen) const
{
   std::ostringstream out;

   // Helper function to nicely print more details than just "install/do not install", such as "removal", "upgrade", "downgrade", "install"
   auto printSelection = [this](Var var, bool assignment)
   {
      return DescribeSelection(var, assignment);
   };

   // Helper: Recurse into all of the children of the clause and print the assignment for them.
   auto recurseChildren = [&](CRef cref, Var skip = Var())
   {
      auto const &clause = clauses[cref];
      if (clause.solutions.empty())
	 out << prefix << "[no choices]\n";
      for (auto choice : clause.solutions)
      {
	 if (choice == skip)
	    continue;

	 if (value(choice) == LiftedBool::Undefined)
	    out << prefix << "- " << toString(choice) << " is undecided\n";
	 else
	    out << prefix << "- " << LongWhyStr(choice, value(choice) == LiftedBool::True, states[choice].reason, prefix + "  ", seen).substr(prefix.size() + 2);
      }
   };

   // Inverse version selection clauses that select the package if the version is selected,
   // such as pkg=ver -> pkg, are irrelevant for the user, skip them
   if (IsPackage(var) && assignment && rclause && clauses[rclause].group == Group::SelectVersion)
   {
      var = clauses[rclause].guard;
      rclause = states[var].reason;
   }

   // No reason given, probably a user request or manually installed or essential or whatnot.
   if (not rclause)
   {
      out << prefix << printSelection(var, assignment) << "\n";
      return out.str();
   }

   // We could be called with a assignment we tried to make but failed due to a conflict;
   // this checks if it is the real assignment.
   if (value(var) != LiftedBool::Undefined && assignment == (value(var) == LiftedBool::True) && states[var].reason == rclause)
   {
      // If we have seen the real assignment before; we dont't need to print it again.
      if (seen.find(var) != seen.end())
      {
	 out << prefix << printSelection(var, assignment) << " as above\n";
	 return out.str();
      }
      seen.insert(var);
   }

   // A package was decided "not install" due to a positive clause, so the clause is unsat.
   if (not assignment && rclause && not clauses[rclause].negative)
   {
      out << prefix << toString(clauses[rclause], true) << "\n";
      out << prefix << "but none of the choices are installable:\n";
      recurseChildren(rclause);
      return out.str();
   }

   // Build the strongest path from a root to our assignment leaf
   std::vector<Var> path;
   for (auto reason = bestReason(rclause, var); not reason.empty(); reason = bestReason(states[reason].reason, reason))
      path.push_back(reason);

   // Render the strong reasoning path
   out << prefix << printSelection(var, assignment) << " because:\n";
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
	    out << prefix << (i == 1 ? "" : "1-") << i << ". " << printSelection(*it, state.assignment == LiftedBool::True) << " as above\n";
	 }
	 continue;
      }
      seen.insert(*it);
      if (state.reason)
      {
	 out << prefix << std::setw(w) << i << ". " << toString(clauses[state.reason], true) << "\n";
	 if (clauses[state.reason].solutions.size() > 1)
	    out << prefix << std::setw(w) << " " << "  [selected " << toString(*it) << " for " << (state.assignment == LiftedBool::True ? "install" : "remove") << "]\n";
      }
      else
	 out << prefix << std::setw(w) << i << ". " << printSelection(*it, state.assignment == LiftedBool::True) << "\n";
   }

   // Print the leaf. We can't have the leaf in the path because we might be called for an attempted assignment
   // that conflicts with the actual assignment (to simplify: we marked X for not install, then we process Y depends X
   // and try to mark X and reach the conflict, we are called with "X" and the "Y depends X" clause).
   out << prefix << std::setw(w) << i << ". " << toString(clauses[rclause], true) << "\n";
   if (clauses[rclause].solutions.size() > 1)
      out << prefix << std::setw(w) << " " << "  " << "[selected " << toString(bestReason(rclause, var)) << "]\n";

   bool firstContext = true;
   // Show alternative paths not taken. Consider you have Y depends X|Z; and you mark X
   // for it; we show above Y -> X as the path, but here we go show why Z was not considered in "Y depends X|Z".
   for (auto it = path.rbegin(); it != path.rend(); ++it)
   {
      auto const &state = states[*it];
      if (not state.reason) // If we have no reason, we don't have alternatives
	 continue;
      if (clauses[state.reason].solutions.size() <= 1) // Nothing to print if we no alternatives
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
   if (clauses[rclause].solutions.size() > 1 && not clauses[rclause].negative)
   {
      if (firstContext)
      {
	 out << prefix << "For context, additional choices that could not be installed:" << "\n";
      }
      firstContext = false;
      out << prefix << "* In " << toString(clauses[rclause], true) << ":\n";
      prefix += "  ";
      recurseChildren(rclause, var);
      prefix.resize(prefix.size() - 2);
   }

   return out.str();
}

bool Solver::Assume(Lit lit, CRef reason)
{
   trailLim.push_back(trail.size());
   return Enqueue(lit, std::move(reason));
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
	 std::ostringstream err;
	 err << "Unable to satisfy dependencies. Reached two conflicting assignments:" << "\n";
	 std::unordered_set<Var> seen;
	 err << "1. " << LongWhyStr(lit.var(), state.assignment == LiftedBool::True, state.reason, "   ", seen).substr(3) << "\n";
	 err << "2. " << LongWhyStr(lit.var(), not lit.sign(), reason, "   ", seen).substr(3);
	 return _error->Error("%s", err.str().c_str());
      }
      return true;
   }

   state.assignment = assignment;
   state.level = decisionLevel();
   state.reason = reason;

   // FIXME: Adjust call to bestReason to use lit
   if (unlikely(debug >= 1))
      std::cerr << "[" << decisionLevel() << "] " << (lit.sign() ? "Reject" : "Install") << ":" << toString(lit.var()) << " (" << WhyStr(bestReason(reason, lit.var())) << ")\n";

   trail.push_back(Trail{lit.var()});
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
      for (auto sol : clause.solutions)
	 if (not Enqueue(~sol, cref))
	    return false;

      return true;
   }

   // Check if the clause is unit, conflict, or undecided
   auto not_false = [&](auto lit) noexcept
   { return value(lit) != LiftedBool::False; };
   auto head = std::ranges::find_if(clause.solutions, not_false);
   auto find_tail = [&]() noexcept
   { return std::ranges::find_last_if(clause.solutions, not_false); };
   if (head == clause.solutions.end())
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
	 return AddWork(Work{cref, decisionLevel()});
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
	 state.level = 0;
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

   // We need to remove any work that is at a higher level.
   trailLim.pop_back();
   work.erase(std::remove_if(work.begin(), work.end(), [this](Work &w) -> bool
			     { return w.level > decisionLevel(); }),
	      work.end());
   std::make_heap(work.begin(), work.end(), [this](Work const &a, Work const &b)
		  { return workLess(a, b); });

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
      for (auto var : clause.solutions)
	 if (not Enqueue(~var, w.clause))
	    return false;
   }
   else
   {
      if (unlikely(debug >= 3 && clause.optional))
	 std::cerr << "Enqueuing Recommends " << toString(clause) << std::endl;
      if (clause.solutions.size() == 1 && not clause.optional)
	 return Enqueue(clause.solutions[0], w.clause);

      w.size = std::count_if(clause.solutions.begin(), clause.solutions.end(), [this](auto V)
			     { return value(V) != LiftedBool::False; });
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

      auto const &clause = clauses[item.clause];
      if (std::any_of(clause.solutions.begin(), clause.solutions.end(), [this](auto ver)
		      { return value(ver) == LiftedBool::True; }))
      {
	 if (unlikely(debug >= 2))
	    std::cerr << "ELIDED " << toString(item) << std::endl;
      }
      else if (auto candidate = std::find_if(clause.solutions.begin(), clause.solutions.end(), [this](auto ver)
					     { return value(ver) == LiftedBool::Undefined; });
	       candidate != clause.solutions.end())
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
