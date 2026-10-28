/*
 * solver_test_hegel.cc - Hegel property tests for the SAT solver core
 *
 * Only built with WITH_HEGEL_TESTS=ON; debian/rules disables them, as
 * configure-time downloads are not allowed during package builds.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-pkg/error.h>
#include <apt-pkg/solver.h>

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common.h"

#include <hegel/gtest.h>

namespace
{
using namespace APT::Solver;
namespace gs = hegel::generators;

// \brief A minimal solver implementation to test the cache-independent core,
// with helpers to draw variables from the registered pool.
class TestSolver : public Solver
{
   hegel::TestCase &tc;
   std::vector<Var> vars;

   public:
   using Solver::AddWork;
   using Solver::newClause;
   using Solver::newVar;
   using Solver::Propagate;
   using Solver::value;
   using Solver::Work;

   // \brief Create a solver with a fresh pool of `count` variables.
   TestSolver(hegel::TestCase &tc, size_t minVars, size_t maxVars) : tc(tc)
   {
      auto const count = tc.draw("varCount", gs::integers<size_t>({.min_value = minVars, .max_value = maxVars}));
      for (size_t i = 0; i < count; ++i)
	 vars.push_back(newVar());
   }

   void Discover(Var) override {}

   CRef AddClause(Clause &&clause)
   {
      return newClause(std::move(clause));
   }

   // \brief Draw one of the registered variables.
   Var drawVar(char const *name)
   {
      return vars[tc.draw(name, gs::integers<size_t>({.min_value = 0, .max_value = vars.size() - 1}))];
   }

   // \brief Draw a guard; one extra value stands for the root variable.
   Var drawGuard(char const *name)
   {
      auto const idx = tc.draw(name, gs::integers<size_t>({.min_value = 0, .max_value = vars.size()}));
      return idx == vars.size() ? Var{} : vars[idx];
   }

   size_t varCount() const { return vars.size(); }
   Var var(size_t idx) const { return vars[idx]; }
};

// Positive binary implications; propagation from an enqueued variable must
// produce exactly its forward closure over the implication graph.
TEST(SolverHegelTest, PropagationClosure)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      TestSolver s{tc, 1, 6};

      auto const clauseCount = tc.draw("clauseCount", gs::integers<size_t>({.min_value = 0, .max_value = 8}));
      std::unordered_multimap<uint32_t, uint32_t> edges;
      for (size_t i = 0; i < clauseCount; ++i)
      {
	 Var guard = s.drawVar("guard");
	 Var sol = s.drawVar("solution");
	 Clause clause{guard, Group::Satisfy};
	 clause.solutions = {sol};
	 s.AddClause(std::move(clause));
	 edges.emplace(guard.value, sol.value);
      }

      auto const selectedGuard = s.drawVar("selectedGuard");

      // Expected forward closure of the selected guard over the implication
      // graph.
      std::unordered_set<uint32_t> closure{selectedGuard.value};
      for (bool changed = true; changed;)
      {
	 changed = false;
	 for (auto [g, sol] : edges)
	    if (closure.contains(g) && closure.insert(sol).second)
	       changed = true;
      }

      ASSERT_TRUE(s.Enqueue(selectedGuard));
      ASSERT_TRUE(s.Propagate());

      for (size_t i = 0; i < s.varCount(); ++i)
      {
	 if (closure.contains(s.var(i).value))
	    EXPECT_EQ(s.value(s.var(i)), LiftedBool::True);
	 else
	    EXPECT_EQ(s.value(s.var(i)), LiftedBool::Undefined);
      } });
}

// Compare against brute force: random root-level (mandatory and optional)
// and guarded positive/negative clauses over a handful of variables;
// Solve() must agree with the exhaustive assignment search, and when it
// succeeds every mandatory clause must be satisfied.
TEST(SolverHegelTest, SolveMatchesBruteForce)
{
   hegel::test([](hegel::TestCase &tc)
	       {
      _error->Discard();
      TestSolver s{tc, 1, 5};

      std::vector<Clause> clauses;
      bool rootConflict = false;

      auto const clauseCount = tc.draw("clauseCount", gs::integers<size_t>({.min_value = 1, .max_value = 6}));
      for (size_t i = 0; i < clauseCount; ++i)
      {
	 // Root-guarded clauses are plain disjunctions queued as work, like
	 // depsolver does; guarded clauses activate when the guard is true.
	 Var guard = s.drawGuard("guard");
	 bool negative = tc.draw("negative", gs::booleans());
	 bool optional = not negative && tc.draw("optional", gs::booleans());
	 Clause clause{guard, Group::Satisfy, optional, negative};

	 auto const solCount = tc.draw("solCount", gs::integers<size_t>({.min_value = 1, .max_value = 3}));
	 for (size_t j = 0; j < solCount; ++j)
	    clause.solutions.push_back(s.drawVar("solution"));

	 clauses.push_back(clause);
	 auto cref = s.AddClause(std::move(clause));
	 // Root-level unit clauses enqueue eagerly and can already conflict;
	 // if so the instance is unsatisfiable, which we verify below.
	 if (guard.empty() && not s.AddWork(TestSolver::Work{cref, 0}))
	    rootConflict = true;
      }

      // Brute-force the expected result over all assignments.
      bool expectedSat = false;
      for (uint32_t mask = 0; mask < (1u << s.varCount()) && not expectedSat; ++mask)
      {
	 auto truth = [&](Var v) { return not v.empty() && ((mask >> (v.value - 1)) & 1); };
	 bool ok = true;
	 for (auto const &clause : clauses)
	 {
	    if (not clause.guard.empty() && not truth(clause.guard))
	       continue; // inactive guarded clause
	    // A positive clause needs one true solution; a negative one
	    // needs all solutions false.
	    bool satisfied = clause.negative;
	    for (auto sol : clause.solutions)
	       if (clause.negative)
		  satisfied = satisfied && not truth(sol);
	       else
		  satisfied = satisfied || truth(sol);
	    if (not satisfied && not clause.optional)
	    {
	       ok = false;
	       break;
	    }
	 }
	 expectedSat = ok;
      }

      // Root-level units already conflicted: the instance must be unsat.
      if (rootConflict)
      {
	 EXPECT_FALSE(expectedSat);
	 _error->Discard();
	 return;
      }

      if (not s.Solve())
      {
	 _error->Discard();
	 EXPECT_FALSE(expectedSat);
	 return;
      }
      EXPECT_TRUE(expectedSat);

      // Every mandatory clause is satisfied in the found assignment.
      for (auto const &clause : clauses)
      {
	 if (clause.optional)
	    continue;
	 if (not clause.guard.empty() && s.value(clause.guard) != LiftedBool::True)
	    continue;
	 bool satisfied = clause.negative;
	 for (auto sol : clause.solutions)
	    if (clause.negative)
	       satisfied = satisfied && s.value(sol) != LiftedBool::True;
	    else
	       satisfied = satisfied || s.value(sol) == LiftedBool::True;
	 EXPECT_TRUE(satisfied);
      }
      _error->Discard(); });
}
} // namespace
