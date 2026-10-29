/*
 * solver_test.cc - Unit tests for the SAT solver core
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <config.h>

#include <apt-pkg/error.h>
#include <apt-pkg/solver.h>

#include <string>

#include "common.h"

namespace
{
using namespace APT::Solver;

// \brief A minimal solver implementation to test the cache-independent core.
class TestSolver : public Solver
{
   public:
   using Solver::bestReason;
   using Solver::newVar;
   using Solver::Propagate;
   using Solver::states;
   using Solver::value;
   using Solver::Work;

   void Discover(Var) override {}

   // \brief Register a clause into the watchers, like DependencySolver::RegisterClause does.
   CRef AddClause(Clause &&clause)
   {
      Clause copy{clause};
      CRef cref = newClause(std::move(clause));
      StoredClause &inserted = clauses[cref];

      EXPECT_EQ(ClauseHeader{copy}, ClauseHeader{inserted});
      EXPECT_TRUE(std::ranges::equal(copy.solutions, inserted.solutions()));
      return cref;
   }
};

TEST(SolverTest, RootAndNewVars)
{
   TestSolver s;
   EXPECT_EQ(s.value(Var{}), LiftedBool::True);
   auto a = s.newVar();
   auto b = s.newVar();
   EXPECT_NE(a, b);
   EXPECT_FALSE(a.empty());
   EXPECT_EQ(s.value(a), LiftedBool::Undefined);
   EXPECT_EQ(s.value(b), LiftedBool::Undefined);
}

TEST(SolverTest, Watches)
{
   TestSolver s;
   auto a = s.newVar();

   auto &watches = s.states[a].watches;
   watches.add(CRef{1}, false);
   watches.add(CRef{2}, true);
   watches.add(CRef{3}, false);
   watches.add(CRef{4}, true);

   {
      // Positive watchers keep their insertion order.
      auto const positive = watches.get(false);
      ASSERT_EQ(positive.size(), 2);
      EXPECT_EQ(positive[0], CRef{1});
      EXPECT_EQ(positive[1], CRef{3});

      // Negative watches are in the right order
      auto const negative = watches.get(true);
      ASSERT_EQ(negative.size(), 2);
      EXPECT_EQ(negative[0], CRef{2});
      EXPECT_EQ(negative[1], CRef{4});
   }

   {
      // Inserting a positive watcher at the end rotates the negative group:
      // the first negative watcher is swapped out to the end of the vector.
      watches.add(CRef{5}, false);

      // Positive watchers keep their insertion order.
      auto const positive = watches.get(false);
      ASSERT_EQ(positive.size(), 3);
      EXPECT_EQ(positive[0], CRef{1});
      EXPECT_EQ(positive[1], CRef{3});
      EXPECT_EQ(positive[2], CRef{5});

      // The negative group rotated [2, 4] -> [4, 2].
      auto const negative = watches.get(true);
      ASSERT_EQ(negative.size(), 2);
      EXPECT_EQ(negative[0], CRef{4});
      EXPECT_EQ(negative[1], CRef{2});
   }
}

TEST(SolverTest, UnitPropagation)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause clause{a, Group::Satisfy};
   clause.solutions = {b};
   s.AddClause(std::move(clause));

   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::True);
}

TEST(SolverTest, Conflict)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause clause{a, Group::Satisfy};
   clause.solutions = {b};
   s.AddClause(std::move(clause));

   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Enqueue(~b));
   EXPECT_FALSE(s.Propagate());
   _error->Discard();
}

TEST(SolverTest, NegativeClause)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   // a -> none of b, c
   Clause clause{a, Group::Satisfy, false, true};
   clause.solutions = {b, c};
   s.AddClause(std::move(clause));

   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::False);
}

TEST(SolverTest, Contrapositive)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   Clause clause{a, Group::Satisfy};
   clause.solutions = {b, c};
   s.AddClause(std::move(clause));

   // With all solutions rejected and the guard undecided, the guard is
   // rejected by contraposition.
   EXPECT_TRUE(s.Enqueue(~b));
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(a), LiftedBool::Undefined);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::Undefined);
   EXPECT_TRUE(s.Enqueue(~c));
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(a), LiftedBool::False);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::False);
}

TEST(SolverTest, OptionalClause)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   Clause clause{a, Group::Satisfy, true};
   clause.solutions = {b, c};
   s.AddClause(std::move(clause));

   // An optional clause does not unit-propagate its last solution, but
   // queues it as work for Solve() which selects c.
   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Enqueue(~b));
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::Undefined);

   EXPECT_TRUE(s.Solve());
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::True);

   // Backtracking rejects the soft choice, and with it requeued, Solve()
   // drops the unsolvable work item, leaving the guard alone.
   EXPECT_TRUE(s.Pop());
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::False);
   EXPECT_TRUE(s.Solve());
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::False);
   EXPECT_EQ(s.value(c), LiftedBool::False);
}

TEST(SolverTest, SolveChoice)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause clause{Var{}, Group::Satisfy};
   clause.solutions = {a, b};
   auto inserted = s.AddClause(std::move(clause));

   EXPECT_TRUE(s.AddWork(TestSolver::Work{inserted, 0}));
   EXPECT_TRUE(s.Solve());
   // The first solution is tried first and nothing rejects it.
   EXPECT_EQ(s.value(a), LiftedBool::True);
   EXPECT_EQ(s.value(b), LiftedBool::Undefined);
}

TEST(SolverTest, SolveBacktracks)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   Clause choice{Var{}, Group::Satisfy};
   choice.solutions = {a, b};
   auto inserted = s.AddClause(std::move(choice));

   // a -> c, but c was rejected, so choosing a must fail and be backtracked
   Clause dep{a, Group::Satisfy};
   dep.solutions = {c};
   s.AddClause(std::move(dep));

   EXPECT_TRUE(s.AddWork(TestSolver::Work{inserted, 0}));
   EXPECT_TRUE(s.Enqueue(~c));
   EXPECT_TRUE(s.Solve());
   EXPECT_EQ(s.value(a), LiftedBool::False);
   EXPECT_EQ(s.value(b), LiftedBool::True);
   EXPECT_EQ(s.value(c), LiftedBool::False);
}

TEST(SolverTest, Unsatisfiable)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause unit{Var{}, Group::Satisfy};
   unit.solutions = {a};
   auto inserted = s.AddClause(std::move(unit));

   Clause dep{a, Group::Satisfy};
   dep.solutions = {b};
   s.AddClause(std::move(dep));

   EXPECT_TRUE(s.AddWork(TestSolver::Work{inserted, 0}));
   EXPECT_TRUE(s.Enqueue(~b));
   EXPECT_FALSE(s.Solve());
   _error->Discard();
}

TEST(SolverTest, RenderVariables)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   EXPECT_EQ(s.toString(Var{}), "x0");
   EXPECT_EQ(s.toString(a), "x1");
   EXPECT_EQ(s.toString(b), "x2");
   EXPECT_EQ(s.toString(Lit(a)), "x1");
   EXPECT_EQ(s.toString(~a), "~x1");
   EXPECT_EQ(s.toString(~b), "~x2");
}

TEST(SolverTest, RenderClauses)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   // A positive clause A -> B | C is rendered as the CNF ~xA | xB | xC
   Clause clause{a, Group::Satisfy};
   clause.solutions = {b, c};
   EXPECT_EQ(s.toString(clause), "~x1 | x2 | x3");

   // A negative clause negates its solutions
   Clause negative{a, Group::Satisfy, false, true};
   negative.solutions = {b};
   EXPECT_EQ(s.toString(negative), "~x1 | ~x2");

   // A clause rooted at the (true) root simplifies to its solutions
   Clause rooted{Var{}, Group::Satisfy};
   rooted.solutions = {a, b};
   EXPECT_EQ(s.toString(rooted), "x1 | x2");

   // An optional work item is rendered with its size and level
   Clause optional{Var{}, Group::Satisfy, true};
   optional.solutions = {a};
   auto inserted = s.AddClause(std::move(optional));
   EXPECT_EQ(s.toString(TestSolver::Work{inserted, 0}), "Optional Item (0@0) x1");
}

TEST(SolverTest, BestReason)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   // Without a clause, there is no reason
   EXPECT_TRUE(s.bestReason(nullptr, a).empty());

   // If the variable is not the clause's guard, the guard is the reason
   Clause pos{b, Group::Satisfy};
   pos.solutions = {c};
   auto posC = s.AddClause(std::move(pos));
   EXPECT_EQ(s.bestReason(posC, a), b);

   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Enqueue(~c));

   // A positive clause is contradicted by its false solution
   EXPECT_EQ(s.bestReason(posC, b), c);

   // Without a false solution, the guard itself remains the reason
   Clause pos2{b, Group::Satisfy};
   pos2.solutions = {a};
   auto pos2C = s.AddClause(std::move(pos2));
   EXPECT_EQ(s.bestReason(pos2C, b), b);

   // A negative clause is contradicted by its true solution
   Clause neg{b, Group::Satisfy, false, true};
   neg.solutions = {a, c};
   auto negC = s.AddClause(std::move(neg));
   EXPECT_EQ(s.bestReason(negC, b), a);

   // Without a true solution, the guard itself remains the reason
   Clause neg2{b, Group::Satisfy, false, true};
   neg2.solutions = {c};
   auto neg2C = s.AddClause(std::move(neg2));
   EXPECT_EQ(s.bestReason(neg2C, b), b);
}

TEST(SolverTest, LiteralBitMagic)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   // A literal stores the variable shifted left by one, with the sign in the lowest bit
   EXPECT_EQ(Lit(a).var(), a);
   EXPECT_FALSE(Lit(a).sign());
   EXPECT_EQ(Lit(a, true).var(), a);
   EXPECT_TRUE(Lit(a, true).sign());

   // Negation flips exactly the sign bit and is an involution
   EXPECT_EQ(~a, Lit(a, true));
   EXPECT_EQ(~~a, Lit(a));
   EXPECT_EQ((~a).var(), a);
   EXPECT_TRUE((~a).sign());
   EXPECT_NE(~a, Lit(a));
   EXPECT_NE(~a, ~b);
   EXPECT_EQ(~~b, Lit(b));

   // Even the root variable has distinct positive and negative literals
   EXPECT_NE(~Var{}, Lit(Var{}));
   EXPECT_TRUE((~Var{}).sign());
}

TEST(SolverTest, LiftedBoolBitMagic)
{
   // Negation swaps the two bits: Undefined stays, True and False are exchanged
   EXPECT_EQ(~LiftedBool::Undefined, LiftedBool::Undefined);
   EXPECT_EQ(~LiftedBool::True, LiftedBool::False);
   EXPECT_EQ(~LiftedBool::False, LiftedBool::True);
   EXPECT_EQ(~~LiftedBool::True, LiftedBool::True);
   EXPECT_EQ(~~LiftedBool::False, LiftedBool::False);
}

TEST(SolverTest, SoftReason)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar(), c = s.newVar();

   // a -> b
   Clause dep{a, Group::Satisfy};
   dep.solutions = {b};
   auto depC = s.AddClause(std::move(dep));

   // A choice clause to use as the assumption's reason
   Clause choice{Var{}, Group::Satisfy};
   choice.solutions = {a, c};
   auto choiceC = s.AddClause(std::move(choice));

   // An assumption records a soft reason: kept for rendering the implication
   // graph, but not available to conflict analysis.
   EXPECT_TRUE(s.Assume(a, choiceC));
   EXPECT_TRUE(s.states[a].flags.soft_reason);
   EXPECT_EQ(s.states[a].reason, choiceC);
   EXPECT_EQ(s.states[a].hardReason(), nullptr);
   EXPECT_EQ(s.WhyStr(a), "x1");

   // A propagated assignment records a hard reason.
   EXPECT_TRUE(s.Propagate());
   EXPECT_EQ(s.value(b), LiftedBool::True);
   EXPECT_FALSE(s.states[b].flags.soft_reason);
   EXPECT_EQ(s.states[b].reason, depC);
   EXPECT_EQ(s.states[b].hardReason(), depC);

   // Backtracking clears the soft reason again.
   EXPECT_TRUE(s.Pop());
   EXPECT_EQ(s.value(a), LiftedBool::False);
   EXPECT_FALSE(s.states[a].flags.soft_reason);
}

TEST(SolverTest, RenderSelection)
{
   TestSolver s;
   auto a = s.newVar();

   EXPECT_EQ(s.DescribeSelection(a, true), "x1 is selected for install");
   EXPECT_EQ(s.DescribeSelection(a, false), "x1 is not selected for install");
}

TEST(SolverTest, RenderReasons)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause clause{a, Group::Satisfy};
   clause.solutions = {b};
   s.AddClause(std::move(clause));

   EXPECT_TRUE(s.Enqueue(a));
   EXPECT_TRUE(s.Propagate());

   // b was installed because of a
   EXPECT_EQ(s.WhyStr(b), "x1 -> x2");

   std::unordered_set<Var> seen;
   auto longWhy = s.LongWhyStr(b, true, s.states[b].reason, "", seen);
   EXPECT_NE(longWhy.find("x2 is selected for install because"), std::string::npos);
   EXPECT_NE(longWhy.find("~x1 | x2"), std::string::npos);
}

TEST(SolverTest, WorkLessStrictWeakOrdering)
{
   TestSolver s;

   // Generate every clause/work combination that affects workLess.
   std::vector<CRef> clauses;
   for (auto optional : {false, true})
      for (auto eager : {false, true})
	 for (auto group : {Group::Satisfy, Group::SelectVersion})
	    for (size_t solCount = 0; solCount <= 2; ++solCount)
	    {
	       Clause clause{Var{}, group, optional};
	       clause.eager = eager;
	       for (size_t i = 0; i < solCount; ++i)
		  clause.solutions.push_back(s.newVar());
	       clauses.push_back(s.AddClause(std::move(clause)));
	    }

   // Sizes 0, 1, 2 are the only values that affect ordering.
   std::vector<TestSolver::Work> items;
   for (auto cref : clauses)
      for (uint32_t size = 0; size <= 2; ++size)
      {
	 TestSolver::Work w{cref, 0};
	 w.size = size;
	 items.push_back(w);
      }

   auto equivalent = [&](TestSolver::Work const &x, TestSolver::Work const &y)
   {
      return not s.workLess(x, y) && not s.workLess(y, x);
   };

   for (size_t i = 0; i < items.size(); ++i)
   {
      // Irreflexivity
      EXPECT_FALSE(s.workLess(items[i], items[i]));

      for (size_t j = 0; j < items.size(); ++j)
      {
	 // Antisymmetry
	 EXPECT_FALSE(s.workLess(items[i], items[j]) && s.workLess(items[j], items[i]));

	 for (size_t k = 0; k < items.size(); ++k)
	 {
	    // Transitivity (<= is implication for booleans).
	    EXPECT_TRUE((s.workLess(items[i], items[j]) && s.workLess(items[j], items[k])) <= s.workLess(items[i], items[k]));

	    // Equivalence transitivity
	    EXPECT_TRUE((equivalent(items[i], items[j]) && equivalent(items[j], items[k])) <= equivalent(items[i], items[k]));
	 }
      }
   }
}
} // namespace
