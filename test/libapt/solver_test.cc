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
   using Solver::analyze;
   using Solver::bestReason;
   using Solver::calcReason;
   using Solver::newVar;
   using Solver::Propagate;
   using Solver::seen;
   using Solver::seenLits;
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

TEST(SolverTest, AnalyzeChain)
{
   TestSolver s;
   auto d = s.newVar(), a = s.newVar(), b = s.newVar(), x = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{a, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{b, Group::Satisfy};
   c3.solutions = {x};
   auto c3r = s.AddClause(std::move(c3));

   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(x, c3r));

   // b conflicts with x (b -> none of x), so ~b | ~x is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~b, ~x}, learnt, backjump);

   // b is the first UIP: resolving ~b | ~x with b's reason ~b | x yields ~b.
   EXPECT_EQ(learnt, std::vector<Lit>{~b});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeFirstUIP)
{
   TestSolver s;
   auto d = s.newVar(), a = s.newVar(), b = s.newVar(), c = s.newVar(), x = s.newVar(), y = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{a, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{a, Group::Satisfy};
   c3.solutions = {c};
   auto c3r = s.AddClause(std::move(c3));
   Clause c4{b, Group::Satisfy};
   c4.solutions = {x};
   auto c4r = s.AddClause(std::move(c4));
   Clause c5{c, Group::Satisfy};
   c5.solutions = {y};
   auto c5r = s.AddClause(std::move(c5));

   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(c, c3r));
   EXPECT_TRUE(s.Enqueue(x, c4r));
   EXPECT_TRUE(s.Enqueue(y, c5r));

   // The graph reconverges on a: d -> a -> {b -> x, c -> y}; ~x | ~y is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~x, ~y}, learnt, backjump);

   // a is the first UIP: resolution stops there rather than at the decision d.
   EXPECT_EQ(learnt, std::vector<Lit>{~a});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeDecisionUIP)
{
   TestSolver s;
   auto d = s.newVar(), a = s.newVar(), b = s.newVar(), x = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{d, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{a, Group::Satisfy};
   c3.solutions = {x};
   auto c3r = s.AddClause(std::move(c3));

   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(x, c3r));

   // b conflicts with x (b -> none of x): two independent paths from d to
   // the conflict, so ~b | ~x is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~b, ~x}, learnt, backjump);

   // No interior UIP: the learnt clause is the negation of the decision.
   EXPECT_EQ(learnt, std::vector<Lit>{~d});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeBackjump)
{
   TestSolver s;
   auto d1 = s.newVar(), a = s.newVar(), b = s.newVar(), x = s.newVar(), d2 = s.newVar();

   Clause c1{d1, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{a, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{b, Group::Satisfy};
   c3.solutions = {x};
   auto c3r = s.AddClause(std::move(c3));

   // Level 1: d1 -> a -> b -> x
   EXPECT_TRUE(s.Assume(d1));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(x, c3r));
   // Level 2: d2 conflicts with x (d2 -> none of x), so ~d2 | ~x is falsified.
   EXPECT_TRUE(s.Assume(d2));

   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~d2, ~x}, learnt, backjump);

   // d2 is the UIP; x remains as the lower-level literal to backjump to.
   EXPECT_EQ(learnt, std::vector<Lit>({~d2, ~x}));
   EXPECT_EQ(backjump, 1u);
}

TEST(SolverTest, AnalyzeBackjumpMax)
{
   TestSolver s;
   auto d1 = s.newVar(), a = s.newVar(), d2 = s.newVar(), b = s.newVar(), d3 = s.newVar(), g = s.newVar();

   Clause n1{d1, Group::Satisfy, false, true};
   n1.solutions = {a};
   auto n1r = s.AddClause(std::move(n1));
   Clause n2{d2, Group::Satisfy, false, true};
   n2.solutions = {b};
   auto n2r = s.AddClause(std::move(n2));
   Clause c3{d3, Group::Satisfy};
   c3.solutions = {g};
   auto c3r = s.AddClause(std::move(c3));

   // Level 1: d1 rejects a; level 2: d2 rejects b; level 3: d3 -> g.
   EXPECT_TRUE(s.Assume(d1));
   EXPECT_TRUE(s.Enqueue(~a, n1r));
   EXPECT_TRUE(s.Assume(d2));
   EXPECT_TRUE(s.Enqueue(~b, n2r));
   EXPECT_TRUE(s.Assume(d3));
   EXPECT_TRUE(s.Enqueue(g, c3r));

   // g -> a | b is conflicting: a and b are both rejected at levels 1 and 2.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~g, a, b}, learnt, backjump);

   // Backjump to the higher level of the two rejected solutions.
   EXPECT_EQ(learnt, std::vector<Lit>({~g, a, b}));
   EXPECT_EQ(backjump, 2u);
}

TEST(SolverTest, AnalyzeReasonPullsLowerLevel)
{
   TestSolver s;
   auto l1 = s.newVar(), z = s.newVar(), d = s.newVar(), a = s.newVar(), b = s.newVar(), c = s.newVar();

   Clause n1{l1, Group::Satisfy, false, true};
   n1.solutions = {z};
   auto n1r = s.AddClause(std::move(n1));
   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{a, Group::Satisfy};
   c2.solutions = {b, z};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{b, Group::Satisfy};
   c3.solutions = {c};
   auto c3r = s.AddClause(std::move(c3));

   // Level 1: l1 rejects z; level 2: d -> a -> b (z is rejected, so a -> b | z
   // is unit) -> c.
   EXPECT_TRUE(s.Assume(l1));
   EXPECT_TRUE(s.Enqueue(~z, n1r));
   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(c, c3r));

   // a conflicts with c, so ~a | ~c is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~a, ~c}, learnt, backjump);

   // a is the first UIP; resolving b pulls in z from level 1 mid-resolution.
   EXPECT_EQ(learnt, std::vector<Lit>({~a, Lit(z)}));
   EXPECT_EQ(backjump, 1u);
}

TEST(SolverTest, AnalyzeDiamond)
{
   TestSolver s;
   auto d = s.newVar(), a = s.newVar(), b = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{d, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));

   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));

   // a conflicts with b, so ~a | ~b is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~a, ~b}, learnt, backjump);

   // Resolving both branches pulls in ~d twice; the seen flag must prevent
   // double counting such that the resolution stops at the decision.
   EXPECT_EQ(learnt, std::vector<Lit>{~d});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeSoftReason)
{
   TestSolver s;
   auto g = s.newVar(), c = s.newVar(), d = s.newVar(), e = s.newVar(), x = s.newVar();

   Clause cg{g, Group::Satisfy};
   cg.solutions = {c};
   auto cgr = s.AddClause(std::move(cg));
   // The (optional) work item the assumption below was made for: c -> d | e
   Clause work{c, Group::Satisfy, true /* optional */};
   work.solutions = {d, e};
   auto workr = s.AddClause(std::move(work));
   Clause c2{d, Group::Satisfy};
   c2.solutions = {x};
   auto c2r = s.AddClause(std::move(c2));

   EXPECT_TRUE(s.Assume(g));
   EXPECT_TRUE(s.Enqueue(c, cgr));
   // The assumption records the work clause as a soft reason.
   EXPECT_TRUE(s.Assume(d, workr));
   EXPECT_TRUE(s.Enqueue(x, c2r));

   // x conflicts with d (x -> none of d), so ~x | ~d is falsified.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~x, ~d}, learnt, backjump);

   // Resolution stops at the assumption d: its soft reason is not available,
   // so ~c (at level 1) must not enter the learnt clause.
   EXPECT_EQ(learnt, std::vector<Lit>{~d});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeNegativeReason)
{
   TestSolver s;
   auto sv = s.newVar(), g = s.newVar(), x = s.newVar();

   // g is rejected because s is installed: g -> none of s
   Clause n{g, Group::Satisfy, false, true};
   n.solutions = {sv};
   auto nr = s.AddClause(std::move(n));
   Clause c2{sv, Group::Satisfy};
   c2.solutions = {x};
   auto c2r = s.AddClause(std::move(c2));

   EXPECT_TRUE(s.Assume(sv));
   EXPECT_TRUE(s.Enqueue(~g, nr));
   EXPECT_TRUE(s.Enqueue(x, c2r));

   // The conflict clause g | ~x is falsified: g is rejected and x is installed.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({Lit(g), ~x}, learnt, backjump);

   // Resolving with the binary reason ~g | ~s of the rejected guard yields ~s.
   EXPECT_EQ(learnt, std::vector<Lit>{~sv});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeNegativeUIP)
{
   TestSolver s;
   auto a = s.newVar(), x = s.newVar();

   // Root clause x | a; with a rejected it implies x.
   Clause c2{Var{}, Group::Satisfy};
   c2.solutions = {x, a};
   auto c2r = s.AddClause(std::move(c2));

   EXPECT_TRUE(s.Assume(~a));
   EXPECT_TRUE(s.Enqueue(x, c2r));

   // The conflict clause a | ~x is falsified: a is rejected, x installed.
   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({Lit(a), ~x}, learnt, backjump);

   // The first UIP is ~a: resolving a | ~x with x's reason x | a yields a.
   EXPECT_EQ(learnt, std::vector<Lit>{Lit(a)});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeSkipsLevel0)
{
   TestSolver s;
   auto f = s.newVar(), d = s.newVar(), x = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {x};
   auto c1r = s.AddClause(std::move(c1));

   // A fact at level 0, e.g. a user request.
   EXPECT_TRUE(s.Enqueue(f));
   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(x, c1r));

   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~x, ~f}, learnt, backjump);

   // Literals assigned at level 0 do not participate in the analysis.
   EXPECT_EQ(learnt, std::vector<Lit>{~x});
   EXPECT_EQ(backjump, 0u);
}

TEST(SolverTest, AnalyzeSeenInspectable)
{
   TestSolver s;
   auto d = s.newVar(), a = s.newVar(), b = s.newVar(), x = s.newVar();

   Clause c1{d, Group::Satisfy};
   c1.solutions = {a};
   auto c1r = s.AddClause(std::move(c1));
   Clause c2{a, Group::Satisfy};
   c2.solutions = {b};
   auto c2r = s.AddClause(std::move(c2));
   Clause c3{b, Group::Satisfy};
   c3.solutions = {x};
   auto c3r = s.AddClause(std::move(c3));

   EXPECT_TRUE(s.Assume(d));
   EXPECT_TRUE(s.Enqueue(a, c1r));
   EXPECT_TRUE(s.Enqueue(b, c2r));
   EXPECT_TRUE(s.Enqueue(x, c3r));

   unsigned int backjump = 0;
   std::vector<Lit> learnt;
   s.analyze({~b, ~x}, learnt, backjump);

   // The seen flags of the analysis remain available for inspection until
   // the next analysis.
   EXPECT_EQ(s.seenLits, std::vector<Var>({b, x}));
   EXPECT_TRUE(s.seen[b]);
   EXPECT_TRUE(s.seen[x]);
   EXPECT_FALSE(s.seen[a]);

   // The next analysis clears them first.
   std::vector<Lit> learnt2;
   s.analyze({~b}, learnt2, backjump);
   EXPECT_EQ(s.seenLits, std::vector<Var>({b}));
   EXPECT_FALSE(s.seen[x]);
}

TEST(SolverTest, CalcReasonPositive)
{
   TestSolver s;
   auto g = s.newVar(), a = s.newVar(), b = s.newVar();

   Clause c{g, Group::Satisfy};
   c.solutions = {a, b};
   auto cr = s.AddClause(std::move(c));

   std::vector<Lit> lits;
   s.calcReason(cr, Lit(a), lits);

   // a was implied because the guard is installed and the other solution is
   // rejected; the reason is the true assignment literals.
   EXPECT_EQ(lits, std::vector<Lit>({Lit(g), ~b}));
}

TEST(SolverTest, CalcReasonPositiveImpliedGuard)
{
   TestSolver s;
   auto g = s.newVar(), a = s.newVar(), b = s.newVar();

   Clause c{g, Group::Satisfy};
   c.solutions = {a, b};
   auto cr = s.AddClause(std::move(c));

   std::vector<Lit> lits;
   s.calcReason(cr, ~g, lits);

   // The guard was rejected because all solutions are rejected.
   EXPECT_EQ(lits, std::vector<Lit>({~a, ~b}));
}

TEST(SolverTest, CalcReasonPositiveRootGuard)
{
   TestSolver s;
   auto a = s.newVar(), b = s.newVar();

   Clause c{Var{}, Group::Satisfy};
   c.solutions = {a, b};
   auto cr = s.AddClause(std::move(c));

   std::vector<Lit> lits;
   s.calcReason(cr, Lit(a), lits);

   // The (always true) root guard is elided.
   EXPECT_EQ(lits, std::vector<Lit>({~b}));
}

TEST(SolverTest, CalcReasonNegativeSolution)
{
   TestSolver s;
   auto g = s.newVar(), a = s.newVar();

   Clause n{g, Group::Satisfy, false, true};
   n.solutions = {a};
   auto nr = s.AddClause(std::move(n));

   std::vector<Lit> lits;
   s.calcReason(nr, ~a, lits);

   // The solution was rejected because the guard is installed.
   EXPECT_EQ(lits, std::vector<Lit>({Lit(g)}));
}

TEST(SolverTest, CalcReasonNegativeGuard)
{
   TestSolver s;
   auto g = s.newVar(), a = s.newVar(), b = s.newVar(), c = s.newVar();

   Clause n{g, Group::Satisfy, false, true};
   n.solutions = {a, b, c};
   auto nr = s.AddClause(std::move(n));

   // a is rejected; c was installed before b.
   EXPECT_TRUE(s.Enqueue(~a));
   EXPECT_TRUE(s.Enqueue(c));
   EXPECT_TRUE(s.Enqueue(b));

   std::vector<Lit> lits;
   s.calcReason(nr, ~g, lits);

   // The guard was rejected because a solution is installed; the earliest
   // installed solution in trail order (c, not the preference-earlier b) is
   // the antecedent.
   EXPECT_EQ(lits, std::vector<Lit>({Lit(c)}));
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
