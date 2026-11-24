#include <config.h>

#include <apt-core/io/task.h>

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>

#include "common.h"

namespace {

using APT::Internal::IO::Task;

// Root driver: manually drives a Task's awaiter from non-coroutine code.
// The task's coroutine (and any nested awaits) run to completion inside the
// single resume(), thanks to symmetric transfer.
template <typename T>
auto run(Task<T> task) -> T
{
   auto awaiter = std::move(task).operator co_await();
   EXPECT_FALSE(awaiter.await_ready());
   auto callee = awaiter.await_suspend(std::noop_coroutine());
   callee.resume();
   return awaiter.await_resume();
}

TEST(IOTaskTest, LazyStartsOnlyOnAwait)
{
   bool ran = false;
   auto make = [&]() -> Task<int>
   {
      ran = true;
      co_return 42;
   };
   auto task = make();
   // Lazy: creating the task did not run its body.
   EXPECT_FALSE(ran);
   EXPECT_EQ(run(std::move(task)), 42);
   EXPECT_TRUE(ran);
}

TEST(IOTaskTest, VoidTaskRunsOnAwait)
{
   bool ran = false;
   auto make = [&]() -> Task<void>
   {
      ran = true;
      co_return;
   };
   auto task = make();
   EXPECT_FALSE(ran);
   run(std::move(task));
   EXPECT_TRUE(ran);
}

TEST(IOTaskTest, ValuePropagation)
{
   auto make_string = []() -> Task<std::string>
   {
      std::string s = "hello";
      s += ", task";
      co_return s;
   };
   auto make_pair = []() -> Task<std::pair<int, int>>
   {
      co_return std::pair<int, int>{3, 4};
   };
   EXPECT_EQ(run(make_string()), "hello, task");
   EXPECT_EQ(run(make_pair()), (std::pair<int, int>{3, 4}));
}

TEST(IOTaskTest, NestedAwait)
{
   bool inner_ran = false;
   auto inner = [&]() -> Task<int>
   {
      inner_ran = true;
      co_return 40;
   };
   auto outer = [&]() -> Task<int>
   {
      auto value = co_await inner();
      co_return value + 2;
   };
   EXPECT_FALSE(inner_ran);
   EXPECT_EQ(run(outer()), 42);
   EXPECT_TRUE(inner_ran);
}

// Recursive chain of 100000 nested awaits: verifies symmetric transfer keeps
// the stack flat instead of blowing up with one stack frame per coroutine.
constexpr int ChainDepth = 100000;

auto chain(int depth) -> Task<int>
{
   if (depth <= 0)
      co_return 0;
   co_return 1 + co_await chain(depth - 1);
}

TEST(IOTaskTest, DeepChainDoesNotOverflowStack)
{
   EXPECT_EQ(run(chain(ChainDepth)), ChainDepth);
}

TEST(IOTaskTest, MoveConstructionTransfersOwnership)
{
   auto make = []() -> Task<int>
   {
      co_return 42;
   };
   auto task = make();
   ASSERT_TRUE(static_cast<bool>(task));
   ASSERT_FALSE(task.done());

   Task<int> moved{std::move(task)};
   EXPECT_FALSE(static_cast<bool>(task));
   EXPECT_FALSE(task.done());
   EXPECT_TRUE(static_cast<bool>(moved));
   EXPECT_FALSE(moved.done());
   EXPECT_EQ(run(std::move(moved)), 42);
}

TEST(IOTaskTest, MoveAssignmentDestroysPrevious)
{
   // A by-value parameter is copied/moved into the coroutine frame, so its
   // destructor runs exactly when the frame is destroyed — proving that
   // move-assignment really destroys the old handle's frame, not merely that
   // its body never started. Compilers may elide the temporary into the frame
   // parameter, so the baseline is recorded immediately before the assignment
   // rather than hardcoded.
   struct FrameProbe
   {
      int *destroyed;
      ~FrameProbe() { ++*destroyed; }
   };
   int destroyed = 0;
   bool replaced_ran = false;
   auto make_replaced = [&](FrameProbe probe) -> Task<int>
   {
      (void)probe;
      replaced_ran = true;
      co_return 1;
   };
   auto make_replacement = []() -> Task<int>
   {
      co_return 42;
   };
   Task<int> destination = make_replaced(FrameProbe{&destroyed});
   ASSERT_TRUE(static_cast<bool>(destination));

   int const before = destroyed;
   destination = make_replacement();
   // The frame of the un-awaited, destroyed task was really destroyed.
   EXPECT_EQ(destroyed, before + 1);
   // And its body must never have started.
   EXPECT_FALSE(replaced_ran);
   EXPECT_TRUE(static_cast<bool>(destination));
   EXPECT_EQ(run(std::move(destination)), 42);
}

TEST(IOTaskTest, ReleasedHandleOwnership)
{
   auto make = []() -> Task<int>
   {
      co_return 42;
   };
   Task<int> task = make();
   ASSERT_TRUE(static_cast<bool>(task));

   auto handle = task.release();
   EXPECT_FALSE(static_cast<bool>(task));

   // Drive the released handle manually: start, run to final suspend, take
   // the (moved-out) result exactly once, then destroy the frame.
   handle.resume();
   ASSERT_TRUE(handle.done());
   EXPECT_EQ(handle.promise().result(), 42);
   handle.destroy();
}

TEST(IOTaskTest, DestroyingUnawaitedTaskDoesNotRunIt)
{
   bool ran = false;
   auto make = [&]() -> Task<int>
   {
      ran = true;
      co_return 42;
   };
   {
      auto task = make();
      EXPECT_TRUE(static_cast<bool>(task));
   }
   EXPECT_FALSE(ran);
}

// A throwing body must hit the [[noreturn]] unhandled_exception(), i.e.
// terminate the process. The child reports *why* it died so the expectation
// can distinguish the three failure modes: a propagated exception exits 43,
// no termination at all exits 44, a signal crash is not an exit either —
// only a real std::terminate() (exit 42, installed via set_terminate)
// passes. All child state stays local to the death-test statement; no fatal
// assertions inside it.
constexpr int TerminateExit = 42;
constexpr int PropagatedExit = 43;
constexpr int NoTerminateExit = 44;

TEST(IOTaskTest, ThrowingBodyTerminates)
{
   auto make = []() -> Task<int>
   {
      throw std::runtime_error("boom");
      co_return 0; // unreachable, but required to form a coroutine
   };
   EXPECT_EXIT(
      {
	 std::set_terminate([] { std::_Exit(TerminateExit); });
	 try
	 {
	    run(make());
	 }
	 catch (...)
	 {
	    std::_Exit(PropagatedExit);
	 }
	 std::_Exit(NoTerminateExit);
      },
      ::testing::ExitedWithCode(TerminateExit), "");
}

// A T whose move construction throws makes return_value()'s emplace throw
// from inside the coroutine body, which likewise must terminate.
TEST(IOTaskTest, ThrowingValueConstructionTerminates)
{
   struct ThrowingMove
   {
      ThrowingMove() = default;
      ThrowingMove(ThrowingMove &&) { throw std::runtime_error("boom"); }
      auto operator=(ThrowingMove &&) -> ThrowingMove & = delete;
   };
   auto make = []() -> Task<ThrowingMove>
   {
      ThrowingMove value;
      co_return std::move(value);
   };
   EXPECT_EXIT(
      {
	 std::set_terminate([] { std::_Exit(TerminateExit); });
	 try
	 {
	    run(make());
	 }
	 catch (...)
	 {
	    std::_Exit(PropagatedExit);
	 }
	 std::_Exit(NoTerminateExit);
      },
      ::testing::ExitedWithCode(TerminateExit), "");
}

} // namespace
