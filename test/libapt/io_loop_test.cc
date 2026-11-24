#include <config.h>

#include <apt-core/io/fd.h>
#include <apt-core/io/loop.h>
#include <apt-core/io/task.h>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <utility>
#include <vector>

#include "common.h"

namespace {

using APT::Internal::IO::Fd;
using APT::Internal::IO::Loop;
using APT::Internal::IO::Task;
using APT::Internal::IO::PollEvents;

// RAII probe living in a coroutine frame: its destructor observes frame
// destruction. Moves are not counted: only real destructions matter.
struct FrameProbe
{
   int *destroyed;
   explicit FrameProbe(int *destroyed) noexcept : destroyed(destroyed) {}
   FrameProbe(FrameProbe const &) = default;
   FrameProbe(FrameProbe &&other) noexcept : destroyed(std::exchange(other.destroyed, nullptr)) {}
   auto operator=(FrameProbe const &) -> FrameProbe & = default;
   auto operator=(FrameProbe &&) -> FrameProbe & = default;
   ~FrameProbe()
   {
      if (destroyed != nullptr)
	 ++*destroyed;
   }
};

struct Pipe
{
   Fd readEnd;
   Fd writeEnd;

   Pipe() : readEnd(), writeEnd()
   {
      int fds[2] = {-1, -1};
      if (::pipe(fds) == 0)
      {
	 readEnd = Fd{fds[0]};
	 writeEnd = Fd{fds[1]};
      }
   }
   ~Pipe()
   {
      // Let the Fd members close their descriptors exactly once.
   }
};

TEST(IoLoopTest, FreshLoopRunReturnsSuccess)
{
   Loop loop;
   EXPECT_TRUE(loop.run().has_value());
}

TEST(IoLoopTest, ReadWaitResumesAfterData)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_TRUE(pipe.writeEnd.valid());

   bool resumed = false;
   auto reader = [&](int fd) -> Task<void>
   {
      co_await loop.poll(fd, PollEvents::Read);
      resumed = true;
   };
   loop.schedule(reader(pipe.readEnd.get()));
   EXPECT_FALSE(resumed);

   // Blocking write end of an empty pipe is always writable, but readiness
   // is only observed by run(); run() must not return while a waiter remains.
   char const byte = 'x';
   ASSERT_EQ(::write(pipe.writeEnd.get(), &byte, 1), 1);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(resumed);
}

TEST(IoLoopTest, WriteWaitResumesOnEmptyPipe)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.writeEnd.valid());

   bool resumed = false;
   auto writer = [&](int fd) -> Task<void>
   {
      co_await loop.poll(fd, PollEvents::Write);
      resumed = true;
   };
   loop.schedule(writer(pipe.writeEnd.get()));
   EXPECT_FALSE(resumed);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(resumed);
}

TEST(IoLoopTest, TwoTasksBothResumeInOneRun)
{
   Loop loop;
   Pipe first;
   Pipe second;
   ASSERT_TRUE(first.readEnd.valid());
   ASSERT_TRUE(second.readEnd.valid());

   int resumed = 0;
   auto waitOn = [&](int fd) -> Task<void>
   {
      co_await loop.poll(fd, PollEvents::Read);
      ++resumed;
   };
   loop.schedule(waitOn(first.readEnd.get()));
   loop.schedule(waitOn(second.readEnd.get()));
   ASSERT_EQ(resumed, 0);

   char const byte = 'x';
   ASSERT_EQ(::write(first.writeEnd.get(), &byte, 1), 1);
   ASSERT_EQ(::write(second.writeEnd.get(), &byte, 1), 1);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_EQ(resumed, 2);
}

TEST(IoLoopTest, CombinedReadAndPollEventsAccepted)
{
   Loop loop;
   // A connected socketpair send buffer is empty (POLLIN not ready) but
   // has room to send (POLLOUT ready), so Read|Write is satisfiable and
   // proves OR semantics: one ready interest resumes the awaiter.
   int fds[2] = {-1, -1};
   ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
   Fd ours{fds[0]};
   Fd theirs{fds[1]};
   ASSERT_TRUE(ours.valid());

   bool resumed = false;
   auto task = [&](int fd) -> Task<void>
   {
      co_await loop.poll(fd, PollEvents::Read | PollEvents::Write);
      resumed = true;
   };
   loop.schedule(task(ours.get()));
   EXPECT_FALSE(resumed);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(resumed);
}

TEST(IoLoopTest, ScheduleTakesOwnership)
{
   int destroyed = 0;
   {
      Loop loop;
      auto make = [&](int fd) -> Task<void>
      {
	 FrameProbe probe{&destroyed};
	 (void)probe;
	 co_await loop.poll(fd, PollEvents::Read);
	 // Suspends; ownership now belongs to the loop.
      };
      Pipe pipe;
      ASSERT_TRUE(pipe.readEnd.valid());

      {
	 auto task = make(pipe.readEnd.get());
	 ASSERT_TRUE(static_cast<bool>(task));
	 loop.schedule(std::move(task));
	 // The loop took the handle; the source Task is empty and its
	 // destructor must not double-destroy the frame.
	 EXPECT_FALSE(static_cast<bool>(task));
      }
      EXPECT_EQ(destroyed, 0);
   }
   // ~Loop destroyed the suspended root frame; its FrameProbe ran.
   EXPECT_EQ(destroyed, 1);
}

TEST(IoLoopTest, CompletingTaskFrameDestroyedAfterSchedule)
{
   // A by-value FrameProbe parameter is moved into the coroutine frame and
   // destroyed only when the frame is destroyed — proving the frame, not
   // merely the body local, was released by schedule(). Moves are free
   // (uncounted), so exactly one counted destruction is expected here.
   int destroyed = 0;
   Loop loop;
   auto make = [](FrameProbe probe) -> Task<void>
   {
      (void)probe;
      co_return;
   };
   FrameProbe probe{&destroyed};
   int const before = destroyed;
   loop.schedule(make(std::move(probe)));
   EXPECT_EQ(destroyed, before + 1);
}

TEST(IoLoopTest, HangupResumesWaiter)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_TRUE(pipe.writeEnd.valid());

   bool resumed = false;
   auto reader = [&](int fd) -> Task<void>
   {
      co_await loop.poll(fd, PollEvents::Read);
      resumed = true;
   };
   loop.schedule(reader(pipe.readEnd.get()));
   EXPECT_FALSE(resumed);

   // Close the write end with no data: poll reports POLLHUP on the read
   // end, which run() must treat as readiness so the coroutine can observe
   // the condition itself.
   EXPECT_TRUE(pipe.writeEnd.close().has_value());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(resumed);
}

TEST(IoLoopTest, DestructorDestroysSuspendedRoot)
{
   int destroyed = 0;
   {
      Loop loop;
      Pipe pipe;
      ASSERT_TRUE(pipe.readEnd.valid());
      int *observer = &destroyed;
      auto make = [&]() -> Task<void>
      {
	 FrameProbe probe{observer};
	 (void)probe;
	 // Root suspends on a descriptor nobody will make readable.
	 co_await loop.poll(pipe.readEnd.get(), PollEvents::Read);
      };
      loop.schedule(make());
      EXPECT_EQ(destroyed, 0);
   }
   // ~Loop cleared the waiters, then destroyed the suspended root frame,
   // running its destructors; no dangling waiter, no crash.
   EXPECT_EQ(destroyed, 1);
}

TEST(IoLoopTest, SleepResumesAfterDuration)
{
   Loop loop;
   bool ran = false;
   auto sleeper = [&]() -> Task<void>
   {
      co_await loop.sleep(std::chrono::nanoseconds{std::chrono::milliseconds{5}});
      ran = true;
   };
   // Record the start before schedule(): the deadline is created (relative
   // to now) during schedule(), so only a pre-schedule start bounds it.
   auto const start = std::chrono::steady_clock::now();
   loop.schedule(sleeper());
   EXPECT_FALSE(ran);
   EXPECT_TRUE(loop.run().has_value());
   auto const elapsed = std::chrono::steady_clock::now() - start;
   EXPECT_TRUE(ran);
   // Only a lower bound: scheduling may overshoot but never undershoot.
   EXPECT_GE(elapsed, std::chrono::milliseconds{5});
}

TEST(IoLoopTest, SleepZeroDoesNotSuspend)
{
   Loop loop;
   bool ran = false;
   auto sleeper = [&]() -> Task<void>
   {
      co_await loop.sleep(std::chrono::nanoseconds{0});
      ran = true;
   };
   loop.schedule(sleeper());
   // Completed during schedule(): await_ready() returned true, no timer.
   EXPECT_TRUE(ran);
   EXPECT_TRUE(loop.run().has_value());
}

TEST(IoLoopTest, SleepOrderingPreserved)
{
   Loop loop;
   std::vector<int> order;
   auto sleeper = [&](int tag, std::chrono::nanoseconds duration) -> Task<void>
   {
      co_await loop.sleep(duration);
      order.push_back(tag);
   };
   loop.schedule(sleeper(1, std::chrono::milliseconds{30}));
   loop.schedule(sleeper(2, std::chrono::milliseconds{5}));
   EXPECT_TRUE(order.empty());
   EXPECT_TRUE(loop.run().has_value());
   // collectDueTimers() stably orders due handles by deadline, so the
   // 5 ms timer resumes before the 30 ms one regardless of registration
   // order; equal deadlines would keep registration order.
   EXPECT_EQ(order, (std::vector<int>{2, 1}));
}

TEST(IoLoopTest, TimerAndFdInterleave)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   bool fdRan = false;
   bool timerRan = false;
   auto reader = [&]() -> Task<void>
   {
      co_await loop.poll(pipe.readEnd.get(), PollEvents::Read);
      fdRan = true;
   };
   auto sleeper = [&]() -> Task<void>
   {
      co_await loop.sleep(std::chrono::milliseconds{50});
      timerRan = true;
   };
   char const byte = 'x';
   ASSERT_EQ(::write(pipe.writeEnd.get(), &byte, 1), 1);
   auto const start = std::chrono::steady_clock::now();
   loop.schedule(reader());
   loop.schedule(sleeper());
   EXPECT_TRUE(loop.run().has_value());
   // Both complete in a single run(); no relative order between them is
   // asserted (a late run() can legitimately make the timer due first).
   EXPECT_TRUE(fdRan);
   EXPECT_TRUE(timerRan);
   // The fd task observed its data.
   char got = 0;
   ASSERT_EQ(::read(pipe.readEnd.get(), &got, 1), 1);
   EXPECT_EQ(got, byte);
   // Lower bound only: the timer's 50 ms elapsed within the run.
   EXPECT_GE(std::chrono::steady_clock::now() - start, std::chrono::milliseconds{50});
}

TEST(IoLoopTest, RunReturnsAfterLastTimer)
{
   Loop loop;
   bool ran = false;
   auto sleeper = [&]() -> Task<void>
   {
      co_await loop.sleep(std::chrono::milliseconds{5});
      ran = true;
   };
   loop.schedule(sleeper());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(ran);
}

TEST(IoLoopTest, DestructorCancelsPendingTimer)
{
   int destroyed = 0;
   {
      Loop loop;
      int *observer = &destroyed;
      auto make = [&]() -> Task<void>
      {
	 FrameProbe probe{observer};
	 (void)probe;
	 // Root suspends on a timer that never fires within this scope.
	 co_await loop.sleep(std::chrono::hours{1});
      };
      loop.schedule(make());
      EXPECT_EQ(destroyed, 0);
   }
   // ~Loop cleared the timers, then destroyed the suspended root frame,
   // running its destructors; no dangling timer, no crash.
   EXPECT_EQ(destroyed, 1);
}

} // namespace