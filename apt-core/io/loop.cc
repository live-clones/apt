#include <config.h>

#include <apt-core/io/loop.h>

#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <ctime>
#include <optional>
#include <algorithm>
#include <system_error>
#include <utility>

namespace APT::inline Internal::IO
{

Loop::~Loop()
{
   // Drop registered waiters, many-waiters and timers first so cancelled
   // roots leave no dangling entries or spans, then destroy every
   // remaining owned root frame.
   waiters.clear();
   manyWaiters.clear();
   timers.clear();
   for (auto handle : owned)
      handle.destroy();
   owned.clear();
}

auto Loop::schedule(Task<void> task) -> void
{
   auto handle = task.release();
   if (!handle)
      return;
   owned.push_back(handle);
   // Start the root coroutine. If it runs to completion immediately, its
   // frame is at final suspension; destroy it now and drop it from owned.
   handle.resume();
   if (handle.done())
   {
      handle.destroy();
      for (auto it = owned.begin(); it != owned.end(); ++it)
      {
	 if (*it == handle)
	 {
	    *it = owned.back();
	    owned.pop_back();
	    break;
	 }
      }
   }
}

Loop::WaitFd::WaitFd(Loop &loop, int fd, PollEvents flags) noexcept : loop(&loop), fd(fd), flags(flags) {}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static) — awaiter protocol
auto Loop::WaitFd::await_ready() const noexcept -> bool
{
   return false; // always suspend
}

auto Loop::WaitFd::await_suspend(std::coroutine_handle<> handle) -> void
{
   loop->waiters.emplace_back(handle, fd, flags);
}

auto Loop::WaitFd::await_resume() const noexcept -> void {}

Loop::ManyWaitFd::ManyWaitFd(Loop &loop, std::span<pollfd> pollfds) noexcept : loop(&loop), pollfds(pollfds) {}

auto Loop::ManyWaitFd::await_ready() const noexcept -> bool
{
   // An empty poll set can never become ready; complete instead of
   // deadlocking.
   return pollfds.empty();
}

auto Loop::ManyWaitFd::await_suspend(std::coroutine_handle<> handle) -> void
{
   loop->manyWaiters.emplace_back(handle, pollfds);
}

auto Loop::ManyWaitFd::await_resume() const noexcept -> void {}
Loop::Sleep::Sleep(Loop &loop, std::chrono::steady_clock::time_point deadline) noexcept : loop(&loop), deadline(deadline) {}

auto Loop::Sleep::await_ready() const noexcept -> bool
{
   return deadline <= std::chrono::steady_clock::now(); // never suspends when already due
}

auto Loop::Sleep::await_suspend(std::coroutine_handle<> handle) -> void
{
   loop->timers.emplace_back(handle, deadline);
}

auto Loop::Sleep::await_resume() const noexcept -> void {}

auto Loop::toPollEvents(PollEvents flags) noexcept -> short
{
   auto const bits = static_cast<unsigned>(flags);
   short events = 0;
   if ((bits & static_cast<unsigned>(PollEvents::Read)) != 0)
      events |= POLLIN;
   if ((bits & static_cast<unsigned>(PollEvents::Write)) != 0)
      events |= POLLOUT;
   return events;
}

// Clamp for absurd deadlines: converting a steady-clock time_point
// remaining-time to nanoseconds can overflow time_t for far-future
// deadlines; 24 hours is far beyond any plausible event-loop wait, so
// clamping loses nothing while keeping the timespec well-defined.
constexpr auto MaxTimeout = std::chrono::hours{24};

auto Loop::toTimespec(std::chrono::steady_clock::time_point deadline) noexcept -> struct ::timespec
{
   auto const now = std::chrono::steady_clock::now();
   if (deadline <= now)
      return ::timespec{.tv_sec = 0, .tv_nsec = 0};
   // Clamp the native steady-clock duration before converting to
   // nanoseconds — the cast itself can overflow for far-future deadlines.
   auto remaining = deadline - now;
   if (remaining > MaxTimeout)
      remaining = MaxTimeout;
   auto const ns = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining);
   auto const seconds = std::chrono::duration_cast<std::chrono::seconds>(ns);
   return ::timespec{.tv_sec = seconds.count(), .tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(ns - seconds).count()};
}

// Collect the due timers and remove them from the list before resuming
// anything: resuming can register new timers and must not invalidate the
// collection step. The due handles are stably ordered by deadline so
// equal deadlines keep registration order.
auto Loop::collectDueTimers(std::vector<std::coroutine_handle<>> &due, std::vector<Timer> &pending) -> void
{
   auto const now = std::chrono::steady_clock::now();
   due.clear();
   pending.clear();
   std::vector<Timer> expired;
   for (auto const &timer : timers)
   {
      if (timer.deadline <= now)
	 expired.push_back(timer);
      else
	 pending.push_back(timer);
   }
   std::ranges::stable_sort(expired, [](Timer const &lhs, Timer const &rhs)
   {
      return lhs.deadline < rhs.deadline;
   });
   for (auto const &timer : expired)
      due.push_back(timer.handle);
   timers.swap(pending);
}

auto Loop::nearestDeadline() const noexcept -> std::optional<std::chrono::steady_clock::time_point>
{
   std::optional<std::chrono::steady_clock::time_point> result;
   for (auto const &timer : timers)
   {
      if (!result || timer.deadline < *result)
	 result = timer.deadline;
   }
   return result;
}

auto Loop::dispatchReady(std::vector<struct ::pollfd> const &pollfds) -> void
{
   // Collect the ready handles and update both waiter lists before
   // resuming anything: resuming can register new waiters and must not
   // invalidate the collection step. Alignment: the flat poll array
   // holds the single waiters' entries first, then each many-waiter's
   // entries in registration order — the same order the lists are
   // walked here, so a sequential iterator cannot drift.
   std::vector<std::coroutine_handle<>> ready;
   std::vector<Waiter> remainingWaiters;
   std::vector<ManyWaiter> remainingMany;
   auto result = pollfds.begin();

   for (auto const &waiter : waiters)
   {
      // poll conveys no status, so the awaiting coroutine must be
      // resumed on error/hangup conditions to observe them itself (this
      // is what makes EOF — read() returning 0 — work).
      short const revents = (result++)->revents;
      bool const isError = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
      bool const wanted = (revents & toPollEvents(waiter.flags)) != 0;
      if (isError || wanted)
	 ready.push_back(waiter.handle);
      else
	 remainingWaiters.push_back(waiter);
   }
   waiters.swap(remainingWaiters);

   for (auto const &waiter : manyWaiters)
   {
      bool any = false;
      for (auto &entry : waiter.pollfds)
      {
	 // Write revents back for every entry; not-ready ones get an
	 // explicit zero so stale caller values cannot masquerade as
	 // readiness.
	 entry.revents = (result++)->revents;
	 if (entry.revents != 0)
	    any = true;
      }
      if (any)
	 ready.push_back(waiter.handle);
      else
	 remainingMany.push_back(waiter);
   }
   manyWaiters.swap(remainingMany);

   for (auto handle : ready)
      handle.resume();
   reapOwned();
}

auto Loop::reapOwned() -> void
{
   // Resumed waiters are mid-coroutine frames owned by their creating
   // coroutines (or root frames owned here); the loop never destroys a
   // waiter handle. Root frames that reached final suspension are
   // destroyed exactly once; suspended (not-done) roots stay owned.
   for (auto it = owned.begin(); it != owned.end();)
   {
      if (it->done())
      {
	 it->destroy();
	 it = owned.erase(it);
      }
      else
      {
	 ++it;
      }
   }
}

auto Loop::run() -> std::expected<void, std::error_code>
{
   std::vector<struct ::pollfd> pollfds;
   std::vector<std::coroutine_handle<>> due;
   std::vector<Timer> pending;
   while (!waiters.empty() || !manyWaiters.empty() || !timers.empty())
   {
      // Every iteration resumes timers whose deadline has passed, whether
      // or not ppoll reported readiness; collectDueTimers() updates the
      // timer list first so resuming cannot invalidate it.
      collectDueTimers(due, pending);
      for (auto handle : due)
	 handle.resume();
      // Timers can complete root tasks too.
      reapOwned();

      if (waiters.empty() && manyWaiters.empty() && timers.empty())
	 break;

      // Rebuild one flat poll array from the current waiters: single
      // waiters' entries first, then each many-waiter's entries (copied
      // with revents = 0 so stale caller values can never leak into the
      // syscall). It may legitimately be empty — ppoll(nullptr, 0,
      // &timeout, ...) is a valid sleep for the timer-only case.
      pollfds.clear();
      pollfds.reserve(waiters.size());
      for (auto const &waiter : waiters)
	 pollfds.push_back(::pollfd{.fd = waiter.fd, .events = toPollEvents(waiter.flags), .revents = 0});
      for (auto const &waiter : manyWaiters)
      {
	 pollfds.reserve(pollfds.size() + waiter.pollfds.size());
	 for (auto const &entry : waiter.pollfds)
	    pollfds.push_back(::pollfd{.fd = entry.fd, .events = entry.events, .revents = 0});
      }

      // Wait with a timeout derived from the nearest timer deadline (null
      // when there are none); the clamp in toTimespec avoids overflow for
      // absurd durations. After collectDueTimers() the nearest pending
      // deadline is strictly in the future, so the timeout is strictly
      // positive and this cannot spin.
      auto const nearest = nearestDeadline();
      ::timespec const *timeout = nullptr;
      ::timespec storage{};
      if (nearest)
      {
	 storage = toTimespec(*nearest);
	 timeout = &storage;
      }

      int const count = ::ppoll(pollfds.data(), pollfds.size(), timeout, nullptr);
      int const saved = errno;
      if (count < 0)
      {
	 if (saved == EINTR)
	    continue;
	 return std::unexpected(std::error_code(saved, std::system_category()));
      }
      if (count == 0)
      {
	 // Pure timeout: the deadline that produced it has (or is about to
	 // have) passed; loop back to collect and resume the due timers.
	 continue;
      }

      dispatchReady(pollfds);
   }
   return {};
}

} // namespace APT::inline Internal::IO
