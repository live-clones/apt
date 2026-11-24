#include <config.h>

#include <apt-core/io/loop.h>

#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>
#include <utility>

namespace APT::inline Internal::IO
{

Loop::~Loop()
{
   // Drop registered waiters first so cancelled roots leave no dangling
   // entries, then destroy every remaining owned root frame.
   waiters.clear();
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

Loop::WaitFd::WaitFd(Loop &loop, int fd, WaitFlags flags) noexcept : loop(&loop), fd(fd), flags(flags) {}

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

// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg)
auto Loop::toPollEvents(WaitFlags flags) noexcept -> short
{
   auto const bits = static_cast<unsigned>(flags);
   short events = 0;
   if ((bits & static_cast<unsigned>(WaitFlags::Read)) != 0)
      events |= POLLIN;
   if ((bits & static_cast<unsigned>(WaitFlags::Write)) != 0)
      events |= POLLOUT;
   return events;
}

auto Loop::run() -> std::expected<void, std::error_code>
{
   std::vector<struct ::pollfd> pollfds;
   std::vector<std::coroutine_handle<>> ready;
   std::vector<Waiter> remaining;
   while (!waiters.empty())
   {
      // Rebuild the poll array from the current waiters, then wait.
      pollfds.clear();
      pollfds.reserve(waiters.size());
      for (auto const &waiter : waiters)
	 pollfds.push_back(::pollfd{.fd = waiter.fd, .events = toPollEvents(waiter.flags), .revents = 0});

      int const count = ::ppoll(pollfds.data(), pollfds.size(), nullptr, nullptr);
      int const saved = errno;
      if (count < 0)
      {
	 if (saved == EINTR)
	    continue;
	 return std::unexpected(std::error_code(saved, std::system_category()));
      }
      if (count == 0)
	 continue;

      // Collect the ready handles and update the waiter list before resuming
      // anything: resuming can register new waiters and must not invalidate
      // the collection step.
      ready.clear();
      ready.reserve(waiters.size());
      remaining.clear();
      auto pollfd = pollfds.begin();
      for (auto const &waiter : waiters)
      {
	 // waitfd conveys no status, so the awaiting coroutine must be
	 // resumed on error/hangup conditions to observe them itself (this
	 // is what makes EOF — read() returning 0 — work).
	 short const revents = pollfd->revents;
	 ++pollfd;
	 bool const isError = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
	 bool const wanted = (revents & toPollEvents(waiter.flags)) != 0;
	 if (isError || wanted)
	    ready.push_back(waiter.handle);
	 else
	    remaining.push_back(waiter);
      }
      waiters.swap(remaining);

      for (auto handle : ready)
	 handle.resume();
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
   return {};
}
// NOLINTEND(cppcoreguidelines-pro-type-vararg)

} // namespace APT::inline Internal::IO