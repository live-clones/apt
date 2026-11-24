/*
 * loop.h - Single-threaded poll(2)-based event loop for Task coroutines
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_CORE_IO_LOOP_H
#define APT_CORE_IO_LOOP_H

#include <apt-core/io/task.h>

#include <chrono>
#include <coroutine>
#include <expected>
#include <optional>
#include <system_error>
#include <vector>

// poll.h types used in private helpers; defined only where needed.
struct pollfd;

namespace APT::inline Internal::IO
{

/// \brief Interests a coroutine can wait for on a descriptor.
enum class PollEvents : unsigned
{
   Read = (1U << 0U),
   Write = (1U << 1U),
};

[[nodiscard]] constexpr auto operator|(PollEvents lhs, PollEvents rhs) noexcept -> PollEvents
{
   return static_cast<PollEvents>(static_cast<unsigned>(lhs) | static_cast<unsigned>(rhs));
}

[[nodiscard]] constexpr auto operator&(PollEvents lhs, PollEvents rhs) noexcept -> PollEvents
{
   return static_cast<PollEvents>(static_cast<unsigned>(lhs) & static_cast<unsigned>(rhs));
}

/** \brief Single-threaded poll(2)-based event loop for Task coroutines.
 *
 * The loop drives scheduled Task<void> coroutines whose bodies suspend on
 * poll() awaitables until their descriptors are readable or writable, or
 * on sleep() awaitables until their steady-clock deadline passes.
 * It is single-threaded by contract: all interaction must happen from the
 * thread running the loop. No synchronization is performed.
 *
 * run() returns when there is neither an fd waiter nor a timer left, even
 * if some scheduled root task is still suspended on something the loop
 * cannot observe; such tasks are destroyed (with their destructors run)
 * by ~Loop(). Timed waits use std::chrono::steady_clock.
 */
class [[nodiscard]] Loop
{
   public:
   /// \brief Awaitable suspending until the descriptor is ready. Only Loop::poll() creates one.
   struct WaitFd
   {
      WaitFd() = delete;
      WaitFd(WaitFd const &) = default;
      WaitFd(WaitFd &&) = default;
      auto operator=(WaitFd const &) -> WaitFd & = delete;
      auto operator=(WaitFd &&) -> WaitFd & = delete;
      ~WaitFd() = default;

      // NOLINTNEXTLINE(readability-convert-member-functions-to-static) — awaiter protocol
      [[nodiscard]] auto await_ready() const noexcept -> bool;
      auto await_suspend(std::coroutine_handle<> handle) -> void;
      auto await_resume() const noexcept -> void;

      private:
      friend class Loop;
      WaitFd(Loop &loop, int fd, PollEvents flags) noexcept;
      // Never null: only Loop::poll constructs a WaitFd.
      Loop *loop;
      int fd;
      PollEvents flags;
   };

   /// \brief Awaitable suspending until the steady-clock deadline passes. Only Loop::sleep() creates one.
   struct Sleep
   {
      Sleep() = delete;
      Sleep(Sleep const &) = default;
      Sleep(Sleep &&) = default;
      auto operator=(Sleep const &) -> Sleep & = delete;
      auto operator=(Sleep &&) -> Sleep & = delete;
      ~Sleep() = default;

      [[nodiscard]] auto await_ready() const noexcept -> bool;
      auto await_suspend(std::coroutine_handle<> handle) -> void;
      auto await_resume() const noexcept -> void;

      private:
      friend class Loop;
      Sleep(Loop &loop, std::chrono::steady_clock::time_point deadline) noexcept;
      // Never null: only Loop::sleep constructs a Sleep.
      Loop *loop;
      std::chrono::steady_clock::time_point deadline;
   };

   Loop() noexcept = default;
   ~Loop();

   Loop(Loop const &) = delete;
   auto operator=(Loop const &) -> Loop & = delete;
   Loop(Loop &&) = delete;
   auto operator=(Loop &&) -> Loop & = delete;

   /// \brief Takes ownership of the task, resumes it, and destroys its frame when it completes.
   auto schedule(Task<void> task) -> void;

   /// \brief Drives the loop until there is nothing left to wait for.
   [[nodiscard]] auto run() -> std::expected<void, std::error_code>;

   /// \brief Awaitable: suspends until `fd` is ready for `flags`.
   ///
   /// Assumes a non-blocking descriptor; readiness is level-triggered.
   [[nodiscard]] auto poll(int fd, PollEvents flags) -> WaitFd
   {
      return WaitFd{*this, fd, flags};
   }

   /// \brief Awaitable: suspends until the steady-clock deadline passes.
   ///
   /// A non-positive duration never suspends (await_ready() is true). The
   /// deadline is saturated at the clock maximum so absurd durations cannot
   /// overflow the time point.
   [[nodiscard]] auto sleep(std::chrono::nanoseconds duration) -> Sleep
   {
      auto const now = std::chrono::steady_clock::now();
      auto const delta = std::chrono::duration_cast<std::chrono::steady_clock::duration>(duration);
      auto const maxDelta = std::chrono::steady_clock::time_point::max() - now;
      auto const deadline = delta >= maxDelta ? std::chrono::steady_clock::time_point::max() : now + delta;
      return Sleep{*this, deadline};
   }

   private:
   struct Waiter
   {
      std::coroutine_handle<> handle;
      int fd;
      PollEvents flags;

      Waiter(std::coroutine_handle<> handle, int fd, PollEvents flags) noexcept : handle(handle), fd(fd), flags(flags) {}
   };

   struct Timer
   {
      std::coroutine_handle<> handle;
      std::chrono::steady_clock::time_point deadline;

      Timer(std::coroutine_handle<> handle, std::chrono::steady_clock::time_point deadline) noexcept : handle(handle), deadline(deadline) {}
   };

   [[nodiscard]] static auto toPollEvents(PollEvents flags) noexcept -> short;
   [[nodiscard]] static auto toTimespec(std::chrono::steady_clock::time_point deadline) noexcept -> struct ::timespec;
   [[nodiscard]] auto nearestDeadline() const noexcept -> std::optional<std::chrono::steady_clock::time_point>;
   auto collectDueTimers(std::vector<std::coroutine_handle<>> &due, std::vector<Timer> &pending) -> void;
   auto dispatchReady(std::vector<struct ::pollfd> const &pollfds) -> void;
   auto reapOwned() -> void;

   std::vector<Waiter> waiters;
   std::vector<Timer> timers;
   std::vector<std::coroutine_handle<>> owned;
};

} // namespace APT::inline Internal::IO

#endif