/*
 * loop.h - Single-threaded poll(2)-based event loop for Task coroutines
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_CORE_IO_LOOP_H
#define APT_CORE_IO_LOOP_H

#include <apt-core/io/task.h>

#include <coroutine>
#include <expected>
#include <system_error>
#include <vector>

namespace APT::inline Internal::IO
{

/// \brief Interests a coroutine can wait for on a descriptor.
enum class WaitFlags : unsigned
{
   Read = (1U << 0U),
   Write = (1U << 1U),
};

[[nodiscard]] constexpr auto operator|(WaitFlags lhs, WaitFlags rhs) noexcept -> WaitFlags
{
   return static_cast<WaitFlags>(static_cast<unsigned>(lhs) | static_cast<unsigned>(rhs));
}

[[nodiscard]] constexpr auto operator&(WaitFlags lhs, WaitFlags rhs) noexcept -> WaitFlags
{
   return static_cast<WaitFlags>(static_cast<unsigned>(lhs) & static_cast<unsigned>(rhs));
}

/** \brief Single-threaded poll(2)-based event loop for Task coroutines.
 *
 * The loop drives scheduled Task<void> coroutines whose bodies suspend on
 * waitfd() awaitables until their descriptors are readable or writable.
 * It is single-threaded by contract: all interaction must happen from the
 * thread running the loop. No synchronization is performed.
 *
 * run() returns when no waiters remain, even if some scheduled root task is
 * still suspended on something the loop cannot observe; such tasks are
 * destroyed (with their destructors run) by ~Loop().
 */
class [[nodiscard]] Loop
{
   public:
   /// \brief Awaitable suspending until the descriptor is ready. Only Loop::waitfd() creates one.
   struct WaitFd
   {
      WaitFd() = delete;
      WaitFd(WaitFd const &) = default;
      WaitFd(WaitFd &&) = default;
      auto operator=(WaitFd const &) -> WaitFd & = delete;
      auto operator=(WaitFd &&) -> WaitFd & = delete;
      ~WaitFd() = default;

      [[nodiscard]] static auto await_ready() noexcept -> bool;
      auto await_suspend(std::coroutine_handle<> handle) -> void;
      auto await_resume() const noexcept -> void;

      private:
      friend class Loop;
      WaitFd(Loop &loop, int fd, WaitFlags flags) noexcept;
      // Never null: only Loop::waitfd constructs a WaitFd.
      Loop *loop;
      int fd;
      WaitFlags flags;
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
   [[nodiscard]] auto waitfd(int fd, WaitFlags flags) -> WaitFd
   {
      return WaitFd{*this, fd, flags};
   }

   private:
   struct Waiter
   {
      std::coroutine_handle<> handle;
      int fd;
      WaitFlags flags;

      Waiter(std::coroutine_handle<> handle, int fd, WaitFlags flags) noexcept : handle(handle), fd(fd), flags(flags) {}
   };

   [[nodiscard]] static auto toPollEvents(WaitFlags flags) noexcept -> short;

   std::vector<Waiter> waiters;
   std::vector<std::coroutine_handle<>> owned;
};

} // namespace APT::inline Internal::IO

#endif