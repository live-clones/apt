/*
 * task.h - Lazy, single-consumer C++23 coroutine Task<T> with symmetric transfer
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_CORE_IO_TASK_H
#define APT_CORE_IO_TASK_H

#include <cassert>
#include <concepts>
#include <coroutine>
#include <exception>
#include <optional>
#include <type_traits>
#include <utility>

namespace APT::inline Internal::IO
{

/** \brief A lazy, move-only, single-consumer C++23 coroutine task.
 *
 * Execution starts only when awaited (as an rvalue) or driven by an event loop.
 * A Task must be non-empty when awaited and may only be awaited once.
 * Supports symmetric transfer to avoid recursion blowup on deep coroutine chains.
 *
 * We generally do not support exceptions, preferring std::terminate instead.
 */
template <typename T = void>
class [[nodiscard]] Task
{
   struct final_awaiter
   {
      [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }

      template <typename Promise>
      auto await_suspend(std::coroutine_handle<Promise> h) noexcept -> std::coroutine_handle<>
      {
	 // return the callers handle for symmetric continuation
	 if (auto continuation = h.promise().continuation)
	    return continuation;
	 // this is a root task, we are done
	 return std::noop_coroutine();
      }

      auto await_resume() const noexcept -> void {}
   };
   struct promise_base
   {
      std::coroutine_handle<> continuation;
      [[noreturn]] auto unhandled_exception() const noexcept -> void { std::terminate(); }
      // std::suspend_always -> task starts suspended
      [[nodiscard]] auto initial_suspend() const noexcept -> std::suspend_always { return {}; }
      [[nodiscard]] auto final_suspend() const noexcept -> final_awaiter { return {}; }
   };

   public:
   struct promise_type final : promise_base
   {
      auto get_return_object() noexcept -> Task
      {
	 return Task{std::coroutine_handle<promise_type>::from_promise(*this)};
      }

      template <typename U>
      requires std::convertible_to<U, T>
      auto return_value(U &&val) noexcept(std::is_nothrow_constructible_v<T, U>) -> void
      {
	 value.emplace(std::forward<U>(val));
      }

      auto result() noexcept(std::is_nothrow_move_constructible_v<T>) -> T
      {
	 return std::move(*value);
      }

      private:
      std::optional<T> value;
   };

   using handle_type = std::coroutine_handle<promise_type>;

   private:
   handle_type handle = nullptr;

   explicit Task(handle_type h) noexcept : handle(h) {}

   public:
   Task() noexcept = default;
   ~Task()
   {
      if (handle)
	 handle.destroy();
   }

   Task(Task &&other) noexcept : handle(std::exchange(other.handle, nullptr)) {}
   auto operator=(Task &&other) noexcept -> Task &
   {
      if (this != &other)
      {
	 if (handle)
	    handle.destroy();
	 handle = std::exchange(other.handle, nullptr);
      }
      return *this;
   }

   Task(const Task &) = delete;
   auto operator=(const Task &) -> Task & = delete;

   [[nodiscard]] explicit operator bool() const noexcept { return handle != nullptr; }
   [[nodiscard]] auto done() const noexcept -> bool { return handle && handle.done(); }

   /// \brief Release ownership of the underlying coroutine handle.
   /// \warning Remember to call destroy() on the handle; final suspension leaves frame alive
   [[nodiscard]] auto release() noexcept -> handle_type
   {
      return std::exchange(handle, nullptr);
   }

   struct Awaiter
   {
      handle_type callee;

      [[nodiscard]] auto await_ready() const noexcept -> bool
      {
	 return callee.done();
      }

      auto await_suspend(std::coroutine_handle<> caller) noexcept -> std::coroutine_handle<>
      {
	 callee.promise().continuation = caller;
	 return callee;
      }

      auto await_resume() noexcept(noexcept(callee.promise().result())) -> T
      {
	 return callee.promise().result();
      }
   };

   /// \brief Consume and await the task (rvalue-only to enforce single consumption).
   auto operator co_await() && noexcept -> Awaiter
   {
      return Awaiter{handle};
   }
};

template <>
struct Task<void>::promise_type final : Task<void>::promise_base
{
   auto get_return_object() noexcept -> Task<void>
   {
      return Task<void>{std::coroutine_handle<promise_type>::from_promise(*this)};
   }

   auto return_void() const noexcept -> void {}
   auto result() const noexcept -> void {}
};

} // namespace APT::inline Internal::IO

#endif
