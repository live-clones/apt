/*
 * fd.h - Move-only, owning file-descriptor abstraction
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_CORE_IO_FD_H
#define APT_CORE_IO_FD_H

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <apt-core/io/task.h>

namespace APT::inline Internal::IO
{

class Loop;

/** \brief A move-only, owning file descriptor.
 *
 * Failures are reported via std::expected with errno-derived
 * std::error_code values; nothing throws except allocation failure
 * (readUntil allocates a std::string and can throw std::bad_alloc).
 *
 * The coroutine read()/write()/writeAll()/readUntil() methods assume a
 * non-blocking descriptor and never block the loop thread; EAGAIN is
 * turned into an await on Loop::poll().
 *
 * Lifetime contract: the Loop and this Fd must outlive the returned
 * Task; the referenced buffer/scratch/delimiter data must remain valid
 * and must not be concurrently mutated or reallocated while the task is
 * pending. readUntil() copies its delimiter view, so it may point into
 * scratch.
 */
class [[nodiscard]] Fd
{
   public:
   Fd() noexcept = default;

   /// \brief Takes ownership of the given descriptor; a negative value means empty.
   explicit Fd(int fd) noexcept;

   /// \brief Closes the descriptor if one is owned; errors are not reported.
   ~Fd();

   Fd(Fd &&other) noexcept;
   auto operator=(Fd &&other) noexcept -> Fd &;

   Fd(Fd const &) = delete;
   auto operator=(Fd const &) -> Fd & = delete;

   [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
   [[nodiscard]] auto valid() const noexcept -> bool;
   [[nodiscard]] auto get() const noexcept -> int;

   /// \brief Gives up ownership and returns the descriptor, leaving this Fd empty.
   [[nodiscard]] auto release() noexcept -> int;

   /// \brief Closes the descriptor if one is owned. Idempotent: closing an empty Fd succeeds.
   [[nodiscard]] auto close() noexcept -> std::expected<void, std::error_code>;

   [[nodiscard]] auto setNonBlocking() const noexcept -> std::expected<void, std::error_code>;
   [[nodiscard]] auto isNonBlocking() const noexcept -> std::expected<bool, std::error_code>;

   /// \brief Reads once the descriptor has data; assumes a non-blocking descriptor.
   ///
   /// EINTR is retried, EAGAIN awaits readability on the loop. Returns the
   /// number of bytes read; 0 means EOF, short reads are returned as-is.
   [[nodiscard]] auto read(Loop &loop, std::span<char> buffer) const -> Task<std::expected<std::size_t, std::error_code>>;

   /// \brief Writes once the descriptor accepts data; assumes a non-blocking descriptor.
   ///
   /// EINTR is retried, EAGAIN awaits writability on the loop. Returns the
   /// number of bytes written; short writes are returned as-is.
   [[nodiscard]] auto write(Loop &loop, std::span<char const> buffer) const -> Task<std::expected<std::size_t, std::error_code>>;

   /// \brief Writes the whole buffer, awaiting writability between short writes.
   ///
   /// Assumes a non-blocking descriptor. An empty buffer succeeds without any syscall.
   [[nodiscard]] auto writeAll(Loop &loop, std::span<char const> buffer) const -> Task<std::expected<void, std::error_code>>;

   /// \brief Reads from `scratch` (a caller-owned reusable buffer) until `delimiter` appears.
   ///
   /// Returns the record including the delimiter and erases it from `scratch`
   /// (without syscalls if it is already there). On EOF the remaining bytes are
   /// returned as the final record and `scratch` is cleared (an empty remainder
   /// yields an empty string, not an error). A record never containing the
   /// delimiter grows `scratch` until EOF; that is the caller's chosen policy.
   /// The delimiter view is copied up front, so it may point into `scratch`.
   [[nodiscard]] auto readUntil(Loop &loop, std::string &scratch, std::string_view delimiter) const -> Task<std::expected<std::string, std::error_code>>;

   private:
   int fd = -1;
};

} // namespace APT::inline Internal::IO

#endif