/*
 * fd.h - Move-only, owning file-descriptor abstraction
 *
 * SPDX-License-Identifier: GPL-2.0+
 */
#ifndef APT_CORE_IO_FD_H
#define APT_CORE_IO_FD_H

#include <expected>
#include <system_error>

namespace APT::inline Internal::IO
{

/** \brief A move-only, owning file descriptor.
 *
 * Failures are reported via std::expected with errno-derived
 * std::error_code values; nothing throws.
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

   private:
   int fd = -1;
};

} // namespace APT::inline Internal::IO

#endif