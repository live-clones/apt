#include <config.h>

#include <apt-core/io/fd.h>

#include <cerrno>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>

#include <utility>

namespace APT::inline Internal::IO
{

Fd::Fd(int fd) noexcept : fd(fd) {}

Fd::~Fd()
{
   if (fd >= 0)
      ::close(fd);
}

Fd::Fd(Fd &&other) noexcept : fd(std::exchange(other.fd, -1)) {}

auto Fd::operator=(Fd &&other) noexcept -> Fd &
{
   if (this != &other)
   {
      if (fd >= 0)
	 ::close(fd);
      fd = std::exchange(other.fd, -1);
   }
   return *this;
}

auto Fd::valid() const noexcept -> bool
{
   return fd >= 0;
}

auto Fd::get() const noexcept -> int
{
   return fd;
}

auto Fd::release() noexcept -> int
{
   return std::exchange(fd, -1);
}

auto Fd::close() noexcept -> std::expected<void, std::error_code>
{
   if (fd < 0)
      return {};
   int const closing = std::exchange(fd, -1);
   // For a plain file or socket descriptor, Linux always releases the
   // descriptor even when close() reports EINTR; retrying could close an
   // unrelated descriptor reused by another thread, so treat EINTR as
   // success. Any other failure (e.g. EIO on a pending flush) is reported.
   int const result = ::close(closing);
   int const saved = errno;
   if (result < 0 && saved != EINTR)
      return std::unexpected(std::error_code(saved, std::system_category()));
   return {};
}

// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg)
auto Fd::setNonBlocking() const noexcept -> std::expected<void, std::error_code>
{
   if (fd < 0)
      return std::unexpected(std::error_code(EBADF, std::system_category()));
   int const flags = ::fcntl(fd, F_GETFL);
   int const saved = errno;
   if (flags < 0)
      return std::unexpected(std::error_code(saved, std::system_category()));
   int const result = ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
   int const savedSet = errno;
   if (result < 0)
      return std::unexpected(std::error_code(savedSet, std::system_category()));
   return {};
}

auto Fd::isNonBlocking() const noexcept -> std::expected<bool, std::error_code>
{
   if (fd < 0)
      return std::unexpected(std::error_code(EBADF, std::system_category()));
   int const flags = ::fcntl(fd, F_GETFL);
   int const saved = errno;
   if (flags < 0)
      return std::unexpected(std::error_code(saved, std::system_category()));
   return (flags & O_NONBLOCK) != 0;
}
// NOLINTEND(cppcoreguidelines-pro-type-vararg)

} // namespace APT::Internal::IO