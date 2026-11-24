#include <config.h>

#include <apt-core/io/fd.h>

#include <apt-core/io/loop.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <system_error>
#include <utility>

namespace APT::inline Internal::IO
{

namespace
{

// One ::read, retrying EINTR. Any other failure is reported; the caller
// decides whether an EAGAIN is worth awaiting.
[[nodiscard]] auto readOnce(int fd, std::span<char> buffer) -> std::expected<std::size_t, std::error_code>
{
   while (true)
   {
      auto const count = ::read(fd, buffer.data(), buffer.size());
      int const saved = errno;
      if (count >= 0)
	 return static_cast<std::size_t>(count);
      if (saved != EINTR)
	 return std::unexpected(std::error_code(saved, std::system_category()));
   }
}

// One ::write, retrying EINTR. Any other failure is reported.
[[nodiscard]] auto writeOnce(int fd, std::span<char const> buffer) -> std::expected<std::size_t, std::error_code>
{
   while (true)
   {
      auto const count = ::write(fd, buffer.data(), buffer.size());
      int const saved = errno;
      if (count >= 0)
	 return static_cast<std::size_t>(count);
      if (saved != EINTR)
	 return std::unexpected(std::error_code(saved, std::system_category()));
   }
}

} // namespace

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

// NOLINTBEGIN(cppcoreguidelines-avoid-reference-coroutine-parameters)
// The reference parameters are the approved API: the loop must outlive the
// task (it is the object driving it), and scratch/delimiter are caller-owned
// by contract.
auto Fd::read(Loop &loop, std::span<char> buffer) const -> Task<std::expected<std::size_t, std::error_code>>
{
   while (true)
   {
      auto const once = readOnce(fd, buffer);
      if (once.has_value())
	 co_return once;
      auto const error = once.error();
      // EAGAIN on a non-blocking descriptor: wait for readability, retry.
      if (error == std::errc::resource_unavailable_try_again)
      {
	 co_await loop.poll(fd, PollEvents::Read);
	 continue;
      }
      co_return std::unexpected(error);
   }
}

auto Fd::write(Loop &loop, std::span<char const> buffer) const -> Task<std::expected<std::size_t, std::error_code>>
{
   while (true)
   {
      auto const once = writeOnce(fd, buffer);
      if (once.has_value())
	 co_return once;
      auto const error = once.error();
      // EAGAIN on a non-blocking descriptor: wait for writability, retry.
      if (error == std::errc::resource_unavailable_try_again)
      {
	 co_await loop.poll(fd, PollEvents::Write);
	 continue;
      }
      co_return std::unexpected(error);
   }
}

auto Fd::writeAll(Loop &loop, std::span<char const> buffer) const -> Task<std::expected<void, std::error_code>>
{
   // An empty buffer succeeds without any syscall.
   while (!buffer.empty())
   {
      auto const written = co_await write(loop, buffer);
      if (!written.has_value())
	 co_return std::unexpected(written.error());
      // Defensive: a non-empty write that reports no progress would loop
      // forever; pipes and files normally error rather than return 0 here,
      // but unusual descriptor types exist.
      if (*written == 0)
	 co_return std::unexpected(std::make_error_code(std::errc::io_error));
      buffer = buffer.subspan(*written);
   }
   co_return std::expected<void, std::error_code>{};
}

// Size of a single readUntil() read chunk; records larger than this grow
// `scratch` across multiple reads.
constexpr std::size_t ReadChunkSize = 4096;

auto Fd::readUntil(Loop &loop, std::string &scratch, std::string_view delimiter) const -> Task<std::expected<std::string, std::error_code>>
{
   // Copy the delimiter into the coroutine frame: a view into scratch would
   // dangle when scratch reallocates during append.
   std::string const needle{delimiter};
   std::array<char, ReadChunkSize> chunk{};
   // Search position: a delimiter straddling the boundary of previously
   // scanned bytes is still found by rewinding needle.size() - 1 bytes.
   std::size_t searchFrom = 0;
   while (true)
   {
      // Delimiter already in scratch: extract the record without syscalls.
      if (auto const position = scratch.find(needle, searchFrom); position != std::string::npos)
      {
	 auto record = scratch.substr(0, position + needle.size());
	 // Leftover bytes were shifted to the front; a next call starts over.
	 scratch.erase(0, position + needle.size());
	 co_return record;
      }
      searchFrom = scratch.size() >= needle.size() ? scratch.size() - needle.size() + 1 : 0;
      auto const count = co_await read(loop, std::span<char>(chunk));
      if (!count.has_value())
	 co_return std::unexpected(count.error());
      if (*count == 0)
      {
	 // EOF: the remaining bytes are the final record (possibly empty).
	 auto record = std::move(scratch);
	 scratch.clear();
	 co_return record;
      }
      scratch.append(chunk.data(), *count);
   }
}
// NOLINTEND(cppcoreguidelines-avoid-reference-coroutine-parameters)

} // namespace APT::Internal::IO