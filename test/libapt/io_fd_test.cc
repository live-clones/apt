#include <config.h>

#include <apt-core/io/fd.h>
#include <apt-core/io/loop.h>
#include <apt-core/io/task.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "common.h"

namespace {

using APT::Internal::IO::Fd;
using APT::Internal::IO::Loop;
using APT::Internal::IO::Task;
using APT::Internal::IO::WaitFlags;

// Creates a fresh descriptor on an unlinked temp file; no temp files left behind.
auto freshFd() -> int
{
   auto const directory = std::filesystem::temp_directory_path();
   auto name = (directory / "io_fd_test_XXXXXX").string();
   int const fd = ::mkstemp(name.data());
   if (fd >= 0)
      ::unlink(name.c_str());
   return fd;
}

// Returns true iff the descriptor is open (no cheap fcntl-free probe exists).
auto isOpen(int fd) -> bool
{
   return ::fcntl(fd, F_GETFD) != -1;
}

TEST(IoFdTest, DefaultConstructedIsEmpty)
{
   Fd fd;
   EXPECT_FALSE(fd.valid());
   EXPECT_FALSE(static_cast<bool>(fd));
   EXPECT_EQ(fd.get(), -1);
}

TEST(IoFdTest, AdoptingFdClosesOnDestruction)
{
   int raw = freshFd();
   ASSERT_GE(raw, 0);

   {
      Fd fd{raw};
      EXPECT_TRUE(fd.valid());
      EXPECT_TRUE(static_cast<bool>(fd));
      EXPECT_EQ(fd.get(), raw);
   }
   // The destructor closed exactly the adopted descriptor.
   errno = 0;
   EXPECT_EQ(::fcntl(raw, F_GETFD), -1);
   EXPECT_EQ(errno, EBADF);
}

TEST(IoFdTest, ExplicitCloseIsIdempotent)
{
   Fd fd{freshFd()};
   ASSERT_TRUE(fd.valid());

   EXPECT_TRUE(fd.close().has_value());
   EXPECT_FALSE(fd.valid());
   EXPECT_EQ(fd.get(), -1);

   // Closing an empty Fd succeeds (idempotent).
   EXPECT_TRUE(fd.close().has_value());
}

TEST(IoFdTest, MoveConstructionTransfersOwnership)
{
   int raw = freshFd();
   Fd source{raw};
   ASSERT_TRUE(source.valid());

   Fd destination{std::move(source)};
   EXPECT_FALSE(source.valid());
   EXPECT_EQ(source.get(), -1);
   EXPECT_TRUE(destination.valid());
   EXPECT_EQ(destination.get(), raw);

   // The source is empty, so its destructor must not close the descriptor.
   EXPECT_TRUE(isOpen(raw));

   EXPECT_TRUE(destination.close().has_value());
   EXPECT_FALSE(isOpen(raw));
}

TEST(IoFdTest, MoveAssignmentTransfersOwnership)
{
   int raw = freshFd();
   Fd source{raw};
   Fd destination{freshFd()};
   int const replaced = destination.get();
   ASSERT_TRUE(source.valid());
   ASSERT_TRUE(destination.valid());

   destination = std::move(source);
   EXPECT_FALSE(source.valid());
   EXPECT_TRUE(destination.valid());
   EXPECT_EQ(destination.get(), raw);
   // The previous descriptor is no longer valid: it was closed by the assignment.
   errno = 0;
   EXPECT_EQ(::fcntl(replaced, F_GETFD), -1);
   EXPECT_EQ(errno, EBADF);

   // The source is empty, so its destructor must not close anything.
   {
      Fd sourceCloseChecker{std::move(destination)};
      EXPECT_EQ(sourceCloseChecker.get(), raw);
   }
   EXPECT_FALSE(destination.valid());
   errno = 0;
   EXPECT_EQ(::fcntl(raw, F_GETFD), -1);
   EXPECT_EQ(errno, EBADF);

   // Closing an empty destination succeeds; a fresh Fd can be assigned into it.
   EXPECT_TRUE(destination.close().has_value());
   destination = Fd{freshFd()};
   EXPECT_TRUE(destination.valid());
   EXPECT_TRUE(destination.close().has_value());
   EXPECT_FALSE(destination.valid());
}

TEST(IoFdTest, ReleaseGivesUpOwnership)
{
   int raw = freshFd();
   Fd fd{raw};
   ASSERT_TRUE(fd.valid());

   EXPECT_EQ(fd.release(), raw);
   EXPECT_FALSE(fd.valid());
   EXPECT_EQ(fd.get(), -1);

   // The caller now owns the descriptor and closes it manually.
   EXPECT_TRUE(isOpen(raw));
   EXPECT_EQ(::close(raw), 0);
}

TEST(IoFdTest, SetNonBlockingSetsFlag)
{
   Fd fd{freshFd()};
   ASSERT_TRUE(fd.valid());
   ASSERT_FALSE(fd.isNonBlocking().value());

   EXPECT_TRUE(fd.setNonBlocking().has_value());
   EXPECT_TRUE(fd.isNonBlocking().value());
}

TEST(IoFdTest, SetNonBlockingPreservesOtherFlags)
{
   int raw = freshFd();
   Fd fd{raw};
   ASSERT_TRUE(fd.valid());
   int const flags = ::fcntl(raw, F_GETFL);
   ASSERT_GE(flags, 0);
   ASSERT_EQ(::fcntl(raw, F_SETFL, flags | O_APPEND), 0);

   EXPECT_TRUE(fd.setNonBlocking().has_value());

   int const after = ::fcntl(raw, F_GETFL);
   ASSERT_GE(after, 0);
   EXPECT_TRUE((after & O_NONBLOCK) != 0);
   EXPECT_TRUE((after & O_APPEND) != 0);
}

TEST(IoFdTest, FcntlErrorsAreReported)
{
   Fd fd;
   ASSERT_FALSE(fd.valid());

   // The empty Fd reports EBADF from the explicit guard, without a syscall.
   auto const setErr = fd.setNonBlocking();
   ASSERT_FALSE(setErr.has_value());
   EXPECT_EQ(setErr.error(), std::error_code(EBADF, std::system_category()));

   auto const isErr = fd.isNonBlocking();
   ASSERT_FALSE(isErr.has_value());
   EXPECT_EQ(isErr.error(), std::error_code(EBADF, std::system_category()));
}

TEST(IoFdTest, FcntlFailureOnClosedDescriptorIsReported)
{
   // Adopt a real descriptor, then close it underneath the Fd so fcntl()
   // itself fails with EBADF — covering the syscall failure branch, not
   // the explicit empty-fd guard above.
   Fd fd{freshFd()};
   ASSERT_TRUE(fd.valid());
   int const raw = fd.get();
   ASSERT_EQ(::close(raw), 0);

   auto const setErr = fd.setNonBlocking();
   ASSERT_FALSE(setErr.has_value());
   EXPECT_EQ(setErr.error(), std::error_code(EBADF, std::system_category()));

   auto const isErr = fd.isNonBlocking();
   ASSERT_FALSE(isErr.has_value());
   EXPECT_EQ(isErr.error(), std::error_code(EBADF, std::system_category()));

   // Reconcile ownership: the Fd must not double-close the descriptor.
   EXPECT_EQ(fd.release(), raw);
}

// A pipe with both ends owned by Fd and set non-blocking, for loop tests.
struct Pipe
{
   Fd readEnd;
   Fd writeEnd;

   explicit Pipe(bool nonBlocking = true) : readEnd(), writeEnd()
   {
      int fds[2] = {-1, -1};
      if (::pipe(fds) != 0)
	 return;
      readEnd = Fd{fds[0]};
      writeEnd = Fd{fds[1]};
      if (nonBlocking)
      {
	 (void)readEnd.setNonBlocking();
	 (void)writeEnd.setNonBlocking();
      }
   }
};

TEST(IoFdTest, ReadReturnsDataFromPipe)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   char const data[] = "hi";
   ASSERT_EQ(::write(pipe.writeEnd.get(), data, 2), 2);

   bool done = false;
   std::size_t got = 0;
   std::array<char, 16> buffer{};
   auto reader = [&]() -> Task<void>
   {
      auto const count = co_await pipe.readEnd.read(loop, std::span(buffer));
      if (count.has_value())
	 got = *count;
      done = true;
   };
   loop.schedule(reader());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(got, 2);
   EXPECT_EQ(std::string_view(buffer.data(), got), std::string_view(data, 2));
}

TEST(IoFdTest, ReadWaitsForData)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   bool done = false;
   std::size_t got = 0;
   std::array<char, 16> buffer{};
   auto reader = [&]() -> Task<void>
   {
      auto const count = co_await pipe.readEnd.read(loop, std::span(buffer));
      if (count.has_value())
	 got = *count;
      done = true;
   };
   loop.schedule(reader());
   // Empty pipe: the reader hit EAGAIN and is suspended, not errored.
   EXPECT_FALSE(done);

   char const data[] = "hi";
   ASSERT_EQ(::write(pipe.writeEnd.get(), data, 2), 2);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(got, 2);
}

TEST(IoFdTest, ReadReturnsZeroOnEof)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   bool done = false;
   std::size_t got = 99;
   std::array<char, 16> buffer{};
   auto reader = [&]() -> Task<void>
   {
      auto const count = co_await pipe.readEnd.read(loop, std::span(buffer));
      if (count.has_value())
	 got = *count;
      done = true;
   };
   // Close the write end: the read end reports EOF, not EAGAIN.
   EXPECT_TRUE(pipe.writeEnd.close().has_value());
   loop.schedule(reader());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(got, 0);
}

TEST(IoFdTest, WriteAllRoundTripsThroughDrainedPipe)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_TRUE(pipe.writeEnd.valid());

   // Larger than the pipe buffer so writeAll genuinely hits EAGAIN and waits.
   std::string const payload(256U * 1024U, 'x');
   bool writerDone = false;
   bool writerOk = false;
   auto writer = [&]() -> Task<void>
   {
      auto const result = co_await pipe.writeEnd.writeAll(loop, payload);
      writerOk = result.has_value();
      writerDone = true;
   };
   std::size_t received = 0;
   bool readerDone = false;
   auto reader = [&]() -> Task<void>
   {
      std::array<char, 4096> buffer{};
      while (received < payload.size())
      {
	 auto const count = co_await pipe.readEnd.read(loop, std::span(buffer));
	 if (!count.has_value() || *count == 0)
	    break;
	 received += *count;
      }
      readerDone = true;
   };
   loop.schedule(writer());
   loop.schedule(reader());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(writerDone);
   EXPECT_TRUE(writerOk);
   EXPECT_TRUE(readerDone);
   EXPECT_EQ(received, payload.size());
}

TEST(IoFdTest, WriteAllEmptyBufferSucceeds)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.writeEnd.valid());

   bool done = false;
   bool ok = false;
   auto writer = [&]() -> Task<void>
   {
      auto const result = co_await pipe.writeEnd.writeAll(loop, std::span<char const>{});
      ok = result.has_value();
      done = true;
   };
   loop.schedule(writer());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_TRUE(ok);
}

TEST(IoFdTest, ReadOnExternallyClosedFdReportsEbadf)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   // Close the descriptor underneath the Fd so ::read fails with EBADF.
   int const raw = pipe.readEnd.get();
   EXPECT_EQ(pipe.readEnd.release(), raw);
   ASSERT_EQ(::close(raw), 0);

   bool done = false;
   bool failed = false;
   std::error_code error;
   std::array<char, 16> buffer{};
   auto reader = [&]() -> Task<void>
   {
      auto const count = co_await pipe.readEnd.read(loop, std::span(buffer));
      if (!count.has_value())
      {
	 failed = true;
	 error = count.error();
      }
      done = true;
   };
   loop.schedule(reader());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_TRUE(failed);
   EXPECT_EQ(error, std::error_code(EBADF, std::system_category()));
}

TEST(IoFdTest, ReadUntilDelimiterAlreadyInScratch)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   std::string scratch = "a\nb";
   bool done = false;
   std::string record;
   auto task = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (result.has_value())
	 record = std::move(*result);
      done = true;
   };
   loop.schedule(task());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(record, "a\n");
   EXPECT_EQ(scratch, "b");
}

TEST(IoFdTest, ReadUntilTwoRecordsInOneWrite)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_EQ(::write(pipe.writeEnd.get(), "one\ntwo\n", 8), 8);

   std::string scratch;
   bool done = false;
   std::string first;
   std::string second;
   auto task = [&]() -> Task<void>
   {
      auto r1 = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (r1.has_value())
      {
	 first = std::move(*r1);
	 auto r2 = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
	 if (r2.has_value())
	    second = std::move(*r2);
      }
      done = true;
   };
   loop.schedule(task());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(first, "one\n");
   EXPECT_EQ(second, "two\n");
   EXPECT_TRUE(scratch.empty());
}

TEST(IoFdTest, ReadUntilRecordSplitAcrossWrites)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_EQ(::write(pipe.writeEnd.get(), "hel", 3), 3);

   std::string scratch;
   bool done = false;
   std::string record;
   auto task = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (result.has_value())
	 record = std::move(*result);
      done = true;
   };
   loop.schedule(task());
   EXPECT_FALSE(done);

   ASSERT_EQ(::write(pipe.writeEnd.get(), "lo\n", 3), 3);
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(record, "hello\n");
   EXPECT_TRUE(scratch.empty());
}

TEST(IoFdTest, ReadUntilEofMidRecordReturnsRemainder)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   ASSERT_EQ(::write(pipe.writeEnd.get(), "partial", 7), 7);
   EXPECT_TRUE(pipe.writeEnd.close().has_value());

   std::string scratch;
   bool done = false;
   std::string record;
   auto task = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (result.has_value())
	 record = std::move(*result);
      done = true;
   };
   loop.schedule(task());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(record, "partial");
   EXPECT_TRUE(scratch.empty());
}

TEST(IoFdTest, ReadUntilEofWithEmptyScratchReturnsEmptyString)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());
   EXPECT_TRUE(pipe.writeEnd.close().has_value());

   std::string scratch;
   bool done = false;
   bool ok = false;
   std::string record;
   auto task = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (result.has_value())
      {
	 ok = true;
	 record = std::move(*result);
      }
      done = true;
   };
   loop.schedule(task());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_TRUE(ok);
   EXPECT_TRUE(record.empty());
   EXPECT_TRUE(scratch.empty());
}

TEST(IoFdTest, ReadUntilDelimiterViewIntoScratch)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   // Prime scratch so the delimiter view points into scratch itself; the
   // view is copied up front, so nothing dangles and the record (including
   // the delimiter) is extracted intact, without syscalls.
   std::string scratch = "one\n";
   bool done = false;
   std::string record;
   auto task = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, std::string_view(scratch.data() + 3, 1));
      if (result.has_value())
	 record = std::move(*result);
      done = true;
   };
   loop.schedule(task());
   EXPECT_TRUE(loop.run().has_value());
   EXPECT_TRUE(done);
   EXPECT_EQ(record, "one\n");
   EXPECT_TRUE(scratch.empty());
}

TEST(IoFdTest, ReadUntilLongRecordWithoutDelimiter)
{
   Loop loop;
   Pipe pipe;
   ASSERT_TRUE(pipe.readEnd.valid());

   // 1 MiB with no delimiter, then EOF: the whole remainder must come
   // back as the final record (also guards the search-offset logic).
   std::size_t const size = 1024U * 1024U;
   std::string payload(size, 'a');
   payload.back() = 'z';
   bool writeDone = false;
   bool writeOk = false;
   auto writer = [&]() -> Task<void>
   {
      auto const result = co_await pipe.writeEnd.writeAll(loop, payload);
      writeOk = result.has_value();
      // Close inside the task so the reader observes EOF during run().
      if (writeOk)
	 (void)pipe.writeEnd.close();
      writeDone = true;
   };
   std::string scratch;
   bool readDone = false;
   bool readOk = false;
   std::string record;
   auto reader = [&]() -> Task<void>
   {
      auto const result = co_await pipe.readEnd.readUntil(loop, scratch, "\n");
      if (result.has_value())
      {
	 readOk = true;
	 record = std::move(*result);
      }
      readDone = true;
   };
   // Write and read concurrently; the writer closes its end on completion
   // so the reader sees EOF and returns the delimiter-less remainder.
   loop.schedule(writer());
   loop.schedule(reader());
   EXPECT_TRUE(loop.run().has_value());

   EXPECT_TRUE(writeDone);
   EXPECT_TRUE(writeOk);
   EXPECT_TRUE(readDone);
   EXPECT_TRUE(readOk);
   EXPECT_EQ(record.size(), size);
   EXPECT_EQ(record, payload);
   EXPECT_TRUE(scratch.empty());
}

} // namespace