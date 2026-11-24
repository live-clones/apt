#include <config.h>

#include <apt-core/io/fd.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <system_error>
#include <utility>

#include "common.h"

namespace {

using APT::Internal::IO::Fd;

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

} // namespace