#include <config.h>

#include <apt-pkg/acquire.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <vector>

#include "common.h"

namespace {

// A minimal pkgAcquire subclass overriding only the legacy virtual fd_set
// hooks, to prove the vector helpers delegate to them.
class AcquireFdHooks : public pkgAcquire
{
   public:
   // Keep the non-virtual vector helpers visible next to the overrides.
   using pkgAcquire::SetFds;
   using pkgAcquire::RunFds;

   int ReadFd = -1;
   int BothFd = -1;
   int SetCalls = 0;
   int RunCalls = 0;
   bool RunResult = true;
   bool SawRead = false;
   bool SawWrite = false;

   void SetFds(int &Fd, fd_set *RSet, fd_set *WSet) override
   {
      ++SetCalls;
      pkgAcquire::SetFds(Fd, RSet, WSet);
      if (ReadFd >= 0)
      {
	 FD_SET(ReadFd, RSet);
	 if (Fd < ReadFd)
	    Fd = ReadFd;
      }
      // Both directions on the same descriptor: must merge into one
      // combined-events entry in the vector translation.
      if (BothFd >= 0)
      {
	 FD_SET(BothFd, RSet);
	 FD_SET(BothFd, WSet);
	 if (Fd < BothFd)
	    Fd = BothFd;
      }
   }

   bool RunFds(fd_set *RSet, fd_set *WSet) override
   {
      ++RunCalls;
      SawRead = ReadFd >= 0 && FD_ISSET(ReadFd, RSet) != 0;
      SawWrite = BothFd >= 0 && FD_ISSET(BothFd, WSet) != 0;
      return RunResult;
   }
};

TEST(AcquireFdsTest, VectorSetFdsDelegatesAndMerges)
{
   int fds[2] = {-1, -1};
   ASSERT_EQ(::pipe(fds), 0);

   AcquireFdHooks acquire;
   acquire.ReadFd = fds[0];
   acquire.BothFd = fds[1];

   std::vector<pollfd> vector;
   acquire.SetFds(vector);
   // The virtual hook ran (delegation, not the vector path bypassing it).
   EXPECT_EQ(acquire.SetCalls, 1);

   auto const entryFor = [&vector](int fd) -> pollfd const *
   {
      auto const it = std::find_if(vector.begin(), vector.end(), [fd](pollfd const &entry)
      {
	 return entry.fd == fd;
      });
      return it == vector.end() ? nullptr : &*it;
   };

   // The read-only descriptor is present with POLLIN and zeroed revents.
   auto const *readEntry = entryFor(fds[0]);
   ASSERT_NE(readEntry, nullptr);
   EXPECT_EQ(readEntry->events, POLLIN);
   EXPECT_EQ(readEntry->revents, 0);

   // The both-directions descriptor appears exactly once, combined.
   EXPECT_EQ(std::count_if(vector.begin(), vector.end(), [fd = fds[1]](pollfd const &entry)
   {
      return entry.fd == fd;
   }), 1);
   auto const *bothEntry = entryFor(fds[1]);
   ASSERT_NE(bothEntry, nullptr);
   EXPECT_EQ(bothEntry->events, POLLIN | POLLOUT);
   EXPECT_EQ(bothEntry->revents, 0);

   ::close(fds[0]);
   ::close(fds[1]);
}

TEST(AcquireFdsTest, VectorRunFdsDelegatesDirectionally)
{
   int fds[2] = {-1, -1};
   ASSERT_EQ(::pipe(fds), 0);

   AcquireFdHooks acquire;
   acquire.ReadFd = fds[0];
   acquire.BothFd = fds[1];

   std::vector<pollfd> vector;
   acquire.SetFds(vector);
   ASSERT_EQ(acquire.SetCalls, 1);

   // Simulate poll(2) results: input readiness on the read-only entry and
   // on the combined entry (never output readiness on the latter).
   for (auto &entry : vector)
   {
      if ((entry.events & POLLIN) != 0)
	 entry.revents = POLLIN;
   }

   EXPECT_TRUE(acquire.RunFds(vector));
   EXPECT_EQ(acquire.RunCalls, 1);
   // The virtual hook observed input readiness on both descriptors...
   EXPECT_TRUE(acquire.SawRead);
   // ...but the output direction was not dispatched for the combined
   // descriptor: only POLLIN readiness was reported, so no WSet bit —
   // directional correctness through the translation.
   EXPECT_FALSE(acquire.SawWrite);

   // The return value propagates through the vector path.
   acquire.RunResult = false;
   EXPECT_FALSE(acquire.RunFds(vector));

   ::close(fds[0]);
   ::close(fds[1]);
}

} // namespace