/*
 * Performance measurements
 *
 * Copyright (C) 2026 Julian Andres Klode <jak@debian.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef APT_PERF_H
#define APT_PERF_H
#if defined(APT_COMPILING_APT) && defined(__linux__)
#include <apt-pkg/macros.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace APT
{

/**
 * \brief A scoped object that will log the performance counters.
 *
 * Set the "APT_PERFORMANCE_LOG" environment variable to produce a
 * JSONL file with records for various contexts, such as the solver.
 */
class PerformanceContext
{
   struct measurement
   {
      uint32_t type;
      uint64_t config;
      const char *name;
   };

   static constexpr std::array<measurement, 10> measurements{
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, "instructions"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, "cpu_cycles"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES, "ref_cpu_cycles"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, "cache_references"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, "cache_misses"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS, "branch_instructions"},
      measurement{PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, "branch_misses"},
      measurement{PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, "cpu_clock"},
      measurement{PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS, "page_faults"},
      measurement{PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS, "cpu_migrations"},
   };

   /// Output filename
   std::string out;
   /// Name of the context
   std::string name;
   /// FDs to communicate with the kernel
   std::array<int, measurements.size()> fds;

   // Wrapper for the system call
   static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			       int cpu, int group_fd, unsigned long flags)
   {
      return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   }

   // Wrapper for the system call
   static int open_perf_counter(uint32_t type, uint64_t config)
   {
      struct perf_event_attr pe;
      memset(&pe, 0, sizeof(struct perf_event_attr));
      pe.type = type;
      pe.size = sizeof(struct perf_event_attr);
      pe.config = config;
      pe.disabled = 1;
      pe.exclude_kernel = 1;
      pe.exclude_hv = 1;

      int fd = perf_event_open(&pe, 0, -1, -1, 0);
      return fd;
   }

   public:
   /// Construct a new scoped performance context
   PerformanceContext(std::string name) : name(name)
   {
      if (auto out = getenv("APT_PERFORMANCE_LOG"))
	 this->out = out;
      if (likely(out.empty()))
	 return;
      for (size_t i = 0; i < measurements.size(); ++i)
	 fds[i] = open_perf_counter(measurements[i].type, measurements[i].config);
      for (auto fd : fds)
	 must_succeed(fd == -1 || ioctl(fd, PERF_EVENT_IOC_RESET, 0) != -1);
      for (auto fd : fds)
	 must_succeed(fd == -1 || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != -1);
   }
   /// Collect the results and store them in the specified performance file
   ~PerformanceContext()
   {
      if (likely(out.empty()))
	 return;
      for (auto fd : fds)
	 must_succeed(fd == -1 || ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) != -1);

      std::array<long long, measurements.size()> values;
      for (size_t i = 0; i < measurements.size(); ++i)
	 must_succeed(fds[i] == -1 || read(fds[i], &values[i], sizeof(values[i])) == sizeof(values[i]));
      for (auto fd : fds)
	 must_succeed(fd == -1 || close(fd) == 0);

      std::stringstream ss;
      ss.imbue(std::locale::classic());
      ss << "{\"context\": " << '"' << name << '"';
      for (size_t i = 0; i < measurements.size(); ++i)
      {
	 ss << ", ";
	 ss << '"' << measurements[i].name << '"' << ": " << values[i];
      }

      ss << "}\n";

      std::string entry = ss.str();

      // Atomically append a line to the JSONL file, allowing all users to read it
      int fd = open(out.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0666);
      must_succeed(fd != -1);
      must_succeed(flock(fd, LOCK_EX) == 0);
      must_succeed(write(fd, entry.c_str(), entry.size()) == static_cast<ssize_t>(entry.size()));
      must_succeed(flock(fd, LOCK_UN) == 0);
      must_succeed(close(fd) == 0);
   }
};

} // namespace APT

#else
namespace APT
{
struct PerformanceContext
{
   PerformanceContext(const char *) {};
   ~PerformanceContext() {};
};
} // namespace APT
#endif
#endif
