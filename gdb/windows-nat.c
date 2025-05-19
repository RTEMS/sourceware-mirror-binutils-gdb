/* Target-vector operations for controlling windows child processes, for GDB.

   Copyright (C) 1995-2025 Free Software Foundation, Inc.

   Contributed by Cygnus Solutions, A Red Hat Company.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Originally by Steve Chamberlain, sac@cygnus.com */

#include "exceptions.h"
#include "frame.h"
#include "inferior.h"
#include "infrun.h"
#include "target.h"
#include "gdbcore.h"
#include "command.h"
#include "completer.h"
#include "regcache.h"
#include "top.h"
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <windows.h>
#include <imagehlp.h>
#ifdef __CYGWIN__
#include <wchar.h>
#include <sys/cygwin.h>
#include <cygwin/version.h>
#endif
#include <algorithm>
#include <atomic>
#include <vector>
#include <queue>

#include "filenames.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdb_bfd.h"
#include "gdbsupport/gdb_obstack.h"
#include "gdbthread.h"
#include "cli/cli-cmds.h"
#include "cli/cli-style.h"
#include <unistd.h>
#include "exec.h"
#include "solist.h"
#include "solib.h"
#include "xml-support.h"
#include "inttypes.h"

#include "i386-tdep.h"
#include "i387-tdep.h"

#include "windows-tdep.h"
#include "windows-nat.h"
#include "x86-nat.h"
#include "complaints.h"
#include "inf-child.h"
#include "gdbsupport/gdb_tilde_expand.h"
#include "gdbsupport/pathstuff.h"
#include "gdbsupport/gdb_wait.h"
#include "nat/windows-nat.h"
#include "gdbsupport/symbol.h"
#include "ser-event.h"
#include "inf-loop.h"

/* This comment documents high-level logic of this file.

all-stop
========

In all-stop mode ("maint set target-non-stop off"), there is only ever
one Windows debug event in flight. When we receive an event from
WaitForDebugEvent, the kernel has already implicitly suspended all the
threads of the process.  We report the breaking event to the core.
When the core decides to resume the inferior, it calls
windows_nat_target:resume, which triggers a ContinueDebugEvent call.
This call makes all unsuspended threads schedulable again, and we go
back to waiting for the next event in WaitForDebugEvent.

non-stop
========

For non-stop mode, we utilize the DBG_REPLY_LATER flag in the
ContinueDebugEvent function.  According to Microsoft:

 "This flag causes dwThreadId to replay the existing breaking event
 after the target continues.  By calling the SuspendThread API against
 dwThreadId, a debugger can resume other threads in the process and
 later return to the breaking."

To enable non-stop mode, windows_nat_target::wait suspends the thread,
calls 'ContinueForDebugEvent(..., DBG_REPLY_LATER)', and sets the
process_thread thread to wait for the next event using
WaitForDebugEvent, all before returning the original breaking event to
the core.

When the user/core finally decides to resume the inferior thread that
reported the event, we unsuspend it using ResumeThread.  Unlike in
all-stop mode, we don't call ContinueDebugEvent then, as it has
already been called when the event was first encountered.  By making
the inferior thread schedulable again (by unsuspending it),
WaitForDebugEvent re-reports the same event (due to the earlier
DBG_REPLY_LATER).  In windows_nat_target::wait, we detect this delayed
re-report and call ContinueDebugEvent on the thread, instructing the
"process_thread" thread (the GDB thread responsible for calling
WaitForDebugEvents) to continue waiting for the next event.

During the initial thread resumption in windows_nat_target::resume, we
recorded the dwContinueStatus argument to be passed to the last
ContinueDebugEvent (called when the reply-later event is re-reported).
See windows_thread_info::reply_later for details.

Note that with this setup, in non-stop mode, every stopped thread has
its own independent last-reported Windows debug event.  Therefore, we
can decide on a per-thread basis whether to pass the thread's
exception (DBG_EXCEPTION_NOT_HANDLED / DBG_CONTINUE) to the inferior.
This per-thread decision is not possible in all-stop mode, where we
only call ContinueDebugEvent for the thread that last reported a stop,
at windows_nat_target::resume time.

Thread and process exits
========================

When a process exits, Windows reports one EXIT_THREAD_DEBUG_EVENT
event for each thread, except for the last thread that exits.  That
last thread reports a EXIT_PROCESS_DEBUG_EVENT event instead.

The last thread that exits is not guaranteed to be the main thread of
the process.  In fact, it seldom is.  E.g., if the main thread calls
ExitProcess (or returns from main, which ends up calling ExitProcess),
then we typically see a EXIT_THREAD_DEBUG_EVENT event for the main
thread first, followed by more EXIT_THREAD_DEBUG_EVENT events for
other threads, and then finaly the EXIT_PROCESS_DEBUG_EVENT for
whatever thread happened to be the last one to exit.

When a thread reports EXIT_THREAD_DEBUG_EVENT /
EXIT_PROCESS_DEBUG_EVENT, our handle to the thread is still valid, and
we can still read its registers.  Windows only destroys the handle
after ContinueDebugEvent.

A thread that has exited CANNOT be suspended.  So if a thread was
previously suspended, and then something kills the whole process
(which force-kills all threads), that suspended thread will
automatically "unsuspend", and report a EXIT_THREAD_DEBUG_EVENT event.
However, if we had previously used DBG_REPLY_LATER on the thread,
Windows will first re-report the kernel-side-queued "reply-later"
event, and only after that one is ContinueDebugEvent'ed, will we see
the EXIT_THREAD_DEBUG_EVENT event.

Detaching and DBG_REPLY_LATER
=============================

After we detach from a process that has threads that we had previously
used DBG_REPLY_LATER on, the kernel re-raises the "reply-later"
exceptions for those threads.  This would most often kill the
just-detached process, if we let it happen.  To prevent it, we flush
all the "reply-later" events from the kernel before detaching.

Cygwin signals
==============

The Cygwin runtime always spawns a "sig" thread, which is responsible
for receiving signal delivery requests, and hijacking the signaled
thread's execution to make it run the signal handler.  This is all
explained here:

  https://sourceware.org/cgit/newlib-cygwin/tree/winsup/cygwin/DevDocs/how-signals-work.txt

There's a custom debug api protocol between GDB and Cygwin to be able
to intercept Cygwin signals before they're seen by the signaled
thread, just like the debugger intercepts signals with ptrace on
Linux.  This Cygwin debugger protocol isn't well documented, though.
Here's what happens: when the special "sig" thread in the Cygwin
runtime is about to deliver a signal to the target thread, it calls
OutputDebugString with a special message:

  https://sourceware.org/cgit/newlib-cygwin/tree/winsup/cygwin/exceptions.cc?id=4becae7bd833e183c789821a477f25898ed0db1f#n1866

OutputDebugString is a function that is part of the Windows debug API.
It generates an OUTPUT_DEBUG_STRING_EVENT event out of
WaitForDebugEvent in the debugger, which freezes the inferior, like
any other event.

GDB recognizes the special Cygwin signal marker string, and is able to
report the intercepted Cygwin signal to the user.

With the windows-nat backend in all-stop mode, if the user decides to
single-step the signaled thread, GDB will set the trace flag in the
signaled thread to force it to single-step, and then re-resume the
program with ContinueDebugEvent.  This resumes both the signaled
thread, and the special "sig" thread.  The special "sig" thread
decides to make the signaled thread run the signal handler, so it
suspends it with SuspendThread, does a read-modify-write operation
with GetThreadContext/SetThreadContext, and then re-resumes it with
ResumeThread.  This is all done here:

   https://sourceware.org/cgit/newlib-cygwin/tree/winsup/cygwin/exceptions.cc?id=4becae7bd833e183c789821a477f25898ed0db1f#n1011

That resulting register context will still have its trace flag set, so
the signaled thread ends up single-stepping the signal handler and
reporting the trace stop to GDB, which reports the stop where the
thread is now stopped, inside the signal handler.

That is the intended behavior; stepping into a signal handler is a
feature that works on other ports as well, including x86 GNU/Linux,
for example.  This is exercised by the gdb.base/sigstep.exp testcase.

Now, making that work with the backend in non-stop mode (the default
on Windows 10 and above) is tricker.  In that case, when GDB sees the
magic OUTPUT_DEBUG_STRING_EVENT event mentioned above, reported for
the "sig" thread, GDB reports the signal stop for the target signaled
thread to the user (leaving that thread stopped), but, unlike with an
all-stop backend, in non-stop, only the evented/signaled thread should
be stopped, so the backend would normally want to re-resume the Cygwin
runtime's "sig" thread after handling the OUTPUT_DEBUG_STRING_EVENT
event, like it does with any other event out of WaitForDebugEvent that
is not reported to the core.  If it did that (resume the "sig" thread)
however, at that point, the signaled thread would be stopped,
suspended with SuspendThread by GDB (while the user is inspecting it),
but, unlike in all-stop, the "sig" thread would be set running free.
The "sig" thread would reach the code that wants to redirect the
signaled thread's execution to the signal handler (by hacking the
registers context, as described above), but unlike in the all-stop
case, the "sig" thread would notice that the signaled thread is
suspended, and so would decide to defer the signal handler until a
later time.  It's the same code as described above for the all-stop
case, except it would take the "then" branch:

   https://sourceware.org/cgit/newlib-cygwin/tree/winsup/cygwin/exceptions.cc?id=4becae7bd833e183c789821a477f25898ed0db1f#n1019

   // Just set pending if thread is already suspended
   if (res)
     {
       tls->unlock ();
       ResumeThread (hth);
       goto out;
     }

The result would be that when the GDB user later finally decides to
step the signaled thread, the signaled thread would just single step
the mainline code, instead of stepping into the signal handler.

To avoid this difference of behavior in non-stop mode compared to
all-stop mode, we use a trick -- whenever we see that magic
OUTPUT_DEBUG_STRING_EVENT event reported for the "sig" thread, we
report a stop for the target signaled thread, _and_ leave the "sig"
thread suspended as well, for as long as the target signaled thread is
suspended.  I.e., we don't let the "sig" thread run before the user
decides what to do with the signaled thread's signal.  Only when the
user re-resumes the signaled thread, will we resume the "sig" thread
as well.  The trick is that all this is done here in the Windows
backend, while providing the illusion to the core of GDB (and the
user) that the "sig" thread is "running", for as long as the core
wants the "sig" thread to be running.

This isn't ideal, since this means that with user-visible non-stop,
the inferior will only be able to process and report one signal at a
time (as the "sig" thread is responsible for that), but that seems
like an acceptible compromise, better than not being able to have the
target work in non-stop by default on Cygwin.  */

using namespace windows_nat;

/* Maintain a linked list of "so" information.  */
struct windows_solib
{
  LPVOID load_addr = 0;
  CORE_ADDR text_offset = 0;

  /* Original name.  */
  std::string original_name;
  /* Expanded form of the name.  */
  std::string name;
};

/* Flags that can be passed to windows_continue.  */

enum windows_continue_flag
  {
    /* This means we have killed the inferior, so windows_continue
       should ignore weird errors due to threads shutting down.  */
    WCONT_KILLED = 1,

    /* This means we expect this windows_continue call to be the last
       call to continue the inferior -- we are either mourning it or
       detaching.  */
    WCONT_LAST_CALL = 2,

    /* By default, windows_continue only calls ContinueDebugEvent in
       all-stop mode.  This flag indicates that windows_continue
       should call ContinueDebugEvent even in non-stop mode.  */
    WCONT_CONTINUE_DEBUG_EVENT = 4,

    /* Skip calling ContinueDebugEvent even in all-stop mode.  This is
       the default in non-stop mode.  */
    WCONT_DONT_CONTINUE_DEBUG_EVENT = 8,
  };

DEF_ENUM_FLAGS_TYPE (windows_continue_flag, windows_continue_flags);

/* We want to register windows_thread_info as struct thread_info
   private data.  thread_info::priv must point to a class that
   inherits from private_thread_info.  But we can't make
   windows_thread_info inherit private_thread_info, because
   windows_thread_info is shared with GDBserver.  So we make a new
   class that inherits from both private_thread_info,
   windows_thread_info, and register that one as thread_info::private.
   This multiple inheritance is benign, because private_thread_info is
   a java-style interface class with no data.  */
struct windows_private_thread_info : private_thread_info, windows_thread_info
{
  windows_private_thread_info (windows_process_info *proc,
			       DWORD tid, HANDLE h, CORE_ADDR tlb)
    : windows_thread_info (proc, tid, h, tlb)
  {}

  ~windows_private_thread_info () override
  {}
};

struct windows_per_inferior : public windows_process_info
{
  windows_thread_info *find_thread (ptid_t ptid) override;
  bool handle_output_debug_string (const DEBUG_EVENT &current_event,
				   struct target_waitstatus *ourstatus) override;
  void handle_load_dll (const char *dll_name, LPVOID base) override;
  void handle_unload_dll (const DEBUG_EVENT &current_event) override;
  bool handle_access_violation (const EXCEPTION_RECORD *rec) override;

  void fill_thread_context (windows_thread_info *th) override;

  void continue_one_thread (windows_thread_info *th,
			    windows_continue_flags cont_flags);

  int windows_initialization_done = 0;

  /* Counts of things.  */
  int saw_create = 0;
  int open_process_used = 0;
#ifdef __x86_64__
  void *wow64_dbgbreak = nullptr;
#endif

  /* This vector maps GDB's idea of a register's number into an offset
     in the windows exception context vector.

     It also contains the bit mask needed to load the register in question.

     The contents of this table can only be computed by the units
     that provide CPU-specific support for Windows native debugging.

     One day we could read a reg, we could inspect the context we
     already have loaded, if it doesn't have the bit set that we need,
     we read that set of registers in using GetThreadContext.  If the
     context already contains what we need, we just unpack it.  Then to
     write a register, first we have to ensure that the context contains
     the other regs of the group, and then we copy the info in and set
     out bit.  */

  const int *mappings = nullptr;

  /* The function to use in order to determine whether a register is
     a segment register or not.  */
  segment_register_p_ftype *segment_register_p = nullptr;

  std::vector<windows_solib> solibs;

#ifdef __CYGWIN__
  /* The starting and ending address of the cygwin1.dll text segment.  */
  CORE_ADDR cygwin_load_start = 0;
  CORE_ADDR cygwin_load_end = 0;
#endif /* __CYGWIN__ */
};

/* The current process.  */
static windows_per_inferior windows_process;

#undef STARTUPINFO

#ifndef __CYGWIN__
# define __PMAX	(MAX_PATH + 1)
# define STARTUPINFO STARTUPINFOA
#else
# define __PMAX	PATH_MAX
#   define STARTUPINFO STARTUPINFOW
#endif

/* If we're not using the old Cygwin header file set, define the
   following which never should have been in the generic Win32 API
   headers in the first place since they were our own invention...  */
#ifndef _GNU_H_WINDOWS_H
enum
  {
    FLAG_TRACE_BIT = 0x100,
  };
#endif

#define DR6_CLEAR_VALUE 0xffff0ff0

/* The string sent by cygwin when it processes a signal.
   FIXME: This should be in a cygwin include file.  */
#ifndef _CYGWIN_SIGNAL_STRING
#define _CYGWIN_SIGNAL_STRING "cYgSiGw00f"
#endif

#define CHECK(x)	check (x, __FILE__,__LINE__)
#define DEBUG_EXEC(fmt, ...) \
  debug_prefixed_printf_cond (debug_exec, "windows exec", fmt, ## __VA_ARGS__)
#define DEBUG_EVENTS(fmt, ...) \
  debug_prefixed_printf_cond (debug_events, "windows events", fmt, \
			      ## __VA_ARGS__)
#define DEBUG_MEM(fmt, ...) \
  debug_prefixed_printf_cond (debug_memory, "windows mem", fmt, \
			      ## __VA_ARGS__)
#define DEBUG_EXCEPT(fmt, ...) \
  debug_prefixed_printf_cond (debug_exceptions, "windows except", fmt, \
			      ## __VA_ARGS__)

static void windows_set_dr (int i, CORE_ADDR addr);
static void windows_set_dr7 (unsigned long val);
static CORE_ADDR windows_get_dr (int i);
static unsigned long windows_get_dr6 (void);
static unsigned long windows_get_dr7 (void);

/* User options.  */
static bool new_console = false;
#ifdef __CYGWIN__
static bool cygwin_exceptions = false;
#endif
static bool new_group = true;
static bool debug_exec = false;		/* show execution */
static bool debug_events = false;	/* show events from kernel */
static bool debug_memory = false;	/* show target memory accesses */
static bool debug_exceptions = false;	/* show target exceptions */
static bool useshell = false;		/* use shell for subprocesses */

/* See windows_nat_target::resume to understand why this is commented
   out.  */
#if 0
/* This vector maps the target's idea of an exception (extracted
   from the DEBUG_EVENT structure) to GDB's idea.  */

struct xlate_exception
  {
    DWORD them;
    enum gdb_signal us;
  };

static const struct xlate_exception xlate[] =
{
  {EXCEPTION_ACCESS_VIOLATION, GDB_SIGNAL_SEGV},
  {STATUS_STACK_OVERFLOW, GDB_SIGNAL_SEGV},
  {EXCEPTION_BREAKPOINT, GDB_SIGNAL_TRAP},
  {DBG_CONTROL_C, GDB_SIGNAL_INT},
  {EXCEPTION_SINGLE_STEP, GDB_SIGNAL_TRAP},
  {STATUS_FLOAT_DIVIDE_BY_ZERO, GDB_SIGNAL_FPE}
};

#endif /* 0 */

struct windows_nat_target final : public x86_nat_target<inf_child_target>
{
  windows_nat_target ();

  void close () override;

  thread_control_capabilities get_thread_control_capabilities () override
  { return tc_schedlock; }

  void attach (const char *, int) override;

  bool attach_no_wait () override
  {
    /* In non-stop, after attach, we leave all threads running, like
       other targets.  */
    return !target_is_non_stop_p ();
  }

  void detach (inferior *, int) override;

  void resume (ptid_t, int , enum gdb_signal) override;

  ptid_t wait (ptid_t, struct target_waitstatus *, target_wait_flags) override;

  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;

  bool stopped_by_sw_breakpoint () override
  {
    windows_thread_info *th = windows_process.find_thread (inferior_ptid);
    return th->stopped_at_software_breakpoint;
  }

  bool supports_stopped_by_sw_breakpoint () override
  {
    return true;
  }

  enum target_xfer_status xfer_partial (enum target_object object,
					const char *annex,
					gdb_byte *readbuf,
					const gdb_byte *writebuf,
					ULONGEST offset, ULONGEST len,
					ULONGEST *xfered_len) override;

  void files_info () override;

  void kill () override;

  void create_inferior (const char *, const std::string &,
			char **, int) override;

  void mourn_inferior () override;

  bool thread_alive (ptid_t ptid) override;

  std::string pid_to_str (ptid_t) override;

  void interrupt () override;
  void stop (ptid_t) override;
  void pass_ctrlc () override;

  void thread_events (bool enable) override;

  bool any_resumed_thread ();

  const char *pid_to_exec_file (int pid) override;

  ptid_t get_ada_task_ptid (long lwp, ULONGEST thread) override;

  bool get_tib_address (ptid_t ptid, CORE_ADDR *addr) override;

  const char *thread_name (struct thread_info *) override;

  ptid_t get_windows_debug_event (int pid, struct target_waitstatus *ourstatus,
				  target_wait_flags options,
				  DEBUG_EVENT *current_event);

  void do_initial_windows_stuff (DWORD pid, bool attaching);

  bool supports_disable_randomization () override
  {
    return disable_randomization_available ();
  }

  bool can_async_p () override
  {
    return true;
  }

  bool is_async_p () override
  {
    return m_is_async;
  }

  bool supports_non_stop () override;

  void async (bool enable) override;

  int async_wait_fd () override
  {
    return serial_event_fd (m_wait_event);
  }

  void debug_registers_changed_all_threads ();

private:

  windows_thread_info *add_thread (ptid_t ptid, HANDLE h, void *tlb,
				   bool main_thread_p);
  void delete_thread (ptid_t ptid, DWORD exit_code, bool main_thread_p);
  DWORD fake_create_process (const DEBUG_EVENT &current_event);

  void stop_one_thread (windows_thread_info *th,
			enum stopping_kind stopping_kind);

  DWORD continue_status_for_event_detaching
    (const DEBUG_EVENT &event, size_t *reply_later_events_left = nullptr);

  DWORD prepare_resume (windows_thread_info *wth,
			thread_info *tp,
			int step, gdb_signal sig);

  BOOL windows_continue (DWORD continue_status, int id,
			 windows_continue_flags cont_flags = 0);

  /* Helper function to start process_thread.  */
  static DWORD WINAPI process_thread_starter (LPVOID self);

  /* This function implements the background thread that starts
     inferiors and waits for events.  */
  void process_thread ();

  /* Push FUNC onto the queue of requests for process_thread, and wait
     until it has been called.  On Windows, certain debugging
     functions can only be called by the thread that started (or
     attached to) the inferior.  These are all done in the worker
     thread, via calls to this method.  If FUNC returns true,
     process_thread will wait for debug events when FUNC returns.  */
  void do_synchronously (gdb::function_view<bool ()> func);

  /* This waits for a debug event, dispatching to the worker thread as
     needed.  */
  void wait_for_debug_event_main_thread (DEBUG_EVENT *event);

  /* This continues the last debug event, dispatching to the worker
     thread as needed.  */
  void continue_last_debug_event_main_thread (const char *context_str,
					      DWORD continue_status,
					      bool last_call = false);

  /* Force the process_thread thread to return from WaitForDebugEvent.
     PROCESS_ALIVE is set to false if the inferior process exits while
     we're trying to break out the process_thread thread.  This can
     happen because this is called while all threads are running free,
     while we're trying to detach.  */
  void break_out_process_thread (bool &process_alive);

  /* Queue used to send requests to process_thread.  This is
     implicitly locked.  */
  std::queue<gdb::function_view<bool ()>> m_queue;

  /* Event used to signal process_thread that an item has been
     pushed.  */
  HANDLE m_pushed_event;
  /* Event used by process_thread to indicate that it has processed a
     single function call.  */
  HANDLE m_response_event;

  /* Serial event used to communicate wait event availability to the
     main loop.  */
  serial_event *m_wait_event;

  /* The last debug event, when M_WAIT_EVENT has been set.  */
  DEBUG_EVENT m_last_debug_event {};
  /* True if a debug event is pending.  */
  std::atomic<bool> m_debug_event_pending { false };

  /* True if currently in async mode.  */
  bool m_is_async = false;

  /* True if we last called ContinueDebugEvent and the process_thread
     thread is now waiting for events.  False if WaitForDebugEvent
     already returned an event, and we need to ContinueDebugEvent
     again to restart the inferior.  */
  bool m_continued = false;

  /* Whether target_thread_events is in effect.  */
  bool m_report_thread_events = false;
};

/* Get the windows_thread_info object associated with THR.  */

static windows_thread_info *
as_windows_thread_info (thread_info *thr)
{
  /* Cast to windows_private_thread_info, which inherits from
     private_thread_info, and is implicitly convertible to
     windows_thread_info, the return type.  */
  return static_cast<windows_private_thread_info *> (thr->priv.get ());
}

/* Creates an iterator that works like all_matching_threads_iterator,
   but that returns windows_thread_info pointers instead of
   thread_info.  This could be replaced with a std::range::transform
   when we require C++20.  */
class all_windows_threads_iterator
{
public:
  typedef all_windows_threads_iterator self_type;
  typedef windows_thread_info *value_type;
  typedef windows_thread_info *&reference;
  typedef windows_thread_info **pointer;
  typedef std::forward_iterator_tag iterator_category;
  typedef int difference_type;

  explicit all_windows_threads_iterator (all_non_exited_threads_iterator base_iter)
    : m_base_iter (base_iter)
  {}

  windows_thread_info *operator* () const { return as_windows_thread_info (*m_base_iter); }

  all_windows_threads_iterator &operator++ ()
  {
    ++m_base_iter;
    return *this;
  }

  bool operator== (const all_windows_threads_iterator &other) const
  { return m_base_iter == other.m_base_iter; }

  bool operator!= (const all_windows_threads_iterator &other) const
  { return !(*this == other); }

private:
  all_non_exited_threads_iterator m_base_iter;
};

/* The range for all_windows_threads, below.  */

class all_windows_threads_range : public all_non_exited_threads_range
{
public:
  all_windows_threads_range (all_non_exited_threads_range base_range)
    : m_base_range (base_range)
  {}

  all_windows_threads_iterator begin () const
  { return all_windows_threads_iterator (m_base_range.begin ()); }
  all_windows_threads_iterator end () const
  { return all_windows_threads_iterator (m_base_range.end ()); }

private:
  all_non_exited_threads_range m_base_range;
};

/* Return a range that can be used to walk over all non-exited Windows
   threads of all inferiors, with range-for.  */

inline all_windows_threads_range
all_windows_threads ()
{
  auto *win_tgt = static_cast<windows_nat_target *> (get_native_target ());
  return (all_windows_threads_range
	  (all_non_exited_threads_range (win_tgt, minus_one_ptid)));
}

static void
check (BOOL ok, const char *file, int line)
{
  if (!ok)
    {
      unsigned err = (unsigned) GetLastError ();
      gdb_printf ("error return %s:%d was %u: %s\n", file, line,
		  err, strwinerror (err));
    }
}

windows_nat_target::windows_nat_target ()
  : m_pushed_event (CreateEvent (nullptr, false, false, nullptr)),
    m_response_event (CreateEvent (nullptr, false, false, nullptr)),
    m_wait_event (make_serial_event ())
{
  HANDLE bg_thread = CreateThread (nullptr, 64 * 1024,
				   process_thread_starter, this, 0, nullptr);
  CloseHandle (bg_thread);
}

void
windows_nat_target::async (bool enable)
{
  if (enable == is_async_p ())
    return;

  if (enable)
    add_file_handler (async_wait_fd (),
		      [] (int, gdb_client_data)
		      {
			inferior_event_handler (INF_REG_EVENT);
		      },
		      nullptr, "windows_nat_target");
  else
    delete_file_handler (async_wait_fd ());

  m_is_async = enable;
}

/* A wrapper for WaitForSingleObject that issues a warning if
   something unusual happens.  */
static void
wait_for_single (HANDLE handle, DWORD howlong)
{
  while (true)
    {
      DWORD r = WaitForSingleObject (handle, howlong);
      if (r == WAIT_OBJECT_0)
	return;
      if (r == WAIT_FAILED)
	{
	  unsigned err = (unsigned) GetLastError ();
	  warning ("WaitForSingleObject failed (code %u): %s",
		   err, strwinerror (err));
	}
      else
	warning ("unexpected result from WaitForSingleObject: %u",
		 (unsigned) r);
    }
}

DWORD WINAPI
windows_nat_target::process_thread_starter (LPVOID self)
{
  ((windows_nat_target *) self)->process_thread ();
  return 0;
}

void
windows_nat_target::process_thread ()
{
  while (true)
    {
      wait_for_single (m_pushed_event, INFINITE);

      gdb::function_view<bool ()> func = std::move (m_queue.front ());
      m_queue.pop ();

      bool should_wait = func ();
      SetEvent (m_response_event);

      if (should_wait)
	{
	  if (!m_debug_event_pending)
	    {
	      wait_for_debug_event (&m_last_debug_event, INFINITE);
	      m_debug_event_pending = true;
	    }
	  serial_event_set (m_wait_event);
	}
   }
}

void
windows_nat_target::do_synchronously (gdb::function_view<bool ()> func)
{
  m_queue.emplace (std::move (func));
  SetEvent (m_pushed_event);
  wait_for_single (m_response_event, INFINITE);
}

void
windows_nat_target::wait_for_debug_event_main_thread (DEBUG_EVENT *event)
{
  do_synchronously ([&] ()
    {
      if (m_debug_event_pending)
	{
	  *event = m_last_debug_event;
	  m_debug_event_pending = false;
	}
      else
	wait_for_debug_event (event, INFINITE);
      return false;
    });

  m_continued = false;
}

void
windows_nat_target::continue_last_debug_event_main_thread
  (const char *context_str, DWORD continue_status, bool last_call)
{
  std::optional<unsigned> err;
  do_synchronously ([&] ()
    {
      if (!continue_last_debug_event (continue_status, debug_events))
	err = (unsigned) GetLastError ();

      /* On the last call, do not block waiting for an event that will
	 never come.  */
      return !last_call;
    });
  if (err.has_value ())
    throw_winerror_with_name (string_printf (_("ContinueDebugEvent failed: %s"),
					     context_str).c_str (),
			      *err);

  m_continued = !last_call;
}

/* See nat/windows-nat.h.  */

windows_thread_info *
windows_per_inferior::find_thread (ptid_t ptid)
{
  auto *win_tgt = static_cast<windows_nat_target *> (get_native_target ());
  thread_info *thr = win_tgt->find_thread (ptid);
  if (thr == nullptr)
    return nullptr;
  return as_windows_thread_info (thr);
}

/* Add a thread to the thread list.

   PTID is the ptid of the thread to be added.
   H is its Windows handle.
   TLB is its thread local base.
   MAIN_THREAD_P should be true if the thread to be added is
   the main thread, false otherwise.  */

windows_thread_info *
windows_nat_target::add_thread (ptid_t ptid, HANDLE h, void *tlb,
				bool main_thread_p)
{
  gdb_assert (ptid.lwp () != 0);

  windows_thread_info *existing = windows_process.find_thread (ptid);
  if (existing != nullptr)
    return existing;

  CORE_ADDR base = (CORE_ADDR) (uintptr_t) tlb;
#ifdef __x86_64__
  /* For WOW64 processes, this is actually the pointer to the 64bit TIB,
     and the 32bit TIB is exactly 2 pages after it.  */
  if (windows_process.wow64_process)
    base += 0x2000;
#endif
  windows_private_thread_info *th
    = new windows_private_thread_info (&windows_process, ptid.lwp (), h, base);

  /* Add this new thread to the list of threads.

     To be consistent with what's done on other platforms, we add
     the main thread silently (in reality, this thread is really
     more of a process to the user than a thread).  */
  thread_info *gth = (main_thread_p
		      ? ::add_thread_silent (this, ptid)
		      : ::add_thread (this, ptid));
  gth->priv.reset (th);

  /* It's simplest to always set this and update the debug
     registers.  */
  th->debug_registers_changed = true;

  /* Even if we're stopping the thread for some reason internal to
     this module, from the perspective of infrun and the
     user/frontend, this new thread is running until it next reports a
     stop.  */
  set_state (this, ptid, THREAD_RUNNING);
  set_internal_state (this, ptid, THREAD_INT_RUNNING);

  return th;
}

/* Delete a thread from the list of threads.

   PTID is the ptid of the thread to be deleted.
   EXIT_CODE is the thread's exit code.
   MAIN_THREAD_P should be true if the thread to be deleted is
   the main thread, false otherwise.  */

void
windows_nat_target::delete_thread (ptid_t ptid, DWORD exit_code,
				   bool main_thread_p)
{
  /* Note that no notification was printed when the main thread was
     created, and thus, unless in verbose mode, we should be symmetrical,
     and avoid an exit notification for the main thread here as well.  */

  bool silent = (main_thread_p && !info_verbose);
  thread_info *to_del = this->find_thread (ptid);
  delete_thread_with_exit_code (to_del, exit_code, silent);
}

/* Fetches register number R from the given windows_thread_info,
   and supplies its value to the given regcache.

   This function assumes that R is non-negative.  A failed assertion
   is raised if that is not true.  */

static void
windows_fetch_one_register (struct regcache *regcache,
			    windows_thread_info *th, int r)
{
  gdb_assert (r >= 0);

  char *context_ptr = windows_process.with_context (th, [] (auto *context)
    {
      return (char *) context;
    });

  char *context_offset = context_ptr + windows_process.mappings[r];
  struct gdbarch *gdbarch = regcache->arch ();
  i386_gdbarch_tdep *tdep = gdbarch_tdep<i386_gdbarch_tdep> (gdbarch);

  gdb_assert (!gdbarch_read_pc_p (gdbarch));
  gdb_assert (gdbarch_pc_regnum (gdbarch) >= 0);
  gdb_assert (!gdbarch_write_pc_p (gdbarch));

  /* GDB treats some registers as 32-bit, where they are in fact only
     16 bits long.  These cases must be handled specially to avoid
     reading extraneous bits from the context.  */
  if (r == I387_FISEG_REGNUM (tdep) || windows_process.segment_register_p (r))
    {
      gdb_byte bytes[4] = {};
      memcpy (bytes, context_offset, 2);
      regcache->raw_supply (r, bytes);
    }
  else if (r == I387_FOP_REGNUM (tdep))
    {
      long l = (*((long *) context_offset) >> 16) & ((1 << 11) - 1);
      regcache->raw_supply (r, &l);
    }
  else
    {
      if (th->stopped_at_software_breakpoint
	  && !th->pc_adjusted
	  && r == gdbarch_pc_regnum (gdbarch))
	{
	  int size = register_size (gdbarch, r);
	  if (size == 4)
	    {
	      uint32_t value;
	      memcpy (&value, context_offset, size);
	      value -= gdbarch_decr_pc_after_break (gdbarch);
	      memcpy (context_offset, &value, size);
	    }
	  else
	    {
	      gdb_assert (size == 8);
	      uint64_t value;
	      memcpy (&value, context_offset, size);
	      value -= gdbarch_decr_pc_after_break (gdbarch);
	      memcpy (context_offset, &value, size);
	    }
	  /* Make sure we only rewrite the PC a single time.  */
	  th->pc_adjusted = true;
	}
      regcache->raw_supply (r, context_offset);
    }
}

void
windows_per_inferior::fill_thread_context (windows_thread_info *th)
{
   windows_process.with_context (th, [&] (auto *context)
     {
       if (context->ContextFlags == 0)
	 {
	   context->ContextFlags = WindowsContext<decltype(context)>::all;
	   CHECK (get_thread_context (th->h, context));
	 }
     });
}

void
windows_nat_target::fetch_registers (struct regcache *regcache, int r)
{
  windows_thread_info *th = windows_process.find_thread (regcache->ptid ());

  /* Check if TH exists.  Windows sometimes uses a non-existent
     thread id in its events.  */
  if (th == nullptr)
    return;

  windows_process.fill_thread_context (th);

  if (r < 0)
    for (r = 0; r < gdbarch_num_regs (regcache->arch()); r++)
      windows_fetch_one_register (regcache, th, r);
  else
    windows_fetch_one_register (regcache, th, r);
}

/* Collect the register number R from the given regcache, and store
   its value into the corresponding area of the given thread's context.

   This function assumes that R is non-negative.  A failed assertion
   assertion is raised if that is not true.  */

static void
windows_store_one_register (const struct regcache *regcache,
			    windows_thread_info *th, int r)
{
  gdb_assert (r >= 0);

  char *context_ptr = windows_process.with_context (th, [] (auto *context)
    {
      gdb_assert (context->ContextFlags != 0);
      return (char *) context;
    });

  struct gdbarch *gdbarch = regcache->arch ();
  i386_gdbarch_tdep *tdep = gdbarch_tdep<i386_gdbarch_tdep> (gdbarch);

  /* GDB treats some registers as 32-bit, where they are in fact only
     16 bits long.  These cases must be handled specially to avoid
     overwriting other registers in the context.  */
  if (r == I387_FISEG_REGNUM (tdep) || windows_process.segment_register_p (r))
    {
      gdb_byte bytes[4];
      regcache->raw_collect (r, bytes);
      memcpy (context_ptr + windows_process.mappings[r], bytes, 2);
    }
  else if (r == I387_FOP_REGNUM (tdep))
    {
      gdb_byte bytes[4];
      regcache->raw_collect (r, bytes);
      /* The value of FOP occupies the top two bytes in the context,
	 so write the two low-order bytes from the cache into the
	 appropriate spot.  */
      memcpy (context_ptr + windows_process.mappings[r] + 2, bytes, 2);
    }
  else
    regcache->raw_collect (r, context_ptr + windows_process.mappings[r]);
}

/* Store a new register value into the context of the thread tied to
   REGCACHE.  */

void
windows_nat_target::store_registers (struct regcache *regcache, int r)
{
  windows_thread_info *th = windows_process.find_thread (regcache->ptid ());

  /* Check if TH exists.  Windows sometimes uses a non-existent
     thread id in its events.  */
  if (th == NULL)
    return;

  if (r < 0)
    for (r = 0; r < gdbarch_num_regs (regcache->arch ()); r++)
      windows_store_one_register (regcache, th, r);
  else
    windows_store_one_register (regcache, th, r);
}

/* See nat/windows-nat.h.  */

static windows_solib *
windows_make_so (const char *name, LPVOID load_addr)
{
  windows_solib *so = &windows_process.solibs.emplace_back ();
  so->load_addr = load_addr;
  so->original_name = name;

#ifndef __CYGWIN__
  char *p;
  char buf[__PMAX];
  char cwd[__PMAX];
  WIN32_FIND_DATA w32_fd;
  HANDLE h = FindFirstFile(name, &w32_fd);

  if (h == INVALID_HANDLE_VALUE)
    strcpy (buf, name);
  else
    {
      FindClose (h);
      strcpy (buf, name);
      if (GetCurrentDirectory (MAX_PATH + 1, cwd))
	{
	  p = strrchr (buf, '\\');
	  if (p)
	    p[1] = '\0';
	  SetCurrentDirectory (buf);
	  GetFullPathName (w32_fd.cFileName, MAX_PATH, buf, &p);
	  SetCurrentDirectory (cwd);
	}
    }
  if (strcasecmp (buf, "ntdll.dll") == 0)
    {
      GetSystemDirectory (buf, sizeof (buf));
      strcat (buf, "\\ntdll.dll");
    }

  so->name = buf;
#else
  wchar_t buf[__PMAX];

  buf[0] = 0;
  if (access (name, F_OK) != 0)
    {
      if (strcasecmp (name, "ntdll.dll") == 0)
	{
	  GetSystemDirectoryW (buf, sizeof (buf) / sizeof (wchar_t));
	  wcscat (buf, L"\\ntdll.dll");
	}
    }
  if (buf[0])
    {
      bool ok = false;

      /* Check how big the output buffer has to be.  */
      ssize_t size = cygwin_conv_path (CCP_WIN_W_TO_POSIX, buf, nullptr, 0);
      if (size > 0)
	{
	  /* SIZE includes the null terminator.  */
	  so->name.resize (size - 1);
	  if (cygwin_conv_path (CCP_WIN_W_TO_POSIX, buf, so->name.data (),
				size) == 0)
	    ok = true;
	}
      if (!ok)
	so->name = so->original_name;
    }
  else
    {
      gdb::unique_xmalloc_ptr<char> rname = gdb_realpath (name);
      if (rname != nullptr)
	so->name = rname.get ();
      else
	{
	  warning (_("dll path for \"%s\" inaccessible"), name);
	  so->name = so->original_name;
	}
    }
  /* Record cygwin1.dll .text start/end.  */
  size_t len = sizeof ("/cygwin1.dll") - 1;
  if (so->name.size () >= len
      && strcasecmp (so->name.c_str () + so->name.size () - len,
		     "/cygwin1.dll") == 0)
    {
      asection *text = NULL;

      gdb_bfd_ref_ptr abfd (gdb_bfd_open (so->name.c_str(), "pei-i386"));

      if (abfd == NULL)
	return so;

      if (bfd_check_format (abfd.get (), bfd_object))
	text = bfd_get_section_by_name (abfd.get (), ".text");

      if (!text)
	return so;

      /* The symbols in a dll are offset by 0x1000, which is the
	 offset from 0 of the first byte in an image - because of the
	 file header and the section alignment.  */
      windows_process.cygwin_load_start = (CORE_ADDR) (uintptr_t) ((char *)
								   load_addr + 0x1000);
      windows_process.cygwin_load_end = windows_process.cygwin_load_start +
	bfd_section_size (text);
    }
#endif

  return so;
}

/* See nat/windows-nat.h.  */

void
windows_per_inferior::handle_load_dll (const char *dll_name, LPVOID base)
{
  windows_solib *solib = windows_make_so (dll_name, base);
  DEBUG_EVENTS ("Loading dll \"%s\" at %s.", solib->name.c_str (),
		host_address_to_string (solib->load_addr));
}

/* See nat/windows-nat.h.  */

void
windows_per_inferior::handle_unload_dll (const DEBUG_EVENT &current_event)
{
  LPVOID lpBaseOfDll = current_event.u.UnloadDll.lpBaseOfDll;

  auto iter = std::remove_if (windows_process.solibs.begin (),
			      windows_process.solibs.end (),
			      [&] (windows_solib &lib)
    {
      if (lib.load_addr == lpBaseOfDll)
	{
	  DEBUG_EVENTS ("Unloading dll \"%s\".", lib.name.c_str ());
	  return true;
	}
      return false;
    });

  if (iter != windows_process.solibs.end ())
    {
      windows_process.solibs.erase (iter, windows_process.solibs.end ());
      return;
    }

  /* We did not find any DLL that was previously loaded at this address,
     so register a complaint.  We do not report an error, because we have
     observed that this may be happening under some circumstances.  For
     instance, running 32bit applications on x64 Windows causes us to receive
     4 mysterious UNLOAD_DLL_DEBUG_EVENTs during the startup phase (these
     events are apparently caused by the WOW layer, the interface between
     32bit and 64bit worlds).  */
  complaint (_("dll starting at %s not found."),
	     host_address_to_string (lpBaseOfDll));
}

/* Clear list of loaded DLLs.  */
static void
windows_clear_solib (void)
{
  windows_process.solibs.clear ();
}

static void
signal_event_command (const char *args, int from_tty)
{
  uintptr_t event_id = 0;
  char *endargs = NULL;

  if (args == NULL)
    error (_("signal-event requires an argument (integer event id)"));

  event_id = strtoumax (args, &endargs, 10);

  if ((errno == ERANGE) || (event_id == 0) || (event_id > UINTPTR_MAX) ||
      ((HANDLE) event_id == INVALID_HANDLE_VALUE))
    error (_("Failed to convert `%s' to event id"), args);

  SetEvent ((HANDLE) event_id);
  CloseHandle ((HANDLE) event_id);
}

/* See nat/windows-nat.h.  */

bool
windows_per_inferior::handle_output_debug_string
  (const DEBUG_EVENT &current_event,
   struct target_waitstatus *ourstatus)
{
  windows_thread_info *event_thr
    = windows_process.find_thread (ptid_t (current_event.dwProcessId,
					   current_event.dwThreadId));
  if (event_thr->reply_later != 0)
    internal_error ("OutputDebugString thread 0x%x has reply-later set",
		    event_thr->tid);

  gdb::unique_xmalloc_ptr<char> s
    = (target_read_string
       ((CORE_ADDR) (uintptr_t) current_event.u.DebugString.lpDebugStringData,
	1024));
  if (s == nullptr || !*(s.get ()))
    /* nothing to do */;
  else if (!startswith (s.get (), _CYGWIN_SIGNAL_STRING))
    {
#ifdef __CYGWIN__
      if (!startswith (s.get (), "cYg"))
#endif
	{
	  char *p = strchr (s.get (), '\0');

	  if (p > s.get () && *--p == '\n')
	    *p = '\0';
	  warning (("%s"), s.get ());
	}
    }
#ifdef __CYGWIN__
  else
    {
      /* Got a cygwin signal marker.  A cygwin signal marker is
	 followed by the signal number itself, and (since Cygwin 1.7)
	 the thread id, and the address of a saved context in the
	 inferior (That context has an IP which is the return address
	 in "user" code of the cygwin internal signal handling code,
	 but is not otherwise usable).

	 Tell gdb to treat this like the given thread issued a real
	 signal.  */
      char *p;
      int sig = strtol (s.get () + sizeof (_CYGWIN_SIGNAL_STRING) - 1, &p, 0);
      gdb_signal gotasig = gdb_signal_from_host (sig);
      LPCVOID x = 0;
      DWORD thread_id = 0;

      if (gotasig != GDB_SIGNAL_0)
	{
	  thread_id = strtoul (p, &p, 0);
	  if (thread_id != 0)
	    {
	      x = (LPCVOID) (uintptr_t) strtoull (p, NULL, 0);

	      ptid_t ptid (current_event.dwProcessId, thread_id, 0);
	      windows_thread_info *th = find_thread (ptid);

	      /* Suspend the signaled thread, and leave the signal as
		 a pending event.  It will be picked up by
		 windows_nat_target::wait.  */
	      th->suspend ();
	      th->stopping = SK_EXTERNAL;
	      th->last_event = {};
	      th->pending_status.set_stopped (gotasig);

	      /* Link the "sig" thread and the signaled threads, so we
		 can keep the "sig" thread suspended until we resume
		 the signaled thread.  See "Cygwin signals" at the
		 top.  */
	      event_thr->signaled_thread = th;
	      th->cygwin_sig_thread = event_thr;

	      /* Leave the "sig" thread suspended.  */
	      event_thr->suspend ();
	      return true;
	    }
	}

      DEBUG_EVENTS ("gdb: cygwin signal %d, thread 0x%x, CONTEXT @ %p",
		    gotasig, thread_id, x);
    }
#endif

  return false;
}

static int
display_selector (HANDLE thread, DWORD sel)
{
  LDT_ENTRY info;
  BOOL ret = windows_process.with_context (nullptr, [&] (auto *context)
    {
      return get_thread_selector_entry (context, thread, sel, &info);
    });
  if (ret)
    {
      int base, limit;
      gdb_printf ("0x%03x: ", (unsigned) sel);
      if (!info.HighWord.Bits.Pres)
	{
	  gdb_puts ("Segment not present\n");
	  return 0;
	}
      base = (info.HighWord.Bits.BaseHi << 24) +
	     (info.HighWord.Bits.BaseMid << 16)
	     + info.BaseLow;
      limit = (info.HighWord.Bits.LimitHi << 16) + info.LimitLow;
      if (info.HighWord.Bits.Granularity)
	limit = (limit << 12) | 0xfff;
      gdb_printf ("base=0x%08x limit=0x%08x", base, limit);
      if (info.HighWord.Bits.Default_Big)
	gdb_puts(" 32-bit ");
      else
	gdb_puts(" 16-bit ");
      switch ((info.HighWord.Bits.Type & 0xf) >> 1)
	{
	case 0:
	  gdb_puts ("Data (Read-Only, Exp-up");
	  break;
	case 1:
	  gdb_puts ("Data (Read/Write, Exp-up");
	  break;
	case 2:
	  gdb_puts ("Unused segment (");
	  break;
	case 3:
	  gdb_puts ("Data (Read/Write, Exp-down");
	  break;
	case 4:
	  gdb_puts ("Code (Exec-Only, N.Conf");
	  break;
	case 5:
	  gdb_puts ("Code (Exec/Read, N.Conf");
	  break;
	case 6:
	  gdb_puts ("Code (Exec-Only, Conf");
	  break;
	case 7:
	  gdb_puts ("Code (Exec/Read, Conf");
	  break;
	default:
	  gdb_printf ("Unknown type 0x%lx",
		      (unsigned long) info.HighWord.Bits.Type);
	}
      if ((info.HighWord.Bits.Type & 0x1) == 0)
	gdb_puts(", N.Acc");
      gdb_puts (")\n");
      if ((info.HighWord.Bits.Type & 0x10) == 0)
	gdb_puts("System selector ");
      gdb_printf ("Privilege level = %ld. ",
		  (unsigned long) info.HighWord.Bits.Dpl);
      if (info.HighWord.Bits.Granularity)
	gdb_puts ("Page granular.\n");
      else
	gdb_puts ("Byte granular.\n");
      return 1;
    }
  else
    {
      DWORD err = GetLastError ();
      if (err == ERROR_NOT_SUPPORTED)
	gdb_printf ("Function not supported\n");
      else
	gdb_printf ("Invalid selector 0x%x.\n", (unsigned) sel);
      return 0;
    }
}

static void
display_selectors (const char * args, int from_tty)
{
  if (inferior_ptid == null_ptid)
    {
      gdb_puts ("Impossible to display selectors now.\n");
      return;
    }

  windows_thread_info *current_windows_thread
    = windows_process.find_thread (inferior_ptid);

  if (!args)
    {
      windows_process.with_context (current_windows_thread, [&] (auto *context)
	{
	  gdb_puts ("Selector $cs\n");
	  display_selector (current_windows_thread->h, context->SegCs);
	  gdb_puts ("Selector $ds\n");
	  display_selector (current_windows_thread->h, context->SegDs);
	  gdb_puts ("Selector $es\n");
	  display_selector (current_windows_thread->h, context->SegEs);
	  gdb_puts ("Selector $ss\n");
	  display_selector (current_windows_thread->h, context->SegSs);
	  gdb_puts ("Selector $fs\n");
	  display_selector (current_windows_thread->h, context->SegFs);
	  gdb_puts ("Selector $gs\n");
	  display_selector (current_windows_thread->h, context->SegGs);
	});
    }
  else
    {
      int sel;
      sel = parse_and_eval_long (args);
      gdb_printf ("Selector \"%s\"\n",args);
      display_selector (current_windows_thread->h, sel);
    }
}

/* See nat/windows-nat.h.  */

bool
windows_per_inferior::handle_access_violation
     (const EXCEPTION_RECORD *rec)
{
#ifdef __CYGWIN__
  /* See if the access violation happened within the cygwin DLL
     itself.  Cygwin uses a kind of exception handling to deal with
     passed-in invalid addresses.  gdb should not treat these as real
     SEGVs since they will be silently handled by cygwin.  A real SEGV
     will (theoretically) be caught by cygwin later in the process and
     will be sent as a cygwin-specific-signal.  So, ignore SEGVs if
     they show up within the text segment of the DLL itself.  */
  const char *fn;
  CORE_ADDR addr = (CORE_ADDR) (uintptr_t) rec->ExceptionAddress;

  if ((!cygwin_exceptions && (addr >= cygwin_load_start
			      && addr < cygwin_load_end))
      || (find_pc_partial_function (addr, &fn, NULL, NULL)
	  && startswith (fn, "KERNEL32!IsBad")))
    return true;
#endif
  return false;
}

void
windows_per_inferior::continue_one_thread (windows_thread_info *th,
					   windows_continue_flags cont_flags)
{
  struct x86_debug_reg_state *state = x86_debug_reg_state (process_id);

  /* If this thread is already gone, but the core doesn't know about
     it yet, there's really nothing to resume.  Such a thread will
     have a pending exit status, so we won't try to resume it in the
     normal resume path.  But, we can still end up here in the
     kill/detach/mourn paths, trying to resume the whole process to
     collect the last debug event.  */
  if (th->h == nullptr)
    return;

  windows_process.with_context (th, [&] (auto *context)
    {
      if (th->debug_registers_changed)
	{
	  windows_process.fill_thread_context (th);

	  gdb_assert ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != 0);

	  /* Check whether the thread has Dr6 set indicating a
	     watchpoint hit, and we haven't seen the watchpoint event
	     yet (reported as
	     EXCEPTION_SINGLE_STEP/STATUS_WX86_SINGLE_STEP).  In that
	     case, don't change the debug registers.  Changing debug
	     registers, even if to the same values, makes the kernel
	     clear Dr6.  The result would be we would lose the
	     unreported watchpoint hit.  */
	  if ((context->Dr6 & ~DR6_CLEAR_VALUE) != 0)
	    {
	      if (th->last_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
		  && (th->last_event.u.Exception.ExceptionRecord.ExceptionCode
		      == EXCEPTION_SINGLE_STEP
		      || (th->last_event.u.Exception.ExceptionRecord.ExceptionCode
			  == STATUS_WX86_SINGLE_STEP)))
		{
		  DEBUG_EVENTS ("0x%x already reported watchpoint", th->tid);
		}
	      else
		{
		  DEBUG_EVENTS ("0x%x last reported something else (0x%x)",
				th->tid,
				th->last_event.dwDebugEventCode);

		  /* Don't touch debug registers.  Let the pending
		     watchpoint event be reported instead.  We will
		     update the debug registers later when the thread
		     is re-resumed by the core after the watchpoint
		     event.  */
		  context->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
		}
	    }
	  else
	    DEBUG_EVENTS ("0x%x has no dr6 set", th->tid);

	  if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != 0)
	    {
	      DEBUG_EVENTS ("0x%x changing dregs", th->tid);
	      context->Dr0 = state->dr_mirror[0];
	      context->Dr1 = state->dr_mirror[1];
	      context->Dr2 = state->dr_mirror[2];
	      context->Dr3 = state->dr_mirror[3];
	      context->Dr6 = DR6_CLEAR_VALUE;
	      context->Dr7 = state->dr_control_mirror;
	    }

	  th->debug_registers_changed = false;
	}
      if (context->ContextFlags)
	{
	  DWORD ec = 0;

	  if (GetExitCodeThread (th->h, &ec)
	      && ec == STILL_ACTIVE)
	    {
	      BOOL status = set_thread_context (th->h, context);

	      if ((cont_flags & WCONT_KILLED) == 0)
		CHECK (status);
	    }
	  context->ContextFlags = 0;
	}
    });

  th->resume ();
  th->stopping = SK_NOT_STOPPING;
  th->last_sig = GDB_SIGNAL_0;
}

/* Resume thread specified by ID, or all artificially suspended
   threads, if we are continuing execution.  See description of
   windows_continue_flags for CONT_FLAGS.  */

BOOL
windows_nat_target::windows_continue (DWORD continue_status, int id,
				      windows_continue_flags cont_flags)
{
  if ((cont_flags & (WCONT_LAST_CALL | WCONT_KILLED)) == 0)
    for (auto *th : all_windows_threads ())
      {
	if ((id == -1 || id == (int) th->tid)
	    && th->pending_status.kind () != TARGET_WAITKIND_IGNORE)
	  {
	    DEBUG_EVENTS ("got matching pending stop event "
			  "for 0x%x, not resuming",
			  th->tid);

	    /* There's no need to really continue, because there's already
	       another event pending.  However, we do need to inform the
	       event loop of this.  */
	    serial_event_set (m_wait_event);
	    return TRUE;
	  }
      }

  /* Resume any suspended thread whose ID matches "ID".  Skip the
     Cygwin "sig" thread in the main iteration, though.  That one is
     only resumed when the target signaled thread is resumed.  See
     "Cygwin signals" in the intro section.  */
  for (auto *th : all_windows_threads ())
    if (th->suspended
#ifdef __CYGWIN__
	&& th->signaled_thread == nullptr
#endif
	&& (id == -1 || id == (int) th->tid))
      {
	windows_process.continue_one_thread (th, cont_flags);

#ifdef __CYGWIN__
	/* See if we're resuming a thread that caught a Cygwin signal.
	   If so, also resume the Cygwin runtime's "sig" thread.  */
	if (th->cygwin_sig_thread != nullptr)
	  {
	    DEBUG_EVENTS ("\"sig\" thread %d (0x%x) blocked by "
			  "just-resumed thread %d (0x%x)",
			  th->cygwin_sig_thread->tid,
			  th->cygwin_sig_thread->tid,
			  th->tid, th->tid);

	    inferior *inf = find_inferior_pid (this,
					       windows_process.process_id);
	    thread_info *sig_thr
	      = inf->find_thread (ptid_t (windows_process.process_id,
					  th->cygwin_sig_thread->tid));
	    if (sig_thr->internal_state () == THREAD_INT_RUNNING)
	      {
		DEBUG_EVENTS ("\"sig\" thread %d (0x%x) meant to be running, "
			      "continuing it now",
			      th->cygwin_sig_thread->tid,
			      th->cygwin_sig_thread->tid);
		windows_process.continue_one_thread (th->cygwin_sig_thread,
						     cont_flags);
	      }
	    /* Break the chain.  */
	    th->cygwin_sig_thread->signaled_thread = nullptr;
	    th->cygwin_sig_thread = nullptr;
	  }
#endif
      }

  /* WCONT_DONT_CONTINUE_DEBUG_EVENT and WCONT_CONTINUE_DEBUG_EVENT
     can't both be enabled at the same time.  */
  gdb_assert ((cont_flags & WCONT_DONT_CONTINUE_DEBUG_EVENT) == 0
	      || (cont_flags & WCONT_CONTINUE_DEBUG_EVENT) == 0);

  bool continue_debug_event;
  if ((cont_flags & WCONT_CONTINUE_DEBUG_EVENT) != 0)
    continue_debug_event = true;
  else if ((cont_flags & WCONT_DONT_CONTINUE_DEBUG_EVENT) != 0)
    continue_debug_event = false;
  else
    continue_debug_event = !target_is_non_stop_p ();
  if (continue_debug_event)
    {
      DEBUG_EVENTS ("windows_continue -> continue_last_debug_event");
      continue_last_debug_event_main_thread
	(_("Failed to resume program execution"), continue_status,
	 cont_flags & WCONT_LAST_CALL);
    }

  return TRUE;
}

/* Called in pathological case where Windows fails to send a
   CREATE_PROCESS_DEBUG_EVENT after an attach.  */
DWORD
windows_nat_target::fake_create_process (const DEBUG_EVENT &current_event)
{
  windows_process.handle
    = OpenProcess (PROCESS_ALL_ACCESS, FALSE,
		   current_event.dwProcessId);
  if (windows_process.handle != NULL)
    windows_process.open_process_used = 1;
  else
    {
      unsigned err = (unsigned) GetLastError ();
      throw_winerror_with_name (_("OpenProcess call failed"), err);
      /*  We can not debug anything in that case.  */
    }
  add_thread (ptid_t (current_event.dwProcessId, current_event.dwThreadId, 0),
		      current_event.u.CreateThread.hThread,
		      current_event.u.CreateThread.lpThreadLocalBase,
		      true /* main_thread_p */);
  return current_event.dwThreadId;
}

/* Prepare TH to be resumed.  TH and TP must point at the same thread.
   Records the right dwContinueStatus for SIG in th->reply_later if we
   used DBG_REPLY_LATER before on this thread, and sets of clears the
   trace flag according to STEP.  Also returns the dwContinueStatus
   argument to pass to ContinueDebugEvent.  The thread is still left
   suspended -- a subsequent windows_continue/continue_one_thread call
   is needed to flush the thread's register context and unsuspend.  */

DWORD
windows_nat_target::prepare_resume (windows_thread_info *th,
				    thread_info *tp,
				    int step, gdb_signal sig)
{
  gdb_assert (th->tid == tp->ptid.lwp ());

  DWORD continue_status = DBG_CONTINUE;

  if (sig != GDB_SIGNAL_0)
    {
      /* Allow continuing with the same signal that interrupted us.
	 Otherwise complain.  */

      /* Note it is OK to call get_last_debug_event_ptid() from the
	 main thread here in all-stop, because we know the
	 process_thread thread is not waiting for an event at this
	 point, so there is no data race.  We cannot call it in
	 non-stop mode, as the process_thread thread _is_ waiting for
	 events right now in that case.  However, the restriction does
	 not exist in non-stop mode, so we don't even call it in that
	 mode.  */
      if (!target_is_non_stop_p ()
	  && tp->ptid != get_last_debug_event_ptid ())
	{
	  /* In all-stop, ContinueDebugEvent will be for a different
	     thread.  For non-stop, we've called ContinueDebugEvent
	     with DBG_REPLY_LATER for this thread, so we just set the
	     intended continue status in 'reply_later', which is later
	     passed to ContinueDebugEvent in windows_nat_target::wait
	     after we resume the thread and we get the replied-later
	     (repeated) event out of WaitForDebugEvent.  */
	  DEBUG_EXCEPT ("Cannot continue with signal %d here.  "
			"Not last-event thread", sig);
	}
      else if (th->last_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
	{
	  DEBUG_EXCEPT ("Cannot continue with signal %d here.  "
			"Not stopped for EXCEPTION_DEBUG_EVENT", sig);
	}
      else if (sig == th->last_sig)
	continue_status = DBG_EXCEPTION_NOT_HANDLED;
      else
#if 0
/* This code does not seem to work, because
  the kernel does probably not consider changes in the ExceptionRecord
  structure when passing the exception to the inferior.
  Note that this seems possible in the exception handler itself.  */
	{
	  for (const xlate_exception &x : xlate)
	    if (x.us == sig)
	      {
		th->last_event.u.Exception.ExceptionRecord.ExceptionCode
		  = x.them;
		continue_status = DBG_EXCEPTION_NOT_HANDLED;
		break;
	      }
	  if (continue_status == DBG_CONTINUE)
	    {
	      DEBUG_EXCEPT ("Cannot continue with signal %d.", sig);
	    }
	}
#endif
      DEBUG_EXCEPT ("Can only continue with received signal %d.",
		    th->last_sig);
    }

  /* If DBG_REPLY_LATER was used on the thread, we override the
     continue status that will be passed to ContinueDebugEvent later
     with the continue status we've just determined fulfils the
     caller's resumption request.  Note that DBG_REPLY_LATER is only
     used in non-stop mode, and in that mode, windows_continue (called
     below) does not call ContinueDebugEvent.  */
  if (th->reply_later != 0)
    th->reply_later = continue_status;

  /* Single step by setting t bit (trap flag).  The trap flag is
     automatically reset as soon as the single-step exception arrives,
     however, it's possible to suspend/stop a thread before it
     executes any instruction, leaving the trace flag set.  If we
     subsequently decide to continue such a thread instead of stepping
     it, and we didn't clear the trap flag, the thread would step, and
     we'd end up reporting a SIGTRAP to the core which the core
     couldn't explain (because the thread wasn't supposed to be
     stepping), and end up reporting a spurious SIGTRAP to the
     user.  */
  regcache *regcache = get_thread_regcache (tp);
  fetch_registers (regcache, gdbarch_ps_regnum (regcache->arch ()));

  windows_process.with_context (th, [&] (auto *context)
    {
      if (step)
	context->EFlags |= FLAG_TRACE_BIT;
      else
	context->EFlags &= ~FLAG_TRACE_BIT;
    });

  return continue_status;
}

void
windows_nat_target::resume (ptid_t ptid, int step, enum gdb_signal sig)
{
  /* A specific PTID means `step only this thread id'.  */
  int resume_all = ptid == minus_one_ptid;

  /* If we're continuing all threads, it's the current inferior that
     should be handled specially.  */
  if (resume_all)
    ptid = inferior_ptid;

  DEBUG_EXEC ("pid=%d, tid=0x%x, step=%d, sig=%d",
	      ptid.pid (), (unsigned) ptid.lwp (), step, sig);

  /* Get currently selected thread.  */
  windows_thread_info *th = windows_process.find_thread (inferior_ptid);
  gdb_assert (th != nullptr);

  DWORD continue_status = prepare_resume (th, inferior_thread (), step, sig);

  if (resume_all)
    windows_continue (continue_status, -1);
  else
    windows_continue (continue_status, ptid.lwp ());
}

/* Interrupt the inferior.  */

void
windows_nat_target::interrupt ()
{
  DEBUG_EVENTS ("interrupt");
#ifdef __x86_64__
  if (windows_process.wow64_process)
    {
      /* Call DbgUiRemoteBreakin of the 32bit ntdll.dll in the target process.
	 DebugBreakProcess would call the one of the 64bit ntdll.dll, which
	 can't be correctly handled by gdb.  */
      if (windows_process.wow64_dbgbreak == nullptr)
	{
	  CORE_ADDR addr;
	  if (!find_minimal_symbol_address ("ntdll!DbgUiRemoteBreakin",
					    &addr, 0))
	    windows_process.wow64_dbgbreak = (void *) addr;
	}

      if (windows_process.wow64_dbgbreak != nullptr)
	{
	  HANDLE thread = CreateRemoteThread (windows_process.handle, NULL,
					      0, (LPTHREAD_START_ROUTINE)
					      windows_process.wow64_dbgbreak,
					      NULL, 0, NULL);
	  if (thread)
	    {
	      CloseHandle (thread);
	      return;
	    }
	}
    }
  else
#endif
    if (DebugBreakProcess (windows_process.handle))
      return;
  warning (_("Could not interrupt program.  "
	     "Press Ctrl-c in the program console."));
}

/* Stop thread TH, for STOPPING_KIND reason.  This leaves a
   GDB_SIGNAL_0 pending in the thread, which is later consumed by
   windows_nat_target::wait.  */

void
windows_nat_target::stop_one_thread (windows_thread_info *th,
				     enum stopping_kind stopping_kind)
{
  ptid_t thr_ptid (windows_process.process_id, th->tid);

  if (th->suspended == -1)
    {
      /* Already known to be stopped; and suspension failed, most
	 probably because the thread is exiting.  Do nothing, and let
	 the thread exit event be reported.  */
      DEBUG_EVENTS ("already suspended %s: suspended=%d, stopping=%d",
		    thr_ptid.to_string ().c_str (),
		    th->suspended, th->stopping);
    }
#ifdef __CYGWIN__
  else if (th->suspended
	   && th->signaled_thread != nullptr
	   && th->pending_status.kind () == TARGET_WAITKIND_IGNORE
	   /* If doing an internal stop to update debug registers,
	      then just leave the "sig" thread suspended.  Otherwise
	      windows_nat_target::wait would incorrectly break the
	      signaled_thread lock when it later processes the pending
	      stop and calls windows_continue on this thread.  */
	   && stopping_kind == SK_EXTERNAL)
    {
      DEBUG_EVENTS ("explict stop for \"sig\" thread %s held for signal",
		    thr_ptid.to_string ().c_str ());

      th->stopping = stopping_kind;
      th->pending_status.set_stopped (GDB_SIGNAL_0);
      th->last_event = {};
      serial_event_set (m_wait_event);
    }
#endif
  else if (th->suspended)
    {
      /* Already known to be stopped; do nothing.  */

      DEBUG_EVENTS ("already suspended %s: suspended=%d, stopping=%d",
		    thr_ptid.to_string ().c_str (),
		    th->suspended, th->stopping);

      /* Upgrade stopping.  */
      if (stopping_kind > th->stopping)
	th->stopping = stopping_kind;
    }
  else
    {
      DEBUG_EVENTS ("stop request for %s", thr_ptid.to_string ().c_str ());

      th->suspend ();

      /* If suspension failed, it means the thread is exiting.  Let
	 the thread exit event be reported instead of faking our own
	 stop.  */
      if (th->suspended == -1)
	{
	  DEBUG_EVENTS ("suspension of %s failed, expect thread exit event",
			thr_ptid.to_string ().c_str ());
	  if (stopping_kind > th->stopping)
	    th->stopping = stopping_kind;
	  return;
	}

      gdb_assert (th->suspended == 1);

      if (stopping_kind > th->stopping)
	{
	  th->stopping = stopping_kind;
	  th->pending_status.set_stopped (GDB_SIGNAL_0);
	  th->last_event = {};
	}

      serial_event_set (m_wait_event);
    }
}

/* Implementation of target_ops::stop.  */

void
windows_nat_target::stop (ptid_t ptid)
{
  for (thread_info *thr : all_non_exited_threads (this))
    {
      if (thr->ptid.matches (ptid))
	stop_one_thread (as_windows_thread_info (thr), SK_EXTERNAL);
    }
}

void
windows_nat_target::pass_ctrlc ()
{
  interrupt ();
}

/* Implementation of the target_ops::thread_events method.  */

void
windows_nat_target::thread_events (bool enable)
{
  DEBUG_EVENTS ("windows_nat_target::thread_events(%d)", enable);
  m_report_thread_events = enable;
}

/* True if there is any resumed thread.  */

bool
windows_nat_target::any_resumed_thread ()
{
  for (thread_info *thread : all_non_exited_threads (this))
    if (thread->internal_state () == THREAD_INT_RUNNING)
      return true;
  return false;
}

/* Called for both EXIT_THREAD_DEBUG_EVENT and
   EXIT_PROCESS_DEBUG_EVENT to handle the fact that the event thread
   has exited.  */

static void
handle_thread_exit (const DEBUG_EVENT &current_event)
{
  ptid_t ptid (current_event.dwProcessId, current_event.dwThreadId);
  windows_thread_info *th = windows_process.find_thread (ptid);
  gdb_assert (th != nullptr);

  /* The handle is still valid, but it is going to be automatically
     closed by Windows when we next call ContinueDebugEvent.  Fetch
     the thread's registers while we still can.  For EXIT_PROCESS,
     ContinueDebugEvent only happens at target_mourn_inferior time,
     but do this not too, for consistency with EXIT_THREAD time.  */
  windows_process.fill_thread_context (th);
  th->h = nullptr;

  /* The thread is gone, so no longer suspended from Windows's
     perspective.  */
  th->suspended = -1;
}

/* Get the next event from the child.  Returns the thread ptid.  */

ptid_t
windows_nat_target::get_windows_debug_event
  (int pid, struct target_waitstatus *ourstatus, target_wait_flags options,
   DEBUG_EVENT *current_event)
{
  DWORD continue_status, event_code;
  DWORD thread_id = 0;

  /* If there is a relevant pending stop, report it now.  See the
     comment by the definition of "windows_thread_info::pending_status"
     for details on why this is needed.  */
  for (thread_info *thread : all_threads_safe ())
    {
      if (thread->inf->process_target () != this)
	continue;

      auto *th = as_windows_thread_info (thread);
      if (thread->internal_state () == THREAD_INT_RUNNING
	  && th->suspended
	  && th->pending_status.kind () != TARGET_WAITKIND_IGNORE)
	{
	  *ourstatus = th->pending_status;
	  th->pending_status.set_ignore ();
	  *current_event = th->last_event;
	  DEBUG_EVENTS ("reporting pending event for 0x%x", th->tid);
	  return thread->ptid;
	}
    }

  /* If there are no resumed threads left, bail.  */
  if (windows_process.windows_initialization_done
      && !any_resumed_thread ())
    {
      ourstatus->set_no_resumed ();
      return minus_one_ptid;
    }

  if ((options & TARGET_WNOHANG) != 0 && !m_debug_event_pending)
    {
      ourstatus->set_ignore ();
      return minus_one_ptid;
    }

  wait_for_debug_event_main_thread (current_event);

  continue_status = DBG_CONTINUE;

  event_code = current_event->dwDebugEventCode;
  ourstatus->set_spurious ();

  ptid_t result_ptid (current_event->dwProcessId,
		      current_event->dwThreadId, 0);
  windows_thread_info *result_th = windows_process.find_thread (result_ptid);

  /* If we previously used DBG_REPLY_LATER on this thread, and we're
     seeing an event for it, it means we've already processed the
     event, and then subsequently resumed the thread [1], intending to
     pass REPLY_LATER to ContinueDebugEvent.  Do that now, before the
     switch table below, which may have side effects that don't make
     sense for a delayed event.

     [1] - with the caveat that sometimes Windows reports an event for
     a suspended thread.  Also handled below.  */
  if (result_th != nullptr && result_th->reply_later != 0)
    {
      DEBUG_EVENTS ("reply-later thread 0x%x, suspended=%d, dwDebugEventCode=%s",
		    result_th->tid, result_th->suspended,
		    event_code_to_string (event_code).c_str ());

      gdb_assert (dbg_reply_later_available ());

      /* We never ask to DBG_REPLY_LATER these two, so we shouldn't
	 see them here.  If a thread is forced-exited when a
	 DBG_REPLY_LATER is in effect, then we will still see the
	 DBG_REPLY_LATER-ed event before the thread/process exit
	 event.  */
      gdb_assert (event_code != EXIT_THREAD_DEBUG_EVENT
		  && event_code != EXIT_PROCESS_DEBUG_EVENT);

      if (result_th->suspended == 1)
	{
	  /* Pending stop.  See the comment by the definition of
	     "pending_status" for details on why this is needed.  */
	  DEBUG_EVENTS ("unexpected reply-later stop in suspended thread 0x%x",
			result_th->tid);

	  /* Put the event back in the kernel queue.  We haven't yet
	     decided which reply to use.  */
	  continue_status = DBG_REPLY_LATER;
	}
      else if (result_th->suspended == -1)
	{
	  /* We resumed the thread expecting to get back a reply-later
	     event.  Before we saw that event, we tried to suspend the
	     thread, but that failed, because the thread exited
	     (likely because the whole process has been killed).  We
	     should get back an EXIT_THREAD_DEBUG_EVENT for this
	     thread, but only after getting past this reply-later
	     event.  */
	  DEBUG_EVENTS ("reply-later stop in suspend-failed "
			"thread 0x%x, ignoring",
			result_th->tid);

	  /* Continue normally, and expect a
	     EXIT_THREAD_DEBUG_EVENT.  */
	  continue_status = DBG_CONTINUE;
	  result_th->reply_later = 0;
	}
      else
	{
	  continue_status = result_th->reply_later;
	  result_th->reply_later = 0;
	}

      /* Go back to waiting for the next event.  */
      continue_last_debug_event_main_thread
	(_("Failed to continue reply-later event"), continue_status);

      ourstatus->set_ignore ();
      return null_ptid;
    }

  DEBUG_EVENTS ("kernel event for pid=%u tid=0x%x code=%s",
		(unsigned) current_event->dwProcessId,
		(unsigned) current_event->dwThreadId,
		event_code_to_string (event_code).c_str ());

  switch (event_code)
    {
    case CREATE_THREAD_DEBUG_EVENT:
      if (windows_process.saw_create != 1)
	{
	  inferior *inf = find_inferior_pid (this, current_event->dwProcessId);
	  if (!windows_process.saw_create && inf->attach_flag)
	    {
	      /* Kludge around a Windows bug where first event is a create
		 thread event.  Caused when attached process does not have
		 a main thread.  */
	      thread_id = fake_create_process (*current_event);
	      if (thread_id)
		windows_process.saw_create++;
	    }
	  break;
	}
      /* Record the existence of this thread.  */
      thread_id = current_event->dwThreadId;

      {
	windows_thread_info *th
	  = (add_thread
	     (ptid_t (current_event->dwProcessId, current_event->dwThreadId, 0),
	      current_event->u.CreateThread.hThread,
	      current_event->u.CreateThread.lpThreadLocalBase,
	      false /* main_thread_p */));

	/* Update the debug registers if we're not reporting the stop.
	   If we are (reporting the stop), the debug registers will be
	   updated when the thread is eventually re-resumed.  */
	if (m_report_thread_events)
	  ourstatus->set_thread_created ();
	else
	  windows_process.continue_one_thread (th, 0);
      }
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      {
	ourstatus->set_thread_exited
	  (current_event->u.ExitThread.dwExitCode);
	thread_id = current_event->dwThreadId;

	handle_thread_exit (*current_event);

	/* Don't decide yet whether to report the event, or delete the
	   thread immediately, because we still need to check whether
	   the event should be left pending, depending on whether the
	   thread was running or not from the core's perspective.  */
      }
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      CloseHandle (current_event->u.CreateProcessInfo.hFile);
      if (++windows_process.saw_create != 1)
	break;

      windows_process.handle = current_event->u.CreateProcessInfo.hProcess;
      /* Add the main thread.  */
      add_thread
	(ptid_t (current_event->dwProcessId,
		 current_event->dwThreadId, 0),
	 current_event->u.CreateProcessInfo.hThread,
	 current_event->u.CreateProcessInfo.lpThreadLocalBase,
	 true /* main_thread_p */);
      thread_id = current_event->dwThreadId;
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      if (!windows_process.windows_initialization_done)
	{
	  target_terminal::ours ();
	  target_mourn_inferior (inferior_ptid);
	  error (_("During startup program exited with code 0x%x."),
		 (unsigned int) current_event->u.ExitProcess.dwExitCode);
	}
      else if (windows_process.saw_create == 1)
	{
	  DWORD exit_status = current_event->u.ExitProcess.dwExitCode;
	  /* If the exit status looks like a fatal exception, but we
	     don't recognize the exception's code, make the original
	     exit status value available, to avoid losing
	     information.  */
	  int exit_signal
	    = WIFSIGNALED (exit_status) ? WTERMSIG (exit_status) : -1;
	  if (exit_signal == -1)
	    ourstatus->set_exited (exit_status);
	  else
	    ourstatus->set_signalled (gdb_signal_from_host (exit_signal));

	  thread_id = current_event->dwThreadId;

	  handle_thread_exit (*current_event);
	}
      break;

    case LOAD_DLL_DEBUG_EVENT:
      CloseHandle (current_event->u.LoadDll.hFile);
      if (windows_process.saw_create != 1
	  || ! windows_process.windows_initialization_done)
	break;
      try
	{
	  windows_process.dll_loaded_event (*current_event);
	}
      catch (const gdb_exception &ex)
	{
	  exception_print (gdb_stderr, ex);
	}
      ourstatus->set_loaded ();
      thread_id = current_event->dwThreadId;
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      if (windows_process.saw_create != 1
	  || ! windows_process.windows_initialization_done)
	break;
      try
	{
	  windows_process.handle_unload_dll (*current_event);
	}
      catch (const gdb_exception &ex)
	{
	  exception_print (gdb_stderr, ex);
	}
      ourstatus->set_loaded ();
      thread_id = current_event->dwThreadId;
      break;

    case EXCEPTION_DEBUG_EVENT:
      if (windows_process.saw_create != 1)
	break;
      switch (windows_process.handle_exception (*current_event,
						ourstatus, debug_exceptions))
	{
	case HANDLE_EXCEPTION_UNHANDLED:
	default:
	  continue_status = DBG_EXCEPTION_NOT_HANDLED;
	  break;
	case HANDLE_EXCEPTION_HANDLED:
	  thread_id = current_event->dwThreadId;
	  break;
	case HANDLE_EXCEPTION_IGNORED:
	  continue_status = DBG_CONTINUE;
	  break;
	}
      break;

    case OUTPUT_DEBUG_STRING_EVENT:	/* Message from the kernel.  */
      if (windows_process.saw_create != 1)
	break;
      if (windows_process.handle_output_debug_string (*current_event,
						      ourstatus))
	{
	  /* We caught a Cygwin signal for a thread.  That thread now
	     has a pending event, and the "sig" thread is
	     suspended.  */
	  serial_event_set (m_wait_event);

	  /* In all-stop, return now to avoid reaching
	     ContinueDebugEvent further below.  In all-stop, it's
	     always windows_nat_target::resume that does the
	     ContinueDebugEvent call.  */
	  if (!target_is_non_stop_p ())
	    {
	      ourstatus->set_ignore ();
	      return null_ptid;
	    }
	}
      break;

    default:
      if (windows_process.saw_create != 1)
	break;
      gdb_printf ("gdb: kernel event for pid=%u tid=0x%x\n",
		  (unsigned) current_event->dwProcessId,
		  (unsigned) current_event->dwThreadId);
      gdb_printf ("                 unknown event code %u\n",
		  (unsigned) current_event->dwDebugEventCode);
      break;
    }

  if (!thread_id || windows_process.saw_create != 1)
    {
      continue_last_debug_event_main_thread
	(_("Failed to resume program execution"), continue_status);
      ourstatus->set_ignore ();
      return null_ptid;
    }

  const ptid_t ptid = ptid_t (current_event->dwProcessId, thread_id);
  thread_info *thread = this->find_thread (ptid);
  auto *th = as_windows_thread_info (thread);

  th->last_event = *current_event;

  if (thread->internal_state () == THREAD_INT_STOPPED)
    {
      gdb_assert (th->suspended != 0);

      /* Pending stop.  See the comment by the definition of
	 "pending_status" for details on why this is needed.  */
      DEBUG_EVENTS ("get_windows_debug_event - "
		    "unexpected stop in suspended thread 0x%x",
		    thread_id);

      /* Use DBG_REPLY_LATER to put the event back in the kernel queue
	 if possible.  Don't do that with exit-thread or exit-process
	 events, because when a thread is dead, it can't be suspended
	 anymore, so the kernel would immediately re-report the
	 event.  */
      if (event_code != EXIT_THREAD_DEBUG_EVENT
	  && event_code != EXIT_PROCESS_DEBUG_EVENT
	  && dbg_reply_later_available ())
	{
	  /* Thankfully, the Windows kernel doesn't immediately
	     re-report the unexpected event for a suspended thread
	     when we defer it with DBG_REPLY_LATER, otherwise this
	     would get us stuck in an infinite loop re-processing the
	     same unexpected event over and over.  (Which is what
	     would happen if we used DBG_REPLY_LATER on an exit-thread
	     or exit-process event.  See comment above.)  */
	  continue_status = DBG_REPLY_LATER;
	}
      else
	{
	  if (current_event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT
	      && ((current_event->u.Exception.ExceptionRecord.ExceptionCode
		   == EXCEPTION_BREAKPOINT)
		  || (current_event->u.Exception.ExceptionRecord.ExceptionCode
		      == STATUS_WX86_BREAKPOINT))
	      && windows_process.windows_initialization_done)
	    {
	      th->stopped_at_software_breakpoint = true;
	      th->pc_adjusted = false;
	    }

	  th->pending_status = *ourstatus;
	  th->last_event = {};
	}

      /* For exit-process, the debug event is continued later, at
	 mourn time.  */
      if (event_code != EXIT_PROCESS_DEBUG_EVENT)
	{
	  continue_last_debug_event_main_thread
	    (_("Failed to resume program execution"), continue_status);
	}
      ourstatus->set_ignore ();
      return null_ptid;
    }

  gdb_assert (thread->internal_state () == THREAD_INT_RUNNING);

  /* Now that we've handled exit events for suspended threads (above),
     we can finally decide whether to report the thread exit event or
     just delete the thread without bothering the core.  */
  if (ourstatus->kind () == TARGET_WAITKIND_THREAD_EXITED
      && !m_report_thread_events)
    {
      delete_thread (ptid, ourstatus->exit_status (),
		     false /* main_thread_p */);
      ourstatus->set_spurious ();
      return null_ptid;
    }

  return ptid;
}

/* Wait for interesting events to occur in the target process.  */
ptid_t
windows_nat_target::wait (ptid_t ptid, struct target_waitstatus *ourstatus,
			  target_wait_flags options)
{
  int pid = -1;

  /* serial_event is a manual-reset event.  Clear it first.  We'll set
     it again if we may need to wake up the event loop to get here
     again.  */
  serial_event_clear (m_wait_event);

  /* We loop when we get a non-standard exception rather than return
     with a SPURIOUS because resume can try and step or modify things,
     which needs a current_thread->h.  But some of these exceptions mark
     the birth or death of threads, which mean that the current thread
     isn't necessarily what you think it is.  */

  while (1)
    {
      DEBUG_EVENT current_event {};

      ptid_t result = get_windows_debug_event (pid, ourstatus, options,
					       &current_event);
      /* True if this is a pending event that we injected ourselves,
	 instead of a real event out of WaitForDebugEvent.  */
      bool fake = current_event.dwDebugEventCode == 0;

      DEBUG_EVENTS ("get_windows_debug_event returned [%s : %s, fake=%d]",
		    result.to_string ().c_str (),
		    ourstatus->to_string ().c_str(),
		    fake);

      if ((options & TARGET_WNOHANG) != 0
	  && ourstatus->kind () == TARGET_WAITKIND_IGNORE)
	return result;

      if (ourstatus->kind () == TARGET_WAITKIND_NO_RESUMED)
	return result;

      if (ourstatus->kind () == TARGET_WAITKIND_SPURIOUS)
	{
	  continue_last_debug_event_main_thread
	    (_("Failed to resume program execution"), DBG_CONTINUE);
	}
      else if (ourstatus->kind () != TARGET_WAITKIND_IGNORE)
	{
	  if (ourstatus->kind () != TARGET_WAITKIND_EXITED
	      && ourstatus->kind () != TARGET_WAITKIND_SIGNALLED)
	    {
	      windows_thread_info *th = windows_process.find_thread (result);

	      /* If this thread was temporarily stopped just so we
		 could update its debug registers on the next
		 resumption, do it now.  */
	      if (th->stopping == SK_INTERNAL)
		{
		  gdb_assert (fake);
		  windows_continue (DBG_CONTINUE, th->tid,
				    WCONT_DONT_CONTINUE_DEBUG_EVENT);
		  continue;
		}

	      th->stopped_at_software_breakpoint = false;
	      if (current_event.dwDebugEventCode
		  == EXCEPTION_DEBUG_EVENT
		  && ((current_event.u.Exception.ExceptionRecord.ExceptionCode
		       == EXCEPTION_BREAKPOINT)
		      || (current_event.u.Exception.ExceptionRecord.ExceptionCode
			  == STATUS_WX86_BREAKPOINT))
		  && windows_process.windows_initialization_done)
		{
		  th->stopped_at_software_breakpoint = true;
		  th->pc_adjusted = false;
		}

	      /* If non-stop, suspend the event thread, and continue
		 it with DBG_REPLY_LATER, so the other threads go back
		 to running as soon as possible.  Don't do this if
		 stopping the thread, as in that case the thread was
		 already suspended, and also there's no real Windows
		 debug event to continue in that case.  */
	      if (windows_process.windows_initialization_done
		  && target_is_non_stop_p ()
		  && !fake)
		{
		  if (ourstatus->kind () == TARGET_WAITKIND_THREAD_EXITED)
		    {
		      gdb_assert (th->suspended == -1);
		      continue_last_debug_event_main_thread
			(_("Init: Failed to DBG_CONTINUE after thread exit"),
			 DBG_CONTINUE);
		    }
		  else
		    {
		      th->suspend ();
		      th->reply_later = DBG_CONTINUE;
		      continue_last_debug_event_main_thread
			(_("Init: Failed to defer event with DBG_REPLY_LATER"),
			 DBG_REPLY_LATER);
		    }
		}

	      /* All-stop, suspend all threads until they are
		 explicitly resumed.  */
	      if (!target_is_non_stop_p ())
		for (auto *thr : all_windows_threads ())
		  thr->suspend ();

	      th->stopping = SK_NOT_STOPPING;
	    }

	  /* If something came out, assume there may be more.  This is
	     needed because there may be pending events ready to
	     consume.  */
	  serial_event_set (m_wait_event);
	  return result;
	}
      else
	{
	  int detach = 0;

	  if (deprecated_ui_loop_hook != NULL)
	    detach = deprecated_ui_loop_hook (0);

	  if (detach)
	    kill ();
	}
    }
}

void
windows_nat_target::do_initial_windows_stuff (DWORD pid, bool attaching)
{
  struct inferior *inf;

  windows_process.open_process_used = 0;
#ifdef __CYGWIN__
  windows_process.cygwin_load_start = 0;
  windows_process.cygwin_load_end = 0;
#endif
  windows_process.process_id = pid;
  inf = current_inferior ();
  if (!inf->target_is_pushed (this))
    inf->push_target (this);
  windows_clear_solib ();
  clear_proceed_status (0);
  init_wait_for_inferior ();

#ifdef __x86_64__
  windows_process.ignore_first_breakpoint
    = !attaching && windows_process.wow64_process;

  if (!windows_process.wow64_process)
    {
      windows_process.mappings  = amd64_mappings;
      windows_process.segment_register_p = amd64_windows_segment_register_p;
    }
  else
#endif
    {
      windows_process.mappings  = i386_mappings;
      windows_process.segment_register_p = i386_windows_segment_register_p;
    }

  inferior_appeared (inf, pid);
  inf->attach_flag = attaching;

  target_terminal::init ();
  target_terminal::inferior ();

  windows_process.windows_initialization_done = 0;

  ptid_t last_ptid;

  /* Keep fetching events until we see the initial breakpoint (which
     is planted by Windows itself) being reported.  */

  while (1)
    {
      struct target_waitstatus status;

      last_ptid = this->wait (minus_one_ptid, &status, 0);

      /* These result in an error being thrown before we get here.  */
      gdb_assert (status.kind () != TARGET_WAITKIND_EXITED
		  && status.kind () != TARGET_WAITKIND_SIGNALLED);

      /* We may also see TARGET_WAITKIND_THREAD_EXITED if
	 target_thread_events is active (because another thread was
	 stepping earlier, for example).  Ignore such events until we
	 see the initial breakpoint.  */

      if (status.kind () == TARGET_WAITKIND_STOPPED)
	break;

      /* Don't use windows_nat_target::resume here because that
	 assumes that inferior_ptid points at a valid thread, and we
	 haven't switched to any thread yet.  */
      windows_continue (DBG_CONTINUE, -1, WCONT_CONTINUE_DEBUG_EVENT);
    }

  switch_to_thread (this->find_thread (last_ptid));

  /* Now that the inferior has been started and all DLLs have been mapped,
     we can iterate over all DLLs and load them in.

     We avoid doing it any earlier because, on certain versions of Windows,
     LOAD_DLL_DEBUG_EVENTs are sometimes not complete.  In particular,
     we have seen on Windows 8.1 that the ntdll.dll load event does not
     include the DLL name, preventing us from creating an associated SO.
     A possible explanation is that ntdll.dll might be mapped before
     the SO info gets created by the Windows system -- ntdll.dll is
     the first DLL to be reported via LOAD_DLL_DEBUG_EVENT and other DLLs
     do not seem to suffer from that problem.

     Rather than try to work around this sort of issue, it is much
     simpler to just ignore DLL load/unload events during the startup
     phase, and then process them all in one batch now.  */
  windows_process.add_all_dlls ();

  windows_process.windows_initialization_done = 1;
  return;
}

/* Try to set or remove a user privilege to the current process.  Return -1
   if that fails, the previous setting of that privilege otherwise.

   This code is copied from the Cygwin source code and rearranged to allow
   dynamically loading of the needed symbols from advapi32 which is only
   available on NT/2K/XP.  */
static int
set_process_privilege (const char *privilege, BOOL enable)
{
  HANDLE token_hdl = NULL;
  LUID restore_priv;
  TOKEN_PRIVILEGES new_priv, orig_priv;
  int ret = -1;
  DWORD size;

  if (!OpenProcessToken (GetCurrentProcess (),
			 TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
			 &token_hdl))
    goto out;

  if (!LookupPrivilegeValueA (NULL, privilege, &restore_priv))
    goto out;

  new_priv.PrivilegeCount = 1;
  new_priv.Privileges[0].Luid = restore_priv;
  new_priv.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

  if (!AdjustTokenPrivileges (token_hdl, FALSE, &new_priv,
			      sizeof orig_priv, &orig_priv, &size))
    goto out;
#if 0
  /* Disabled, otherwise every `attach' in an unprivileged user session
     would raise the "Failed to get SE_DEBUG_NAME privilege" warning in
     windows_attach().  */
  /* AdjustTokenPrivileges returns TRUE even if the privilege could not
     be enabled.  GetLastError () returns an correct error code, though.  */
  if (enable && GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    goto out;
#endif

  ret = orig_priv.Privileges[0].Attributes == SE_PRIVILEGE_ENABLED ? 1 : 0;

out:
  if (token_hdl)
    CloseHandle (token_hdl);

  return ret;
}

/* Attach to process PID, then initialize for debugging it.  */

void
windows_nat_target::attach (const char *args, int from_tty)
{
  DWORD pid;

  pid = parse_pid_to_attach (args);

  if (set_process_privilege (SE_DEBUG_NAME, TRUE) < 0)
    warning ("Failed to get SE_DEBUG_NAME privilege\n"
	     "This can cause attach to fail on Windows NT/2K/XP");

  windows_process.saw_create = 0;

  std::optional<unsigned> err;
  do_synchronously ([&] ()
    {
      BOOL ok = DebugActiveProcess (pid);

#ifdef __CYGWIN__
      if (!ok)
	{
	  /* Maybe PID was a Cygwin PID.  Try the corresponding native
	     Windows PID.  */
	  DWORD winpid = cygwin_internal (CW_CYGWIN_PID_TO_WINPID, pid);

	  if (winpid != 0)
	    {
	      /* It was indeed a Cygwin PID.  Fully switch to the
		 Windows PID from here on.  We don't do this
		 unconditionally to avoid ending up with PID=0 in the
		 error message below.  */
	      pid = winpid;

	      ok = DebugActiveProcess (winpid);
	    }
	}
#endif

      if (!ok)
	err = (unsigned) GetLastError ();

      return ok;
    });

  if (err.has_value ())
    {
      std::string msg = string_printf (_("Can't attach to process %u"),
				       (unsigned) pid);
      throw_winerror_with_name (msg.c_str (), *err);
    }

  DebugSetProcessKillOnExit (FALSE);

  target_announce_attach (from_tty, pid);

#ifdef __x86_64__
  HANDLE h = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (h != NULL)
    {
      BOOL wow64;
      if (IsWow64Process (h, &wow64))
	windows_process.wow64_process = wow64;
      CloseHandle (h);
    }
#endif

  do_initial_windows_stuff (pid, 1);

  if (target_is_non_stop_p ())
    {
      /* Leave all threads running.  */

      continue_last_debug_event_main_thread
	(_("Failed to DBG_CONTINUE after attach"),
	 DBG_CONTINUE);

      /* The thread that reports the initial breakpoint, and thus ends
	 up as selected thread here, was injected by Windows into the
	 program for the attach, and it exits as soon as we resume it.
	 Switch to the first thread in the inferior, otherwise the
	 user will be left with an exited thread selected.  */
      switch_to_thread (first_thread_of_inferior (current_inferior ()));
    }
  else
    {
      set_state (this, minus_one_ptid, THREAD_STOPPED);
      set_internal_state (this, minus_one_ptid, THREAD_INT_STOPPED);

      target_terminal::ours ();
    }
}

void
windows_nat_target::break_out_process_thread (bool &process_alive)
{
  /* This is called when the process_thread thread is blocked in
     WaitForDebugEvent (unless it already returned some event we
     haven't consumed yet), and we need to unblock it so that we can
     have it call DebugActiveProcessStop.

     To make WaitForDebugEvent return, we need to force some event in
     the inferior.  Any method that lets us do that (without
     disturbing the other threads), injects a new thread in the
     inferior.

     We don't use DebugBreakProcess for this, because that injects a
     thread that ends up executing a breakpoint instruction.  We can't
     let the injected thread hit that breakpoint _after_ we've
     detached.  Consuming events until we see a breakpoint trap isn't
     100% reliable, because we can't distinguish it from some other
     thread itself deciding to call int3 while we're detaching, unless
     we temporarily suspend all threads.  It's just a lot of
     complication, and there's an easier way.

     Important observation: the thread creation event for the newly
     injected thread is sufficient to unblock WaitForDebugEvent.

     Instead of DebugBreakProcess, we can instead use
     CreateRemoteThread to control the code that the injected thread
     runs ourselves.  We could consider pointing the injected thread
     at some side-effect-free Win32 function as entry point.  However,
     finding the address of such a function requires having at least
     minimal symbols loaded for ntdll.dll.  Having a way that avoids
     that is better, so that detach always works correctly even when
     we don't have any symbols loaded.

     So what we do is inject a thread that doesn't actually run ANY
     userspace code, because we force-terminate it as soon as we see
     its corresponding thread creation event.  CreateRemoteThread
     gives us the new thread's ID, which we can match with the thread
     associated with the CREATE_THREAD_DEBUG_EVENT event.  */

  DWORD injected_thread_id = 0;
  HANDLE injected_thread_handle
    = CreateRemoteThread (windows_process.handle, NULL,
			  0, (LPTHREAD_START_ROUTINE) 0,
			  NULL, 0, &injected_thread_id);

  if (injected_thread_handle == NULL)
    {
      DWORD err = GetLastError ();

      DEBUG_EVENTS ("CreateRemoteThread failed with %u", err);

      if (err == ERROR_ACCESS_DENIED)
	{
	  /* Creating the remote thread fails with ERROR_ACCESS_DENIED
	     if the process exited before we had a chance to inject
	     the thread.  Continue with the loop below and consume the
	     process exit event anyhow, so that our caller can always
	     call windows_continue.  */
	}
      else
	throw_winerror_with_name (_("Can't detach from running process.  "
				    "Interrupt it first."),
				  err);
    }

  process_alive = true;

  /* At this point, the user has declared that they want to detach, so
     any event that happens from this point on should be forwarded to
     the inferior.  */

  for (;;)
    {
      DEBUG_EVENT current_event;
      wait_for_debug_event_main_thread (&current_event);

      if (current_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
	{
	  DEBUG_EVENTS ("got EXIT_PROCESS_DEBUG_EVENT");
	  process_alive = false;
	  break;
	}

      if (current_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT
	  && current_event.dwThreadId == injected_thread_id)
	{
	  DEBUG_EVENTS ("got CREATE_THREAD_DEBUG_EVENT for injected thread");

	  /* Terminate the injected thread, so it doesn't run any code
	     at all.  All we wanted was some event, and
	     CREATE_THREAD_DEBUG_EVENT is sufficient.  */
	  CHECK (TerminateThread (injected_thread_handle, 0));
	  break;
	}

      DEBUG_EVENTS ("got unrelated event, code %u",
		    current_event.dwDebugEventCode);

      DWORD continue_status
	= continue_status_for_event_detaching (current_event);
      windows_continue (continue_status, -1, WCONT_CONTINUE_DEBUG_EVENT);
    }

  if (injected_thread_handle != NULL)
    CHECK (CloseHandle (injected_thread_handle));
}


/* Used while detaching.  Decide whether to pass the exception or not.
   Returns the dwContinueStatus argument to pass to
   ContinueDebugEvent.  */

DWORD
windows_nat_target::continue_status_for_event_detaching
  (const DEBUG_EVENT &event, size_t *reply_later_events_left)
{
  ptid_t ptid (event.dwProcessId, event.dwThreadId, 0);
  windows_thread_info *th = windows_process.find_thread (ptid);

  /* This can be a thread that we don't know about, as we're not
     tracking thread creation events at this point.  */
  if (th != nullptr && th->reply_later != 0)
    {
      DWORD res = th->reply_later;
      th->reply_later = 0;
      if (reply_later_events_left != nullptr)
	(*reply_later_events_left)--;
      return res;
    }
  else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
      /* As the user asked to detach already, any new exception not
	 seen by infrun before, is passed down to the inferior without
	 considering "handle SIG pass/nopass".  We can just pretend
	 the exception was raised after the inferior was detached.  */
      return DBG_EXCEPTION_NOT_HANDLED;
    }
  else
    return DBG_CONTINUE;
}

void
windows_nat_target::detach (inferior *inf, int from_tty)
{
  DWORD continue_status = DBG_CONTINUE;

  /* For any thread the core hasn't resumed, call prepare_resume with
     the signal that the thread would be resumed with, so that we set
     the right reply_later value, and also, so that we clear the trace
     flag.  */
  for (thread_info *tp : inf->non_exited_threads ())
    {
      if (tp->internal_state () != THREAD_INT_RUNNING)
	{
	  windows_thread_info *wth = windows_process.find_thread (tp->ptid);
	  gdb_signal signo = get_detach_signal (this, tp->ptid);

	  if (signo != wth->last_sig
	      || (signo != GDB_SIGNAL_0 && !signal_pass_state (signo)))
	    signo = GDB_SIGNAL_0;

	  DWORD cstatus = prepare_resume (wth, tp, 0, signo);

	  if (!m_continued && tp->ptid == get_last_debug_event_ptid ())
	    continue_status = cstatus;
	}
    }

  /* If we see the process exit while unblocking the process_thread
     helper thread, then we should skip the actual
     DebugActiveProcessStop call.  But don't report an error.  Just
     pretend the process exited shortly after the detach.  */
  bool process_alive = true;

  /* The process_thread helper thread will be blocked in
     WaitForDebugEvent waiting for events if we're in non-stop mode,
     or if in all-stop and we've resumed the target before we get
     here, e.g., with "attach&" or "c&".  We need to unblock it so
     that we can have it call DebugActiveProcessStop below, in the
     do_synchronously block.  */
  if (m_continued)
    {
      break_out_process_thread (process_alive);

      /* We're now either stopped at a thread exit event, or a process
	 exit event.  */
      continue_status = DBG_CONTINUE;
    }

  windows_continue (continue_status, -1,
		    WCONT_LAST_CALL | WCONT_CONTINUE_DEBUG_EVENT);

  std::optional<unsigned> err;
  if (process_alive)
    do_synchronously ([&] ()
      {
	/* The kernel re-raises any exception previously intercepted
	   and deferred with DBG_REPLY_LATER in the inferior after we
	   detach.  We need to flush those, and suppress those which
	   aren't meant to be seen by the inferior (e.g., breakpoints,
	   single-steps, any with matching "handle SIG nopass", etc.),
	   otherwise the inferior dies immediately after the detach,
	   due to an unhandled exception.  */
	DEBUG_EVENT event;

	/* Count how many threads have pending reply-later events.  */
	size_t reply_later_events_left = 0;
	for (auto *th : all_windows_threads ())
	  if (th->reply_later != 0)
	    reply_later_events_left++;

	DEBUG_EVENTS ("flushing %zu reply-later events",
		      reply_later_events_left);

	/* Note we have to use a blocking wait (hence the need for the
	   counter).  Just polling (timeout=0) until WaitForDebugEvent
	   returns false would be racy -- the kernel may take a little
	   bit to put the events in the pending queue.  That has been
	   observed on Windows 11, where detaching would still very
	   occasionally result in the inferior dying after the detach
	   due to a reply-later event.  */
	while (reply_later_events_left > 0
	       && wait_for_debug_event (&event, INFINITE))
	  {
	    DEBUG_EVENTS ("flushed kernel event code %u",
			  event.dwDebugEventCode);

	    DWORD cstatus = (continue_status_for_event_detaching
			     (event, &reply_later_events_left));
	    if (!continue_last_debug_event (cstatus, debug_events))
	      {
		err = (unsigned) GetLastError ();
		return false;
	      }

	    if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
	      {
		DEBUG_EVENTS ("got EXIT_PROCESS_DEBUG_EVENT, skipping detach");
		process_alive = false;
		break;
	      }
	  }

	if (process_alive
	    && !DebugActiveProcessStop (windows_process.process_id))
	  err = (unsigned) GetLastError ();
	else
	  DebugSetProcessKillOnExit (FALSE);
	return false;
      });

  if (err.has_value ())
    {
      std::string msg
	= string_printf (_("Can't detach process %u"),
			 windows_process.process_id);
      throw_winerror_with_name (msg.c_str (), *err);
    }

  target_announce_detach (from_tty);

  x86_cleanup_dregs ();
  switch_to_no_thread ();
  detach_inferior (inf);

  maybe_unpush_target ();
}

/* The pid_to_exec_file target_ops method for this platform.  */

const char *
windows_nat_target::pid_to_exec_file (int pid)
{
  return windows_process.pid_to_exec_file (pid);
}

/* Print status information about what we're accessing.  */

void
windows_nat_target::files_info ()
{
  struct inferior *inf = current_inferior ();

  gdb_printf ("\tUsing the running image of %s %s.\n",
	      inf->attach_flag ? "attached" : "child",
	      target_pid_to_str (ptid_t (inf->pid)).c_str ());
}

/* Modify CreateProcess parameters for use of a new separate console.
   Parameters are:
   *FLAGS: DWORD parameter for general process creation flags.
   *SI: STARTUPINFO structure, for which the console window size and
   console buffer size is filled in if GDB is running in a console.
   to create the new console.
   The size of the used font is not available on all versions of
   Windows OS.  Furthermore, the current font might not be the default
   font, but this is still better than before.
   If the windows and buffer sizes are computed,
   SI->DWFLAGS is changed so that this information is used
   by CreateProcess function.  */

static void
windows_set_console_info (STARTUPINFO *si, DWORD *flags)
{
  HANDLE hconsole = CreateFile ("CONOUT$", GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);

  if (hconsole != INVALID_HANDLE_VALUE)
    {
      CONSOLE_SCREEN_BUFFER_INFO sbinfo;
      COORD font_size;
      CONSOLE_FONT_INFO cfi;

      GetCurrentConsoleFont (hconsole, FALSE, &cfi);
      font_size = GetConsoleFontSize (hconsole, cfi.nFont);
      GetConsoleScreenBufferInfo(hconsole, &sbinfo);
      si->dwXSize = sbinfo.srWindow.Right - sbinfo.srWindow.Left + 1;
      si->dwYSize = sbinfo.srWindow.Bottom - sbinfo.srWindow.Top + 1;
      if (font_size.X)
	si->dwXSize *= font_size.X;
      else
	si->dwXSize *= 8;
      if (font_size.Y)
	si->dwYSize *= font_size.Y;
      else
	si->dwYSize *= 12;
      si->dwXCountChars = sbinfo.dwSize.X;
      si->dwYCountChars = sbinfo.dwSize.Y;
      si->dwFlags |= STARTF_USESIZE | STARTF_USECOUNTCHARS;
    }
  *flags |= CREATE_NEW_CONSOLE;
}

#ifndef __CYGWIN__
/* Function called by qsort to sort environment strings.  */

static int
envvar_cmp (const void *a, const void *b)
{
  const char **p = (const char **) a;
  const char **q = (const char **) b;
  return strcasecmp (*p, *q);
}
#endif

#ifdef __CYGWIN__
static void
clear_win32_environment (char **env)
{
  int i;
  size_t len;
  wchar_t *copy = NULL, *equalpos;

  for (i = 0; env[i] && *env[i]; i++)
    {
      len = mbstowcs (NULL, env[i], 0) + 1;
      copy = (wchar_t *) xrealloc (copy, len * sizeof (wchar_t));
      mbstowcs (copy, env[i], len);
      equalpos = wcschr (copy, L'=');
      if (equalpos)
	*equalpos = L'\0';
      SetEnvironmentVariableW (copy, NULL);
    }
  xfree (copy);
}
#endif

#ifndef __CYGWIN__

/* Redirection of inferior I/O streams for native MS-Windows programs.
   Unlike on Unix, where this is handled by invoking the inferior via
   the shell, on MS-Windows we need to emulate the cmd.exe shell.

   The official documentation of the cmd.exe redirection features is here:

     http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/redirection.mspx

   (That page talks about Windows XP, but there's no newer
   documentation, so we assume later versions of cmd.exe didn't change
   anything.)

   Caveat: the documentation on that page seems to include a few lies.
   For example, it describes strange constructs 1<&2 and 2<&1, which
   seem to work only when 1>&2 resp. 2>&1 would make sense, and so I
   think the cmd.exe parser of the redirection symbols simply doesn't
   care about the < vs > distinction in these cases.  Therefore, the
   supported features are explicitly documented below.

   The emulation below aims at supporting all the valid use cases
   supported by cmd.exe, which include:

     < FILE    redirect standard input from FILE
     0< FILE   redirect standard input from FILE
     <&N       redirect standard input from file descriptor N
     0<&N      redirect standard input from file descriptor N
     > FILE    redirect standard output to FILE
     >> FILE   append standard output to FILE
     1>> FILE  append standard output to FILE
     >&N       redirect standard output to file descriptor N
     1>&N      redirect standard output to file descriptor N
     >>&N      append standard output to file descriptor N
     1>>&N     append standard output to file descriptor N
     2> FILE   redirect standard error to FILE
     2>> FILE  append standard error to FILE
     2>&N      redirect standard error to file descriptor N
     2>>&N     append standard error to file descriptor N

     Note that using N > 2 in the above construct is supported, but
     requires that the corresponding file descriptor be open by some
     means elsewhere or outside GDB.  Also note that using ">&0" or
     "<&2" will generally fail, because the file descriptor redirected
     from is normally open in an incompatible mode (e.g., FD 0 is open
     for reading only).  IOW, use of such tricks is not recommended;
     you are on your own.

     We do NOT support redirection of file descriptors above 2, as in
     "3>SOME-FILE", because MinGW compiled programs don't (supporting
     that needs special handling in the startup code that MinGW
     doesn't have).  Pipes are also not supported.

     As for invalid use cases, where the redirection contains some
     error, the emulation below will detect that and produce some
     error and/or failure.  But the behavior in those cases is not
     bug-for-bug compatible with what cmd.exe does in those cases.
     That's because what cmd.exe does then is not well defined, and
     seems to be a side effect of the cmd.exe parsing of the command
     line more than anything else.  For example, try redirecting to an
     invalid file name, as in "> foo:bar".

     There are also minor syntactic deviations from what cmd.exe does
     in some corner cases.  For example, it doesn't support the likes
     of "> &foo" to mean redirect to file named literally "&foo"; we
     do support that here, because that, too, sounds like some issue
     with the cmd.exe parser.  Another nicety is that we support
     redirection targets that use file names with forward slashes,
     something cmd.exe doesn't -- this comes in handy since GDB
     file-name completion can be used when typing the command line for
     the inferior.  */

/* Support routines for redirecting standard handles of the inferior.  */

/* Parse a single redirection spec, open/duplicate the specified
   file/fd, and assign the appropriate value to one of the 3 standard
   file descriptors. */
static int
redir_open (const char *redir_string, int *inp, int *out, int *err)
{
  int *fd, ref_fd = -2;
  int mode;
  const char *fname = redir_string + 1;
  int rc = *redir_string;

  switch (rc)
    {
    case '0':
      fname++;
      [[fallthrough]];
    case '<':
      fd = inp;
      mode = O_RDONLY;
      break;
    case '1': case '2':
      fname++;
      [[fallthrough]];
    case '>':
      fd = (rc == '2') ? err : out;
      mode = O_WRONLY | O_CREAT;
      if (*fname == '>')
	{
	  fname++;
	  mode |= O_APPEND;
	}
      else
	mode |= O_TRUNC;
      break;
    default:
      return -1;
    }

  if (*fname == '&' && '0' <= fname[1] && fname[1] <= '9')
    {
      /* A reference to a file descriptor.  */
      char *fdtail;
      ref_fd = (int) strtol (fname + 1, &fdtail, 10);
      if (fdtail > fname + 1 && *fdtail == '\0')
	{
	  /* Don't allow redirection when open modes are incompatible.  */
	  if ((ref_fd == 0 && (fd == out || fd == err))
	      || ((ref_fd == 1 || ref_fd == 2) && fd == inp))
	    {
	      errno = EPERM;
	      return -1;
	    }
	  if (ref_fd == 0)
	    ref_fd = *inp;
	  else if (ref_fd == 1)
	    ref_fd = *out;
	  else if (ref_fd == 2)
	    ref_fd = *err;
	}
      else
	{
	  errno = EBADF;
	  return -1;
	}
    }
  else
    fname++;	/* skip the separator space */
  /* If the descriptor is already open, close it.  This allows
     multiple specs of redirections for the same stream, which is
     somewhat nonsensical, but still valid and supported by cmd.exe.
     (But cmd.exe only opens a single file in this case, the one
     specified by the last redirection spec on the command line.)  */
  if (*fd >= 0)
    _close (*fd);
  if (ref_fd == -2)
    {
      *fd = _open (fname, mode, _S_IREAD | _S_IWRITE);
      if (*fd < 0)
	return -1;
    }
  else if (ref_fd == -1)
    *fd = -1;	/* reset to default destination */
  else
    {
      *fd = _dup (ref_fd);
      if (*fd < 0)
	return -1;
    }
  /* _open just sets a flag for O_APPEND, which won't be passed to the
     inferior, so we need to actually move the file pointer.  */
  if ((mode & O_APPEND) != 0)
    _lseek (*fd, 0L, SEEK_END);
  return 0;
}

/* Canonicalize a single redirection spec and set up the corresponding
   file descriptor as specified.  */
static int
redir_set_redirection (const char *s, int *inp, int *out, int *err)
{
  char buf[__PMAX + 2 + 5]; /* extra space for quotes & redirection string */
  char *d = buf;
  const char *start = s;
  int quote = 0;

  *d++ = *s++;	/* copy the 1st character, < or > or a digit */
  if ((*start == '>' || *start == '1' || *start == '2')
      && *s == '>')
    {
      *d++ = *s++;
      if (*s == '>' && *start != '>')
	*d++ = *s++;
    }
  else if (*start == '0' && *s == '<')
    *d++ = *s++;
  /* cmd.exe recognizes "&N" only immediately after the redirection symbol.  */
  if (*s != '&')
    {
      while (isspace (*s))  /* skip whitespace before file name */
	s++;
      *d++ = ' ';	    /* separate file name with a single space */
    }

  /* Copy the file name.  */
  while (*s)
    {
      /* Remove quoting characters from the file name in buf[].  */
      if (*s == '"')	/* could support '..' quoting here */
	{
	  if (!quote)
	    quote = *s++;
	  else if (*s == quote)
	    {
	      quote = 0;
	      s++;
	    }
	  else
	    *d++ = *s++;
	}
      else if (*s == '\\')
	{
	  if (s[1] == '"')	/* could support '..' here */
	    s++;
	  *d++ = *s++;
	}
      else if (isspace (*s) && !quote)
	break;
      else
	*d++ = *s++;
      if (d - buf >= sizeof (buf) - 1)
	{
	  errno = ENAMETOOLONG;
	  return 0;
	}
    }
  *d = '\0';

  /* Windows doesn't allow redirection characters in file names, so we
     can bail out early if they use them, or if there's no target file
     name after the redirection symbol.  */
  if (d[-1] == '>' || d[-1] == '<')
    {
      errno = ENOENT;
      return 0;
    }
  if (redir_open (buf, inp, out, err) == 0)
    return s - start;
  return 0;
}

/* Parse the command line for redirection specs and prepare the file
   descriptors for the 3 standard streams accordingly.  */
static bool
redirect_inferior_handles (const char *cmd_orig, char *cmd,
			   int *inp, int *out, int *err)
{
  const char *s = cmd_orig;
  char *d = cmd;
  int quote = 0;
  bool retval = false;

  while (isspace (*s))
    *d++ = *s++;

  while (*s)
    {
      if (*s == '"')	/* could also support '..' quoting here */
	{
	  if (!quote)
	    quote = *s;
	  else if (*s == quote)
	    quote = 0;
	}
      else if (*s == '\\')
	{
	  if (s[1] == '"')	/* escaped quote char */
	    s++;
	}
      else if (!quote)
	{
	  /* Process a single redirection candidate.  */
	  if (*s == '<' || *s == '>'
	      || ((*s == '1' || *s == '2') && s[1] == '>')
	      || (*s == '0' && s[1] == '<'))
	    {
	      int skip = redir_set_redirection (s, inp, out, err);

	      if (skip <= 0)
		return false;
	      retval = true;
	      s += skip;
	    }
	}
      if (*s)
	*d++ = *s++;
    }
  *d = '\0';
  return retval;
}
#endif	/* !__CYGWIN__ */

/* Start an inferior windows child process and sets inferior_ptid to its pid.
   EXEC_FILE is the file to run.
   ALLARGS is a string containing the arguments to the program.
   ENV is the environment vector to pass.  Errors reported with error().  */

void
windows_nat_target::create_inferior (const char *exec_file,
				     const std::string &origallargs,
				     char **in_env, int from_tty)
{
  STARTUPINFO si;
#ifdef __CYGWIN__
  wchar_t real_path[__PMAX];
  wchar_t shell[__PMAX]; /* Path to shell */
  wchar_t infcwd[__PMAX];
  const char *sh;
  wchar_t *toexec;
  wchar_t *cygallargs;
  wchar_t *args;
  char **old_env = NULL;
  PWCHAR w32_env;
  size_t len;
  int tty;
  int ostdin, ostdout, ostderr;
#else  /* !__CYGWIN__ */
  char shell[__PMAX]; /* Path to shell */
  const char *toexec;
  char *args, *allargs_copy;
  size_t args_len, allargs_len;
  int fd_inp = -1, fd_out = -1, fd_err = -1;
  HANDLE tty = INVALID_HANDLE_VALUE;
  bool redirected = false;
  char *w32env;
  char *temp;
  size_t envlen;
  int i;
  size_t envsize;
  char **env;
#endif	/* !__CYGWIN__ */
  const char *allargs = origallargs.c_str ();
  PROCESS_INFORMATION pi;
  std::optional<unsigned> ret;
  DWORD flags = 0;
  const std::string &inferior_tty = current_inferior ()->tty ();

  if (!exec_file)
    error (_("No executable specified, use `target exec'."));

  const char *inferior_cwd = current_inferior ()->cwd ().c_str ();
  std::string expanded_infcwd;
  if (*inferior_cwd == '\0')
    inferior_cwd = nullptr;
  else
    {
      expanded_infcwd = gdb_tilde_expand (inferior_cwd);
      /* Mirror slashes on inferior's cwd.  */
      std::replace (expanded_infcwd.begin (), expanded_infcwd.end (),
		    '/', '\\');
      inferior_cwd = expanded_infcwd.c_str ();
    }

  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);

  if (new_group)
    flags |= CREATE_NEW_PROCESS_GROUP;

  if (new_console)
    windows_set_console_info (&si, &flags);

#ifdef __CYGWIN__
  if (!useshell)
    {
      flags |= DEBUG_ONLY_THIS_PROCESS;
      if (cygwin_conv_path (CCP_POSIX_TO_WIN_W, exec_file, real_path,
			    __PMAX * sizeof (wchar_t)) < 0)
	error (_("Error starting executable: %d"), errno);
      toexec = real_path;
      len = mbstowcs (NULL, allargs, 0) + 1;
      if (len == (size_t) -1)
	error (_("Error starting executable: %d"), errno);
      cygallargs = (wchar_t *) alloca (len * sizeof (wchar_t));
      mbstowcs (cygallargs, allargs, len);
    }
  else
    {
      sh = get_shell ();
      if (cygwin_conv_path (CCP_POSIX_TO_WIN_W, sh, shell, __PMAX) < 0)
	error (_("Error starting executable via shell: %d"), errno);
      len = sizeof (L" -c 'exec  '") + mbstowcs (NULL, exec_file, 0)
	    + mbstowcs (NULL, allargs, 0) + 2;
      cygallargs = (wchar_t *) alloca (len * sizeof (wchar_t));
      swprintf (cygallargs, len, L" -c 'exec %s %s'", exec_file, allargs);
      toexec = shell;
      flags |= DEBUG_PROCESS;
    }

  if (inferior_cwd != NULL
      && cygwin_conv_path (CCP_POSIX_TO_WIN_W, inferior_cwd,
			   infcwd, strlen (inferior_cwd)) < 0)
    error (_("Error converting inferior cwd: %d"), errno);

  args = (wchar_t *) alloca ((wcslen (toexec) + wcslen (cygallargs) + 2)
			     * sizeof (wchar_t));
  wcscpy (args, toexec);
  wcscat (args, L" ");
  wcscat (args, cygallargs);

#ifdef CW_CVT_ENV_TO_WINENV
  /* First try to create a direct Win32 copy of the POSIX environment. */
  w32_env = (PWCHAR) cygwin_internal (CW_CVT_ENV_TO_WINENV, in_env);
  if (w32_env != (PWCHAR) -1)
    flags |= CREATE_UNICODE_ENVIRONMENT;
  else
    /* If that fails, fall back to old method tweaking GDB's environment. */
#endif	/* CW_CVT_ENV_TO_WINENV */
    {
      /* Reset all Win32 environment variables to avoid leftover on next run. */
      clear_win32_environment (environ);
      /* Prepare the environment vars for CreateProcess.  */
      old_env = environ;
      environ = in_env;
      cygwin_internal (CW_SYNC_WINENV);
      w32_env = NULL;
    }

  if (inferior_tty.empty ())
    tty = ostdin = ostdout = ostderr = -1;
  else
    {
      tty = open (inferior_tty.c_str (), O_RDWR | O_NOCTTY);
      if (tty < 0)
	{
	  warning_filename_and_errno (inferior_tty.c_str (), errno);
	  ostdin = ostdout = ostderr = -1;
	}
      else
	{
	  ostdin = dup (0);
	  ostdout = dup (1);
	  ostderr = dup (2);
	  dup2 (tty, 0);
	  dup2 (tty, 1);
	  dup2 (tty, 2);
	}
    }

  do_synchronously ([&] ()
    {
      BOOL ok = create_process (nullptr, args, flags, w32_env,
				inferior_cwd != nullptr ? infcwd : nullptr,
				disable_randomization,
				&si, &pi);

      if (!ok)
	ret = (unsigned) GetLastError ();

      return ok;
    });

  if (w32_env)
    /* Just free the Win32 environment, if it could be created. */
    free (w32_env);
  else
    {
      /* Reset all environment variables to avoid leftover on next run. */
      clear_win32_environment (in_env);
      /* Restore normal GDB environment variables.  */
      environ = old_env;
      cygwin_internal (CW_SYNC_WINENV);
    }

  if (tty >= 0)
    {
      ::close (tty);
      dup2 (ostdin, 0);
      dup2 (ostdout, 1);
      dup2 (ostderr, 2);
      ::close (ostdin);
      ::close (ostdout);
      ::close (ostderr);
    }
#else  /* !__CYGWIN__ */
  allargs_len = strlen (allargs);
  allargs_copy = strcpy ((char *) alloca (allargs_len + 1), allargs);
  if (strpbrk (allargs_copy, "<>") != NULL)
    {
      int e = errno;
      errno = 0;
      redirected =
	redirect_inferior_handles (allargs, allargs_copy,
				   &fd_inp, &fd_out, &fd_err);
      if (errno)
	warning (_("Error in redirection: %s."), safe_strerror (errno));
      else
	errno = e;
      allargs_len = strlen (allargs_copy);
    }
  /* If not all the standard streams are redirected by the command
     line, use INFERIOR_TTY for those which aren't.  */
  if (!inferior_tty.empty ()
      && !(fd_inp >= 0 && fd_out >= 0 && fd_err >= 0))
    {
      SECURITY_ATTRIBUTES sa;
      sa.nLength = sizeof(sa);
      sa.lpSecurityDescriptor = 0;
      sa.bInheritHandle = TRUE;
      tty = CreateFileA (inferior_tty.c_str (), GENERIC_READ | GENERIC_WRITE,
			 0, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      if (tty == INVALID_HANDLE_VALUE)
	{
	  unsigned err = (unsigned) GetLastError ();
	  warning (_("Warning: Failed to open TTY %s, error %#x: %s"),
		   inferior_tty.c_str (), err, strwinerror (err));
	}
    }
  if (redirected || tty != INVALID_HANDLE_VALUE)
    {
      if (fd_inp >= 0)
	si.hStdInput = (HANDLE) _get_osfhandle (fd_inp);
      else if (tty != INVALID_HANDLE_VALUE)
	si.hStdInput = tty;
      else
	si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
      if (fd_out >= 0)
	si.hStdOutput = (HANDLE) _get_osfhandle (fd_out);
      else if (tty != INVALID_HANDLE_VALUE)
	si.hStdOutput = tty;
      else
	si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
      if (fd_err >= 0)
	si.hStdError = (HANDLE) _get_osfhandle (fd_err);
      else if (tty != INVALID_HANDLE_VALUE)
	si.hStdError = tty;
      else
	si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
      si.dwFlags |= STARTF_USESTDHANDLES;
    }

  toexec = exec_file;
  /* Build the command line, a space-separated list of tokens where
     the first token is the name of the module to be executed.
     To avoid ambiguities introduced by spaces in the module name,
     we quote it.  */
  args_len = strlen (toexec) + 2 /* quotes */ + allargs_len + 2;
  args = (char *) alloca (args_len);
  xsnprintf (args, args_len, "\"%s\" %s", toexec, allargs_copy);

  flags |= DEBUG_ONLY_THIS_PROCESS;

  /* CreateProcess takes the environment list as a null terminated set of
     strings (i.e. two nulls terminate the list).  */

  /* Get total size for env strings.  */
  for (envlen = 0, i = 0; in_env[i] && *in_env[i]; i++)
    envlen += strlen (in_env[i]) + 1;

  envsize = sizeof (in_env[0]) * (i + 1);
  env = (char **) alloca (envsize);
  memcpy (env, in_env, envsize);
  /* Windows programs expect the environment block to be sorted.  */
  qsort (env, i, sizeof (char *), envvar_cmp);

  w32env = (char *) alloca (envlen + 1);

  /* Copy env strings into new buffer.  */
  for (temp = w32env, i = 0; env[i] && *env[i]; i++)
    {
      strcpy (temp, env[i]);
      temp += strlen (temp) + 1;
    }

  /* Final nil string to terminate new env.  */
  *temp = 0;

  do_synchronously ([&] ()
    {
      BOOL ok = create_process (nullptr, /* image */
				args,	/* command line */
				flags,	/* start flags */
				w32env,	/* environment */
				inferior_cwd, /* current directory */
				disable_randomization,
				&si,
				&pi);
      if (!ok)
	ret = (unsigned) GetLastError ();

      return ok;
    });
  if (tty != INVALID_HANDLE_VALUE)
    CloseHandle (tty);
  if (fd_inp >= 0)
    _close (fd_inp);
  if (fd_out >= 0)
    _close (fd_out);
  if (fd_err >= 0)
    _close (fd_err);
#endif	/* !__CYGWIN__ */

  if (ret.has_value ())
    {
      std::string msg = _("Error creating process ") + std::string (exec_file);
      throw_winerror_with_name (msg.c_str (), *ret);
    }

#ifdef __x86_64__
  BOOL wow64;
  if (IsWow64Process (pi.hProcess, &wow64))
    windows_process.wow64_process = wow64;
#endif

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  if (useshell && shell[0] != '\0')
    windows_process.saw_create = -1;
  else
    windows_process.saw_create = 0;

  do_initial_windows_stuff (pi.dwProcessId, 0);

  /* Present the initial thread as stopped to the core.  */
  windows_thread_info *th = windows_process.find_thread (inferior_ptid);

  th->suspend ();
  set_state (this, inferior_ptid, THREAD_STOPPED);
  set_internal_state (this, inferior_ptid, THREAD_INT_STOPPED);

  if (target_is_non_stop_p ())
    {
      /* In non-stop mode, we always immediately use DBG_REPLY_LATER
	 on threads as soon as they report an event.  However, during
	 the initial startup, windows_nat_target::wait does not do
	 this, so we need to handle it here for the initial
	 thread.  */
      th->reply_later = DBG_CONTINUE;
      continue_last_debug_event_main_thread
	(_("Failed to defer event with DBG_REPLY_LATER"),
	 DBG_REPLY_LATER);
    }
}

void
windows_nat_target::mourn_inferior ()
{
  windows_continue (DBG_CONTINUE, -1,
		    WCONT_LAST_CALL | WCONT_CONTINUE_DEBUG_EVENT);
  x86_cleanup_dregs();
  if (windows_process.open_process_used)
    {
      CHECK (CloseHandle (windows_process.handle));
      windows_process.open_process_used = 0;
    }
  inf_child_target::mourn_inferior ();
}

/* Helper for windows_xfer_partial that handles memory transfers.
   Arguments are like target_xfer_partial.  */

static enum target_xfer_status
windows_xfer_memory (gdb_byte *readbuf, const gdb_byte *writebuf,
		     ULONGEST memaddr, ULONGEST len, ULONGEST *xfered_len)
{
  SIZE_T done = 0;
  BOOL success;
  DWORD lasterror = 0;

  if (writebuf != NULL)
    {
      DEBUG_MEM ("write target memory, %s bytes at %s",
		 pulongest (len), core_addr_to_string (memaddr));
      success = WriteProcessMemory (windows_process.handle,
				    (LPVOID) (uintptr_t) memaddr, writebuf,
				    len, &done);
      if (!success)
	lasterror = GetLastError ();
      FlushInstructionCache (windows_process.handle,
			     (LPCVOID) (uintptr_t) memaddr, len);
    }
  else
    {
      DEBUG_MEM ("read target memory, %s bytes at %s",
		 pulongest (len), core_addr_to_string (memaddr));
      success = ReadProcessMemory (windows_process.handle,
				   (LPCVOID) (uintptr_t) memaddr, readbuf,
				   len, &done);
      if (!success)
	lasterror = GetLastError ();
    }
  *xfered_len = (ULONGEST) done;
  if (!success && lasterror == ERROR_PARTIAL_COPY && done > 0)
    return TARGET_XFER_OK;
  else
    return success ? TARGET_XFER_OK : TARGET_XFER_E_IO;
}

/* Return true if all the threads of the process have already
   exited.  */

static bool
already_dead ()
{
  for (windows_thread_info *th : all_windows_threads ())
    if (th->h != nullptr)
      return false;
  return true;
}

void
windows_nat_target::kill ()
{
  /* If all the threads of the process have already exited, there is
     really nothing to kill.  This can happen with e.g., scheduler
     locking, where the thread exit events for all threads are still
     pending to be processed by the core.  */
  if (already_dead ())
    {
      target_mourn_inferior (inferior_ptid);
      return;
    }

  CHECK (TerminateProcess (windows_process.handle, 0));

  /* In non-stop mode, windows_continue does not call
     ContinueDebugEvent by default.  This behavior is appropriate for
     the first call to windows_continue because any thread that is
     stopped has already been ContinueDebugEvent'ed with
     DBG_REPLY_LATER.  However, after the first
     wait_for_debug_event_main_thread call in the loop, this will no
     longer be true.

     In all-stop mode, the WCONT_CONTINUE_DEBUG_EVENT flag has no
     effect, so writing the code in this way ensures that the code is
     the same for both modes.  */
  windows_continue_flags flags = WCONT_KILLED;

  for (;;)
    {
      if (!windows_continue (DBG_CONTINUE, -1, flags))
	break;
      DEBUG_EVENT current_event;
      wait_for_debug_event_main_thread (&current_event);
      if (current_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
	break;
      flags |= WCONT_CONTINUE_DEBUG_EVENT;
    }

  target_mourn_inferior (inferior_ptid);	/* Or just windows_mourn_inferior?  */
}

void
windows_nat_target::close ()
{
  DEBUG_EVENTS ("inferior_ptid=%d\n", inferior_ptid.pid ());
  async (false);
}

/* Convert pid to printable format.  */
std::string
windows_nat_target::pid_to_str (ptid_t ptid)
{
  if (ptid.lwp () != 0)
    return string_printf ("Thread %d.0x%lx", ptid.pid (), ptid.lwp ());

  return normal_pid_to_str (ptid);
}

static enum target_xfer_status
windows_xfer_shared_libraries (struct target_ops *ops,
			       enum target_object object, const char *annex,
			       gdb_byte *readbuf, const gdb_byte *writebuf,
			       ULONGEST offset, ULONGEST len,
			       ULONGEST *xfered_len)
{
  if (writebuf)
    return TARGET_XFER_E_IO;

  std::string xml = "<library-list>\n";
  for (windows_solib &so : windows_process.solibs)
    windows_xfer_shared_library (so.name.c_str (),
				 (CORE_ADDR) (uintptr_t) so.load_addr,
				 &so.text_offset,
				 current_inferior ()->arch (), xml);
  xml += "</library-list>\n";

  ULONGEST len_avail = xml.size ();
  if (offset >= len_avail)
    len = 0;
  else
    {
      if (len > len_avail - offset)
	len = len_avail - offset;
      memcpy (readbuf, xml.data () + offset, len);
    }

  *xfered_len = (ULONGEST) len;
  return len != 0 ? TARGET_XFER_OK : TARGET_XFER_EOF;
}

/* Helper for windows_nat_target::xfer_partial that handles signal info.  */

static enum target_xfer_status
windows_xfer_siginfo (gdb_byte *readbuf, ULONGEST offset, ULONGEST len,
		      ULONGEST *xfered_len)
{
  windows_thread_info *th = windows_process.find_thread (inferior_ptid);

  if (th->xfer_siginfo (readbuf, offset, len, xfered_len))
    return TARGET_XFER_OK;
  else
    return TARGET_XFER_E_IO;
}

enum target_xfer_status
windows_nat_target::xfer_partial (enum target_object object,
				  const char *annex, gdb_byte *readbuf,
				  const gdb_byte *writebuf, ULONGEST offset,
				  ULONGEST len, ULONGEST *xfered_len)
{
  switch (object)
    {
    case TARGET_OBJECT_MEMORY:
      return windows_xfer_memory (readbuf, writebuf, offset, len, xfered_len);

    case TARGET_OBJECT_LIBRARIES:
      return windows_xfer_shared_libraries (this, object, annex, readbuf,
					    writebuf, offset, len, xfered_len);

    case TARGET_OBJECT_SIGNAL_INFO:
      return windows_xfer_siginfo (readbuf, offset, len, xfered_len);

    default:
      if (beneath () == NULL)
	{
	  /* This can happen when requesting the transfer of unsupported
	     objects before a program has been started (and therefore
	     with the current_target having no target beneath).  */
	  return TARGET_XFER_E_IO;
	}
      return beneath ()->xfer_partial (object, annex,
				       readbuf, writebuf, offset, len,
				       xfered_len);
    }
}

/* Provide thread local base, i.e. Thread Information Block address.
   Returns 1 if ptid is found and sets *ADDR to thread_local_base.  */

bool
windows_nat_target::get_tib_address (ptid_t ptid, CORE_ADDR *addr)
{
  windows_thread_info *th;

  th = windows_process.find_thread (ptid);
  if (th == NULL)
    return false;

  if (addr != NULL)
    *addr = th->thread_local_base;

  return true;
}

ptid_t
windows_nat_target::get_ada_task_ptid (long lwp, ULONGEST thread)
{
  return ptid_t (inferior_ptid.pid (), lwp, 0);
}

/* Implementation of the to_thread_name method.  */

const char *
windows_nat_target::thread_name (struct thread_info *thr)
{
  windows_thread_info *th = windows_process.find_thread (thr->ptid);
  return th->thread_name ();
}


/* Implementation of the target_ops::supports_non_stop method.  */

bool
windows_nat_target::supports_non_stop ()
{
  /* Non-stop support requires DBG_REPLY_LATER, which only exists on
     Windows 10 and later.  */
  return dbg_reply_later_available ();
}

void _initialize_windows_nat ();
void
_initialize_windows_nat ()
{
  x86_dr_low.set_control = windows_set_dr7;
  x86_dr_low.set_addr = windows_set_dr;
  x86_dr_low.get_addr = windows_get_dr;
  x86_dr_low.get_status = windows_get_dr6;
  x86_dr_low.get_control = windows_get_dr7;

  /* x86_dr_low.debug_register_length field is set by
     calling x86_set_debug_register_length function
     in processor windows specific native file.  */

  /* The target is not a global specifically to avoid a C++ "static
     initializer fiasco" situation.  */
  add_inf_child_target (new windows_nat_target);

#ifdef __CYGWIN__
  cygwin_internal (CW_SET_DOS_FILE_WARNING, 0);
#endif

  add_com ("signal-event", class_run, signal_event_command, _("\
Signal a crashed process with event ID, to allow its debugging.\n\
This command is needed in support of setting up GDB as JIT debugger on\n\
MS-Windows.  The command should be invoked from the GDB command line using\n\
the '-ex' command-line option.  The ID of the event that blocks the\n\
crashed process will be supplied by the Windows JIT debugging mechanism."));

#ifdef __CYGWIN__
  add_setshow_boolean_cmd ("shell", class_support, &useshell, _("\
Set use of shell to start subprocess."), _("\
Show use of shell to start subprocess."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("cygwin-exceptions", class_support,
			   &cygwin_exceptions, _("\
Break when an exception is detected in the Cygwin DLL itself."), _("\
Show whether gdb breaks on exceptions in the Cygwin DLL itself."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);
#endif

  add_setshow_boolean_cmd ("new-console", class_support, &new_console, _("\
Set creation of new console when creating child process."), _("\
Show creation of new console when creating child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("new-group", class_support, &new_group, _("\
Set creation of new group when creating child process."), _("\
Show creation of new group when creating child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("debugexec", class_support, &debug_exec, _("\
Set whether to display execution in child process."), _("\
Show whether to display execution in child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("debugevents", class_support, &debug_events, _("\
Set whether to display kernel events in child process."), _("\
Show whether to display kernel events in child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("debugmemory", class_support, &debug_memory, _("\
Set whether to display memory accesses in child process."), _("\
Show whether to display memory accesses in child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("debugexceptions", class_support,
			   &debug_exceptions, _("\
Set whether to display kernel exceptions in child process."), _("\
Show whether to display kernel exceptions in child process."), NULL,
			   NULL,
			   NULL, /* FIXME: i18n: */
			   &setlist, &showlist);

  init_w32_command_list ();

  add_cmd ("selector", class_info, display_selectors,
	   _("Display selectors infos."),
	   &info_w32_cmdlist);

  if (!initialize_loadable ())
    {
      /* This will probably fail on Windows 9x/Me.  Let the user know
	 that we're missing some functionality.  */
      warning(_("\
cannot automatically find executable file or library to read symbols.\n\
Use \"%ps\" or \"%ps\" command to load executable/libraries directly."),
	      styled_string (command_style.style (), "file"),
	      styled_string (command_style.style (), "dll"));
    }
}

/* For each thread, set the debug_registers_changed flag, and
   temporarily stop it so we can update its debug registers.  */

void
windows_nat_target::debug_registers_changed_all_threads ()
{
  for (auto *th : all_windows_threads ())
    {
      th->debug_registers_changed = true;

      /* Note we don't SuspendThread => update debug regs =>
	 ResumeThread, because SuspendThread is actually asynchronous
	 (and GetThreadContext blocks until the thread really
	 suspends), and doing that for all threads may take a bit.
	 Also, the core does one call per DR register update, so that
	 would result in a lot of suspend-resumes.  So instead, we
	 suspend the thread if it wasn't already suspended, and queue
	 a pending stop to be handled by windows_nat_target::wait.
	 This means we only stop each thread once, and, we don't block
	 waiting for each individual thread stop.  */
      stop_one_thread (th, SK_INTERNAL);
    }
}

/* Trampoline helper to get at the
   windows_nat_target::debug_registers_changed_all_threads method in
   the native target.  */

static void
debug_registers_changed_all_threads ()
{
  auto *win_tgt = static_cast<windows_nat_target *> (get_native_target ());
  win_tgt->debug_registers_changed_all_threads ();
}

/* Hardware watchpoint support, adapted from go32-nat.c code.  */

/* Pass the address ADDR to the inferior in the I'th debug register.
   Here we just store the address in dr array, the registers will be
   actually set up when windows_continue is called.  */
static void
windows_set_dr (int i, CORE_ADDR addr)
{
  if (i < 0 || i > 3)
    internal_error (_("Invalid register %d in windows_set_dr.\n"), i);

  debug_registers_changed_all_threads ();
}

/* Pass the value VAL to the inferior in the DR7 debug control
   register.  Here we just store the address in D_REGS, the watchpoint
   will be actually set up in windows_wait.  */
static void
windows_set_dr7 (unsigned long val)
{
  debug_registers_changed_all_threads ();
}

/* Get the value of debug register I from the inferior.  */

static CORE_ADDR
windows_get_dr (int i)
{
  windows_thread_info *th = windows_process.find_thread (inferior_ptid);

  return windows_process.with_context (th, [&] (auto *context) -> CORE_ADDR
    {
      gdb_assert (context->ContextFlags != 0);
      switch (i)
	{
	case 0:
	  return context->Dr0;
	case 1:
	  return context->Dr1;
	case 2:
	  return context->Dr2;
	case 3:
	  return context->Dr3;
	case 6:
	  return context->Dr6;
	case 7:
	  return context->Dr7;
	};

      gdb_assert_not_reached ("invalid x86 dr register number: %d", i);
    });
}

/* Get the value of the DR6 debug status register from the
   inferior.  */

static unsigned long
windows_get_dr6 (void)
{
  return windows_get_dr (6);
}

/* Get the value of the DR7 debug status register from the
   inferior.  */

static unsigned long
windows_get_dr7 (void)
{
  return windows_get_dr (7);
}

/* Determine if the thread referenced by "ptid" is alive
   by "polling" it.  If WaitForSingleObject returns WAIT_OBJECT_0
   it means that the thread has died.  Otherwise it is assumed to be alive.  */

bool
windows_nat_target::thread_alive (ptid_t ptid)
{
  gdb_assert (ptid.lwp () != 0);

  windows_thread_info *th = windows_process.find_thread (ptid);
  return WaitForSingleObject (th->h, 0) != WAIT_OBJECT_0;
}

void _initialize_check_for_gdb_ini ();
void
_initialize_check_for_gdb_ini ()
{
  char *homedir;
  if (inhibit_gdbinit)
    return;

  homedir = getenv ("HOME");
  if (homedir)
    {
      char *p;
      char *oldini = (char *) alloca (strlen (homedir) +
				      sizeof ("gdb.ini") + 1);
      strcpy (oldini, homedir);
      p = strchr (oldini, '\0');
      if (p > oldini && !IS_DIR_SEPARATOR (p[-1]))
	*p++ = '/';
      strcpy (p, "gdb.ini");
      if (access (oldini, 0) == 0)
	{
	  int len = strlen (oldini);
	  char *newini = (char *) alloca (len + 2);

	  xsnprintf (newini, len + 2, "%.*s.gdbinit",
		     (int) (len - (sizeof ("gdb.ini") - 1)), oldini);
	  warning (_("obsolete '%s' found. Rename to '%s'."), oldini, newini);
	}
    }
}
