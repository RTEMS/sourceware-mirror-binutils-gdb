/* Definitions used by event-top.c, for GDB, the GNU debugger.

   Copyright (C) 1999-2025 Free Software Foundation, Inc.

   Written by Elena Zannoni <ezannoni@cygnus.com> of Cygnus Solutions.

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

#ifndef GDB_EVENT_TOP_H
#define GDB_EVENT_TOP_H

#include <signal.h>

#include "extension.h"

struct cmd_list_element;

/* The current quit handler (and its type).  This is called from the
   QUIT macro.  See default_quit_handler below for default behavior.
   Parts of GDB temporarily override this to e.g., completely suppress
   Ctrl-C because it would not be safe to throw.  E.g., normally, you
   wouldn't want to quit between a RSP command and its response, as
   that would break the communication with the target, but you may
   still want to intercept the Ctrl-C and offer to disconnect if the
   user presses Ctrl-C multiple times while the target is stuck
   waiting for the wedged remote stub.  */
typedef void (quit_handler_ftype) ();
extern quit_handler_ftype *quit_handler;

/* Exported functions from event-top.c.
   FIXME: these should really go into top.h.  */

/* The default quit handler.  Checks whether Ctrl-C was pressed, and
   if so:

     - If GDB owns the terminal, throws a quit exception.

     - If GDB does not own the terminal, forwards the Ctrl-C to the
       target.
*/

extern void default_quit_handler ();

/* Flag that function quit should call quit_force.  */

extern volatile bool sync_quit_force_run;

/* Set sync_quit_force_run and also call set_quit_flag().  */

extern void set_force_quit_flag ();

/* Control C eventually causes this to be called, at a convenient time.  */

extern void quit ();

/* Helper for the QUIT macro.  */

extern void maybe_quit ();

/* Check whether a Ctrl-C was typed, and if so, call the current quit
   handler.  */

#define QUIT maybe_quit ()

/* Set the serial event associated with the quit flag.  */

extern void quit_serial_event_set ();

/* Clear the serial event associated with the quit flag.  */

extern void quit_serial_event_clear ();

/* Wrap f (args) and handle exceptions by:
   - returning val, and
   - calling set_quit_flag or set_force_quit_flag, if needed.  */

template <typename R, R val, typename F, typename... Args>
static R
catch_exceptions (F &&f, Args&&... args)
{
   try
     {
       return f (std::forward<Args> (args)...);
     }
   catch (const gdb_exception &ex)
     {
       if (ex.reason == RETURN_QUIT)
	 set_quit_flag ();
       else if (ex.reason == RETURN_FORCED_QUIT)
	 set_force_quit_flag ();
     }

   return val;
}

extern void display_gdb_prompt (const char *new_prompt);
extern void gdb_setup_readline (int);
extern void gdb_disable_readline (void);
extern void gdb_init_signals (void);
extern void change_line_handler (int);

extern void command_line_handler (gdb::unique_xmalloc_ptr<char> &&rl);
extern void command_handler (const char *command);

#ifdef SIGTSTP
extern void handle_sigtstp (int sig);
#endif

extern void handle_sigint (int sig);
extern void handle_sigterm (int sig);
extern void async_request_quit (void *arg);
extern void async_disable_stdin (void);
extern void async_enable_stdin (void);

/* Exported variables from event-top.c.
   FIXME: these should really go into top.h.  */

extern bool set_editing_cmd_var;
extern bool exec_done_display_p;
extern void (*after_char_processing_hook) (void);
extern int call_stdin_event_handler_again_p;
extern void gdb_readline_no_editing_callback (void *client_data);

/* Wrappers for rl_callback_handler_remove and
   rl_callback_handler_install that keep track of whether the callback
   handler is installed in readline.  Do not call the readline
   versions directly.  */
extern void gdb_rl_callback_handler_remove (void);
extern void gdb_rl_callback_handler_install (const char *prompt);

/* Reinstall the readline callback handler (with no prompt), if not
   currently installed.  */
extern void gdb_rl_callback_handler_reinstall (void);

/* Called by readline after a complete line has been gathered from the
   user, but before the line is dispatched to back to GDB.  This function
   is a wrapper around readline's builtin rl_deprep_terminal function, and
   handles the case where readline received EOF.  */
extern void gdb_rl_deprep_term_function (void);

typedef void (*segv_handler_t) (int);

/* On construction, replaces the current thread's SIGSEGV handler with
   the provided one.  On destruction, restores the handler to the
   original one.  */
class scoped_segv_handler_restore
{
 public:
  scoped_segv_handler_restore (segv_handler_t new_handler);
  ~scoped_segv_handler_restore ();

 private:
  segv_handler_t m_old_handler;
};

#endif /* GDB_EVENT_TOP_H */
