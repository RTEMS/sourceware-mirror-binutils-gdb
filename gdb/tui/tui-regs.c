/* TUI display registers in window.

   Copyright (C) 1998-2025 Free Software Foundation, Inc.

   Contributed by Hewlett-Packard Company.

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

#include "arch-utils.h"
#include "tui/tui.h"
#include "symtab.h"
#include "cli/cli-style.h"
#include "frame.h"
#include "regcache.h"
#include "inferior.h"
#include "target.h"
#include "tui/tui-layout.h"
#include "tui/tui-win.h"
#include "tui/tui-wingeneral.h"
#include "tui/tui-regs.h"
#include "reggroups.h"
#include "completer.h"

#include "gdb_curses.h"

/* A subclass of string_file that expands tab characters.  */
class tab_expansion_file : public string_file
{
public:

  tab_expansion_file () = default;

  void write (const char *buf, long length_buf) override;

private:

  int m_column = 0;
};

void
tab_expansion_file::write (const char *buf, long length_buf)
{
  for (long i = 0; i < length_buf; ++i)
    {
      if (buf[i] == '\t')
	{
	  do
	    {
	      string_file::write (" ", 1);
	      ++m_column;
	    }
	  while ((m_column % 8) != 0);
	}
      else
	{
	  string_file::write (&buf[i], 1);
	  if (buf[i] == '\n')
	    m_column = 0;
	  else
	    ++m_column;
	}
    }
}

/* Get the register from the frame and return a printable
   representation of it.  */

static std::string
tui_register_format (const frame_info_ptr &frame, int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);

  /* Expand tabs into spaces, since ncurses on MS-Windows doesn't.  */
  tab_expansion_file stream;
  gdbarch_print_registers_info (gdbarch, &stream, frame, regnum, 1);

  /* Remove the possible \n.  */
  std::string str = stream.release ();
  if (!str.empty () && str.back () == '\n')
    str.pop_back ();

  return str;
}

/* Compute the register value from the given frame and format it for
   the display.  Update 'content' and set 'm_highlight' if the
   contents changed.  */
void
tui_register_info::update (const frame_info_ptr &frame)
{
  std::string new_content = tui_register_format (frame, m_regno);
  m_highlight = content != new_content;
  content = std::move (new_content);
}

/* See tui-regs.h.  */

int
tui_data_window::last_regs_line_no () const
{
  int num_lines = m_regs_content.size () / m_regs_column_count;
  if (m_regs_content.size () % m_regs_column_count)
    num_lines++;
  return num_lines;
}

/* See tui-regs.h.  */

int
tui_data_window::line_from_reg_element_no (int element_no) const
{
  if (element_no < m_regs_content.size ())
    {
      int i, line = (-1);

      i = 1;
      while (line == (-1))
	{
	  if (element_no < m_regs_column_count * i)
	    line = i - 1;
	  else
	    i++;
	}

      return line;
    }
  else
    return (-1);
}

/* See tui-regs.h.  */

int
tui_data_window::first_reg_element_no_inline (int line_no) const
{
  if (line_no * m_regs_column_count <= m_regs_content.size ())
    return ((line_no + 1) * m_regs_column_count) - m_regs_column_count;
  else
    return (-1);
}

/* See tui-regs.h.  */

void
tui_data_window::set_register_group (const reggroup *group)
{
  update_register_data (group);
  rerender ();
}

/* Set the data window to display the registers of the register group
   using the given frame.  */

void
tui_data_window::update_register_data (const reggroup *group)
{
  if (!target_has_registers ()
      || !target_has_stack ()
      || !target_has_memory ())
    {
      set_title (_("Registers"));
      m_current_group = nullptr;
      m_gdbarch = nullptr;
      m_regs_content.clear ();
      return;
    }

  if (group == nullptr)
    group = general_reggroup;

  frame_info_ptr frame = get_selected_frame (nullptr);
  struct gdbarch *gdbarch = get_frame_arch (frame);

  if (m_current_group == group && m_gdbarch == gdbarch)
    {
      /* Nothing to do here.  */
      return;
    }

  m_current_group = group;
  m_gdbarch = gdbarch;

  /* Make a new title showing which group we display.  */
  this->set_title (string_printf ("Register group: %s", group->name ()));

  /* Create the registers.  */
  m_regs_content.clear ();

  for (int regnum = 0;
       regnum < gdbarch_num_cooked_regs (gdbarch);
       regnum++)
    {
      /* Must be in the group.  */
      if (!gdbarch_register_reggroup_p (gdbarch, regnum, group))
	continue;

      /* If the register name is empty, it is undefined for this
	 processor, so don't display anything.  */
      const char *name = gdbarch_register_name (gdbarch, regnum);
      if (*name == '\0')
	continue;

      m_regs_content.emplace_back (regnum, frame);
    }
}

/* See tui-regs.h.  */

void
tui_data_window::display_registers_from (int start_element_no)
{
  werase (handle.get ());
  check_and_display_highlight_if_needed ();

  /* In case the regs window is not boxed, we'll write the last char in the
     last line here, causing a scroll, so prevent that.  */
  scrollok (handle.get (), FALSE);

  int max_len = 0;
  for (auto &&data_item_win : m_regs_content)
    {
      int len = data_item_win.content.size ();

      if (len > max_len)
	max_len = len;
    }
  m_item_width = max_len + 1;

  int i;
  /* Mark register windows above the visible area.  */
  for (i = 0; i < start_element_no; i++)
    m_regs_content[i].y = 0;

  m_regs_column_count = (width - box_size ()) / m_item_width;
  if (m_regs_column_count == 0)
    m_regs_column_count = 1;
  m_item_width = (width - box_size ()) / m_regs_column_count;

  /* Now create each data "sub" window, and write the display into
     it.  */
  int cur_y = box_width ();
  while (i < m_regs_content.size () && cur_y <= height - box_size ())
    {
      for (int j = 0;
	   j < m_regs_column_count && i < m_regs_content.size ();
	   j++)
	{
	  /* Create the window if necessary.  */
	  m_regs_content[i].x = box_width () + (m_item_width * j);
	  m_regs_content[i].y = cur_y;
	  m_regs_content[i].rerender (handle.get (), m_item_width);
	  i++;		/* Next register.  */
	}
      cur_y++;		/* Next row.  */
    }

  /* Mark register windows below the visible area.  */
  for (; i < m_regs_content.size (); i++)
    m_regs_content[i].y = 0;
}

/* See tui-regs.h.  */

void
tui_data_window::display_reg_element_at_line (int start_element_no,
					      int start_line_no)
{
  int element_no = start_element_no;

  if (start_element_no != 0 && start_line_no != 0)
    {
      int last_line_no, first_line_on_last_page;

      last_line_no = last_regs_line_no ();
      first_line_on_last_page = last_line_no - (height - box_size ());
      if (first_line_on_last_page < 0)
	first_line_on_last_page = 0;

      /* If the element_no causes us to scroll past the end of the
	 registers, adjust what element to really start the
	 display at.  */
      if (start_line_no > first_line_on_last_page)
	element_no = first_reg_element_no_inline (first_line_on_last_page);
    }
  display_registers_from (element_no);
}

/* See tui-regs.h.  */

int
tui_data_window::display_registers_from_line (int line_no)
{
  int element_no;

  if (line_no < 0)
    line_no = 0;
  else
    {
      /* Make sure that we don't display off the end of the
	 registers.  */
      if (line_no >= last_regs_line_no ())
	{
	  line_no = line_from_reg_element_no (m_regs_content.size () - 1);
	  if (line_no < 0)
	    line_no = 0;
	}
    }

  element_no = first_reg_element_no_inline (line_no);
  if (element_no < m_regs_content.size ())
    display_reg_element_at_line (element_no, line_no);
  else
    line_no = (-1);

  return line_no;
}


/* Answer the index first element displayed.  If none are displayed,
   then return (-1).  */
int
tui_data_window::first_data_item_displayed ()
{
  for (int i = 0; i < m_regs_content.size (); i++)
    {
      if (m_regs_content[i].visible ())
	return i;
    }

  return -1;
}

void
tui_data_window::erase_data_content ()
{
  center_string (_("[ Register Values Unavailable ]"));
}

/* See tui-regs.h.  */

void
tui_data_window::rerender ()
{
  if (m_regs_content.empty ())
    erase_data_content ();
  else
    display_registers_from (0);
  refresh_window ();
}


/* Scroll the data window vertically forward or backward.  */
void
tui_data_window::do_scroll_vertical (int num_to_scroll)
{
  int first_element_no;
  int first_line = (-1);

  first_element_no = first_data_item_displayed ();
  if (first_element_no < m_regs_content.size ())
    first_line = line_from_reg_element_no (first_element_no);
  else
    { /* Calculate the first line from the element number which is in
	the general data content.  */
    }

  if (first_line >= 0)
    {
      first_line += num_to_scroll;
      display_registers_from_line (first_line);
      refresh_window ();
    }
}

/* This function check all displayed registers for changes in values,
   given a particular frame.  If the values have changed, they are
   updated with the new value and highlighted.  */
void
tui_data_window::check_register_values (const frame_info_ptr &frame)
{
  /* If the frame architecture changed, we need to reset the register
     group.  */
  if (frame == nullptr || get_frame_arch (frame) != m_gdbarch)
    set_register_group (nullptr);
  else
    {
      for (tui_register_info &data_item_win : m_regs_content)
	{
	  bool was_hilighted = data_item_win.highlighted ();

	  data_item_win.update (frame);

	  if ((data_item_win.highlighted () || was_hilighted)
	      && data_item_win.visible ())
	    data_item_win.rerender (handle.get (), m_item_width);
	}
      refresh_window ();
    }
}

/* Display a register in a window.  */
void
tui_register_info::rerender (WINDOW *handle, int field_width)
{
  if (m_highlight)
    /* We ignore the return value, casting it to void in order to avoid
       a compiler warning.  The warning itself was introduced by a patch
       to ncurses 5.7 dated 2009-08-29, changing this macro to expand
       to code that causes the compiler to generate an unused-value
       warning.  */
    (void) wstandout (handle);
      
  mvwaddnstr (handle, y, x, content.c_str (), field_width - 1);
  if (content.size () < field_width)
    waddstr (handle, n_spaces (field_width - content.size ()));

  if (m_highlight)
    /* We ignore the return value, casting it to void in order to avoid
       a compiler warning.  The warning itself was introduced by a patch
       to ncurses 5.7 dated 2009-08-29, changing this macro to expand
       to code that causes the compiler to generate an unused-value
       warning.  */
    (void) wstandend (handle);
}

/* Helper for "tui reg next", returns the next register group after
   CURRENT_GROUP in the register group list for GDBARCH, with wrap around
   behavior.

   If CURRENT_GROUP is nullptr (e.g. if the tui register window has only
   just been displayed and has no current group selected) or the currently
   selected register group can't be found (e.g. if the architecture has
   changed since the register window was last updated), then the first
   register group will be returned.  */

static const reggroup *
tui_reg_next (const reggroup *current_group, struct gdbarch *gdbarch)
{
  const std::vector<const reggroup *> &groups = gdbarch_reggroups (gdbarch);
  auto it = std::find (groups.begin (), groups.end (), current_group);
  if (it != groups.end ())
    it++;
  if (it == groups.end ())
    return groups.front ();
  return *it;
}

/* Helper for "tui reg prev", returns the register group previous to
   CURRENT_GROUP in the register group list for GDBARCH, with wrap around
   behavior.

   If CURRENT_GROUP is nullptr (e.g. if the tui register window has only
   just been displayed and has no current group selected) or the currently
   selected register group can't be found (e.g. if the architecture has
   changed since the register window was last updated), then the last
   register group will be returned.  */

static const reggroup *
tui_reg_prev (const reggroup *current_group, struct gdbarch *gdbarch)
{
  const std::vector<const reggroup *> &groups = gdbarch_reggroups (gdbarch);
  auto it = std::find (groups.rbegin (), groups.rend (), current_group);
  if (it != groups.rend ())
    it++;
  if (it == groups.rend ())
    return groups.back ();
  return *it;
}

/* Implement the 'tui reg' command.  Changes the register group displayed
   in the tui register window.  Displays the tui register window if it is
   not already on display.  */

static void
tui_reg_command (const char *args, int from_tty)
{
  struct gdbarch *gdbarch = get_current_arch ();

  if (args != NULL)
    {
      size_t len = strlen (args);

      tui_batch_rendering suppress;

      /* Make sure the curses mode is enabled.  */
      tui_enable ();

      /* Make sure the register window is visible.  If not, select an
	 appropriate layout.  We need to do this before trying to run the
	 'next' or 'prev' commands.  */
      if (tui_data_win () == nullptr || !tui_data_win ()->is_visible ())
	tui_regs_layout ();

      const reggroup *match = nullptr;
      const reggroup *current_group = tui_data_win ()->get_current_group ();
      if (strncmp (args, "next", len) == 0)
	match = tui_reg_next (current_group, gdbarch);
      else if (strncmp (args, "prev", len) == 0)
	match = tui_reg_prev (current_group, gdbarch);
      else
	{
	  /* This loop matches on the initial part of a register group
	     name.  If this initial part in ARGS matches only one register
	     group then the switch is made.  */
	  for (const struct reggroup *group : gdbarch_reggroups (gdbarch))
	    {
	      if (strncmp (group->name (), args, len) == 0)
		{
		  if (match != NULL)
		    error (_("ambiguous register group name '%s'"), args);
		  match = group;
		}
	    }
	}

      if (match == NULL)
	error (_("unknown register group '%s'"), args);

      tui_data_win ()->set_register_group (match);
    }
  else
    {
      gdb_printf (_("\"%ps\" must be followed by the name of "
		    "either a register group,\nor one of 'next' "
		    "or 'prev'.  Known register groups are:\n"),
		  styled_string (command_style.style (), "tui reg"));

      bool first = true;
      for (const struct reggroup *group : gdbarch_reggroups (gdbarch))
	{
	  if (!first)
	    gdb_printf (", ");
	  first = false;
	  gdb_printf ("%s", group->name ());
	}

      gdb_printf ("\n");
    }
}

/* Complete names of register groups, and add the special "prev" and "next"
   names.  */

static void
tui_reggroup_completer (struct cmd_list_element *ignore,
			completion_tracker &tracker,
			const char *text, const char *word)
{
  static const char * const extra[] = { "next", "prev", NULL };

  reggroup_completer (ignore, tracker, text, word);

  complete_on_enum (tracker, extra, text, word);
}

INIT_GDB_FILE (tui_regs)
{
  struct cmd_list_element **tuicmd, *cmd;

  tuicmd = tui_get_cmd_list ();

  cmd = add_cmd ("reg", class_tui, tui_reg_command, _("\
TUI command to control the register window.\n\
Usage: tui reg NAME\n\
NAME is the name of the register group to display"), tuicmd);
  set_cmd_completer (cmd, tui_reggroup_completer);
}
