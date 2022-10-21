/* Frame info pointer

   Copyright (C) 2022 Free Software Foundation, Inc.

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

#include "defs.h"

#include "frame-info.h"
#include "frame.h"
#include "gdbsupport/selftest.h"
#include "scoped-mock-context.h"
#include "test-target.h"

/* See frame-info-ptr.h.  */

intrusive_list<frame_info_ptr> frame_info_ptr::frame_list;

/* See frame-info-ptr.h.  */

frame_info_ptr::frame_info_ptr (struct frame_info *ptr)
  : m_ptr (ptr)
{
  frame_list.push_back (*this);

  if (m_ptr != nullptr)
    {
      m_cached_level = frame_relative_level (m_ptr);

      if (m_cached_level != 0
	  || (m_ptr != nullptr && frame_is_user_created (m_ptr)))
	m_cached_id = get_frame_id (m_ptr);
    }
}

/* See frame-info-ptr.h.  */

frame_info *
frame_info_ptr::reinflate () const
{
  /* Ensure we have a valid frame level (sentinel frame or above), indicating
     prepare_reinflate was called.  */
  gdb_assert (m_cached_level >= -1);

  if (m_ptr != nullptr)
    {
      /* The frame_info wasn't invalidated, no need to reinflate.  */
      return m_ptr;
    }

  /* Frame #0 needs special handling, see comment in select_frame.  */
  if (m_cached_level == 0)
    {
      if (!frame_id_p (m_cached_id))
	m_ptr = get_current_frame ().get ();
      else
	m_ptr = create_new_frame (m_cached_id.stack_addr,
				  m_cached_id.code_addr).get ();
    }
  else
    {
      gdb_assert (frame_id_p (m_cached_id));
      m_ptr = frame_find_by_id (m_cached_id).get ();
    }

  gdb_assert (m_ptr != nullptr);
  return m_ptr;
}

#if GDB_SELF_TEST

namespace selftests {

static void
test_user_created_frame ()
{
  scoped_mock_context<test_target_ops> mock_context
    (current_inferior ()->gdbarch);
  frame_info_ptr frame = create_new_frame (0x1234, 0x5678);

  frame_id id = get_frame_id (frame);
  SELF_CHECK (id.stack_status == FID_STACK_VALID);
  SELF_CHECK (id.stack_addr == 0x1234);
  SELF_CHECK (id.code_addr_p);
  SELF_CHECK (id.code_addr == 0x5678);

  reinit_frame_cache ();

  id = get_frame_id (frame);
  SELF_CHECK (id.stack_status == FID_STACK_VALID);
  SELF_CHECK (id.stack_addr == 0x1234);
  SELF_CHECK (id.code_addr_p);
  SELF_CHECK (id.code_addr == 0x5678);
}

} /* namespace selftests */

#endif

void _initialize_frame_info ();
void
_initialize_frame_info ()
{
#if GDB_SELF_TEST
  selftests::register_test ("frame_info_ptr_user",
			    selftests::test_user_created_frame);
#endif
}
