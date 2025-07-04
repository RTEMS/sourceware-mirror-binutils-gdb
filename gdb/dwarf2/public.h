/* Public API for gdb DWARF reader

   Copyright (C) 2021-2025 Free Software Foundation, Inc.

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

#ifndef GDB_DWARF2_PUBLIC_H
#define GDB_DWARF2_PUBLIC_H

/* A DWARF names index variant.  */
enum class dw_index_kind
{
  /* GDB's own .gdb_index format.   */
  GDB_INDEX,

  /* DWARF5 .debug_names.  */
  DEBUG_NAMES,
};

#if defined(DWARF_FORMAT_AVAILABLE)

/* Try to locate the sections we need for DWARF 2 debugging
   information.  If these are found, begin reading the DWARF and
   return true.  Otherwise, return false.  NAMES points to the dwarf2
   section names, or is NULL if the standard ELF names are used.
   CAN_COPY is true for formats where symbol interposition is possible
   and so symbol values must follow copy relocation rules.  */

extern bool dwarf2_initialize_objfile
     (struct objfile *,
      const struct dwarf2_debug_sections * = nullptr,
      bool = false);

extern void dwarf2_build_frame_info (struct objfile *);

/* Append the DWARF-2 frame unwinders to GDBARCH's list.  */

void dwarf2_append_unwinders (struct gdbarch *gdbarch);

#else /* DWARF_FORMAT_AVAILABLE */

static inline bool
dwarf2_initialize_objfile (struct objfile  *,
			   const struct dwarf2_debug_sections * = nullptr,
			   bool = false)
{
  warning (_("No dwarf support available."));
  return false;
}

static inline void
dwarf2_build_frame_info (struct objfile *)
{
  warning (_("No dwarf support available."));
}

#endif /* DWARF_FORMAT_AVAILABLE */

#endif /* GDB_DWARF2_PUBLIC_H */
