/* Target-dependent code for GDB on PowerPC systems running FreeBSD.

   Copyright (C) 2013-2025 Free Software Foundation, Inc.

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

#ifndef GDB_PPC_FBSD_TDEP_H
#define GDB_PPC_FBSD_TDEP_H

struct regset;

/* From ppc-fbsd-tdep.c ...  */
const struct regset *ppc_fbsd_gregset (int);
const struct regset *ppc_fbsd_fpregset (void);

#endif /* GDB_PPC_FBSD_TDEP_H */
