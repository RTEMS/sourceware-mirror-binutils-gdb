/* Copyright 2022-2025 Free Software Foundation, Inc.

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

static int
foo (int x)
{
  return 0;
}

static int
foo (char c)
{
  return 0;	/* Multi-location breakpoint here.  */
}

static int __attribute__((noinline))
bar ()
{
  int res = foo ('1');	/* Single-location breakpoint here.  */

  return res;
}

int
main ()
{
  int res = bar ();

  res = foo (1);

  return res;
}
