/* This testcase is part of GDB, the GNU debugger.

   Copyright 2009-2025 Free Software Foundation, Inc.

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

void
func (void)
{
  int a;

  a = 1; /* set breakpoint here */
  a = 2;
}

int
main (int argc, char **argv)
{
  int i;

  i = 1;
  i = 2;
  i = 3;
  func ();

  return 0;
}
