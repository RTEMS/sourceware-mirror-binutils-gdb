#!/bin/sh

# gdb_index_test_3.sh -- a test case for the --gdb-index option.

# Copyright (C) 2012-2025 Free Software Foundation, Inc.
# Written by Cary Coutant <ccoutant@google.com>.

# This file is part of gold.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.

check()
{
    if ! grep -q "$2" "$1"
    then
	echo "Did not find expected output:"
	echo "   $2"
	echo ""
	echo "Actual error output below:"
	cat "$1"
	exit 1
    fi
}

STDOUT=gdb_index_test_3.stdout

check $STDOUT "^Version [4-7]"

# Look for the symbols we know should be in the symbol table.

check $STDOUT "^\[ *[0-9]*\] main:"
check $STDOUT "^\[ *[0-9]*\] check_int:"
check $STDOUT "^\[ *[0-9]*\] j:"
check $STDOUT "^\[ *[0-9]*\] int:"

exit 0
