/* Self tests for blockvectors

   Copyright (C) 2025-2026 Free Software Foundation, Inc.

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

#include "gdbsupport/selftest.h"
#include "block.h"
#include "addrmap.h"
#include "obstack.h"


namespace selftests {

/* Create and add new block to given blockvector.  */
static struct block *
make_block (struct blockvector &bv, struct obstack &ob, CORE_ADDR start,
	    CORE_ADDR end, struct block *superblock = nullptr)
{
  auto b = new (&ob) struct block;
  b->set_start (start);
  b->set_end (end);
  b->set_superblock (superblock);
  b->set_multidict (mdict_create_linear_expandable (language_unknown));

  bv.append_block (b);

  return b;
}

static void
test_blockvector_lookup_contains ()
{
  /* Create blockvector with following blocks:

	B0    0x1000 - 0x4000   (global block)
	B1    0x1000 - 0x4000   (static block)
	  B2  0x1000 - 0x2000
				(hole)
	  B3  0x3000 - 0x4000
  */
  auto_obstack ob;
  blockvector_up bv = std::make_unique<struct blockvector> (0);

  auto global_block = make_block (*bv.get (), ob, 0x1000, 0x4000);
  auto static_block = make_block (*bv.get (), ob, 0x1000, 0x4000,
				  global_block);
  make_block (*bv.get (), ob, 0x1000, 0x2000, static_block);
  make_block (*bv.get (), ob, 0x3000, 0x4000, static_block);

  /* Test address outside global block's range.  */
  SELF_CHECK (bv->lookup (0x0500) == nullptr);
  SELF_CHECK (bv->contains (0x0500) == false);

  /* Test address falling into a block.  */
  SELF_CHECK (bv->lookup (0x1500) == bv->block (2));
  SELF_CHECK (bv->contains (0x1500) == true);

  /* Test address falling into a "hole".  */
  SELF_CHECK (bv->lookup (0x2500) == bv->block (STATIC_BLOCK));
  SELF_CHECK (bv->contains (0x2500) == true);

  /* Test address falling into a block above the "hole".  */
  SELF_CHECK (bv->lookup (0x3500) == bv->block (3));
  SELF_CHECK (bv->contains (0x3500) == true);

  /* Test address outside global block's range.  */
  SELF_CHECK (bv->lookup (0x4000) == nullptr);
  SELF_CHECK (bv->contains (0x4000) == false);
}

/* Create and return struct blockranges* from 2 ranges.  */
static struct blockranges *
make_blockranges_2 (struct obstack &ob, CORE_ADDR start0,
	    CORE_ADDR end0, CORE_ADDR start1,
	    CORE_ADDR end1)
{
  struct blockranges *ranges = (struct blockranges *) obstack_alloc
    (&ob, sizeof (struct blockranges) + (2 - 1) * sizeof (struct blockrange));

  ranges->nranges = 2;
  ranges->range[0].set_start (start0);
  ranges->range[0].set_end (end0);
  ranges->range[1].set_start (start1);
  ranges->range[1].set_end (end1);

  return ranges;
}

static void
test_blockvector_lookup_non_continuguous ()
{
  /* Create blockvector with following blocks:

	B0      0x1000 - 0x8000   (global block)
	B1      0x1000 - 0x8000   (static block)
	  B2    0x1000 - 0x2000   (B2's range 1)
	  B3    0x2000 - 0x3000   (B3's range 1)
				  (hole 1)
	    B4  0x5000 - 0x5500
				  (hole 2)
	 (B2)   0x6000 - 0x7000   (B2's range 2)
	 (B3)   0x7000 - 0x8000   (B3's range 2)

    Blocks B2 and B3 are non-continguous (consist of two
    disjoint ranges) and interleaved.
  */
  auto_obstack ob;
  blockvector_up bv = std::make_unique<struct blockvector> (0);

  auto global_block = make_block (*bv.get (), ob, 0x1000, 0x8000);
  auto static_block = make_block (*bv.get (), ob, 0x1000, 0x8000,
				  global_block);
  auto b2 = make_block (*bv.get (), ob, 0x1000, 0x7000, static_block);
  b2->set_ranges (make_blockranges_2 (ob, 0x1000, 0x2000, 0x6000, 0x7000));
  auto b3 = make_block (*bv.get (), ob, 0x2000, 0x8000, static_block);
  b3->set_ranges (make_blockranges_2 (ob, 0x2000, 0x3000, 0x7000, 0x8000));
  auto b4 = make_block (*bv.get (), ob, 0x5000, 0x5500, static_block);

  /* Test address falling into range 1 of B2.  */
  SELF_CHECK (bv->lookup (0x1500) == b2);

  /* Test address falling into range 2 of B2.  */
  SELF_CHECK (bv->lookup (0x6000) == b2);

  /* Test address falling into range 1 of B3.  */
  SELF_CHECK (bv->lookup (0x2500) == b3);

  /* Test address falling into range 2 of B3.  */
  SELF_CHECK (bv->lookup (0x7999) == b3);

  /* Test address falling into B4.  */
  SELF_CHECK (bv->lookup (0x5250) == b4);

  /* Test address falling into hole 1.  */
  SELF_CHECK (bv->lookup (0x4000) == static_block);

  /* Test address falling into hole 2.  */
  SELF_CHECK (bv->lookup (0x5750) == static_block);
}

} /* namespace selftests */


INIT_GDB_FILE (block_selftest)
{
  selftests::register_test ("blockvector-lookup-contains",
			    selftests::test_blockvector_lookup_contains);
  selftests::register_test
    ("blockvector-lookup-non-contiguous",
    selftests::test_blockvector_lookup_non_continuguous);
}
