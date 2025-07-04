/* Generate a core file for the inferior process.

   Copyright (C) 2001-2025 Free Software Foundation, Inc.

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

#include "elf-bfd.h"
#include "infcall.h"
#include "inferior.h"
#include "gdbcore.h"
#include "objfiles.h"
#include "solib.h"
#include "symfile.h"
#include "arch-utils.h"
#include "completer.h"
#include "gcore.h"
#include "cli/cli-decode.h"
#include <fcntl.h>
#include "regcache.h"
#include "regset.h"
#include "gdb_bfd.h"
#include "readline/tilde.h"
#include <algorithm>
#include "gdbsupport/gdb_unlinker.h"
#include "gdbsupport/byte-vector.h"
#include "gdbsupport/scope-exit.h"

/* To generate sparse cores, we look at the data to write in chunks of
   this size when considering whether to skip the write.  Only if we
   have a full block of this size with all zeros do we skip writing
   it.  A simpler algorithm that would try to skip all zeros would
   result in potentially many more write/lseek syscalls, as normal
   data is typically sprinkled with many small holes of zeros.  Also,
   it's much more efficient to memcmp a block of data against an
   all-zero buffer than to check each and every data byte against zero
   one by one.  */
#define SPARSE_BLOCK_SIZE 0x1000

/* The largest amount of memory to read from the target at once.  We
   must throttle it to limit the amount of memory used by GDB during
   generate-core-file for programs with large resident data.  */
#define MAX_COPY_BYTES (256 * SPARSE_BLOCK_SIZE)

static const char *default_gcore_target (void);
static enum bfd_architecture default_gcore_arch (void);
static int gcore_memory_sections (bfd *);

/* create_gcore_bfd -- helper for gcore_command (exported).
   Open a new bfd core file for output, and return the handle.  */

gdb_bfd_ref_ptr
create_gcore_bfd (const char *filename)
{
  gdb_bfd_ref_ptr obfd (gdb_bfd_openw (filename, default_gcore_target ()));

  if (obfd == NULL)
    error (_("Failed to open '%s' for output."), filename);
  bfd_set_format (obfd.get (), bfd_core);
  bfd_set_arch_mach (obfd.get (), default_gcore_arch (), 0);
  return obfd;
}

/* write_gcore_file_1 -- do the actual work of write_gcore_file.  */

static void
write_gcore_file_1 (bfd *obfd)
{
  gdb::unique_xmalloc_ptr<char> note_data;
  int note_size = 0;
  asection *note_sec = NULL;
  gdbarch *arch = current_inferior ()->arch ();

  /* An external target method must build the notes section.  */
  /* FIXME: uweigand/2011-10-06: All architectures that support core file
     generation should be converted to gdbarch_make_corefile_notes; at that
     point, the target vector method can be removed.  */
  if (!gdbarch_make_corefile_notes_p (arch))
    note_data = target_make_corefile_notes (obfd, &note_size);
  else
    note_data = gdbarch_make_corefile_notes (arch, obfd, &note_size);

  if (note_data == NULL || note_size == 0)
    error (_("Target does not support core file generation."));

  /* Create the note section.  */
  note_sec = bfd_make_section_anyway_with_flags (obfd, "note0",
						 SEC_HAS_CONTENTS
						 | SEC_READONLY
						 | SEC_ALLOC);
  if (note_sec == NULL)
    error (_("Failed to create 'note' section for corefile: %s"),
	   bfd_errmsg (bfd_get_error ()));

  bfd_set_section_vma (note_sec, 0);
  bfd_set_section_alignment (note_sec, 0);
  bfd_set_section_size (note_sec, note_size);

  /* Now create the memory/load sections.  Note
     gcore_memory_sections's sparse logic is assuming that we'll
     always write something afterwards, which we do: just below, we
     write the note section.  So there's no need for an ftruncate-like
     call to grow the file to the right size if the last memory
     sections were zeros and we skipped writing them.  */
  if (gcore_memory_sections (obfd) == 0)
    error (_("gcore: failed to get corefile memory sections from target."));

  /* Write out the contents of the note section.  */
  if (!bfd_set_section_contents (obfd, note_sec, note_data.get (), 0,
				 note_size))
    warning (_("writing note section (%s)"), bfd_errmsg (bfd_get_error ()));
}

/* write_gcore_file -- helper for gcore_command (exported).
   Compose and write the corefile data to the core file.  */

void
write_gcore_file (bfd *obfd)
{
  target_prepare_to_generate_core ();
  SCOPE_EXIT { target_done_generating_core (); };
  write_gcore_file_1 (obfd);
}

/* gcore_command -- implements the 'gcore' command.
   Generate a core file from the inferior process.  */

static void
gcore_command (const char *args, int from_tty)
{
  gdb::unique_xmalloc_ptr<char> corefilename;

  /* No use generating a corefile without a target process.  */
  if (!target_has_execution ())
    noprocess ();

  if (args && *args)
    corefilename.reset (tilde_expand (args));
  else
    {
      /* Default corefile name is "core.PID".  */
      corefilename = xstrprintf ("core.%d", inferior_ptid.pid ());
    }

  if (info_verbose)
    gdb_printf ("Opening corefile '%s' for output.\n",
		corefilename.get ());

  if (target_supports_dumpcore ())
    target_dumpcore (corefilename.get ());
  else
    {
      /* Open the output file.  */
      gdb_bfd_ref_ptr obfd (create_gcore_bfd (corefilename.get ()));

      /* Arrange to unlink the file on failure.  */
      gdb::unlinker unlink_file (corefilename.get ());

      /* Call worker function.  */
      write_gcore_file (obfd.get ());

      /* Succeeded.  */
      unlink_file.keep ();
    }

  gdb_printf ("Saved corefile %s\n", corefilename.get ());
}

static enum bfd_architecture
default_gcore_arch (void)
{
  const bfd_arch_info *bfdarch
    = gdbarch_bfd_arch_info (current_inferior ()->arch ());

  if (bfdarch != NULL)
    return bfdarch->arch;
  if (current_program_space->exec_bfd () == NULL)
    error (_("Can't find bfd architecture for corefile (need execfile)."));

  return bfd_get_arch (current_program_space->exec_bfd ());
}

static const char *
default_gcore_target (void)
{
  gdbarch *arch = current_inferior ()->arch ();
  /* The gdbarch may define a target to use for core files.  */
  if (gdbarch_gcore_bfd_target_p (arch))
    return gdbarch_gcore_bfd_target (arch);

  /* Otherwise, try to fall back to the exec target.  This will probably
     not work for non-ELF targets.  */
  if (current_program_space->exec_bfd () == NULL)
    return NULL;
  else
    return bfd_get_target (current_program_space->exec_bfd ());
}

/* Derive a reasonable stack segment by unwinding the target stack,
   and store its limits in *BOTTOM and *TOP.  Return non-zero if
   successful.  */

static int
derive_stack_segment (bfd_vma *bottom, bfd_vma *top)
{
  frame_info_ptr fi, tmp_fi;

  gdb_assert (bottom);
  gdb_assert (top);

  /* Can't succeed without stack and registers.  */
  if (!target_has_stack () || !target_has_registers ())
    return 0;

  /* Can't succeed without current frame.  */
  fi = get_current_frame ();
  if (fi == NULL)
    return 0;

  /* Save frame pointer of TOS frame.  */
  *top = get_frame_base (fi);
  /* If current stack pointer is more "inner", use that instead.  */
  if (gdbarch_inner_than (get_frame_arch (fi), get_frame_sp (fi), *top))
    *top = get_frame_sp (fi);

  /* Find prev-most frame.  */
  while ((tmp_fi = get_prev_frame (fi)) != NULL)
    fi = tmp_fi;

  /* Save frame pointer of prev-most frame.  */
  *bottom = get_frame_base (fi);

  /* Now canonicalize their order, so that BOTTOM is a lower address
     (as opposed to a lower stack frame).  */
  if (*bottom > *top)
    {
      bfd_vma tmp_vma;

      tmp_vma = *top;
      *top = *bottom;
      *bottom = tmp_vma;
    }

  return 1;
}

/* call_target_sbrk --
   helper function for derive_heap_segment.  */

static bfd_vma
call_target_sbrk (int sbrk_arg)
{
  struct objfile *sbrk_objf;
  struct gdbarch *gdbarch;
  bfd_vma top_of_heap;
  struct value *target_sbrk_arg;
  struct value *sbrk_fn, *ret;
  bfd_vma tmp;

  if (lookup_minimal_symbol (current_program_space, "sbrk").minsym != nullptr)
    {
      sbrk_fn = find_function_in_inferior ("sbrk", &sbrk_objf);
      if (sbrk_fn == NULL)
	return (bfd_vma) 0;
    }
  else if (lookup_minimal_symbol (current_program_space, "_sbrk").minsym
	   != nullptr)
    {
      sbrk_fn = find_function_in_inferior ("_sbrk", &sbrk_objf);
      if (sbrk_fn == NULL)
	return (bfd_vma) 0;
    }
  else
    return (bfd_vma) 0;

  gdbarch = sbrk_objf->arch ();
  target_sbrk_arg = value_from_longest (builtin_type (gdbarch)->builtin_int, 
					sbrk_arg);
  gdb_assert (target_sbrk_arg);
  ret = call_function_by_hand (sbrk_fn, NULL, target_sbrk_arg);
  if (ret == NULL)
    return (bfd_vma) 0;

  tmp = value_as_long (ret);
  if ((LONGEST) tmp <= 0 || (LONGEST) tmp == 0xffffffff)
    return (bfd_vma) 0;

  top_of_heap = tmp;
  return top_of_heap;
}

/* Derive a reasonable heap segment for ABFD by looking at sbrk and
   the static data sections.  Store its limits in *BOTTOM and *TOP.
   Return non-zero if successful.  */

static int
derive_heap_segment (bfd *abfd, bfd_vma *bottom, bfd_vma *top)
{
  bfd_vma top_of_data_memory = 0;
  bfd_vma top_of_heap = 0;
  bfd_size_type sec_size;
  bfd_vma sec_vaddr;
  asection *sec;

  gdb_assert (bottom);
  gdb_assert (top);

  /* This function depends on being able to call a function in the
     inferior.  */
  if (!target_has_execution ())
    return 0;

  /* The following code assumes that the link map is arranged as
     follows (low to high addresses):

     ---------------------------------
     | text sections                 |
     ---------------------------------
     | data sections (including bss) |
     ---------------------------------
     | heap                          |
     --------------------------------- */

  for (sec = abfd->sections; sec; sec = sec->next)
    {
      if (bfd_section_flags (sec) & SEC_DATA
	  || strcmp (".bss", bfd_section_name (sec)) == 0)
	{
	  sec_vaddr = bfd_section_vma (sec);
	  sec_size = bfd_section_size (sec);
	  if (sec_vaddr + sec_size > top_of_data_memory)
	    top_of_data_memory = sec_vaddr + sec_size;
	}
    }

  top_of_heap = call_target_sbrk (0);
  if (top_of_heap == (bfd_vma) 0)
    return 0;

  /* Return results.  */
  if (top_of_heap > top_of_data_memory)
    {
      *bottom = top_of_data_memory;
      *top = top_of_heap;
      return 1;
    }

  /* No additional heap space needs to be saved.  */
  return 0;
}

static void
make_output_phdrs (bfd *obfd, asection *osec)
{
  int p_flags = 0;
  int p_type = 0;

  /* Memory tag segments have already been handled by the architecture, as
     those contain arch-specific information.  If we have one of those, just
     return.  */
  if (startswith (bfd_section_name (osec), "memtag"))
    return;

  /* FIXME: these constants may only be applicable for ELF.  */
  if (startswith (bfd_section_name (osec), "load"))
    p_type = PT_LOAD;
  else if (startswith (bfd_section_name (osec), "note"))
    p_type = PT_NOTE;
  else
    p_type = PT_NULL;

  p_flags |= PF_R;	/* Segment is readable.  */
  if (!(bfd_section_flags (osec) & SEC_READONLY))
    p_flags |= PF_W;	/* Segment is writable.  */
  if (bfd_section_flags (osec) & SEC_CODE)
    p_flags |= PF_X;	/* Segment is executable.  */

  bfd_record_phdr (obfd, p_type, 1, p_flags, 0, 0, 0, 0, 1, &osec);
}

/* find_memory_region_ftype implementation.

   MEMORY_TAGGED is true if the memory region contains memory tags, false
   otherwise.

   DATA is 'bfd *' for the core file GDB is creating.  */

static int
gcore_create_callback (CORE_ADDR vaddr, unsigned long size, int read,
		       int write, int exec, int modified, bool memory_tagged,
		       void *data)
{
  bfd *obfd = (bfd *) data;
  asection *osec;
  flagword flags = SEC_ALLOC | SEC_HAS_CONTENTS | SEC_LOAD;

  /* If the memory segment has no permissions set, ignore it, otherwise
     when we later try to access it for read/write, we'll get an error
     or jam the kernel.  */
  if (read == 0 && write == 0 && exec == 0 && modified == 0)
    {
      if (info_verbose)
	gdb_printf ("Ignore segment, %s bytes at %s\n",
		    plongest (size), paddress (current_inferior ()->arch (),
		    vaddr));

      return 0;
    }

  if (write == 0 && modified == 0 && !solib_keep_data_in_core (vaddr, size))
    {
      /* See if this region of memory lies inside a known file on disk.
	 If so, we can avoid copying its contents by clearing SEC_LOAD.  */

      for (objfile *objfile : current_program_space->objfiles ())
	for (obj_section *objsec : objfile->sections ())
	  {
	    bfd *abfd = objfile->obfd.get ();
	    asection *asec = objsec->the_bfd_section;
	    bfd_vma align = (bfd_vma) 1 << bfd_section_alignment (asec);
	    bfd_vma start = objsec->addr () & -align;
	    bfd_vma end = (objsec->endaddr () + align - 1) & -align;

	    /* Match if either the entire memory region lies inside the
	       section (i.e. a mapping covering some pages of a large
	       segment) or the entire section lies inside the memory region
	       (i.e. a mapping covering multiple small sections).

	       This BFD was synthesized from reading target memory,
	       we don't want to omit that.  */
	    if (objfile->separate_debug_objfile_backlink == NULL
		&& ((vaddr >= start && vaddr + size <= end)
		    || (start >= vaddr && end <= vaddr + size))
		&& !(bfd_get_file_flags (abfd) & BFD_IN_MEMORY))
	      {
		flags &= ~(SEC_LOAD | SEC_HAS_CONTENTS);
		goto keep;	/* Break out of two nested for loops.  */
	      }
	  }

    keep:;
    }

  if (write == 0)
    flags |= SEC_READONLY;

  if (exec)
    flags |= SEC_CODE;
  else
    flags |= SEC_DATA;

  osec = bfd_make_section_anyway_with_flags (obfd, "load", flags);
  if (osec == NULL)
    {
      warning (_("Couldn't make gcore segment: %s"),
	       bfd_errmsg (bfd_get_error ()));
      return 1;
    }

  if (info_verbose)
    gdb_printf ("Save segment, %s bytes at %s\n",
		plongest (size), paddress (current_inferior ()->arch (),
		vaddr));

  bfd_set_section_size (osec, size);
  bfd_set_section_vma (osec, vaddr);
  bfd_set_section_lma (osec, 0);
  return 0;
}

/* gdbarch_find_memory_region callback for creating a memory tag section.

   MEMORY_TAGGED is true if the memory region contains memory tags, false
   otherwise.

   DATA is 'bfd *' for the core file GDB is creating.  */

static int
gcore_create_memtag_section_callback (CORE_ADDR vaddr, unsigned long size,
				      int read, int write, int exec,
				      int modified, bool memory_tagged,
				      void *data)
{
  /* Are there memory tags in this particular memory map entry?  */
  if (!memory_tagged)
    return 0;

  bfd *obfd = (bfd *) data;

  /* Ask the architecture to create a memory tag section for this particular
     memory map entry.  It will be populated with contents later, as we can't
     start writing the contents before we have all the sections sorted out.  */
  gdbarch *arch = current_inferior ()->arch ();
  asection *memtag_section
    = gdbarch_create_memtag_section (arch, obfd, vaddr, size);

  if (memtag_section == nullptr)
    {
      warning (_("Couldn't make gcore memory tag segment: %s"),
	       bfd_errmsg (bfd_get_error ()));
      return 1;
    }

  if (info_verbose)
    {
      gdb_printf (gdb_stdout, "Saved memory tag segment, %s bytes "
			      "at %s\n",
		  plongest (bfd_section_size (memtag_section)),
		  paddress (arch, vaddr));
    }

  return 0;
}

int
objfile_find_memory_regions (struct target_ops *self,
			     find_memory_region_ftype func, void *obfd)
{
  /* Use objfile data to create memory sections.  */
  bfd_vma temp_bottom = 0, temp_top = 0;

  /* Call callback function for each objfile section.  */
  for (objfile *objfile : current_program_space->objfiles ())
    for (obj_section *objsec : objfile->sections ())
      {
	asection *isec = objsec->the_bfd_section;
	flagword flags = bfd_section_flags (isec);

	/* Separate debug info files are irrelevant for gcore.  */
	if (objfile->separate_debug_objfile_backlink != NULL)
	  continue;

	if ((flags & SEC_ALLOC) || (flags & SEC_LOAD))
	  {
	    int size = bfd_section_size (isec);
	    int ret;

	    ret = (*func) (objsec->addr (), size,
			   1, /* All sections will be readable.  */
			   (flags & SEC_READONLY) == 0, /* Writable.  */
			   (flags & SEC_CODE) != 0, /* Executable.  */
			   1, /* MODIFIED is unknown, pass it as true.  */
			   false, /* No memory tags in the object file.  */
			   obfd);
	    if (ret != 0)
	      return ret;
	  }
      }

  /* Make a stack segment.  */
  if (derive_stack_segment (&temp_bottom, &temp_top))
    (*func) (temp_bottom, temp_top - temp_bottom,
	     1, /* Stack section will be readable.  */
	     1, /* Stack section will be writable.  */
	     0, /* Stack section will not be executable.  */
	     1, /* Stack section will be modified.  */
	     false, /* No memory tags in the object file.  */
	     obfd);

  /* Make a heap segment.  */
  if (derive_heap_segment (current_program_space->exec_bfd (), &temp_bottom,
			   &temp_top))
    (*func) (temp_bottom, temp_top - temp_bottom,
	     1, /* Heap section will be readable.  */
	     1, /* Heap section will be writable.  */
	     0, /* Heap section will not be executable.  */
	     1, /* Heap section will be modified.  */
	     false, /* No memory tags in the object file.  */
	     obfd);

  return 0;
}

/* Check if we have a block full of zeros at DATA within the [DATA,
   DATA+SIZE) buffer.  Returns the size of the all-zero block found.
   Returns at most the minimum between SIZE and SPARSE_BLOCK_SIZE.  */

static size_t
get_all_zero_block_size (const gdb_byte *data, size_t size)
{
  size = std::min (size, (size_t) SPARSE_BLOCK_SIZE);

  /* A memcmp of a whole block is much faster than a simple for loop.
     This makes a big difference, as with a for loop, this code would
     dominate the performance and result in doubling the time to
     generate a core, at the time of writing.  With an optimized
     memcmp, this doesn't even show up in the perf trace.  */
  static const gdb_byte all_zero_block[SPARSE_BLOCK_SIZE] = {};
  if (memcmp (data, all_zero_block, size) == 0)
    return size;
  return 0;
}

/* Basically a named-elements pair, used as return type of
   find_next_all_zero_block.  */

struct offset_and_size
{
  size_t offset;
  size_t size;
};

/* Find the next all-zero block at DATA+OFFSET within the [DATA,
   DATA+SIZE) buffer.  Returns the offset and the size of the all-zero
   block if found, or zero if not found.  */

static offset_and_size
find_next_all_zero_block (const gdb_byte *data, size_t offset, size_t size)
{
  for (; offset < size; offset += SPARSE_BLOCK_SIZE)
    {
      size_t zero_block_size
	= get_all_zero_block_size (data + offset, size - offset);
      if (zero_block_size != 0)
	return {offset, zero_block_size};
    }
  return {0, 0};
}

/* Wrapper around bfd_set_section_contents that avoids writing
   all-zero blocks to disk, so we create a sparse core file.
   SKIP_ALIGN is a recursion helper -- if true, we'll skip aligning
   the file position to SPARSE_BLOCK_SIZE.  */

static bool
sparse_bfd_set_section_contents (bfd *obfd, asection *osec,
				 const gdb_byte *data,
				 size_t sec_offset,
				 size_t size,
				 bool skip_align = false)
{
  /* Note, we don't have to have special handling for the case of the
     last memory region ending with zeros, because our caller always
     writes out the note section after the memory/load sections.  If
     it didn't, we'd have to seek+write the last byte to make the file
     size correct.  (Or add an ftruncate abstraction to bfd and call
     that.)  */

  if (size == 0)
    return true;

  size_t data_offset = 0;

  if (!skip_align)
    {
      /* Align the all-zero block search with SPARSE_BLOCK_SIZE, to
	 better align with filesystem blocks.  If we find we're
	 misaligned, then write/skip the bytes needed to make us
	 aligned.  We do that with (one level) recursion.  */

      /* We need to know the section's file offset on disk.  We can
	 only look at it after the bfd's 'output_has_begun' flag has
	 been set, as bfd hasn't computed the file offsets
	 otherwise.  */
      if (!obfd->output_has_begun)
	{
	  gdb_byte dummy = 0;

	  /* A write forces BFD to compute the bfd's section file
	     positions.  Zero size works for that too.  */
	  if (!bfd_set_section_contents (obfd, osec, &dummy, 0, 0))
	    return false;

	  gdb_assert (obfd->output_has_begun);
	}

      /* How much after the last aligned offset are we writing at.  */
      size_t aligned_offset_remainder
	= (osec->filepos + sec_offset) % SPARSE_BLOCK_SIZE;

      /* Do we need to align?  */
      if (aligned_offset_remainder != 0)
	{
	  /* How much we need to advance in order to find the next
	     SPARSE_BLOCK_SIZE filepos-aligned block.  */
	  size_t distance_to_next_aligned
	    = SPARSE_BLOCK_SIZE - aligned_offset_remainder;

	  /* How much we'll actually write in the recursion call.  The
	     caller may want us to write fewer bytes than
	     DISTANCE_TO_NEXT_ALIGNED.  */
	  size_t align_write_size = std::min (size, distance_to_next_aligned);

	  /* Recurse, skipping the alignment code.  */
	  if (!sparse_bfd_set_section_contents (obfd, osec, data,
						sec_offset,
						align_write_size, true))
	    return false;

	  /* Skip over what we've written, and proceed with
	     assumes-aligned logic.  */
	  data_offset += align_write_size;
	}
    }

  while (data_offset < size)
    {
      size_t all_zero_block_size
	= get_all_zero_block_size (data + data_offset, size - data_offset);
      if (all_zero_block_size != 0)
	{
	  /* Skip writing all-zero blocks.  */
	  data_offset += all_zero_block_size;
	  continue;
	}

      /* We have some non-zero data to write to file.  Find the next
	 all-zero block within the data, and only write up to it.  */

      offset_and_size next_all_zero_block
	= find_next_all_zero_block (data,
				    data_offset + SPARSE_BLOCK_SIZE,
				    size);
      size_t next_data_offset = (next_all_zero_block.offset == 0
				 ? size
				 : next_all_zero_block.offset);

      if (!bfd_set_section_contents (obfd, osec, data + data_offset,
				     sec_offset + data_offset,
				     next_data_offset - data_offset))
	return false;

      data_offset = next_data_offset;

      /* If we already know we have an all-zero block at the next
	 offset, we can skip calling get_all_zero_block_size for
	 it again.  */
      if (next_all_zero_block.offset != 0)
	data_offset += next_all_zero_block.size;
    }

  return true;
}

static void
gcore_copy_callback (bfd *obfd, asection *osec)
{
  bfd_size_type size, total_size = bfd_section_size (osec);
  file_ptr offset = 0;

  /* Read-only sections are marked; we don't have to copy their contents.  */
  if ((bfd_section_flags (osec) & SEC_LOAD) == 0)
    return;

  /* Only interested in "load" sections.  */
  if (!startswith (bfd_section_name (osec), "load"))
    return;

  size = std::min (total_size, (bfd_size_type) MAX_COPY_BYTES);
  gdb::byte_vector memhunk (size);

  while (total_size > 0)
    {
      if (size > total_size)
	size = total_size;

      if (target_read_memory (bfd_section_vma (osec) + offset,
			      memhunk.data (), size) != 0)
	{
	  warning (_("Memory read failed for corefile "
		     "section, %s bytes at %s."),
		   plongest (size),
		   paddress (current_inferior ()->arch (),
			     bfd_section_vma (osec)));
	  break;
	}

      if (!sparse_bfd_set_section_contents (obfd, osec, memhunk.data (),
					    offset, size))
	{
	  warning (_("Failed to write corefile contents (%s)."),
		   bfd_errmsg (bfd_get_error ()));
	  break;
	}

      total_size -= size;
      offset += size;
    }
}

/* Callback to copy contents to a particular memory tag section.  */

static void
gcore_copy_memtag_section_callback (bfd *obfd, asection *osec)
{
  /* We are only interested in "memtag" sections.  */
  if (!startswith (bfd_section_name (osec), "memtag"))
    return;

  /* Fill the section with memory tag contents.  */
  if (!gdbarch_fill_memtag_section (current_inferior ()->arch (), osec))
    error (_("Failed to fill memory tag section for core file."));
}

static int
gcore_memory_sections (bfd *obfd)
{
  /* Try gdbarch method first, then fall back to target method.  */
  gdbarch *arch = current_inferior ()->arch ();
  if (!gdbarch_find_memory_regions_p (arch)
      || gdbarch_find_memory_regions (arch, gcore_create_callback, obfd) != 0)
    {
      if (target_find_memory_regions (gcore_create_callback, obfd) != 0)
	return 0;			/* FIXME: error return/msg?  */
    }

  /* Take care of dumping memory tags, if there are any.  */
  if (!gdbarch_find_memory_regions_p (arch)
      || gdbarch_find_memory_regions (arch, gcore_create_memtag_section_callback,
				      obfd) != 0)
    {
      if (target_find_memory_regions (gcore_create_memtag_section_callback,
				      obfd) != 0)
	return 0;
    }

  /* Record phdrs for section-to-segment mapping.  */
  for (asection *sect : gdb_bfd_sections (obfd))
    make_output_phdrs (obfd, sect);

  /* Copy memory region and memory tag contents.  */
  for (asection *sect : gdb_bfd_sections (obfd))
    {
      gcore_copy_callback (obfd, sect);
      gcore_copy_memtag_section_callback (obfd, sect);
    }

  return 1;
}

/* See gcore.h.  */

thread_info *
gcore_find_signalled_thread ()
{
  thread_info *curr_thr = inferior_thread ();
  if (curr_thr->state != THREAD_EXITED
      && curr_thr->stop_signal () != GDB_SIGNAL_0)
    return curr_thr;

  for (thread_info *thr : current_inferior ()->non_exited_threads ())
    if (thr->stop_signal () != GDB_SIGNAL_0)
      return thr;

  /* Default to the current thread, unless it has exited.  */
  if (curr_thr->state != THREAD_EXITED)
    return curr_thr;

  return nullptr;
}

INIT_GDB_FILE (gcore)
{
  cmd_list_element *generate_core_file_cmd
    = add_com ("generate-core-file", class_files, gcore_command, _("\
Save a core file with the current state of the debugged process.\n\
Usage: generate-core-file [FILENAME]\n\
Argument is optional filename.  Default filename is 'core.PROCESS_ID'."));

  add_com_alias ("gcore", generate_core_file_cmd, class_files, 1);
}
