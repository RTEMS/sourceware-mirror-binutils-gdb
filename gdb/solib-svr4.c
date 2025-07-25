/* Handle SVR4 shared libraries for GDB, the GNU Debugger.

   Copyright (C) 1990-2025 Free Software Foundation, Inc.

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


#include "elf/external.h"
#include "elf/common.h"
#include "elf/mips.h"

#include "exceptions.h"
#include "extract-store-integer.h"
#include "symtab.h"
#include "bfd.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdbcore.h"
#include "target.h"
#include "inferior.h"
#include "infrun.h"
#include "regcache.h"
#include "observable.h"

#include "solib.h"
#include "solib-svr4.h"

#include "bfd-target.h"
#include "elf-bfd.h"
#include "exec.h"
#include "auxv.h"
#include "gdb_bfd.h"
#include "probe.h"

#include <map>

static void svr4_relocate_main_executable (void);
static void probes_table_remove_objfile_probes (struct objfile *objfile);
static void svr4_iterate_over_objfiles_in_search_order
  (gdbarch *gdbarch, iterate_over_objfiles_in_search_order_cb_ftype cb,
   objfile *current_objfile);


/* On SVR4 systems, a list of symbols in the dynamic linker where
   GDB can try to place a breakpoint to monitor shared library
   events.

   If none of these symbols are found, or other errors occur, then
   SVR4 systems will fall back to using a symbol as the "startup
   mapping complete" breakpoint address.  */

static const char * const solib_break_names[] =
{
  "r_debug_state",
  "_r_debug_state",
  "_dl_debug_state",
  "rtld_db_dlactivity",
  "__dl_rtld_db_dlactivity",
  "_rtld_debug_state",

  NULL
};

static const char * const bkpt_names[] =
{
  "_start",
  "__start",
  "main",
  NULL
};

static const  char * const main_name_list[] =
{
  "main_$main",
  NULL
};

/* A probe's name and its associated action.  */

struct probe_info
{
  /* The name of the probe.  */
  const char *name;

  /* What to do when a probe stop occurs.  */
  enum probe_action action;
};

/* A list of named probes and their associated actions.  If all
   probes are present in the dynamic linker then the probes-based
   interface will be used.  */

static const struct probe_info probe_info[] =
{
  { "init_start", DO_NOTHING },
  { "init_complete", FULL_RELOAD },
  { "map_start", DO_NOTHING },
  { "map_failed", DO_NOTHING },
  { "reloc_complete", UPDATE_OR_RELOAD },
  { "unmap_start", DO_NOTHING },
  { "unmap_complete", FULL_RELOAD },
};

#define NUM_PROBES ARRAY_SIZE (probe_info)

/* Return non-zero if GDB_SO_NAME and INFERIOR_SO_NAME represent
   the same shared library.  */

static int
svr4_same_1 (const char *gdb_so_name, const char *inferior_so_name)
{
  if (strcmp (gdb_so_name, inferior_so_name) == 0)
    return 1;

  /* On Solaris, when starting inferior we think that dynamic linker is
     /usr/lib/ld.so.1, but later on, the table of loaded shared libraries
     contains /lib/ld.so.1.  Sometimes one file is a link to another, but
     sometimes they have identical content, but are not linked to each
     other.  We don't restrict this check for Solaris, but the chances
     of running into this situation elsewhere are very low.  */
  if (strcmp (gdb_so_name, "/usr/lib/ld.so.1") == 0
      && strcmp (inferior_so_name, "/lib/ld.so.1") == 0)
    return 1;

  /* Similarly, we observed the same issue with amd64 and sparcv9, but with
     different locations.  */
  if (strcmp (gdb_so_name, "/usr/lib/amd64/ld.so.1") == 0
      && strcmp (inferior_so_name, "/lib/amd64/ld.so.1") == 0)
    return 1;

  if (strcmp (gdb_so_name, "/usr/lib/sparcv9/ld.so.1") == 0
      && strcmp (inferior_so_name, "/lib/sparcv9/ld.so.1") == 0)
    return 1;

  return 0;
}

static bool
svr4_same (const char *gdb_name, const char *inferior_name,
	   const lm_info_svr4 &gdb_lm_info,
	   const lm_info_svr4 &inferior_lm_info)
{
  if (!svr4_same_1 (gdb_name, inferior_name))
    return false;

  /* There may be different instances of the same library, in different
     namespaces.  Each instance, however, must have been loaded at a
     different address so its relocation offset would be different.  */
  return gdb_lm_info.l_addr_inferior == inferior_lm_info.l_addr_inferior;
}

bool
svr4_solib_ops::same (const solib &gdb, const solib &inferior) const
{
  auto *lmg
    = gdb::checked_static_cast<const lm_info_svr4 *> (gdb.lm_info.get ());
  auto *lmi
    = gdb::checked_static_cast<const lm_info_svr4 *> (inferior.lm_info.get ());

  return svr4_same (gdb.original_name.c_str (),
		    inferior.original_name.c_str (), *lmg, *lmi);
}

lm_info_svr4_up
svr4_solib_ops::read_lm_info (CORE_ADDR lm_addr) const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  lm_info_svr4_up lm_info;

  gdb::byte_vector lm (lmo->link_map_size);

  if (target_read_memory (lm_addr, lm.data (), lmo->link_map_size) != 0)
    warning (_("Error reading shared library list entry at %s"),
	     paddress (current_inferior ()->arch (), lm_addr));
  else
    {
      type *ptr_type
	= builtin_type (current_inferior ()->arch ())->builtin_data_ptr;

      lm_info = std::make_unique<lm_info_svr4> ();
      lm_info->lm_addr = lm_addr;

      lm_info->l_addr_inferior = extract_typed_address (&lm[lmo->l_addr_offset],
							ptr_type);
      lm_info->l_ld = extract_typed_address (&lm[lmo->l_ld_offset], ptr_type);
      lm_info->l_next = extract_typed_address (&lm[lmo->l_next_offset],
					       ptr_type);
      lm_info->l_prev = extract_typed_address (&lm[lmo->l_prev_offset],
					       ptr_type);
      lm_info->l_name = extract_typed_address (&lm[lmo->l_name_offset],
					       ptr_type);
    }

  return lm_info;
}

int
svr4_solib_ops::has_lm_dynamic_from_link_map () const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();

  return lmo->l_ld_offset >= 0;
}

CORE_ADDR
svr4_solib_ops::lm_addr_check (const solib &so, bfd *abfd) const
{
  auto *li = gdb::checked_static_cast<lm_info_svr4 *> (so.lm_info.get ());

  if (!li->l_addr_p)
    {
      struct bfd_section *dyninfo_sect;
      CORE_ADDR l_addr, l_dynaddr, dynaddr;

      l_addr = li->l_addr_inferior;

      if (!abfd || !this->has_lm_dynamic_from_link_map ())
	goto set_addr;

      l_dynaddr = li->l_ld;

      dyninfo_sect = bfd_get_section_by_name (abfd, ".dynamic");
      if (dyninfo_sect == NULL)
	goto set_addr;

      dynaddr = bfd_section_vma (dyninfo_sect);

      if (dynaddr + l_addr != l_dynaddr)
	{
	  CORE_ADDR align = 0x1000;
	  CORE_ADDR minpagesize = align;

	  if (bfd_get_flavour (abfd) == bfd_target_elf_flavour)
	    {
	      Elf_Internal_Ehdr *ehdr = elf_tdata (abfd)->elf_header;
	      Elf_Internal_Phdr *phdr = elf_tdata (abfd)->phdr;
	      int i;

	      align = 1;

	      for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_align > align)
		  align = phdr[i].p_align;

	      minpagesize = get_elf_backend_data (abfd)->minpagesize;
	    }

	  /* Turn it into a mask.  */
	  align--;

	  /* If the changes match the alignment requirements, we
	     assume we're using a core file that was generated by the
	     same binary, just prelinked with a different base offset.
	     If it doesn't match, we may have a different binary, the
	     same binary with the dynamic table loaded at an unrelated
	     location, or anything, really.  To avoid regressions,
	     don't adjust the base offset in the latter case, although
	     odds are that, if things really changed, debugging won't
	     quite work.

	     One could expect more the condition
	       ((l_addr & align) == 0 && ((l_dynaddr - dynaddr) & align) == 0)
	     but the one below is relaxed for PPC.  The PPC kernel supports
	     either 4k or 64k page sizes.  To be prepared for 64k pages,
	     PPC ELF files are built using an alignment requirement of 64k.
	     However, when running on a kernel supporting 4k pages, the memory
	     mapping of the library may not actually happen on a 64k boundary!

	     (In the usual case where (l_addr & align) == 0, this check is
	     equivalent to the possibly expected check above.)

	     Even on PPC it must be zero-aligned at least for MINPAGESIZE.  */

	  l_addr = l_dynaddr - dynaddr;

	  if ((l_addr & (minpagesize - 1)) == 0
	      && (l_addr & align) == ((l_dynaddr - dynaddr) & align))
	    {
	      if (info_verbose)
		gdb_printf (_("Using PIC (Position Independent Code) "
			      "prelink displacement %s for \"%s\".\n"),
			    paddress (current_inferior ()->arch (), l_addr),
			    so.name.c_str ());
	    }
	  else
	    {
	      /* There is no way to verify the library file matches.  prelink
		 can during prelinking of an unprelinked file (or unprelinking
		 of a prelinked file) shift the DYNAMIC segment by arbitrary
		 offset without any page size alignment.  There is no way to
		 find out the ELF header and/or Program Headers for a limited
		 verification if it they match.  One could do a verification
		 of the DYNAMIC segment.  Still the found address is the best
		 one GDB could find.  */

	      warning (_(".dynamic section for \"%s\" "
			 "is not at the expected address "
			 "(wrong library or version mismatch?)"),
			 so.name.c_str ());
	    }
	}

    set_addr:
      li->l_addr = l_addr;
      li->l_addr_p = 1;
    }

  return li->l_addr;
}

struct svr4_so
{
  svr4_so (const char *name, lm_info_svr4_up lm_info)
    : name (name), lm_info (std::move (lm_info))
  {}

  std::string name;
  lm_info_svr4_up lm_info;
};

/* Per pspace SVR4 specific data.  */

struct svr4_info
{
  /* Base of dynamic linker structures in default namespace.  */
  CORE_ADDR debug_base = 0;

  /* Validity flag for debug_loader_offset.  */
  int debug_loader_offset_p = 0;

  /* Load address for the dynamic linker, inferred.  */
  CORE_ADDR debug_loader_offset = 0;

  /* Name of the dynamic linker, valid if debug_loader_offset_p.  */
  std::string debug_loader_name;

  /* Load map address for the main executable in default namespace.  */
  CORE_ADDR main_lm_addr = 0;

  CORE_ADDR interp_text_sect_low = 0;
  CORE_ADDR interp_text_sect_high = 0;
  CORE_ADDR interp_plt_sect_low = 0;
  CORE_ADDR interp_plt_sect_high = 0;

  /* True if the list of objects was last obtained from the target
     via qXfer:libraries-svr4:read.  */
  bool using_xfer = false;

  /* Table of struct probe_and_action instances, used by the
     probes-based interface to map breakpoint addresses to probes
     and their associated actions.  Lookup is performed using
     probe_and_action->prob->address.  */
  htab_up probes_table;

  /* List of objects loaded into the inferior per namespace, used by the
     probes-based interface.

     The namespace is represented by the address of its corresponding
     r_debug[_ext] object.  We get the namespace id as argument to the
     'reloc_complete' probe but we don't get it when scanning the load map
     on attach.

     The r_debug[_ext] objects may move when ld.so itself moves.  In that
     case, we expect also the global _r_debug to move so we can detect
     this and reload everything.  The r_debug[_ext] objects are not
     expected to move individually.

     The special entry zero is reserved for a linear list to support
     gdbstubs that do not support namespaces.  */
  std::map<CORE_ADDR, std::vector<svr4_so>> solib_lists;

  /* Mapping between r_debug[_ext] addresses and a user-friendly
     identifier for the namespace.  A vector is used to make it
     easy to assign new internal IDs to namespaces.

     For gdbservers that don't support namespaces, the first (and only)
     entry of the vector will be 0.

     A note on consistency. We can't make the IDs be consistent before
     and after the initial relocation of the inferior (when the global
     _r_debug is relocated, as mentioned in the previous comment).  It is
     likely that this is a non-issue, since the inferior can't have called
     dlmopen yet, but I think it is worth noting.

     The only issue I am aware at this point is that, if when parsing an
     XML file, we read an LMID that given by an XML file (and read in
     library_list_start_library) is the identifier obtained with dlinfo
     instead of the address of r_debug[_ext], and after attaching the
     inferior adds another SO to that namespace, we might double-count it
     since we won't have access to the LMID later on.  However, this is
     already a problem with the existing solib_lists code.  */
  std::vector<CORE_ADDR> namespace_id;

  /* This identifies which namespaces are active.  A namespace is considered
     active when there is at least one shared object loaded into it.  */
  std::set<size_t> active_namespaces;

  /* This flag indicates whether initializations related to the
     GLIBC TLS module id tracking code have been performed.  */
  bool glibc_tls_slots_inited = false;

  /* A vector of link map addresses for GLIBC TLS slots.  See comment
     for tls_maybe_fill_slot for more information.  */
  std::vector<CORE_ADDR> glibc_tls_slots;
};

/* Per-program-space data key.  */
static const registry<program_space>::key<svr4_info> solib_svr4_pspace_data;

/* Check if the lmid address is already assigned an ID in the svr4_info,
   and if not, assign it one and add it to the list of known namespaces.  */
static void
svr4_maybe_add_namespace (svr4_info *info, CORE_ADDR lmid)
{
  int i;
  for (i = 0; i < info->namespace_id.size (); i++)
    {
      if (info->namespace_id[i] == lmid)
	break;
    }
  if (i == info->namespace_id.size ())
    info->namespace_id.push_back (lmid);

  info->active_namespaces.insert (i);

  /* Create or update the convenience variable "active_namespaces".
     It only needs to be updated here, as this only changes when a
     dlmopen or dlclose call happens.  */
  set_internalvar_integer (lookup_internalvar ("_active_linker_namespaces"),
			   info->active_namespaces.size ());
}

/* Return whether DEBUG_BASE is the default namespace of INFO.  */

static bool
svr4_is_default_namespace (const svr4_info *info, CORE_ADDR debug_base)
{
  return (debug_base == info->debug_base);
}

/* Free the probes table.  */

void
svr4_solib_ops::free_probes_table (svr4_info *info) const
{
  info->probes_table.reset (nullptr);
}

/* Get the svr4 data for program space PSPACE.  If none is found yet, add it now.
   This function always returns a valid object.  */

static struct svr4_info *
get_svr4_info (program_space *pspace)
{
  struct svr4_info *info = solib_svr4_pspace_data.get (pspace);

  if (info == NULL)
    info = solib_svr4_pspace_data.emplace (pspace);

  return info;
}

/* Local function prototypes */

static int match_main (const char *);

/* Read program header TYPE from inferior memory.  The header is found
   by scanning the OS auxiliary vector.

   If TYPE == -1, return the program headers instead of the contents of
   one program header.

   Return vector of bytes holding the program header contents, or an empty
   optional on failure.  If successful and P_ARCH_SIZE is non-NULL, the target
   architecture size (32-bit or 64-bit) is returned to *P_ARCH_SIZE.  Likewise,
   the base address of the section is returned in *BASE_ADDR.  */

static std::optional<gdb::byte_vector>
read_program_header (int type, int *p_arch_size, CORE_ADDR *base_addr)
{
  bfd_endian byte_order = gdbarch_byte_order (current_inferior ()->arch ());
  CORE_ADDR at_phdr, at_phent, at_phnum, pt_phdr = 0;
  int arch_size, sect_size;
  CORE_ADDR sect_addr;
  int pt_phdr_p = 0;

  /* Get required auxv elements from target.  */
  if (target_auxv_search (AT_PHDR, &at_phdr) <= 0)
    return {};
  if (target_auxv_search (AT_PHENT, &at_phent) <= 0)
    return {};
  if (target_auxv_search (AT_PHNUM, &at_phnum) <= 0)
    return {};
  if (!at_phdr || !at_phnum)
    return {};

  /* Determine ELF architecture type.  */
  if (at_phent == sizeof (Elf32_External_Phdr))
    arch_size = 32;
  else if (at_phent == sizeof (Elf64_External_Phdr))
    arch_size = 64;
  else
    return {};

  /* Find the requested segment.  */
  if (type == -1)
    {
      sect_addr = at_phdr;
      sect_size = at_phent * at_phnum;
    }
  else if (arch_size == 32)
    {
      Elf32_External_Phdr phdr;
      int i;

      /* Search for requested PHDR.  */
      for (i = 0; i < at_phnum; i++)
	{
	  int p_type;

	  if (target_read_memory (at_phdr + i * sizeof (phdr),
				  (gdb_byte *)&phdr, sizeof (phdr)))
	    return {};

	  p_type = extract_unsigned_integer ((gdb_byte *) phdr.p_type,
					     4, byte_order);

	  if (p_type == PT_PHDR)
	    {
	      pt_phdr_p = 1;
	      pt_phdr = extract_unsigned_integer ((gdb_byte *) phdr.p_vaddr,
						  4, byte_order);
	    }

	  if (p_type == type)
	    break;
	}

      if (i == at_phnum)
	return {};

      /* Retrieve address and size.  */
      sect_addr = extract_unsigned_integer ((gdb_byte *)phdr.p_vaddr,
					    4, byte_order);
      sect_size = extract_unsigned_integer ((gdb_byte *)phdr.p_memsz,
					    4, byte_order);
    }
  else
    {
      Elf64_External_Phdr phdr;
      int i;

      /* Search for requested PHDR.  */
      for (i = 0; i < at_phnum; i++)
	{
	  int p_type;

	  if (target_read_memory (at_phdr + i * sizeof (phdr),
				  (gdb_byte *)&phdr, sizeof (phdr)))
	    return {};

	  p_type = extract_unsigned_integer ((gdb_byte *) phdr.p_type,
					     4, byte_order);

	  if (p_type == PT_PHDR)
	    {
	      pt_phdr_p = 1;
	      pt_phdr = extract_unsigned_integer ((gdb_byte *) phdr.p_vaddr,
						  8, byte_order);
	    }

	  if (p_type == type)
	    break;
	}

      if (i == at_phnum)
	return {};

      /* Retrieve address and size.  */
      sect_addr = extract_unsigned_integer ((gdb_byte *)phdr.p_vaddr,
					    8, byte_order);
      sect_size = extract_unsigned_integer ((gdb_byte *)phdr.p_memsz,
					    8, byte_order);
    }

  /* PT_PHDR is optional, but we really need it
     for PIE to make this work in general.  */

  if (pt_phdr_p)
    {
      /* at_phdr is real address in memory. pt_phdr is what pheader says it is.
	 Relocation offset is the difference between the two. */
      sect_addr = sect_addr + (at_phdr - pt_phdr);
    }

  /* Read in requested program header.  */
  gdb::byte_vector buf (sect_size);
  if (target_read_memory (sect_addr, buf.data (), sect_size))
    return {};

  if (p_arch_size)
    *p_arch_size = arch_size;
  if (base_addr)
    *base_addr = sect_addr;

  return buf;
}

/* See solib-svr4.h.  */

std::optional<gdb::byte_vector>
svr4_find_program_interpreter ()
{
  /* If we have a current exec_bfd, use its section table.  */
  if (current_program_space->exec_bfd ()
      && (bfd_get_flavour (current_program_space->exec_bfd ())
	  == bfd_target_elf_flavour))
   {
     struct bfd_section *interp_sect;

     interp_sect = bfd_get_section_by_name (current_program_space->exec_bfd (),
					    ".interp");
     if (interp_sect != NULL)
      {
	int sect_size = bfd_section_size (interp_sect);

	gdb::byte_vector buf (sect_size);
	bool res
	  = bfd_get_section_contents (current_program_space->exec_bfd (),
				      interp_sect, buf.data (), 0, sect_size);
	if (res)
	  return buf;
      }
   }

  /* If we didn't find it, use the target auxiliary vector.  */
  return read_program_header (PT_INTERP, NULL, NULL);
}


/* Scan for DESIRED_DYNTAG in .dynamic section of the target's main executable,
   found by consulting the OS auxiliary vector.  If DESIRED_DYNTAG is found, 1
   is returned and the corresponding PTR is set.  */

static int
scan_dyntag_auxv (const int desired_dyntag, CORE_ADDR *ptr,
		  CORE_ADDR *ptr_addr)
{
  bfd_endian byte_order = gdbarch_byte_order (current_inferior ()->arch ());
  int arch_size, step;
  long current_dyntag;
  CORE_ADDR dyn_ptr;
  CORE_ADDR base_addr;

  /* Read in .dynamic section.  */
  std::optional<gdb::byte_vector> ph_data
    = read_program_header (PT_DYNAMIC, &arch_size, &base_addr);
  if (!ph_data)
    return 0;

  /* Iterate over BUF and scan for DYNTAG.  If found, set PTR and return.  */
  step = (arch_size == 32) ? sizeof (Elf32_External_Dyn)
			   : sizeof (Elf64_External_Dyn);
  for (gdb_byte *buf = ph_data->data (), *bufend = buf + ph_data->size ();
       buf < bufend; buf += step)
  {
    if (arch_size == 32)
      {
	Elf32_External_Dyn *dynp = (Elf32_External_Dyn *) buf;

	current_dyntag = extract_unsigned_integer ((gdb_byte *) dynp->d_tag,
					    4, byte_order);
	dyn_ptr = extract_unsigned_integer ((gdb_byte *) dynp->d_un.d_ptr,
					    4, byte_order);
      }
    else
      {
	Elf64_External_Dyn *dynp = (Elf64_External_Dyn *) buf;

	current_dyntag = extract_unsigned_integer ((gdb_byte *) dynp->d_tag,
					    8, byte_order);
	dyn_ptr = extract_unsigned_integer ((gdb_byte *) dynp->d_un.d_ptr,
					    8, byte_order);
      }
    if (current_dyntag == DT_NULL)
      break;

    if (current_dyntag == desired_dyntag)
      {
	if (ptr)
	  *ptr = dyn_ptr;

	if (ptr_addr)
	  *ptr_addr = base_addr + buf - ph_data->data ();

	return 1;
      }
  }

  return 0;
}

/* Locate the base address of dynamic linker structs for SVR4 elf
   targets.

   For SVR4 elf targets the address of the dynamic linker's runtime
   structure is contained within the dynamic info section in the
   executable file.  The dynamic section is also mapped into the
   inferior address space.  Because the runtime loader fills in the
   real address before starting the inferior, we have to read in the
   dynamic info section from the inferior address space.
   If there are any errors while trying to find the address, we
   silently return 0, otherwise the found address is returned.  */

static CORE_ADDR
elf_locate_base (void)
{
  CORE_ADDR dyn_ptr, dyn_ptr_addr;

  /* Look for DT_MIPS_RLD_MAP first.  MIPS executables use this
     instead of DT_DEBUG, although they sometimes contain an unused
     DT_DEBUG.  */
  if (gdb_bfd_scan_elf_dyntag (DT_MIPS_RLD_MAP,
			       current_program_space->exec_bfd (),
			       &dyn_ptr, NULL)
      || scan_dyntag_auxv (DT_MIPS_RLD_MAP, &dyn_ptr, NULL))
    {
      type *ptr_type
	= builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
      gdb_byte *pbuf;
      int pbuf_size = ptr_type->length ();

      pbuf = (gdb_byte *) alloca (pbuf_size);
      /* DT_MIPS_RLD_MAP contains a pointer to the address
	 of the dynamic link structure.  */
      if (target_read_memory (dyn_ptr, pbuf, pbuf_size))
	return 0;
      return extract_typed_address (pbuf, ptr_type);
    }

  /* Then check DT_MIPS_RLD_MAP_REL.  MIPS executables now use this form
     because of needing to support PIE.  DT_MIPS_RLD_MAP will also exist
     in non-PIE.  */
  if (gdb_bfd_scan_elf_dyntag (DT_MIPS_RLD_MAP_REL,
			       current_program_space->exec_bfd (),
			       &dyn_ptr, &dyn_ptr_addr)
      || scan_dyntag_auxv (DT_MIPS_RLD_MAP_REL, &dyn_ptr, &dyn_ptr_addr))
    {
      type *ptr_type
	= builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
      gdb_byte *pbuf;
      int pbuf_size = ptr_type->length ();

      pbuf = (gdb_byte *) alloca (pbuf_size);
      /* DT_MIPS_RLD_MAP_REL contains an offset from the address of the
	 DT slot to the address of the dynamic link structure.  */
      if (target_read_memory (dyn_ptr + dyn_ptr_addr, pbuf, pbuf_size))
	return 0;
      return extract_typed_address (pbuf, ptr_type);
    }

  /* Find DT_DEBUG.  */
  if (gdb_bfd_scan_elf_dyntag (DT_DEBUG, current_program_space->exec_bfd (),
			       &dyn_ptr, NULL)
      || scan_dyntag_auxv (DT_DEBUG, &dyn_ptr, NULL))
    return dyn_ptr;

  /* This may be a static executable.  Look for the symbol
     conventionally named _r_debug, as a last resort.  */
  bound_minimal_symbol msymbol
    = lookup_minimal_symbol (current_program_space, "_r_debug",
			     current_program_space->symfile_object_file);
  if (msymbol.minsym != NULL)
    return msymbol.value_address ();

  /* DT_DEBUG entry not found.  */
  return 0;
}

/* Find the first element in the inferior's dynamic link map, and
   return its address in the inferior.  Return zero if the address
   could not be determined.

   FIXME: Perhaps we should validate the info somehow, perhaps by
   checking r_version for a known version number, or r_state for
   RT_CONSISTENT.  */

CORE_ADDR
svr4_solib_ops::read_r_map (CORE_ADDR debug_base) const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  type *ptr_type
    = builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
  CORE_ADDR addr = 0;

  try
    {
      addr = read_memory_typed_address (debug_base + lmo->r_map_offset,
					ptr_type);
    }
  catch (const gdb_exception_error &ex)
    {
      exception_print (gdb_stderr, ex);
    }

  return addr;
}

/* Find r_brk from the inferior's debug base.  */

CORE_ADDR
svr4_solib_ops::find_r_brk (svr4_info *info) const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  type *ptr_type
    = builtin_type (current_inferior ()->arch ())->builtin_data_ptr;

  return read_memory_typed_address (info->debug_base + lmo->r_brk_offset,
				    ptr_type);
}

/* Find the link map for the dynamic linker (if it is not in the
   normal list of loaded shared objects).  */

CORE_ADDR
svr4_solib_ops::find_r_ldsomap (svr4_info *info) const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  type *ptr_type
    = builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
  enum bfd_endian byte_order = type_byte_order (ptr_type);
  ULONGEST version = 0;

  try
    {
      /* Check version, and return zero if `struct r_debug' doesn't have
	 the r_ldsomap member.  */
      version
	= read_memory_unsigned_integer (info->debug_base + lmo->r_version_offset,
					lmo->r_version_size, byte_order);
    }
  catch (const gdb_exception_error &ex)
    {
      exception_print (gdb_stderr, ex);
    }

  if (version < 2 || lmo->r_ldsomap_offset == -1)
    return 0;

  return read_memory_typed_address (info->debug_base + lmo->r_ldsomap_offset,
				    ptr_type);
}

/* Find the next namespace from the r_next field.  */

CORE_ADDR
svr4_solib_ops::read_r_next (CORE_ADDR debug_base) const
{
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  type *ptr_type
    = builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
  bfd_endian byte_order = type_byte_order (ptr_type);
  ULONGEST version = 0;

  try
    {
      version
	= read_memory_unsigned_integer (debug_base + lmo->r_version_offset,
					lmo->r_version_size, byte_order);
    }
  catch (const gdb_exception_error &ex)
    {
      exception_print (gdb_stderr, ex);
    }

  /* The r_next field is added with r_version == 2.  */
  if (version < 2 || lmo->r_next_offset == -1)
    return 0;

  return read_memory_typed_address (debug_base + lmo->r_next_offset,
				    ptr_type);
}

/* On Solaris systems with some versions of the dynamic linker,
   ld.so's l_name pointer points to the SONAME in the string table
   rather than into writable memory.  So that GDB can find shared
   libraries when loading a core file generated by gcore, ensure that
   memory areas containing the l_name string are saved in the core
   file.  */

bool
svr4_solib_ops::keep_data_in_core (CORE_ADDR vaddr, unsigned long size) const
{
  struct svr4_info *info;
  CORE_ADDR ldsomap;
  CORE_ADDR name_lm;

  info = get_svr4_info (current_program_space);

  info->debug_base = elf_locate_base ();
  if (info->debug_base == 0)
    return false;

  ldsomap = this->find_r_ldsomap (info);
  if (!ldsomap)
    return false;

  std::unique_ptr<lm_info_svr4> li = this->read_lm_info (ldsomap);
  name_lm = li != NULL ? li->l_name : 0;

  return (name_lm >= vaddr && name_lm < vaddr + size);
}

/* See solib.h.  */

bool
svr4_solib_ops::open_symbol_file_object (int from_tty) const
{
  CORE_ADDR lm, l_name;
  link_map_offsets *lmo = this->fetch_link_map_offsets ();
  type *ptr_type
    = builtin_type (current_inferior ()->arch ())->builtin_data_ptr;
  int l_name_size = ptr_type->length ();
  gdb::byte_vector l_name_buf (l_name_size);
  struct svr4_info *info = get_svr4_info (current_program_space);
  symfile_add_flags add_flags = 0;

  if (from_tty)
    add_flags |= SYMFILE_VERBOSE;

  if (current_program_space->symfile_object_file)
    if (!query (_("Attempt to reload symbols from process? ")))
      return false;

  /* Always locate the debug struct, in case it has moved.  */
  info->debug_base = elf_locate_base ();
  if (info->debug_base == 0)
    return false;	/* failed somehow...  */

  /* First link map member should be the executable.  */
  lm = this->read_r_map (info->debug_base);
  if (lm == 0)
    return false;	/* failed somehow...  */

  /* Read address of name from target memory to GDB.  */
  read_memory (lm + lmo->l_name_offset, l_name_buf.data (), l_name_size);

  /* Convert the address to host format.  */
  l_name = extract_typed_address (l_name_buf.data (), ptr_type);

  if (l_name == 0)
    return false;		/* No filename.  */

  /* Now fetch the filename from target memory.  */
  gdb::unique_xmalloc_ptr<char> filename
    = target_read_string (l_name, SO_NAME_MAX_PATH_SIZE - 1);

  if (filename == nullptr)
    {
      warning (_("failed to read exec filename from attached file"));
      return false;
    }

  /* Have a pathname: read the symbol file.  */
  symbol_file_add_main (filename.get (), add_flags);

  return true;
}

/* Data exchange structure for the XML parser as returned by
   svr4_current_sos_via_xfer_libraries.  */

struct svr4_library_list
{
  /* The so list for the current namespace.  This is internal to XML
     parsing.  */
  std::vector<svr4_so> *cur_list;

  /* Inferior address of struct link_map used for the main executable.  It is
     NULL if not known.  */
  CORE_ADDR main_lm;

  /* List of objects loaded into the inferior per namespace.  This does
     not include any default sos.

     See comment on struct svr4_info.solib_lists.  */
  std::map<CORE_ADDR, std::vector<svr4_so>> solib_lists;
};

/* This module's 'free_objfile' observer.  */

static void
svr4_free_objfile_observer (struct objfile *objfile)
{
  probes_table_remove_objfile_probes (objfile);
}

/* Implement solib_ops.clear_so.  */

void
svr4_solib_ops::clear_so (const solib &so) const
{
  auto *li = gdb::checked_static_cast<lm_info_svr4 *> (so.lm_info.get ());

  if (li != NULL)
    li->l_addr_p = 0;
}

/* Create the solib objects equivalent to the svr4_sos in SOS.  */

owning_intrusive_list<solib>
svr4_solib_ops::solibs_from_svr4_sos (const std::vector<svr4_so> &sos) const
{
  owning_intrusive_list<solib> dst;

  for (const svr4_so &so : sos)
    {
      auto &newobj = dst.emplace_back (*this);

      newobj.name = so.name;
      newobj.original_name = so.name;
      newobj.lm_info = std::make_unique<lm_info_svr4> (*so.lm_info);
    }

  return dst;
}

#ifdef HAVE_LIBEXPAT

#include "xml-support.h"

/* Handle the start of a <library> element.  Note: new elements are added
   at the tail of the list, keeping the list in order.  */

static void
library_list_start_library (struct gdb_xml_parser *parser,
			    const struct gdb_xml_element *element,
			    void *user_data,
			    std::vector<gdb_xml_value> &attributes)
{
  struct svr4_library_list *list = (struct svr4_library_list *) user_data;
  const char *name
    = (const char *) xml_find_attribute (attributes, "name")->value.get ();
  ULONGEST *lmp
    = (ULONGEST *) xml_find_attribute (attributes, "lm")->value.get ();
  ULONGEST *l_addrp
    = (ULONGEST *) xml_find_attribute (attributes, "l_addr")->value.get ();
  ULONGEST *l_ldp
    = (ULONGEST *) xml_find_attribute (attributes, "l_ld")->value.get ();

  lm_info_svr4_up li = std::make_unique<lm_info_svr4> ();
  li->lm_addr = *lmp;
  li->l_addr_inferior = *l_addrp;
  li->l_ld = *l_ldp;

  std::vector<svr4_so> *solist;

  /* Older versions did not supply lmid.  Put the element into the flat
     list of the special namespace zero in that case.  */
  gdb_xml_value *at_lmid = xml_find_attribute (attributes, "lmid");
  svr4_info *info = get_svr4_info (current_program_space);
  if (at_lmid == nullptr)
    {
      solist = list->cur_list;
      svr4_maybe_add_namespace (info, 0);
    }
  else
    {
      ULONGEST lmid = *(ULONGEST *) at_lmid->value.get ();
      solist = &list->solib_lists[lmid];
      svr4_maybe_add_namespace (info, lmid);
    }
  solist->emplace_back (name, std::move (li));
}

/* Handle the start of a <library-list-svr4> element.  */

static void
svr4_library_list_start_list (struct gdb_xml_parser *parser,
			      const struct gdb_xml_element *element,
			      void *user_data,
			      std::vector<gdb_xml_value> &attributes)
{
  struct svr4_library_list *list = (struct svr4_library_list *) user_data;
  const char *version
    = (const char *) xml_find_attribute (attributes, "version")->value.get ();
  struct gdb_xml_value *main_lm = xml_find_attribute (attributes, "main-lm");

  if (strcmp (version, "1.0") != 0)
    gdb_xml_error (parser,
		   _("SVR4 Library list has unsupported version \"%s\""),
		   version);

  if (main_lm)
    list->main_lm = *(ULONGEST *) main_lm->value.get ();

  /* Older gdbserver do not support namespaces.  We use the special
     namespace zero for a linear list of libraries.  */
  list->cur_list = &list->solib_lists[0];
}

/* The allowed elements and attributes for an XML library list.
   The root element is a <library-list>.  */

static const struct gdb_xml_attribute svr4_library_attributes[] =
{
  { "name", GDB_XML_AF_NONE, NULL, NULL },
  { "lm", GDB_XML_AF_NONE, gdb_xml_parse_attr_ulongest, NULL },
  { "l_addr", GDB_XML_AF_NONE, gdb_xml_parse_attr_ulongest, NULL },
  { "l_ld", GDB_XML_AF_NONE, gdb_xml_parse_attr_ulongest, NULL },
  { "lmid", GDB_XML_AF_NONE, gdb_xml_parse_attr_ulongest, NULL },
  { NULL, GDB_XML_AF_NONE, NULL, NULL }
};

static const struct gdb_xml_element svr4_library_list_children[] =
{
  {
    "library", svr4_library_attributes, NULL,
    GDB_XML_EF_REPEATABLE | GDB_XML_EF_OPTIONAL,
    library_list_start_library, NULL
  },
  { NULL, NULL, NULL, GDB_XML_EF_NONE, NULL, NULL }
};

static const struct gdb_xml_attribute svr4_library_list_attributes[] =
{
  { "version", GDB_XML_AF_NONE, NULL, NULL },
  { "main-lm", GDB_XML_AF_OPTIONAL, gdb_xml_parse_attr_ulongest, NULL },
  { NULL, GDB_XML_AF_NONE, NULL, NULL }
};

static const struct gdb_xml_element svr4_library_list_elements[] =
{
  { "library-list-svr4", svr4_library_list_attributes, svr4_library_list_children,
    GDB_XML_EF_NONE, svr4_library_list_start_list, NULL },
  { NULL, NULL, NULL, GDB_XML_EF_NONE, NULL, NULL }
};

/* Parse qXfer:libraries:read packet into *LIST.

   Return 0 if packet not supported, *LIST is not modified in such case.
   Return 1 if *LIST contains the library list.  */

static int
svr4_parse_libraries (const char *document, struct svr4_library_list *list)
{
  auto cleanup = make_scope_exit ([list] ()
    {  list->solib_lists.clear (); });

  list->cur_list = nullptr;
  list->main_lm = 0;
  list->solib_lists.clear ();
  if (gdb_xml_parse_quick (_("target library list"), "library-list-svr4.dtd",
			   svr4_library_list_elements, document, list) == 0)
    {
      /* Parsed successfully, keep the result.  */
      cleanup.release ();
      return 1;
    }

  return 0;
}

/* Attempt to get the shared object list from target via
   qXfer:libraries-svr4:read packet.

   Return 0 if packet not supported, *LIST is not modified in such case.
   Return 1 if *LIST contains the library list.

   Note that ANNEX must be NULL if the remote does not explicitly allow
   qXfer:libraries-svr4:read packets with non-empty annexes.  Support for
   this can be checked using target_augmented_libraries_svr4_read ().  */

static int
svr4_current_sos_via_xfer_libraries (struct svr4_library_list *list,
				     const char *annex)
{
  gdb_assert (annex == NULL || target_augmented_libraries_svr4_read ());

  /* Fetch the list of shared libraries.  */
  std::optional<gdb::char_vector> svr4_library_document
    = target_read_stralloc (current_inferior ()->top_target (),
			    TARGET_OBJECT_LIBRARIES_SVR4,
			    annex);
  if (!svr4_library_document)
    return 0;

  return svr4_parse_libraries (svr4_library_document->data (), list);
}

#else

static int
svr4_current_sos_via_xfer_libraries (struct svr4_library_list *list,
				     const char *annex)
{
  return 0;
}

#endif

/* If no shared library information is available from the dynamic
   linker, build a fallback list from other sources.  */

owning_intrusive_list<solib>
svr4_solib_ops::default_sos (svr4_info *info) const
{
  if (!info->debug_loader_offset_p)
    return {};

  auto li = std::make_unique<lm_info_svr4> ();

  /* Nothing will ever check the other fields if we set l_addr_p.  */
  li->l_addr = li->l_addr_inferior = info->debug_loader_offset;
  li->l_addr_p = 1;

  owning_intrusive_list<solib> sos;
  auto &newobj = sos.emplace_back (*this);

  newobj.lm_info = std::move (li);
  newobj.name = info->debug_loader_name;
  newobj.original_name = newobj.name;

  return sos;
}

/* Read the whole inferior libraries chain starting at address LM.
   Expect the first entry in the chain's previous entry to be PREV_LM.
   Add the entries to SOS.  Ignore the first entry if IGNORE_FIRST and set
   global MAIN_LM_ADDR according to it.  Returns nonzero upon success.  If zero
   is returned the entries stored to LINK_PTR_PTR are still valid although they may
   represent only part of the inferior library list.  */

int
svr4_solib_ops::read_so_list (svr4_info *info, CORE_ADDR lm, CORE_ADDR prev_lm,
			      std::vector<svr4_so> &sos, int ignore_first) const
{
  CORE_ADDR first_l_name = 0;
  CORE_ADDR next_lm;

  for (; lm != 0; prev_lm = lm, lm = next_lm)
    {
      lm_info_svr4_up li = this->read_lm_info (lm);
      if (li == NULL)
	return 0;

      next_lm = li->l_next;

      if (li->l_prev != prev_lm)
	{
	  warning (_("Corrupted shared library list: %s != %s"),
		   paddress (current_inferior ()->arch (), prev_lm),
		   paddress (current_inferior ()->arch (), li->l_prev));
	  return 0;
	}

      /* For SVR4 versions, the first entry in the link map is for the
	 inferior executable, so we must ignore it.  For some versions of
	 SVR4, it has no name.  For others (Solaris 2.3 for example), it
	 does have a name, so we can no longer use a missing name to
	 decide when to ignore it.  */
      if (ignore_first && li->l_prev == 0)
	{
	  first_l_name = li->l_name;
	  info->main_lm_addr = li->lm_addr;
	  continue;
	}

      /* Extract this shared object's name.  */
      gdb::unique_xmalloc_ptr<char> name
	= target_read_string (li->l_name, SO_NAME_MAX_PATH_SIZE - 1);
      if (name == nullptr)
	{
	  /* If this entry's l_name address matches that of the
	     inferior executable, then this is not a normal shared
	     object, but (most likely) a vDSO.  In this case, silently
	     skip it; otherwise emit a warning. */
	  if (first_l_name == 0 || li->l_name != first_l_name)
	    warning (_("Can't read pathname for load map."));
	  continue;
	}

      /* If this entry has no name, or its name matches the name
	 for the main executable, don't include it in the list.  */
      if (*name == '\0' || match_main (name.get ()))
	continue;

      sos.emplace_back (name.get (), std::move (li));
    }

  return 1;
}

/* Read the full list of currently loaded shared objects directly
   from the inferior, without referring to any libraries read and
   stored by the probes interface.  Handle special cases relating
   to the first elements of the list in default namespace.  */

void
svr4_solib_ops::current_sos_direct (svr4_info *info) const
{
  CORE_ADDR lm;
  bool ignore_first;
  struct svr4_library_list library_list;

  /* Remove any old libraries.  We're going to read them back in again.  */
  info->solib_lists.clear ();

  info->active_namespaces.clear ();

  /* Fall back to manual examination of the target if the packet is not
     supported or gdbserver failed to find DT_DEBUG.  gdb.server/solib-list.exp
     tests a case where gdbserver cannot find the shared libraries list while
     GDB itself is able to find it via SYMFILE_OBJFILE.

     Unfortunately statically linked inferiors will also fall back through this
     suboptimal code path.  */

  info->using_xfer = svr4_current_sos_via_xfer_libraries (&library_list,
							  NULL);
  if (info->using_xfer)
    {
      if (library_list.main_lm)
	info->main_lm_addr = library_list.main_lm;

      /* Remove an empty special zero namespace so we know that when there
	 is one, it is actually used, and we have a flat list without
	 namespace information.  */
      auto it_0 = library_list.solib_lists.find (0);
      if (it_0 != library_list.solib_lists.end ()
	  && it_0->second.empty ())
	library_list.solib_lists.erase (it_0);

      /* Replace the (empty) solib_lists in INFO with the one generated
	 from the target.  We don't want to copy it on assignment and then
	 delete the original afterwards, so let's just swap the
	 internals.  */
      std::swap (info->solib_lists, library_list.solib_lists);
      return;
    }

  /* If we can't find the dynamic linker's base structure, this
     must not be a dynamically linked executable.  Hmm.  */
  info->debug_base = elf_locate_base ();
  if (info->debug_base == 0)
    return;

  /* Assume that everything is a library if the dynamic loader was loaded
     late by a static executable.  */
  if (current_program_space->exec_bfd ()
      && bfd_get_section_by_name (current_program_space->exec_bfd (),
				  ".dynamic") == NULL)
    ignore_first = false;
  else
    ignore_first = true;

  auto cleanup = make_scope_exit ([info] ()
    {
      info->solib_lists.clear ();
      info->active_namespaces.clear ();
    });

  /* Collect the sos in each namespace.  */
  CORE_ADDR debug_base = info->debug_base;
  for (; debug_base != 0;
       ignore_first = false, debug_base = this->read_r_next (debug_base))
    {
      /* Walk the inferior's link map list, and build our so_list list.  */
      lm = this->read_r_map (debug_base);
      if (lm != 0)
	{
	  svr4_maybe_add_namespace (info, debug_base);
	  this->read_so_list (info, lm, 0, info->solib_lists[debug_base],
			      ignore_first);
	}
    }

  /* On Solaris, the dynamic linker is not in the normal list of
     shared objects, so make sure we pick it up too.  Having
     symbol information for the dynamic linker is quite crucial
     for skipping dynamic linker resolver code.

     Note that we interpret the ldsomap load map address as 'virtual'
     r_debug object.  If we added it to the default namespace (as it was),
     we would probably run into inconsistencies with the load map's
     prev/next links (I wonder if we did).  */
  debug_base = this->find_r_ldsomap (info);
  if (debug_base != 0)
    {
      /* Add the dynamic linker's namespace unless we already did.  */
      if (info->solib_lists.find (debug_base) == info->solib_lists.end ())
	{
	  svr4_maybe_add_namespace (info, debug_base);
	  this->read_so_list (info, debug_base, 0,
			      info->solib_lists[debug_base], 0);
	}
    }

  cleanup.release ();
}

/* Collect sos read and stored by the probes interface.  */

owning_intrusive_list<solib>
svr4_solib_ops::collect_probes_sos (svr4_info *info) const
{
  owning_intrusive_list<solib> res;

  for (const auto &tuple : info->solib_lists)
    {
      const std::vector<svr4_so> &sos = tuple.second;
      res.splice (this->solibs_from_svr4_sos (sos));
    }

  return res;
}

/* Implement the main part of the "current_sos" solib_ops
   method.  */

owning_intrusive_list<solib>
svr4_solib_ops::current_sos_1 (svr4_info *info) const
{
  owning_intrusive_list<solib> sos;

  /* If we're using the probes interface, we can use the cache as it will
     be maintained by probe update/reload actions.  */
  if (info->probes_table != nullptr)
    sos = this->collect_probes_sos (info);

  /* If we're not using the probes interface or if we didn't cache
     anything, read the sos to fill the cache, then collect them from the
     cache.  */
  if (sos.empty ())
    {
      this->current_sos_direct (info);

      sos = this->collect_probes_sos (info);
      if (sos.empty ())
	sos = this->default_sos (info);
    }

  return sos;
}

/* Implement the "current_sos" solib_ops method.  */

owning_intrusive_list<solib>
svr4_solib_ops::current_sos () const
{
  svr4_info *info = get_svr4_info (current_program_space);
  owning_intrusive_list<solib> sos = this->current_sos_1 (info);
  struct mem_range vsyscall_range;

  /* Filter out the vDSO module, if present.  Its symbol file would
     not be found on disk.  The vDSO/vsyscall's OBJFILE is instead
     managed by symfile-mem.c:add_vsyscall_page.  */
  if (gdbarch_vsyscall_range (current_inferior ()->arch (), &vsyscall_range)
      && vsyscall_range.length != 0)
    {
      for (auto so = sos.begin (); so != sos.end (); )
	{
	  /* We can't simply match the vDSO by starting address alone,
	     because lm_info->l_addr_inferior (and also l_addr) do not
	     necessarily represent the real starting address of the
	     ELF if the vDSO's ELF itself is "prelinked".  The l_ld
	     field (the ".dynamic" section of the shared object)
	     always points at the absolute/resolved address though.
	     So check whether that address is inside the vDSO's
	     mapping instead.

	     E.g., on Linux 3.16 (x86_64) the vDSO is a regular
	     0-based ELF, and we see:

	      (gdb) info auxv
	      33  AT_SYSINFO_EHDR  System-supplied DSO's ELF header 0x7ffff7ffb000
	      (gdb)  p/x *_r_debug.r_map.l_next
	      $1 = {l_addr = 0x7ffff7ffb000, ..., l_ld = 0x7ffff7ffb318, ...}

	     And on Linux 2.6.32 (x86_64) we see:

	      (gdb) info auxv
	      33  AT_SYSINFO_EHDR  System-supplied DSO's ELF header 0x7ffff7ffe000
	      (gdb) p/x *_r_debug.r_map.l_next
	      $5 = {l_addr = 0x7ffff88fe000, ..., l_ld = 0x7ffff7ffe580, ... }

	     Dumping that vDSO shows:

	      (gdb) info proc mappings
	      0x7ffff7ffe000  0x7ffff7fff000  0x1000  0  [vdso]
	      (gdb) dump memory vdso.bin 0x7ffff7ffe000 0x7ffff7fff000
	      # readelf -Wa vdso.bin
	      [...]
		Entry point address: 0xffffffffff700700
	      [...]
	      Section Headers:
		[Nr] Name     Type    Address	       Off    Size
		[ 0]	      NULL    0000000000000000 000000 000000
		[ 1] .hash    HASH    ffffffffff700120 000120 000038
		[ 2] .dynsym  DYNSYM  ffffffffff700158 000158 0000d8
	      [...]
		[ 9] .dynamic DYNAMIC ffffffffff700580 000580 0000f0
	  */

	  auto *li = gdb::checked_static_cast<lm_info_svr4 *> (so->lm_info.get ());

	  if (vsyscall_range.contains (li->l_ld))
	    {
	      so = sos.erase (so);
	      break;
	    }

	  ++so;
	}
    }

  return sos;
}

/* Get the address of the link_map for a given OBJFILE.  */

CORE_ADDR
svr4_fetch_objfile_link_map (struct objfile *objfile)
{
  struct svr4_info *info = get_svr4_info (objfile->pspace ());

  /* Cause svr4_current_sos() to be run if it hasn't been already.  */
  if (info->main_lm_addr == 0)
    solib_add (NULL, 0, auto_solib_add);

  /* svr4_current_sos() will set main_lm_addr for the main executable.  */
  if (objfile == current_program_space->symfile_object_file)
    return info->main_lm_addr;

  /* The other link map addresses may be found by examining the list
     of shared libraries.  */
  for (const solib &so : current_program_space->solibs ())
    if (so.objfile == objfile)
      {
	auto *li
	  = gdb::checked_static_cast<lm_info_svr4 *> (so.lm_info.get ());

	return li->lm_addr;
      }

  /* Not found!  */
  return 0;
}

/* Return true if bfd section BFD_SECT is a thread local section
   (i.e. either named ".tdata" or ".tbss"), and false otherwise.  */

static bool
is_thread_local_section (struct bfd_section *bfd_sect)
{
  return ((strcmp (bfd_sect->name, ".tdata") == 0
	   || strcmp (bfd_sect->name, ".tbss") == 0)
	  && bfd_sect->size != 0);
}

/* Return true if objfile OBJF contains a thread local section, and
   false otherwise.  */

static bool
has_thread_local_section (const objfile *objf)
{
  for (obj_section *objsec : objf->sections ())
    if (is_thread_local_section (objsec->the_bfd_section))
      return true;
  return false;
}

/* Return true if solib SO contains a thread local section, and false
   otherwise.  */

static bool
has_thread_local_section (const solib &so)
{
  for (const target_section &p : so.sections)
    if (is_thread_local_section (p.the_bfd_section))
      return true;
  return false;
}

/* For the MUSL C library, given link map address LM_ADDR, return the
   corresponding TLS module id, or 0 if not found.

   Background: Unlike the mechanism used by glibc (see below), the
   scheme used by the MUSL C library is pretty simple.  If the
   executable contains TLS variables it gets module id 1.  Otherwise,
   the first shared object loaded which contains TLS variables is
   assigned to module id 1.  TLS-containing shared objects are then
   assigned consecutive module ids, based on the order that they are
   loaded.  When unloaded via dlclose, module ids are reassigned as if
   that module had never been loaded.  */

int
musl_link_map_to_tls_module_id (CORE_ADDR lm_addr)
{
  /* When lm_addr is zero, the program is statically linked.  Any TLS
     variables will be in module id 1.  */
  if (lm_addr == 0)
    return 1;

  int mod_id = 0;
  if (has_thread_local_section (current_program_space->symfile_object_file))
    mod_id++;

  struct svr4_info *info = get_svr4_info (current_program_space);

  /* Cause svr4_current_sos() to be run if it hasn't been already.  */
  if (info->main_lm_addr == 0)
    solib_add (NULL, 0, auto_solib_add);

  /* Handle case where lm_addr corresponds to the main program.
     Return value is either 0, when there are no TLS variables, or 1,
     when there are.  */
  if (lm_addr == info->main_lm_addr)
    return mod_id;

  /* Iterate through the shared objects, possibly incrementing the
     module id, and returning mod_id should a match be found.  */
  for (const solib &so : current_program_space->solibs ())
    {
      if (has_thread_local_section (so))
	mod_id++;

      auto *li = gdb::checked_static_cast<lm_info_svr4 *> (so.lm_info.get ());
      if (li->lm_addr == lm_addr)
	return mod_id;
    }
  return 0;
}

/* For GLIBC, given link map address LM_ADDR, return the corresponding TLS
   module id, or 0 if not found.  */

int
glibc_link_map_to_tls_module_id (CORE_ADDR lm_addr)
{
  /* When lm_addr is zero, the program is statically linked.  Any TLS
     variables will be in module id 1.  */
  if (lm_addr == 0)
    return 1;

  /* Look up lm_addr in the TLS slot data structure.  */
  struct svr4_info *info = get_svr4_info (current_program_space);
  auto it = std::find (info->glibc_tls_slots.begin (),
		       info->glibc_tls_slots.end (),
		       lm_addr);
  if (it == info->glibc_tls_slots.end ())
    return 0;
  else
    return 1 + it - info->glibc_tls_slots.begin ();
}

/* Conditionally, based on whether the shared object, SO, contains TLS
   variables, assign a link map address to a TLS module id slot.  This
   code is GLIBC-specific and may only work for specific GLIBC
   versions.  That said, it is known to work for (at least) GLIBC
   versions 2.27 thru 2.40.

   Background: In order to implement internal TLS address lookup
   code, it is necessary to find the module id that has been
   associated with a specific link map address.  In GLIBC, the TLS
   module id is stored in struct link_map, in the member
   'l_tls_modid'.  While the first several members of struct link_map
   are part of the SVR4 ABI, the offset to l_tls_modid definitely is
   not.  Therefore, since we don't know the offset to l_tls_modid, we
   cannot simply look it up - which is a shame, because things would
   be so much more easy and obviously accurate, if we could access
   l_tls_modid.

   GLIBC has a concept of TLS module id slots.  These slots are
   allocated consecutively as shared objects containing TLS variables
   are loaded.  When unloaded (e.g. via dlclose()), the corresponding
   slot is marked as unused, but may be used again when later loading
   a shared object.

   The functions tls_maybe_fill_slot and tls_maybe_erase_slot are
   associated with the observers 'solib_loaded' and 'solib_unloaded'.
   They (attempt to) track use of TLS module id slots in the same way
   that GLIBC does, which will hopefully provide an accurate module id
   when asked to provide it via glibc_link_map_to_tls_module_id(),
   above.  */

static void
tls_maybe_fill_slot (solib &so)
{
  auto *li = dynamic_cast<lm_info_svr4 *> (so.lm_info.get ());
  if (li == nullptr)
    return;

  struct svr4_info *info = get_svr4_info (current_program_space);
  if (!info->glibc_tls_slots_inited)
    {
      /* Cause svr4_current_sos() to be run if it hasn't been already.  */
      if (info->main_lm_addr == 0)
	{
	  auto &ops
	    = gdb::checked_static_cast<const svr4_solib_ops &> (so.ops ());
	  ops.current_sos_direct (info);
	}

      /* Quit early when main_lm_addr is still 0.  */
      if (info->main_lm_addr == 0)
	return;

      /* Also quit early when symfile_object_file is not yet known.  */
      if (current_program_space->symfile_object_file == nullptr)
	return;

      if (has_thread_local_section (current_program_space->symfile_object_file))
	info->glibc_tls_slots.push_back (info->main_lm_addr);
      info->glibc_tls_slots_inited = true;
    }

  if (has_thread_local_section (so))
    {
      auto it = std::find (info->glibc_tls_slots.begin (),
			   info->glibc_tls_slots.end (),
			   0);
      if (it == info->glibc_tls_slots.end ())
	info->glibc_tls_slots.push_back (li->lm_addr);
      else
	*it = li->lm_addr;
    }
}

/* Remove a link map address from the TLS module slot data structure.
   As noted above, this code is GLIBC-specific.  */

static void
tls_maybe_erase_slot (program_space *pspace, const solib &so,
		      bool still_in_use, bool silent)
{
  if (still_in_use)
    return;

  auto *li = dynamic_cast<lm_info_svr4 *> (so.lm_info.get ());
  if (li == nullptr)
    return;

  struct svr4_info *info = get_svr4_info (pspace);
  auto it = std::find (info->glibc_tls_slots.begin (),
		       info->glibc_tls_slots.end (),
		       li->lm_addr);
  if (it != info->glibc_tls_slots.end ())
    *it = 0;
}

/* On some systems, the only way to recognize the link map entry for
   the main executable file is by looking at its name.  Return
   non-zero iff SONAME matches one of the known main executable names.  */

static int
match_main (const char *soname)
{
  const char * const *mainp;

  for (mainp = main_name_list; *mainp != NULL; mainp++)
    {
      if (strcmp (soname, *mainp) == 0)
	return (1);
    }

  return (0);
}

/* Return true if PC lies in the dynamic symbol resolution code of the
   SVR4 run time loader.  */

bool
svr4_solib_ops::in_dynsym_resolve_code (CORE_ADDR pc) const
{
  struct svr4_info *info = get_svr4_info (current_program_space);

  return ((pc >= info->interp_text_sect_low
	   && pc < info->interp_text_sect_high)
	  || (pc >= info->interp_plt_sect_low
	      && pc < info->interp_plt_sect_high)
	  || in_plt_section (pc)
	  || in_gnu_ifunc_stub (pc));
}

/* Given an executable's ABFD and target, compute the entry-point
   address.  */

static CORE_ADDR
exec_entry_point (struct bfd *abfd, struct target_ops *targ)
{
  CORE_ADDR addr;

  /* KevinB wrote ... for most targets, the address returned by
     bfd_get_start_address() is the entry point for the start
     function.  But, for some targets, bfd_get_start_address() returns
     the address of a function descriptor from which the entry point
     address may be extracted.  This address is extracted by
     gdbarch_convert_from_func_ptr_addr().  The method
     gdbarch_convert_from_func_ptr_addr() is the merely the identify
     function for targets which don't use function descriptors.  */
  addr = gdbarch_convert_from_func_ptr_addr (current_inferior ()->arch (),
					     bfd_get_start_address (abfd),
					     targ);
  return gdbarch_addr_bits_remove (current_inferior ()->arch (), addr);
}

/* A probe and its associated action.  */

struct probe_and_action
{
  /* The probe.  */
  probe *prob;

  /* The relocated address of the probe.  */
  CORE_ADDR address;

  /* The action.  */
  enum probe_action action;

  /* The objfile where this probe was found.  */
  struct objfile *objfile;
};

/* Returns a hash code for the probe_and_action referenced by p.  */

static hashval_t
hash_probe_and_action (const void *p)
{
  const struct probe_and_action *pa = (const struct probe_and_action *) p;

  return (hashval_t) pa->address;
}

/* Returns non-zero if the probe_and_actions referenced by p1 and p2
   are equal.  */

static int
equal_probe_and_action (const void *p1, const void *p2)
{
  const struct probe_and_action *pa1 = (const struct probe_and_action *) p1;
  const struct probe_and_action *pa2 = (const struct probe_and_action *) p2;

  return pa1->address == pa2->address;
}

/* Traversal function for probes_table_remove_objfile_probes.  */

static int
probes_table_htab_remove_objfile_probes (void **slot, void *info)
{
  probe_and_action *pa = (probe_and_action *) *slot;
  struct objfile *objfile = (struct objfile *) info;

  if (pa->objfile == objfile)
    htab_clear_slot (get_svr4_info (objfile->pspace ())->probes_table.get (),
		     slot);

  return 1;
}

/* Remove all probes that belong to OBJFILE from the probes table.  */

static void
probes_table_remove_objfile_probes (struct objfile *objfile)
{
  svr4_info *info = solib_svr4_pspace_data.get (objfile->pspace ());
  if (info == nullptr || info->probes_table == nullptr)
    return;

  htab_traverse_noresize (info->probes_table.get (),
			  probes_table_htab_remove_objfile_probes, objfile);
}

/* Register a solib event probe and its associated action in the
   probes table.  */

static void
register_solib_event_probe (svr4_info *info, struct objfile *objfile,
			    probe *prob, CORE_ADDR address,
			    enum probe_action action)
{
  struct probe_and_action lookup, *pa;
  void **slot;

  /* Create the probes table, if necessary.  */
  if (info->probes_table == NULL)
    info->probes_table.reset (htab_create_alloc (1, hash_probe_and_action,
						 equal_probe_and_action,
						 xfree, xcalloc, xfree));

  lookup.address = address;
  slot = htab_find_slot (info->probes_table.get (), &lookup, INSERT);
  gdb_assert (*slot == HTAB_EMPTY_ENTRY);

  pa = XCNEW (struct probe_and_action);
  pa->prob = prob;
  pa->address = address;
  pa->action = action;
  pa->objfile = objfile;

  *slot = pa;
}

/* Get the solib event probe at the specified location, and the
   action associated with it.  Returns NULL if no solib event probe
   was found.  */

static struct probe_and_action *
solib_event_probe_at (struct svr4_info *info, CORE_ADDR address)
{
  struct probe_and_action lookup;
  void **slot;

  lookup.address = address;
  slot = htab_find_slot (info->probes_table.get (), &lookup, NO_INSERT);

  if (slot == NULL)
    return NULL;

  return (struct probe_and_action *) *slot;
}

/* Decide what action to take when the specified solib event probe is
   hit.  */

static enum probe_action
solib_event_probe_action (struct probe_and_action *pa)
{
  enum probe_action action;
  unsigned probe_argc = 0;
  frame_info_ptr frame = get_current_frame ();

  action = pa->action;
  if (action == DO_NOTHING || action == PROBES_INTERFACE_FAILED)
    return action;

  gdb_assert (action == FULL_RELOAD || action == UPDATE_OR_RELOAD);

  /* Check that an appropriate number of arguments has been supplied.
     We expect:
       arg0: Lmid_t lmid (mandatory)
       arg1: struct r_debug *debug_base (mandatory)
       arg2: struct link_map *new (optional, for incremental updates)  */
  try
    {
      probe_argc = pa->prob->get_argument_count (get_frame_arch (frame));
    }
  catch (const gdb_exception_error &ex)
    {
      exception_print (gdb_stderr, ex);
      probe_argc = 0;
    }

  /* If get_argument_count throws an exception, probe_argc will be set
     to zero.  However, if pa->prob does not have arguments, then
     get_argument_count will succeed but probe_argc will also be zero.
     Both cases happen because of different things, but they are
     treated equally here: action will be set to
     PROBES_INTERFACE_FAILED.  */
  if (probe_argc == 2)
    action = FULL_RELOAD;
  else if (probe_argc < 2)
    action = PROBES_INTERFACE_FAILED;

  return action;
}

/* Populate the shared object list by reading the entire list of
   shared objects from the inferior.  Handle special cases relating
   to the first elements of the list.  Returns nonzero on success.  */

void
svr4_solib_ops::update_full (svr4_info *info) const
{
  this->current_sos_direct (info);
}

/* Update the shared object list starting from the link-map entry
   passed by the linker in the probe's third argument.  Returns
   nonzero if the list was successfully updated, or zero to indicate
   failure.  */

int
svr4_solib_ops::update_incremental (svr4_info *info, CORE_ADDR debug_base,
				    CORE_ADDR lm) const
{
  /* Fall back to a full update if we are using a remote target
     that does not support incremental transfers.  */
  if (info->using_xfer && !target_augmented_libraries_svr4_read ())
    return 0;

  /* Fall back to a full update if we used the special namespace zero.  We
     wouldn't be able to find the last item in the DEBUG_BASE namespace
     and hence get the prev link wrong.  */
  if (info->solib_lists.find (0) != info->solib_lists.end ())
    return 0;

  std::vector<svr4_so> &solist = info->solib_lists[debug_base];
  CORE_ADDR prev_lm;

  if (solist.empty ())
    {
      /* svr4_current_sos_direct contains logic to handle a number of
	 special cases relating to the first elements of the list in
	 default namespace.  To avoid duplicating this logic we defer to
	 solist_update_full in this case.  */
      if (svr4_is_default_namespace (info, debug_base))
	return 0;

      prev_lm = 0;

      /* If the list is empty, we are seeing a new namespace for the
	 first time, so assign it an internal ID.  */
      svr4_maybe_add_namespace (info, debug_base);
    }
  else
    prev_lm = solist.back ().lm_info->lm_addr;

  /* Read the new objects.  */
  if (info->using_xfer)
    {
      struct svr4_library_list library_list;
      char annex[64];

      /* Unknown key=value pairs are ignored by the gdbstub.  */
      xsnprintf (annex, sizeof (annex), "lmid=%s;start=%s;prev=%s",
		 phex_nz (debug_base),
		 phex_nz (lm),
		 phex_nz (prev_lm));
      if (!svr4_current_sos_via_xfer_libraries (&library_list, annex))
	return 0;

      /* Get the so list from the target.  We replace the list in the
	 target response so we can easily check that the response only
	 covers one namespace.

	 We expect gdbserver to provide updates for the namespace that
	 contains LM, which would be this namespace...  */
      std::vector<svr4_so> sos;
      auto it_debug_base = library_list.solib_lists.find (debug_base);
      if (it_debug_base != library_list.solib_lists.end ())
	std::swap (sos, it_debug_base->second);
      else
	{
	  /* ...or for the special zero namespace for earlier versions...  */
	  auto it_0 = library_list.solib_lists.find (0);
	  if (it_0 != library_list.solib_lists.end ())
	    std::swap (sos, it_0->second);
	}

      /* ...but nothing else.  */
      for (const auto &tuple : library_list.solib_lists)
	gdb_assert (tuple.second.empty ());

      std::move (sos.begin (), sos.end (), std::back_inserter (solist));
    }
  else
    {
      /* IGNORE_FIRST may safely be set to zero here because the
	 above check and deferral to solist_update_full ensures
	 that this call to svr4_read_so_list will never see the
	 first element.  */
      if (!this->read_so_list (info, lm, prev_lm, solist, 0))
	return 0;
    }

  return 1;
}

/* Disable the probes-based linker interface and revert to the
   original interface.  We don't reset the breakpoints as the
   ones set up for the probes-based interface are adequate.  */

void
svr4_solib_ops::disable_probes_interface (svr4_info *info) const
{
  warning (_("Probes-based dynamic linker interface failed.\n"
	     "Reverting to original interface."));

  free_probes_table (info);
  info->solib_lists.clear ();
  info->namespace_id.clear ();
  info->active_namespaces.clear ();
}

/* Update the solib list as appropriate when using the
   probes-based linker interface.  Do nothing if using the
   standard interface.  */

void
svr4_solib_ops::handle_event () const
{
  struct svr4_info *info = get_svr4_info (current_program_space);
  struct probe_and_action *pa;
  enum probe_action action;
  struct value *val = NULL;
  CORE_ADDR pc, debug_base, lm = 0;
  frame_info_ptr frame = get_current_frame ();

  /* Do nothing if not using the probes interface.  */
  if (info->probes_table == NULL)
    return;

  pc = regcache_read_pc (get_thread_regcache (inferior_thread ()));
  pa = solib_event_probe_at (info, pc);
  if (pa == nullptr)
    {
      /* When some solib ops sits above us, it can respond to a solib event
	 by calling in here.  This is done assuming that if the current event
	 is not an SVR4 solib event, calling here should be a no-op.  */
      return;
    }

  /* If anything goes wrong we revert to the original linker
     interface.  */
  auto cleanup = make_scope_exit ([this, info] ()
    {
      this->disable_probes_interface (info);
    });

  action = solib_event_probe_action (pa);
  if (action == PROBES_INTERFACE_FAILED)
    return;

  if (action == DO_NOTHING)
    {
      cleanup.release ();
      return;
    }

  /* evaluate_argument looks up symbols in the dynamic linker
     using find_pc_section.  find_pc_section is accelerated by a cache
     called the section map.  The section map is invalidated every
     time a shared library is loaded or unloaded, and if the inferior
     is generating a lot of shared library events then the section map
     will be updated every time svr4_handle_solib_event is called.
     We called find_pc_section in svr4_create_solib_event_breakpoints,
     so we can guarantee that the dynamic linker's sections are in the
     section map.  We can therefore inhibit section map updates across
     these calls to evaluate_argument and save a lot of time.  */
  {
    scoped_restore inhibit_updates
      = inhibit_section_map_updates (current_program_space);

    try
      {
	val = pa->prob->evaluate_argument (1, frame);
      }
    catch (const gdb_exception_error &ex)
      {
	exception_print (gdb_stderr, ex);
	val = NULL;
      }

    if (val == NULL)
      return;

    debug_base = value_as_address (val);
    if (debug_base == 0)
      return;

    /* If the global _r_debug object moved, we need to reload everything
       since we cannot identify namespaces (by the location of their
       r_debug_ext object) anymore.  */
    CORE_ADDR global_debug_base = elf_locate_base ();
    if (global_debug_base != info->debug_base)
      {
	info->debug_base = global_debug_base;
	action = FULL_RELOAD;
      }

    if (info->debug_base == 0)
      {
	/* It's possible for the reloc_complete probe to be triggered before
	   the linker has set the DT_DEBUG pointer (for example, when the
	   linker has finished relocating an LD_AUDIT library or its
	   dependencies).  Since we can't yet handle libraries from other link
	   namespaces, we don't lose anything by ignoring them here.  */
	struct value *link_map_id_val;
	try
	  {
	    link_map_id_val = pa->prob->evaluate_argument (0, frame);
	  }
	catch (const gdb_exception_error &)
	  {
	    link_map_id_val = NULL;
	  }
	/* glibc and illumos' libc both define LM_ID_BASE as zero.  */
	if (link_map_id_val != NULL && value_as_long (link_map_id_val) != 0)
	  action = DO_NOTHING;
	else
	  return;
      }

    if (action == UPDATE_OR_RELOAD)
      {
	try
	  {
	    val = pa->prob->evaluate_argument (2, frame);
	  }
	catch (const gdb_exception_error &ex)
	  {
	    exception_print (gdb_stderr, ex);
	    return;
	  }

	if (val != NULL)
	  lm = value_as_address (val);

	if (lm == 0)
	  action = FULL_RELOAD;
      }

    /* Resume section map updates.  Closing the scope is
       sufficient.  */
  }

  if (action == UPDATE_OR_RELOAD)
    {
      if (!this->update_incremental (info, debug_base, lm))
	action = FULL_RELOAD;
    }

  if (action == FULL_RELOAD)
    this->update_full (info);

  cleanup.release ();
}

/* Helper function for svr4_update_solib_event_breakpoints.  */

static bool
svr4_update_solib_event_breakpoint (struct breakpoint *b)
{
  if (b->type != bp_shlib_event)
    {
      /* Continue iterating.  */
      return false;
    }

  for (bp_location &loc : b->locations ())
    {
      struct svr4_info *info;
      struct probe_and_action *pa;

      info = solib_svr4_pspace_data.get (loc.pspace);
      if (info == NULL || info->probes_table == NULL)
	continue;

      pa = solib_event_probe_at (info, loc.address);
      if (pa == NULL)
	continue;

      if (pa->action == DO_NOTHING)
	{
	  if (b->enable_state == bp_disabled && stop_on_solib_events)
	    enable_breakpoint (b);
	  else if (b->enable_state == bp_enabled && !stop_on_solib_events)
	    disable_breakpoint (b);
	}

      break;
    }

  /* Continue iterating.  */
  return false;
}

/* Enable or disable optional solib event breakpoints as appropriate.
   Called whenever stop_on_solib_events is changed.  */

void
svr4_solib_ops::update_breakpoints () const
{
  for (breakpoint &bp : all_breakpoints_safe ())
    svr4_update_solib_event_breakpoint (&bp);
}

/* Create and register solib event breakpoints.  PROBES is an array
   of NUM_PROBES elements, each of which is vector of probes.  A
   solib event breakpoint will be created and registered for each
   probe.  */

void
svr4_solib_ops::create_probe_breakpoints (svr4_info *info, gdbarch *gdbarch,
					  const std::vector<probe *> *probes,
					  objfile *objfile) const
{
  for (int i = 0; i < NUM_PROBES; i++)
    {
      enum probe_action action = probe_info[i].action;

      for (probe *p : probes[i])
	{
	  CORE_ADDR address = p->get_relocated_address (objfile);

	  solib_debug_printf ("name=%s, addr=%s", probe_info[i].name,
			      paddress (gdbarch, address));

	  create_solib_event_breakpoint (gdbarch, address);
	  register_solib_event_probe (info, objfile, p, address, action);
	}
    }

  this->update_breakpoints ();
}

/* Find all the glibc named probes.  Only if all of the probes are found, then
   create them and return true.  Otherwise return false.  If WITH_PREFIX is set
   then add "rtld" to the front of the probe names.  */
bool
svr4_solib_ops::find_and_create_probe_breakpoints (svr4_info *info,
						   gdbarch *gdbarch,
						   obj_section *os,
						   bool with_prefix) const
{
  SOLIB_SCOPED_DEBUG_START_END ("objfile=%s, with_prefix=%d",
				os->objfile->original_name, with_prefix);

  std::vector<probe *> probes[NUM_PROBES];

  for (int i = 0; i < NUM_PROBES; i++)
    {
      const char *name = probe_info[i].name;
      char buf[32];

      /* Fedora 17 and Red Hat Enterprise Linux 6.2-6.4 shipped with an early
	 version of the probes code in which the probes' names were prefixed
	 with "rtld_" and the "map_failed" probe did not exist.  The locations
	 of the probes are otherwise the same, so we check for probes with
	 prefixed names if probes with unprefixed names are not present.  */
      if (with_prefix)
	{
	  xsnprintf (buf, sizeof (buf), "rtld_%s", name);
	  name = buf;
	}

      probes[i] = find_probes_in_objfile (os->objfile, "rtld", name);
      solib_debug_printf ("probe=%s, num found=%zu", name, probes[i].size ());

      /* Ensure at least one probe for the current name was found.  */
      if (probes[i].empty ())
	{
	  /* The "map_failed" probe did not exist in early versions of the
	     probes code in which the probes' names were prefixed with
	     "rtld_".

	     Additionally, the "map_failed" probe was accidentally removed
	     from glibc 2.35 and 2.36, when changes in glibc meant the
	     probe could no longer be reached, and the compiler optimized
	     the probe away.  In this case the probe name doesn't have the
	     "rtld_" prefix.

	     To handle this, and give GDB as much flexibility as possible,
	     we make the rule that, if a probe isn't required for the
	     correct operation of GDB (i.e. its action is DO_NOTHING), then
	     we will still use the probes interface, even if that probe is
	     missing.

	     The only (possible) downside of this is that, if the user has
	     'set stop-on-solib-events on' in effect, then they might get
	     fewer events using the probes interface than with the classic
	     non-probes interface.  */
	  if (probe_info[i].action == DO_NOTHING)
	    continue;
	  else
	    return false;
	}

      /* Ensure probe arguments can be evaluated.  */
      for (probe *p : probes[i])
	{
	  if (!p->can_evaluate_arguments ())
	    return false;
	  /* This will fail if the probe is invalid.  This has been seen on Arm
	     due to references to symbols that have been resolved away.  */
	  try
	    {
	      p->get_argument_count (gdbarch);
	    }
	  catch (const gdb_exception_error &ex)
	    {
	      exception_print (gdb_stderr, ex);
	      warning (_("Initializing probes-based dynamic linker interface "
			 "failed.\nReverting to original interface."));
	      return false;
	    }
	}
    }

  /* All probes found.  Now create them.  */
  solib_debug_printf ("using probes interface");
  this->create_probe_breakpoints (info, gdbarch, probes, os->objfile);
  return true;
}

/* Both the SunOS and the SVR4 dynamic linkers call a marker function
   before and after mapping and unmapping shared libraries.  The sole
   purpose of this method is to allow debuggers to set a breakpoint so
   they can track these changes.

   Some versions of the glibc dynamic linker contain named probes
   to allow more fine grained stopping.  Given the address of the
   original marker function, this function attempts to find these
   probes, and if found, sets breakpoints on those instead.  If the
   probes aren't found, a single breakpoint is set on the original
   marker function.  */

void
svr4_solib_ops::create_event_breakpoints (svr4_info *info, gdbarch *gdbarch,
					  CORE_ADDR address) const
{
  struct obj_section *os = find_pc_section (address);

  if (os == nullptr
      || (!this->find_and_create_probe_breakpoints (info, gdbarch, os, false)
	  && !this->find_and_create_probe_breakpoints (info, gdbarch, os,
						       true)))
    {
      solib_debug_printf ("falling back to r_brk breakpoint: addr=%s",
			  paddress (gdbarch, address));
      create_solib_event_breakpoint (gdbarch, address);
    }
}

/* Arrange for dynamic linker to hit breakpoint.

   Both the SunOS and the SVR4 dynamic linkers have, as part of their
   debugger interface, support for arranging for the inferior to hit
   a breakpoint after mapping in the shared libraries.  This function
   enables that breakpoint.

   For SunOS, there is a special flag location (in_debugger) which we
   set to 1.  When the dynamic linker sees this flag set, it will set
   a breakpoint at a location known only to itself, after saving the
   original contents of that place and the breakpoint address itself,
   in its own internal structures.  When we resume the inferior, it
   will eventually take a SIGTRAP when it runs into the breakpoint.
   We handle this (in a different place) by restoring the contents of
   the breakpointed location (which is only known after it stops),
   chasing around to locate the shared libraries that have been
   loaded, then resuming.

   For SVR4, the debugger interface structure contains a member (r_brk)
   which is statically initialized at the time the shared library is
   built, to the offset of a function (_r_debug_state) which is guaran-
   teed to be called once before mapping in a library, and again when
   the mapping is complete.  At the time we are examining this member,
   it contains only the unrelocated offset of the function, so we have
   to do our own relocation.  Later, when the dynamic linker actually
   runs, it relocates r_brk to be the actual address of _r_debug_state().

   The debugger interface structure also contains an enumeration which
   is set to either RT_ADD or RT_DELETE prior to changing the mapping,
   depending upon whether or not the library is being mapped or unmapped,
   and then set to RT_CONSISTENT after the library is mapped/unmapped.  */

int
svr4_solib_ops::enable_break (svr4_info *info, int from_tty) const
{
  const char * const *bkpt_namep;
  asection *interp_sect;
  CORE_ADDR sym_addr;

  info->interp_text_sect_low = info->interp_text_sect_high = 0;
  info->interp_plt_sect_low = info->interp_plt_sect_high = 0;

  /* If we already have a shared library list in the target, and
     r_debug contains r_brk, set the breakpoint there - this should
     mean r_brk has already been relocated.  Assume the dynamic linker
     is the object containing r_brk.  */

  solib_add (NULL, from_tty, auto_solib_add);
  sym_addr = 0;
  if (info->debug_base && this->read_r_map (info->debug_base) != 0)
    sym_addr = this->find_r_brk (info);

  if (sym_addr != 0)
    {
      struct obj_section *os;

      sym_addr = gdbarch_addr_bits_remove
	(current_inferior ()->arch (),
	 gdbarch_convert_from_func_ptr_addr
	   (current_inferior ()->arch (), sym_addr,
	    current_inferior ()->top_target ()));

      /* On at least some versions of Solaris there's a dynamic relocation
	 on _r_debug.r_brk and SYM_ADDR may not be relocated yet, e.g., if
	 we get control before the dynamic linker has self-relocated.
	 Check if SYM_ADDR is in a known section, if it is assume we can
	 trust its value.  This is just a heuristic though, it could go away
	 or be replaced if it's getting in the way.

	 On ARM we need to know whether the ISA of rtld_db_dlactivity (or
	 however it's spelled in your particular system) is ARM or Thumb.
	 That knowledge is encoded in the address, if it's Thumb the low bit
	 is 1.  However, we've stripped that info above and it's not clear
	 what all the consequences are of passing a non-addr_bits_remove'd
	 address to svr4_create_solib_event_breakpoints.  The call to
	 find_pc_section verifies we know about the address and have some
	 hope of computing the right kind of breakpoint to use (via
	 symbol info).  It does mean that GDB needs to be pointed at a
	 non-stripped version of the dynamic linker in order to obtain
	 information it already knows about.  Sigh.  */

      os = find_pc_section (sym_addr);
      if (os != NULL)
	{
	  /* Record the relocated start and end address of the dynamic linker
	     text and plt section for svr4_in_dynsym_resolve_code.  */
	  bfd *tmp_bfd;
	  CORE_ADDR load_addr;

	  tmp_bfd = os->objfile->obfd.get ();
	  load_addr = os->objfile->text_section_offset ();

	  interp_sect = bfd_get_section_by_name (tmp_bfd, ".text");
	  if (interp_sect)
	    {
	      info->interp_text_sect_low
		= bfd_section_vma (interp_sect) + load_addr;
	      info->interp_text_sect_high
		= info->interp_text_sect_low + bfd_section_size (interp_sect);
	    }
	  interp_sect = bfd_get_section_by_name (tmp_bfd, ".plt");
	  if (interp_sect)
	    {
	      info->interp_plt_sect_low
		= bfd_section_vma (interp_sect) + load_addr;
	      info->interp_plt_sect_high
		= info->interp_plt_sect_low + bfd_section_size (interp_sect);
	    }

	  this->create_event_breakpoints (info, current_inferior ()->arch (),
					  sym_addr);
	  return 1;
	}
    }

  /* Find the program interpreter; if not found, warn the user and drop
     into the old breakpoint at symbol code.  */
  std::optional<gdb::byte_vector> interp_name_holder
    = svr4_find_program_interpreter ();
  if (interp_name_holder)
    {
      const char *interp_name = (const char *) interp_name_holder->data ();
      CORE_ADDR load_addr = 0;
      int load_addr_found = 0;
      int loader_found_in_list = 0;
      target_ops_up tmp_bfd_target;

      sym_addr = 0;

      /* Now we need to figure out where the dynamic linker was
	 loaded so that we can load its symbols and place a breakpoint
	 in the dynamic linker itself.

	 This address is stored on the stack.  However, I've been unable
	 to find any magic formula to find it for Solaris (appears to
	 be trivial on GNU/Linux).  Therefore, we have to try an alternate
	 mechanism to find the dynamic linker's base address.  */

      gdb_bfd_ref_ptr tmp_bfd;
      try
	{
	  tmp_bfd = solib_bfd_open (interp_name);
	}
      catch (const gdb_exception &ex)
	{
	}

      if (tmp_bfd == NULL)
	goto bkpt_at_symbol;

      /* Now convert the TMP_BFD into a target.  That way target, as
	 well as BFD operations can be used.  */
      tmp_bfd_target = target_bfd_reopen (tmp_bfd);

      /* On a running target, we can get the dynamic linker's base
	 address from the shared library table.  */
      for (const solib &so : current_program_space->solibs ())
	{
	  if (svr4_same_1 (interp_name, so.original_name.c_str ()))
	    {
	      load_addr_found = 1;
	      loader_found_in_list = 1;
	      load_addr = this->lm_addr_check (so, tmp_bfd.get ());
	      break;
	    }
	}

      /* If we were not able to find the base address of the loader
	 from our so_list, then try using the AT_BASE auxiliary entry.  */
      if (!load_addr_found)
	if (target_auxv_search (AT_BASE, &load_addr) > 0)
	  {
	    int addr_bit = gdbarch_addr_bit (current_inferior ()->arch ());

	    /* Ensure LOAD_ADDR has proper sign in its possible upper bits so
	       that `+ load_addr' will overflow CORE_ADDR width not creating
	       invalid addresses like 0x101234567 for 32bit inferiors on 64bit
	       GDB.  */

	    if (addr_bit < (sizeof (CORE_ADDR) * HOST_CHAR_BIT))
	      {
		CORE_ADDR space_size = (CORE_ADDR) 1 << addr_bit;
		CORE_ADDR tmp_entry_point
		  = exec_entry_point (tmp_bfd.get (), tmp_bfd_target.get ());

		gdb_assert (load_addr < space_size);

		/* TMP_ENTRY_POINT exceeding SPACE_SIZE would be for prelinked
		   64bit ld.so with 32bit executable, it should not happen.  */

		if (tmp_entry_point < space_size
		    && tmp_entry_point + load_addr >= space_size)
		  load_addr -= space_size;
	      }

	    load_addr_found = 1;
	  }

      /* Otherwise we find the dynamic linker's base address by examining
	 the current pc (which should point at the entry point for the
	 dynamic linker) and subtracting the offset of the entry point.

	 This is more fragile than the previous approaches, but is a good
	 fallback method because it has actually been working well in
	 most cases.  */
      if (!load_addr_found)
	{
	  regcache *regcache
	    = get_thread_arch_regcache (current_inferior (), inferior_ptid,
					current_inferior ()->arch ());

	  load_addr = (regcache_read_pc (regcache)
		       - exec_entry_point (tmp_bfd.get (),
					   tmp_bfd_target.get ()));
	}

      if (!loader_found_in_list)
	{
	  info->debug_loader_name = interp_name;
	  info->debug_loader_offset_p = 1;
	  info->debug_loader_offset = load_addr;
	  solib_add (NULL, from_tty, auto_solib_add);
	}

      /* Record the relocated start and end address of the dynamic linker
	 text and plt section for svr4_in_dynsym_resolve_code.  */
      interp_sect = bfd_get_section_by_name (tmp_bfd.get (), ".text");
      if (interp_sect)
	{
	  info->interp_text_sect_low
	    = bfd_section_vma (interp_sect) + load_addr;
	  info->interp_text_sect_high
	    = info->interp_text_sect_low + bfd_section_size (interp_sect);
	}
      interp_sect = bfd_get_section_by_name (tmp_bfd.get (), ".plt");
      if (interp_sect)
	{
	  info->interp_plt_sect_low
	    = bfd_section_vma (interp_sect) + load_addr;
	  info->interp_plt_sect_high
	    = info->interp_plt_sect_low + bfd_section_size (interp_sect);
	}

      /* Now try to set a breakpoint in the dynamic linker.  */
      for (bkpt_namep = solib_break_names; *bkpt_namep != NULL; bkpt_namep++)
	{
	  sym_addr
	    = (gdb_bfd_lookup_symbol
	       (tmp_bfd.get (),
		[=] (const asymbol *sym)
		{
		  return (strcmp (sym->name, *bkpt_namep) == 0
			  && ((sym->section->flags & (SEC_CODE | SEC_DATA))
			      != 0));
		}));
	  if (sym_addr != 0)
	    break;
	}

      if (sym_addr != 0)
	/* Convert 'sym_addr' from a function pointer to an address.
	   Because we pass tmp_bfd_target instead of the current
	   target, this will always produce an unrelocated value.  */
	sym_addr = gdbarch_convert_from_func_ptr_addr
		     (current_inferior ()->arch (), sym_addr,
		      tmp_bfd_target.get ());

      if (sym_addr != 0)
	{
	  this->create_event_breakpoints (info, current_inferior ()->arch (),
					  load_addr + sym_addr);
	  return 1;
	}

      /* For whatever reason we couldn't set a breakpoint in the dynamic
	 linker.  Warn and drop into the old code.  */
    bkpt_at_symbol:
      warning (_("Unable to find dynamic linker breakpoint function.\n"
		 "GDB will be unable to debug shared library initializers\n"
		 "and track explicitly loaded dynamic code."));
    }

  /* Scan through the lists of symbols, trying to look up the symbol and
     set a breakpoint there.  Terminate loop when we/if we succeed.  */

  objfile *objf = current_program_space->symfile_object_file;
  for (bkpt_namep = solib_break_names; *bkpt_namep != NULL; bkpt_namep++)
    {
      bound_minimal_symbol msymbol
	= lookup_minimal_symbol (current_program_space, *bkpt_namep, objf);
      if ((msymbol.minsym != NULL)
	  && (msymbol.value_address () != 0))
	{
	  sym_addr = msymbol.value_address ();
	  sym_addr = gdbarch_convert_from_func_ptr_addr
	    (current_inferior ()->arch (), sym_addr,
	     current_inferior ()->top_target ());
	  this->create_event_breakpoints (info, current_inferior ()->arch (),
					  sym_addr);
	  return 1;
	}
    }

  if (interp_name_holder && !current_inferior ()->attach_flag)
    {
      for (bkpt_namep = bkpt_names; *bkpt_namep != NULL; bkpt_namep++)
	{
	  bound_minimal_symbol msymbol
	    = lookup_minimal_symbol (current_program_space, *bkpt_namep, objf);
	  if ((msymbol.minsym != NULL)
	      && (msymbol.value_address () != 0))
	    {
	      sym_addr = msymbol.value_address ();
	      sym_addr = gdbarch_convert_from_func_ptr_addr
		(current_inferior ()->arch (), sym_addr,
		 current_inferior ()->top_target ());
	      this->create_event_breakpoints (info,
					      current_inferior ()->arch (),
					      sym_addr);
	      return 1;
	    }
	}
    }
  return 0;
}

/* Read the ELF program headers from ABFD.  */

static std::optional<gdb::byte_vector>
read_program_headers_from_bfd (bfd *abfd)
{
  Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  int phdrs_size = ehdr->e_phnum * ehdr->e_phentsize;
  if (phdrs_size == 0)
    return {};

  gdb::byte_vector buf (phdrs_size);
  if (bfd_seek (abfd, ehdr->e_phoff, SEEK_SET) != 0
      || bfd_read (buf.data (), phdrs_size, abfd) != phdrs_size)
    return {};

  return buf;
}

/* Return 1 and fill *DISPLACEMENTP with detected PIE offset of inferior
   exec_bfd.  Otherwise return 0.

   We relocate all of the sections by the same amount.  This
   behavior is mandated by recent editions of the System V ABI.
   According to the System V Application Binary Interface,
   Edition 4.1, page 5-5:

     ...  Though the system chooses virtual addresses for
     individual processes, it maintains the segments' relative
     positions.  Because position-independent code uses relative
     addressing between segments, the difference between
     virtual addresses in memory must match the difference
     between virtual addresses in the file.  The difference
     between the virtual address of any segment in memory and
     the corresponding virtual address in the file is thus a
     single constant value for any one executable or shared
     object in a given process.  This difference is the base
     address.  One use of the base address is to relocate the
     memory image of the program during dynamic linking.

   The same language also appears in Edition 4.0 of the System V
   ABI and is left unspecified in some of the earlier editions.

   Decide if the objfile needs to be relocated.  As indicated above, we will
   only be here when execution is stopped.  But during attachment PC can be at
   arbitrary address therefore regcache_read_pc can be misleading (contrary to
   the auxv AT_ENTRY value).  Moreover for executable with interpreter section
   regcache_read_pc would point to the interpreter and not the main executable.

   So, to summarize, relocations are necessary when the start address obtained
   from the executable is different from the address in auxv AT_ENTRY entry.

   [ The astute reader will note that we also test to make sure that
     the executable in question has the DYNAMIC flag set.  It is my
     opinion that this test is unnecessary (undesirable even).  It
     was added to avoid inadvertent relocation of an executable
     whose e_type member in the ELF header is not ET_DYN.  There may
     be a time in the future when it is desirable to do relocations
     on other types of files as well in which case this condition
     should either be removed or modified to accommodate the new file
     type.  - Kevin, Nov 2000. ]  */

static int
svr4_exec_displacement (CORE_ADDR *displacementp)
{
  /* ENTRY_POINT is a possible function descriptor - before
     a call to gdbarch_convert_from_func_ptr_addr.  */
  CORE_ADDR entry_point, exec_displacement;

  if (current_program_space->exec_bfd () == NULL)
    return 0;

  /* Therefore for ELF it is ET_EXEC and not ET_DYN.  Both shared libraries
     being executed themselves and PIE (Position Independent Executable)
     executables are ET_DYN.  */

  if ((bfd_get_file_flags (current_program_space->exec_bfd ()) & DYNAMIC) == 0)
    return 0;

  if (target_auxv_search (AT_ENTRY, &entry_point) <= 0)
    return 0;

  exec_displacement
    = entry_point - bfd_get_start_address (current_program_space->exec_bfd ());

  /* Verify the EXEC_DISPLACEMENT candidate complies with the required page
     alignment.  It is cheaper than the program headers comparison below.  */

  if (bfd_get_flavour (current_program_space->exec_bfd ())
      == bfd_target_elf_flavour)
    {
      const struct elf_backend_data *elf
	= get_elf_backend_data (current_program_space->exec_bfd ());

      /* p_align of PT_LOAD segments does not specify any alignment but
	 only congruency of addresses:
	   p_offset % p_align == p_vaddr % p_align
	 Kernel is free to load the executable with lower alignment.  */

      if ((exec_displacement & (elf->minpagesize - 1)) != 0)
	return 0;
    }

  /* Verify that the auxiliary vector describes the same file as exec_bfd, by
     comparing their program headers.  If the program headers in the auxiliary
     vector do not match the program headers in the executable, then we are
     looking at a different file than the one used by the kernel - for
     instance, "gdb program" connected to "gdbserver :PORT ld.so program".  */

  if (bfd_get_flavour (current_program_space->exec_bfd ())
      == bfd_target_elf_flavour)
    {
      /* Be optimistic and return 0 only if GDB was able to verify the headers
	 really do not match.  */
      int arch_size;

      std::optional<gdb::byte_vector> phdrs_target
	= read_program_header (-1, &arch_size, NULL);
      std::optional<gdb::byte_vector> phdrs_binary
	= read_program_headers_from_bfd (current_program_space->exec_bfd ());
      if (phdrs_target && phdrs_binary)
	{
	  bfd_endian byte_order = gdbarch_byte_order (current_inferior ()->arch ());

	  /* We are dealing with three different addresses.  EXEC_BFD
	     represents current address in on-disk file.  target memory content
	     may be different from EXEC_BFD as the file may have been prelinked
	     to a different address after the executable has been loaded.
	     Moreover the address of placement in target memory can be
	     different from what the program headers in target memory say -
	     this is the goal of PIE.

	     Detected DISPLACEMENT covers both the offsets of PIE placement and
	     possible new prelink performed after start of the program.  Here
	     relocate BUF and BUF2 just by the EXEC_BFD vs. target memory
	     content offset for the verification purpose.  */

	  if (phdrs_target->size () != phdrs_binary->size ()
	      || bfd_get_arch_size (current_program_space->exec_bfd ()) != arch_size)
	    return 0;
	  else if (arch_size == 32
		   && phdrs_target->size () >= sizeof (Elf32_External_Phdr)
		   && phdrs_target->size () % sizeof (Elf32_External_Phdr) == 0)
	    {
	      Elf_Internal_Ehdr *ehdr2
		= elf_tdata (current_program_space->exec_bfd ())->elf_header;
	      Elf_Internal_Phdr *phdr2
		= elf_tdata (current_program_space->exec_bfd ())->phdr;
	      CORE_ADDR displacement = 0;
	      int i;

	      /* DISPLACEMENT could be found more easily by the difference of
		 ehdr2->e_entry.  But we haven't read the ehdr yet, and we
		 already have enough information to compute that displacement
		 with what we've read.  */

	      for (i = 0; i < ehdr2->e_phnum; i++)
		if (phdr2[i].p_type == PT_LOAD)
		  {
		    Elf32_External_Phdr *phdrp;
		    gdb_byte *buf_vaddr_p, *buf_paddr_p;
		    CORE_ADDR vaddr, paddr;
		    CORE_ADDR displacement_vaddr = 0;
		    CORE_ADDR displacement_paddr = 0;

		    phdrp = &((Elf32_External_Phdr *) phdrs_target->data ())[i];
		    buf_vaddr_p = (gdb_byte *) &phdrp->p_vaddr;
		    buf_paddr_p = (gdb_byte *) &phdrp->p_paddr;

		    vaddr = extract_unsigned_integer (buf_vaddr_p, 4,
						      byte_order);
		    displacement_vaddr = vaddr - phdr2[i].p_vaddr;

		    paddr = extract_unsigned_integer (buf_paddr_p, 4,
						      byte_order);
		    displacement_paddr = paddr - phdr2[i].p_paddr;

		    if (displacement_vaddr == displacement_paddr)
		      displacement = displacement_vaddr;

		    break;
		  }

	      /* Now compare program headers from the target and the binary
		 with optional DISPLACEMENT.  */

	      for (i = 0;
		   i < phdrs_target->size () / sizeof (Elf32_External_Phdr);
		   i++)
		{
		  Elf32_External_Phdr *phdrp;
		  Elf32_External_Phdr *phdr2p;
		  gdb_byte *buf_vaddr_p, *buf_paddr_p;
		  CORE_ADDR vaddr, paddr;
		  asection *plt2_asect;

		  phdrp = &((Elf32_External_Phdr *) phdrs_target->data ())[i];
		  buf_vaddr_p = (gdb_byte *) &phdrp->p_vaddr;
		  buf_paddr_p = (gdb_byte *) &phdrp->p_paddr;
		  phdr2p = &((Elf32_External_Phdr *) phdrs_binary->data ())[i];

		  /* PT_GNU_STACK is an exception by being never relocated by
		     prelink as its addresses are always zero.  */

		  if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
		    continue;

		  /* Check also other adjustment combinations - PR 11786.  */

		  vaddr = extract_unsigned_integer (buf_vaddr_p, 4,
						    byte_order);
		  vaddr -= displacement;
		  store_unsigned_integer (buf_vaddr_p, 4, byte_order, vaddr);

		  paddr = extract_unsigned_integer (buf_paddr_p, 4,
						    byte_order);
		  paddr -= displacement;
		  store_unsigned_integer (buf_paddr_p, 4, byte_order, paddr);

		  if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
		    continue;

		  /* Strip modifies the flags and alignment of PT_GNU_RELRO.
		     CentOS-5 has problems with filesz, memsz as well.
		     Strip also modifies memsz of PT_TLS.
		     See PR 11786.  */
		  if (phdr2[i].p_type == PT_GNU_RELRO
		      || phdr2[i].p_type == PT_TLS)
		    {
		      Elf32_External_Phdr tmp_phdr = *phdrp;
		      Elf32_External_Phdr tmp_phdr2 = *phdr2p;

		      memset (tmp_phdr.p_filesz, 0, 4);
		      memset (tmp_phdr.p_memsz, 0, 4);
		      memset (tmp_phdr.p_flags, 0, 4);
		      memset (tmp_phdr.p_align, 0, 4);
		      memset (tmp_phdr2.p_filesz, 0, 4);
		      memset (tmp_phdr2.p_memsz, 0, 4);
		      memset (tmp_phdr2.p_flags, 0, 4);
		      memset (tmp_phdr2.p_align, 0, 4);

		      if (memcmp (&tmp_phdr, &tmp_phdr2, sizeof (tmp_phdr))
			  == 0)
			continue;
		    }

		  /* prelink can convert .plt SHT_NOBITS to SHT_PROGBITS.  */
		  bfd *exec_bfd = current_program_space->exec_bfd ();
		  plt2_asect = bfd_get_section_by_name (exec_bfd, ".plt");
		  if (plt2_asect)
		    {
		      int content2;
		      gdb_byte *buf_filesz_p = (gdb_byte *) &phdrp->p_filesz;
		      CORE_ADDR filesz;

		      content2 = (bfd_section_flags (plt2_asect)
				  & SEC_HAS_CONTENTS) != 0;

		      filesz = extract_unsigned_integer (buf_filesz_p, 4,
							 byte_order);

		      /* PLT2_ASECT is from on-disk file (exec_bfd) while
			 FILESZ is from the in-memory image.  */
		      if (content2)
			filesz += bfd_section_size (plt2_asect);
		      else
			filesz -= bfd_section_size (plt2_asect);

		      store_unsigned_integer (buf_filesz_p, 4, byte_order,
					      filesz);

		      if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
			continue;
		    }

		  return 0;
		}
	    }
	  else if (arch_size == 64
		   && phdrs_target->size () >= sizeof (Elf64_External_Phdr)
		   && phdrs_target->size () % sizeof (Elf64_External_Phdr) == 0)
	    {
	      Elf_Internal_Ehdr *ehdr2
		= elf_tdata (current_program_space->exec_bfd ())->elf_header;
	      Elf_Internal_Phdr *phdr2
		= elf_tdata (current_program_space->exec_bfd ())->phdr;
	      CORE_ADDR displacement = 0;
	      int i;

	      /* DISPLACEMENT could be found more easily by the difference of
		 ehdr2->e_entry.  But we haven't read the ehdr yet, and we
		 already have enough information to compute that displacement
		 with what we've read.  */

	      for (i = 0; i < ehdr2->e_phnum; i++)
		if (phdr2[i].p_type == PT_LOAD)
		  {
		    Elf64_External_Phdr *phdrp;
		    gdb_byte *buf_vaddr_p, *buf_paddr_p;
		    CORE_ADDR vaddr, paddr;
		    CORE_ADDR displacement_vaddr = 0;
		    CORE_ADDR displacement_paddr = 0;

		    phdrp = &((Elf64_External_Phdr *) phdrs_target->data ())[i];
		    buf_vaddr_p = (gdb_byte *) &phdrp->p_vaddr;
		    buf_paddr_p = (gdb_byte *) &phdrp->p_paddr;

		    vaddr = extract_unsigned_integer (buf_vaddr_p, 8,
						      byte_order);
		    displacement_vaddr = vaddr - phdr2[i].p_vaddr;

		    paddr = extract_unsigned_integer (buf_paddr_p, 8,
						      byte_order);
		    displacement_paddr = paddr - phdr2[i].p_paddr;

		    if (displacement_vaddr == displacement_paddr)
		      displacement = displacement_vaddr;

		    break;
		  }

	      /* Now compare BUF and BUF2 with optional DISPLACEMENT.  */

	      for (i = 0;
		   i < phdrs_target->size () / sizeof (Elf64_External_Phdr);
		   i++)
		{
		  Elf64_External_Phdr *phdrp;
		  Elf64_External_Phdr *phdr2p;
		  gdb_byte *buf_vaddr_p, *buf_paddr_p;
		  CORE_ADDR vaddr, paddr;
		  asection *plt2_asect;

		  phdrp = &((Elf64_External_Phdr *) phdrs_target->data ())[i];
		  buf_vaddr_p = (gdb_byte *) &phdrp->p_vaddr;
		  buf_paddr_p = (gdb_byte *) &phdrp->p_paddr;
		  phdr2p = &((Elf64_External_Phdr *) phdrs_binary->data ())[i];

		  /* PT_GNU_STACK is an exception by being never relocated by
		     prelink as its addresses are always zero.  */

		  if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
		    continue;

		  /* Check also other adjustment combinations - PR 11786.  */

		  vaddr = extract_unsigned_integer (buf_vaddr_p, 8,
						    byte_order);
		  vaddr -= displacement;
		  store_unsigned_integer (buf_vaddr_p, 8, byte_order, vaddr);

		  paddr = extract_unsigned_integer (buf_paddr_p, 8,
						    byte_order);
		  paddr -= displacement;
		  store_unsigned_integer (buf_paddr_p, 8, byte_order, paddr);

		  if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
		    continue;

		  /* Strip modifies the flags and alignment of PT_GNU_RELRO.
		     CentOS-5 has problems with filesz, memsz as well.
		     Strip also modifies memsz of PT_TLS.
		     See PR 11786.  */
		  if (phdr2[i].p_type == PT_GNU_RELRO
		      || phdr2[i].p_type == PT_TLS)
		    {
		      Elf64_External_Phdr tmp_phdr = *phdrp;
		      Elf64_External_Phdr tmp_phdr2 = *phdr2p;

		      memset (tmp_phdr.p_filesz, 0, 8);
		      memset (tmp_phdr.p_memsz, 0, 8);
		      memset (tmp_phdr.p_flags, 0, 4);
		      memset (tmp_phdr.p_align, 0, 8);
		      memset (tmp_phdr2.p_filesz, 0, 8);
		      memset (tmp_phdr2.p_memsz, 0, 8);
		      memset (tmp_phdr2.p_flags, 0, 4);
		      memset (tmp_phdr2.p_align, 0, 8);

		      if (memcmp (&tmp_phdr, &tmp_phdr2, sizeof (tmp_phdr))
			  == 0)
			continue;
		    }

		  /* prelink can convert .plt SHT_NOBITS to SHT_PROGBITS.  */
		  plt2_asect
		    = bfd_get_section_by_name (current_program_space->exec_bfd (),
					       ".plt");
		  if (plt2_asect)
		    {
		      int content2;
		      gdb_byte *buf_filesz_p = (gdb_byte *) &phdrp->p_filesz;
		      CORE_ADDR filesz;

		      content2 = (bfd_section_flags (plt2_asect)
				  & SEC_HAS_CONTENTS) != 0;

		      filesz = extract_unsigned_integer (buf_filesz_p, 8,
							 byte_order);

		      /* PLT2_ASECT is from on-disk file (current
			 exec_bfd) while FILESZ is from the in-memory
			 image.  */
		      if (content2)
			filesz += bfd_section_size (plt2_asect);
		      else
			filesz -= bfd_section_size (plt2_asect);

		      store_unsigned_integer (buf_filesz_p, 8, byte_order,
					      filesz);

		      if (memcmp (phdrp, phdr2p, sizeof (*phdrp)) == 0)
			continue;
		    }

		  return 0;
		}
	    }
	  else
	    return 0;
	}
    }

  if (info_verbose)
    {
      /* It can be printed repeatedly as there is no easy way to check
	 the executable symbols/file has been already relocated to
	 displacement.  */

      gdb_printf (_("Using PIE (Position Independent Executable) "
		    "displacement %s for \"%s\".\n"),
		  paddress (current_inferior ()->arch (), exec_displacement),
		  bfd_get_filename (current_program_space->exec_bfd ()));
    }

  *displacementp = exec_displacement;
  return 1;
}

/* Relocate the main executable.  This function should be called upon
   stopping the inferior process at the entry point to the program.
   The entry point from BFD is compared to the AT_ENTRY of AUXV and if they are
   different, the main executable is relocated by the proper amount.  */

static void
svr4_relocate_main_executable (void)
{
  CORE_ADDR displacement;

  /* If we are re-running this executable, SYMFILE_OBJFILE->SECTION_OFFSETS
     probably contains the offsets computed using the PIE displacement
     from the previous run, which of course are irrelevant for this run.
     So we need to determine the new PIE displacement and recompute the
     section offsets accordingly, even if SYMFILE_OBJFILE->SECTION_OFFSETS
     already contains pre-computed offsets.

     If we cannot compute the PIE displacement, either:

       - The executable is not PIE.

       - SYMFILE_OBJFILE does not match the executable started in the target.
	 This can happen for main executable symbols loaded at the host while
	 `ld.so --ld-args main-executable' is loaded in the target.

     Then we leave the section offsets untouched and use them as is for
     this run.  Either:

       - These section offsets were properly reset earlier, and thus
	 already contain the correct values.  This can happen for instance
	 when reconnecting via the remote protocol to a target that supports
	 the `qOffsets' packet.

       - The section offsets were not reset earlier, and the best we can
	 hope is that the old offsets are still applicable to the new run.  */

  if (! svr4_exec_displacement (&displacement))
    return;

  /* Even DISPLACEMENT 0 is a valid new difference of in-memory vs. in-file
     addresses.  */

  objfile *objf = current_program_space->symfile_object_file;
  if (objf)
    {
      section_offsets new_offsets (objf->section_offsets.size (),
				   displacement);
      objfile_relocate (objf, new_offsets);
    }
  else if (current_program_space->exec_bfd ())
    {
      asection *asect;

      bfd *exec_bfd = current_program_space->exec_bfd ();
      for (asect = exec_bfd->sections; asect != NULL; asect = asect->next)
	exec_set_section_address (bfd_get_filename (exec_bfd), asect->index,
				  bfd_section_vma (asect) + displacement);
    }
}

/* Implement the "create_inferior_hook" target_solib_ops method.

   For SVR4 executables, this first instruction is either the first
   instruction in the dynamic linker (for dynamically linked
   executables) or the instruction at "start" for statically linked
   executables.  For dynamically linked executables, the system
   first exec's /lib/libc.so.N, which contains the dynamic linker,
   and starts it running.  The dynamic linker maps in any needed
   shared libraries, maps in the actual user executable, and then
   jumps to "start" in the user executable.

   We can arrange to cooperate with the dynamic linker to discover the
   names of shared libraries that are dynamically linked, and the base
   addresses to which they are linked.

   This function is responsible for discovering those names and
   addresses, and saving sufficient information about them to allow
   their symbols to be read at a later time.  */

void
svr4_solib_ops::create_inferior_hook (int from_tty) const
{
  struct svr4_info *info;

  info = get_svr4_info (current_program_space);

  /* Clear the probes-based interface's state.  */
  this->free_probes_table (info);
  info->solib_lists.clear ();
  info->namespace_id.clear ();
  info->active_namespaces.clear ();

  /* Relocate the main executable if necessary.  */
  svr4_relocate_main_executable ();

  /* No point setting a breakpoint in the dynamic linker if we can't
     hit it (e.g., a core file, or a trace file).  */
  if (!target_has_execution ())
    return;

  if (!this->enable_break (info, from_tty))
    return;
}

void
svr4_solib_ops::clear_solib (program_space *pspace) const
{
  svr4_info *info = get_svr4_info (pspace);
  info->debug_base = 0;
  info->debug_loader_offset_p = 0;
  info->debug_loader_offset = 0;
  info->debug_loader_name.clear ();
}

/* Clear any bits of ADDR that wouldn't fit in a target-format
   data pointer.  "Data pointer" here refers to whatever sort of
   address the dynamic linker uses to manage its sections.  At the
   moment, we don't support shared libraries on any processors where
   code and data pointers are different sizes.

   This isn't really the right solution.  What we really need here is
   a way to do arithmetic on CORE_ADDR values that respects the
   natural pointer/address correspondence.  (For example, on the MIPS,
   converting a 32-bit pointer to a 64-bit CORE_ADDR requires you to
   sign-extend the value.  There, simply truncating the bits above
   gdbarch_ptr_bit, as we do below, is no good.)  This should probably
   be a new gdbarch method or something.  */
static CORE_ADDR
svr4_truncate_ptr (CORE_ADDR addr)
{
  if (gdbarch_ptr_bit (current_inferior ()->arch ()) == sizeof (CORE_ADDR) * 8)
    /* We don't need to truncate anything, and the bit twiddling below
       will fail due to overflow problems.  */
    return addr;
  else
    return addr & (((CORE_ADDR) 1 << gdbarch_ptr_bit (current_inferior ()->arch ())) - 1);
}

/* Find the LOAD-able program header in ABFD that contains ASECT.  Return
   NULL if no such header can be found.  */

static Elf_Internal_Phdr *
find_loadable_elf_internal_phdr (bfd *abfd, bfd_section *asect)
{
  Elf_Internal_Ehdr *ehdr = elf_tdata (abfd)->elf_header;
  Elf_Internal_Phdr *phdr = elf_tdata (abfd)->phdr;

  for (int i = 0; i < ehdr->e_phnum; i++)
    {
      if (phdr[i].p_type == PT_LOAD)
	{
	  /* A section without the SEC_LOAD flag is a no-bits section
	     (e.g. .bss) and has zero size within ABFD.  */
	  ULONGEST section_file_size
	    = (((bfd_section_flags (asect) & SEC_LOAD) != 0)
	       ? bfd_section_size (asect)
	       : 0);

	  if (asect->filepos >= phdr[i].p_offset
	      && ((asect->filepos + section_file_size)
		  <= (phdr[i].p_offset + phdr[i].p_filesz)))
	    return &phdr[i];
	}
    }

  return nullptr;
}

void
svr4_solib_ops::relocate_section_addresses (solib &so,
					    target_section *sec) const
{
  bfd *abfd = sec->the_bfd_section->owner;

  sec->addr = svr4_truncate_ptr (sec->addr + this->lm_addr_check (so, abfd));
  sec->endaddr
    = svr4_truncate_ptr (sec->endaddr + this->lm_addr_check (so, abfd));

  struct bfd_section *asect = sec->the_bfd_section;
  gdb_assert (asect != nullptr);

  /* Update the address range of SO based on ASECT.  */
  if ((bfd_section_flags (asect) & SEC_ALLOC) != 0
      && bfd_get_flavour (abfd) == bfd_target_elf_flavour)
    {
      /* First, SO must cover the contents of ASECT.  */
      if (so.addr_low == 0 || sec->addr < so.addr_low)
	so.addr_low = sec->addr;

      if (so.addr_high == 0 || sec->endaddr > so.addr_high)
	so.addr_high = sec->endaddr;

      gdb_assert (so.addr_low <= so.addr_high);

      /* But we can do better.  Find the program header which contains
	 ASECT, and figure out its extents.  This gives an larger possible
	 region for SO.  */
      Elf_Internal_Phdr *phdr = find_loadable_elf_internal_phdr (abfd, asect);

      if (phdr != nullptr)
	{
	  /* Figure out the alignment required by this segment.  */
	  ULONGEST minpagesize = get_elf_backend_data (abfd)->minpagesize;
	  ULONGEST segment_alignment
	    = std::max (minpagesize, static_cast<ULONGEST> (phdr->p_align));
	  ULONGEST at_pagesz;
	  if (target_auxv_search (AT_PAGESZ, &at_pagesz) > 0)
	    segment_alignment = std::max (segment_alignment, at_pagesz);

	  /* The offset of this section within the segment.  */
	  ULONGEST section_offset = asect->vma - phdr->p_vaddr;

	  /* The start address for the segment, without alignment.  */
	  CORE_ADDR unaligned_start = sec->addr - section_offset;

	  /* And the start address with downward alignment.  */
	  CORE_ADDR aligned_start
	    = align_down (unaligned_start, segment_alignment);

	  /* The end address of the segment depends on its size.  Start
	     with the size as described in the ELF.  This check of the
	     memory size and file size is what BFD does, so assume it
	     knows best and copy this logic.  */
	  ULONGEST seg_size = std::max (phdr->p_memsz, phdr->p_filesz);

	  /* But by aligning the start address down we need to also include
	     that difference in the segment size.  */
	  seg_size += (unaligned_start - aligned_start);

	  /* And align the segment size upward.  */
	  seg_size = align_up (seg_size, segment_alignment);

	  /* Finally, we can compute the end address.  */
	  CORE_ADDR end = aligned_start + seg_size;

	  /* And now we can update the extend of SO.  */
	  if (so.addr_low == 0 || aligned_start < so.addr_low)
	    so.addr_low = aligned_start;

	  if (so.addr_high == 0 || end > so.addr_high)
	    so.addr_high = end;

	  gdb_assert (so.addr_low <= so.addr_high);
	}
    }
}

/* See solib-svr4.h.  */

void
set_solib_svr4_ops (gdbarch *gdbarch, gdbarch_make_solib_ops_ftype make_solib_ops)
{
  set_gdbarch_make_solib_ops (gdbarch, make_solib_ops);
  set_gdbarch_iterate_over_objfiles_in_search_order
    (gdbarch, svr4_iterate_over_objfiles_in_search_order);
}

/* See solib-svr4.h.  */

solib_ops_up
make_svr4_ilp32_solib_ops ()
{
  return std::make_unique<ilp32_svr4_solib_ops> ();
}

/* Most OS'es that have SVR4-style ELF dynamic libraries define a
   `struct r_debug' and a `struct link_map' that are binary compatible
   with the original SVR4 implementation.  */

/* Fetch (and possibly build) an appropriate `struct link_map_offsets'
   for an ILP32 SVR4 system.  */

link_map_offsets *
ilp32_svr4_solib_ops::fetch_link_map_offsets () const
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 4;
      lmo.r_brk_offset = 8;
      lmo.r_ldsomap_offset = 20;
      lmo.r_next_offset = -1;

      /* Everything we need is in the first 20 bytes.  */
      lmo.link_map_size = 20;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 4;
      lmo.l_ld_offset = 8;
      lmo.l_next_offset = 12;
      lmo.l_prev_offset = 16;
    }

  return lmp;
}

/* solib_ops for LP64 SVR4 systems.  */

struct lp64_svr4_solib_ops : public svr4_solib_ops
{
  link_map_offsets *fetch_link_map_offsets () const override;
};

/* See solib-svr4.h.  */

solib_ops_up
make_svr4_lp64_solib_ops ()
{
  return std::make_unique<lp64_svr4_solib_ops> ();
}

/* Fetch (and possibly build) an appropriate `struct link_map_offsets'
   for an LP64 SVR4 system.  */

link_map_offsets *
lp64_svr4_solib_ops::fetch_link_map_offsets () const
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 8;
      lmo.r_brk_offset = 16;
      lmo.r_ldsomap_offset = 40;
      lmo.r_next_offset = -1;

      /* Everything we need is in the first 40 bytes.  */
      lmo.link_map_size = 40;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 8;
      lmo.l_ld_offset = 16;
      lmo.l_next_offset = 24;
      lmo.l_prev_offset = 32;
    }

  return lmp;
}


/* Return the DSO matching OBJFILE or nullptr if none can be found.  */

static const solib *
find_solib_for_objfile (struct objfile *objfile)
{
  if (objfile == nullptr)
    return nullptr;

  /* If OBJFILE is a separate debug object file, look for the original
     object file.  */
  if (objfile->separate_debug_objfile_backlink != nullptr)
    objfile = objfile->separate_debug_objfile_backlink;

  for (const solib &so : current_program_space->solibs ())
    if (so.objfile == objfile)
      return &so;

  return nullptr;
}

/* Return the address of the r_debug object for the namespace containing
   SOLIB or zero if it cannot be found.  This may happen when symbol files
   are added manually, for example, or with the main executable.

   Current callers treat zero as initial namespace so they are doing the
   right thing for the main executable.  */

static CORE_ADDR
find_debug_base_for_solib (const solib *solib)
{
  if (solib == nullptr)
    return 0;

  /* This is always called for solibs with an associated objfile.  */
  gdb_assert (solib->objfile != nullptr);

  svr4_info *info = get_svr4_info (solib->objfile->pspace ());
  gdb_assert (info != nullptr);

  auto *lm_info
    = gdb::checked_static_cast<const lm_info_svr4 *> (solib->lm_info.get ());

  for (const auto &[debug_base, sos] : info->solib_lists)
    for (const svr4_so &so : sos)
      if (svr4_same (solib->original_name.c_str (), so.name.c_str (), *lm_info,
		     *so.lm_info))
	return debug_base;

  return 0;
}

/* Search order for ELF DSOs linked with -Bsymbolic.  Those DSOs have a
   different rule for symbol lookup.  The lookup begins here in the DSO,
   not in the main executable.  When starting from CURRENT_OBJFILE, we
   stay in the same namespace as that file.  Otherwise, we only consider
   the initial namespace.  */

static void
svr4_iterate_over_objfiles_in_search_order
  (gdbarch *gdbarch, iterate_over_objfiles_in_search_order_cb_ftype cb,
   objfile *current_objfile)
{
  bool checked_current_objfile = false;
  if (current_objfile != nullptr)
    {
      bfd *abfd;

      if (current_objfile->separate_debug_objfile_backlink != nullptr)
	current_objfile = current_objfile->separate_debug_objfile_backlink;

      if (current_objfile == current_program_space->symfile_object_file)
	abfd = current_program_space->exec_bfd ();
      else
	abfd = current_objfile->obfd.get ();

      if (abfd != nullptr
	  && gdb_bfd_scan_elf_dyntag (DT_SYMBOLIC, abfd, nullptr, nullptr) == 1)
	{
	  checked_current_objfile = true;
	  if (cb (current_objfile))
	    return;
	}
    }

  /* The linker namespace to iterate identified by the address of its
     r_debug object, defaulting to the initial namespace.  */
  CORE_ADDR initial = elf_locate_base ();
  const solib *curr_solib = find_solib_for_objfile (current_objfile);
  CORE_ADDR debug_base = find_debug_base_for_solib (curr_solib);
  if (debug_base == 0)
    debug_base = initial;

  for (objfile *objfile : current_program_space->objfiles ())
    {
      if (checked_current_objfile && objfile == current_objfile)
	continue;

      /* Try to determine the namespace into which objfile was loaded.

	 If we fail, e.g. for manually added symbol files or for the main
	 executable, we assume that they were added to the initial
	 namespace.  */
      const solib *solib = find_solib_for_objfile (objfile);
      CORE_ADDR solib_base = find_debug_base_for_solib (solib);
      if (solib_base == 0)
	solib_base = initial;

      /* Ignore objfiles that were added to a different namespace.  */
      if (solib_base != debug_base)
	continue;

      if (cb (objfile))
	return;
    }
}

std::optional<CORE_ADDR>
svr4_solib_ops::find_solib_addr (solib &so) const
{
  auto *li = gdb::checked_static_cast<lm_info_svr4 *> (so.lm_info.get ());
  return li->l_addr_inferior;
}

int
svr4_solib_ops::find_solib_ns (const solib &so) const
{
  CORE_ADDR debug_base = find_debug_base_for_solib (&so);
  svr4_info *info = get_svr4_info (current_program_space);
  for (int i = 0; i < info->namespace_id.size (); i++)
    {
      if (info->namespace_id[i] == debug_base)
	{
	  gdb_assert (info->active_namespaces.count (i) == 1);
	  return i;
	}
    }
  error (_("No namespace found"));
}

int
svr4_solib_ops::num_active_namespaces () const
{
  svr4_info *info = get_svr4_info (current_program_space);
  return info->active_namespaces.size ();
}

std::vector<const solib *>
svr4_solib_ops::get_solibs_in_ns (int nsid) const
{
  std::vector<const solib*> ns_solibs;
  svr4_info *info = get_svr4_info (current_program_space);

  /* If the namespace ID is inactive, there will be no active
     libraries, so we can have an early exit, as a treat.  */
  if (info->active_namespaces.count (nsid) != 1)
    return ns_solibs;

  /* Since we only have the names of solibs in a given namespace,
     we'll need to walk through the solib list of the inferior and
     find which solib objects correspond to which svr4_so.  We create
     an unordered map with the names and lm_info to check things
     faster, and to be able to remove SOs from the map, to avoid
     returning the dynamic linker multiple times.  */
  CORE_ADDR debug_base = info->namespace_id[nsid];
  std::unordered_map<std::string, const lm_info_svr4 *> namespace_solibs;
  for (svr4_so &so : info->solib_lists[debug_base])
    namespace_solibs[so.name] = so.lm_info.get ();

  for (const solib &so: current_program_space->solibs ())
    {
      auto *lm_inferior
	= gdb::checked_static_cast<const lm_info_svr4 *> (so.lm_info.get ());

      /* This is inspired by the svr4_same, by finding the svr4_so object
	 in the map, and then double checking if the lm_info is considered
	 the same.  */
      if (namespace_solibs.count (so.original_name) > 0
	  && namespace_solibs[so.original_name]->l_addr_inferior
	      == lm_inferior->l_addr_inferior)
	{
	  ns_solibs.push_back (&so);
	  /* Remove the SO from the map, so that we don't end up
	     printing the dynamic linker multiple times.  */
	  namespace_solibs.erase (so.original_name);
	}
    }

  return ns_solibs;
}

INIT_GDB_FILE (svr4_solib)
{
  gdb::observers::free_objfile.attach (svr4_free_objfile_observer,
				       "solib-svr4");

  /* Set up observers for tracking GLIBC TLS module id slots.  */
  gdb::observers::solib_loaded.attach (tls_maybe_fill_slot, "solib-svr4");
  gdb::observers::solib_unloaded.attach (tls_maybe_erase_slot, "solib-svr4");
}
