# This shell script emits a C file. -*- C -*-
# It does some substitutions.
if [ -z "$MACHINE" ]; then
  OUTPUT_ARCH=${ARCH}
else
  OUTPUT_ARCH=${ARCH}:${MACHINE}
fi
fragment <<EOF
/* This file is part of GLD, the Gnu Linker.
   Copyright (C) 1995-2025 Free Software Foundation, Inc.

   This file is part of the GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


/* For WINDOWS_NT */
/* The original file generated returned different default scripts depending
   on whether certain switches were set, but these switches pertain to the
   Linux system and that particular version of coff.  In the NT case, we
   only determine if the subsystem is console or windows in order to select
   the correct entry point by default. */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "ctf-api.h"
#include "getopt.h"
#include "libiberty.h"
#include "filenames.h"
#include "ld.h"
#include "ldmain.h"
#include "ldexp.h"
#include "ldlang.h"
#include "ldfile.h"
#include "ldemul.h"
#include <ldgram.h>
#include "ldlex.h"
#include "ldmisc.h"
#include "ldctor.h"
#include "coff/internal.h"
#include "../bfd/libcoff.h"

#define TARGET_IS_${EMULATION_NAME}

static struct internal_extra_pe_aouthdr pe;
static int dll;

extern const char *output_filename;

static void
gld${EMULATION_NAME}_before_parse (void)
{
  ldfile_set_output_arch ("${OUTPUT_ARCH}", bfd_arch_`echo ${ARCH} | sed -e 's/:.*//'`);
  output_filename = "a.exe";
}

/* PE format extra command line options.  */

static void
gld${EMULATION_NAME}_add_options
  (int ns ATTRIBUTE_UNUSED, char **shortopts ATTRIBUTE_UNUSED, int nl,
   struct option **longopts, int nrl ATTRIBUTE_UNUSED,
   struct option **really_longopts ATTRIBUTE_UNUSED)
{
  static const struct option xtra_long[] = {
    /* PE options */
    {"base-file", required_argument, NULL, OPTION_BASE_FILE},
    {"dll", no_argument, NULL, OPTION_DLL},
    {"file-alignment", required_argument, NULL, OPTION_FILE_ALIGNMENT},
    {"heap", required_argument, NULL, OPTION_HEAP},
    {"major-image-version", required_argument, NULL, OPTION_MAJOR_IMAGE_VERSION},
    {"major-os-version", required_argument, NULL, OPTION_MAJOR_OS_VERSION},
    {"major-subsystem-version", required_argument, NULL, OPTION_MAJOR_SUBSYSTEM_VERSION},
    {"minor-image-version", required_argument, NULL, OPTION_MINOR_IMAGE_VERSION},
    {"minor-os-version", required_argument, NULL, OPTION_MINOR_OS_VERSION},
    {"minor-subsystem-version", required_argument, NULL, OPTION_MINOR_SUBSYSTEM_VERSION},
    {"section-alignment", required_argument, NULL, OPTION_SECTION_ALIGNMENT},
    {"stack", required_argument, NULL, OPTION_STACK},
    {"subsystem", required_argument, NULL, OPTION_SUBSYSTEM},
    {NULL, no_argument, NULL, 0}
  };

  *longopts = (struct option *)
    xrealloc (*longopts, nl * sizeof (struct option) + sizeof (xtra_long));
  memcpy (*longopts + nl, &xtra_long, sizeof (xtra_long));
}


/* PE/WIN32; added routines to get the subsystem type, heap and/or stack
   parameters which may be input from the command line */

typedef struct {
  void *ptr;
  int size;
  int value;
  char *symbol;
  int inited;
} definfo;

#define D(field,symbol,def)  {&pe.field,sizeof(pe.field), def, symbol,0}

static definfo init[] =
{
  /* imagebase must be first */
#define IMAGEBASEOFF 0
  D(ImageBase,"__image_base__", BEOS_EXE_IMAGE_BASE),
#define DLLOFF 1
  {&dll, sizeof(dll), 0, "__dll__", 0},
  D(SectionAlignment,"__section_alignment__", PE_DEF_SECTION_ALIGNMENT),
  D(FileAlignment,"__file_alignment__", PE_DEF_FILE_ALIGNMENT),
  D(MajorOperatingSystemVersion,"__major_os_version__", 4),
  D(MinorOperatingSystemVersion,"__minor_os_version__", 0),
  D(MajorImageVersion,"__major_image_version__", 1),
  D(MinorImageVersion,"__minor_image_version__", 0),
  D(MajorSubsystemVersion,"__major_subsystem_version__", 4),
  D(MinorSubsystemVersion,"__minor_subsystem_version__", 0),
  D(Subsystem,"__subsystem__", 3),
  D(SizeOfStackReserve,"__size_of_stack_reserve__", 0x2000000),
  D(SizeOfStackCommit,"__size_of_stack_commit__", 0x1000),
  D(SizeOfHeapReserve,"__size_of_heap_reserve__", 0x100000),
  D(SizeOfHeapCommit,"__size_of_heap_commit__", 0x1000),
  D(LoaderFlags,"__loader_flags__", 0x0),
  { NULL, 0, 0, NULL, 0 }
};


static void
set_pe_name (char *name, long val)
{
  int i;
  /* Find the name and set it. */
  for (i = 0; init[i].ptr; i++)
    {
      if (strcmp (name, init[i].symbol) == 0)
	{
	  init[i].value = val;
	  init[i].inited = 1;
	  return;
	}
    }
  abort();
}


static void
set_pe_subsystem (void)
{
  const char *sver;
  int len;
  int i;
  static const struct
    {
      const char *name;
      const int value;
      const char *entry;
    }
  v[] =
    {
      { "native", 1, "_NtProcessStartup" },
      { "windows", 2, "_WinMainCRTStartup" },
      { "wwindows", 2, "_wWinMainCRTStartup" },
      { "console", 3, "_mainCRTStartup" },
      { "wconsole", 3, "_wmainCRTStartup" },
      { "posix", 7, "___PosixProcessStartup"},
      { 0, 0, 0 }
    };

  sver = strchr (optarg, ':');
  if (sver == NULL)
    len = strlen (optarg);
  else
    {
      char *end;

      len = sver - optarg;
      set_pe_name ("__major_subsystem_version__",
		   strtoul (sver + 1, &end, 0));
      if (*end == '.')
	set_pe_name ("__minor_subsystem_version__",
		     strtoul (end + 1, &end, 0));
      if (*end != '\0')
	einfo (_("%P: warning: bad version number in -subsystem option\n"));
    }

  for (i = 0; v[i].name; i++)
    {
      if (strncmp (optarg, v[i].name, len) == 0
	  && v[i].name[len] == '\0')
	{
	  set_pe_name ("__subsystem__", v[i].value);

	  /* If the subsystem is windows, we use a different entry
	     point.  */
	  lang_default_entry (v[i].entry);

	  return;
	}
    }
  fatal (_("%P: invalid subsystem type %s\n"), optarg);
}


static void
set_pe_value (char *name)
{
  char *end;
  set_pe_name (name,  strtoul (optarg, &end, 0));
  if (end == optarg)
    fatal (_("%P: invalid hex number for PE parameter '%s'\n"), optarg);

  optarg = end;
}

static void
set_pe_stack_heap (char *resname, char *comname)
{
  set_pe_value (resname);
  if (*optarg == ',')
    {
      optarg++;
      set_pe_value (comname);
    }
  else if (*optarg)
    fatal (_("%P: strange hex info for PE parameter '%s'\n"), optarg);
}


static bool
gld${EMULATION_NAME}_handle_option (int optc)
{
  switch (optc)
    {
    default:
      return false;

    case OPTION_BASE_FILE:
      link_info.base_file = fopen (optarg, FOPEN_WB);
      if (link_info.base_file == NULL)
	fatal (_("%P: cannot open base file %s\n"), optarg);
      break;

      /* PE options */
    case OPTION_HEAP:
      set_pe_stack_heap ("__size_of_heap_reserve__", "__size_of_heap_commit__");
      break;
    case OPTION_STACK:
      set_pe_stack_heap ("__size_of_stack_reserve__", "__size_of_stack_commit__");
      break;
    case OPTION_SUBSYSTEM:
      set_pe_subsystem ();
      break;
    case OPTION_MAJOR_OS_VERSION:
      set_pe_value ("__major_os_version__");
      break;
    case OPTION_MINOR_OS_VERSION:
      set_pe_value ("__minor_os_version__");
      break;
    case OPTION_MAJOR_SUBSYSTEM_VERSION:
      set_pe_value ("__major_subsystem_version__");
      break;
    case OPTION_MINOR_SUBSYSTEM_VERSION:
      set_pe_value ("__minor_subsystem_version__");
      break;
    case OPTION_MAJOR_IMAGE_VERSION:
      set_pe_value ("__major_image_version__");
      break;
    case OPTION_MINOR_IMAGE_VERSION:
      set_pe_value ("__minor_image_version__");
      break;
    case OPTION_FILE_ALIGNMENT:
      set_pe_value ("__file_alignment__");
      break;
    case OPTION_SECTION_ALIGNMENT:
      set_pe_value ("__section_alignment__");
      break;
    case OPTION_DLL:
      set_pe_name ("__dll__", 1);
      break;
    case OPTION_IMAGE_BASE:
      set_pe_value ("__image_base__");
      break;
    }
  return true;
}

/* Assign values to the special symbols before the linker script is
   read.  */

static void
gld${EMULATION_NAME}_set_symbols (void)
{
  /* Run through and invent symbols for all the
     names and insert the defaults. */
  int j;

  if (!init[IMAGEBASEOFF].inited)
    {
      if (bfd_link_relocatable (&link_info))
	init[IMAGEBASEOFF].value = 0;
      else if (init[DLLOFF].value)
	init[IMAGEBASEOFF].value = BEOS_DLL_IMAGE_BASE;
      else
	init[IMAGEBASEOFF].value = BEOS_EXE_IMAGE_BASE;
    }

  /* Don't do any symbol assignments if this is a relocatable link.  */
  if (bfd_link_relocatable (&link_info))
    return;

  /* Glue the assignments into the abs section */
  push_stat_ptr (&abs_output_section->children);

  for (j = 0; init[j].ptr; j++)
    {
      long val = init[j].value;
      lang_add_assignment (exp_assign (init[j].symbol, exp_intop (val),
				       false));
      if (init[j].size == sizeof(short))
	*(short *)init[j].ptr = val;
      else if (init[j].size == sizeof(int))
	*(int *)init[j].ptr = val;
      else if (init[j].size == sizeof(long))
	*(long *)init[j].ptr = val;
      /* This might be a long long or other special type.  */
      else if (init[j].size == sizeof(bfd_vma))
	*(bfd_vma *)init[j].ptr = val;
      else	abort();
    }
  /* Restore the pointer. */
  pop_stat_ptr ();

  if (pe.FileAlignment >
      pe.SectionAlignment)
    {
      einfo (_("%P: warning, file alignment > section alignment\n"));
    }
}

static void
gld${EMULATION_NAME}_after_open (void)
{
  after_open_default ();

  /* Pass the wacky PE command line options into the output bfd.
     FIXME: This should be done via a function, rather than by
     including an internal BFD header.  */
  if (!obj_pe (link_info.output_bfd))
    fatal (_("%P: PE operations on non PE file\n"));

  pe_data(link_info.output_bfd)->pe_opthdr = pe;
  pe_data(link_info.output_bfd)->dll = init[DLLOFF].value;

}

/* Callback functions for qsort in sort_sections. */

static int
sort_by_file_name (const void *a, const void *b)
{
  const lang_input_section_type *const *ra = a;
  const lang_input_section_type *const *rb = b;
  asection *sa = (*ra)->section;
  asection *sb = (*rb)->section;
  int i, a_sec, b_sec;

  i = filename_cmp (bfd_get_filename (sa->owner->my_archive),
		    bfd_get_filename (sb->owner->my_archive));
  if (i != 0)
    return i;

  i = filename_cmp (bfd_get_filename (sa->owner),
		    bfd_get_filename (sb->owner));
  if (i != 0)
    return i;
  /* the tail idata4/5 are the only ones without relocs to an
     idata$6 section unless we are importing by ordinal,
     so sort them to last to terminate the IAT
     and HNT properly. if no reloc this one is import by ordinal
     so we have to sort by section contents */

  if (sa->reloc_count + sb->reloc_count != 0)
    {
      i = sa->reloc_count > sb->reloc_count ? -1 : 0;
      if (i != 0)
	return i;

      return sa->reloc_count > sb->reloc_count ? 0 : 1;
    }
  else
    {
      /* don't sort .idata$6 or .idata$7 FIXME dlltool eliminate .idata$7 */
      if ((strcmp (sa->name, ".idata$6") == 0))
	return 0;

      if (!bfd_get_section_contents (sa->owner, sa, &a_sec, (file_ptr) 0,
				     (bfd_size_type) sizeof (a_sec)))
	fatal (_("%P: %pB: can't read contents of section .idata: %E\n"),
	       sa->owner);

      if (!bfd_get_section_contents (sb->owner, sb, &b_sec, (file_ptr) 0,
				     (bfd_size_type) sizeof (b_sec)))
	fatal (_("%P: %pB: can't read contents of section .idata: %E\n"),
	       sb->owner);

      i = a_sec < b_sec ? -1 : 0;
      if (i != 0)
	return i;
      return a_sec < b_sec ? 0 : 1;
    }
  return 0;
}

static int
sort_by_section_name (const void *a, const void *b)
{
  const lang_input_section_type *const *ra = a;
  const lang_input_section_type *const *rb = b;
  const char *sna = (*ra)->section->name;
  const char *snb = (*rb)->section->name;
  int i;
  i = strcmp (sna, snb);
  /* This is a hack to make .stab and .stabstr last, so we don't have
     to fix strip/objcopy for .reloc sections.
     FIXME stripping images with a .rsrc section still needs to be fixed.  */
  if (i != 0)
    {
      if ((startswith (sna, ".stab"))
	  && (!startswith (snb, ".stab")))
	return 1;
    }
  return i;
}

/* Subroutine of sort_sections to a contiguous subset of a list of sections.
   NEXT_AFTER is the element after the last one to sort.
   The result is a pointer to the last element's "next" pointer.  */

static lang_statement_union_type **
sort_sections_1 (lang_statement_union_type **startptr,
		 lang_statement_union_type *next_after,
		 int count,
		 int (*sort_func) (const void *, const void *))
{
  lang_statement_union_type **vec;
  lang_statement_union_type *p;
  int i;
  lang_statement_union_type **ret;

  if (count == 0)
    return startptr;

  vec = ((lang_statement_union_type **)
	 xmalloc (count * sizeof (lang_statement_union_type *)));

  for (p = *startptr, i = 0; i < count; i++, p = p->header.next)
    vec[i] = p;

  qsort (vec, count, sizeof (vec[0]), sort_func);

  /* Fill in the next pointers again. */
  *startptr = vec[0];
  for (i = 0; i < count - 1; i++)
    vec[i]->header.next = vec[i + 1];
  vec[i]->header.next = next_after;
  ret = &vec[i]->header.next;
  free (vec);
  return ret;
}

/* Sort the .idata\$foo input sections of archives into filename order.
   The reason is so dlltool can arrange to have the pe dll import information
   generated correctly - the head of the list goes into dh.o, the tail into
   dt.o, and the guts into ds[nnnn].o.  Note that this is only needed for the
   .idata section.
   FIXME: This may no longer be necessary with grouped sections.  Instead of
   sorting on dh.o, ds[nnnn].o, dt.o, one could, for example, have dh.o use
   .idata\$4h, have ds[nnnn].o use .idata\$4s[nnnn], and have dt.o use .idata\$4t.
   This would have to be elaborated upon to handle multiple dll's
   [assuming such an eloboration is possible of course].

   We also sort sections in '\$' wild statements.  These are created by the
   place_orphans routine to implement grouped sections.  */

static void
sort_sections (lang_statement_union_type *s)
{
  for (; s ; s = s->header.next)
    switch (s->header.type)
      {
      case lang_output_section_statement_enum:
	sort_sections (s->output_section_statement.children.head);
	break;
      case lang_wild_statement_enum:
	{
	  lang_statement_union_type **p = &s->wild_statement.children.head;
	  struct wildcard_list *sec;

	  for (sec = s->wild_statement.section_list; sec; sec = sec->next)
	    {
	      /* Is this the .idata section?  */
	      if (sec->spec.name != NULL
		  && startswith (sec->spec.name, ".idata"))
		{
		  /* Sort the children.  We want to sort any objects in
		     the same archive.  In order to handle the case of
		     including a single archive multiple times, we sort
		     all the children by archive name and then by object
		     name.  After sorting them, we re-thread the pointer
		     chain.  */

		  while (*p)
		    {
		      lang_statement_union_type *start = *p;
		      if (start->header.type != lang_input_section_enum
			  || !start->input_section.section->owner->my_archive)
			p = &(start->header.next);
		      else
			{
			  lang_statement_union_type *end;
			  int count;

			  for (end = start, count = 0;
			       end && (end->header.type
				       == lang_input_section_enum);
			       end = end->header.next)
			    count++;

			  p = sort_sections_1 (p, end, count,
					       sort_by_file_name);
			}
		    }
		  break;
		}

	      /* If this is a collection of grouped sections, sort them.
		 The linker script must explicitly mention "*(.foo\$)" or
		 "*(.foo\$*)".  Don't sort them if \$ is not the last
		 character (not sure if this is really useful, but it
		 allows explicitly mentioning some \$ sections and letting
		 the linker handle the rest).  */
	      if (sec->spec.name != NULL)
		{
		  char *q = strchr (sec->spec.name, '\$');

		  if (q != NULL
		      && (q[1] == '\0'
			  || (q[1] == '*' && q[2] == '\0')))
		    {
		      lang_statement_union_type *end;
		      int count;

		      for (end = *p, count = 0; end; end = end->header.next)
			{
			  if (end->header.type != lang_input_section_enum)
			    abort ();
			  count++;
			}
		      (void) sort_sections_1 (p, end, count,
					      sort_by_section_name);
		    }
		  break;
		}
	    }
	}
	break;
      default:
	break;
      }
}

static void
gld${EMULATION_NAME}_before_allocation (void)
{
#ifdef TARGET_IS_armpe
  /* FIXME: we should be able to set the size of the interworking stub
     section.

     Here we rummage through the found bfds to collect glue
     information.  FIXME: should this be based on a command line
     option?  krk@cygnus.com */
  {
    LANG_FOR_EACH_INPUT_STATEMENT (is)
    {
      if (!arm_process_before_allocation (is->the_bfd, & link_info))
	{
	  einfo (_("%P: errors encountered processing file %s\n"),
		 is->filename);
	}
    }
  }

  /* We have seen it all. Allocate it, and carry on */
  arm_allocate_interworking_sections (& link_info);
#endif /* TARGET_IS_armpe */

  sort_sections (stat_ptr->head);

  before_allocation_default ();
}

/* Place an orphan section.  We use this to put sections with a '\$' in them
   into the right place.  Any section with a '\$' in them (e.g. .text\$foo)
   gets mapped to the output section with everything from the '\$' on stripped
   (e.g. .text).
   See the Microsoft Portable Executable and Common Object File Format
   Specification 4.1, section 4.2, Grouped Sections.

   FIXME: This is now handled by the linker script using wildcards,
   but I'm leaving this here in case we want to enable it for sections
   which are not mentioned in the linker script.  */

static lang_output_section_statement_type *
gld${EMULATION_NAME}_place_orphan (asection *s,
				   const char *secname,
				   int constraint)
{
  char *output_secname, *ps;
  lang_output_section_statement_type *os;
  lang_statement_union_type *l;

  if ((s->flags & SEC_ALLOC) == 0)
    return NULL;

  /* Don't process grouped sections unless doing a final link.
     If they're marked as COMDAT sections, we don't want .text\$foo to
     end up in .text and then have .text disappear because it's marked
     link-once-discard.  */
  if (bfd_link_relocatable (&link_info))
    return NULL;

  /* Everything from the '\$' on gets deleted so don't allow '\$' as the
     first character.  */
  if (*secname == '\$')
    fatal (_("%P: section %s has '\$' as first character\n"), secname);
  if (strchr (secname + 1, '\$') == NULL)
    return NULL;

  /* Look up the output section.  The Microsoft specs say sections names in
     image files never contain a '\$'.  Fortunately, lang_..._lookup creates
     the section if it doesn't exist.  */
  output_secname = xstrdup (secname);
  ps = strchr (output_secname + 1, '\$');
  *ps = 0;
  os = lang_output_section_statement_lookup (output_secname, constraint, true);

  /* Find the '\$' wild statement for this section.  We currently require the
     linker script to explicitly mention "*(.foo\$)".  */

  ps[0] = '\$';
  ps[1] = 0;
  for (l = os->children.head; l; l = l->header.next)
    if (l->header.type == lang_wild_statement_enum)
      {
	struct wildcard_list *sec;

	for (sec = l->wild_statement.section_list; sec; sec = sec->next)
	  if (sec->spec.name && strcmp (sec->spec.name, output_secname) == 0)
	    break;
	if (sec)
	  break;
      }
  ps[0] = 0;
  if (l == NULL)
    fatal (_("%P: *(%s\$) missing from linker script\n"), output_secname);

  /* Link the input section in and we're done for now.
     The sections still have to be sorted, but that has to wait until
     all such sections have been processed by us.  The sorting is done by
     sort_sections.  */
  lang_add_section (&l->wild_statement.children, s, NULL, NULL, os);

  return os;
}

static char *
gld${EMULATION_NAME}_get_script (int *isfile)
EOF

if test x"$COMPILE_IN" = xyes
then
# Scripts compiled in.

# sed commands to quote an ld script as a C string.
sc="-f ${srcdir}/emultempl/stringify.sed"

fragment <<EOF
{
  *isfile = 0;

  if (bfd_link_relocatable (&link_info) && config.build_constructors)
    return
EOF
sed $sc ldscripts/${EMULATION_NAME}.xu                 >> e${EMULATION_NAME}.c
echo '  ; else if (bfd_link_relocatable (&link_info)) return' >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xr                 >> e${EMULATION_NAME}.c
echo '  ; else if (!config.text_read_only) return'     >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xbn                >> e${EMULATION_NAME}.c
echo '  ; else if (!config.magic_demand_paged) return' >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xn                 >> e${EMULATION_NAME}.c
echo '  ; else return'                                 >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.x                  >> e${EMULATION_NAME}.c
echo '; }'                                             >> e${EMULATION_NAME}.c

else
# Scripts read from the filesystem.

fragment <<EOF
{
  *isfile = 1;

  if (bfd_link_relocatable (&link_info) && config.build_constructors)
    return "ldscripts/${EMULATION_NAME}.xu";
  else if (bfd_link_relocatable (&link_info))
    return "ldscripts/${EMULATION_NAME}.xr";
  else if (!config.text_read_only)
    return "ldscripts/${EMULATION_NAME}.xbn";
  else if (!config.magic_demand_paged)
    return "ldscripts/${EMULATION_NAME}.xn";
  else
    return "ldscripts/${EMULATION_NAME}.x";
}
EOF
fi

LDEMUL_AFTER_OPEN=gld${EMULATION_NAME}_after_open
LDEMUL_BEFORE_ALLOCATION=gld${EMULATION_NAME}_before_allocation
LDEMUL_PLACE_ORPHAN=gld${EMULATION_NAME}_place_orphan
LDEMUL_SET_SYMBOLS=gld${EMULATION_NAME}_set_symbols
LDEMUL_ADD_OPTIONS=gld${EMULATION_NAME}_add_options
LDEMUL_HANDLE_OPTION=gld${EMULATION_NAME}_handle_option

source_em ${srcdir}/emultempl/emulation.em
