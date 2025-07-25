/* ldwrite.c -- write out the linked file
   Copyright (C) 1991-2025 Free Software Foundation, Inc.
   Written by Steve Chamberlain sac@cygnus.com

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

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libiberty.h"
#include "ctf-api.h"
#include "safe-ctype.h"

#include "ld.h"
#include "ldexp.h"
#include "ldlang.h"
#include "ldwrite.h"
#include "ldmisc.h"
#include <ldgram.h>
#include "ldmain.h"

/* Build link_order structures for the BFD linker.  */

static void
build_link_order (lang_statement_union_type *statement)
{
  switch (statement->header.type)
    {
    case lang_data_statement_enum:
      {
	asection *output_section;
	struct bfd_link_order *link_order;
	bfd_vma value;

	output_section = statement->data_statement.output_section;
	ASSERT (output_section->owner == link_info.output_bfd);

	if (!((output_section->flags & SEC_HAS_CONTENTS) != 0
	      || ((output_section->flags & SEC_LOAD) != 0
		  && (output_section->flags & SEC_THREAD_LOCAL))))
	  break;

	link_order = bfd_new_link_order (link_info.output_bfd, output_section);
	if (link_order == NULL)
	  fatal (_("%P: bfd_new_link_order failed: %E\n"));

	link_order->type = bfd_data_link_order;
	link_order->offset = statement->data_statement.output_offset;
	link_order->u.data.contents = bfd_alloc (link_info.output_bfd,
						 QUAD_SIZE);
	if (link_order->u.data.contents == NULL)
	  fatal (_("%P: bfd_new_link_order failed: %E\n"));

	value = statement->data_statement.value;

	/* By convention, the bfd_put routines for an unknown
	   endianness are big endian, so we must swap here if the
	   input is little endian.  */
	if (!bfd_big_endian (link_info.output_bfd)
	    && !bfd_little_endian (link_info.output_bfd)
	    && !link_info.big_endian)
	  {
	    bfd_byte buffer[8];

	    switch (statement->data_statement.type)
	      {
	      case QUAD:
	      case SQUAD:
		if (sizeof (bfd_vma) >= QUAD_SIZE)
		  {
		    bfd_putl64 (value, buffer);
		    value = bfd_getb64 (buffer);
		    break;
		  }
		/* Fall through.  */
	      case LONG:
		bfd_putl32 (value, buffer);
		value = bfd_getb32 (buffer);
		break;
	      case SHORT:
		bfd_putl16 (value, buffer);
		value = bfd_getb16 (buffer);
		break;
	      case BYTE:
		break;
	      default:
		abort ();
	      }
	  }

	ASSERT (output_section->owner == link_info.output_bfd);
	switch (statement->data_statement.type)
	  {
	  case QUAD:
	  case SQUAD:
	    if (sizeof (bfd_vma) >= QUAD_SIZE)
	      bfd_put_64 (link_info.output_bfd, value,
			  link_order->u.data.contents);
	    else
	      {
		bfd_vma high;

		if (statement->data_statement.type == QUAD)
		  high = 0;
		else if ((value & 0x80000000) == 0)
		  high = 0;
		else
		  high = (bfd_vma) -1;
		bfd_put_32 (link_info.output_bfd, high,
			    (link_order->u.data.contents
			     + (link_info.big_endian ? 0 : 4)));
		bfd_put_32 (link_info.output_bfd, value,
			    (link_order->u.data.contents
			     + (link_info.big_endian ? 4 : 0)));
	      }
	    link_order->size = QUAD_SIZE;
	    break;
	  case LONG:
	    bfd_put_32 (link_info.output_bfd, value,
			link_order->u.data.contents);
	    link_order->size = LONG_SIZE;
	    break;
	  case SHORT:
	    bfd_put_16 (link_info.output_bfd, value,
			link_order->u.data.contents);
	    link_order->size = SHORT_SIZE;
	    break;
	  case BYTE:
	    bfd_put_8 (link_info.output_bfd, value,
		       link_order->u.data.contents);
	    link_order->size = BYTE_SIZE;
	    break;
	  default:
	    abort ();
	  }
	link_order->u.data.size = link_order->size;
      }
      break;

    case lang_reloc_statement_enum:
      {
	lang_reloc_statement_type *rs;
	asection *output_section;
	struct bfd_link_order *link_order;

	rs = &statement->reloc_statement;

	output_section = rs->output_section;
	ASSERT (output_section->owner == link_info.output_bfd);

	if (!((output_section->flags & SEC_HAS_CONTENTS) != 0
	      || ((output_section->flags & SEC_LOAD) != 0
		  && (output_section->flags & SEC_THREAD_LOCAL))))
	  break;

	link_order = bfd_new_link_order (link_info.output_bfd, output_section);
	if (link_order == NULL)
	  fatal (_("%P: bfd_new_link_order failed: %E\n"));

	link_order->offset = rs->output_offset;
	link_order->size = bfd_get_reloc_size (rs->howto);

	link_order->u.reloc.p = (struct bfd_link_order_reloc *)
	  bfd_alloc (link_info.output_bfd, sizeof (struct bfd_link_order_reloc));
	if (link_order->u.reloc.p == NULL)
	  fatal (_("%P: bfd_new_link_order failed: %E\n"));

	link_order->u.reloc.p->reloc = rs->reloc;
	link_order->u.reloc.p->addend = rs->addend_value;

	if (rs->name == NULL)
	  {
	    link_order->type = bfd_section_reloc_link_order;
	    if (rs->section->owner == link_info.output_bfd)
	      link_order->u.reloc.p->u.section = rs->section;
	    else
	      {
		link_order->u.reloc.p->u.section = rs->section->output_section;
		link_order->u.reloc.p->addend += rs->section->output_offset;
	      }
	  }
	else
	  {
	    link_order->type = bfd_symbol_reloc_link_order;
	    link_order->u.reloc.p->u.name = rs->name;
	  }
      }
      break;

    case lang_input_section_enum:
      {
	/* Create a new link_order in the output section with this
	   attached */
	asection *i = statement->input_section.section;

	if (i->sec_info_type != SEC_INFO_TYPE_JUST_SYMS
	    && (i->flags & SEC_EXCLUDE) == 0)
	  {
	    asection *output_section = i->output_section;
	    struct bfd_link_order *link_order;

	    ASSERT (output_section->owner == link_info.output_bfd);

	    if (!((output_section->flags & SEC_HAS_CONTENTS) != 0
		  || ((output_section->flags & SEC_LOAD) != 0
		      && (output_section->flags & SEC_THREAD_LOCAL))))
	      break;

	    link_order = bfd_new_link_order (link_info.output_bfd,
					     output_section);
	    if (link_order == NULL)
	      fatal (_("%P: bfd_new_link_order failed: %E\n"));

	    if ((i->flags & SEC_NEVER_LOAD) != 0
		&& (i->flags & SEC_DEBUGGING) == 0)
	      {
		/* We've got a never load section inside one which is
		   going to be output, we'll change it into a fill.  */
		link_order->type = bfd_data_link_order;
		link_order->u.data.contents = (unsigned char *) "";
		link_order->u.data.size = 1;
	      }
	    else
	      {
		link_order->type = bfd_indirect_link_order;
		link_order->u.indirect.section = i;
		ASSERT (i->output_section == output_section);
	      }
	    link_order->size = i->size;
	    link_order->offset = i->output_offset;
	  }
      }
      break;

    case lang_padding_statement_enum:
      /* Make a new link_order with the right filler */
      {
	asection *output_section;
	struct bfd_link_order *link_order;

	output_section = statement->padding_statement.output_section;
	ASSERT (statement->padding_statement.output_section->owner
		== link_info.output_bfd);

	if (!((output_section->flags & SEC_HAS_CONTENTS) != 0
	      || ((output_section->flags & SEC_LOAD) != 0
		  && (output_section->flags & SEC_THREAD_LOCAL))))
	  break;

	link_order = bfd_new_link_order (link_info.output_bfd,
					 output_section);
	if (link_order == NULL)
	  fatal (_("%P: bfd_new_link_order failed: %E\n"));
	link_order->type = bfd_data_link_order;
	link_order->size = statement->padding_statement.size;
	link_order->offset = statement->padding_statement.output_offset;
	link_order->u.data.contents = statement->padding_statement.fill->data;
	link_order->u.data.size = statement->padding_statement.fill->size;
      }
      break;

    default:
      /* All the other ones fall through */
      break;
    }
}

/* Return true if NAME is the name of an unsplittable section. These
   are the stabs strings, dwarf strings.  */

static bool
unsplittable_name (const char *name)
{
  if (startswith (name, ".stab"))
    {
      /* There are several stab like string sections. We pattern match on
	 ".stab...str"  */
      unsigned len = strlen (name);
      if (strcmp (&name[len-3], "str") == 0)
	return true;
    }
  else if (strcmp (name, "$GDB_STRINGS$") == 0)
    return true;
  return false;
}

/* Wander around the input sections, make sure that
   we'll never try and create an output section with more relocs
   than will fit.. Do this by always assuming the worst case, and
   creating new output sections with all the right bits.  */
#define TESTIT 1
static asection *
clone_section (bfd *abfd, asection *s, const char *name, int *count)
{
  char *tname;
  char *sname;
  unsigned int len;
  asection *n;
  struct bfd_link_hash_entry *h;

  /* Invent a section name from the section name and a dotted numeric
     suffix.   */
  len = strlen (name);
  tname = (char *) xmalloc (len + 1);
  memcpy (tname, name, len + 1);
  /* Remove a dotted number suffix, from a previous split link. */
  while (len && ISDIGIT (tname[len-1]))
    len--;
  if (len > 1 && tname[len-1] == '.')
    /* It was a dotted number. */
    tname[len-1] = 0;

  /* We want to use the whole of the original section name for the
     split name, but coff can be restricted to 8 character names.  */
  if (bfd_family_coff (abfd) && strlen (tname) > 5)
    {
      /* Some section names cannot be truncated, as the name is
	 used to locate some other section.  */
      if (startswith (name, ".stab")
	  || strcmp (name, "$GDB_SYMBOLS$") == 0)
	{
	  fatal (_ ("%P: cannot create split section name for %s\n"), name);
	  return NULL;
	}
      tname[5] = 0;
    }

  if ((sname = bfd_get_unique_section_name (abfd, tname, count)) == NULL
      || (n = bfd_make_section_anyway (abfd, sname)) == NULL
      || (h = bfd_link_hash_lookup (link_info.hash,
				    sname, true, true, false)) == NULL)
    {
      fatal (_("%P: clone section failed: %E\n"));
      return NULL;
    }
  free (tname);

  /* Set up section symbol.  */
  h->type = bfd_link_hash_defined;
  h->u.def.value = 0;
  h->u.def.section = n;

  n->flags = s->flags;
  n->vma = s->vma;
  n->user_set_vma = s->user_set_vma;
  n->lma = s->lma;
  n->size = 0;
  n->output_offset = s->output_offset;
  n->output_section = n;
  n->orelocation = 0;
  n->reloc_count = 0;
  n->alignment_power = s->alignment_power;

  bfd_copy_private_section_data (abfd, s, abfd, n, NULL);

  return n;
}

#if TESTING
static void
ds (asection *s)
{
  struct bfd_link_order *l = s->map_head.link_order;
  printf ("vma %x size %x\n", s->vma, s->size);
  while (l)
    {
      if (l->type == bfd_indirect_link_order)
	printf ("%8x %s\n", l->offset, l->u.indirect.section->owner->filename);
      else
	printf (_("%8x something else\n"), l->offset);
      l = l->next;
    }
  printf ("\n");
}

dump (char *s, asection *a1, asection *a2)
{
  printf ("%s\n", s);
  ds (a1);
  ds (a2);
}

static void
sanity_check (bfd *abfd)
{
  asection *s;
  for (s = abfd->sections; s; s = s->next)
    {
      struct bfd_link_order *p;
      bfd_vma prev = 0;
      for (p = s->map_head.link_order; p; p = p->next)
	{
	  if (p->offset > 100000)
	    abort ();
	  if (p->offset < prev)
	    abort ();
	  prev = p->offset;
	}
    }
}
#else
#define sanity_check(a)
#define dump(a, b, c)
#endif

static void
split_sections (bfd *abfd, struct bfd_link_info *info)
{
  asection *original_sec;
  int nsecs = abfd->section_count;
  sanity_check (abfd);
  /* Look through all the original sections.  */
  for (original_sec = abfd->sections;
       original_sec && nsecs;
       original_sec = original_sec->next, nsecs--)
    {
      int count = 0;
      unsigned int lines = 0;
      unsigned int relocs = 0;
      bfd_size_type sec_size = 0;
      struct bfd_link_order *l;
      struct bfd_link_order *p;
      bfd_vma vma = original_sec->vma;
      asection *cursor = original_sec;

      /* Count up the relocations and line entries to see if anything
	 would be too big to fit.  Accumulate section size too.  */
      for (l = NULL, p = cursor->map_head.link_order; p != NULL; p = l->next)
	{
	  unsigned int thislines = 0;
	  unsigned int thisrelocs = 0;
	  bfd_size_type thissize = 0;
	  if (p->type == bfd_indirect_link_order)
	    {
	      asection *sec;

	      sec = p->u.indirect.section;

	      if (info->strip == strip_none
		  || info->strip == strip_some)
		thislines = sec->lineno_count;

	      if (bfd_link_relocatable (info))
		thisrelocs = sec->reloc_count;

	      thissize = sec->size;

	    }
	  else if (bfd_link_relocatable (info)
		   && (p->type == bfd_section_reloc_link_order
		       || p->type == bfd_symbol_reloc_link_order))
	    thisrelocs++;

	  if (l != NULL
	      && (thisrelocs + relocs >= config.split_by_reloc
		  || thislines + lines >= config.split_by_reloc
		  || (thissize + sec_size >= config.split_by_file))
	      && !unsplittable_name (cursor->name))
	    {
	      /* Create a new section and put this link order and the
		 following link orders into it.  */
	      bfd_vma shift_offset;
	      asection *n;

	      n = clone_section (abfd, cursor, original_sec->name, &count);

	      /* Attach the link orders to the new section and snip
		 them off from the old section.  */
	      n->map_head.link_order = p;
	      n->map_tail.link_order = cursor->map_tail.link_order;
	      cursor->map_tail.link_order = l;
	      l->next = NULL;
	      l = p;

	      /* Change the size of the original section and
		 update the vma of the new one.  */

	      dump ("before snip", cursor, n);

	      shift_offset = p->offset;
	      n->size = cursor->size - shift_offset;
	      cursor->size = shift_offset;

	      vma += shift_offset;
	      n->lma = n->vma = vma;

	      /* Run down the chain and change the output section to
		 the right one, update the offsets too.  */
	      do
		{
		  p->offset -= shift_offset;
		  if (p->type == bfd_indirect_link_order)
		    {
		      p->u.indirect.section->output_section = n;
		      p->u.indirect.section->output_offset = p->offset;
		    }
		  p = p->next;
		}
	      while (p);

	      dump ("after snip", cursor, n);
	      cursor = n;
	      relocs = thisrelocs;
	      lines = thislines;
	      sec_size = thissize;
	    }
	  else
	    {
	      l = p;
	      relocs += thisrelocs;
	      lines += thislines;
	      sec_size += thissize;
	    }
	}
    }
  sanity_check (abfd);
}

/* Call BFD to write out the linked file.  */

void
ldwrite (void)
{
  /* Reset error indicator, which can typically something like invalid
     format from opening up the .o files.  */
  bfd_set_error (bfd_error_no_error);
  lang_clear_os_map ();
  lang_for_each_statement (build_link_order);

  if (config.split_by_reloc != (unsigned) -1
      || config.split_by_file != (bfd_size_type) -1)
    split_sections (link_info.output_bfd, &link_info);
  if (!bfd_final_link (link_info.output_bfd, &link_info))
    {
      if (bfd_get_error () != bfd_error_no_error)
	fatal (_("%P: final link failed: %E\n"));
      else
	fatal (_("%P: final link failed\n"));
    }
}
