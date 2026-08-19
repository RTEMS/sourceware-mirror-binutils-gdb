/* CTF dict creation.
   Copyright (C) 2019-2025 Free Software Foundation, Inc.

   This file is part of libctf.

   libctf is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 3, or (at your option) any later
   version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#include <ctf-impl.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <elf.h>
#include "ctf-api.h"
#include "ctf.h"
#include "elf-bfd.h"

#include <ctf-util-ref.h>

/* Functions in this file are roughly divided into two types: sizing functions,
   which work out the size of various structures in the final serialized
   representation, and emission functions that actually emit data into them.

   When the sizing functions are called, the buffer into which the output will
   be serialized has not yet been created: so no functions which create
   references into that buffer (notably, ctf_*_add_ref) should be called.

   This requirement is to some degree enforced by ctf_assert calls.  */

/* Symtypetab sections.  */

/* Emit a ref to a type in this dict.  As with string refs, this ref can be
   updated later on to change the type ID recorded in this location.  The ref
   may not be emitted if the value is already known and cannot change.

   All refs must point within the ctf_serialize.cs_buf or the
   ctf_serialize.cs_symtypetab_buf.  */

static ctf_ret_t
ctf_type_add_ref (ctf_dict_t *fp, uint32_t *ref)
{
  ctf_dtdef_t *dtd;

  /* Type in the static portion: cannot change, value already correct.  */
  if (*ref <= fp->ctf_stypes)
    return 0;

  dtd = ctf_dtd_lookup (fp, *ref);

  if (!ctf_assert (fp, dtd))
    return 0;

  if (!ctf_assert (fp, (fp->ctf_serialize.cs_buf != NULL
			&& (unsigned char *) ref > fp->ctf_serialize.cs_buf
			&& (unsigned char *) ref < fp->ctf_serialize.cs_buf
			+ fp->ctf_serialize.cs_buf_size)
		   || (fp->ctf_serialize.cs_symtypetab_buf != NULL
		       && (unsigned char *) ref > fp->ctf_serialize.cs_symtypetab_buf
		       && (unsigned char *) ref < fp->ctf_serialize.cs_symtypetab_buf
		       + fp->ctf_serialize.cs_symtypetab_buf_size)))
    return -1;

  /* Simple case: final ID different from what is recorded, but already known.
     Just set it.  */
  if (dtd->dtd_final_type)
    *ref = dtd->dtd_final_type;
  /* Otherwise, create a ref to it so we can set it later.  */
  else if (!ctf_create_ref (fp, &dtd->dtd_refs, ref))
    return (ctf_set_errno (fp, ENOMEM));

  return 0;
}

/* Purge all refs to this dict's dynamic types (all refs added by
   ctf_type_add_ref while serializing this dict).  */
static void
ctf_type_purge_refs (ctf_dict_t *fp)
{
  ctf_dtdef_t *dtd;

  for (dtd = ctf_list_next (&fp->ctf_dtdefs); dtd != NULL;
       dtd = ctf_list_next (dtd))
    ctf_purge_ref_list (fp, &dtd->dtd_refs);
}

/* Determine if a symbol is "skippable" and should never appear in the
   symtypetab sections.  We skip only symbols which cannot possibly have
   types (even if the linker should somehow provide some) and are not
   platform-dependent.  */

int
ctf_symtab_skippable (ctf_link_sym_t *sym)
{
  /* Never skip symbols whose name is not yet known.  */
  if (sym->st_nameidx_set)
    return 0;

  /* Always skip non-function, non-object symbols.  */
  if (sym->st_type != STT_FUNC && sym->st_type != STT_OBJECT)
    return 1;

  /* Skip symbols with no name and undefined symbols.  */

  return (sym->st_name == NULL || sym->st_name[0] == 0
	  || sym->st_shndx == SHN_UNDEF);
}

/* Contents of the temporary symhash constructed within
   ctf_serialize_emit_symtypetabs.  */
typedef struct ctf_all_symtypes
{
  ctf_dict_t *fp;
  ctf_id_t type;
} ctf_all_symtypes_t;

/* Sort function to sort symtypetab entries into order.  */

static int
symhash_sort (const ctf_next_hkv_t *one, const ctf_next_hkv_t *two,
	      void *unused _libctf_unused_)
{
  ctf_all_symtypes_t *v1 = (ctf_all_symtypes_t *) one->hkv_value;
  ctf_all_symtypes_t *v2 = (ctf_all_symtypes_t *) two->hkv_value;

  if (v1->fp->ctf_new_archive_index < v2->fp->ctf_new_archive_index)
    return -1;
  else if (v1->fp->ctf_new_archive_index > v2->fp->ctf_new_archive_index)
    return 1;

  return strcmp ((const char *) one->hkv_key, (const char *) two->hkv_key);
}

/* Emit symtypetabs for the given archive and put them in the passed in
   ctf_sect_t arguments.  The SYMTYPETABSECT contains a simplified form
   consisting of pure type IDs; the SYMTYPETABALLSECT contains an array of
   ctf_symtypetab_all_ent_t's.  Both arrays is sorted into name order (or,
   for SYMTYPETABALLSECT, member-index-then-name order) if it seems likely
   to be worth doing, but this is not guaranteed: the consumer must be
   prepared for unsorted tables.

   The input archive ARC typically corresponds to linker outputs, but may be
   arbitrary dicts: thus it may already have serialized symbols on it that
   need rescuing and putting into the new archive in the right order.  */

ctf_ret_t
ctf_serialize_emit_symtypetabs (ctf_archive_t *arc, ctf_sect_t *symtypetabsect,
				ctf_sect_t *symtypetaballsect, ctf_error_t *errp)
{
  uint32_t *symtypetab = NULL;
  uint32_t *symtypetabp;
  ctf_symtypetab_all_ent_t *symtypetaball = NULL;
  ctf_symtypetab_all_ent_t *symtypetaballp;

  ctf_dict_t *symfp, *fp;
  ctf_next_t *it = NULL;
  ctf_error_t err;
  ctf_hash_sort_f symhash_sorter;
  ctf_dynhash_t *symhash = NULL;
  const char *name;
  void *k, *v;
  ctf_id_t type;
  ptrdiff_t nsymtypetab = 0, nsymtypetaball = 0;

  /* In case of error, we have no symtypetabs.  */

  symtypetabsect->cts_size = 0;
  symtypetaballsect->cts_size = 0;

  /* The linker always reports symbols against the first dict in the
     archive.  */

  if ((symfp = ctf_dict_open_cached (arc, 0, errp)) == NULL)
    return -1;					/* errno is set for us.  */

  /* Suppress sorting if linking but not filtering out unreported symbols
     (which has already been done for us by the deduplicator).  This case is
     almost certainly an ld -r, and only the linker is likely to consume
     these symtypetabs again.  The linker doesn't care what order the
     symtypetab entries are in, since it only iterates over symbols and does
     not use the ctf_arc_lookup_by_symbol* API.)  */

  symhash_sorter = symhash_sort;
  if (symfp->ctf_flags & LCTF_LINKING
      && symfp->ctf_link_flags & CTF_LINK_NO_FILTER_REPORTED_SYMS)
    symhash_sorter = NULL;

  /* Work over all the symtypes, assemble them into a temporary hash, and
     figure out which goes into which symtypetab.  Only add to this hash if
     not already present: this ensures that newly-added dynamic types take
     precedence over older static ones if two have the same name.  */

  if ((symhash = ctf_dynhash_create (ctf_hash_string, ctf_hash_eq_string,
				     NULL, free)) == NULL)
    {
      *errp = errno;
      goto err;
    }

  while ((fp = ctf_arc_symbol_next (arc, &it, &name, &type, errp)) == 0)
    {
      ctf_all_symtypes_t *symtype;

      if (ctf_dynhash_lookup (symhash, name))
	continue;

      if ((symtype = malloc (sizeof (ctf_all_symtypes_t))) == NULL)
	goto oom;

      symtype->fp = fp;
      symtype->type = type;

      if (ctf_dynhash_insert (symhash, (void *) name, symtype) < 0)
	{
	  *errp = ENOMEM;
	  goto err;
	}

      if (fp == symfp)
	{
	  symtypetabsect->cts_size += sizeof (uint32_t);
	  nsymtypetab++;
	}
      else
	{
	  symtypetaballsect->cts_size += sizeof (ctf_symtypetab_all_ent_t);
	  nsymtypetaball++;
	}
    }
  if (*errp != ECTF_NEXT_END)
    {
      ctf_err (err_locus (NULL), *errp, _("iterating over CTF symtypetab during "
					  "serialization"));
      goto err;
    }

  ctf_dprintf ("Symtypetab: %zi objects, table size %i\n",
	       nsymtypetab, (int)symtypetabsect->cts_size);

  ctf_dprintf ("Child dict symtypetab: %zi objects, table size %i\n",
	       nsymtypetaball, (int) symtypetabsect->cts_size);

  if (nsymtypetab > 0
      && ((symtypetab = calloc (sizeof (*symtypetab), nsymtypetab)) == NULL))
    goto oom;

  if (nsymtypetaball > 0
      && ((symtypetaball = calloc (sizeof (*symtypetaball), nsymtypetaball)) == NULL))
    goto oom;

  symtypetabp = symtypetab;
  symtypetaballp = symtypetaball;

  /* The symtypetab buffer contains refs to the parent dict only, so we can
     set it up here.  The symtypetaball buffers need to be set up whenever a
     type is added to any of them.  */
  if (symtypetab)
    {
      symfp->ctf_serialize.cs_symtypetab_buf = (unsigned char *) symtypetab;
      symfp->ctf_serialize.cs_symtypetab_buf_size = nsymtypetab * sizeof (*symtypetab);
    }

  /* Work over the symbols, in possibly-sorted order, and emit them into
     their destination sections.  */

  while ((err = ctf_dynhash_next_sorted (symhash, &it, &k, &v,
					 symhash_sorter, NULL)) == 0)
    {
      ctf_all_symtypes_t *symtype = (ctf_all_symtypes_t *) v;

      /* Put in the right table.  */
      if (symtype->fp == symfp)
	{
	  if (!ctf_assert (symtype->fp, (symtypetabp - symtypetab) < nsymtypetab))
	    {
	      *errp = ctf_errno (symtype->fp);
	      goto err;				/* errno is set for us.  */
	    }

	  /* Straight array of type IDs.  */
	  *symtypetabp = symtype->type;

	  if (ctf_type_add_ref (symtype->fp, symtypetabp) < 0)
	    {
	      *errp = ctf_errno (symtype->fp);
	      goto err;				/* errno is set for us.  */
	    }

          symtypetabp++;
	}
      else
	{
	  /* Array of (index, ID) pairs.  */

	  if (!ctf_assert (symtype->fp, (symtypetaballp - symtypetaball)
			   < nsymtypetaball))
	    {
	      *errp = ctf_errno (symtype->fp);
	      goto err;				/* errno is set for us.  */
	    }

	  symtypetaballp->sta_archive_member = symtype->fp->ctf_new_archive_index;
	  symtypetaballp->sta_type = symtype->type;

	  symtype->fp->ctf_serialize.cs_symtypetab_buf = (unsigned char *) symtypetaball;
	  symtype->fp->ctf_serialize.cs_symtypetab_buf_size = nsymtypetaball * sizeof (*symtypetaball);

	  if (ctf_type_add_ref (symtype->fp, &symtypetaballp->sta_type) < 0)
	    {
	      *errp = ctf_errno (symtype->fp);
	      goto err;				/* errno is set for us.  */
	    }

	  symtypetaballp++;
	}
    }
  if (*errp != ECTF_NEXT_END)
    {
      ctf_err (err_locus (NULL), *errp, _("iterating over CTF symtypetab during "
					  "serialization"));
      goto err;
    }

  symtypetabsect->cts_data = (unsigned char *) symtypetab;
  symtypetaballsect->cts_data = (unsigned char *) symtypetaball;

  return 0;

 oom:
  *errp = ENOMEM;

 err:
  free (symtypetab);
  free (symtypetaball);
  symfp->ctf_serialize.cs_symtypetab_buf = NULL;

  ctf_next_destroy (it);
  ctf_dynhash_destroy (symhash);
  ctf_dict_close (symfp);
  symtypetabsect->cts_size = 0;
  symtypetaballsect->cts_size = 0;
  return -1;
}

/* Type section.  */

/* Kind suppression.  */

ctf_ret_t
ctf_write_suppress_kind (ctf_dict_t *fp, ctf_kind_t kind, int prohibited)
{
  ctf_dynset_t *set;

  if (kind < CTF_K_UNKNOWN || kind > CTF_K_MAX)
    return (ctf_set_errno (fp, EINVAL));

  if (prohibited)
    set = fp->ctf_write_prohibitions;
  else
    set = fp->ctf_write_suppressions;

  if (!set)
    {
      set = ctf_dynset_create (htab_hash_pointer, htab_eq_pointer, NULL);
      if (!set)
	return (ctf_set_errno (fp, errno));

      if (prohibited)
	fp->ctf_write_prohibitions = set;
      else
	fp->ctf_write_suppressions = set;
    }

  if ((ctf_dynset_cinsert (set, (const void *) (ctf_kind_t) kind)) < 0)
    return (ctf_set_errno (fp, errno));

  fp->ctf_serialize.cs_initialized = 0;

  return 0;
}

/* Figure out whether we can elide a given type prefix as unnecessary.

   Prefixes can be elided iff they are BIG and zero-size and zero-vlen and (if
   structs) the type as a whole is smallifiable.  If not elided, this prefix is
   included.  */
static int
ctf_prefix_elidable (ctf_dict_t *fp, uint32_t kind, ctf_dtdef_t *dtd,
		     ctf_type_t *prefix)
{
  ctf_kind_t prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, prefix->ctt_info);

  if ((prefix_kind == CTF_K_BIG) && prefix->ctt_size == 0
      && LCTF_INFO_UNPREFIXED_VLEN (fp, prefix->ctt_info) == 0)
    {
      ssize_t size;

      if (kind != CTF_K_STRUCT)
	return 1;

      /* For bitfields, we must check if the individual member offsets will
	 still fit if they are encoded as offsets rather than offset-since-last.
	 We can check this for both cases without checking individual fields by
	 looking at the ctt_size.  We need not check for nameless padding
	 members, because these can only be produced at all if the struct would
	 require CTF_K_BIG in the first place.  */

      size = ctf_get_ctt_size (fp, dtd->dtd_buf, NULL, NULL);

      if (CTF_INFO_KFLAG (dtd->dtd_data->ctt_info))
	return (size <= CTF_MAX_BIT_OFFSET);
      else
	return (size <= CTF_MAX_SIZE);
    }
  return 0;
}

/* Determine whether newly-defined or modified types indicate that we will be
   able to emit a BTF type section or must emit a CTF one.  Only called if we
   have already verified that the CTF-specific sections (typetabs, etc) will be
   empty, and that the input dict was freshly-created or read in from BTF.  */

static ctf_ret_t
ctf_type_sect_is_btf (ctf_dict_t *fp, int force_ctf)
{
  ctf_dtdef_t *dtd;
  ctf_next_t *i = NULL;
  ctf_next_t *prohibit_i = NULL;
  void *pkind;
  ctf_error_t err;

  /* Verify prohibitions.  Do this first, for a fast return if a kind is
     prohibited.  */

  if (fp->ctf_write_prohibitions)
    {
      while ((err = ctf_dynset_next (fp->ctf_write_prohibitions,
				     &prohibit_i, &pkind)) == 0)
	{
	  ctf_kind_t kind = (ctf_kind_t) pkind;
	  ctf_id_t type;

	  if ((type = ctf_type_kind_next (fp, &i, kind)) != CTF_ERR)
	    {
	      ctf_next_destroy (i);
	      ctf_next_destroy (prohibit_i);
	      return ctf_err (type_err_locus (fp, type), ECTF_KIND_PROHIBITED,
			    _("kind %i"), kind);
	    }
	}
      if (err != ECTF_NEXT_END)
	{
	  ctf_next_destroy (prohibit_i);
	  return ctf_err (err_locus (fp), err,
			  _("iteration error checking prohibited kinds"));
	}
    }

  /* Prohibitions checked: if the user requested CTF come what may, we know this
     cannot be BTF.  */

  if (force_ctf)
    return 0;

  /* Check all types for invalid-in-BTF features.  */

  for (dtd = ctf_list_next (&fp->ctf_dtdefs);
       dtd != NULL; dtd = ctf_list_next (dtd))
    {
      ctf_type_t *tp = dtd->dtd_buf;
      ctf_kind_t kind = LCTF_KIND (fp, dtd->dtd_buf);
      ctf_kind_t prefix_kind;

      /* Any un-suppressed prefixes other than an empty/redundant CTF_K_BIG must
	 be CTF. (Redundant CTF_K_BIGs will be elided instead.)  */

      while (prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info),
	     LCTF_IS_PREFIXED_KIND (prefix_kind))
	{
	  if (!ctf_prefix_elidable (fp, kind, dtd, tp))
	    if (!fp->ctf_write_suppressions
		|| ctf_dynset_lookup (fp->ctf_write_suppressions,
				      (const void *) (ctf_kind_t) prefix_kind) == NULL)
	      {
		ctf_dprintf ("Type %lx is prefixed with a nonelidable CTF-specific prefix %i: dict is CTF",
			     dtd->dtd_type, kind);
		return 0;
	      }

	  tp++;
	}

      /* Prefixes checked.  If this kind is suppressed, it won't influence the
	 result.  */

      if (fp->ctf_write_suppressions
	  && ctf_dynset_lookup (fp->ctf_write_suppressions,
				(const void *) (ctf_kind_t) kind))
	continue;

      if (kind == CTF_K_FLOAT || kind == CTF_K_SLICE)
	{
	  ctf_dprintf ("Type %lx is kind %i: dict is CTF", dtd->dtd_type, kind);
	  return 0;
	}
    }

  return 1;
}

/* Iterate through the static types and the dynamic type definition list and
   compute the size of the CTF type section.

   This is a sizing function, called before the output buffer is
   constructed.  Do not add any refs in this function!  */

static size_t
ctf_type_sect_size (ctf_dict_t *fp)
{
  ctf_dtdef_t *dtd;
  size_t type_size = 0;

  for (dtd = ctf_list_next (&fp->ctf_dtdefs);
       dtd != NULL; dtd = ctf_list_next (dtd))
    {
      ctf_kind_t kind = LCTF_KIND (fp, dtd->dtd_buf);
      ctf_kind_t prefix_kind;
      ctf_type_t *tp = dtd->dtd_buf;

      /* Check for suppressions: a suppression consumes precisely one ctf_type_t
	 record of space.  A suppressed prefix suppresses the whole type.  */

      if (fp->ctf_write_suppressions)
	{
	  int suppress = 0;

	  while (prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info),
		 LCTF_IS_PREFIXED_KIND (prefix_kind))
	    {
	      if (!ctf_prefix_elidable (fp, kind, dtd, tp)
		  && (ctf_dynset_lookup (fp->ctf_write_suppressions,
					 (const void *) (ctf_kind_t) prefix_kind) != NULL))
		{
		  suppress = 1;
		  break;
		}

	      tp++;
	    }
	  if (ctf_dynset_lookup (fp->ctf_write_suppressions,
				 (const void *) kind) != NULL)
	    suppress = 1;

	  if (suppress)
	    {
	      type_size += sizeof (ctf_type_t);
	      continue;
	    }
	}

      /* Type headers: elide CTF_K_BIG from types if possible.  */

      tp = dtd->dtd_buf;
      while (prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info),
	     LCTF_IS_PREFIXED_KIND (prefix_kind))
	{
	  if (!ctf_prefix_elidable (fp, kind, dtd, tp))
	    type_size += sizeof (ctf_type_t);
	  tp++;
	}
      type_size += sizeof (ctf_type_t);
      type_size += dtd->dtd_vlen_size;
    }

  return type_size + fp->ctf_header->btf.bth_type_len;
}

/* Take a final lap through the dynamic type definition list and copy the
   appropriate type records to the output buffer, noting down the strings
   and type IDs as we go.

   By this stage we no longer need to worry about CTF-versus-BTF, only about
   whether a type has been suppressed or not.  */

static ctf_ret_t
ctf_emit_type_sect (ctf_dict_t *fp, unsigned char **tptr,
		    size_t expected_size)
{
  unsigned char *t = *tptr;
  ctf_dtdef_t *dtd;
  ctf_id_t id;

  id = fp->ctf_stypes + 1;

  if (fp->ctf_flags & LCTF_CHILD)
    id += fp->ctf_parent->ctf_typemax;

  for (dtd = ctf_list_next (&fp->ctf_dtdefs);
       dtd != NULL; dtd = ctf_list_next (dtd), id++)
    {
      ctf_kind_t prefix_kind;
      ctf_kind_t kind = LCTF_KIND (fp, dtd->dtd_buf);
      size_t vlen = LCTF_VLEN (fp, dtd->dtd_buf);
      ctf_type_t *tp = dtd->dtd_buf;
      ctf_type_t *copied;
      const char *name;
      int suppress = 0;
      int big = 0, big_elided = 0;
      size_t i;

      /* Make sure the ID hasn't changed, if already assigned by a previous
	 serialization.  */

      if (dtd->dtd_final_type != 0
	  && !ctf_assert (fp, dtd->dtd_final_type == id))
	return -1;				/* errno is set for us.  */

      /* Suppress everything if this kind is suppressed.  */

      while (prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info),
	     LCTF_IS_PREFIXED_KIND (prefix_kind))
	{
	  /* Don't worry about BIGs that will be elided.  */
	  if (ctf_prefix_elidable (fp, kind, dtd, tp))
	    {
	      tp++;
	      continue;
	    }

	  if (!fp->ctf_write_suppressions
	      || ctf_dynset_lookup (fp->ctf_write_suppressions,
				    (const void *) (ctf_kind_t) prefix_kind) == NULL)
	    {
	      if (_libctf_btf_mode == LIBCTF_BTM_BTF)
		return ctf_err (type_err_locus (fp, id), ECTF_NOTBTF,
				_("attempt to write out CTF-specific kind %i"),
				prefix_kind);
	    }
	  else
	    {
	      suppress = 1;
	      break;
	    }
	  tp++;
	}

      if (fp->ctf_write_suppressions
	  && ctf_dynset_lookup (fp->ctf_write_suppressions,
				(const void *) (ctf_kind_t) kind) != NULL)
	suppress = 1;

      if (suppress)
	{
	  ctf_type_t suppressed = { 0 };

	  if (!ctf_assert (fp, t - *tptr + sizeof (ctf_type_t) <= expected_size))
	    return -1; 				/* errno is set for us.  */

	  suppressed.ctt_info = CTF_TYPE_INFO (CTF_K_UNKNOWN, 0, 0);
	  memcpy (t, &suppressed, sizeof (ctf_type_t));
	  t += sizeof (ctf_type_t);
	  dtd->dtd_final_type = id;

	  continue;
	}

      /* Write out all the type headers, eliding empty CTF_K_BIG, and noting if
	 this type is BIG.  */

      tp = dtd->dtd_buf;
      while (prefix_kind = LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info),
	     LCTF_IS_PREFIXED_KIND (prefix_kind))
	{
	  if (prefix_kind == CTF_K_BIG)
	    {
	      big = 1;

	      if (ctf_prefix_elidable (fp, kind, dtd, tp))
		{
		  big_elided = 1;
		  tp++;
		  continue;
		}
	    }

	  if (!ctf_assert (fp, t - *tptr + sizeof (ctf_type_t) <= expected_size))
	    return -1;				/* errno is set for us.  */

	  memcpy (t, tp, sizeof (ctf_type_t));
	  copied = (ctf_type_t *) t;

	  /* CTF_K_CONFLICTING has a name to keep track of.  */

	  if (copied->ctt_name
	      && (name = ctf_strraw (fp, copied->ctt_name)) != NULL)
	    ctf_str_add_ref (fp, name, &copied->ctt_name);

	  /* No prefixed kinds have any ctt_types to deal with. */

	  tp++;
	  t += sizeof (ctf_type_t);
	}

      if (!ctf_assert (fp, t - *tptr + sizeof (ctf_type_t) <= expected_size))
	return -1; 				/* errno is set for us.  */

      memcpy (t, tp, sizeof (ctf_type_t));
      copied = (ctf_type_t *) t;
      if (copied->ctt_name
	  && (name = ctf_strraw (fp, copied->ctt_name)) != NULL)
        ctf_str_add_ref (fp, name, &copied->ctt_name);
      t += sizeof (ctf_type_t);

      if (!ctf_assert (fp, t - *tptr + dtd->dtd_vlen_size <= expected_size))
	return -1; 				/* errno is set for us.  */

      memcpy (t, dtd->dtd_vlen, dtd->dtd_vlen_size);

      switch (kind)
	{
	case CTF_K_ARRAY:
	  {
	    ctf_array_t *array = (ctf_array_t *) t;

	    if (ctf_type_add_ref (fp, &array->cta_contents) < 0)
	      return -1;			/* errno is set for us.  */

	    if (ctf_type_add_ref (fp, &array->cta_index) < 0)
	      return -1;			/* errno is set for us.  */
	  }
	  break;

	case CTF_K_POINTER:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
	case CTF_K_TYPEDEF:
	case CTF_K_FUNC_LINKAGE:
	case CTF_K_TYPE_TAG:
	case CTF_K_DECL_TAG:
	case CTF_K_VAR:
	  if (ctf_type_add_ref (fp, &copied->ctt_type) < 0)
	    return -1;				/* errno is set for us.  */
	  break;

	/* These kinds have no strings or type IDs in them, and so don't need
	   any special treatment.  */
	case CTF_K_INTEGER:
	case CTF_K_FORWARD:
	case CTF_K_FLOAT:
	case CTF_K_BTF_FLOAT:
	case CTF_K_UNKNOWN:
	  break;

	/* These kinds are prefixes, and cannot appear here.  */
	case CTF_K_BIG:
	case CTF_K_CONFLICTING:
	  ctf_warn (type_err_locus (fp, id), ECTF_INTERNAL,
		    _("prefix type found during serialization: skipped"));
	  break;

	case CTF_K_SLICE:
	  {
	    ctf_slice_t *slice = (ctf_slice_t *) t;

	    if (ctf_type_add_ref (fp, &slice->cts_type) < 0)
	      return -1;			/* errno is set for us. */
	  }

	  break;

	case CTF_K_FUNCTION:
	  {
	    ctf_param_t *args = (ctf_param_t *) t;
	    ctf_param_t *dtd_args = (ctf_param_t *) dtd->dtd_vlen;

	    if (ctf_type_add_ref (fp, &copied->ctt_type) < 0)
	      return -1;			/* errno is set for us.  */

	    for (i = 0; i < vlen; i++)
	      {
		const char *name = ctf_strraw (fp, args[i].cfp_name);

		ctf_str_add_ref (fp, name, &args[i].cfp_name);
		ctf_str_add_ref (fp, name, &dtd_args[i].cfp_name);

		if (ctf_type_add_ref (fp, &args[i].cfp_type) < 0)
		  return -1;			/* errno is set for us.  */
	      }
	    break;
	  }

	  /* These may need all their offsets adjusting.  */
	case CTF_K_STRUCT:
	case CTF_K_UNION:
	  {
	    size_t offset = 0;
	    int bitwise = CTF_INFO_KFLAG (tp->ctt_info);
	    int struct_is_prefixed_big = big;

	    ctf_member_t *memb = (ctf_member_t *) t;
	    ctf_member_t *dtd_memb = (ctf_member_t *) dtd->dtd_vlen;

	    /* All structs and unions in a DTD must always be BIG.  */

	    if (!ctf_assert (fp, struct_is_prefixed_big))
	      return -1;			/* errno is set for us.  */

	    for (i = 0; i < vlen; i++)
	      {
		const char *name = ctf_strraw (fp, memb[i].ctm_name);

		ctf_str_add_ref (fp, name, &memb[i].ctm_name);
		ctf_str_add_ref (fp, name, &dtd_memb[i].ctm_name);

		/* If we are reducing a struct to non-big, we must convert its
		   offsets back to offset-from-start.  */

		if (big_elided && kind == CTF_K_STRUCT)
		  {
		    size_t this_offset, this_size;

		    if (bitwise)
		      {
			this_offset = CTF_MEMBER_BIT_OFFSET (memb[i].ctm_offset);
			this_size = CTF_MEMBER_BIT_SIZE (memb[i].ctm_offset);
			offset += this_offset;
			memb[i].ctm_offset = CTF_MEMBER_MAKE_BIT_OFFSET (this_size,
									 offset);
		      }
		    else
		      {
			offset += memb[i].ctm_offset;
			memb[i].ctm_offset = offset;
		      }
		  }

		if (ctf_type_add_ref (fp, &memb[i].ctm_type) < 0)
		  return -1;			/* errno is set for us.  */
	      }
	  }
	  break;

	case CTF_K_ENUM:
	  {
	    ctf_enum_t *dtd_vlen = (ctf_enum_t *) dtd->dtd_vlen;
	    ctf_enum_t *t_vlen = (ctf_enum_t *) t;

	    for (i = 0; i < vlen; i++)
	      {
		const char *name = ctf_strraw (fp, dtd_vlen[i].cte_name);

		ctf_str_add_ref (fp, name, &dtd_vlen[i].cte_name);
		ctf_str_add_ref (fp, name, &t_vlen[i].cte_name);
	      }

	    break;
	  }

	case CTF_K_ENUM64:
	  {
	    ctf_enum64_t *dtd_vlen = (ctf_enum64_t *) dtd->dtd_vlen;
	    ctf_enum64_t *t_vlen = (ctf_enum64_t *) t;

	    for (i = 0; i < vlen; i++)
	      {
		const char *name = ctf_strraw (fp, dtd_vlen[i].cte_name);

		ctf_str_add_ref (fp, name, &dtd_vlen[i].cte_name);
		ctf_str_add_ref (fp, name, &t_vlen[i].cte_name);
	      }

	    break;
	  }
	case CTF_K_DATASEC:
	  {
	    ctf_var_secinfo_t *sec = (ctf_var_secinfo_t *) t;

	    if (dtd->dtd_flags & DTD_F_UNSORTED)
	      ctf_datasec_sort (fp, dtd);

	    for (i = 0; i < vlen; i++)
	      {
		if (ctf_type_add_ref (fp, &sec[i].cvs_type) < 0)
		  return -1;			/* errno is set for us.  */
	      }
	    break;
	  }
	}

#ifdef ENABLE_LIBCTF_HASH_DEBUGGING
      if (dtd->dtd_type != id)
	ctf_dprintf ("%p: provisional ID assignment: %lx -> %lx\n", (void *) fp,
		     dtd->dtd_type, id);
#endif

      t += dtd->dtd_vlen_size;
      dtd->dtd_final_type = id;
    }

  *tptr = t;

  return 0;
}

/* Overall serialization.  */

/* Determine the output format.  Returns 0 on successful determination or -1 and
   an error if an attempt is being made to write out a CTF dict but the library
   state prohibits it, or a per-dict prohibition is preventing the writeout of a
   type kind that this dict contains.  */

ctf_ret_t
ctf_serialize_output_format (ctf_dict_t *fp, int force_ctf)
{
  int ctf_needed = 0;

  /* If CTF is forced for some other reason, or the global BTF emission mode has
     changed, recheck everything except the expensive type-section scans, which
     are only shortcut by force_ctf, not otherwise changed.  */

  if (fp->ctf_serialize.cs_initialized && !force_ctf
      && fp->ctf_serialize.cs_btf_mode == _libctf_btf_mode)
    return 0;

  /* Complain if we're asked to emit BTF only, but we have types that call for
     CTFv4 extensions, or we are forced to emit CTF because the caller requested
     compression.  */

  if (force_ctf)
    ctf_needed = 1;

  if (ctf_needed && _libctf_btf_mode == LIBCTF_BTM_BTF)
    goto err_not_btf;

  /* Relatively expensive, so done after cheap checks.  If we are called more
     than once, and subsequent calls have force_ctf (above), we can be sure that
     ctf_type_sect_is_btf will return 0 (CTF is needed) on those subsequent
     calls: so we can skip the entire expensive operation then too.  If we
     opened this dict as CTF in the first place, and it had any types in it at
     the time, downgrading is not supported (because we don't check
     already-present static types for CTF-only features), so we can skip the
     check in that (common) case as well.  */

  if (!fp->ctf_serialize.cs_initialized)
    {
      if (!fp->ctf_opened_btf && fp->ctf_stypes > 0)
	ctf_needed = 1;
      else
	switch (ctf_type_sect_is_btf (fp, force_ctf))
	  {
	  case -1: return -1;				/* errno is set for us.  */
	  case 0: ctf_needed = 1;
	  default:;
	  }
    }

  if (ctf_needed && _libctf_btf_mode == LIBCTF_BTM_BTF)
    goto err_not_btf;

  if (_libctf_btf_mode == LIBCTF_BTM_ALWAYS
      || (_libctf_btf_mode == LIBCTF_BTM_POSSIBLE && ctf_needed))
    fp->ctf_serialize.cs_is_btf = 0;
  else
    fp->ctf_serialize.cs_is_btf = 1;

  fp->ctf_serialize.cs_btf_mode = _libctf_btf_mode;
  fp->ctf_serialize.cs_initialized = 1;

  return 0;

 err_not_btf:
  ctf_set_errno (fp, ECTF_NOTBTF);
  /* TODO: a little more info?  */
  if (force_ctf)
    return ctf_err (err_locus (fp), 0, _("compression requested"));
  else
    return ctf_err (err_locus (fp), 0, _("would lose information"));
}

/* Determine whether the output that will be built from a single specific dict
   is compatible with pure BTF or would require CTF.  */

ctf_ret_t
ctf_serialize_output_dict_is_btf (ctf_dict_t *fp)
{
  if (ctf_serialize_output_format (fp, 0) < 0)
    return -1;					     /* errno is set for us.  */

  return fp->ctf_serialize.cs_is_btf;
}

/* Do all aspects of serialization up to strtab writeout, including final type
   ID assignment.  The resulting dict must not be modified in any way before
   serialization.  (This is not enforced, as this feature is internal-only,
   employed by the archive writeout machinery, which does a serialization right
   after preserialization and string dedup.)  */

ctf_ret_t
ctf_preserialize (ctf_dict_t *fp)
{
  ctf_header_t hdr;
  ctf_dtdef_t *dtd;
  size_t hdr_len;
  int ctf_adjustment = 0;
  int force_ctf = 0;

  unsigned char *t;
  size_t buf_size, type_size;
  unsigned char *buf = NULL;

  ctf_dprintf ("Preserializing dict for %s\n", ctf_dict_cuname (fp));

  /* Make sure that any parents have been serialized at least once since the
     last type was added to them, so we have known final IDs for all their
     types.  */

  if (fp->ctf_parent)
    {
      if (fp->ctf_parent->ctf_nprovtypes > 0)
	{
	  ctf_dtdef_t *dtd;

	  dtd = ctf_list_prev (&fp->ctf_parent->ctf_dtdefs);

	  if (dtd && dtd->dtd_final_type == 0)
	    return ctf_err (err_locus (fp), ECTF_NOTSERIALIZED,
			    _("cannot write out child dict: write out the parent dict first"));
	}

      /* Prohibit serialization of a dict which has already been serialized and
	 whose parent has had more types added to it since then: this dict would
	 have overlapping types if serialized, since we only pass through
	 newly-added types to renumber them, not already-existing types in the
	 read-in buffer.  You can emit such dicts using ctf_link, which can
	 change type IDs arbitrarily, resolving all overlaps.  */

      if (fp->ctf_header->btf.bth_str_len > 0 &&
	  fp->ctf_header->cth_parent_ntypes < fp->ctf_parent->ctf_typemax)
	return ctf_err (err_locus (fp), ECTF_NOTSERIALIZED,
			_("cannot write out already-written child dict: parent has had %u types added"),
			fp->ctf_parent->ctf_typemax - fp->ctf_header->cth_parent_ntypes);
    }
  else
    {
      /* Prohibit serialization of a parent dict which has already been
	 serialized, has children, and has had strings added since the last
	 serialization: because we update strtabs in the dict itself, not just
	 the serialized copy, this would cause overlapping strtabs.

	 TODO: lift this restriction.  */

      if (fp->ctf_str[CTF_STRTAB_0].cts_len != 0
	  && fp->ctf_max_children > 0
	  && fp->ctf_str_prov_len != 0)
	return ctf_err (err_locus (fp), ECTF_NOTSERIALIZED,
			_("cannot write out already-written dict with children and newly-added strings"));
    }

  /* Prohibit serialization of a dict that contains alien type kinds.  */
  if (fp->ctf_alien)
    return ctf_err (err_locus (fp), ECTF_CTFVERS,
		    _("cannot serialize BTF containing unknown type kinds"));

  /* Fill in an initial CTF header.  The type section begins at a 4-byte aligned
     boundary past the CTF header itself (at relative offset zero).

     It is quite possible that we will only write out the leading
     ctf_btf_header_t portion of this structure.  */

  memset (&hdr, 0, sizeof (hdr));
  hdr.btf.bth_preamble.btf_magic = CTF_BTF_MAGIC;
  hdr.btf.bth_preamble.btf_version = CTF_BTF_VERSION;
  hdr.btf.bth_preamble.btf_flags = 0;
  hdr.btf.bth_hdr_len = sizeof (ctf_btf_header_t);
  hdr.cth_preamble.ctp_magic_version = (CTFv4_MAGIC << 16) | CTF_VERSION;

  if (ctf_serialize_output_format (fp, force_ctf) < 0)
    return -1;					/* errno is set for us.  */

  type_size = ctf_type_sect_size (fp);

  /* Compute the size of the CTF buffer we need, sans only the string table,
     then allocate a new buffer and memcpy the finished header to the start of
     the buffer.  (We will adjust this later with strtab length info.)

     Offsets in the BTF and CTF headers are relative to the end of te header in
     question.  */

  if (fp->ctf_serialize.cs_is_btf)
    {
      ctf_dprintf ("Writing out as BTF\n");

      hdr_len = sizeof (ctf_btf_header_t);
    }
  else
    {
      ctf_dprintf ("Writing out as CTF\n");

      hdr_len = sizeof (ctf_header_t);
      ctf_adjustment = sizeof (ctf_header_t) - sizeof (ctf_btf_header_t);

      /* Stop unstable file formats (subject to change) getting out into the
	 wild.  */
#if CTF_VERSION != CTF_STABLE_VERSION
      if (!getenv ("I_KNOW_LIBCTF_IS_UNSTABLE"))
	{
	  ctf_set_errno (fp, ECTF_UNSTABLE);
	  goto err;
	}
#endif
    }

  hdr.btf.bth_type_off = 0 + ctf_adjustment;
  hdr.btf.bth_type_len = type_size;
  hdr.btf.bth_str_off = hdr.btf.bth_type_off + type_size;
  hdr.btf.bth_str_len = 0;
  hdr.btf.bth_layout_off = 0;
  hdr.btf.bth_layout_len = 0;
  hdr.cth_parent_strlen = 0;
  if (fp->ctf_parent)
    hdr.cth_parent_ntypes = fp->ctf_parent->ctf_typemax;

  /* No strings yet.  */
  buf_size = sizeof (ctf_btf_header_t) + hdr.btf.bth_str_off;

  if ((buf = malloc (buf_size)) == NULL)
    return (ctf_set_errno (fp, EAGAIN));

  fp->ctf_serialize.cs_buf = buf;
  fp->ctf_serialize.cs_buf_size = buf_size;

  memcpy (buf, &hdr, hdr_len);
  t = (unsigned char *) buf + hdr_len + hdr.btf.bth_type_off;

  if (!fp->ctf_serialize.cs_is_btf)
    {
      ctf_header_t *hdrp = (ctf_header_t *) buf;

      if (fp->ctf_cu_name != NULL)
	ctf_str_add_ref (fp, fp->ctf_cu_name, &hdrp->cth_cu_name);
    }

  /* Copy in existing static types, then emit new dynamic types.  */

  memcpy (t, fp->ctf_buf + fp->ctf_header->btf.bth_type_off,
	  fp->ctf_header->btf.bth_type_len);
  t += fp->ctf_header->btf.bth_type_len;

  if (ctf_emit_type_sect (fp, &t, hdr.btf.bth_str_off
			  - fp->ctf_header->btf.bth_type_len) < 0)
    goto err;

  assert (t == (unsigned char *) buf + sizeof (ctf_btf_header_t)
	  + hdr.btf.bth_str_off);

  /* All types laid out: update all refs to types to cite the final IDs.  */

  for (dtd = ctf_list_next (&fp->ctf_dtdefs);
       dtd != NULL; dtd = ctf_list_next (dtd))
    {
      if (!ctf_assert (fp, dtd->dtd_type != 0 && dtd->dtd_final_type != 0))
	goto err;

      ctf_update_refs (&dtd->dtd_refs, dtd->dtd_final_type);
    }

  ctf_type_purge_refs (fp);

  return 0;

 err:
  fp->ctf_serialize.cs_initialized = 0;
  fp->ctf_serialize.cs_buf = NULL;
  fp->ctf_serialize.cs_buf_size = 0;

  free (buf);
  ctf_str_purge_refs (fp);
  ctf_type_purge_refs (fp);

  return -1;				/* errno is set for us.  */
}

/* Undo preserialization (called on error).  */
void
ctf_depreserialize (ctf_dict_t *fp)
{
  ctf_str_purge_refs (fp);
  ctf_type_purge_refs (fp);

  fp->ctf_serialize.cs_initialized = 0;
  free (fp->ctf_serialize.cs_buf);
  fp->ctf_serialize.cs_buf = NULL;
  fp->ctf_serialize.cs_buf_size = 0;
}

/* Emit a new CTF dict which is a serialized copy of this one: also reify the
   string table and update all offsets in the newly-serialized dict suitably.
   (This simplifies ctf-util-string.c a little, at the cost of storing a second
   copy of the strtab during serialization.)

   Other aspects of the existing dict are unchanged, although some static
   entries may be duplicated in the dynamic state (which should have no effect
   on visible operation).  */

static unsigned char *
ctf_serialize (ctf_dict_t *fp, size_t *bufsiz)
{
  const ctf_strs_writable_t *strtab;
  unsigned char *buf, *newbuf;
  ctf_btf_header_t *hdrp;

  /* Preserialize, if we need to.  */

  if (!fp->ctf_serialize.cs_buf)
    if (ctf_preserialize (fp) < 0)
      return NULL;				/* errno is set for us.  */

  /* Freshly-created parent and child during linking.  Construct the final
     string table and fill out all the string refs with the final offsets.  At
     link time, before the strtab can be constructed, child dicts also need
     their cth_parent_strlen header field updated to match the parent's, since
     the parent's was just updated while its strtab was written out.  (These are
     always newly-created dicts, so we don't need to worry about the
     upgraded-from-v3 case, which must always retain a cth_parent_strlen value
     of 0.)  */

  if ((fp->ctf_flags & LCTF_LINKING) && fp->ctf_parent)
    fp->ctf_header->cth_parent_strlen = fp->ctf_parent->ctf_str[CTF_STRTAB_0].cts_len;

  ctf_dprintf ("Writing strtab for %s\n", ctf_dict_cuname (fp));
  strtab = ctf_str_write_strtab (fp);

  if (strtab == NULL)
    goto err;

  if ((newbuf = realloc (fp->ctf_serialize.cs_buf, fp->ctf_serialize.cs_buf_size
			 + strtab->cts_len)) == NULL)
    goto oom;

  fp->ctf_serialize.cs_buf = newbuf;
  memcpy (fp->ctf_serialize.cs_buf + fp->ctf_serialize.cs_buf_size, strtab->cts_strs,
	  strtab->cts_len);

  hdrp = (ctf_btf_header_t *) fp->ctf_serialize.cs_buf;
  hdrp->bth_str_len = strtab->cts_len;
  fp->ctf_serialize.cs_buf_size += hdrp->bth_str_len;

  /* Update the string length in the real header too, as a flag that
     serialization has happened at least once: this allows us to prevent
     reserializations of parents once the children have been serialized
     (effectively freezing the number of types and strings in the parent at that
     point).  */
  fp->ctf_header->btf.bth_str_len = strtab->cts_len;

  if (!fp->ctf_serialize.cs_is_btf)
    {
      ctf_header_t *ctf_hdrp;

      ctf_hdrp = (ctf_header_t *) (void *) hdrp;
      ctf_hdrp->cth_parent_strlen = fp->ctf_header->cth_parent_strlen;
    }

  *bufsiz = fp->ctf_serialize.cs_buf_size;

  buf = fp->ctf_serialize.cs_buf;

  fp->ctf_serialize.cs_initialized = 0;
  fp->ctf_serialize.cs_buf = NULL;
  fp->ctf_serialize.cs_buf_size = 0;

  return buf;

oom:
  ctf_set_errno (fp, EAGAIN);
err:
  ctf_depreserialize (fp);
  return NULL;					/* errno is set for us.  */
}

/* File writing.  */

/* Serialize and return the specified CTF dictionary as a new dynamically-
   allocated string.  Possibly write it with reversed endianness.  */
unsigned char *
ctf_write_mem (ctf_dict_t *fp, size_t *size)
{
  unsigned char *buf;
  unsigned char *bp;
  ctf_header_t *hp;
  size_t len = 0;
  size_t hdrlen;
  int flip_endian;

  flip_endian = getenv ("LIBCTF_WRITE_FOREIGN_ENDIAN") != NULL;

  if ((buf = ctf_serialize (fp, &len)) == NULL)
    return NULL;				/* errno is set for us.  */

  if (fp->ctf_serialize.cs_is_btf)
    hdrlen = sizeof (ctf_btf_header_t);
  else
    hdrlen = sizeof (ctf_header_t);

  if (!ctf_assert (fp, len >= hdrlen))
    goto err;

  *size = len;

  /* Trivial operation if we're not doing a forced write-time flip.  */

  if (!flip_endian)
    return buf;

  hp = (ctf_header_t *) buf;
  bp = buf + sizeof (ctf_btf_header_t);

  if (ctf_flip_header (hp, 1, fp->ctf_serialize.cs_is_btf, 0) < 0)
    goto err;				/* errno is set for us.  */
  if (ctf_flip (fp, hp, bp, 1) < 0)
    goto err;				/* errno is set for us.  */

  return buf;
err:
  free (buf);
  return NULL;
}

/* Write the given CTF data stream to the specified file descriptor.  */
ctf_ret_t
ctf_write (ctf_dict_t *fp, int fd)
{
  unsigned char *buf;
  unsigned char *bp;
  size_t tmp;
  ssize_t buf_len;
  ssize_t len;
  ctf_ret_t ret = -1;

  if ((buf = ctf_write_mem (fp, &tmp)) == NULL)
    return -1;					/* errno is set for us.  */

  buf_len = tmp;
  bp = buf;

  while (buf_len > 0)
    {
      if ((len = write (fd, bp, buf_len)) < 0)
	{
	  ctf_err (err_locus (fp), errno, NULL);
	  goto ret;
	}
      buf_len -= len;
      bp += len;
    }
  ret = 0;

ret:
  free (buf);
  return ret;
}
