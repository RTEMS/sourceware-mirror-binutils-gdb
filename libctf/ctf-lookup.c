/* Symbol, variable and name lookup.
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

#include "ctf-api.h"
#include <ctf-impl.h>
#include <elf.h>
#include <string.h>
#include <assert.h>

/* Grow the pptrtab so that it is at least NEW_LEN long.  */
static int
grow_pptrtab (ctf_dict_t *fp, size_t new_len)
{
  uint32_t *new_pptrtab;

  if ((new_pptrtab = realloc (fp->ctf_pptrtab, sizeof (uint32_t)
			      * new_len)) == NULL)
    return (ctf_set_errno (fp, ENOMEM));

  fp->ctf_pptrtab = new_pptrtab;

  memset (fp->ctf_pptrtab + fp->ctf_pptrtab_len, 0,
	  sizeof (uint32_t) * (new_len - fp->ctf_pptrtab_len));

  fp->ctf_pptrtab_len = new_len;
  return 0;
}

/* Update entries in the pptrtab that relate to types newly added in the
   child.  */
int
ctf_refresh_pptrtab (ctf_dict_t *fp)
{
  uint32_t i;
  ctf_dict_t *pfp = fp->ctf_parent;

  if (!pfp || fp->ctf_pptrtab_typemax >= fp->ctf_typemax)
    return 0;

  for (i = fp->ctf_pptrtab_typemax; i <= fp->ctf_typemax; i++)
    {
      ctf_id_t type = ctf_index_to_type (fp, i);
      ctf_id_t reffed_type;

      if (ctf_type_kind (fp, type) != CTF_K_POINTER)
	continue;

      reffed_type = ctf_type_reference (fp, type);

      if (ctf_type_isparent (fp, reffed_type))
	{
	  uint32_t idx = ctf_type_to_index (pfp, reffed_type);

	  /* Guard against references to invalid types.  No need to consider
	     the CTF dict corrupt in this case: this pointer just can't be a
	     pointer to any type we know about.  */
	  if (idx <= pfp->ctf_typemax)
	    {
	      if (idx >= fp->ctf_pptrtab_len
		  && grow_pptrtab (fp, pfp->ctf_ptrtab_len) < 0)
		return -1;			/* errno is set for us.  */

	      fp->ctf_pptrtab[idx] = i;
	    }
	}
    }

  fp->ctf_pptrtab_typemax = fp->ctf_typemax;

  return 0;
}

/* Compare the given input string and length against a table of known C storage
   qualifier keywords.  We just ignore these in ctf_lookup_by_name, below.  To
   do this quickly, we use a pre-computed Perfect Hash Function similar to the
   technique originally described in the classic paper:

   R.J. Cichelli, "Minimal Perfect Hash Functions Made Simple",
   Communications of the ACM, Volume 23, Issue 1, January 1980, pp. 17-19.

   For an input string S of length N, we use hash H = S[N - 1] + N - 105, which
   for the current set of qualifiers yields a unique H in the range [0 .. 20].
   The hash can be modified when the keyword set changes as necessary.  We also
   store the length of each keyword and check it prior to the final strcmp().

   TODO: just use gperf.  */

static int
isqualifier (const char *s, size_t len)
{
  static const struct qual
  {
    const char *q_name;
    size_t q_len;
  } qhash[] = {
    {"static", 6}, {"", 0}, {"", 0}, {"", 0},
    {"volatile", 8}, {"", 0}, {"", 0}, {"", 0}, {"", 0},
    {"", 0}, {"auto", 4}, {"extern", 6}, {"", 0}, {"", 0},
    {"", 0}, {"", 0}, {"const", 5}, {"register", 8},
    {"", 0}, {"restrict", 8}, {"_Restrict", 9}
  };

  int h = s[len - 1] + (int) len - 105;
  const struct qual *qp;

  if (h < 0 || (size_t) h >= sizeof (qhash) / sizeof (qhash[0]))
    return 0;

  qp = &qhash[h];

  return ((size_t) len == qp->q_len &&
	  strncmp (qp->q_name, s, qp->q_len) == 0);
}

/* Find a pointer to type by looking in the's ctf_pptrtab (if child is set) and
   fp->ctf_ptrtab.  Return -1 / ECTF_NOTYPE if no type exists.

   Skip lookups if this is a child type and we are looking in the parent (with
   child set), because you cannot have a pointer in the parent to a type in the
   child (an earlier loop checks for pointers to child types).

   There is extra complexity here because uninitialized elements in the pptrtab
   and ptrtab are set to zero, but zero (as the type ID meaning the
   unimplemented type) is a valid return type from ctf_lookup_by_name.
   (Pointers to types are never of type 0, so this is unambiguous, just fiddly
   to deal with.)  */

static ctf_id_t
lookup_ptrtab (ctf_dict_t *fp, ctf_dict_t *child, ctf_id_t type, int *in_child)
{
  ctf_id_t ntype = 0;
  uint32_t idx;

  *in_child = 0;

  /* If we're looking up types in the parent from the perspective of a child,
     don't even try looking if this is a child type: this is done earlier.  */

  if (child && ctf_type_ischild (fp, type))
    return ctf_set_typed_errno (fp, ECTF_NOTYPE);

  idx = ctf_type_to_index (fp, type);
  ntype = CTF_ERR;

  /* Lookup of parent type in child: check pptrtab.  */
  if (child)
    {
      if (idx < child->ctf_pptrtab_len)
	{
	  ntype = child->ctf_pptrtab[idx];
	  if (ntype)
	    *in_child = 1;
	  else
	    ntype = CTF_ERR;
	}
    }
  /* Type, and pointer to it, might still be in the parent: check its ptrtab.  */
  if (ntype == CTF_ERR)
    {
      idx = ctf_type_to_index (fp, type);
      ntype = fp->ctf_ptrtab[idx];

      if (ntype == 0)
	ntype = CTF_ERR;
    }
  if (ntype == CTF_ERR)
    return ctf_set_typed_errno (fp, ECTF_NOTYPE);

  return ntype;
}

/* Attempt to convert the given C type name into the corresponding CTF type ID.
   It is not possible to do complete and proper conversion of type names
   without implementing a more full-fledged parser, which is necessary to
   handle things like types that are function pointers to functions that
   have arguments that are function pointers, and fun stuff like that.
   Instead, this function implements a very simple conversion algorithm that
   finds the things that we actually care about: structs, unions, enums,
   integers, floats, typedefs, and pointers to any of these named types.  */

static ctf_id_t
ctf_lookup_by_name_internal (ctf_dict_t *fp, ctf_dict_t *child,
			     const char *name)
{
  static const char delimiters[] = " \t\n\r\v\f*";

  const ctf_lookup_t *lp;
  const char *p, *q, *end;
  ctf_id_t type = 0;
  ctf_id_t ntype, ptype;

  if (name == NULL)
    return (ctf_set_typed_errno (fp, EINVAL));

  for (p = name, end = name + strlen (name); *p != '\0'; p = q)
    {
      while (isspace ((int) *p))
	p++;			/* Skip leading whitespace.  */

      if (p == end)
	break;

      if ((q = strpbrk (p + 1, delimiters)) == NULL)
	q = end;		/* Compare until end.  */

      if (*p == '*')
	{
	  /* Find a pointer to type by looking in child->ctf_pptrtab (if child
	     is set) and fp->ctf_ptrtab.  If we can't find a pointer to the
	     given type, see if we can compute a pointer to the type resulting
	     from resolving the type down to its base type and use that instead.
	     This helps with cases where the CTF data includes "struct foo *"
	     but not "foo_t *" and the user tries to access "foo_t *" in the
	     debugger.  */

	  int in_child = 0;

	  /* Parent type, not looking in the parent yet?  Do so. */

	  if (!child && fp->ctf_flags & LCTF_CHILD
	      && ctf_type_isparent (fp, type))
	    goto notype;

	  ntype = lookup_ptrtab (fp, child, type, &in_child);

	  /* Try resolving to its base type and check again.  */
	  if (ntype == CTF_ERR && ctf_errno (fp) == ECTF_NOTYPE)
	    {
	      ctf_error_t err;

	      if (child)
		{
		  ntype = ctf_type_resolve_unsliced (child, type);
		  err = ctf_errno (child);
		}
	      else
		{
		  ntype = ctf_type_resolve_unsliced (fp, type);
		  err = ctf_errno (fp);
		}

	      if (ntype == CTF_ERR)
		{
		  if (err == ECTF_BADID)
		    goto notype;
		  else
		    return ctf_set_typed_errno (fp, err);
		}

	      ntype = lookup_ptrtab (fp, child, type, &in_child);
	    }
	  if (ntype == CTF_ERR)
	    {
	      if (ctf_errno (fp) == ECTF_BADID
		  || ctf_errno (fp) == ECTF_NOTYPE)
		goto notype;
	      else
		return -1;			/* errno is set for us.  */
	    }

	  if (in_child)
	    type = ctf_index_to_type (child, ntype);
	  else
	    type = ctf_index_to_type (fp, ntype);

	  /* We are looking up a type in the parent, but the pointed-to type is
	     in the child.  Switch to looking in the child: if we need to go
	     back into the parent, we can recurse again.  */
	  if (in_child)
	    {
	      fp = child;
	      child = NULL;
	    }

	  q = p + 1;
	  continue;
	}

      if (isqualifier (p, (size_t) (q - p)))
	continue;		/* Skip qualifier keyword.  */

      for (lp = fp->ctf_lookups; lp->ctl_prefix != NULL; lp++)
	{
	  /* TODO: This is not MT-safe.  */
	  if ((lp->ctl_prefix[0] == '\0' ||
	       strncmp (p, lp->ctl_prefix, (size_t) (q - p)) == 0) &&
	      (size_t) (q - p) >= lp->ctl_len)
	    {
	      for (p += lp->ctl_len; isspace ((int) *p); p++)
		continue;	/* Skip prefix and next whitespace.  */

	      if ((q = strchr (p, '*')) == NULL)
		q = end;	/* Compare until end.  */

	      while (isspace ((int) q[-1]))
		q--;		/* Exclude trailing whitespace.  */

	      /* Expand and/or allocate storage for a slice of the name, then
		 copy it in.  */

	      if (fp->ctf_tmp_typeslicelen >= (size_t) (q - p) + 1)
		{
		  memcpy (fp->ctf_tmp_typeslice, p, (size_t) (q - p));
		  fp->ctf_tmp_typeslice[(size_t) (q - p)] = '\0';
		}
	      else
		{
		  free (fp->ctf_tmp_typeslice);
		  fp->ctf_tmp_typeslice = xstrndup (p, (size_t) (q - p));
		  if (fp->ctf_tmp_typeslice == NULL)
		    return ctf_set_typed_errno (fp, ENOMEM);
		}

	      if ((type = (ctf_id_t) (uintptr_t)
		   ctf_dynhash_lookup (lp->ctl_hash,
				       fp->ctf_tmp_typeslice)) == 0)
		goto notype;

	      break;
	    }
	}

      if (lp->ctl_prefix == NULL)
	goto notype;
    }

  if (*p != '\0' || type == 0)
    return (ctf_set_typed_errno (fp, ECTF_SYNTAX));

  return type;

 notype:
  ctf_set_errno (fp, ECTF_NOTYPE);
  if (fp->ctf_parent != NULL)
    {
      /* Need to look up in the parent, from the child's perspective.
	 Make sure the pptrtab is up to date.  */

      if (ctf_refresh_pptrtab (fp) < 0)
	return CTF_ERR;				/* errno is set for us.  */

      if ((ptype = ctf_lookup_by_name_internal (fp->ctf_parent, fp,
						name)) != CTF_ERR)
	return ptype;
      return (ctf_set_typed_errno (fp, ctf_errno (fp->ctf_parent)));
    }

  return CTF_ERR;
}

ctf_id_t
ctf_lookup_by_name (ctf_dict_t *fp, const char *name)
{
  return ctf_lookup_by_name_internal (fp, NULL, name);
}

/* Return the pointer to the internal CTF type data corresponding to the given
   type ID.  If the ID is invalid, the function returns NULL.  The type data
   returned is the prefix, if this is a a prefixed kind: if SUFFIX is set, also
   provide the suffix.  If there is no prefix, the SUFFIX is the same as the
   return value.  (See ctf-open.c's dictops for why.)

   This function is not exported outside of the library.  */

const ctf_type_t *
ctf_lookup_by_id (ctf_dict_t **fpp, ctf_id_t type, const ctf_type_t **suffix)
{
  ctf_dict_t *fp = *fpp;
  ctf_id_t idx;

  if ((fp = ctf_get_dict (fp, type)) == NULL)
    {
      (void) ctf_set_errno (*fpp, ECTF_NOPARENT);
      return NULL;
    }

  idx = ctf_type_to_index (fp, type);
  if ((unsigned long) idx > fp->ctf_typemax)
    {
      ctf_set_errno (*fpp, ECTF_BADID);
      return NULL;
    }

  *fpp = fp;		/* Possibly the parent CTF dict.  */
  if (idx > fp->ctf_stypes)
    {
      ctf_dtdef_t *dtd;

      dtd = ctf_dtd_lookup (fp, ctf_index_to_type (fp, idx));

      /* During a rollback, DTD lookup may return NULL for dynamic types that
	 otherwise appear to exist.  */
      if (!dtd)
	{
	  ctf_set_errno (*fpp, ECTF_BADID);
	  return NULL;
	}

      if (suffix)
	*suffix = dtd->dtd_data;
      return dtd->dtd_buf;
    }
  else
    {
      ctf_type_t *tp = fp->ctf_txlate[idx];

      if (suffix)
	{
	  ctf_type_t *suff;

	  suff = tp;
	  while (LCTF_IS_PREFIXED_INFO (suff->ctt_info))
	    suff++;

	  *suffix = suff;
	}
      return tp;
    }
}

/* Find a given prefix in some type, if any.  */
const ctf_type_t *
ctf_find_prefix (ctf_dict_t *fp, const ctf_type_t *tp, ctf_kind_t kind)
{
  ctf_kind_t kind_ = kind;

  while (LCTF_IS_PREFIXED_INFO (tp->ctt_info)
	 && CTF_INFO_KIND (tp->ctt_info) != kind_)
    tp++;

  if (LCTF_INFO_UNPREFIXED_KIND (fp, tp->ctt_info) != kind_)
    return NULL;

  return tp;
}

/* Look up some kind of thing in the name tables.  */

ctf_id_t
ctf_lookup_by_kind (ctf_dict_t *fp, ctf_kind_t kind, const char *name)
{
  ctf_id_t type;

  if (kind == CTF_K_TYPE_TAG || kind == CTF_K_DECL_TAG)
    return ctf_typed_err (err_locus (fp), ECTF_WRONGKIND,
			  _("cannot call this function with a tag kind"));

  if ((type = ctf_dynhash_lookup_type (ctf_name_table (fp, kind),
				       name)) != CTF_ERR)
    return type;

  if (fp->ctf_parent
      && (type = ctf_dynhash_lookup_type (ctf_name_table (fp->ctf_parent, kind),
					  name)) != CTF_ERR)
    return type;

  return ctf_typed_err (err_locus (fp), ECTF_NOTYPE,
			_("type named %s of type %i"), name, kind);
}

/* Look up a single enumerator by enumeration constant name.  Returns the ID of
   the enum it is contained within and optionally its value.  Error out with
   ECTF_DUPLICATE if multiple exist (which can happen in some older dicts).  See
   ctf_lookup_enumerator_next in that case.  Enumeration constants in non-root
   types are not returned, but constants in parents are, if not overridden by
   an enum in the child..  */

ctf_id_t
ctf_lookup_enumerator (ctf_dict_t *fp, const char *name, ctf_enum_value_t *enum_value)
{
  ctf_id_t type;
  ctf_enum_value_t val;

  if (ctf_dynset_lookup (fp->ctf_conflicting_enums, name))
    return (ctf_set_typed_errno (fp, ECTF_DUPLICATE));

  /* CTF_K_UNKNOWN suffices for things like enumeration constants that aren't
     actually types at all (ending up in the global name table).  */
  type = ctf_lookup_by_rawname (fp, CTF_K_UNKNOWN, name);
  /* Nonexistent type? It may be in the parent.  */
  if (type == 0 && fp->ctf_parent)
    {
      if ((type = ctf_lookup_enumerator (fp->ctf_parent, name, enum_value)) == 0)
	return ctf_typed_err (err_locus (fp), ECTF_NONAME, _("enumerator %s"),
			      name);
      return type;
    }

  /* Nothing more to do if this type didn't exist or we don't have to look up
     the enum value.  */
  if (type == 0)
    return ctf_typed_err (err_locus (fp), ECTF_NONAME, _("enumerator %s"),
			  name);

  if (enum_value == NULL)
    return type;

  if (ctf_enum_value (fp, type, name, &val) < 0)
    return CTF_ERR;
  *enum_value = val;

  return type;
}

/* Return all enumeration constants with a given name in a given dict, similar
   to ctf_lookup_enumerator above but capable of returning multiple values.
   Enumerators in parent dictionaries are not returned: enumerators in
   hidden types *are* returned.  */

ctf_id_t
ctf_lookup_enumerator_next (ctf_dict_t *fp, const char *name,
			    ctf_next_t **it, ctf_enum_value_t *valp)
{
  ctf_next_t *i = *it;
  int found = 0;
  ctf_error_t err;

  /* We use ctf_type_next() to iterate across all types, but then traverse each
     enumerator found by hand: traversing enumerators is very easy, and it would
     probably be more confusing to use two nested iterators than to do it this
     way.  We use ctn_next to work over enums, then ctn_en and ctn_n to work
     over enumerators within each enum.  */
  if (!i)
    {
      if ((i = ctf_next_create ()) == NULL)
	return ctf_set_typed_errno (fp, ENOMEM);

      i->cu.ctn_fp = fp;
      i->ctn_iter_fun = (void (*) (void)) ctf_lookup_enumerator_next;
      i->ctn_increment = 0;
      i->ctn_tp = NULL;
      i->u.ctn_en = NULL;
      i->u.ctn_en64 = NULL;
      i->ctn_n = 0;
      *it = i;
    }

  if ((void (*) (void)) ctf_lookup_enumerator_next != i->ctn_iter_fun)
    {
      err = ECTF_NEXT_WRONGFUN;
      goto end;
    }

  if (fp != i->cu.ctn_fp)
    {
      err = ECTF_NEXT_WRONGFP;
      goto end;
    }

  do
    {
      const char *this_name;
      int is_enum64 = 0;

      /* At end of enum? Traverse to next one, if any are left.  */

      if ((i->u.ctn_en == NULL && i->u.ctn_en64 == NULL) || i->ctn_n == 0)
	{
	  const ctf_type_t *tp;
	  ctf_dtdef_t *dtd;
	  ctf_kind_t kind;
	  unsigned char *vlen;

	  /* It's a shame we can't use ctf_type_kind_next here, but we're
	     looking for two type kinds at once...  */
	  do
	    i->i.ctn_type = ctf_type_next (i->cu.ctn_fp, &i->ctn_next, NULL, 1);
	  while (i->i.ctn_type != CTF_ERR
		 && ((kind = ctf_type_kind_unsliced (i->cu.ctn_fp, i->i.ctn_type))
		     != CTF_K_ENUM && kind != CTF_K_ENUM64));

	  if (i->i.ctn_type == CTF_ERR)
	    {
	      /* Conveniently, when the iterator over all types is done, so is the
		 iteration as a whole: so we can just pass all errors from the
		 internal iterator straight back out..  */
	      err = ctf_errno (fp);
	      goto end;
	    }

	  if ((tp = ctf_lookup_by_id (&fp, i->i.ctn_type, &i->ctn_tp)) == NULL)
	    {
	      err = ctf_errno (fp);
	      goto end;
	    }
	  i->ctn_n = LCTF_VLEN (fp, tp);

	  if ((dtd = ctf_dynamic_type (fp, i->i.ctn_type)) != NULL)
	    vlen = dtd->dtd_vlen;
	  else
	    {
	      ctf_get_ctt_size (fp, tp, NULL, &i->ctn_increment);
	      vlen = (unsigned char *) ((uintptr_t) tp + i->ctn_increment);
	    }

	  if (kind == CTF_K_ENUM)
	    i->u.ctn_en = (const ctf_enum_t *) vlen;
	  else
	    i->u.ctn_en64 = (const ctf_enum64_t *) vlen;
	}

      if (LCTF_KIND (fp, i->ctn_tp) == CTF_K_ENUM64)
	is_enum64 = 1;

      /* ctf_enum_t and ctf_enum64_t have the name in common, and ctn_en and
	 ctn_en64 are in a union.  */
      this_name = ctf_strptr (fp, i->u.ctn_en->cte_name);

      i->ctn_n--;

      if (strcmp (name, this_name) == 0)
	{
	  if (valp)
	    {
	      ctf_enum_value_t val;

	      if (ctf_enum_value (fp, i->i.ctn_type, this_name, &val) < 0)
		{
		  err = ctf_errno (fp);
		  goto end;
		}
	      *valp = val;
	    }
	  found = 1;

	  /* Constant found in this enum: try the next one.  (Constant names
	     cannot be duplicated within a given enum.)  */

	  i->ctn_n = 0;
	}

      if (is_enum64)
	i->u.ctn_en64++;
      else
	i->u.ctn_en++;
    }
  while (!found);

  return i->i.ctn_type;

 end:
  ctf_set_errno (fp, err);
  ctf_next_destroy (i);
  *it = NULL;
  return CTF_ERR;
}

static int
qsort_symtypetab (const void *one_, const void *two_)
{
  const ctf_symtypetab_all_named_ent_t *one = one_;
  const ctf_symtypetab_all_named_ent_t *two = two_;

  if (one->sta_archive_member < two->sta_archive_member)
    return -1;
  else if (one->sta_archive_member > two->sta_archive_member)
    return 1;

  return (strcmp (one->sta_name, two->sta_name));
}

/* Sort the ctf_symtypetab by name, and populate its name caches from the
   underlying dictionaries.  The array is only sorted if necessary (but is
   populated with names regardless).  Only called once for any given
   table.  */

static ctf_error_t
ctf_symidx_populate_sort (ctf_archive_t *arc)
{
  size_t i;
  int needs_sort = 0;
  ctf_error_t err;
  ctf_symtypetab_all_named_ent_t *ent, *last = NULL;

  /* Populate with names (opening everything necessary), and determine if
     sorted.  */

  for (i = 0; i < arc->ctfi_symtypetab_len; i++)
    {
      ctf_dict_t *fp;
      const char *str;

      ent = &arc->ctfi_symtypetab[i];
      fp = ctf_dict_open_cached (arc, ent->sta_archive_member,
				 &err);

      if (!fp)
	{
	  ctf_err (err_locus (NULL), err,
		   _("when sorting archive symtypetabs, entry %zi references archive member %u"),
		   i, ent->sta_archive_member);
	  return err;
	}

      if ((str = ctf_type_name_raw (fp, ent->sta_type)) == NULL)
	{
	  ctf_err (err_locus (NULL), ctf_errno (fp),
		   _("when sorting archive symtypetabs, error getting name of type %zi in member %zi, referenced by entry %u"),
		   ent->sta_type, i, ent->sta_archive_member);
	  err = ctf_errno (fp);
	  ctf_dict_close (fp);
	  return err;
	}

      /* Name population.  str will live as long as the archive.  */
      ent->sta_name = str;

      if (last && (last->sta_archive_member > ent->sta_archive_member
		   || (strcmp (last->sta_name, str) > 0)))
	needs_sort = 1;
      last = ent;
    }

  if (needs_sort)
    {
      ctf_dprintf ("Symtypetab unsorted: sorting.\n");
      qsort (arc->ctfi_symtypetab, arc->ctfi_symtypetab_len,
	     sizeof (ctf_symtypetab_all_named_ent_t),
	     qsort_symtypetab);
    }

  arc->ctfi_flags |= CTFA_F_SYMTYPES_POPULATED;
  return 0;
}

/* Given a symbol index, return the name of that symbol from the table
   provided by ctf_link_shuffle_syms, or failing that from the secondary
   string table, or the null string.

   Returns the null string on error, not NULL.  */

static const char *
ctf_arc_lookup_symbol_info (ctf_archive_t *arc, unsigned long symidx,
			    ctf_error_t *errp)
{
  const ctf_sect_t *sp = &arc->ctfi_symsect;
  ctf_dict_t *fp;
  ctf_link_sym_t sym;
  ctf_error_t err;

  /* The shuffled dynsymidx, if set, is always on the first dict in an
     archive (but is rarely set on archives at all).  Having no index 0 is
     in theory fine, if strange: we can still look up names in the ELF
     symbol table itself.  There simply cannot be a dynsymidx.  However, for
     now, we mandate at least one dict, because it makes it easier to
     support ELF strtab lookup later.  */

  fp = ctf_dict_open_cached (arc, 0, errp);

  if (fp == NULL)
    return NULL;				/* errno is set for us.  */

  if (fp->ctf_dynsymidx)
    {
      err = EINVAL;
      if (symidx <= fp->ctf_dynsymmax)
	{
	  ctf_link_sym_t *symp = fp->ctf_dynsymidx[symidx];

	  if (symp)
	    return symp->st_name;
	}
    }

  err = ECTF_NOTYPEDAT;

  if ((size_t) symidx >= arc->ctfi_symtypetab_len)
    goto err;

  switch (sp->cts_entsize)
    {
    case sizeof (Elf64_Sym):
      {
	const Elf64_Sym *symp = (Elf64_Sym *) sp->cts_data + symidx;
	ctf_elf64_to_link_sym (fp, &sym, symp, symidx);
      }
      break;
    case sizeof (Elf32_Sym):
      {
	const Elf32_Sym *symp = (Elf32_Sym *) sp->cts_data + symidx;
	ctf_elf32_to_link_sym (fp, &sym, symp, symidx);
      }
      break;
    default:
      ctf_err (err_locus (fp), 0, _("when looking up symbols, symtab entries of unexpected size: %zi"),
	       sp->cts_entsize);
      err = ECTF_NOSYMTAB;
      goto err;
    }

  assert (!sym.st_nameidx_set);

  return sym.st_name;

 err:
  *errp = err;
  ctf_dict_close (fp);
  return "";
}

/* Iterate over all symbols with types.  The name, type, and errp arguments
   are not optional.  The return order is arbitrary, though is likely to be
   in symbol index or name order within each dict.  Adding symbols while
   iteration is underway may also lead to other symbols being skipped.

   If symbols were already present in the dict when opened and replacements
   were subsequently added via ctf_add_sym, both will be returned, the
   newly-added ones first.

   As usual with ctf_arc_*() functions, the dict refcnt is bumped with every
   symbol returned: the caller must ctf_close it.

   Takes the internal symtypetab (ctfi_symtypetab, or ctf_symtypetab_all)
   to iterate over, and allow filtering down dynamic symbol lookups to one
   dict.  */

static ctf_dict_t *
ctf_arc_symbol_tab_next (ctf_archive_t *arc, ctf_dict_t *one_dict,
			 ctf_symtypetab_all_named_ent_t *tab,
			 size_t tab_len, ctf_next_t **it, const char **name,
			 ctf_id_t *type, ctf_error_t *errp)
{
  ctf_next_t *i = *it;
  ctf_dict_t *fp;

  if (!i)
    {
      if ((i = ctf_next_create ()) == NULL)
	{
	  *errp = ENOMEM;
	  return NULL;
	}

      i->cu.ctn_arc = arc;
      i->ctn_iter_fun = (void (*) (void)) ctf_arc_symbol_next;
      i->u.ctn_fp = one_dict;
      i->ctn_n = 0;
      i->ctn_next = NULL;
      i->ctn_next_inner = NULL;
      *it = i;
    }

  if ((void (*) (void)) ctf_arc_symbol_next != i->ctn_iter_fun)
    {
      *errp = ECTF_NEXT_WRONGFUN;
      goto end;
    }

  /* The only caller of this function with a non-NULL one_dict arg will
     never change it, and will error out itself if its caller does so.  */

  if (arc != i->cu.ctn_arc || (one_dict != NULL && one_dict != i->u.ctn_fp))
    {
      *errp = ECTF_NEXT_WRONGFP;
      goto end;
    }

  /* This iterator is two-phase.  In the first phase, ctn_next works over
     dicts while ctn_next_inner works over the members of the ctf_dynsymidx
     within each dict. In the second phase, handled by
     ctf_arc_symbol_next_static, ctn_n tracks the index within the
     ctfi_symtypetab.  */

  /* First phase, detected by seeing whether the second phase has started
     yet.  */

  if (i->ctn_n == 0)
    {
      /* Check the dynamic set of names first, to allow previously-written
	 names to be replaced with dynamic ones (there is still no way to
	 remove them, though).

	 We intentionally use raw access, not ctf_lookup_by_symbol, to avoid
	 incurring additional sorting cost for unsorted symtypetabs coming
	 from the compiler, to allow ctf_symbol_next to work in the absence
	 of a symtab, and finally because it's easier to work out what the
	 name of each symbol is if we do that.  */

      do
	{
	  if (i->ctn_next)
	    {
	      void *dyn_name = NULL, *dyn_value = NULL;
	      ctf_error_t err;

	      err = ctf_dynhash_next (i->u.ctn_fp->ctf_symtypehash,
				      &i->ctn_next_inner, &dyn_name, &dyn_value);

	      if (err == 0)
		{
		  *name = dyn_name;
		  *type = (ctf_id_t) (uintptr_t) dyn_value;
		  i->u.ctn_fp->ctf_refcnt++;
		  return i->u.ctn_fp;
		}

	      if (err != ECTF_NEXT_END)
		{
		  *errp = err;
		  goto end;
		}
	    }

	  /* That's it, if we're filtering to only one dict.  */

	  if (one_dict)
	    break;

	  /* Next dict.  */

	  ctf_dict_close (i->u.ctn_fp);
	  i->u.ctn_fp = ctf_archive_next (i->cu.ctn_arc, &i->ctn_next, NULL, 0, errp);

	  if (*errp != 0 && *errp != ECTF_NEXT_END)
	    goto end;

	} while (errp == 0);
    }

  /* Second phase: static types.  There might be no static table at all, if
     all types are dynamic (e.g. if this is a dict that has not yet been
     written out as an archive.)  */

  if (!tab)
    {
      *errp = ECTF_NEXT_END;
      return NULL;
    }

  do
    {
      if (i->ctn_n >= tab_len)
	{
	  *errp = ECTF_NEXT_END;
	  goto end;
	}

      /* If we're returning results from only one dict, skip until we find
	 it.  */

      if (one_dict && (((size_t) tab[i->ctn_n].sta_archive_member)
		       != one_dict->ctf_archive_index))
	{
	  i->ctn_n++;
	  continue;
	}

      /* The names may not yet be cached: cache them as we go.  */

      fp = ctf_dict_open_cached ((ctf_archive_t *) i->cu.ctn_arc,
				 tab[i->ctn_n].sta_archive_member, errp);
      if (!fp)
	goto end;					/* *errp is set for us.  */


      if ((tab[i->ctn_n].sta_name = ctf_type_name_raw (fp, tab[i->ctn_n].sta_type)) == NULL)
	{
	  *errp = ctf_errno (fp);
	  goto end;
	}

      *name = tab[i->ctn_n].sta_name;
      *type = tab[i->ctn_n].sta_type;
      i->ctn_n++;

      if (*type != CTF_ERR)
	return fp;
    } while (0);

 end:
  ctf_next_destroy (i);
  *it = NULL;
  return NULL;
}

/* Public entry point: ctf_arc_symbol_tab_next on the total set of symbols.  */
ctf_dict_t *
ctf_arc_symbol_next (ctf_archive_t *arc, ctf_next_t **it, const char **name,
		     ctf_id_t *type, ctf_error_t *errp)
{
  return ctf_arc_symbol_tab_next (arc, NULL, arc->ctfi_symtypetab,
				  arc->ctfi_symtypetab_len, it, name, type,
				  errp);
}

/* Traverse all symbols in a dict, one by one, and return the type of each
   and (if NAME is non-NULL) optionally its name.  Internally,
   ctf_arc_symbol_tab_next but restricted to only one dict.  */

ctf_id_t
ctf_symbol_next (ctf_dict_t *fp, ctf_next_t **it, const char **name)
{
  ctf_archive_t *arc;
  ctf_error_t err;
  ctf_symtypetab_all_named_ent_t *tab;
  size_t tab_len;
  ctf_dict_t *tmp;
  ctf_id_t type;

  if (fp == NULL || (*it && (*it)->u.ctn_fp != fp))
    {
      ctf_next_destroy (*it);
      *it = NULL;
      return ctf_set_typed_errno (fp, ECTF_NEXT_WRONGFP);
    }

  if ((arc = ctf_dict_arc (fp, 0)) == NULL)
    {
      ctf_next_destroy (*it);
      return -1;				/* errno is set for us.  */
    }

  if (fp->ctf_archive_index == 0)
    {
      tab = arc->ctfi_symtypetab;
      tab_len = arc->ctfi_symtypetab_len;
    }
  else
    {
      tab = arc->ctfi_symtypetab_all;
      tab_len = arc->ctfi_symtypetab_all_len;
    }

  tmp = ctf_arc_symbol_tab_next (arc, fp, tab, tab_len, it, name,
				 &type, &err);

  ctf_dict_close (tmp);
  ctf_arc_close (arc);

  if (err != 0)
    {
      ctf_set_errno (fp, err);
      return -1;
    }
  return type;
}

/* A bsearch function for symtypetab symbol names.  */

static int
ctf_lookup_idx_name (const void *key, const void *ent_)
{
  const char *name = (const char *) key;
  const ctf_symtypetab_all_named_ent_t *ent = ent_;

  return (strcmp (name, ent->sta_name));
}

/* Given a symbol name, return the type of the function or data object described
   by the corresponding entry in the symbol table.  */

ctf_dict_t *
ctf_arc_lookup_symbol_name (ctf_archive_t *arc, const char *name,
			    ctf_id_t *type, ctf_error_t *errp)
{
  ctf_dict_t *fp;

  if (!name || name[0] == '\0')
    {
      *errp = ECTF_NOTYPEDAT;
      return NULL;
    }

  ctf_dprintf ("Looking up type of symbol with name %s in symtypetab\n", name);

  /* Check for a dynamic sym first.  If there are no dicts in this archive,
     there's no need to do that.  */

  fp = ctf_dict_open_cached (arc, 0, errp);

  if (fp == NULL && *errp != ECTF_ARNNAME)
    return NULL;				/* errp is set for us. */
  else if (fp != NULL
	   && (fp->ctf_symtypehash != NULL
	       && ((*type = (ctf_id_t) (uintptr_t)
		    ctf_dynhash_lookup (fp->ctf_symtypehash, name)) != 0)))
    return fp;

  ctf_dict_close (fp);

  if (!(arc->ctfi_flags & CTFA_F_SYMTYPES_POPULATED))
    {
      if ((*errp = ctf_symidx_populate_sort (arc) < 0))
	{
	  ctf_err (err_locus (NULL), 0, _("cannot sort symtypetabs"));
	  return NULL;
	}
    }

  ctf_symtypetab_all_named_ent_t *idx;

  idx = bsearch (name, arc->ctfi_symtypetab, arc->ctfi_symtypetab_len,
		 sizeof (ctf_symtypetab_all_named_ent_t), ctf_lookup_idx_name);

  if (!idx)
    {
      *errp = ECTF_NOTYPEDAT;
      ctf_dprintf ("%s not found in idx\n", name);
      return NULL;
    }

  /* Should be impossible, but be paranoid.  */
  if ((idx - arc->ctfi_symtypetab) > (ptrdiff_t) arc->ctfi_symtypetab_len)
    {
      *errp = ECTF_CORRUPT;
      return NULL;
    }

  fp = ctf_dict_open_cached (arc, idx->sta_archive_member, errp);
  if (fp == NULL)
    return NULL;				/* errp is set for us. */

  ctf_dprintf ("Symbol %s is of type %lx in archive member %x\n", name, idx->sta_type,
	       idx->sta_archive_member);
  *type = idx->sta_type;
  return fp;
}

/* Given a symbol table index, return the type of the function or data object
   described by the corresponding entry in the symbol table.  */
ctf_dict_t *
ctf_arc_lookup_symbol (ctf_archive_t *arc, unsigned long symidx, ctf_id_t *type,
		       ctf_error_t *errp)
{
  const char *name;

  *errp = 0;
  name = ctf_arc_lookup_symbol_info (arc, symidx, errp);

  if (*errp != 0)
    return NULL;				/* errno is set for us.  */

  return ctf_arc_lookup_symbol_name (arc, name, type, errp);
}

