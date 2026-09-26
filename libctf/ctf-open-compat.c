/* Opening CTF files: back-compatibility.
   Copyright (C) 2019-2026 Free Software Foundation, Inc.

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
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <elf.h>
#include "ctf.h"
#include "ctf-util-swap.h"
#include <bfd.h>

/* Much format-dependent stuff is done for us by the ctf_dictops machinery in
   ctf-open, but we still need to do endian-flipping, header management,
   and the actual format conversion explicitly.  */

/* Upgrade CTFv1 and v2 headers to v3, to simplify compat reading code.
   May be in foreign endianness.  */

ctf_header_v3_t *
ctf_compat_upgrade_header_v3 (ctf_header_t *hp)
{
  ctf_header_v2_t *oldhp = (ctf_header_v2_t *) hp;
  ctf_header_v3_t *ret;

  if ((ret = malloc (sizeof (ctf_header_v3_t))) == NULL)
    return NULL;
  memset (&ret, 0, sizeof (ret));

  ret->cth_preamble = oldhp->cth_preamble;
  ret->cth_parlabel = oldhp->cth_parlabel;
  ret->cth_parname = oldhp->cth_parname;
  ret->cth_lbloff = oldhp->cth_lbloff;
  ret->cth_objtoff = oldhp->cth_objtoff;
  ret->cth_funcoff = oldhp->cth_funcoff;
  ret->cth_objtidxoff = oldhp->cth_varoff;	/* Zero-length.  */
  ret->cth_funcidxoff = oldhp->cth_varoff;	/* Zero-length.  */
  ret->cth_varoff = oldhp->cth_varoff;
  ret->cth_typeoff = oldhp->cth_typeoff;
  ret->cth_stroff = oldhp->cth_stroff;
  ret->cth_strlen = oldhp->cth_strlen;

  return ret;
}

/* Endian-flip a v3-or-below header.  */
void
ctf_compat_flip_header_v3 (ctf_header_v3_t *cth)
{
  swap_thing (cth->cth_preamble.ctp_magic);
  swap_thing (cth->cth_preamble.ctp_version);
  swap_thing (cth->cth_preamble.ctp_flags);
  swap_thing (cth->cth_parlabel);
  swap_thing (cth->cth_parname);
  swap_thing (cth->cth_cuname);
  swap_thing (cth->cth_objtoff);
  swap_thing (cth->cth_funcoff);
  swap_thing (cth->cth_objtidxoff);
  swap_thing (cth->cth_funcidxoff);
  swap_thing (cth->cth_varoff);
  swap_thing (cth->cth_typeoff);
  swap_thing (cth->cth_stroff);
  swap_thing (cth->cth_strlen);
}

/* Upgrade the header (already v3) to CTF_VERSION_4.  Only sections that
   exist in v4 are carried over.  The upgraded header is only for the sake
   of shared validation in the opening code: the compat reading code will
   replace the entire dict with a refilled one.  */

ctf_ret_t
ctf_compat_upgrade_header_v4 (ctf_header_t *hp, ctf_header_v3_t *oldhp,
			      ctf_error_t *errp)
{
  if (oldhp->cth_stroff < oldhp->cth_typeoff)
    {
      ctf_err (err_locus (NULL), ECTF_CORRUPT,
	       _("overlapping or misordered CTF type section"));
      ctf_set_open_errno (errp, ECTF_CORRUPT);
      return -1;
    }

  hp->btf.bth_type_off = oldhp->cth_typeoff;
  hp->btf.bth_type_len = oldhp->cth_stroff - oldhp->cth_typeoff;
  hp->btf.bth_str_off = oldhp->cth_stroff;
  hp->btf.bth_str_len = oldhp->cth_strlen;
  hp->cth_cu_name = oldhp->cth_cuname;
  hp->cth_parent_ntypes = 0;
  hp->cth_parent_strlen = 0;		   /* Strings start at offset 0.  */
  return 0;
}

/* Flip the endianness of the v3 type section, a tagged array of ctf_type or
   ctf_stype followed by variable data.  */

static ctf_ret_t
flip_types_v3 (ctf_dict_t *fp, void *start, size_t len, ctf_error_t *errp)
{
  ctf_type_t *tp = start;
  size_t type = 0;
  unsigned char *tend = (unsigned char *) ((uintptr_t) start) + len;

  /* This is a bit tricky.  Many of the functions we call take a ctf_type_t, but
     this is really a ctf_type_v2_t.  */

  while ((unsigned char *) tp < tend)
    {
      ctf_kind_t kind;
      ssize_t size, increment, vbytes;
      uint32_t vlen;
      ctf_type_v2_t *tp_v2 = (ctf_type_v2_t *) tp;
      unsigned char *p = (unsigned char *) tp;
      unsigned char *vp;

      swap_thing (tp_v2->ctt_name);
      swap_thing (tp_v2->ctt_info);
      swap_thing (tp_v2->ctt_size);

      if (_libctf_unlikely_ (tp_v2->ctt_size == CTF_LSIZE_SENT))
	{
	  swap_thing (tp_v2->ctt_lsizehi);
	  swap_thing (tp_v2->ctt_lsizelo);
	}

      kind = CTF_V2_INFO_KIND (tp_v2->ctt_info);
      (void) ctf_get_ctt_size (fp, tp, &size, &increment);
      vbytes = LCTF_VBYTES (fp, tp, size, NULL);
      vlen = LCTF_VLEN (fp, tp);

      if (vbytes < 0)
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("type at index %zi invalid"), type);
	  goto err;
	}

      if (p + increment > tend
	  || p + increment + vbytes > tend)
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("when upgrading, type %zi runs off end"), type);
	  goto err;
	}

      vp = p + increment;

      switch (kind)
	{
	case CTF_V3_K_FORWARD:
	case CTF_V3_K_UNKNOWN:
	case CTF_V3_K_POINTER:
	case CTF_V3_K_TYPEDEF:
	case CTF_V3_K_VOLATILE:
	case CTF_V3_K_CONST:
	case CTF_V3_K_RESTRICT:
	  /* These types have no vlen data to swap.  */
	  assert (vbytes == 0);
	  break;

	case CTF_V3_K_INTEGER:
	case CTF_V3_K_FLOAT:
	  {
	    /* These types have a single uint32_t.  */

	    uint32_t *item = (uint32_t *) vp;

	    swap_thing (*item);
	    break;
	  }

	case CTF_V3_K_FUNCTION:
	  {
	    /* This type has a bunch of uint32_ts.  */

	    uint32_t *item = (uint32_t *) vp;
	    ssize_t i;

	    for (i = vlen; i > 0; item++, i--)
	      swap_thing (*item);
	    break;
	  }

	case CTF_V3_K_ARRAY:
	  {
	    /* This has a single ctf_array_t.  */

	    ctf_array_t *a = (ctf_array_t *) vp;

	    assert (vbytes == sizeof (ctf_array_t));
	    swap_thing (a->cta_contents);
	    swap_thing (a->cta_index);
	    swap_thing (a->cta_nelems);

	    break;
	  }

	case CTF_V3_K_SLICE:
	  {
	    /* This has a single ctf_slice_v3_t.  */

	    ctf_slice_v3_t *s = (ctf_slice_v3_t *) vp;

	    assert (vbytes == sizeof (ctf_slice_v3_t));
	    swap_thing (s->cts_type);
	    swap_thing (s->cts_offset);
	    swap_thing (s->cts_bits);

	    break;
	  }

	case CTF_V3_K_STRUCT:
	case CTF_V3_K_UNION:
	  {
	    /* This has an array of ctf_member_v2 or ctf_lmember_v2, depending
	       on size.  We could consider it to be a simple array of uint32_t,
	       but for safety's sake in case these structures ever acquire
	       non-uint32_t members, do it member by member.  */

	    if (_libctf_unlikely_ (size >= CTF_LSTRUCT_THRESH))
	      {
		ctf_lmember_v2_t *lm = (ctf_lmember_v2_t *) vp;
		ssize_t i;
		for (i = vlen; i > 0; i--, lm++)
		  {
		    swap_thing (lm->ctlm_name);
		    swap_thing (lm->ctlm_offsethi);
		    swap_thing (lm->ctlm_type);
		    swap_thing (lm->ctlm_offsetlo);
		  }
	      }
	    else
	      {
		ctf_member_v2_t *m = (ctf_member_v2_t *) vp;
		ssize_t i;
		for (i = vlen; i > 0; i--, m++)
		  {
		    swap_thing (m->ctm_name);
		    swap_thing (m->ctm_offset);
		    swap_thing (m->ctm_type);
		  }
	      }
	    break;
	  }

	case CTF_V3_K_ENUM:
	  {
	    /* This has an array of ctf_enum_t.  */

	    ctf_enum_t *item = (ctf_enum_t *) vp;
	    ssize_t i;

	    for (i = vlen; i > 0; item++, i--)
	      {
		swap_thing (item->cte_name);
		swap_thing (item->cte_value);
	      }
	    break;
	  }
	default:
	  ctf_err (err_locus (fp), ECTF_CORRUPT,
		   _("unhandled CTF kind in endianness conversion: %x"),
		   kind);
	  goto err;
	}

      tp = (ctf_type_t *) ((uintptr_t) tp + increment + vbytes);
    }

  return 0;

 err:
  ctf_set_open_errno (errp, ECTF_CORRUPT);
  return -1;
}

/* Flip the endianness of the v3 variable section, an array of ctf_varent_t.  */

static void
flip_vars_v3 (void *start, size_t len)
{
  ctf_varent_v3_t *var = start;
  ssize_t i;

  for (i = len / sizeof (ctf_varent_v3_t); i > 0; var++, i--)
    {
      swap_thing (var->ctv_name);
      swap_thing (var->ctv_type);
    }
}

/* Flip the endianness of the data-object or function sections or their indexes,
   all arrays of uint32_t.  */

static void
flip_objts_v3 (void *start, ssize_t len)
{
  uint32_t *obj = start;
  ssize_t i;

  if (len < 0)
    return;

  for (i = len / sizeof (uint32_t); i > 0; obj++, i--)
      swap_thing (*obj);
}

/* Determine if a symbol is "skippable" and should never appear in the
   symtypetab sections.  This includes some Solaris-specific strangeness which
   we cannot drop from v3 because doing so would change the layout of existing
   tables.  */

static int
ctf_symtab_v3_skippable (ctf_link_sym_t *sym)
{
  /* Always skip non-function, non-object symbols.  */
  if (sym->st_type != STT_FUNC && sym->st_type != STT_OBJECT)
    return 1;

  return (sym->st_name == NULL || sym->st_name[0] == 0
	  || sym->st_shndx == SHN_UNDEF
	  || strcmp (sym->st_name, "_START_") == 0
	  || strcmp (sym->st_name, "_END_") == 0
	  || strcmp (sym->st_name, "_DYNAMIC") == 0
	  || strcmp (sym->st_name, "_GLOBAL_OFFSET_TABLE_") == 0
	  || strcmp (sym->st_name, "_PROCEDURE_LINKAGE_TABLE_") == 0
	  || strcmp (sym->st_name, "_edata") == 0
	  || strcmp (sym->st_name, "_end") == 0
	  || strcmp (sym->st_name, "_etext") == 0
	  || (sym->st_type == STT_OBJECT && sym->st_shndx == SHN_ABS
	      && sym->st_value == 0));
}

static ctf_ret_t
ctf_compat_upgrade_one_symtypetab (ctf_dict_t *fp, ctf_dict_t *newfp,
				   uint32_t *tabstart, uint32_t *tabend,
				   uint32_t *idxstart, uint32_t *idxend,
				  int function_tab)
{
  uint32_t *tab = tabstart;
  uint32_t *idx = idxstart;

  /* Indexed: look up name via symtab.  */

  if (idxstart != idxend)
    {
      /* Index not the same length as the symtypetab itself? Corrupt, we never
	 write such a thing.  */
      if (idxend - idxstart != tabend - tabstart)
	{
	  ctf_err (err_locus (fp), ECTF_CORRUPT,
		   "when upgrading length of %s symtypetab %zi != length of index %zi",
		   function_tab ? "function" : "object", tabend - tab, idxend - idx);
	  return -1;
	}

      for (; tab != tabend && idx != idxend; tab++, idx++)
	{
	  const char *name = ctf_strraw (fp, *idx);

	  if (!name)
	    {
	      ctf_warn (err_locus (fp), ECTF_CORRUPT,
			"%s symbol %zi has no name in index\n",
			function_tab ? "function" : "object",
			idx - idxstart);
	      continue;
	    }

	  if (ctf_add_sym (newfp, name, *tab) < 0)
	    ctf_warn (err_locus (fp), ctf_errno (newfp),
		      "cannot add %s symtypetab entry %zi\n",
		      function_tab ? "function" : "object",
		      tab - tabstart);
	}
    }
  else
    {
      /* Unindexed.  Get the symbol names out of the symtab, traversing STT_FUNC
	 / STT_OBJT as appropriate and skipping suitably.  */

      size_t symtypetab_len;
      size_t symidx = 0;
      const ctf_sect_t *sp = &fp->ctf_ext_symsect;

      if (!sp->cts_data)
	{
	  ctf_err (err_locus (fp), ECTF_NOSYMTAB,
		   _("cannot read symtypetab for upgrading"));
	  return -1;				/* errno is set for us.  */
	}

      symtypetab_len = sp->cts_size / sp->cts_entsize;

      for (; tab != tabend; tab++)
	{
	  ctf_link_sym_t sym = {0};

          /* Find the name.  */

	  do
	    {
	      memset (&sym, 0, sizeof (ctf_link_sym_t));
	      if (symidx > symtypetab_len)
		{
		  ctf_err (err_locus (fp), ECTF_CORRUPT,
			   _("symtypetab runs off end of symbol table while upgrading"));
		  return -1;			/* errno is set for us.  */
		}

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
		  return -1;			/* errno is set for us.  */
		}
	      if ((function_tab && sym.st_type != STT_FUNC)
		  || (!function_tab && sym.st_type != STT_OBJECT)
		  || ctf_symtab_v3_skippable (&sym))
		{
		  symidx++;
		  sym.st_name = "";
		  continue;
		}
	      symidx++;
	    }
	  while (sym.st_name[0] == '\0');

	  if (ctf_add_sym (newfp, sym.st_name, *tab) < 0)
	    ctf_warn (err_locus (fp), ctf_errno (newfp),
		      "cannot add %s symtypetab entry %zi\n",
		      function_tab ? "function" : "object",
		      tab - tabstart);
	}
    }

  return 0;
}

/* Upgrade both sets of symtypetabs, by inserting each symbol anew into the
   NEWFP.  */

static ctf_ret_t
ctf_compat_upgrade_symtypetabs (ctf_dict_t *fp, ctf_dict_t *newfp)
{
  ctf_header_v3_t *h3p = fp->ctf_v3_header;
  uint32_t *symtype, *symtypeend, *symidx, *symidxend;

  symtype = (uint32_t *) (fp->ctf_buf + h3p->cth_objtoff);
  symtypeend = (uint32_t *) (fp->ctf_buf + h3p->cth_funcoff);
  symidx = (uint32_t *) (fp->ctf_buf + h3p->cth_objtidxoff);
  symidxend = (uint32_t *) (fp->ctf_buf + h3p->cth_funcidxoff);

  if (ctf_compat_upgrade_one_symtypetab (fp, newfp, symtype, symtypeend,
					 symidx, symidxend, 0) < 0)
    return -1;					/* errno is set for us.  */

  symtype = (uint32_t *) (fp->ctf_buf + h3p->cth_funcoff);
  symtypeend = (uint32_t *) (fp->ctf_buf + h3p->cth_objtidxoff);
  symidx = (uint32_t *) (fp->ctf_buf + h3p->cth_funcidxoff);
  symidxend = (uint32_t *) (fp->ctf_buf + h3p->cth_varoff);

  return ctf_compat_upgrade_one_symtypetab (fp, newfp, symtype, symtypeend,
					    symidx, symidxend, 1);
}

/* State to remember during compat opening about struct fields.  */
typedef struct sou_field
{
  ctf_id_t sou_type;
  const char *name;
  ctf_id_t type;
  size_t offset;
} sou_field_t;

/* Hash an sou_field.  */

static hashval_t
hash_sou_field (const void *p)
{
  const unsigned char *mem = (const unsigned char *) p;
  hashval_t r = 0;
  size_t i;

  for (i = sizeof (sou_field_t); i > 0; i--)
    {
      unsigned char c = *mem++;
      r = r * 67 + c - 113;
    }

  return r;
}

/* An equality function for an sou_field.  */
static int
eq_sou_field (const void *a_, const void *b_)
{
  const sou_field_t *a = (const sou_field_t *) a_;
  const sou_field_t *b = (const sou_field_t *) b_;

  /* These are all strings from the ctf-util-string atom pool, so straight
     pointer equality will work.  */
  return (a->sou_type == b->sou_type)
    && (a->name == b->name)
    && (a->type == b->type)
    && (a->offset == b->offset);
}

/* Upgrade from any earlier version.  */

ctf_dict_t *
ctf_compat_upgrade_types (int version, ctf_dict_t *fp, ctf_header_t *cth,
			  ctf_open_sect_t *sects, ctf_dict_t *parent,
			  ctf_archive_t *ctf_archive,
			  int foreign_endian, ctf_error_t *errp)
{
  ctf_dict_t *newfp = NULL;
  ctf_header_v3_t *h3p = fp->ctf_v3_header;
  unsigned char *tp, *tend;

  ctf_next_t *it = NULL;
  ctf_error_t err;

  /* Lengths for clarity.  */

  ssize_t objt_len = h3p->cth_funcoff - h3p->cth_objtoff;
  ssize_t objtidx_len = h3p->cth_funcidxoff - h3p->cth_objtidxoff;
  ssize_t func_len = h3p->cth_objtidxoff - h3p->cth_funcoff;
  ssize_t funcidx_len = h3p->cth_varoff - h3p->cth_funcidxoff;

  /* We track type IDs and indexes explicitly here, for simplicity.  */

  uint32_t id = 1;
  ctf_id_t type = 1;
  void *k, *v;
  ctf_varent_v3_t *vars;

  /* State to remember about slices, non-root-visible types, and struct/union
     fields.  */

  ctf_dynhash_t *slices = NULL;			/* id -> slices_t.  */
  ctf_dynset_t *struct_fields = NULL;		/* sou_field_t.  */
  ctf_dynset_t *nonroots = NULL;		/* Just a ctf_id_t.  */

  /* v3 needs validation of symtypetab alignments, etc.  */

  if (version == 3)
    {
      if (_libctf_unlikely_ (objtidx_len != 0 && (objtidx_len != objt_len
						 || objtidx_len < 0)))
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("object index section is neither empty nor the "
		     "same length as the object section: %zi versus %zi "
		     "bytes"), objt_len, objtidx_len);
	  return (ctf_set_open_errno (errp, ECTF_CORRUPT));
	}

      /* v3 only needs this invariant if CTF_F_NEWFUNCINFO is set: if it's not, the
	 section is ignored anyway.  */
      if (_libctf_unlikely_ ((funcidx_len != 0) &&
			     ((funcidx_len != func_len) |\
			      (funcidx_len < 0)) &&
			     (h3p->cth_flags & CTF_3_F_NEWFUNCINFO)))
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("function index section is neither empty nor the "
		     "same length as the function section: %zi versus %zi "
		     "bytes"), func_len, funcidx_len);
	  return (ctf_set_open_errno (errp, ECTF_CORRUPT));
	}

      if (_libctf_unlikely_ (h3p->cth_objtoff > fp->ctf_size
			     || h3p->cth_funcoff > fp->ctf_size
			     || h3p->cth_objtidxoff > fp->ctf_size
			     || h3p->cth_funcidxoff > fp->ctf_size
			     || h3p->cth_varoff > fp->ctf_size))
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("header offset or length exceeds CTF size"));
	  return (ctf_set_open_errno (errp, ECTF_CORRUPT));
	}
    }

  if (_libctf_unlikely_ (version < 3
			 && h3p->cth_varoff - h3p->cth_objtoff != 0))
    {
      /* The symtypetabs in these CTF versions can contain function entries
	 which contain embedded CTF info.  We do not support dynamically
	 upgrading such entries (none should exist in any case, since
	 dwarf2ctf does not create them).  */

      ctf_err (err_locus (NULL), ECTF_NOTSUP,
	       "CTF version %d symtypetabs not supported", version);
      return (ctf_set_open_errno (errp, ECTF_NOTSUP));
    }

  /* v3 and below consider dicts children if and only if they have a
     non-NULL parname.  */

  if (h3p->cth_parname == 0)
    parent = NULL;

  /* Flip everything, if needed.  We can't flip v1 dicts: no version of libctf
     ever supported foreign-endian reading of such dicts.  */

  if (foreign_endian)
    {
      if (version == 1)
	{
	  ctf_err (err_locus (NULL), ECTF_NOTYET,
		   _("foreign-endian ancient CTF dicts are not yet supported."));
	  return (ctf_set_open_errno (errp, ECTF_NOTYET));
	}

      if (flip_types_v3 (fp, fp->ctf_buf + cth->btf.bth_type_off,
			 cth->btf.bth_type_len, errp) < 0)
	goto err;

      /* Don't even try to read in symtypetabs for versions < 3.  */
      if (version == 3 && h3p->cth_flags & CTF_3_F_NEWFUNCINFO)
	{
          flip_objts_v3 (fp->ctf_buf + h3p->cth_objtoff, objt_len);
          flip_objts_v3 (fp->ctf_buf + h3p->cth_funcoff, func_len);
          flip_objts_v3 (fp->ctf_buf + h3p->cth_objtidxoff, objtidx_len);
          flip_objts_v3 (fp->ctf_buf + h3p->cth_funcidxoff, funcidx_len);
	}
      flip_vars_v3 (fp->ctf_buf + h3p->cth_varoff,
		    h3p->cth_typeoff - h3p->cth_varoff);
    }

  if ((newfp = ctf_create_internal (parent, fp, sects, ctf_archive,
				    0, errp)) == NULL)
    return NULL;				/* errno is set for us.  */

  /* Make the dict as non-strict as possible while we populate it.  */

  newfp->ctf_flags &= ~LCTF_STRICT_NO_DUP_ENUMERATORS;
  newfp->ctf_flags |= LCTF_NO_NAME_VALIDATION;

  /* Prepare to track info about slices and struct/union fields.  */

  if ((slices = ctf_dynhash_create (ctf_hash_integer, ctf_hash_eq_integer,
				    NULL, free)) == NULL)
    goto oom;

  if ((struct_fields = ctf_dynset_create (hash_sou_field, eq_sou_field,
					  free)) == NULL)
    goto oom;

  if ((nonroots = ctf_dynset_create (ctf_hash_integer,
				     ctf_hash_eq_integer, NULL)) == NULL)
    goto oom;

  /* The starting type ID for child dicts is version-dependent.  We handle
     v4 too, for ease of future upgrades.  */

  if (parent)
    {
      if (version == CTF_VERSION_1 || version == CTF_VERSION_1_UPGRADED_3)
	newfp->ctf_header->cth_parent_ntypes = CTF_MAX_PTYPE_V1;
      else if (version < CTF_VERSION_4)
	newfp->ctf_header->cth_parent_ntypes = CTF_MAX_PTYPE;
      else
	newfp->ctf_header->cth_parent_ntypes = fp->ctf_header->cth_parent_ntypes;

      type = newfp->ctf_header->cth_parent_ntypes + 1;
    }

  /* Pass through the types, upgrading each.  There is a strict 1:1 relationship
     between types in the source and types in the target, so that other dicts
     and external sources referencing types by ID still work.  So little complex
     mapping is needed: it's just a 1:1 read/emission process, though we do need
     to do a bit of late emission of things like non-root markers to avoid the
     extra types that involves in CTFv4 from messing up the alignment.  (This is
     also why the dict has name validation turned off, because thanks to this,
     during the first phase of population, all types are root-visible, even
     duplicates).

     We run through the types only once, but there are multiple rounds of
     emission from data collected at this stage.  */

  tp = fp->ctf_buf + cth->btf.bth_type_off;
  tend = fp->ctf_buf + cth->btf.bth_type_off + cth->btf.bth_type_len;

  for (; tp < tend; id++, type++)
    {
      ctf_type_v1_t *tp_v1 = (ctf_type_v1_t *) tp;
      ctf_type_v2_t *tp_v2 = (ctf_type_v2_t *) tp;
      ctf_type_t *tp_v4 = (ctf_type_t *) tp;
      uint32_t type_info;
      uint32_t ref = 0;
      ctf_id_t newtype;
      size_t vlen = LCTF_VLEN (fp, tp_v4);

      uint32_t kind, nameptr;
      ssize_t size, increment, vbytes;
      int isroot = LCTF_ISROOT (fp, tp_v4);
      int alien;
      const char *name;
      unsigned char *vp;

      /* Figure out everything we can which is both kind- and version-dependent
	 first.  */

      switch (version)
	{
	case CTF_VERSION_1:
	  type_info = tp_v1->ctt_info;
	  nameptr = tp_v1->ctt_name;
	  kind = CTF_V1_INFO_KIND (tp_v1->ctt_info);
	  break;
	case CTF_VERSION_1_UPGRADED_3:
	case CTF_VERSION_2:
	case CTF_VERSION_3:
	  type_info = tp_v2->ctt_info;
	  nameptr = tp_v2->ctt_name;
	  kind = CTF_V2_INFO_KIND (tp_v2->ctt_info);
	  break;
	default:
	  ctf_err (err_locus (NULL), ECTF_NOCTFBUF,
		   _("Header specifies CTF version %i, which is not a valid version"),
		   version);
	  ctf_set_open_errno (errp, ECTF_NOCTFBUF);
	  goto err;
	}

      switch (kind)
	{
	case CTF_V3_K_FUNCTION:
	case CTF_V3_K_FORWARD:
	case CTF_V3_K_TYPEDEF:
	case CTF_V3_K_POINTER:
	case CTF_V3_K_VOLATILE:
	case CTF_V3_K_CONST:
	case CTF_V3_K_RESTRICT:
	  if (version == 1)
	    ref = tp_v1->ctt_type;
	  else
	    ref = tp_v2->ctt_type;
	  break;
	}

      /* This is not expected to ever happen, but if it does, the input was
	 generated by something we don't know about: best to abort.  */

      if (kind != CTF_K_FORWARD && ref > type)
	{
	  ctf_err (err_locus (NULL), ECTF_NOTYET,
		   _("when upgrading, type %zi references type %u, a forward-reference"),
		   type, ref);
	  ctf_set_open_errno (errp, ECTF_NOTYET);
	  goto err;
	}

      kind = LCTF_INFO_UNPREFIXED_KIND (fp, type_info);
      (void) ctf_get_ctt_size (fp, tp_v4, &size, &increment);
      name = ctf_strraw (fp, nameptr);
      vbytes = LCTF_VBYTES (fp, tp_v4, size, &alien);

      if (vbytes < 0)
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("type %zi at index %u invalid"), type, id);
	  ctf_set_open_errno (errp, ECTF_CORRUPT);
	  goto err;
	}

      if (!ctf_assert (fp, !alien))
	{
	  ctf_set_open_errno (errp, ctf_errno (fp));
	  goto err;
	}

      if (((uintptr_t) tp) + increment > (uintptr_t) tend
	  || ((uintptr_t) tp) + increment + vbytes > (uintptr_t) tend)
	{
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("when upgrading, type %zi at index %u runs off end"),
		   type, id);
	  ctf_set_open_errno (errp, ECTF_CORRUPT);
	  goto err;
	}

      if (!isroot &&
	  ctf_dynset_insert (nonroots, (void *) (uintptr_t) type) < 0)
	goto oom;

      vp = tp + increment;

      switch (kind)
	{
	case CTF_V3_K_UNKNOWN:
	  newtype = ctf_add_unknown (newfp, name);
	  break;
	case CTF_V3_K_INTEGER:
	  {
	    uint32_t *vdata = (uint32_t *) vp;
	    ctf_encoding_t en;

	    en.cte_format = CTF_INT_ENCODING (*vdata);
	    en.cte_offset = CTF_INT_OFFSET (*vdata);
	    en.cte_bits = CTF_INT_BITS (*vdata);

	    newtype = ctf_add_integer (newfp, name, &en);
	    break;
	  }
	case CTF_V3_K_FLOAT:
	  {
	    uint32_t *vdata = (uint32_t *) vp;
	    ctf_encoding_t en;

	    en.cte_format = CTF_V3_FP_ENCODING (*vdata);
	    en.cte_offset = CTF_FP_OFFSET (*vdata);
	    en.cte_bits = CTF_FP_BITS (*vdata);

	    /* Some v3 encodings were inherited from Solaris: they were never
	       generated by GCC and their purpose is unclear (maybe compiler
	       extensions).  Strings not translated to avoid wasting
	       translators' time on things this obscure.  */

	    if (en.cte_format > CTF_FP_MAX)
	      {
		ctf_warn (err_locus (NULL), ECTF_NONREPRESENTABLE,
			  "when upgrading, floating-point type %zi at index %u "
			  "uses an obsolete encoding: replaced with a type of kind unknown.",
			  type, id);
		newtype = ctf_add_unknown (newfp, name);
		break;
	      }

	    /* Could insert a slice here, but what's the point? These things
	       never appear.  */

            if (en.cte_offset != 0 || en.cte_bits != 0)
	      {
		ctf_warn (err_locus (NULL), ECTF_NONREPRESENTABLE,
			  "when upgrading, floating-point type %zi at index %u "
			  "is a bitfield: replaced with a type of kind unknown.",
			  type, id);
		newtype = ctf_add_unknown (newfp, name);
		break;
	      }

	    newtype = ctf_add_float (newfp, name, &en);

            break;
	  }
	case CTF_V3_K_POINTER:
	  newtype = ctf_add_pointer (newfp, ref);
	  break;
	case CTF_V3_K_VOLATILE:
	  newtype = ctf_add_qualifier (newfp, CTF_K_VOLATILE, ref);
	  break;
	case CTF_V3_K_CONST:
	  newtype = ctf_add_qualifier (newfp, CTF_K_CONST, ref);
	  break;
	case CTF_V3_K_RESTRICT:
	  newtype = ctf_add_qualifier (newfp, CTF_K_RESTRICT, ref);
	  break;
	case CTF_V3_K_FORWARD:
	  newtype = ctf_add_forward (newfp, name, ref);
	  break;
	case CTF_V3_K_TYPEDEF:
	  newtype = ctf_add_typedef (newfp, name, ref);
	  break;
	case CTF_V3_K_ARRAY:
	  {
	    const ctf_array_v1_t *a1p = (const ctf_array_v1_t *) vp;
	    ctf_array_t *a2p = (ctf_array_t *) vp;
	    ctf_arinfo_t ap;

	    if (version == 1)
	      {
		ap.ctr_contents = a1p->cta_contents;
		ap.ctr_index = a1p->cta_index;
		ap.ctr_nelems = a1p->cta_nelems;
	      }
	    else
	      {
		ap.ctr_contents = a2p->cta_contents;
		ap.ctr_index = a2p->cta_index;
		ap.ctr_nelems = a2p->cta_nelems;
	      }

            newtype = ctf_add_array (newfp, &ap);
	    break;
	  }
	case CTF_V3_K_ENUM:
	  {
	    ctf_encoding_t en = {0};
	    ctf_enum_t *enumerator = (ctf_enum_t *) vp;
	    size_t i;

	    en.cte_format = CTF_INT_SIGNED;	/* Hardwired in v3 and below.  */
            if ((newtype = ctf_add_enum (newfp, name, CTF_K_ENUM, size, &en)) == CTF_ERR)
	      break;

            for (i = vlen; i > 0; i--, enumerator++)
	      {
		const char *enum_name = ctf_strraw (fp, enumerator->cte_name);

                if (ctf_add_enumerator (newfp, newtype, enum_name,
					enumerator->cte_value) < 0)
		  {
		    /* Maybe this should be a warning?  */

                    ctf_err (err_locus (NULL), ctf_errno (newfp),
			     _("when upgrading, adding enumerator %s from type %zi\n"),
			     enum_name ? enum_name : _("(null)"), type);
		    ctf_set_open_errno (errp, ctf_errno (newfp));
		    goto err;
		  }
	      }
	    break;
	  }
	case CTF_V3_K_FUNCTION:
	  {
	    unsigned short *v1args = (unsigned short *) vp;
	    uint32_t *args = (uint32_t *) vp;
	    ctf_id_t *argsarg;
	    size_t i = 0;
	    ctf_func_type_flags_t flags = 0;

	    if ((argsarg = calloc (vlen, sizeof (ctf_id_t))) == NULL)
	      goto oom;

	    if (version == 1)
	      {
		for (i = 0; i < vlen; i++, v1args++)
		  argsarg[i] = *v1args;
	      }
	    else
	      {
		for (i = 0; i < vlen; i++, args++)
		  argsarg[i] = *args;
	      }

            if (argsarg[vlen - 1] == 0)
	      {
		flags |= CTF_FUNC_VARARG;
		vlen--;
	      }

	    newtype = ctf_add_function (newfp, ref, flags, argsarg, NULL, vlen);
	    break;
	  }
	case CTF_V3_K_STRUCT:
	case CTF_V3_K_UNION:
	  {
	    /* For structures and unions we must remember every pertinent detail
	       about every field, for later emission.  */

            size_t i;
	    ctf_kind_t v4kind = (kind == CTF_V3_K_STRUCT) ? CTF_K_STRUCT : CTF_K_UNION;

            const ctf_member_v1_t *m1 = (const ctf_member_v1_t *) vp;
	    const ctf_lmember_v1_t *lm1 = (const ctf_lmember_v1_t *) m1;
	    ctf_member_v2_t *m2 = (ctf_member_v2_t *) vp;
	    ctf_lmember_v2_t *lm2 = (ctf_lmember_v2_t *) m2;

	    /* No structs "contain bitfields" in this sense: bitfields in the
	       form of slices are translated into new base-type bitfields.  */

            newtype = ctf_add_struct (newfp, name, v4kind, 0, size);

            /* Now collect info about every field in the structure, for later
	       emission.  */

	    for (i = 0; i < vlen; i++)
	      {
		sou_field_t *field;
		uint32_t name;

		if ((field = calloc (1, sizeof (sou_field_t))) == NULL)
		  goto oom;

		field->sou_type = type;
                if (version == 1)
		  {
		    if (size < CTF_LSTRUCT_THRESH_V1)
		      {
			name = m1[i].ctm_name;
			field->type = m1[i].ctm_type;
			field->offset = m1[i].ctm_offset;
		      }
		    else
		      {
			name = lm1[i].ctlm_name;
			field->type = lm1[i].ctlm_type;
			field->offset = CTF_V3_LMEM_OFFSET (&lm1[i]);
 		      }
		  }
		else
		  {
		    if (size < CTF_LSTRUCT_THRESH)
		      {
			name = m2[i].ctm_name;
			field->type = m2[i].ctm_type;
			field->offset = m2[i].ctm_offset;
		      }
		    else
		      {
			name = lm2[i].ctlm_name;
			field->type = lm2[i].ctlm_type;
			field->offset = CTF_V3_LMEM_OFFSET (&lm2[i]);
		      }
		  }

		field->name = ctf_strraw (fp, name);
		if (!field->name)
		  field->name = "";

		if (ctf_dynset_insert (struct_fields, field) < 0)
		  {
		    free (field);
		    goto oom;
		  }
	      }
	    break;
	  }
	case CTF_V3_K_SLICE:
	  {
	    /* Remember the details of every slice, for later re-emission as a
	       base-type bitfield; emit a CTF_K_UNKNOWN in its place (to keep
	       type IDs the same).  */

	    ctf_slice_v3_t *slice = (ctf_slice_v3_t *) vp;
	    ctf_slice_v3_t *tmp;

	    if ((tmp = malloc (sizeof (ctf_slice_v3_t))) == NULL)
	      goto oom;

	    memcpy (&tmp, slice, sizeof (ctf_slice_v3_t));

	    if (ctf_dynhash_insert (slices, (void *) (uintptr_t) type, tmp) < 0)
	      {
		free (tmp);
		goto oom;
	      }

	    newtype = ctf_add_unknown (newfp, "");
	    break;
	  }
	default:
	  ctf_err (err_locus (NULL), ECTF_CORRUPT,
		   _("when upgrading, type %zi has unknown kind %i"), type,
		   kind);
	  ctf_set_open_errno (errp, ECTF_CORRUPT);
	  goto err;
	}

      if (newtype == CTF_ERR)
	{
	  ctf_err (err_locus (NULL), ctf_errno (newfp),
		   _("when upgrading, cannot upgrade type %zi"), newtype);
	  ctf_set_open_errno (errp, ctf_errno (newfp));
	  goto err;
	}

      if (!ctf_assert (fp, newtype != type))
	{
	  ctf_err (err_locus (NULL), ECTF_INTERNAL,
		   _("when upgrading, 1:1 type replacement failed: "
		     "old type %zi turned into new type %zi"), type, newtype);
	  ctf_set_open_errno (errp, ECTF_INTERNAL);
	  goto err;
	}

      tp += (uintptr_t) tp + increment + vbytes;
    }

  /* Slices are not supported by CTFv4, so instead are emitted as CTF_K_UNKNOWN
     above, and replaced via the obscure ctf_add_type encoding-replacing variant
     and equally obscure ctf_replace_type mechanism with references to a newly-
     emitted type chain terminating in an old-style bitfield or enums with
     encoding overrides.  The latter have no encoding in CTFv4 (you're supposed
     to use new-style struct bitfields), but that's OK, the user will get an
     error when serializing and can try a ctf_link instead.  */

  /* From this point on, we prefer warnings to errors, because that at least
     means that *most* of the dict is recoverable.  This is not possible above
     this point because failure to insert a type would throw off the 1:1
     correspondence.  */

  while ((err = ctf_dynhash_next (slices, &it, &k, &v)) == 0)
    {
      ctf_id_t original = (ctf_id_t) k;
      ctf_slice_v3_t *slice = (ctf_slice_v3_t *) v;
      ctf_encoding_t en;
      ctf_id_t new;

      en.cte_offset = slice->cts_offset;
      en.cte_bits = slice->cts_bits;

      if ((new = ctf_add_type_encoded (newfp, newfp, slice->cts_type,
				       &en)) == CTF_ERR)
	{
	  ctf_warn (err_locus (NULL), ctf_errno (newfp),
		    "when upgrading, addition of type to replace slice %zi failed",
		    original);
	  goto err;
	}
      else
	if (ctf_replace_type (newfp, original, new) < 0)
	  goto err;
    }
  if (err != ECTF_NEXT_END)
    {
      ctf_err (err_locus (NULL), err,
	       "when upgrading, iteration for slice conversion failed");
      ctf_set_open_errno (errp, err);
      goto err;
    }

  /* Next, emit structure members, which can refer to types later than the
     structure itself so cannot be emitted at the time the structure is
     emitted.  */

  while ((err = ctf_dynset_next (struct_fields, &it, &k)) == 0)
    {
      sou_field_t *sou = (sou_field_t *) k;

      if (ctf_add_member (newfp, sou->sou_type, sou->name, sou->type,
			  sou->offset) < 0)
	ctf_warn (err_locus (NULL), ctf_errno (newfp),
		  _("when upgrading, cannot add struct field %s in struct %zi"),
		  sou->name, sou->sou_type);
    }
  if (err != ECTF_NEXT_END)
    {
      ctf_err (err_locus (NULL), err,
	       "when upgrading, iteration for structure field emission failed");
      ctf_set_open_errno (errp, err);
      goto err;
    }

  /* Now non-root types.  In v4 these are types in themselves, not a flag on a
     type, so we must emit them separately to avoid throwing off the 1:1
     correspondence.  There's no need to refer to them: their mere existence
     makes a type non-root-visible.  */

  while ((err = ctf_dynset_next (nonroots, &it, &k)) == 0)
    {
      ctf_id_t nonroot = (ctf_id_t) k;

      if (ctf_type_set_conflicting (newfp, nonroot, NULL) < 0)
	ctf_warn (err_locus (NULL), ctf_errno (newfp),
		  _("when upgrading, cannot set type %zi as non-root-visible"),
		  nonroot);
    }
  if (err != ECTF_NEXT_END)
    {
      ctf_err (err_locus (NULL), err,
	       "when upgrading, iteration for non-root-visible marking failed");
      ctf_set_open_errno (errp, err);
      goto err;
    }

  /* Now translate the variable section.  We can't be sure what their linkage
     is, but most likely static: non-static vars would be in the symtypetabs.  */

  for (vars = (ctf_varent_v3_t *) fp->ctf_buf + h3p->cth_varoff;
       vars < (ctf_varent_v3_t *) (fp->ctf_buf + h3p->cth_typeoff);
       vars++)
    {
      if (ctf_add_variable (newfp, ctf_strptr (fp, vars->ctv_name),
			    CTF_LINKAGE_STATIC, vars->ctv_type) == CTF_ERR)
	ctf_warn (err_locus (NULL), ctf_errno (newfp),
		  _("when upgrading, cannot add variable %s"),
		  ctf_strptr (fp, vars->ctv_name));
    }

  /* Finally the symtypetabs.  */

  if (version == 3 && (h3p->cth_flags & CTF_3_F_NEWFUNCINFO)
      && ctf_compat_upgrade_symtypetabs (fp, newfp) < 0)
    {
      ctf_set_open_errno (errp, ctf_errno (fp));
      goto err;
    }

  /* Capture any warnings.  */
  ctf_err_copy (newfp, fp);

  ctf_dict_close (fp);

  newfp->ctf_flags &= ~LCTF_NO_NAME_VALIDATION;
  return newfp;

  ctf_dynset_destroy (struct_fields);
  ctf_dynset_destroy (nonroots);
  ctf_dynhash_destroy (slices);

  return 0;

 oom:
  ctf_set_errno (fp, ENOMEM);

 err:
  ctf_dynset_destroy (struct_fields);
  ctf_dynset_destroy (nonroots);
  ctf_dynhash_destroy (slices);

  /* Capture any warnings.  */
  ctf_err_copy (fp, newfp);
  ctf_dict_close (newfp);
  return NULL;
}


