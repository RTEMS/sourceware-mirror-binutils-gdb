/* CTF archive files.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include "ctf-endian.h"
#include "swap.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

/* Note on datatypes: the datatype known outside this file as ctf_archive_t
   is here known as struct ctf_archive_internal, to emphasise its role as a
   wrapper with no on-disk representation.

   The on-disk structure is struct ctf_archive.  */

static ctf_ret_t arc_write_one_ctf (ctf_dict_t *fp, int fd, size_t threshold);
static ctf_ret_t ctf_arc_flip_v1_modents (ctf_archive_v1_modent_t *modent, uint64_t els,
					  unsigned char *ents, uint64_t base,
					  size_t arc_len, ctf_error_t *errp);
static ctf_ret_t ctf_arc_range_check_v1_hdr (struct ctf_archive_internal *arci,
					     size_t arc_len,
					     ctf_archive_v1_modent_t *modent,
					     ctf_error_t *errp);
static int ctf_arc_range_check_v1_modents (ctf_archive_v1_modent_t *modent,
					   struct ctf_archive_v1 *arc_hdr,
					   unsigned char *arc_bytes,
					   uint64_t contents_base,
					   size_t contents_els, size_t arc_len,
					   ctf_error_t *errp);
static void *arc_mmap_file (int fd, size_t size);
static int arc_mmap_unmap (void *header, size_t headersz, const char **errmsg);
static void *arc_pread_file (int fd, size_t size);
static int ctf_arc_import_parent (const struct ctf_archive_internal *arci,
				  ctf_dict_t *fp, ctf_error_t *errp);

/* Flag to indicate "symbol not present" in ctf_archive_internal.ctfi_symdicts
   and ctfi_symnamedicts.  Never initialized.  */
static ctf_dict_t enosym;

/* Prepare to serialize everything.  Members of archives have dependencies on
   each other, because the strtabs and type IDs of children depend on the
   parent: so we have to work over the archive as a whole to prepare for final
   serialization.

   Returns zero on success, or an errno, or an ECTF_* value.

   Updates the first dict in the archive with the errno value.  */

static ctf_error_t
ctf_arc_preserialize (ctf_dict_t **ctf_dicts, ssize_t ctf_dict_cnt,
		      size_t threshold)
{
  uint64_t old_parent_strlen, all_strlens = 0;
  ssize_t i;
  ctf_error_t err;

  ctf_dprintf ("Preserializing %zi dicts.\n", ctf_dict_cnt);

  /* Preserialize everything, doing everything but strtab generation and things
     that depend on that.  Any archive with more than one dict in it must
     be CTF.  */
  for (i = 0; i < ctf_dict_cnt; i++)
    if (ctf_preserialize (ctf_dicts[i], threshold != (size_t) -1
			  || ctf_dict_cnt > 1) < 0)
      goto err;

  for (i = 0; i < ctf_dict_cnt; i++)
    all_strlens += ctf_dicts[i]->ctf_str[0].cts_len
      + ctf_dicts[i]->ctf_str_prov_len;

  /* If linking, deduplicate strings against the children in every dict that has
     any.  (String deduplication is not yet implemented for non-linked dicts.)  */

  if (ctf_dict_cnt > 1 && ctf_dicts[0]->ctf_flags & LCTF_LINKING &&
      ctf_dicts[0]->ctf_link_outputs)
    {
      ctf_dprintf ("Deduplicating strings.\n");

      old_parent_strlen = ctf_dicts[0]->ctf_str[0].cts_len
	+ ctf_dicts[0]->ctf_str_prov_len;

      if (ctf_dedup_strings (ctf_dicts[0]) < 0)
	goto err;

      ctf_dprintf ("Deduplicated strings: original parent strlen: %zu; "
		   "original lengths: %zu; final parent length: %zu.\n",
		   (size_t) old_parent_strlen, (size_t) all_strlens,
		   (size_t) ctf_dicts[0]->ctf_str_prov_len);
    }

  return 0;

 err:
  err = ctf_errno (ctf_dicts[i]);
  ctf_err_copy (ctf_dicts[0], ctf_dicts[i]);
  for (i--; i >= 0; i--)
    ctf_depreserialize (ctf_dicts[i]);
  return err;
}

/* Write out a CTF archive to the start of the file referenced by the
   passed-in fd.  The entries are named according to their cunames, unless
   CTF_ARC_WRITE_NAMELESS is set in the flags, in which case no name table
   is written.

   Returns 0 on success, or an errno, or an ECTF_* value.  */
ctf_error_t
ctf_arc_write_fd (int fd, ctf_dict_t **ctf_dicts, size_t ctf_dict_cnt,
		  size_t threshold, enum ctf_arc_write_flags flags)
{
  size_t i;
  uint64_t magic = CTFA_MAGIC;
  size_t magic_len = sizeof (uint64_t);
  ssize_t len;
  const char *errmsg;
  unsigned char *mp;
  ctf_error_t err;

  /* Prepare by serializing everything.  Done first because it allocates a lot
     of space and thus is more likely to fail.  */
  if (ctf_dict_cnt > 0 &&
      ((err = ctf_arc_preserialize (ctf_dicts, ctf_dict_cnt, threshold)) < 0))
    return err;

  for (i = 0; i < ctf_dict_cnt; i++)
    {
      if (arc_write_one_ctf (ctf_dicts[i], fd, threshold) < 0)
	{
	  errmsg = N_("cannot write CTF file to archive");
	  goto err;
	}
    }

  if (flags & CTF_ARC_WRITE_NAMELESS)
    return 0;

  /* Write out the magic number, then the name table.  */

  mp = (unsigned char *) &magic;
  while (magic_len > 0)
    {
      if ((len = write (fd, mp, magic_len)) < 0)
	{
	  errmsg = N_("cannot write magic number to archive");
	  goto err;
	}
      magic_len -= len;
      mp += len;
    }

  for (i = 0; i < ctf_dict_cnt; i++)
    {
      const char *cuname = ctf_dict_cuname (ctf_dicts[i]);
      const char *p;
      size_t cuname_len;

      if (!cuname)
	cuname = "";

      cuname_len = strlen (cuname) + 1;
      p = cuname;

      if ((len = write (fd, p, cuname_len)) < 0)
	{
	  ctf_err (err_locus (ctf_dict_cnt > 0 ? ctf_dicts[0] : NULL), errno,
		   "cannot write name of archive member %zi (%s) to archive",
		   i, cuname);
	  return errno;
	}
      cuname_len -= len;
      p += len;
    }

  return 0;

err:
  /* We report errors into the first file in the archive, if any: if this is a
     zero-file archive, put it in the open-errors stream for lack of anywhere
     else for it to go.  */
  ctf_err (err_locus (ctf_dict_cnt > 0 ? ctf_dicts[0] : NULL), errno, "%s",
	   gettext (errmsg));
  return errno;
}

/* Write out a CTF archive.  The entries in CTF_DICTS are named by their
   cunames, unless CTF_ARC_WRITE_NAMELESS is set in the flags, in which case
   no name table is written.

   If the filename is NULL, create a temporary file and return a pointer to it.

   Returns 0 on success, or an errno, or an ECTF_* value.  */
ctf_error_t
ctf_arc_write (const char *file, ctf_dict_t **ctf_dicts, size_t ctf_dict_cnt,
	       size_t threshold, enum ctf_arc_write_flags flags)
{
  ctf_error_t err;
  int fd;

  if ((fd = open (file, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0666)) < 0)
    {
      ctf_err (err_locus (ctf_dict_cnt > 0 ? ctf_dicts[0] : NULL), errno,
	       _("cannot create %s"), file);
      return errno;
    }

  err = ctf_arc_write_fd (fd, ctf_dicts, ctf_dict_cnt, threshold, flags);
  if (err)
    goto err_close;

  if ((err = close (fd)) < 0)
    ctf_err (err_locus (ctf_dict_cnt > 0 ? ctf_dicts[0] : NULL), errno,
	     _("cannot close %s after writing"), file);
  goto err;

 err_close:
  (void) close (fd);
 err:
  if (err != 0)
    unlink (file);

  return err;
}

/* Write one CTF dict out.  Return success or a negative errno or ctf_errno
   value.  On error, the file position may no longer be at the end of the
   file, but if it is, it will be at an 8-byte aligned offset.  Sets errno
   on error.  */
static ctf_ret_t
arc_write_one_ctf (ctf_dict_t *fp, int fd, size_t threshold)
{
  off_t off, end_off;

  if ((off = lseek (fd, 0, SEEK_CUR)) < 0)
    return -1;

  if (ctf_write_thresholded (fp, fd, threshold) != 0)
    {
      errno = fp->ctf_errno;
      return -1;
    }

  if ((end_off = lseek (fd, 0, SEEK_CUR)) < 0)
    return -1;

  /* Align the end byte and move there.  */

  end_off = LCTF_ALIGN_OFFS (end_off, 8);
  if ((lseek (fd, end_off, SEEK_SET)) < 0)
    return -1;

  return 0;
}

/* Byteswap a v1 archive (but not its members) if necessary.  After this, the
   entire archive is in native-endian byte order.  */

static ctf_ret_t
ctf_arc_flip_v1_archive (struct ctf_archive_internal *arci, size_t arc_len,
			 ctf_error_t *errp)
{
  struct ctf_archive_v1 *hdr = arci->ctfi_v1_hdr;
  int needs_flipping = 0;
  ctf_archive_v1_modent_t *modent;
  unsigned char *arc_bytes = arci->ctfi_archive;
  unsigned char *ents;

  if (bswap_64 (hdr->magic) == CTFA_V1_MAGIC)
    needs_flipping = 1;

  if (!needs_flipping)
    return 0;

  /* Headers.  */

  swap_thing (hdr->magic);
  swap_thing (hdr->model);
  swap_thing (hdr->ndicts);
  swap_thing (hdr->names);
  swap_thing (hdr->ctfs);

  /* Swap the tables and the sizes of things therein.

     We must range-check first to be sure that the modent arrays are not out
     of range.  */

  modent = (ctf_archive_v1_modent_t *) (arc_bytes + sizeof (struct ctf_archive_v1));
  if (ctf_arc_range_check_v1_hdr (arci, arc_len, modent, errp) < 0)
    return -1;					/* errp is set for us.  */

  ents = (unsigned char *) (arc_bytes + arci->ctfi_v1_hdr->ctfs);
  if (ctf_arc_flip_v1_modents (modent, arci->ctfi_v1_hdr->ndicts, ents,
			       arci->ctfi_v1_hdr->ctfs, arc_len, errp) < 0)
    return -1;					/* errp is set for us.  */

  return 0;
}

/* Byteswap a v1 modent table with offsets rooted at BASE, including the
   size entries preceding the elements themselves.  */

static ctf_ret_t
ctf_arc_flip_v1_modents (ctf_archive_v1_modent_t *modent, uint64_t els,
			 unsigned char *ents, uint64_t base, size_t arc_len,
			 ctf_error_t *errp)
{
  uint64_t i;

  for (i = 0; i < els; i++)
    {
      uint64_t *ctf_size;

      swap_thing (modent[i].name);
      swap_thing (modent[i].contents);

      if (base + modent[i].contents + sizeof (uint64_t) > arc_len)
	{
	  ctf_set_open_errno (errp, EOVERFLOW);
	  return ctf_err (err_locus (NULL), EOVERFLOW,
			  "CTF v1 archive overflow in content offset for member %" PRIu64
			  " of %zi + %zi", i, base, modent[i].contents);
	}

      ctf_size = (uint64_t *) (ents + modent[i].contents);
      swap_thing (*ctf_size);
    }

  return 0;
}

/* Range- and overlap-check the v1 archive header.  At this stage, only the
   name offsets, and overlaps of the starts of tables, are checkable.  The
   rest gets checked further down, in ctf_arc_range_check.  */

static ctf_ret_t
ctf_arc_range_check_v1_hdr (struct ctf_archive_internal *arci, size_t arc_len,
			    ctf_archive_v1_modent_t *modent, ctf_error_t *errp)
{
  unsigned char *arc_bytes = arci->ctfi_archive;
  uint64_t ndict_end;
  const char *err;

  ndict_end = ((unsigned char *) modent)
    + (arci->ctfi_v1_hdr->ndicts * sizeof (ctf_archive_v1_modent_t))
    - arc_bytes;

  if (ndict_end > arc_len)
    {
      ctf_set_open_errno (errp, EOVERFLOW);
      return ctf_err (err_locus (NULL), EOVERFLOW,
		      _("CTF v1 archive overflow: archive is %zi bytes, but ctfs end at %zi + (%zi * %zi) = %zi"),
		      arc_len, sizeof (struct ctf_archive_v1),
		      sizeof (ctf_archive_v1_modent_t),
		      arci->ctfi_v1_hdr->ndicts, ndict_end);
    }

  if (ndict_end > arci->ctfi_v1_hdr->names
      || ndict_end > arci->ctfi_v1_hdr->ctfs
      || arci->ctfi_v1_hdr->names == arci->ctfi_v1_hdr->ctfs
      || arci->ctfi_v1_hdr->names < ndict_end
      || arci->ctfi_v1_hdr->ctfs < ndict_end)
    {
      err = "ctf table";
      goto err;
    }

  if (arci->ctfi_v1_hdr->names > arc_len)
    {
      err = "name table";
      goto err;
    }

  if (arci->ctfi_v1_hdr->ctfs > arc_len)
    {
      err = "member table";
      goto err;
    }

  return 0;

 err:
  ctf_set_open_errno (errp, EOVERFLOW);
  return ctf_err (err_locus (NULL), EOVERFLOW,
		  _("CTF v1 archive overflow: overlapping %s in archive"),
		  gettext (err));
}

/* Find the closest section to BASE that is located after it.  If none, the
   archive length is returned.  */

static uint64_t
ctf_arc_closest_v1_section (struct ctf_archive_v1 *arc_v1_hdr, uint64_t base,
			    size_t arc_len)
{
  uint64_t closest = arc_len;

  if (arc_v1_hdr->names > base
      && arc_v1_hdr->ctfs < closest)
    closest = arc_v1_hdr->names;

  if (arc_v1_hdr->ctfs > base
      && arc_v1_hdr->ctfs < closest)
    closest = arc_v1_hdr->ctfs;

  return closest;
}

/* Range-check a single v1 modent array.  */

static ctf_ret_t
ctf_arc_range_check_v1_modents (ctf_archive_v1_modent_t *modent,
				struct ctf_archive_v1 *arc_v1_hdr,
				unsigned char *arc_bytes,
				uint64_t ctf_base, size_t ctf_els,
				size_t arc_len,
				ctf_error_t *errp)
{
  uint64_t i;
  char *names = (char *) arc_bytes + arc_v1_hdr->names;
  uint64_t name_base = arc_v1_hdr->names;
  unsigned char *ctf = (unsigned char *) arc_bytes + ctf_base;
  size_t closest_names_offset, closest_ctf_offset;

  /* Figure out the offset of the thing that is closest to, but after the
     end of, the names section, or the end of the file if none.  */

  closest_names_offset = arc_len;

  closest_names_offset = ctf_arc_closest_v1_section (arc_v1_hdr, name_base, arc_len);
  closest_ctf_offset = ctf_arc_closest_v1_section (arc_v1_hdr, ctf_base,
						   arc_len);

  for (i = 0; i < ctf_els; i++)
    {
      uint64_t name_off = modent[i].name + name_base;
      uint64_t ctf_off = modent[i].contents + ctf_base;
      ssize_t space_left;
      uint64_t *ctf_size;

      /* We already checked for modent table overflow and overlap, but we
	 cannot check for name table overlap except member-by-member.  We
	 have to check the name offset first to make sure that strlen()ing
	 the string is safe, then check that.  */

      if (name_off > closest_names_offset
	  || (ctf_off + sizeof (uint64_t) > closest_ctf_offset))
	goto err;

      space_left = closest_names_offset - name_off;

      if (space_left < 0)
	goto err;

      if (strnlen (&names[modent[i].name], space_left)
	  == (size_t) space_left)
	goto err;

      /* Checking the CTF offset is simpler: we already checked that the
	 actual size didn't overflow, so now we just need to make sure that
	 the entire dict (or, depending on the call, property value) fits.  */

      ctf_size = (uint64_t *) (ctf + modent[i].contents);

      /* The contents size includes the size of the size uint64_t itself, so
	 all archive opens opened one uint64_t too much.  Fix this up, since
	 the values are otherwise valid.  If the ctf_size is zero,
	 ironically, we know this is an underflow! */

      if (*ctf_size < sizeof (uint64_t))
	goto err;
      *ctf_size -= sizeof (uint64_t);

      if (ctf_off + sizeof (uint64_t) + *ctf_size > closest_ctf_offset)
	goto err;
    }

  return 0;

err:
  ctf_set_open_errno (errp, EOVERFLOW);
  return ctf_err (err_locus (NULL), EOVERFLOW, _("CTF v1 archive overflow: "
		  "modent array element %" PRIu64 " overflow/overlap"), i);
}

/* Range check the v1 archive modent tables.  By this stage the tables are
   all in native endianness.  */

static ctf_ret_t
ctf_arc_range_check_v1 (struct ctf_archive_internal *arci, size_t arc_len,
			ctf_error_t *errp)
{
  unsigned char *arc_bytes = arci->ctfi_archive;
  ctf_archive_v1_modent_t *modents;

  if (arc_len < sizeof (struct ctf_archive_v1))
    {
      ctf_set_open_errno (errp, EOVERFLOW);
      return ctf_err (err_locus (NULL), EOVERFLOW, "CTF v1 archive header is %zi bytes, "
		      "but input is only %zi bytes\n", sizeof (struct ctf_archive_v1),
		      arc_len);
    }

  modents = (ctf_archive_v1_modent_t *) (arc_bytes + sizeof (struct ctf_archive_v1));

  if (ctf_arc_range_check_v1_hdr (arci, arc_len, modents, errp) < 0)
    return -1;					/* errno is set for us.  */

  if (ctf_arc_range_check_v1_modents (modents, arci->ctfi_v1_hdr, arc_bytes,
				      arci->ctfi_v1_hdr->ctfs,
				      arci->ctfi_v1_hdr->ndicts, arc_len,
				      errp) < 0)
    return -1;					/* errno is set for us.  */

  return 0;
}

/* Hunt down one of the magic numbers for a CTFv4 or BTF dict or its
   trailing strtab in a given range in BUF.  If a strtab magic is found, set
   STRTAB.

   Allow up to 64 bytes of padding.  */

static unsigned char *
ctf_arc_find_magic (unsigned char *buf, size_t len, int *strtab)
{
  uint64_t magic;
  uint16_t magic_16;
  void *ret;

  if (len == 0)
    return NULL;

  magic_16 = CTF_BTF_MAGIC;
  if ((ret = memmem (buf, len, &magic_16, sizeof (magic_16))) != NULL)
    return ret;

  swap_thing (magic_16);
  if ((ret = memmem (buf, len, &magic_16, sizeof (magic_16))) != NULL)
    return ret;

  magic = CTFA_MAGIC;
  if ((ret = memmem (buf, len, &magic, sizeof (magic))) != NULL)
    {
      *strtab = 1;
      return ret;
    }

  swap_thing (magic);
  if ((ret = memmem (buf, len, &magic, sizeof (magic))) != NULL)
    {
      *strtab = 1;
      return ret;
    }
  return NULL;
}

/* Make a new struct ctf_archive_internal wrapper for a buffer (which may
   contain a ctf_archive) or a single ctf_dict: endian-swap the archive
   header as necessary, and check all its offsets for validity.
   Close/optionally unmap BUF and/or FP on error.  Arrange to free or unmap
   the SYMSECT or STRSECT, as needed, on close.  */

struct ctf_archive_internal *
ctf_new_archive_internal (unsigned char *buf, ctf_dict_t *fp, int v1,
			  enum arc_on_close_operation on_close,
			  size_t len, const ctf_sect_t *symsect,
			  const ctf_sect_t *strsect, ctf_error_t *errp)
{
  struct ctf_archive_internal *arci = NULL;
  size_t ufsize;
  ctf_error_t err = 0;

  ctf_set_open_errno (errp, 0);

  if ((arci = calloc (1, sizeof (struct ctf_archive_internal))) == NULL)
    goto err;

  if ((arci->ctfi_named_indexes = ctf_dynhash_create (ctf_hash_string,
						      ctf_hash_eq_string,
						      NULL, NULL)) == NULL)
    goto err;

  if ((arci->ctfi_member_names = ctf_dynhash_create (ctf_hash_integer,
						     ctf_hash_eq_integer,
						     NULL, NULL)) == NULL)
    goto err;

  arci->ctfi_archive = buf;
  arci->ctfi_archive_len = len;
  arci->ctfi_on_close = on_close;

  /* v1 archive: header, followed by members.  */
  if (v1)
    {
      ctf_archive_v1_modent_t *modent;
      size_t i;

      if (len < sizeof (struct ctf_archive_v1))
	{
	  ufsize = sizeof (struct ctf_archive_v1);
	  goto underflow;
	}

      if ((arci->ctfi_v1_hdr = malloc (sizeof (struct ctf_archive_v1))) == NULL)
	goto err;

      memcpy (arci->ctfi_v1_hdr, buf, sizeof (struct ctf_archive_v1));

      if (ctf_arc_flip_v1_archive (arci, len, errp) < 0)
	goto err_set;

      if (ctf_arc_range_check_v1 (arci, len, errp) < 0)
	goto err_set;

      modent = (ctf_archive_v1_modent_t *) ((char *) arci->ctfi_archive
					    + sizeof (struct ctf_archive_v1));

      /* Transform the modent array into a ctfi_named_indexes and
	 ctf_members array, and a backpointing ctfi_member_names array (used
	 for getting member names when iterating over members).  */

      arci->ctfi_nmemb = arci->ctfi_v1_hdr->ndicts;
      arci->ctfi_names = (const char *) arci->ctfi_archive + arci->ctfi_v1_hdr->names;

      if ((arci->ctfi_members = calloc (arci->ctfi_nmemb, sizeof (size_t))) == NULL)
	goto err;

      for (i = 0; i < arci->ctfi_nmemb; i++)
	{
	  arci->ctfi_members[i] = arci->ctfi_v1_hdr->ctfs
				  + modent[i].contents;

	  if (ctf_dynhash_cinsert (arci->ctfi_named_indexes,
				   &arci->ctfi_names[modent[i].name],
				   (void *) i) < 0)
	    goto err;

	  if (ctf_dynhash_cinsert (arci->ctfi_member_names,
				   (void *) arci->ctfi_members[i],
				   &arci->ctfi_names[modent[i].name]) < 0)
	    goto err;
	}
    }
  else if (buf)		      /* Buffer containing some number of dicts.  */
    {
      size_t i = 0;
      unsigned char *p = buf;
      unsigned char *magic;
      size_t num_dicts = 0;
      int strtab = 0;

      /* Count dicts.  Hunt forwards in the buffer for magic numbers: either
	 the magic number of another CTFv4 or BTF dict, or of the strtab
	 (which, like a lack of magic numbers, indicates the end of the
	 array of dicts).  Allow magic numbers (thus, dicts or the strtab)
	 to be separated by up to 64 bytes of padding.  Since this is really
	 only for alignment, intervening bytes are almost certainly zero:
	 the relative shortness of the magic numbers is not a problem.

	 Since we search for magic numbers without consideration for whether
	 they're embedded in a dict or not, this value may be too high: but
	 it will not be too low.  */

      if (len < sizeof (ctf_btf_header_t))
	{
	  ufsize = sizeof (ctf_btf_header_t);
	  goto underflow;
	}

      while ((magic = ctf_arc_find_magic (p, len - (p - buf), &strtab)) != NULL)
	{
	  if (strtab)
	    break;

	  p = magic + sizeof (uint16_t);
	  num_dicts++;
	}

      if (num_dicts == 0)
	{
	  ctf_set_open_errno (errp, ECTF_FMT);
	  ctf_err (err_locus (NULL), ECTF_FMT,
		   _("Buffer not a CTF archive: no magic number"));
	  goto err_set;
	}

      ctf_dprintf ("Counted at most %zi member(s).\n", num_dicts);
      strtab = 0;

      /* Allocate space for the archive members, then fill it out with
	 offsets via another pass through the archive.  */
      if ((arci->ctfi_members = calloc (num_dicts, sizeof (size_t))) == NULL)
	goto err;

      p = buf;
      while ((magic = ctf_arc_find_magic (p, MIN (65, len - (p - buf)), &strtab)) != NULL)
	{
	  ssize_t dict_len;
	  ctf_sect_t tmp;

	  if (strtab)
	    break;

	  p = magic;
	  arci->ctfi_members[i] = (p - buf);

	  memset (&tmp, 0, sizeof (ctf_sect_t));
	  tmp.cts_size = len - (p - buf);	/* (upper bound)  */
	  tmp.cts_data = p;
	  if ((dict_len = ctf_buflen (&tmp, &err)) < 0)
	    {
	      ctf_set_open_errno (errp, err);
	      ctf_err (err_locus (NULL), err,
		       _("determining dict length at archive offset %zi"),
		       (p - buf));
	      goto err_set;
	    }

	  i++;
	  p += dict_len;
	}

      arci->ctfi_nmemb = i;

      /* The archive length does not include the length of the strtab, if
	 any (which the loop above will have terminated at).  */
      if (strtab)
	arci->ctfi_archive_len = magic - buf;

      /* Shrink to the actual number of dicts.  */

      if (num_dicts > i)
	{
	  if ((arci->ctfi_members = realloc (arci->ctfi_members,
					     i * sizeof (size_t))) == NULL)
	    {
	      ctf_set_open_errno (errp, ECTF_INTERNAL);
	      ctf_err (err_locus (NULL), ECTF_INTERNAL,
		       _("allocation shrinkage failed"));
	      goto err_set;
	    }
	}

      ctf_dprintf ("v2 archive: %zi members\n", arci->ctfi_nmemb);

      /* Archive has a string table: collate that, too, 1:1 with the dicts.  */
      if (strtab)
	{
	  size_t j = 0;
	  const char *name;

	  arci->ctfi_names = (const char *) magic + sizeof (uint64_t);	/* Skip over the CTFA_MAGIC.  */

	  for (name = arci->ctfi_names; j < i;
	       j++, name += strlen (name) + 1)
	    {
	      if (ctf_dynhash_cinsert (arci->ctfi_named_indexes, name, (void *) j) < 0)
		goto err;
	      if (ctf_dynhash_cinsert (arci->ctfi_member_names,
				       (void *) arci->ctfi_members[j], name) < 0)
		goto err;
	    }
	}
    }
  else
    {
      /* Wrapper around a single dict.  Dict already opened and
	 byteswapped.  */

      arci->ctfi_dict = fp;
      arci->ctfi_nmemb = 1;

      if ((arci->ctfi_members = calloc (1, sizeof (size_t))) == NULL)
	goto err;
      arci->ctfi_members[0] = 0;

      if (ctf_dynhash_cinsert (arci->ctfi_named_indexes, _CTF_SECTION, (void *) 0) < 0)
	goto err;
      if (ctf_dynhash_cinsert (arci->ctfi_member_names, (void *) 0, _CTF_SECTION) < 0)
	goto err;
    }

  if (symsect)
     memcpy (&arci->ctfi_symsect, symsect, sizeof (struct ctf_sect));
  if (strsect)
     memcpy (&arci->ctfi_strsect, strsect, sizeof (struct ctf_sect));
  arci->ctfi_free_symsect = 0;
  arci->ctfi_free_strsect = 0;
  arci->ctfi_symsect_little_endian = -1;

  return arci;

 underflow:
  errno = EOVERFLOW;
  ctf_err (err_locus (NULL), EOVERFLOW,
	   _("CTF archive underflow: archive is %zi bytes, shorter than the header length of %zi bytes"),
	   len, ufsize);
 err:
  ctf_set_open_errno (errp, errno);
 err_set:
  if (arci)
    {
      free (arci->ctfi_members);
      ctf_dynhash_destroy (arci->ctfi_member_names);
      ctf_dynhash_destroy (arci->ctfi_named_indexes);
      ctf_arc_close_free (arci);
      free (arci->ctfi_v1_hdr);
      free (arci);
    }
  return NULL;
}

/* Make an archive that is a wrapper around a single dict.  The archive's
   lifetime is subordinate to that of the dict: it is closed when the dict
   is.  */

struct ctf_archive_internal *
ctf_new_archive_wrapper (ctf_dict_t *fp, const ctf_sect_t *symsect,
			 const ctf_sect_t *strsect, ctf_error_t *errp)
{
  struct ctf_archive_internal *arci;
  if ((arci = ctf_new_archive_internal (NULL, fp, 0, FREE_ARCHIVE_ON_DICT_CLOSE,
					0, symsect, strsect, errp)) != NULL)
    arci->ctfi_symsect_little_endian = fp->ctf_symsect_little_endian;
  return arci;
}

/* Set the symbol-table endianness of an archive (defaulting the symtab
   endianness of all ctf_file_t's opened from that archive).  */
void
ctf_arc_symsect_endianness (struct ctf_archive_internal *arci, int little_endian)
{
  arci->ctfi_symsect_little_endian = !!little_endian;
  if (arci->ctfi_dict)
    ctf_symsect_endianness (arci->ctfi_dict, arci->ctfi_symsect_little_endian);
}

/* Get the CTF preamble from data in a buffer, which may be either an archive or
   a CTF dict.  If multiple dicts are present in an archive, the preamble comes
   from an arbitrary dict.  The preamble is a pointer into the ctfsect passed
   in.  Returns NULL if called on non-v1 archives.  (Backward-compatibility
   only.)  */

const ctf_preamble_t *
ctf_arc_bufpreamble_v1 (const ctf_sect_t *ctfsect)
{
  if (ctfsect->cts_data == NULL
      || ctfsect->cts_size <= sizeof (uint64_t))
    {
      errno = EOVERFLOW;
      return NULL;
    }

  if (le64toh ((*(uint64_t *) ctfsect->cts_data)) == CTFA_V1_MAGIC)
    {
      struct ctf_archive_v1 *arc = (struct ctf_archive_v1 *) ctfsect->cts_data;
      return (const ctf_preamble_t *) ((char *) arc + le64toh (arc->ctfs)
				       + sizeof (uint64_t));
    }

  return NULL;
}

/* Open a CTF archive or dictionary from data in a buffer (which the caller must
   preserve until ctf_arc_close() time).  Returns the archive, or NULL and an
   error in *err (if not NULL).  */
ctf_archive_t *
ctf_arc_bufopen (const ctf_sect_t *ctfsect, const ctf_sect_t *symsect,
		 const ctf_sect_t *strsect, ctf_error_t *errp)
{
  int v1 = 0;

  if (ctfsect->cts_data != NULL
      && ctfsect->cts_size > sizeof (uint64_t)
      && (le64toh ((*(uint64_t *) ctfsect->cts_data)) == CTFA_V1_MAGIC))
    v1 = 1;

  return ctf_new_archive_internal ((unsigned char *) ctfsect->cts_data, NULL,
				   v1, FREE_ARCHIVE_ONLY_DICT, ctfsect->cts_size,
				   symsect, strsect, errp);
}

/* Open a CTF archive from a given fd.  Returns the archive (wrapper), or
   NULL and an error in *err (if not NULL).  Both dicts and archives may be
   passed in.  */

struct ctf_archive_internal *
ctf_arc_open_internal (int fd, const char *filename, ctf_error_t *errp)
{
  const char *errmsg;
  enum arc_on_close_operation close_op = FREE_ARCHIVE_UNMAP_ON_CLOSE;
  int v1 = 0;
  struct stat s;
  struct ctf_archive_v1 *arc;		/* (Actually the whole file.)  */
  unsigned char *content;		/* A dict, as a bag of bytes.  */
  struct ctf_archive_internal *ret;
  int err;

  libctf_init_debug();
  if (fstat (fd, &s) < 0)
    {
      errmsg = N_("cannot stat %s");
      goto err_no;
    }

  if ((size_t) s.st_size < sizeof (uint64_t))
    {
      err = ECTF_FMT;
      errmsg = N_("%s is too small");
      goto err;
    }

  /* This will fail if the file is too big -- e.g. > 4GiB on 32-bit
     platforms -- and thus free us from having to do integer-overflow checks
     elsewhere.  */
  if ((content = arc_mmap_file (fd, s.st_size)) == NULL)
    {
      close_op = FREE_ARCHIVE_ON_CLOSE;

      if ((content = arc_pread_file (fd, s.st_size)) == NULL)
	{
	  errmsg = N_("cannot read in %s");
	  goto err_no;
	}
    }

  arc = (struct ctf_archive_v1 *) content;
  if (le64toh (arc->magic) == CTFA_V1_MAGIC)
      v1 = 1;

  ret = ctf_new_archive_internal (content, NULL, v1, close_op, s.st_size,
				  NULL, NULL, errp);

  /* ctf_new_archive_internal cleans up on error, so shouldn't do so.  */
  return ret;

err_no:
  err = errno;
  if (errp)
    *errp = err;
 err:
  ctf_set_open_errno (errp, err);
  ctf_err (err_locus (NULL), err, gettext (errmsg), filename);
  return NULL;
}

/* Close an archive and possibly free its archive/dict children.  */
void
ctf_arc_close_free (struct ctf_archive_internal *arci)
{
  if (arci == NULL)
    return;

  /* When invoked by ctf_dict_arc(), the lifetime of archives is reversed:
     the archive is an explict child of a single dict, is owned by that
     dict, and is freed by it when the dict is freed.  It must not be freed
     on closing the archive in this case.  */
  if (arci->ctfi_dict && arci->ctfi_on_close != FREE_ARCHIVE_ON_DICT_CLOSE)
    ctf_dict_close (arci->ctfi_dict);

  switch (arci->ctfi_on_close)
    {
    case FREE_ARCHIVE_ON_CLOSE:
      free (arci->ctfi_archive);
      break;
    case FREE_ARCHIVE_UNMAP_ON_CLOSE:
      arc_mmap_unmap (arci->ctfi_archive, arci->ctfi_archive_len, NULL);
      break;
    default:;
      /* Other cases don't need special handling.  */
    }
}

/* Public entry point: close an archive (via its wrapper), or CTF dict.  */
void
ctf_arc_close (struct ctf_archive_internal *arci)
{
  if (arci == NULL)
    return;

  ctf_arc_close_free (arci);
  free (arci->ctfi_v1_hdr);
  free (arci->ctfi_members);
  ctf_dynhash_destroy (arci->ctfi_named_indexes);
  ctf_dynhash_destroy (arci->ctfi_member_names);
  free (arci->ctfi_default_parent_cuname);
  free (arci->ctfi_symdicts);
  free (arci->ctfi_symnamedicts);
  ctf_dynhash_destroy (arci->ctfi_dicts);
  if (arci->ctfi_free_symsect)
    free ((void *) arci->ctfi_symsect.cts_data);
  if (arci->ctfi_free_strsect)
    free ((void *) arci->ctfi_strsect.cts_data);
  free (arci->ctfi_data);
  if (arci->ctfi_bfd_close)
    arci->ctfi_bfd_close (arci);
  free (arci);
}

/* Default the parent dict's cuname, if currently unset.  Used by linkers
   to set the parent cuname without needing to open the dict.  */
void
ctf_link_set_default_parent_cuname (ctf_archive_t *arc,
				    const char *cuname)
{
  arc->ctfi_default_parent_cuname = xstrdup (cuname);
}

/* Get the length of an archive member in an archive.  Works for v1 and v2
   dicts, but not wrappers.  The caller must do index-validity checking.  */
static size_t
ctf_arc_get_dict_len (const struct ctf_archive_internal *arci,
		      size_t index)
{
  size_t next;

  if (arci->ctfi_v1_hdr)
    return (size_t) *((uint64_t *) &arci->ctfi_archive[arci->ctfi_members[index]]);

  if (index == arci->ctfi_nmemb - 1)
    next = arci->ctfi_archive_len;
  else
    next = arci->ctfi_members[index + 1];

  return next - arci->ctfi_members[index];
}

/* Return the ctf_dict_t at the given offset, or NULL if none, setting 'err'
   if non-NULL.  */
static ctf_dict_t *
ctf_dict_open_by_offset (const struct ctf_archive_internal *arci,
			 const ctf_sect_t *symsect,
			 const ctf_sect_t *strsect, size_t offset,
			 size_t len, int little_endian_symtab,
			 ctf_error_t *errp)
{
  ctf_sect_t ctfsect;
  ctf_dict_t *fp;

  ctf_dprintf ("ctf_dict_open_by_offset(%zi): opening\n", offset);

  if (symsect->cts_name == NULL)
    symsect = NULL;
  if (strsect->cts_name == NULL)
    strsect = NULL;

  memset (&ctfsect, 0, sizeof (ctf_sect_t));

  /* Offsets in v1 are relative to the ctfs header offset.  In v2 they are
     simply file offsets.  */
  if (arci->ctfi_v1_hdr)
    offset += arci->ctfi_v1_hdr->ctfs;

  ctfsect.cts_name = _CTF_SECTION;
  ctfsect.cts_entsize = 1;
  ctfsect.cts_data = (void *) (&arci->ctfi_archive[offset]);
  ctfsect.cts_size = len;

  /* v1 has a length word preceding the actual data.  */
  if (arci->ctfi_v1_hdr)
    ctfsect.cts_data = (void *) (&arci->ctfi_archive[offset] + sizeof (uint64_t));

  fp = ctf_bufopen (&ctfsect, symsect, strsect, errp);
  if (!fp)
    return NULL;				/* errno is set for us.  */

  /* V1 archives record the data model of their members.  v2 must get
     it from elsewhere (BFD, the caller...) */
  if (arci->ctfi_v1_hdr)
    ctf_dict_set_model (fp, arci->ctfi_v1_hdr->model);
  if (little_endian_symtab >= 0)
    ctf_symsect_endianness (fp, little_endian_symtab);

  /* Set the CU name if unset, either by looking up the name for the member
     at this offset in the strtab, or by using a linker-set default
     (applicable to the parent dict only).  */
  if (ctf_dict_cuname (fp) == NULL)
    {
      const char *name;

      if ((name = ctf_dynhash_lookup (arci->ctfi_member_names,
				      (void *) offset)) != NULL)
	ctf_dict_set_cuname (fp, name);
      else if (offset == 0 && arci->ctfi_default_parent_cuname)
	ctf_dict_set_cuname (fp, arci->ctfi_default_parent_cuname);
    }
  return fp;
}

/* Return the ctf_dict_t with the given index in the archive, or NULL if
   none, setting 'err' if non-NULL.  A name of NULL means to open the
   default file.

   Public entry point.  */
ctf_dict_t *
ctf_dict_open_by_index (const struct ctf_archive_internal *arci, size_t index,
			ctf_error_t *errp)
{
  if (errp)
    *errp = 0;

  ctf_dprintf ("ctf_dict_open_by_index (%zi): opening\n", index);

  if (!arci->ctfi_dict)
    {
      ctf_dict_t *fp;
      size_t len;

      if (index >= arci->ctfi_nmemb)
	{
	  ctf_err (err_locus (NULL), EOVERFLOW,
		   _("overflow opening archive member with index %zi: only %zi members"),
		   index, arci->ctfi_nmemb);
	  if (errp)
	    *errp = EOVERFLOW;
	  return NULL;
	}

      len = ctf_arc_get_dict_len (arci, index);
      fp = ctf_dict_open_by_offset (arci, &arci->ctfi_symsect,
				    &arci->ctfi_strsect,
				    arci->ctfi_members[index], len,
				    arci->ctfi_symsect_little_endian, errp);
      if (fp)
	{
	  fp->ctf_archive = (struct ctf_archive_internal *) arci;
	  if (ctf_arc_import_parent (arci, fp, errp) < 0)
	    {
	      ctf_dict_close (fp);
	      return NULL;
	    }
	}
      return fp;
    }

  /* Wrapper around a single dict, which is always index 0.  */

  if (index != 0)
    {
      /* This is actually a common case and normal operation: no error
	 debug output.  */
      if (errp)
	*errp = ECTF_ARNNAME;
      return NULL;
    }

  arci->ctfi_dict->ctf_archive = (struct ctf_archive_internal *) arci;

  /* Bump the refcount so that the user can ctf_dict_close() it.  */
  arci->ctfi_dict->ctf_refcnt++;
  return arci->ctfi_dict;
}

/* Return the ctf_dict_t with the given name, or NULL if none, setting 'err' if
   non-NULL.  A name of NULL means to open the default file.

   Public entry point.  */
ctf_dict_t *
ctf_dict_open (const struct ctf_archive_internal *arci, const char *name,
	       ctf_error_t *errp)
{
  void *index_v;
  size_t index;

  if (name == NULL)
    name = _CTF_SECTION;			/* The default name.  */

  ctf_dprintf ("ctf_dict_open (%s): opening\n", name);

  if (!ctf_dynhash_lookup_kv (arci->ctfi_named_indexes, name, NULL, &index_v))
    {
      /* This is actually a common case and normal operation: no error
	 debug output.  */
      if (errp)
	*errp = ECTF_ARNNAME;
      return NULL;
    }

  index = (size_t) index_v;
  return ctf_dict_open_by_index (arci, index, errp);
}

static void
ctf_cached_dict_close (void *fp)
{
  ctf_dict_close ((ctf_dict_t *) fp);
}

/* Return the ctf_dict_t with the given index and cache it in the archive's
   ctfi_dicts.  If this is the first cached dict, designate it the
   crossdict_cache.  The archive is already known not to be a wrapper.  */
static ctf_dict_t *
ctf_dict_open_cached (struct ctf_archive_internal *arci, size_t index,
		      ctf_error_t *errp)
{
  ctf_dict_t *fp;

  /* Just return from the cache if possible.  */
  if (arci->ctfi_dicts
      && ((fp = ctf_dynhash_lookup (arci->ctfi_dicts, (void *) index)) != NULL))
    {
      fp->ctf_refcnt++;
      return fp;
    }

  /* Not yet cached: open it.  */
  if (index >= arci->ctfi_nmemb)
    {
      ctf_err (err_locus (NULL), EOVERFLOW,
	       _("overflow opening archive member with index %zi: only %zi members"),
	       index, arci->ctfi_nmemb);
      if (errp)
	*errp = EOVERFLOW;
      return NULL;
    }

  if ((fp = ctf_dict_open_by_index (arci, index, errp)) == NULL)
    goto err;

  if (arci->ctfi_dicts == NULL)
    if ((arci->ctfi_dicts
	 = ctf_dynhash_create (ctf_hash_integer, ctf_hash_eq_integer,
			       NULL, ctf_cached_dict_close)) == NULL)
      goto oom;

  if (ctf_dynhash_insert (arci->ctfi_dicts, (void *) index, fp) < 0)
    goto oom;
  fp->ctf_refcnt++;

  if (arci->ctfi_crossdict_cache == NULL)
    arci->ctfi_crossdict_cache = fp;

  /* If this archive has multiple members, and this is a parent, pretend
     that we have opened at least one child.  This forces type and string
     allocations in the parent to use provisional IDs, permitting you to
     import existing children into it even if you modify the parent before
     you import any.  */
  if (!arci->ctfi_dict && arci->ctfi_nmemb > 1 && !(fp->ctf_flags & LCTF_CHILD))
    {
      ctf_dprintf ("archived parent: max children bumped.\n");
      fp->ctf_max_children++;
    }

  return fp;

 oom:
  if (errp)
    *errp = ENOMEM;
 err:
  ctf_dict_close (fp);
  return NULL;
}

/* Flush any caches the CTF archive may have open.  */
void
ctf_arc_flush_caches (struct ctf_archive_internal *arci)
{
  free (arci->ctfi_symdicts);
  ctf_dynhash_destroy (arci->ctfi_symnamedicts);
  ctf_dynhash_destroy (arci->ctfi_dicts);
  arci->ctfi_symdicts = NULL;
  arci->ctfi_symnamedicts = NULL;
  arci->ctfi_dicts = NULL;
  arci->ctfi_crossdict_cache = NULL;
}

/* Import the parent into a ctf archive, if this is a child, the parent is not
   already set, and a suitable archive member exists.  No error is raised if
   this is not possible: this is just a best-effort helper operation to give
   people useful dicts to start with.  */
static ctf_ret_t
ctf_arc_import_parent (const struct ctf_archive_internal *arci, ctf_dict_t *fp,
		       ctf_error_t *errp)
{
  ctf_error_t err = 0;
  ctf_dict_t *parent = NULL;
  const char *parent_name = fp->ctf_parent_name;
  int load_parent = 0;
  size_t parent_index = 0;

  if (!(fp->ctf_flags & LCTF_CHILD) || fp->ctf_parent)
    return 0;

  /* If no parent name is set, and this is a v2 archive, use the first
     member.  */

  if (fp->ctf_parent_name)
    {
      void *index_v;
      if (!ctf_dynhash_lookup_kv (arci->ctfi_named_indexes, parent_name, NULL,
				  &index_v))
	{
	  parent_index = (size_t) index_v;
	  load_parent = 1;
	}
    }
  else if (!arci->ctfi_v1_hdr)
    load_parent = 1;

  if (load_parent)
    {
      parent = ctf_dict_open_cached ((ctf_archive_t *) arci, parent_index,
				     &err);

      if (errp)
	*errp = err;
    }

  if (parent)
    {
      if (ctf_import (fp, parent) < 0)
	ctf_warn (err_locus (NULL), ctf_errno (fp), NULL);
      ctf_dict_close (parent);
    }
  else if (err == ECTF_ARNNAME)
    ctf_errwarning_remove (NULL, ECTF_ARNNAME);
  else if (err)
    return -1;					/* errno is set for us.  */
  return 0;
}

/* Return the number of members in an archive.  */
size_t
ctf_archive_count (const struct ctf_archive_internal *arci)
{
  return arci->ctfi_nmemb;
}

/* Look up a symbol in an archive by name or index (if the name is set, a lookup
   by name is done).  Return the dict in the archive that the symbol is found
   in, and (optionally) the ctf_id_t of the symbol in that dict (so you don't
   have to look it up yourself).  The dict is cached, so repeated lookups are
   nearly free.

   As usual, you should ctf_dict_close() the returned dict once you are done
   with it.

   Returns NULL on error, and an error in errp (if set).  */

static ctf_dict_t *
ctf_arc_lookup_sym_or_name (struct ctf_archive_internal *arci, unsigned long symidx,
			    const char *symname, ctf_id_t *typep, ctf_error_t *errp)
{
  ctf_dict_t *fp;
  void *fpkey;
  ctf_id_t type;

  /* The usual non-archive-transparent-wrapper special case.  */
  if (arci->ctfi_dict)
    {
      if (!symname)
	{
	  if ((type = ctf_lookup_by_symbol (arci->ctfi_dict, symidx)) == CTF_ERR)
	    {
	      if (errp)
		*errp = ctf_errno (arci->ctfi_dict);
	      return NULL;
	    }
	}
      else
	{
	  if ((type = ctf_lookup_by_symbol_name (arci->ctfi_dict,
						 symname)) == CTF_ERR)
	    {
	      if (errp)
		*errp = ctf_errno (arci->ctfi_dict);
	      return NULL;
	    }
	}
      if (typep)
	*typep = type;
      arci->ctfi_dict->ctf_refcnt++;
      return arci->ctfi_dict;
    }

  if (arci->ctfi_symsect.cts_name == NULL
      || arci->ctfi_symsect.cts_data == NULL
      || arci->ctfi_symsect.cts_size == 0
      || arci->ctfi_symsect.cts_entsize == 0)
    {
      if (errp)
	*errp = ECTF_NOSYMTAB;
      return NULL;
    }

  /* Make enough space for all possible symbol indexes, if not already done.  We
     cache the originating dictionary of all symbols.  The dict links are weak,
     to the dictionaries cached in ctfi_dicts: their refcnts are *not* bumped.
     We also cache similar mappings for symbol names: these are ordinary
     dynhashes, with weak links to dicts.  */

  if (!arci->ctfi_symdicts)
    {
      if ((arci->ctfi_symdicts = calloc (arci->ctfi_symsect.cts_size
					 / arci->ctfi_symsect.cts_entsize,
					 sizeof (ctf_dict_t *))) == NULL)
	{
	  if (errp)
	    *errp = ENOMEM;
	  return NULL;
	}
    }
  if (!arci->ctfi_symnamedicts)
    {
      if ((arci->ctfi_symnamedicts = ctf_dynhash_create (ctf_hash_string,
							 ctf_hash_eq_string,
							 free, NULL)) == NULL)
	{
	  if (errp)
	    *errp = ENOMEM;
	  return NULL;
	}
    }

  /* Perhaps the dict in which we found a previous lookup is cached.  If it's
     supposed to be cached but we don't find it, pretend it was always not
     found: this should never happen, but shouldn't be allowed to cause trouble
     if it does.  */

  if ((symname && ctf_dynhash_lookup_kv (arci->ctfi_symnamedicts,
					 symname, NULL, &fpkey))
      || (!symname && arci->ctfi_symdicts[symidx] != NULL))
    {
      if (symname)
	fp = (ctf_dict_t *) fpkey;
      else
	fp = arci->ctfi_symdicts[symidx];

      if (fp == &enosym)
	goto no_sym;

      if (symname)
	{
	  if ((type = ctf_lookup_by_symbol_name (fp, symname)) == CTF_ERR)
	    goto cache_no_sym;
	}
      else
	{
	  if ((type = ctf_lookup_by_symbol (fp, symidx)) == CTF_ERR)
	    goto cache_no_sym;
	}

      if (typep)
	*typep = type;
      fp->ctf_refcnt++;
      return fp;
    }

  /* Not cached: find it and cache it.  We must track open errors ourselves even
     if our caller doesn't, to be able to distinguish no-error end-of-iteration
     from open errors.  */

  ctf_error_t local_err;
  ctf_error_t *local_errp;
  ctf_next_t *i = NULL;

  if (errp)
    local_errp = errp;
  else
    local_errp = &local_err;

  while ((fp = ctf_archive_next (arci, &i, NULL, 0, local_errp)) != NULL)
    {
      if (!symname)
	{
	  if ((type = ctf_lookup_by_symbol (fp, symidx)) != CTF_ERR)
	    arci->ctfi_symdicts[symidx] = fp;
	}
      else
	{
	  if ((type = ctf_lookup_by_symbol_name (fp, symname)) != CTF_ERR)
	    {
	      char *tmp;
	      /* No error checking, as above.  */
	      if ((tmp = strdup (symname)) != NULL)
		ctf_dynhash_insert (arci->ctfi_symnamedicts, tmp, fp);
	    }
	}

      if (type != CTF_ERR)
	{
	  if (typep)
	    *typep = type;
	  ctf_next_destroy (i);
	  return fp;
	}
      if (ctf_errno (fp) != ECTF_NOTYPEDAT)
	{
	  if (errp)
	    *errp = ctf_errno (fp);
	  ctf_dict_close (fp);
	  ctf_next_destroy (i);
	  return NULL;				/* errno is set for us.  */
	}
      ctf_dict_close (fp);
    }
  if (*local_errp != ECTF_NEXT_END)
    return NULL;

  /* Don't leak end-of-iteration to the caller.  */
  *local_errp = 0;

 cache_no_sym:
  if (!symname)
    arci->ctfi_symdicts[symidx] = &enosym;
  else
    {
      char *tmp;

      /* No error checking: if caching fails, there is only a slight performance
	 impact.  */
      if ((tmp = strdup (symname)) != NULL)
	if (ctf_dynhash_insert (arci->ctfi_symnamedicts, tmp, &enosym) < 0)
	  free (tmp);
    }

 no_sym:
  if (errp)
    *errp = ECTF_NOTYPEDAT;
  if (typep)
    *typep = CTF_ERR;
  return NULL;
}

/* The public API for looking up a symbol by index.  */
ctf_dict_t *
ctf_arc_lookup_symbol (struct ctf_archive_internal *arci, unsigned long symidx,
		       ctf_id_t *typep, ctf_error_t *errp)
{
  return ctf_arc_lookup_sym_or_name (arci, symidx, NULL, typep, errp);
}

/* The public API for looking up a symbol by name. */

ctf_dict_t *
ctf_arc_lookup_symbol_name (struct ctf_archive_internal *arci, const char *symname,
			    ctf_id_t *typep, ctf_error_t *errp)
{
  return ctf_arc_lookup_sym_or_name (arci, 0, symname, typep, errp);
}

/* Return all enumeration constants with a given NAME across all dicts in an
   archive, similar to ctf_lookup_enumerator_next.  The DICT is cached, so
   opening costs are paid only once, but (unlike ctf_arc_lookup_symbol*
   above) the results of the iterations are not cached.  dict and errp are
   not optional.  */

ctf_id_t
ctf_arc_lookup_enumerator_next (struct ctf_archive_internal *arci,
				const char *name, ctf_next_t **it,
				ctf_enum_value_t *enum_value,
				ctf_dict_t **dict, ctf_error_t *errp)
{
  ctf_next_t *i = *it;
  ctf_id_t type;
  int opened_this_time = 0;
  ctf_error_t err;

  /* We have two nested iterators in here: ctn_next tracks archives, while
     within it ctn_next_inner tracks enumerators within an archive.  We
     keep track of the dict by simply reusing the passed-in arg: if it's
     changed by the caller, the caller will get an ECTF_WRONGFP error,
     so this is quite safe and means we don't have to track the arc and fp
     simultaneously in the ctf_next_t.  */

  if (!i)
    {
      if ((i = ctf_next_create ()) == NULL)
	{
	  err = ENOMEM;
	  goto err;
	}
      i->ctn_iter_fun = (void (*) (void)) ctf_arc_lookup_enumerator_next;
      i->cu.ctn_arc = arci;
      *it = i;
    }

  if ((void (*) (void)) ctf_arc_lookup_enumerator_next != i->ctn_iter_fun)
    {
      err = ECTF_NEXT_WRONGFUN;
      goto err;
    }

  if (arci != i->cu.ctn_arc)
    {
      err = ECTF_NEXT_WRONGFP;
      goto err;
    }

  /* Prevent any earlier end-of-iteration on this dict from confusing the
     test below.  */
  if (i->ctn_next != NULL)
    ctf_set_errno (*dict, 0);

  do
    {
      /* At end of one dict, or not started any iterations yet?
	 Traverse to next dict.  If we never returned this dict to the
	 caller, close it ourselves: the caller will never see it and cannot
	 do so.  */

      if (i->ctn_next == NULL || ctf_errno (*dict) == ECTF_NEXT_END)
	{
	  if (opened_this_time)
	    {
	      ctf_dict_close (*dict);
	      *dict = NULL;
	      opened_this_time = 0;
	    }

	  *dict = ctf_archive_next (arci, &i->ctn_next, NULL, 0, &err);
	  if (!*dict)
	    goto err;
	  opened_this_time = 1;
	}

      type = ctf_lookup_enumerator_next (*dict, name, &i->ctn_next_inner,
					 enum_value);
    }
  while (type == CTF_ERR && ctf_errno (*dict) == ECTF_NEXT_END);

  if (type == CTF_ERR)
    {
      err = ctf_errno (*dict);
      goto err;
    }

  /* If this dict is being reused from the previous iteration, bump its
     refcnt: the caller is going to close it and has no idea that we didn't
     open it this time round.  */
  if (!opened_this_time)
    (*dict)->ctf_refcnt++;

  return type;

 err:						/* Also ECTF_NEXT_END. */
  if (opened_this_time)
    {
      ctf_dict_close (*dict);
      *dict = NULL;
    }

  ctf_next_destroy (i);
  *it = NULL;
  if (errp)
    *errp = err;
  return CTF_ERR;
}

/* Raw iteration over all CTF dicts in an archive: public entry point.

   Returns -EINVAL if not supported for this sort of archive.  */
const char *
ctf_archive_raw_next (const struct ctf_archive_internal *arci, ctf_next_t **it,
		      const void **contents, size_t *len, ctf_error_t *errp)
{
  ctf_next_t *i = *it;
  const char *name;
  size_t offset;
  ctf_error_t err;

  if (arci->ctfi_dict || !arci->ctfi_archive)
    {
      if (errp)
	*errp = EINVAL;
      return NULL;				/* Not supported.  */
    }

  if (!i)
    {
      if ((i = ctf_next_create()) == NULL)
	{
	  if (errp)
	    *errp = ENOMEM;
	  return NULL;
	}
      i->cu.ctn_arc = arci;
      i->ctn_iter_fun = (void (*) (void)) ctf_archive_raw_next;
      i->ctn_size = arci->ctfi_nmemb;
      i->ctn_n = 0;
      *it = i;
    }

  if ((void (*) (void)) ctf_archive_raw_next != i->ctn_iter_fun)
    {
      err = ECTF_NEXT_WRONGFUN;
      goto end;
    }

  if (arci != i->cu.ctn_arc)
    {
      err = ECTF_NEXT_WRONGFP;
      goto end;
    }

  if (i->ctn_n >= i->ctn_size)
    {
      err = ECTF_NEXT_END;
      goto end;
    }

  offset = arci->ctfi_members[i->ctn_n];
  if (contents)
    *contents = &arci->ctfi_archive[offset];
  if (len)
    *len = ctf_arc_get_dict_len (arci, i->ctn_n);

  i->ctn_n++;

  name = ctf_dynhash_lookup (arci->ctfi_member_names, (void *) offset);
  if (name == NULL)
    name = "";

  return name;

 end:
  ctf_next_destroy (i);
  *it = NULL;
  if (errp)
    *errp = err;
  return NULL;
}

/* Iterate over all CTF files in an archive, returning each dict in turn as a
   ctf_dict_t, and NULL on error or end of iteration.  It is the caller's
   responsibility to close it.  Parent dicts may be skipped.

   The archive member is cached for rapid return on future calls.

   We identify v1 parents by name rather than by flag value, which works
   well enough given that the linker always emits parents with the same
   name: for v2, we use the index, because the first dict in an archive is
   always the parent.  */

ctf_dict_t *
ctf_archive_next (const struct ctf_archive_internal *arci, ctf_next_t **it,
		  const char **name, int skip_parent, ctf_error_t *errp)
{
  ctf_dict_t *f;
  ctf_next_t *i = *it;
  const char *name_;
  size_t index;
  ctf_error_t err;

  if (!i)
    {
      if ((i = ctf_next_create()) == NULL)
	{
	  if (errp)
	    *errp = ENOMEM;
	  return NULL;
	}
      i->cu.ctn_arc = arci;
      i->ctn_iter_fun = (void (*) (void)) ctf_archive_next;
      *it = i;
    }

  if ((void (*) (void)) ctf_archive_next != i->ctn_iter_fun)
    {
      err = ECTF_NEXT_WRONGFUN;
      goto end;
    }

  if (arci != i->cu.ctn_arc)
    {
      err = ECTF_NEXT_WRONGFP;
      goto end;
    }

  /* Iteration is made a bit more complex by the need to handle ctf_dict_t's
     transparently wrapped in a single-member archive.  These are parents:
     if skip_parent is on, they are skipped and athe iterator terminates
     immediately.  */

  if (arci->ctfi_dict && i->ctn_n == 0)
    {
      i->ctn_n++;
      if (!skip_parent)
	{
	  arci->ctfi_dict->ctf_refcnt++;
	  if (name)
	    *name = _CTF_SECTION;
	  return arci->ctfi_dict;
	}
    }

  /* The loop keeps going when skip_parent is on as long as the member we find
     is the parent (i.e. at most two iterations, but possibly an early return if
     *all* we have is a parent).  */

  do
    {
      size_t offset;

      if ((arci->ctfi_dict) || (i->ctn_n >= arci->ctfi_nmemb))
	{
	  err = ECTF_NEXT_END;
	  goto end;
	}

      index = i->ctn_n;
      offset = arci->ctfi_members[index];
      name_ = ctf_dynhash_lookup (arci->ctfi_member_names, (void *) offset);
      if (name_ == NULL)
	name_ = "";

      i->ctn_n++;
    }
  while (skip_parent && ((arci->ctfi_v1_hdr && strcmp (name_, _CTF_SECTION) == 0)
			 || index == 0));

  if (name)
    *name = name_;

  f = ctf_dict_open_cached ((ctf_archive_t *) arci, index, errp);
  return f;

 end:
  ctf_next_destroy (i);
  *it = NULL;
  if (errp)
    *errp = err;
  return NULL;
}

/* Pull in the whole file, for reading only.  We assume the current file
   position is at the start of the file.  */
static void *
arc_pread_file (int fd, size_t size)
{
  char *data;

  if ((data = malloc (size)) == NULL)
    return NULL;

  if (ctf_pread (fd, data, size, 0) < 0)
    {
      free (data);
      return NULL;
    }
  return data;
}

#ifdef HAVE_MMAP
/* mmap() the whole file, for reading only.  (Map it writably, but privately: we
   need to modify the region, but don't need anyone else to see the
   modifications.)  */
static void *arc_mmap_file (int fd, size_t size)
{
  void *arc;
  if ((arc = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		   fd, 0)) == MAP_FAILED)
    return NULL;
  return arc;
}

/* Unmap the region.  */
static int arc_mmap_unmap (void *addr, size_t len, const char **errmsg)
{
  if (munmap (addr, len) < 0)
    {
      if (errmsg)
	*errmsg = N_("arc_mmap_unmap(): cannot unmap after writing "
		     "to %s: %s");
      return -1;
    }
    return 0;
}
#else
/* Pull in the whole file, for reading only.  We assume the current file
   position is at the start of the file.  */
static void *arc_mmap_file (int fd, size_t size)
{
  char *data;

  if ((data = malloc (size)) == NULL)
    return NULL;

  if (ctf_pread (fd, data, size, 0) < 0)
    {
      free (data);
      return NULL;
    }
  return data;
}

/* Unmap the region.  */
static int arc_mmap_unmap (void *addr, size_t len _libctf_unused_,
			   const char **errmsg _libctf_unused_)
{
  free (addr);
  return 0;
}
#endif
