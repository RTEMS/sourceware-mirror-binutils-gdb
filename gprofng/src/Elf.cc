/* Copyright (C) 2021-2025 Free Software Foundation, Inc.
   Contributed by Oracle.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "config.h"
#include <unistd.h>

#include "util.h"
#include "bfd.h"
#include "elf-bfd.h"
#include "Elf.h"
#include "Map.h"
#include "StringBuilder.h"
#include "DbeFile.h"
#include "DbeSession.h"
#include "Dwarf.h"

typedef uint32_t Elf32_Word;
typedef uint32_t Elf64_Word;
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Xword;
typedef int32_t Elf32_Sword;
typedef int64_t Elf64_Sxword;
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

// Ancillary entry
typedef struct
{
  Elf32_Word a_tag;         /* how to interpret value */
  union
  {
    Elf32_Word a_val;
    Elf32_Addr a_ptr;
  } a_un;
} Elf32_Ancillary;

struct S_Elf64_Ancillary
{
  Elf64_Xword a_tag;        /* how to interpret value */
  union
  {
    Elf64_Xword a_val;
    Elf64_Addr a_ptr;
  } a_un;
};

/* Dynamic section entry.  */
typedef struct
{
  Elf32_Sword d_tag;        /* Dynamic entry type */

  union
  {
    Elf32_Word d_val;       /* Integer value */
    Elf32_Addr d_ptr;       /* Address value */
  } d_un;
} Elf32_Dyn;

struct S_Elf64_Dyn
{
  Elf64_Sxword d_tag;       /* Dynamic entry type */

  union
  {
    Elf64_Xword d_val;      /* Integer value */
    Elf64_Addr d_ptr;       /* Address value */
  } d_un;
};

#ifndef DEBUGDIR
#define DEBUGDIR "/lib/debug"
#endif
#ifndef EXTRA_DEBUG_ROOT1
#define EXTRA_DEBUG_ROOT1 "/usr/lib/debug"
#endif
#ifndef EXTRA_DEBUG_ROOT2
#define EXTRA_DEBUG_ROOT2 "/usr/lib/debug/usr"
#endif

static const char *debug_dirs[] = {
  DEBUGDIR, EXTRA_DEBUG_ROOT1, EXTRA_DEBUG_ROOT2, "."
};

template<> void Vector<asymbol *>::dump (const char *msg)
{
  Dprintf (1, NTXT ("\nFile: %s Vector<asymbol *> [%ld]\n"),
	   msg ? msg : "NULL", (long) size ());
  for (long i = 0, sz = size (); i < sz; i++)
    {
      asymbol *sym = get (i);
      Dprintf (1, "  %3ld %s\n", i, sym->name);
    }
}

int Elf::bfd_status = -1;

void
Elf::elf_init ()
{
  if (bfd_status == -1)
    bfd_status = bfd_init ();
}

Elf::Elf (char *filename) : DbeMessages (), Data_window (filename)
{
  ehdrp = NULL;
  data = NULL;
  ancillary_files = NULL;
  elfSymbols = NULL;
  gnu_debug_file = NULL;
  gnu_debugalt_file = NULL;
  sections = NULL;
  dbeFile = NULL;
  abfd = NULL;
  bfd_symcnt = -1;
  bfd_dynsymcnt = -1;
  bfd_synthcnt = -1;
  bfd_sym = NULL;
  bfd_dynsym = NULL;
  bfd_synthsym = NULL;
  synthsym = NULL;

  if (bfd_status != BFD_INIT_MAGIC)
    {
      status = ELF_ERR_CANT_OPEN_FILE;
      return;
    }
  abfd = bfd_openr (filename, NULL);
  if (abfd == NULL)
    {
      status = ELF_ERR_CANT_OPEN_FILE;
      return;
    }
  abfd->flags |= BFD_DECOMPRESS;
  if (!bfd_check_format (abfd, bfd_object))
    {
      bfd_close (abfd);
      abfd = NULL;
      status = ELF_ERR_CANT_OPEN_FILE;
      return;
    }
  ehdrp = elf_getehdr ();
  if (ehdrp == NULL)
    {
      bfd_close (abfd);
      abfd = NULL;
      status = ELF_ERR_BAD_ELF_FORMAT;
      return;
    }
  elf_class = ehdrp->e_ident[EI_CLASS];
  elf_datatype = ehdrp->e_ident[EI_DATA];

  if (not_opened ())
    {
      status = ELF_ERR_CANT_OPEN_FILE;
      return;
    }
  status = ELF_ERR_NONE;

  need_swap_endian = DbeSession::is_bigendian () != bfd_big_endian (abfd);
  analyzerInfo = 0;
  stab = 0;
  stabIndex = 0;
  stabIndexStr = 0;
  stabExcl = 0;
  stabExclStr = 0;
  info = 0;
  plt = 0;
  dwarf = false;

  for (unsigned int sec = 1; sec < elf_getehdr ()->e_shnum; sec++)
    {
      char *name = get_sec_name (sec);
      if (name == NULL)
	continue;
      if (streq (name, NTXT (".stab")))
	stab = sec;
      else if (streq (name, NTXT (".stabstr")))
	stabStr = sec;
      else if (streq (name, NTXT (".stab.index")))
	stabIndex = sec;
      else if (streq (name, NTXT (".stab.indexstr")))
	stabIndexStr = sec;
      else if (streq (name, NTXT (".stab.excl")))
	stabExcl = sec;
      else if (streq (name, NTXT (".stab.exclstr")))
	stabExclStr = sec;
      else if (streq (name, NTXT (".__analyzer_info")))
	analyzerInfo = sec;
      else if (streq (name, NTXT (".info")))
	info = true;
      else if (streq (name, NTXT (".plt")))
	plt = sec;
      else if (strncmp (name, NTXT (".debug"), 6) == 0)
	dwarf = true;
    }
  if (fd != -1)
    {
      close (fd);
      fd = -1;
    }
}

Elf::~Elf ()
{
  if (data)
    {
      for (int i = 0; i < (int) ehdrp->e_shnum; i++)
	{
	  Elf_Data *p = data[i];
	  if (p)
	    {
	      if (p->d_flags & SEC_DECOMPRESSED)
		free (p->d_buf);
	      else if (!mmap_on_file && (p->d_flags & SHF_SUNW_ABSENT) == 0)
		free (p->d_buf);
	      delete p;
	    }
	}
      free (data);
    }
  if (sections)
    {
      for (int i = 0; i < (int) ehdrp->e_shnum; i++)
	delete sections[i];
      free (sections);
    }
  if (ancillary_files)
    {
      ancillary_files->destroy ();
      delete ancillary_files;
    }
  delete elfSymbols;
  delete gnu_debug_file;
  delete gnu_debugalt_file;
  delete dbeFile;
  delete synthsym;
  free (bfd_sym);
  free (bfd_dynsym);
  free (bfd_synthsym);
  if (abfd)
    bfd_close (abfd);
}

Elf_Internal_Ehdr *
Elf::elf_getehdr ()
{
  if (ehdrp == NULL && abfd)
    ehdrp = elf_elfheader (abfd);
  return ehdrp;
}

Elf_Internal_Phdr *
Elf::get_phdr (unsigned int ndx)
{
  if (ehdrp == NULL || ndx >= ehdrp->e_phnum)
    return NULL;
  return &(elf_tdata (abfd)->phdr[ndx]);
}

Elf_Internal_Shdr *
Elf::get_shdr (unsigned int ndx)
{
  if (ehdrp == NULL || ndx >= ehdrp->e_shnum)
    return NULL;
  return elf_elfsections (abfd)[ndx];
}

Elf64_Dyn *
Elf::elf_getdyn (Elf_Internal_Phdr *phdr, unsigned int ndx, Elf64_Dyn *pdyn)
{
  if (elf_getclass () == ELFCLASS32)
    {
      if (ndx * sizeof (Elf32_Dyn) >= phdr->p_filesz)
	return NULL;
      Elf32_Dyn *hdr = (Elf32_Dyn*) bind (phdr->p_offset + ndx * sizeof (Elf32_Dyn),
					  sizeof (Elf32_Dyn));
      if (hdr == NULL)
	return NULL;
      pdyn->d_tag = decode (hdr->d_tag);
      pdyn->d_un.d_val = decode (hdr->d_un.d_val);
    }
  else
    {
      if (ndx * sizeof (Elf64_Dyn) >= phdr->p_filesz)
	return NULL;
      Elf64_Dyn *hdr = (Elf64_Dyn*) bind (phdr->p_offset + ndx * sizeof (Elf64_Dyn),
					  sizeof (Elf64_Dyn));
      if (hdr == NULL)
	return NULL;
      pdyn->d_tag = decode (hdr->d_tag);
      pdyn->d_un.d_val = decode (hdr->d_un.d_val);
    }
  return pdyn;
}

unsigned
Elf::elf_version (unsigned ver)
{
  // We compile locally, no need to check the version
  return ver;
}

Elf *
Elf::elf_begin (char *fname, Elf_status *stp)
{
  if (fname == NULL)
    {
      if (stp)
	*stp = ELF_ERR_CANT_OPEN_FILE;
      return NULL;
    }
  Elf *elf = new Elf (fname);
  if (stp)
    *stp = elf->status;
  if (elf->status != ELF_ERR_NONE)
    {
      delete elf;
      return NULL;
    }
#if DEBUG
  if (DUMP_ELF_SEC)
    {
      char *str = elf->dump ();
      fprintf (stderr, NTXT ("%s\n\n"), str);
      free (str);
    }
#endif /* DEBUG */
  return elf;
}

unsigned int
Elf::elf_get_sec_num (const char *name)
{
  if (name == NULL || ehdrp == NULL)
    return 0;
  for (unsigned int sec = 1; sec < ehdrp->e_shnum; sec++)
    {
      Elf_Internal_Shdr *shdr = get_shdr (sec);
      if (shdr == NULL)
	continue;
      char *sname = elf_strptr (ehdrp->e_shstrndx, shdr->sh_name);
      if (sname != NULL && strcmp (name, sname) == 0)
	return sec;
    }
  return 0;
}

char *
Elf::get_sec_name (unsigned int sec)
{
  Elf_Internal_Shdr *shdr = get_shdr (sec);
  if (ehdrp == NULL || shdr == NULL)
    return NULL;
  return elf_strptr (ehdrp->e_shstrndx, shdr->sh_name);
}

DwrSec *
Elf::get_dwr_section (const char *sec_name)
{
  int sec_num = elf_get_sec_num (sec_name);
  if (sec_num > 0)
    {
      if (sections == NULL)
	{
	  sections = (DwrSec **) xmalloc (ehdrp->e_shnum * sizeof (DwrSec *));
	  for (int i = 0; i < (int) ehdrp->e_shnum; i++)
	    sections[i] = NULL;
	}
      if (sections[sec_num] == NULL)
	{
	  Elf_Data *elfData = elf_getdata (sec_num);
	  if (elfData)
	    sections[sec_num] = new DwrSec ((unsigned char *) elfData->d_buf,
				    elfData->d_size, need_swap_endian,
				    elf_getclass () == ELFCLASS32);
	}
      return sections[sec_num];
    }
  return NULL;
}

Elf_Data *
Elf::elf_getdata (unsigned int sec)
{
  if (sec == 0)
    return NULL;
  if (data == NULL)
    {
      data = (Elf_Data **) xmalloc (ehdrp->e_shnum * sizeof (Elf_Data *));
      for (int i = 0; i < (int) ehdrp->e_shnum; i++)
	data[i] = NULL;
    }
  Elf_Data *edta = data[sec];
  if (edta == NULL)
    {
      Elf_Internal_Shdr *shdr = get_shdr (sec);
      if (shdr == NULL)
	return NULL;
      edta = new Elf_Data;
      data[sec] = edta;
      if ((shdr->sh_flags & SHF_SUNW_ABSENT) != 0)
	{
	  char *sname = get_sec_name (sec);
	  for (int i = 0, sz = VecSize(ancillary_files); i < sz; i++)
	    {
	      Elf *ancElf = ancillary_files->fetch (i);
	      int secNum = sec;
	      if (dbe_strcmp (sname, ancElf->get_sec_name (sec)) != 0)
		{
		  append_msg (CMSG_WARN,
			      "Warning: the section #%d (%s) is mismatch in ancillary file '%s')\n",
			      sec, STR (sname), STR (ancElf->fname));
		  secNum = ancElf->elf_get_sec_num (sname);
		}
	      if (secNum > 0)
		{
		  Elf_Data *ed = ancElf->elf_getdata (secNum);
		  if (ed && ed->d_buf)
		    {
		      *edta = *ed;
		      edta->d_flags |= SHF_SUNW_ABSENT;
		      return edta;
		    }
		}
	    }
	}

      sec_ptr sp = shdr->bfd_section;
      if (sp && bfd_is_section_compressed (abfd, sp))
	{
	  bfd_byte *p = NULL;
	  if (bfd_get_full_section_contents (abfd, sp, &p))
	    {
	      edta->d_buf = p;
	      edta->d_size = p ? sp->size : 0;
	      edta->d_off = 0;
	      edta->d_flags = shdr->sh_flags | SEC_DECOMPRESSED;
	      edta->d_align = shdr->sh_addralign;
	    }
	}
      else
	{
	  edta->d_buf = get_data (shdr->sh_offset, (size_t) shdr->sh_size, NULL);
	  edta->d_flags = shdr->sh_flags;
	  edta->d_size = ((edta->d_buf == NULL) || (shdr->sh_type == SHT_NOBITS)) ? 0 : shdr->sh_size;
	  edta->d_off = shdr->sh_offset;
	  edta->d_align = shdr->sh_addralign;
	}
    }
  return edta;
}

int64_t
Elf::elf_checksum ()
{
  if (ehdrp == NULL)
    return 0;
  int64_t chk = 0;
  for (unsigned int ndx = 0; ndx < ehdrp->e_phnum; ndx++)
    {
      Elf_Internal_Phdr *phdr = get_phdr (ndx);
      if (phdr == NULL)
	continue;
      if (phdr->p_type == PT_DYNAMIC)
	{
	  Elf64_Dyn edyn;
	  for (unsigned int i = 0; elf_getdyn (phdr, i, &edyn) != NULL; i++)
	    {
	      if (!edyn.d_tag)
		break;
	      if (edyn.d_tag == DT_CHECKSUM)
		{
		  chk = edyn.d_un.d_val;
		  break;
		}
	    }
	}
    }
  return normalize_checksum (chk);
}

uint64_t
Elf::get_baseAddr ()
{
  uint64_t addr = 0;
  for (unsigned int pnum = 0; pnum < elf_getehdr ()->e_phnum; pnum++)
    {
      Elf_Internal_Phdr *phdr = get_phdr (pnum);
      if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X))
	{
	  if (addr == 0)
	    addr = phdr->p_vaddr;
	  else
	    {
	      addr = 0;
	      break;
	    }
	}
    }
  return addr;
}

char *
Elf::elf_strptr (unsigned int sec, uint64_t off)
{
  Elf_Data *edta = elf_getdata (sec);
  if (edta && edta->d_buf && edta->d_size > off)
    return ((char *) edta->d_buf) + off;
  return NULL;
}

long
Elf::elf_getSymCount (bool is_dynamic)
{
  if (bfd_dynsym == NULL && bfd_sym == NULL)
    get_bfd_symbols ();
  if (is_dynamic)
    return bfd_dynsymcnt;
  return bfd_symcnt;
}

/* Returns an ASYMBOL on index NDX if it exists.  If DST is defined,
   the internal elf symbol at intex NDX is copied into it.  IS_DYNAMIC
   selects the type of the symbol.  */

asymbol *
Elf::elf_getsym (unsigned int ndx, Elf_Internal_Sym *dst, bool is_dynamic)
{
  asymbol *asym;

  if (bfd_dynsym == NULL && bfd_sym == NULL)
    get_bfd_symbols ();

  if (is_dynamic)
    if (ndx < bfd_dynsymcnt)
      asym = bfd_dynsym[ndx];
    else
      return NULL;
  else
    if (ndx < bfd_symcnt)
      asym = bfd_sym[ndx];
    else
      return NULL;

  if (dst != NULL)
    *dst = ((elf_symbol_type *) asym)->internal_elf_sym;

  return asym;
}

Elf64_Ancillary *
Elf::elf_getancillary (Elf_Data *edta, unsigned int ndx, Elf64_Ancillary *dst)
{
  if (dst == NULL || edta == NULL || edta->d_buf == NULL)
    return NULL;
  if (elf_getclass () == ELFCLASS32)
    {
      Elf32_Ancillary *p = ((Elf32_Ancillary *) edta->d_buf) + ndx;
      dst->a_tag = decode (p->a_tag);
      dst->a_un.a_val = decode (p->a_un.a_val);
    }
  else
    {
      Elf64_Ancillary *p = ((Elf64_Ancillary *) edta->d_buf) + ndx;
      dst->a_tag = decode (p->a_tag);
      dst->a_un.a_val = decode (p->a_un.a_val);
    }
  return dst;
}

Elf *
Elf::get_related_file (const char *lo_name, const char *nm)
{
  DbeFile *df;
  if (*nm == '/')
    {
      df = new DbeFile (nm);
      df->filetype |= (DbeFile::F_FILE | DbeFile::F_DEBUG_FILE);
    }
  else
    {
      char *bname = get_basename (lo_name);
      char *fnm = dbe_sprintf ("%.*s/%s", (int) (bname - lo_name), lo_name, nm);
      df = new DbeFile (fnm);
      df->filetype |= (DbeFile::F_FILE | DbeFile::F_DEBUG_FILE);
      free (fnm);
    }
  Dprintf (DEBUG_STABS, "get_related_file: %s  -> '%s'\n", nm, df->get_name ());
  Elf_status st = ELF_ERR_CANT_OPEN_FILE;
  Elf *elf = elf_begin (df->get_location (), &st);
  if (elf)
    {
      elf->dbeFile = df;
      return elf;
    }
  switch (st)
    {
    case ELF_ERR_CANT_OPEN_FILE:
      append_msg (CMSG_ERROR, GTXT ("Cannot open file `%s'"), df->get_name ());
      break;
    case ELF_ERR_BAD_ELF_FORMAT:
    default:
      append_msg (CMSG_ERROR, GTXT ("Cannot read ELF header of `%s'"),
		  df->get_name ());
      break;
    }
  delete df;
  return NULL;
}

static char *
find_file (char *(bfd_func) (bfd *, const char *), bfd *abfd)
{
  char *fnm = NULL;
  for (size_t i = 0; i < ARR_SIZE (debug_dirs); i++)
    {
      fnm = bfd_func (abfd, debug_dirs[i]);
      if (fnm)
	break;
    }
  Dprintf (DUMP_DWARFLIB, "FOUND: gnu_debug_file: %s --> %s\n",
	   abfd->filename, fnm);
  return fnm;
}

void
Elf::find_gnu_debug_files ()
{
  char *fnm;
  if (gnu_debug_file == NULL)
    {
      fnm = find_file (bfd_follow_gnu_debuglink, abfd);
      if (fnm)
	{
	  gnu_debug_file = Elf::elf_begin (fnm);
	  free (fnm);
	  if (gnu_debug_file)
	    gnu_debug_file->find_gnu_debug_files ();
	}
    }
  if (gnu_debugalt_file == NULL)
    {
      fnm = find_file (bfd_follow_gnu_debugaltlink, abfd);
      if (fnm)
	{
	  gnu_debugalt_file = Elf::elf_begin (fnm);
	  free (fnm);
	}
    }
}

void
Elf::find_ancillary_files (const char *lo_name)
{
  // read the .SUNW_ancillary section
  if (ancillary_files != NULL)
    return;
  unsigned int sec = elf_get_sec_num (".SUNW_ancillary");
  if (sec > 0)
    {
      Elf_Internal_Shdr *shdr = get_shdr (sec);
      uint64_t check_sum = 0;
      char *ancName = NULL;
      if (shdr)
	{
	  Elf_Data *dp = elf_getdata (sec);
	  for (int i = 0, sz = (int) (shdr->sh_size / shdr->sh_entsize);
		  i < sz; i++)
	    {
	      Elf64_Ancillary anc;
	      if (elf_getancillary (dp, i, &anc) == NULL
		  || anc.a_tag == ANC_SUNW_NULL)
		break;
	      if (anc.a_tag == ANC_SUNW_MEMBER)
		ancName = elf_strptr (shdr->sh_link, anc.a_un.a_ptr);
	      else if (anc.a_tag == ANC_SUNW_CHECKSUM)
		{
		  if (i == 0)
		    {
		      check_sum = anc.a_un.a_val;
		      continue;
		    }
		  if (check_sum == anc.a_un.a_val)
		    ancName = NULL;
		  if (ancName)
		    {
		      Elf *ancElf = get_related_file (lo_name, ancName);
		      if (ancElf == NULL)
			continue;
		      int ancSec = ancElf->elf_get_sec_num (".SUNW_ancillary");
		      if (ancSec > 0)
			{
			  Elf_Internal_Shdr *ancHdr = ancElf->get_shdr (ancSec);
			  if (ancHdr)
			    {
			      Elf_Data *anc_dp = ancElf->elf_getdata (ancSec);
			      Elf64_Ancillary anc1;
			      if (ancElf->elf_getancillary (anc_dp, 0, &anc1)
				  && (anc1.a_tag == ANC_SUNW_CHECKSUM) &&
				  anc1.a_un.a_val == anc.a_un.a_val)
				{
				  if (ancillary_files == NULL)
				    ancillary_files = new Vector<Elf*>(2);
				  ancillary_files->append (ancElf);
				}
			      else
				append_msg (CMSG_WARN, GTXT ("Load Object: '%s' (checksum Ox%lld). The .anc file '%s' has checksum Ox%llx"),
					    STR (fname), (long long) check_sum,
					    STR (ancElf->dbeFile->get_location ()),
					    (long long) anc1.a_un.a_val);
			    }
			}
		      ancName = NULL;
		    }
		}
	    }
	}
    }
}

void
Elf::get_bfd_symbols()
{
  if (bfd_symcnt < 0)
    {
      if ((bfd_get_file_flags (abfd) & HAS_SYMS) != 0)
	bfd_symcnt = bfd_get_symtab_upper_bound (abfd);
      if (bfd_symcnt > 0)
	{
	  bfd_sym = (asymbol **) xmalloc (bfd_symcnt);
	  bfd_symcnt = bfd_canonicalize_symtab (abfd, bfd_sym);
	  if (bfd_symcnt < 0)
	    {
	      free (bfd_sym);
	      bfd_sym = NULL;
	    }
	}
      else
	bfd_symcnt = 0;
    }

  if (bfd_dynsymcnt < 0)
    {
      bfd_dynsymcnt = bfd_get_dynamic_symtab_upper_bound (abfd);
      if (bfd_dynsymcnt > 0)
	{
	  bfd_dynsym = (asymbol **) xmalloc (bfd_dynsymcnt);
	  bfd_dynsymcnt = bfd_canonicalize_dynamic_symtab (abfd, bfd_dynsym);
	  if (bfd_dynsymcnt < 0)
	    {
	      free (bfd_dynsym);
	      bfd_dynsym = NULL;
	    }
	}
      else
	bfd_dynsymcnt = 0;
    }
  if (bfd_synthcnt < 0)
    {
      bfd_synthcnt = bfd_get_synthetic_symtab (abfd, bfd_symcnt, bfd_sym,
				bfd_dynsymcnt, bfd_dynsym, &bfd_synthsym);
      if (bfd_synthcnt < 0)
	bfd_synthcnt = 0;
    }
}

static int
cmp_sym_addr (const void *a, const void *b)
{
  asymbol *sym1 = *((asymbol **) a);
  asymbol *sym2 = *((asymbol **) b);
  uint64_t a1 = sym1->value;
  uint64_t a2 = sym2->value;
  if (sym1->section)
    a1 += sym1->section->vma;
  if (sym2->section)
    a2 += sym2->section->vma;
  return a1 < a2 ? -1 : (a1 == a2 ? 0 : 1);
}

const char *
Elf::get_funcname_in_plt (uint64_t pc)
{
  if (synthsym == NULL)
    {
      get_bfd_symbols();
      synthsym = new Vector<asymbol *> (bfd_synthcnt + 1);
      for (long i = 0; i < bfd_synthcnt; i++)
	synthsym->append (bfd_synthsym + i);
      synthsym->sort (cmp_sym_addr);
      if (DUMP_ELF_SYM)
	synthsym->dump (get_location ());
    }

  asymbol sym, *symp = &sym;
  sym.section = NULL;
  sym.value = pc;
  long ind = synthsym->bisearch (0, -1, &symp, cmp_sym_addr);
  if (ind >= 0)
    return synthsym->get (ind)->name;
  return NULL;
}

char*
Elf::get_location ()
{
  return dbeFile ? dbeFile->get_location () : fname;
}

#define RET_S(x)   if (t == x) return (char *) #x

static char *
get_elf_class_name (int t)
{
  RET_S (ELFCLASSNONE);
  RET_S (ELFCLASS32);
  RET_S (ELFCLASS64);
  return NTXT ("ELFCLASS_UNKNOWN");
}

static char *
get_elf_data_name (int t)
{
  RET_S (ELFDATANONE);
  RET_S (ELFDATA2LSB);
  RET_S (ELFDATA2MSB);
  return NTXT ("ELFDATA_UNKNOWN");
}

static char *
get_elf_osabi_name (int t)
{
  RET_S (ELFOSABI_NONE);
  RET_S (ELFOSABI_HPUX);
  RET_S (ELFOSABI_NETBSD);
  RET_S (ELFOSABI_LINUX);
  RET_S (ELFOSABI_SOLARIS);
  RET_S (ELFOSABI_AIX);
  RET_S (ELFOSABI_IRIX);
  RET_S (ELFOSABI_FREEBSD);
  RET_S (ELFOSABI_TRU64);
  RET_S (ELFOSABI_MODESTO);
  RET_S (ELFOSABI_OPENBSD);
  return NTXT ("ELFOSABI_UNKNOWN");
}

static char *
get_elf_etype_name (int t)
{
  RET_S (ET_NONE);
  RET_S (ET_REL);
  RET_S (ET_EXEC);
  RET_S (ET_DYN);
  RET_S (ET_CORE);
  RET_S (ET_LOPROC);
  RET_S (ET_HIPROC);
  return NTXT ("ETYPE_UNKNOWN");
}

static char *
get_elf_ptype_name (int t)
{
  RET_S (PT_NULL);
  RET_S (PT_LOAD);
  RET_S (PT_DYNAMIC);
  RET_S (PT_INTERP);
  RET_S (PT_NOTE);
  RET_S (PT_SHLIB);
  RET_S (PT_PHDR);
  RET_S (PT_TLS);
  RET_S (PT_LOOS);
  RET_S (PT_GNU_EH_FRAME);
  RET_S (PT_GNU_EH_FRAME);
  RET_S (PT_HIOS);
  RET_S (PT_LOPROC);
  RET_S (PT_HIPROC);
  return NTXT ("PTYPE_UNKNOWN");
}

static char *
get_elf_shtype_name (unsigned int t)
{
  RET_S (SHT_NULL);
  RET_S (SHT_PROGBITS);
  RET_S (SHT_SYMTAB);
  RET_S (SHT_STRTAB);
  RET_S (SHT_RELA);
  RET_S (SHT_HASH);
  RET_S (SHT_DYNAMIC);
  RET_S (SHT_NOTE);
  RET_S (SHT_NOBITS);
  RET_S (SHT_REL);
  RET_S (SHT_SHLIB);
  RET_S (SHT_DYNSYM);
  RET_S (SHT_INIT_ARRAY);
  RET_S (SHT_FINI_ARRAY);
  RET_S (SHT_PREINIT_ARRAY);
  RET_S (SHT_GROUP);
  RET_S (SHT_SYMTAB_SHNDX);
  RET_S (SHT_LOOS);
  RET_S (SHT_SUNW_verdef);
  RET_S (SHT_SUNW_verneed);
  RET_S (SHT_HIOS);
  RET_S (SHT_LOPROC);
  RET_S (SHT_HIPROC);
  RET_S (SHT_LOUSER);
  RET_S (SHT_HIUSER);
  return NTXT ("SHTYPE_UNKNOWN");
}

static char *
get_elf_machine_name (int t)
{
  RET_S (EM_NONE);
  RET_S (EM_M32);
  RET_S (EM_SPARC);
  RET_S (EM_386);
  RET_S (EM_68K);
  RET_S (EM_88K);
  RET_S (EM_860);
  RET_S (EM_MIPS);
  RET_S (EM_S370);
  RET_S (EM_MIPS_RS3_LE);
  RET_S (EM_SPARC32PLUS);
  RET_S (EM_960);
  RET_S (EM_PPC);
  RET_S (EM_PPC64);
  RET_S (EM_V800);
  RET_S (EM_FR20);
  RET_S (EM_RH32);
  RET_S (EM_RCE);
  RET_S (EM_ARM);
  RET_S (EM_ALPHA);
  RET_S (EM_SH);
  RET_S (EM_SPARCV9);
  RET_S (EM_TRICORE);
  RET_S (EM_ARC);
  RET_S (EM_H8_300);
  RET_S (EM_H8_300H);
  RET_S (EM_H8S);
  RET_S (EM_H8_500);
  RET_S (EM_IA_64);
  RET_S (EM_MIPS_X);
  RET_S (EM_COLDFIRE);
  RET_S (EM_68HC12);
  RET_S (EM_MMA);
  RET_S (EM_PCP);
  RET_S (EM_NCPU);
  RET_S (EM_NDR1);
  RET_S (EM_STARCORE);
  RET_S (EM_ME16);
  RET_S (EM_ST100);
  RET_S (EM_TINYJ);
  RET_S (EM_X86_64);
  RET_S (EM_PDSP);
  RET_S (EM_FX66);
  RET_S (EM_ST9PLUS);
  RET_S (EM_ST7);
  RET_S (EM_68HC16);
  RET_S (EM_68HC11);
  RET_S (EM_68HC08);
  RET_S (EM_68HC05);
  RET_S (EM_SVX);
  RET_S (EM_ST19);
  RET_S (EM_VAX);
  RET_S (EM_CRIS);
  RET_S (EM_JAVELIN);
  RET_S (EM_FIREPATH);
  RET_S (EM_ZSP);
  RET_S (EM_MMIX);
  RET_S (EM_HUANY);
  RET_S (EM_PRISM);
  RET_S (EM_AVR);
  RET_S (EM_FR30);
  RET_S (EM_D10V);
  RET_S (EM_D30V);
  RET_S (EM_V850);
  RET_S (EM_M32R);
  RET_S (EM_MN10300);
  RET_S (EM_MN10200);
  RET_S (EM_PJ);
  RET_S (EM_OPENRISC);
  RET_S (EM_XTENSA);
  return NTXT ("ELFMACHINE_UNKNOWN");
}

static char *
get_elf_version_name (int t)
{
  RET_S (EV_NONE);
  RET_S (EV_CURRENT);
  return NTXT ("VERSION_UNKNOWN");
}

static char *
get_elf_ancillary_tag (int t)
{
  RET_S (ANC_SUNW_NULL);
  RET_S (ANC_SUNW_CHECKSUM);
  RET_S (ANC_SUNW_MEMBER);
  RET_S (ANC_SUNW_NUM);
  return NTXT ("ANCILLARY_TAG_UNKNOWN");
}

#define ADD_S(x)    if ((f & (x)) == (x)) { sb->append(' '); sb->append(#x); f &= ~(x); }

static void
dump_sh_flags (StringBuilder *sb, long long flags)
{
  long long f = flags;
  if (f != 0)
    {
      sb->append (NTXT (" ["));
      ADD_S (SHF_WRITE)
      ADD_S (SHF_ALLOC)
      ADD_S (SHF_EXECINSTR)
      ADD_S (SHF_MERGE)
      ADD_S (SHF_STRINGS)
      ADD_S (SHF_INFO_LINK)
      ADD_S (SHF_LINK_ORDER)
      ADD_S (SHF_OS_NONCONFORMING)
      ADD_S (SHF_GROUP)
      ADD_S (SHF_TLS)
      ADD_S (SHF_SUNW_ABSENT)
      ADD_S (SHF_EXCLUDE)
      if (f != 0 && f != flags)
	sb->appendf (NTXT (" 0x%llx"), (long long) f);
      sb->append (NTXT (" ]"));
    }
  sb->append (NTXT ("\n"));
}

static void
dump_p_flags (StringBuilder *sb, long long flags)
{
  long long f = flags;
  if (f != 0)
    {
      sb->append (NTXT (" ["));
      ADD_S (PF_X)
      ADD_S (PF_W)
      ADD_S (PF_R)
      ADD_S (PF_MASKPROC)
      if (f != 0 && f != flags)
	sb->appendf (NTXT (" 0x%llx"), (long long) f);
      sb->append (NTXT (" ]"));
    }
  sb->append (NTXT ("\n"));
}

char *
Elf::dump ()
{
  StringBuilder sb;
  sb.sprintf (NTXT ("ELF Header: %s\n"), fname ? fname : GTXT ("(unknown)"));
  if (ehdrp == NULL)
    {
      sb.appendf (GTXT ("\n\n Cannot read Elf header\n"));
      return sb.toString ();
    }
  sb.appendf (NTXT ("  %-15s "), NTXT ("e_ident"));
  for (int i = 0; i < EI_NIDENT; i++)
    sb.appendf (NTXT ("%x"), ehdrp->e_ident[i]);
  sb.append (NTXT ("\n"));
  char *fmt0 = NTXT ("  %-15s %10lld ( %s )\n");
  char *fmt1 = NTXT ("  %-15s 0x%08llx ( %lld )\n");
  char *fmt2 = NTXT ("  %-15s 0x%08llx");
  sb.appendf (fmt0, NTXT ("EI_CLASS"), (long long) ehdrp->e_ident[EI_CLASS],
	      get_elf_class_name (ehdrp->e_ident[EI_CLASS]));
  sb.appendf (fmt0, NTXT ("EI_DATA"), (long long) ehdrp->e_ident[EI_DATA],
	      get_elf_data_name (ehdrp->e_ident[EI_DATA]));
  sb.appendf (fmt0, NTXT ("EI_OSABI"), (long long) ehdrp->e_ident[EI_OSABI],
	      get_elf_osabi_name (ehdrp->e_ident[EI_OSABI]));
  sb.appendf (fmt0, NTXT ("e_type"), (long long) ehdrp->e_type,
	      get_elf_etype_name (ehdrp->e_type));
  sb.appendf (fmt0, NTXT ("e_machine"), (long long) ehdrp->e_machine,
	      get_elf_machine_name (ehdrp->e_machine));
  sb.appendf (fmt0, NTXT ("e_version"), (long long) ehdrp->e_version,
	      get_elf_version_name (ehdrp->e_version));
  sb.appendf (fmt1, NTXT ("e_entry"), (long long) ehdrp->e_entry,
	      (long long) ehdrp->e_entry);
  sb.appendf (fmt1, NTXT ("e_phoff"), (long long) ehdrp->e_phoff,
	      (long long) ehdrp->e_phoff);
  sb.appendf (fmt1, NTXT ("e_shoff"), (long long) ehdrp->e_shoff,
	      (long long) ehdrp->e_shoff);
  sb.appendf (fmt1, NTXT ("e_flags"), (long long) ehdrp->e_flags,
	      (long long) ehdrp->e_flags);
  sb.appendf (fmt1, NTXT ("e_ehsize"), (long long) ehdrp->e_ehsize,
	      (long long) ehdrp->e_ehsize);
  sb.appendf (fmt1, NTXT ("e_phentsize"), (long long) ehdrp->e_phentsize,
	      (long long) ehdrp->e_phentsize);
  sb.appendf (fmt1, NTXT ("e_phnum"), (long long) ehdrp->e_phnum,
	      (long long) ehdrp->e_phnum);
  sb.appendf (fmt1, NTXT ("e_shentsize"), (long long) ehdrp->e_shentsize,
	      (long long) ehdrp->e_shentsize);
  sb.appendf (fmt1, NTXT ("e_shnum"), (long long) ehdrp->e_shnum,
	      (long long) ehdrp->e_shnum);
  sb.appendf (fmt1, NTXT ("e_shstrndx"), (long long) ehdrp->e_shstrndx,
	      (long long) ehdrp->e_shstrndx);

  for (unsigned int i = 0; i < ehdrp->e_phnum; i++)
    {
      sb.appendf (NTXT ("\nProgram Header[%d]:\n"), i);
      Elf_Internal_Phdr *phdr = get_phdr (i);
      if (phdr == NULL)
	{
	  sb.appendf (NTXT ("      ERROR: get_phdr(%d) failed\n"), i);
	  continue;
	}
      sb.appendf (fmt0, "p_type", (long long) phdr->p_type,
		  get_elf_ptype_name (phdr->p_type));
      sb.appendf (fmt2, "p_flags", (long long) phdr->p_flags);
      dump_p_flags (&sb, phdr->p_flags);
      sb.appendf (fmt1, "p_offset", (long long) phdr->p_offset,
		  (long long) phdr->p_offset);
      sb.appendf (fmt1, "p_vaddr", (long long) phdr->p_vaddr,
		  (long long) phdr->p_vaddr);
      sb.appendf (fmt1, "p_paddr", (long long) phdr->p_paddr,
		  (long long) phdr->p_paddr);
      sb.appendf (fmt1, "p_filesz", (long long) phdr->p_filesz,
		  (long long) phdr->p_filesz);
      sb.appendf (fmt1, "p_memsz", (long long) phdr->p_memsz,
		  (long long) phdr->p_memsz);
      sb.appendf (fmt1, "p_align", (long long) phdr->p_align,
		  (long long) phdr->p_align);
    }

  for (unsigned int i = 1; i < ehdrp->e_shnum; i++)
    {
      sb.appendf (NTXT ("\nSection Header[%d]:\n"), i);
      Elf_Internal_Shdr *shdr = get_shdr (i);
      if (shdr == NULL)
	{
	  sb.appendf (NTXT ("      ERROR: get_shdr(%d) failed\n"), i);
	  continue;
	}
      char *s = get_sec_name (i);
      sb.appendf (fmt0, "sh_name", (long long) shdr->sh_name,
		  s ? s : NTXT ("NULL"));
      sb.appendf (fmt0, "sh_type", (long long) shdr->sh_type,
		  get_elf_shtype_name (shdr->sh_type));
      sb.appendf (fmt2, "sh_flags", (long long) shdr->sh_flags);
      dump_sh_flags (&sb, shdr->sh_flags);
      sb.appendf (fmt1, "sh_addr", (long long) shdr->sh_addr,
		  (long long) shdr->sh_addr);
      sb.appendf (fmt1, "sh_offset", (long long) shdr->sh_offset,
		  (long long) shdr->sh_offset);
      sb.appendf (fmt1, "sh_size", (long long) shdr->sh_size,
		  (long long) shdr->sh_size);
      sb.appendf (fmt1, "sh_link", (long long) shdr->sh_link,
		  (long long) shdr->sh_link);
      sb.appendf (fmt1, "sh_info", (long long) shdr->sh_info,
		  (long long) shdr->sh_info);
      sb.appendf (fmt1, "sh_addralign", (long long) shdr->sh_addralign,
		  (long long) shdr->sh_addralign);
      sb.appendf (fmt1, "sh_entsize", (long long) shdr->sh_entsize,
		  (long long) shdr->sh_entsize);
    }

  for (unsigned int i = 1; i < ehdrp->e_shnum; i++)
    {
      Elf_Internal_Shdr *shdr = get_shdr (i);
      if (shdr == NULL)
	continue;
      char *secName = get_sec_name (i);
      if (secName == NULL)
	continue;
      if (strcmp (NTXT (".SUNW_ancillary"), secName) == 0)
	{
	  sb.appendf (NTXT ("\nSection[%d]:  %s\n"), i, secName);
	  Elf_Data *dp = elf_getdata (i);
	  for (int j = 0, cnt = (int) (shdr->sh_size / shdr->sh_entsize);
		  j < cnt; j++)
	    {
	      Elf64_Ancillary anc;
	      if (elf_getancillary (dp, j, &anc) == NULL)
		break;
	      sb.appendf (NTXT ("%10d  %-20s 0x%08llx %6lld"), j,
			  get_elf_ancillary_tag ((int) anc.a_tag),
			  (long long) anc.a_un.a_ptr, (long long) anc.a_un.a_ptr);
	      if (anc.a_tag == ANC_SUNW_MEMBER)
		sb.appendf (NTXT ("  %s\n"), STR (elf_strptr (shdr->sh_link, anc.a_un.a_ptr)));
	      else
		sb.append (NTXT ("\n"));
	    }
	}
    }
  return sb.toString ();
}

void
Elf::dump_elf_sec ()
{
  if (!DUMP_ELF_SEC)
    return;
  if (ehdrp == NULL)
    return;
  Dprintf (DUMP_ELF_SEC, "======= DwarfLib::dump_elf_sec\n"
	   " N |type|flags|  sh_addr | sh_offset | sh_size | sh_link |"
	   " sh_info | sh_addralign | sh_entsize | sh_name | name\n");
  for (unsigned int sec = 1; sec < ehdrp->e_shnum; sec++)
    {
      Elf_Internal_Shdr *shdr = get_shdr (sec);
      if (shdr == NULL)
	continue;
      char *name = elf_strptr (ehdrp->e_shstrndx, shdr->sh_name);
      Dprintf (DUMP_ELF_SEC, "%3d:%3d |%4d |%9lld | %9lld |%8lld |%8lld |"
	       "%8lld |%14d |%11lld | %6lld %s\n",
	       sec, (int) shdr->sh_type, (int) shdr->sh_flags,
	       (long long) shdr->sh_addr, (long long) shdr->sh_offset,
	       (long long) shdr->sh_size, (long long) shdr->sh_link,
	       (long long) shdr->sh_info,
	       (int) shdr->sh_addralign, (long long) shdr->sh_entsize,
	       (long long) shdr->sh_name, name ? name : NTXT ("NULL"));
    }
  Dprintf (DUMP_ELF_SEC, NTXT ("\n"));
}
