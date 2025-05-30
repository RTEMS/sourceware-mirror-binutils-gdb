/* SPARC ELF specific backend routines.
   Copyright (C) 2005-2025 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

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

#include "elf/common.h"
#include "elf/internal.h"

struct _bfd_sparc_elf_section_data
{
  struct bfd_elf_section_data elf;
  unsigned int do_relax, reloc_count;
};

#define sec_do_relax(sec) \
  ((struct _bfd_sparc_elf_section_data *) elf_section_data (sec))->do_relax
#define canon_reloc_count(sec) \
  ((struct _bfd_sparc_elf_section_data *) elf_section_data (sec))->reloc_count

struct _bfd_sparc_elf_app_reg
{
  unsigned char bind;
  unsigned short shndx;
  bfd *abfd;
  char *name;
};

/* Sparc ELF linker hash table.  */

struct _bfd_sparc_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cut to get to dynamic linker sections.  */
  asection *interp;

  union
  {
    bfd_signed_vma refcount;
    bfd_vma offset;
  } tls_ldm_got;

  /* Used by local STT_GNU_IFUNC symbols.  */
  htab_t loc_hash_table;
  void *loc_hash_memory;

  /* The (unloaded but important) .rela.plt.unloaded section, for VxWorks.  */
  asection *srelplt2;

  void (*put_word) (bfd *, bfd_vma, void *);
  bfd_vma (*r_info) (Elf_Internal_Rela *, bfd_vma, bfd_vma);
  bfd_vma (*r_symndx) (bfd_vma);
  int (*build_plt_entry) (bfd *, asection *, bfd_vma, bfd_vma, bfd_vma *);
  const char *dynamic_interpreter;
  int dynamic_interpreter_size;
  unsigned int word_align_power;
  unsigned int align_power_max;
  unsigned int plt_header_size;
  unsigned int plt_entry_size;
  int bytes_per_word;
  int bytes_per_rela;
  int dtpoff_reloc;
  int dtpmod_reloc;
  int tpoff_reloc;

  struct _bfd_sparc_elf_app_reg app_regs [4];
};

/* Get the SPARC ELF linker hash table from a link_info structure.  */

#define _bfd_sparc_elf_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == SPARC_ELF_DATA)	\
   ? (struct _bfd_sparc_elf_link_hash_table *) (p)->hash : NULL)

extern reloc_howto_type *_bfd_sparc_elf_reloc_type_lookup
  (bfd *, bfd_reloc_code_real_type);
extern reloc_howto_type *_bfd_sparc_elf_reloc_name_lookup
  (bfd *, const char *);
extern bool _bfd_sparc_elf_info_to_howto
  (bfd *, arelent *, Elf_Internal_Rela *);
extern reloc_howto_type *_bfd_sparc_elf_info_to_howto_ptr
  (bfd*, unsigned int);
extern bool _bfd_sparc_elf_mkobject
  (bfd *);
extern struct bfd_link_hash_table *_bfd_sparc_elf_link_hash_table_create
  (bfd *);
extern bool _bfd_sparc_elf_create_dynamic_sections
  (bfd *, struct bfd_link_info *);
extern void _bfd_sparc_elf_copy_indirect_symbol
  (struct bfd_link_info *,
   struct elf_link_hash_entry *,
   struct elf_link_hash_entry *);
extern bool _bfd_sparc_elf_check_relocs
  (bfd *, struct bfd_link_info *,
   asection *, const Elf_Internal_Rela *);
extern asection *_bfd_sparc_elf_gc_mark_hook
  (asection *, struct bfd_link_info *,
   Elf_Internal_Rela *, struct elf_link_hash_entry *,
   Elf_Internal_Sym *);
extern bool _bfd_sparc_elf_adjust_dynamic_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *);
extern bool _bfd_sparc_elf_omit_section_dynsym
  (bfd *, struct bfd_link_info *, asection *);
extern bool _bfd_sparc_elf_late_size_sections
  (bfd *, struct bfd_link_info *);
extern bool _bfd_sparc_elf_new_section_hook
  (bfd *, asection *);
extern bool _bfd_sparc_elf_relax_section
  (bfd *, struct bfd_section *, struct bfd_link_info *, bool *);
extern int _bfd_sparc_elf_relocate_section
  (bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
   Elf_Internal_Rela *, Elf_Internal_Sym *, asection **);
extern bool _bfd_sparc_elf_finish_dynamic_symbol
  (bfd *, struct bfd_link_info *, struct elf_link_hash_entry *,
   Elf_Internal_Sym *sym);
extern bool _bfd_sparc_elf_finish_dynamic_sections
  (bfd *, struct bfd_link_info *);
extern bool _bfd_sparc_elf_fixup_symbol
  (struct bfd_link_info *, struct elf_link_hash_entry *);
extern bool _bfd_sparc_elf_object_p
  (bfd *);
extern bfd_vma _bfd_sparc_elf_plt_sym_val
  (bfd_vma, const asection *, const arelent *);
extern bool _bfd_sparc_elf_merge_private_bfd_data
  (bfd *, struct bfd_link_info *);
