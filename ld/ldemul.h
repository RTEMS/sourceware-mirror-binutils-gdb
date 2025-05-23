/* ld-emul.h - Linker emulation header file
   Copyright (C) 1991-2025 Free Software Foundation, Inc.

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

#ifndef LDEMUL_H
#define LDEMUL_H

/* Forward declaration for ldemul_add_options() and others.  */
struct option;

extern void ldemul_hll
  (char *);
extern void ldemul_syslib
  (char *);
extern void ldemul_after_parse
  (void);
extern void ldemul_before_parse
  (void);
extern void ldemul_before_plugin_all_symbols_read
  (void);
extern void ldemul_after_open
  (void);
extern void ldemul_after_check_relocs
  (void);
extern void ldemul_before_place_orphans
  (void);
extern void ldemul_after_allocation
  (void);
extern void ldemul_before_allocation
  (void);
extern void ldemul_set_output_arch
  (void);
extern char *ldemul_choose_target
  (int, char**);
extern void ldemul_choose_mode
  (char *);
extern void ldemul_list_emulations
  (FILE *);
extern void ldemul_list_emulation_options
  (FILE *);
extern char *ldemul_get_script
  (int *isfile);
extern void ldemul_finish
  (void);
extern void ldemul_set_symbols
  (void);
extern void ldemul_create_output_section_statements
  (void);
extern lang_output_section_statement_type *ldemul_place_orphan
  (asection *, const char *, int);
extern bool ldemul_parse_args
  (int, char **);
extern void ldemul_add_options
  (int, char **, int, struct option **, int, struct option **);
extern bool ldemul_handle_option
  (int);
extern bool ldemul_unrecognized_file
  (struct lang_input_statement_struct *);
extern bool ldemul_recognized_file
  (struct lang_input_statement_struct *);
extern bool ldemul_open_dynamic_archive
  (const char *, struct search_dirs *, struct lang_input_statement_struct *);
extern char *ldemul_default_target
  (int, char**);
extern void after_parse_default
  (void);
extern void after_open_default
  (void);
extern void after_check_relocs_default
  (void);
extern void before_place_orphans_default
  (void);
extern void after_allocation_default
  (void);
extern void before_allocation_default
  (void);
extern void finish_default
  (void);
extern void finish_default
  (void);
extern void set_output_arch_default
  (void);
extern void syslib_default
  (char*);
extern void hll_default
  (char*);
extern int  ldemul_find_potential_libraries
  (char *, struct lang_input_statement_struct *);
extern struct bfd_elf_version_expr *ldemul_new_vers_pattern
  (struct bfd_elf_version_expr *);
extern void ldemul_extra_map_file_text
  (bfd *, struct bfd_link_info *, FILE *);
/* Return 1 if we are emitting CTF early, and 0 if ldemul_examine_strtab_for_ctf
   will be called by the target.  */
extern int ldemul_emit_ctf_early
  (void);
/* Called from per-target code to examine the strtab and symtab.  */
extern void ldemul_acquire_strings_for_ctf
  (struct ctf_dict *, struct elf_strtab_hash *);
extern void ldemul_new_dynsym_for_ctf
  (struct ctf_dict *, int symidx, struct elf_internal_sym *);
extern bool ldemul_print_symbol
  (struct bfd_link_hash_entry *hash_entry, void *ptr);
extern struct bfd_link_hash_entry * ldemul_find_alt_start_symbol
  (struct bfd_sym_chain *);

typedef struct ld_emulation_xfer_struct {
  /* Run before parsing the command line and script file.
     Set the architecture, maybe other things.  */
  void   (*before_parse) (void);

  /* Handle the SYSLIB (low level library) script command.  */
  void   (*syslib) (char *);

  /* Handle the HLL (high level library) script command.  */
  void   (*hll) (char *);

  /* Run after parsing the command line and script file.  */
  void   (*after_parse) (void);

  /* Run before calling plugin 'all symbols read' hook.  */
  void   (*before_plugin_all_symbols_read)  (void);

  /* Run after opening all input files, and loading the symbols.  */
  void   (*after_open) (void);

  /* Run after checking relocations.  */
  void   (*after_check_relocs)  (void);

  /* Run before placing orphans.  */
  void   (*before_place_orphans)  (void);

  /* Run after allocating output sections.  */
  void   (*after_allocation)  (void);

  /* Set the output architecture and machine if possible.  */
  void   (*set_output_arch) (void);

  /* Decide which target name to use.  */
  char * (*choose_target) (int, char**);

  /* Run before allocating output sections.  */
  void   (*before_allocation) (void);

  /* Return the appropriate linker script.  */
  char * (*get_script) (int *isfile);

  /* The name of this emulation.  */
  char *emulation_name;

  /* The output format.  */
  char *target_name;

  /* Run after assigning values from the script.  */
  void	(*finish) (void);

  /* Create any output sections needed by the target.  */
  void	(*create_output_section_statements) (void);

  /* Try to open a dynamic library.  ARCH is an architecture name, and
     is normally the empty string.  ENTRY is the lang_input_statement
     that should be opened.  */
  bool (*open_dynamic_archive)
    (const char *arch, struct search_dirs *,
     struct lang_input_statement_struct *entry);

  /* Place an orphan section.  Return TRUE if it was placed, FALSE if
     the default action should be taken.  This field may be NULL, in
     which case the default action will always be taken.  */
  lang_output_section_statement_type *(*place_orphan)
    (asection *, const char *, int);

  /* Run after assigning parsing with the args, but before
     reading the script.  Used to initialize symbols used in the script.  */
  void	(*set_symbols) (void);

  /* Parse args which the base linker doesn't understand.
     Return TRUE if the arg needs no further processing.  */
  bool (*parse_args) (int, char **);

  /* Hook to add options to parameters passed by the base linker to
     getopt_long and getopt_long_only calls.  */
  void (*add_options)
    (int, char **, int, struct option **, int, struct option **);

  /* Companion to the above to handle an option.  Returns TRUE if it is
     one of our options.  */
  bool (*handle_option) (int);

  /* Run to handle files which are not recognized as object files or
     archives.  Return TRUE if the file was handled.  */
  bool (*unrecognized_file)
    (struct lang_input_statement_struct *);

  /* Run to list the command line options which parse_args handles.  */
  void (* list_options) (FILE *);

  /* Run to specially handle files which *are* recognized as object
     files or archives.  Return TRUE if the file was handled.  */
  bool (*recognized_file)
    (struct lang_input_statement_struct *);

  /* Called when looking for libraries in a directory specified
     via a linker command line option or linker script option.
     Files that match the pattern "lib*.a" have already been scanned.
     (For VMS files matching ":lib*.a" have also been scanned).  */
  int (* find_potential_libraries)
    (char *, struct lang_input_statement_struct *);

  /* Called when adding a new version pattern.  PowerPC64-ELF uses
     this hook to add a pattern matching ".foo" for every "foo".  */
  struct bfd_elf_version_expr * (*new_vers_pattern)
    (struct bfd_elf_version_expr *);

  /* Called when printing the map file, in case there are
     emulation-specific sections for it.  */
  void (*extra_map_file_text)
    (bfd *, struct bfd_link_info *, FILE *);

  /* If this returns true, we emit CTF as early as possible: if false, we emit
     CTF once the strtab and symtab are laid out.  */
  int (*emit_ctf_early)
    (void);

  /* Called to examine the string table late enough in linking that it is
     finally laid out.  If emit_ctf_early returns true, this is not called, and
     ldemul_maybe_emit_ctf emits CTF in 'early' mode: otherwise, it waits
     until 'late'. (Late mode needs explicit support at per-target link time to
     get called at all).  If set, called by ld when the examine_strtab
     bfd_link_callback is invoked by per-target code.  */
  void (*acquire_strings_for_ctf) (struct ctf_dict *, struct elf_strtab_hash *);

  /* Called when a new symbol is added to the dynamic symbol table.  If
     emit_ctf_early returns true, this is not called, and ldemul_maybe_emit_ctf
     emits CTF in 'early' mode: otherwise, it waits until 'late'. (Late mode
     needs explicit support at per-target link time to get called at all).  If
     set, called by ld when the ctf_new_symbol bfd_link_callback is invoked by
     per-target code.  Called with a NULL symbol when no further symbols will be
     provided.  */
  void (*new_dynsym_for_ctf) (struct ctf_dict *, int, struct elf_internal_sym *);

  /* Called when printing a symbol to the map file.   AIX uses this
     hook to flag gc'd symbols.  */
  bool (*print_symbol)
    (struct bfd_link_hash_entry *hash_entry, void *ptr);

  /* Called when ENTRY->name cannot be found by a direct lookup in INFO->hash.
     Allows emulations to try variations of the name.  */
  struct bfd_link_hash_entry * (*find_alt_start_symbol)
    (struct bfd_sym_chain *entry);

} ld_emulation_xfer_type;

typedef enum {
  intel_ic960_ld_mode_enum,
  default_mode_enum,
  intel_gld960_ld_mode_enum
} lang_emulation_mode_enum_type;

extern ld_emulation_xfer_type *ld_emulations[];

#endif
