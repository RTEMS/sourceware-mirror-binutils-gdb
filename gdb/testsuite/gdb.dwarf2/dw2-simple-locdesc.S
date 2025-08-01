/* This testcase is part of GDB, the GNU debugger.

   Copyright 2011-2025 Free Software Foundation, Inc.

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

/* This source file was generated by:
   echo 'struct s { char a[1<<24]; int b; } s;' \
   | gcc -dA -o dw2-simple-locdesc.S -S -gdwarf-2 -x c -
   */
	.text
var:

	.section	.debug_info
.Ldebug_info0:
d:
	.4byte	.Lcu_end - 1f	/* Length of Compilation Unit Info */
1:
	.2byte	0x3	/* DWARF version number */
	.4byte	.Ldebug_abbrev0	/* Offset Into Abbrev. Section */
	.byte	0x4	/* Pointer Size (in bytes) */
	.uleb128 0x1	/* (DIE (0xb) DW_TAG_compile_unit) */
	.4byte	.LASF2	/* DW_AT_producer: "GNU C 4.7.0 20110727 (experimental)" */
	.byte	0x1	/* DW_AT_language */
.Ldie19:
	.uleb128 0x2	/* (DIE (0x19) DW_TAG_structure_type) */
	.ascii "s\0"	/* DW_AT_name */
	.4byte	0x1000004	/* DW_AT_byte_size */
	.byte	0x1	/* DW_AT_decl_file (<stdin>) */
	.byte	0x1	/* DW_AT_decl_line */
.Ldie30:
	.uleb128 0x4	/* (DIE (0x30) DW_TAG_member) */
	.ascii "data4\0"	/* DW_AT_name */
	.byte	0x1	/* DW_AT_decl_file (<stdin>) */
	.byte	0x1	/* DW_AT_decl_line */
	.4byte	.Ldie62 - d	/* DW_AT_type */
	.4byte	0x10000	/* DW_AT_data_member_location */
.Ldie32:
	.uleb128 0x3	/* (DIE (0x32) DW_TAG_member) */
	.ascii "shl\0"	/* DW_AT_name */
	.byte	0x1	/* DW_AT_decl_file (<stdin>) */
	.byte	0x1	/* DW_AT_decl_line */
	.4byte	.Ldie62 - d	/* DW_AT_type */
	.byte	0x4	/* DW_AT_data_member_location */
	.byte	0x40	/* DW_OP_lit16 */
	.byte	0x44	/* DW_OP_lit20 */
	.byte	0x24	/* DW_OP_shl */
	.byte	0x22	/* DW_OP_plus */
	.byte	0	/* end of children of DIE 0x19 */
.Ldie62:
	.uleb128 0x7	/* (DIE (0x62) DW_TAG_base_type) */
	.byte	0x4	/* DW_AT_byte_size */
	.byte	0x5	/* DW_AT_encoding */
	.ascii "int\0"	/* DW_AT_name */
.Ldie69:
	.uleb128 0x8	/* (DIE (0x69) DW_TAG_variable) */
	.ascii "s\0"	/* DW_AT_name */
	.byte	0x1	/* DW_AT_decl_file (<stdin>) */
	.byte	0x1	/* DW_AT_decl_line */
	.4byte	.Ldie19 - d	/* DW_AT_type */
	.byte	0x1	/* DW_AT_external */
	.byte	2f - 1f	/* DW_AT_location */
1:
	.byte	0x3	/* DW_OP_addr */
	.4byte	var
2:
	.byte	0	/* end of children of DIE 0xb */
.Lcu_end:
	.section	.debug_abbrev
.Ldebug_abbrev0:
	.uleb128 0x1	/* (abbrev code) */
	.uleb128 0x11	/* (TAG: DW_TAG_compile_unit) */
	.byte	0x1	/* DW_children_yes */
	.uleb128 0x25	/* (DW_AT_producer) */
	.uleb128 0xe	/* (DW_FORM_strp) */
	.uleb128 0x13	/* (DW_AT_language) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.byte	0
	.byte	0
	.uleb128 0x2	/* (abbrev code) */
	.uleb128 0x13	/* (TAG: DW_TAG_structure_type) */
	.byte	0x1	/* DW_children_yes */
	.uleb128 0x3	/* (DW_AT_name) */
	.uleb128 0x8	/* (DW_FORM_string) */
	.uleb128 0xb	/* (DW_AT_byte_size) */
	.uleb128 0x6	/* (DW_FORM_data4) */
	.uleb128 0x3a	/* (DW_AT_decl_file) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3b	/* (DW_AT_decl_line) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.byte	0
	.byte	0
	.uleb128 0x3	/* (abbrev code) */
	.uleb128 0xd	/* (TAG: DW_TAG_member) */
	.byte	0	/* DW_children_no */
	.uleb128 0x3	/* (DW_AT_name) */
	.uleb128 0x8	/* (DW_FORM_string) */
	.uleb128 0x3a	/* (DW_AT_decl_file) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3b	/* (DW_AT_decl_line) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x49	/* (DW_AT_type) */
	.uleb128 0x13	/* (DW_FORM_ref4) */
	.uleb128 0x38	/* (DW_AT_data_member_location) */
	.uleb128 0xa	/* (DW_FORM_block1) */
	.byte	0
	.byte	0
	.uleb128 0x4	/* (abbrev code) */
	.uleb128 0xd	/* (TAG: DW_TAG_member) */
	.byte	0	/* DW_children_no */
	.uleb128 0x3	/* (DW_AT_name) */
	.uleb128 0x8	/* (DW_FORM_string) */
	.uleb128 0x3a	/* (DW_AT_decl_file) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3b	/* (DW_AT_decl_line) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x49	/* (DW_AT_type) */
	.uleb128 0x13	/* (DW_FORM_ref4) */
	.uleb128 0x38	/* (DW_AT_data_member_location) */
	.uleb128 0x6	/* (DW_FORM_data4) */
	.byte	0
	.byte	0
	.uleb128 0x7	/* (abbrev code) */
	.uleb128 0x24	/* (TAG: DW_TAG_base_type) */
	.byte	0	/* DW_children_no */
	.uleb128 0xb	/* (DW_AT_byte_size) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3e	/* (DW_AT_encoding) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3	/* (DW_AT_name) */
	.uleb128 0x8	/* (DW_FORM_string) */
	.byte	0
	.byte	0
	.uleb128 0x8	/* (abbrev code) */
	.uleb128 0x34	/* (TAG: DW_TAG_variable) */
	.byte	0	/* DW_children_no */
	.uleb128 0x3	/* (DW_AT_name) */
	.uleb128 0x8	/* (DW_FORM_string) */
	.uleb128 0x3a	/* (DW_AT_decl_file) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x3b	/* (DW_AT_decl_line) */
	.uleb128 0xb	/* (DW_FORM_data1) */
	.uleb128 0x49	/* (DW_AT_type) */
	.uleb128 0x13	/* (DW_FORM_ref4) */
	.uleb128 0x3f	/* (DW_AT_external) */
	.uleb128 0xc	/* (DW_FORM_flag) */
	.uleb128 0x2	/* (DW_AT_location) */
	.uleb128 0xa	/* (DW_FORM_block1) */
	.byte	0
	.byte	0
	.byte	0
#ifdef __arm__
	.section	.debug_str,"MS",%progbits,1
#else
	.section	.debug_str,"MS",@progbits,1
#endif
.LASF2:
	.string	"GNU C 4.7.0 20110727 (experimental)"
.LASF0:
	.string	"sizetype"
.LASF1:
	.string	"char"
#ifdef __arm__
	.section	.note.GNU-stack,"",%progbits
#else
	.section	.note.GNU-stack,"",@progbits
#endif
