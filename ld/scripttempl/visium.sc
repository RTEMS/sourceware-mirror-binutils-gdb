# Copyright (C) 2014-2025 Free Software Foundation, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.

#  Many sections come in three flavours.  There is the 'real' section,
#  like ".data".  Then there are the per-procedure or per-variable
#  sections, generated by -ffunction-sections and -fdata-sections in GCC,
#  and useful for --gc-sections, which for a variable "foo" might be
#  ".data.foo".  Then there are the linkonce sections, for which the linker
#  eliminates duplicates, which are named like ".gnu.linkonce.d.foo".
#  The exact correspondences are:
#
#  Section	Linkonce section
#  .text	.gnu.linkonce.t.foo
#  .rodata	.gnu.linkonce.r.foo
#  .data	.gnu.linkonce.d.foo
#  .bss		.gnu.linkonce.b.foo
#  .sdata	.gnu.linkonce.s.foo
#  .sbss	.gnu.linkonce.sb.foo
#  .sdata2	.gnu.linkonce.s2.foo
#  .sbss2	.gnu.linkonce.sb2.foo
#  .debug_info	.gnu.linkonce.wi.foo
#  .tdata	.gnu.linkonce.td.foo
#  .tbss	.gnu.linkonce.tb.foo
#  .lrodata	.gnu.linkonce.lr.foo
#  .ldata	.gnu.linkonce.l.foo
#  .lbss	.gnu.linkonce.lb.foo
#
#  Each of these can also have corresponding .rel.* and .rela.* sections.

test -z "$ENTRY" && ENTRY=__start
cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}")

ENTRY(${ENTRY})
EOF

test -n "${RELOCATING}" && cat <<EOF
/* Start and end of main stack. Assumes 256K of RAM.  */
_estack = 0xe0040000 - 4;
_sstack = 0xe0040000 - 64K;

/* End of heap.  */
_eheap = _sstack - 4;

MEMORY
{
  init    : ORIGIN = 0x00000000, LENGTH = 0x0003fffc
  scr     : ORIGIN = 0x0003fffc, LENGTH = 0x00000004
  rom     : ORIGIN = 0x00044000, LENGTH = 0x1ffbc000
  ram     : ORIGIN = 0xe0000000, LENGTH = 0x10000000
  saferam : ORIGIN = 0xf0000000, LENGTH = 0x10000000
}

EOF

cat <<EOF
SECTIONS
{
  .init ${RELOCATING-0} : {
    KEEP (*(SORT_NONE(.init)))
    ${RELOCATING+KEEP (*(SORT_NONE(.fini)))}
    ${RELOCATING+ _einit  =  .;}
  } ${RELOCATING+ > init}

  .text ${RELOCATING-0} : {
    ${RELOCATING+ _ftext  =  .;}
    *(.text)
    ${RELOCATING+*(.text.*)}
    ${RELOCATING+*(.gnu.linkonce.t.*)}
    ${RELOCATING+ _etext  =  .;}
  } ${RELOCATING+ > rom}

  .ctors ${RELOCATING-0} : {
    ${CONSTRUCTING+ . = ALIGN(4);}
    ${CONSTRUCTING+ __CTOR_LIST__ = .;}
    /* gcc uses crtbegin.o to find the start of
       the constructors, so we make sure it is
       first.  Because this is a wildcard, it
       doesn't matter if the user does not
       actually link against crtbegin.o; the
       linker won't look for a file to match a
       wildcard.  The wildcard also means that it
       doesn't matter which directory crtbegin.o
       is in.  */

    KEEP (*crtbegin*.o(.ctors))

    /* We don't want to include the .ctor section from
       from the crtend.o file until after the sorted ctors.
       The .ctor section from the crtend file contains the
       end of ctors marker and it must be last.  */

    KEEP (*(EXCLUDE_FILE (*crtend*.o) .ctors))
    ${RELOCATING+KEEP (*(SORT(.ctors.*)))}
    KEEP (*(.ctors))
    ${CONSTRUCTING+ __CTOR_END__ = .;}
  } ${RELOCATING+ > rom}

  .dtors ${RELOCATING-0} : {
    ${CONSTRUCTING+ __DTOR_LIST__ = .;}
    KEEP (*crtbegin*.o(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend*.o) .dtors))
    ${RELOCATING+KEEP (*(SORT(.dtors.*)))}
    KEEP (*(.dtors))
    ${CONSTRUCTING+ __DTOR_END__ = .;}
  } ${RELOCATING+ > rom}
  .rodata ${RELOCATING-0} : {
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ _srdata  =  .;}
    ${RELOCATING+*(.rdata)}
    *(.rodata)
    ${RELOCATING+*(.rodata.*)}
    ${RELOCATING+*(.gnu.linkonce.r.*)}
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ _erdata  =  .;}
  } ${RELOCATING+ > rom}

  .eh_frame ${RELOCATING-0} :
  {
    ${RELOCATING+PROVIDE (__eh_frame_begin = .);}
    *(.eh_frame)
    ${RELOCATING+ LONG (0);}
    ${RELOCATING+PROVIDE (__eh_frame_end = .);}
  } ${RELOCATING+ > rom}
  .gcc_except_table ${RELOCATING-0} : { *(.gcc_except_table) } ${RELOCATING+ > rom}
  .jcr ${RELOCATING-0} : { *(.jcr) } ${RELOCATING+ > rom}

  .data ${RELOCATING-0} : {
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ _sdata  =  .;}
    *(.data)
    ${RELOCATING+*(.data.*)}
    ${RELOCATING+*(.gnu.linkonce.d.*)}
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ _edata  =  .;}
  } ${RELOCATING+ > ram}
  .bss ${RELOCATING-0} : {
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ __bss_start = .;}
    *(.bss)
    ${RELOCATING+*(.bss.*)}
    ${RELOCATING+*(.gnu.linkonce.b.*)}
    ${RELOCATING+*(COMMON)}
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ __bss_end = .;}
    ${RELOCATING+ _sheap = .;}
  } ${RELOCATING+ > ram}

  saferam ${RELOCATING-0} : {
    *(saferam)
    ${RELOCATING+ . = ALIGN(4);}
    ${RELOCATING+ unitidentry = .;}
  } ${RELOCATING+ > saferam}

  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }

  .comment       0 : { *(.comment); LINKER_VERSION; }

EOF

source_sh $srcdir/scripttempl/DWARF.sc

cat <<EOF
}
${RELOCATING+
/* Provide a default address for the simulated file-I/O device.  */
PROVIDE (_sim_fileio_register = 0x2fff0000);

/* Provide a default address for the simulated command line device.  */
PROVIDE (_sim_cmdline_header = 0x2ffe0000);

/* Provide a default address for the simulated 1 MHz clock.  */
PROVIDE (_sim_clock = 0x20002100);}

EOF
