#as: --scfi=experimental -W
#as:
#objdump: --sframe
#name: Synthesize CFI with .cfi_sections
#...
Contents of the SFrame section .sframe:
  Header :

    Version: SFRAME_VERSION_2
    Flags: SFRAME_F_FDE_FUNC_START_PCREL
    CFA fixed RA offset: \-8
    Num FDEs: 1
    Num FREs: 5

  Function Index :

    func idx \[0\]: pc = 0x0, size = 12 bytes
    STARTPC + CFA + FP + RA +
    0+0000 +sp\+8 +u +f +
    0+0001 +sp\+16 +c\-16 +f +
    0+0004 +fp\+16 +c-16 +f +
    0+000a +sp\+16 +c\-16 +f +
    0+000b +sp\+8 +u +f +

#pass
