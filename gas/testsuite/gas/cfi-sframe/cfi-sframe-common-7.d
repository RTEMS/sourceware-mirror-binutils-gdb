#as: --gsframe
#objdump: --sframe=.sframe
#name: SFrame cfi_rel_offset test
#...
Contents of the SFrame section .sframe:

  Header :

    Version: SFRAME_VERSION_2
    Flags: SFRAME_F_FDE_FUNC_START_PCREL
#?    CFA fixed FP offset: \-?\d+
#?    CFA fixed RA offset: \-?\d+
    Num FDEs: 1
    Num FREs: 3

  Function Index :
    func idx \[0\]: pc = 0x0, size = 12 bytes
    STARTPC + CFA + FP + RA +
#...
    0+0004 +sp\+8 +u +[uf] +
    0+0008 +sp\+8 +u +[uf] +

#pass
