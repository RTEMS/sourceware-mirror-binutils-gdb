# Testcase for pushsection directive and SCFI.
        .text
        .globl  foo
        .type   foo, @function
foo:
        .cfi_startproc
        pushq   %r12
        .cfi_def_cfa_offset 16
        .cfi_offset 12, -16
        pushq   %r13
        .cfi_def_cfa_offset 24
        .cfi_offset 13, -24
        subq    $8, %rsp
        .cfi_def_cfa_offset 32
	mov	%rax, %rbx
# The .pushsection directive creates a new code block,
# which must not contribute ginsn to the existing one.
	.pushsection .text2
# For CFI to be synthesized for this block, the user should have
# demarcated the beginning with a .type name, @function
	.cfi_startproc
	subq    $40, %rsp
	.cfi_def_cfa_offset 48
	ret
	.cfi_endproc
	.popsection
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
        popq    %r13
        .cfi_restore 13
        .cfi_def_cfa_offset 16
        popq    %r12
        .cfi_restore 12
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
.LFE0:
        .size   foo, .-foo
