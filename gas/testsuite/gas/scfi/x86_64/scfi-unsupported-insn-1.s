# Certain APX instructions are not supported currently
	.text
	.globl	foo
	.type	foo, @function
foo:
        pop2p  %r12, %rax
        pop2   %r12, %rax
        push2  %r12, %rax
        push2p %rax, %r17
	ret
.LFE0:
	.size	foo, .-foo
