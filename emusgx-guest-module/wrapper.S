#include <linux/linkage.h>

#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/page_types.h>
#include <asm/irqflags.h>
#include <asm/paravirt.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/pgtable_types.h>
#include <asm/export.h>
#include <asm/frame.h>
#include <asm/nospec-branch.h>
#include <linux/err.h>

#include <linux/jump_label.h>
#include <asm/unwind_hints.h>
#include <asm/cpufeatures.h>
#include <asm/page_types.h>
#include <asm/percpu.h>
#include <asm/asm-offsets.h>
#include <asm/processor-flags.h>
#include "calling.h"

#include <asm/trapnr.h>

.code64
.section .entry.text, "ax"

/*
 * A wrapper for error_return and error_entry
 */

SYM_CODE_START_LOCAL(error_return_wrapper)
	subq 	$16, %rsp		/* reserve 2 qword space on stack */ 
	movq	%rax, (%rsp)		/* (%rsp) for %eax */
	movq	error_return_ptr, %rax	/* move pointer to register */
	movq	%rax, 8(%rsp)		/* 8(%rsp) for the return address */
	popq	%rax
	ret				/* goto error_exit */
SYM_CODE_END(error_return_wrapper)

SYM_CODE_START_LOCAL(error_entry_wrapper)
	subq 	$16, %rsp		/* reserve 2 qword space on stack */ 
	movq	%rax, (%rsp)		/* (%rsp) for %eax */
	movq	error_entry_ptr, %rax	/* move pointer to register */
	movq	%rax, 8(%rsp)		/* 8(%rsp) for the return address */
	popq	%rax
	ret				/* goto error_entry */
SYM_CODE_END(error_entry_wrapper)

/**
 * idtentry_body - Macro to emit code calling the C function
 * @cfunc:		C function to be called
 * @has_error_code:	Hardware pushed error code on stack
 */
.macro idtentry_body cfunc has_error_code:req

	call	error_entry_wrapper
	UNWIND_HINT_REGS

	movq	%rsp, %rdi			/* pt_regs pointer into 1st argument*/

	.if \has_error_code == 1
		movq	ORIG_RAX(%rsp), %rsi	/* get error code into 2nd argument*/
		movq	$-1, ORIG_RAX(%rsp)	/* no syscall to restart */
	.endif

	call	\cfunc

	jmp	error_return_wrapper
.endm


/**
 * idtentry - Macro to generate entry stubs for simple IDT entries
 * @vector:		Vector number
 * @asmsym:		ASM symbol for the entry point
 * @cfunc:		C function to be called
 * @has_error_code:	Hardware pushed error code on stack
 *
 * The macro emits code to set up the kernel context for straight forward
 * and simple IDT entries. No IST stack, no paranoid entry checks.
 */
.macro idtentry vector asmsym cfunc has_error_code:req
SYM_CODE_START(\asmsym)
	UNWIND_HINT_IRET_REGS offset=\has_error_code*8
	ASM_CLAC

	.if \has_error_code == 0
		pushq	$-1			/* ORIG_RAX: no syscall to restart */
	.endif

	.if \vector == X86_TRAP_BP
		/*
		 * If coming from kernel space, create a 6-word gap to allow the
		 * int3 handler to emulate a call instruction.
		 */
		testb	$3, CS-ORIG_RAX(%rsp)
		jnz	.Lfrom_usermode_no_gap_\@
		.rept	6
		pushq	5*8(%rsp)
		.endr
		UNWIND_HINT_IRET_REGS offset=8
.Lfrom_usermode_no_gap_\@:
	.endif

	idtentry_body \cfunc \has_error_code

_ASM_NOKPROBE(\asmsym)
SYM_CODE_END(\asmsym)
.endm

idtentry	X86_TRAP_UD	asm_emusgx_exc_invalid_op	emusgx_exc_invalid_op	has_error_code=0
