#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/tlbflush.h>
#include <asm/io.h>

#include "emusgx.h"
#include "emusgx_sender.h"
#include "emusgx_internal.h"
#include "emusgx_debug.h"

// EXTREMELY UNWANTED HACK
// handle_page_fault is a static symbol 
// However exc_page_fault contains exception_enter which messes
// with RCU. We have no choice but to use this symbol
void (*handle_page_fault_p)(struct pt_regs *regs, unsigned long hw_error_code, unsigned long address);

void vsgx_handle_aex(struct pt_regs *regs, struct vsgx_exit_info *exit_info) {
	// Checks about exit_info
	// Then do fault handlers according to exit_info->exception_code
	// Note that here regs is already the synthetic state

	switch (exit_info->exception_code) {
	case 14:
		// PF
		(*handle_page_fault_p)(regs, exit_info->error_code, exit_info->fault_addr);
		break;
	default:
		// Shit happened
		emusgx_gp(0, regs);
	}
}

