#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

#include <asm/traps.h>
#include <asm/siginfo.h>

void emusgx_gp(int code, struct pt_regs *ptrace_regs) {
	pr_info("EmuSGX: General Protection Fault happened to this thread. Kill with SEGV\n");
	force_sig(SIGSEGV);
}

void emusgx_pf(void __user *addr, struct pt_regs *ptrace_regs) {
	// A bad page fault causes an SIGSEGV
	pr_info("EmuSGX: Bad Page Fault happened to this thread. Kill with SEGV\n");
	force_sig(SIGSEGV);
}