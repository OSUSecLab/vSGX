#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/kprobes.h>

#include <linux/interrupt.h>
#include <linux/sched.h>


#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/ptrace.h>

#include "emusgx.h"
#include "emusgx_mm.h"
#include "emusgx_internal.h"
#include "emusgx_cpuid.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shixuan Zhao");
MODULE_DESCRIPTION("EmuSGX guest OS module.");
MODULE_VERSION("0.01");

#define EMUSGX_IRQ 			10

extern asmlinkage void asm_emusgx_exc_invalid_op(void);
extern __visible void emusgx_exc_invalid_op(struct pt_regs *regs);

extern __visible void (*exc_invalid_op_ptr)(struct pt_regs *regs);

#ifdef CONFIG_UPROBES
extern unsigned long (*uprobe_get_trap_addr_ptr)(struct pt_regs *regs); 
#endif

unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
//void (*flush_tlb_mm_range_ptr)(struct mm_struct *mm, unsigned long start, unsigned long end, unsigned long stride_shift, bool freed_tables);

void *error_return_ptr;
void *error_entry_ptr;

int (*set_memory_ro_ptr)(unsigned long addr, int numpages);
int (*set_memory_rw_ptr)(unsigned long addr, int numpages);

asmlinkage void (*asm_exc_invalid_op_ptr)(void);

// EXTREMELY UNWANTED HACK
// handle_page_fault is a static symbol 
// However exc_page_fault contains exception_enter which messes
// with RCU. We have no choice but to use this symbol
extern void (*handle_page_fault_p)(struct pt_regs *regs, unsigned long hw_error_code, unsigned long address);

static gate_desc *idt_table_ptr;

/*
struct idt_data {
	unsigned int	vector;
	unsigned int	segment;
	struct idt_bits	bits;
	const void	*addr;
};*/

static inline void emusgx_idt_init_desc(gate_desc *gate, const struct idt_data *d)
{
	unsigned long addr = (unsigned long) d->addr;

	gate->offset_low	= (u16) addr;
	gate->segment		= (u16) d->segment;
	gate->bits		= d->bits;
	gate->offset_middle	= (u16) (addr >> 16);
#ifdef CONFIG_X86_64
	gate->offset_high	= (u32) (addr >> 32);
	gate->reserved		= 0;
#endif
}

static void
emusgx_idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size)
{
	gate_desc desc;

	for (; size > 0; t++, size--) {
		emusgx_idt_init_desc(&desc, t);
		(*set_memory_rw_ptr)((unsigned long)idt_table_ptr, 1);
		write_idt_entry(idt, t->vector, &desc);
		(*set_memory_ro_ptr)((unsigned long)idt_table_ptr, 1);
	}
}

static void emusgx_set_intr_gate(unsigned int n, const void *addr)
{
	struct idt_data data;

	BUG_ON(n > 0xFF);

	memset(&data, 0, sizeof(data));
	data.vector	= n;
	data.addr	= addr;
	data.segment	= __KERNEL_CS;
	data.bits.type	= GATE_INTERRUPT;
	data.bits.p	= 1;

	emusgx_idt_setup_from_table(idt_table_ptr, &data, 1);
}

static void emusgx_hook_idt(void) {
	error_return_ptr = (void *)(*kallsyms_lookup_name_ptr)("error_return");
	error_entry_ptr = (void *)(*kallsyms_lookup_name_ptr)("error_entry");
	idt_table_ptr = (gate_desc *)(*kallsyms_lookup_name_ptr)("idt_table");
	set_memory_ro_ptr = (void *)(*kallsyms_lookup_name_ptr)("set_memory_ro");
	set_memory_rw_ptr = (void *)(*kallsyms_lookup_name_ptr)("set_memory_rw");
	emusgx_set_intr_gate(X86_TRAP_UD, &asm_emusgx_exc_invalid_op);
}

static void emusgx_unhook_idt(void) {
	asm_exc_invalid_op_ptr = (void *)(*kallsyms_lookup_name_ptr)("asm_exc_invalid_op");
	emusgx_set_intr_gate(X86_TRAP_UD, asm_exc_invalid_op_ptr);
}

static int __kprobes vsgx_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	return 0;
}

unsigned long vsgx_lookup_kallsyms(void) {
	struct kprobe kp;
	int retval;
	memset(&kp, 0, sizeof(struct kprobe));
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = vsgx_handler_pre;
	if ((retval = register_kprobe(&kp)) < 0) {
		printk(KERN_INFO "vSGX: Failed to register kprobe with %d\n", retval);
		return retval;
	}
	printk(KERN_INFO "vSGX: kallsyms_lookup_name@0x%016llX\n", (uint64_t)kp.addr);

	kallsyms_lookup_name_ptr = (void *)(kp.addr);
	unregister_kprobe(&kp);
	return 0;
}

static int __init emusgx_guest_init(void) {
	int err, cpuid_success;
	printk(KERN_INFO "EmuSGX: Initializing guest OS module...\n");
	printk(KERN_INFO "vSGX: Fucking kallsyms...\n");
	if (vsgx_lookup_kallsyms()) {
		printk(KERN_INFO "vSGX: Failed to fuck kallsyms\n");
		return -1;
	}
	handle_page_fault_p = (void *)(*kallsyms_lookup_name_ptr)("handle_page_fault");
	//flush_tlb_mm_range_ptr = (void *)(*kallsyms_lookup_name_ptr)("flush_tlb_mm_range");
	printk(KERN_INFO "EmuSGX: Hooking IDT...\n");
	emusgx_hook_idt();
	printk(KERN_INFO "EmuSGX: IDT hooked. EmuSGX is now running\n");
	err = request_irq(EMUSGX_IRQ, emusgx_irq_handler, 0, "emusgx_irq_response", NULL);
	if (err < 0) {
		pr_info("EmuSGX: Failed to register IRQ handler, err = %d\n", err);
	}
	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_RESET_HYPERVISOR)
		: "%rcx", "%rdx"
	);
	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_RUN_SENDER_KTHREADS)
		: "%rcx", "%rdx"
	);
	if (!cpuid_success) {
		pr_info("EmuSGX: CPUID failed");
	}
	vsgx_switchless_init_locks();
	#ifdef CONFIG_UPROBES
	uprobe_get_trap_addr_ptr = (void *)(*kallsyms_lookup_name_ptr)("uprobe_get_trap_addr");
	#endif
        exc_invalid_op_ptr = (void *)(*kallsyms_lookup_name_ptr)("exc_invalid_op");

	emusgx_init_shared_page();
	vsgx_run_worker_threads();
	return 0;
}

static void __exit emusgx_guest_exit(void) {
	int cpuid_success;
	pr_info("EmuSGX: Exiting...\n");
	free_irq(EMUSGX_IRQ, NULL);
	pr_info("EmuSGX: Freed IRQ\n");
	if (emusgx_receive_page != NULL) {
		emusgx_unshare_page();
	}
	pr_info("EmuSGX: Freed shared page\n");
	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_RESET_HYPERVISOR)
		: "%rcx", "%rdx"
	);
	if (!cpuid_success) {
		pr_info("EmuSGX: CPUID failed");
	}
	printk(KERN_INFO "EmuSGX: Unhooking IDT...\n");
	emusgx_unhook_idt();
	printk(KERN_INFO "vSGX: Stopping worker threads...\n");
	vsgx_stop_worker_threads();
	printk(KERN_INFO "EmuSGX: IDT unhooked. Goodbye\n");
}

module_init(emusgx_guest_init);
module_exit(emusgx_guest_exit);
