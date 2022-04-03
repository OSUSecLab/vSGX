#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/atomic.h>

#include <asm/traps.h>
#include <asm/desc.h>
#include <asm/segment.h>

#include "emusgx.h"
#include "emusgx_internal.h"
#include "emusgx_mm.h"

atomic_t emusgx_alrady_inited = (atomic_t)ATOMIC_INIT(0);

extern unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
__visible void (*exc_invalid_op_ptr)(struct pt_regs *regs);

#ifdef CONFIG_UPROBES
unsigned long (*uprobe_get_trap_addr_ptr)(struct pt_regs *regs);
#define IP ((void __user *)(*uprobe_get_trap_addr_ptr)(regs))
#else
#define IP ((void __user *)uprobe_get_trap_addr(regs))
#endif

#define VSGX_CHEAT_GET_SECS		0
#define VSGX_CHEAT_MAP_EPC		1
#define VSGX_CHEAT_UNMAP_EPC		2
#define VSGX_CHEAT_MAP_EPC2		3

extern unsigned long vsgx_vma_get_user_paddr(struct mm_struct *mm, unsigned long vaddr);
extern uint64_t vsgx_cheat_secs;

__visible noinstr void emusgx_exc_invalid_op(struct pt_regs *regs, long error_code) {
	// Handle the SGX instructions
	void *rip;
	uint8_t opcode_prefix = 0;
	uint8_t opcode_primary = 0;
	uint8_t opcode_secondary = 0;
	struct emusgx_regs reg_status;
	uint8_t still_ud = 1;
	uint8_t opcode_buffer[3];
	uint64_t in_kernel_va;

	//mm_segment_t old_fs = get_fs();

	rip = (void *)(regs->ip);

	if (user_mode(regs)) {
		if (copy_from_user(opcode_buffer, rip, 3)) {
			pr_err("vSGX: Failed to retrive user opcode @ 0x%016llX\n", (uint64_t)rip);
			goto direct_error;
		}
	}
	else {
		if (copy_from_kernel_nofault(opcode_buffer, rip, 3)) {
			pr_err("vSGX: Failed to retrive code @ 0x%016llX\n", (uint64_t)rip);
			goto direct_error;
		}
	}
	opcode_prefix = opcode_buffer[0];
	opcode_primary = opcode_buffer[1];
	opcode_secondary = opcode_buffer[2];
	if (opcode_prefix == 0x0F &&
		opcode_primary == 0x01) {
		reg_status.rax = (uint32_t)regs->ax;
		reg_status.rbx = regs->bx;
		reg_status.rcx = regs->cx;
		reg_status.rdx = regs->dx;
		reg_status.eflags = regs->flags;
		if (opcode_secondary == 0xD7) {
			// pr_info("SGX: trapped. not bad instruction, continued\n");
			//set_fs(KERNEL_DS);
			emusgx_handle_enclu(&reg_status, regs);
			//set_fs(old_fs);
			still_ud = 0;
		}
		if (opcode_secondary == 0xCF) {
			// pr_info("SGX: trapped. not bad instruction, continued\n");
			//set_fs(KERNEL_DS);
			still_ud = emusgx_handle_encls(&reg_status, regs);
			//set_fs(old_fs);
		}

		if (!still_ud) {
			// if not still UD, we can return now
			if (reg_status.rax == EMUSGX_EENTER || reg_status.rax == EMUSGX_ERESUME) {
				// EENTER/ERESUME has setup the regs for us. We can simply return now
				return;
			}
			regs->ax = reg_status.rax;
			regs->bx = reg_status.rbx;
			regs->cx = reg_status.rcx;
			regs->dx = reg_status.rdx;
			regs->flags = reg_status.eflags;
			regs->ip += 3;
			return;
		}
		if (opcode_secondary == 0xEB) { // esgxmgr: EmuSGX register enclave user program
			if (atomic_xchg(&emusgx_alrady_inited, 1) != 0) {
				pr_err("vSGX: You cannot register two apps\n");
				regs->ax = -1;
				regs->ip += 3;
				return;
			}
			if (regs->ax == 0) {
				// Register it self
				emusgx_init_shared_page();
			}
			else {
				// Unregister it self
				emusgx_unshare_page();
			}
			regs->ax = 0;
			regs->ip += 3;
			return;
		}
		/*if (opcode_secondary == 0xEC) { // esgxsl: EmuSGX Switchless Page Syncing
			// DOES NOT EXPECT TO RETURN

			// The switchless page syncing process
			emusgx_switchless_sync_worker();
			
			regs->ax = -1;
			regs->ip += 3;
			return;
		}
		
		if (opcode_secondary == 0xED) { // esgxes: EmuSGX Dispatcher
			// DOES NOT EXPECT TO RETURN

			emusgx_dispatcher();

			// Only possible to be here when SIGKILL is issued
			regs->ax = -1; 
			regs->ip += 3;
			return;
		}*/
		if (opcode_secondary == 0xEE) { // esgxcheat: Calls to get cheat cheat data for testing purpose
			regs->ip += 3;
			if (regs->ax == VSGX_CHEAT_GET_SECS) {
				regs->ax = 0;
				regs->bx = (uint64_t)vsgx_cheat_secs;
				return;
			}
			else if (regs->ax == VSGX_CHEAT_MAP_EPC) {
				in_kernel_va = (uint64_t)ioremap_cache(vsgx_vma_get_user_paddr(current->mm, regs->bx), 4096);
				if (in_kernel_va == 0) {
					regs->ax = -1;
				}
				else {
					regs->ax = 0;
				}
				regs->bx = in_kernel_va;
				return;
			}
			else if (regs->ax == VSGX_CHEAT_UNMAP_EPC) {
				iounmap((void *)regs->bx);
				regs->ax = 0;
				return;
			}
			else if (regs->ax == VSGX_CHEAT_MAP_EPC2) {
			    in_kernel_va = (uint64_t)ioremap_cache(regs->bx, 4096);
			    if (in_kernel_va == 0) {
			        regs->ax = -1;
			    }
			    else {
			        regs->ax = 0;
			    }
			    regs->bx = in_kernel_va;
			    return;
			}
			regs->ax = -1;
			return;
		}
		// else go UD
	}

	// Call the do_invalid_op if not SGX
	pr_err("vSGX: Still bad instruction. %02X %02X %02X\n", opcode_prefix, opcode_primary, opcode_secondary);
direct_error:
	(*exc_invalid_op_ptr)(regs);
}
