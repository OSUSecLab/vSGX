#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

#include "emusgx.h"
#include "emusgx_arch.h"
#include "emusgx_internal.h"

static void emusgx_eenter(struct emusgx_regs* reg_status, struct pt_regs *regs) {
	// RBX: TCS		enclave
	// RCX: AEP		just a pointer
	void *tcs = (void *)reg_status->rbx;
	void *aep = (void *)reg_status->rcx;
	
	emusgx_enter_enclave(tcs, aep, regs);
}

static void emusgx_eresume(struct emusgx_regs* reg_status, struct pt_regs *regs) {
	// RBX: TCS		enclave
	// RCX: AEP		just a pointer
	void *tcs = (void *)reg_status->rbx;
	void *aep = (void *)reg_status->rcx;
	
	emusgx_resume_enclave(tcs, aep, regs);
}


/*
static void (*emusgx_enclu_handlers[8])(struct emusgx_regs*) = {
	&emusgx_enclu_gp,
	&emusgx_enclu_gp,
	NULL,
	&emusgx_enclu_gp,
	&emusgx_enclu_gp,
	&emusgx_enclu_gp,
	&emusgx_enclu_gp,
	&emusgx_enclu_gp
};*/

void emusgx_handle_enclu(struct emusgx_regs *reg_status, struct pt_regs *regs) {
	if ((uint32_t)(reg_status->rax) <= 7) {
		if ((uint32_t)(reg_status->rax) == EMUSGX_EENTER) {
			emusgx_eenter(reg_status, regs);
		}
		else if ((uint32_t)(reg_status->rax) == EMUSGX_ERESUME) {
			emusgx_eresume(reg_status, regs);
		}
		else {
			emusgx_gp(0, regs);
		}
	}
	else {
		emusgx_gp(0, regs);
	}
}

