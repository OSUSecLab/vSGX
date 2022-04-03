#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "emusgx.h"
#include "emusgx_arch.h"
#include "emusgx_internal.h"
#include "emusgx_debug.h"

uint64_t vsgx_cheat_secs = 0;

static int eadd_counter = 0;
static int eextend_counter = 0;

static void emusgx_ecreate(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> pageinfo		user
	// RCX -> secs page in EPC	enclave
	struct sgx_pageinfo __user *tmp_pageinfo = (void __user *)(reg_status->rbx);
	void *epc_page = (void *)(reg_status->rcx);
	void __user *tmp_srcpge;
	struct sgx_secinfo __user *tmp_secinfo;
	int i;
	uint8_t tmp_result;

	uint64_t time_0;

	time_0 = ktime_get_real_ns();
	emusgx_debug_print("vSGX: enter ecreate\n");
	vsgx_cheat_secs = reg_status->rcx;
	__uaccess_begin();
	tmp_srcpge = (void *)tmp_pageinfo->srcpage;
	tmp_secinfo = (void *)tmp_pageinfo->secinfo;
	__uaccess_end();

	pr_info("vSGX: ECREATE 0x%016llX, 0x%016llX\n", reg_status->rbx, reg_status->rcx);
	
	// Enclave alignment must be enforced
	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	__uaccess_begin();

	if (tmp_pageinfo->linaddr != 0 || tmp_pageinfo->secs != 0) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}

	// Check for misconfigured SECINFO flags
	for (i = 0; i < 7; i++) {
		if (tmp_secinfo->reserved[i] != 0) {
			__uaccess_end();
			emusgx_gp(0, fault_regs);
			return;
		}
	}
	if (tmp_secinfo->flags.page_type != SGX_PT_SECS) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}

	__uaccess_end();

	tmp_result = emusgx_validate_and_do_remote_for_ecreate(tmp_srcpge, epc_page);
	if (tmp_result == 1) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	if (tmp_result == 2) {
		emusgx_gp(0, fault_regs);
		return;
	}
	pr_info("vSGX: ECREATE %lld\n", ktime_get_real_ns() - time_0);

}

static void emusgx_eadd(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RCX -> EPC page in enclave
	void *epc_page = (void *)(reg_status->rcx);
	struct sgx_pageinfo __user *tmp_pageinfo = (void *)(reg_status->rbx);
	struct sgx_secinfo *scratch_secinfo;
	void *tmp_srcpge;
	uint8_t tmp_result = 0;

	void *arg_secs;
	void *arg_linaddr;

	//uint64_t time_0 = ktime_get_real_ns();
	eadd_counter += 1;

	__uaccess_begin();
	scratch_secinfo = (void *)(tmp_pageinfo->secinfo);
	tmp_srcpge = (void *)(tmp_pageinfo->srcpage);
	arg_secs = (void *)tmp_pageinfo->secs;
	arg_linaddr = (void *)tmp_pageinfo->linaddr;
	__uaccess_end();

	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	__uaccess_begin();
	if (tmp_pageinfo->srcpage % 4096 != 0 || tmp_pageinfo->secs % 4096 != 0 || tmp_pageinfo->linaddr % 4096 != 0) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}

	// Check secinfo
	if (scratch_secinfo->flags.page_type != SGX_PT_REG && scratch_secinfo->flags.page_type != SGX_PT_TCS) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}
	__uaccess_end();

	tmp_result = emusgx_validate_and_do_remote_for_eadd(arg_secs, epc_page, arg_linaddr, tmp_srcpge, scratch_secinfo);
	if (tmp_result == 1) {
		emusgx_pf(arg_secs, fault_regs);
		return;
	}
	if (tmp_result == 2) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	if (tmp_result == 3) {
		emusgx_gp(0, fault_regs);
		return;
	}

	/*if (eadd_counter < 20) {
		pr_info("vSGX: EADD %lld\n", ktime_get_real_ns() - time_0);
		eadd_counter += 1;
	}*/
}

static void emusgx_einit(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> sigstruct 	user
	// RCX -> secs 		enclave
	// RDX -> einittoken 	user
	struct sgx_sigstruct __user *tmp_sigstruct = (void __user *)reg_status->rbx;
	uint64_t time_0 = ktime_get_real_ns();

	pr_info("vSGX DEBUG: EADD COUNTER = %d\n", eadd_counter);
	pr_info("vSGX DEBUG: EEXTEND COUNTER = %d\n", eextend_counter);
	eadd_counter = 0;
	eextend_counter = 0;

	//pr_info("vSGX: EINIT 0x%016llX 0x%016llX, 0x%016llX\n", reg_status->rbx, reg_status->rcx, reg_status->rdx);
	
	// make sure SIGSTRUCT and SECS are aligned 
	if (reg_status->rbx % 4096 != 0 || reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// make sure the EINITTOKEN is aligned
	if (reg_status->rdx % 256 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// Verify SIGSTRUCT Header
	__uaccess_begin();
	// This is like... totally shitty
	// Intel's reference is documenting these constants using
	// little endian???
	if (tmp_sigstruct->header[0] != 0x000000E100000006 ||
		tmp_sigstruct->header[1] != 0x0000000000010000) {
		pr_info("EmuSGX: EINIT failed due to header1\n");
		__uaccess_end();
		reg_status->flags.ZF = 1;
		reg_status->rax = EMUSGX_INVALID_SIG_STRUCT;
		goto EXIT;
	}

	if ((tmp_sigstruct->vendor != 0 && tmp_sigstruct->vendor != 0x00008086)) {
		pr_info("EmuSGX: EINIT failed due to vendor\n");
		__uaccess_end();
		reg_status->flags.ZF = 1;
		reg_status->rax = EMUSGX_INVALID_SIG_STRUCT;
		goto EXIT;
	}
	
	if (tmp_sigstruct->header2[0] != 0x0000006000000101 ||
		tmp_sigstruct->header2[1] != 0x0000000100000060) {
		pr_info("EmuSGX: EINIT failed due to header2\n");
		pr_info("EmuSGX: header2[0] = 0x%016llX\n", tmp_sigstruct->header2[0]);
		pr_info("EmuSGX: header2[1] = 0x%016llX\n", tmp_sigstruct->header2[1]);
		__uaccess_end();
		reg_status->flags.ZF = 1;
		reg_status->rax = EMUSGX_INVALID_SIG_STRUCT;
		goto EXIT;
	}

	if (tmp_sigstruct->exponent != 0x00000003) {
		pr_info("EmuSGX: EINIT failed due to exponent\n");
		__uaccess_end();
		reg_status->flags.ZF = 1;
		reg_status->rax = EMUSGX_INVALID_SIG_STRUCT;
		goto EXIT;
	}
	__uaccess_end();

	// Verify signature - Done remotely

	// go remote
	reg_status->rax = emusgx_validate_and_do_remote_for_einit(tmp_sigstruct, (void *)reg_status->rcx, (void __user *)reg_status->rdx);
	if (reg_status->rax != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
	
	if (reg_status->rax == EMUSGX_GP) {
		emusgx_gp(0, fault_regs);
		return;
	}
	else if (reg_status->rax == EMUSGX_PF_RCX) {
		emusgx_pf((void *)reg_status->rcx, fault_regs);
		return;
	}
	else if (reg_status->rax == EMUSGX_PF_RDX) {
		emusgx_pf((void *)reg_status->rdx, fault_regs);
		return;
	}

EXIT:
	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
	
	pr_info("vSGX: EINIT %lld\n", ktime_get_real_ns() - time_0);
}

static void emusgx_eremove(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RCX -> EPC page to be removed	enclave
	void *epc_page = (void *)reg_status->rcx;

	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// In the manual here the processor treats
	// RBX as pageinfo. While a pageinfo is never
	// used in this instruction nor gets mentioned
	// before

	// Ignored all RBX related

	reg_status->rax = emusgx_validate_and_do_remote_for_eremove(epc_page);
	if (reg_status->rax != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
	else {
		reg_status->flags.ZF = 0;
	}
	
	if (reg_status->rax == EMUSGX_GP) {
		emusgx_gp(0, fault_regs);
		return;
	}
	else if (reg_status->rax == EMUSGX_PF_RCX) {
		emusgx_pf((void *)reg_status->rcx, fault_regs);
		return;
	}

	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
}

static void emusgx_eextend(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RCX -> EPC address points to a 256B block	enclave
	void *epc_addr = (void *)reg_status->rcx;
	uint8_t tmp_result;
	//uint64_t time_0 = ktime_get_real_ns();

	eextend_counter += 1;

	// Enforce in-enclave alignment
	if (reg_status->rcx % 256 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// Do update MRENCLAVE
	tmp_result = emusgx_validate_and_do_remote_for_eextend(epc_addr);
	if (tmp_result == 1) {
		emusgx_pf(epc_addr, fault_regs);
		return;
	}
	if (tmp_result == 2) {
		emusgx_gp(0, fault_regs);
		return;
	}

	
	/*if (eextend_counter < 20) {
		pr_info("vSGX: EEXTEND %lld\n", ktime_get_real_ns() - time_0);
		eextend_counter += 1;
	}*/
}

static void emusgx_eldb_eldu(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> pageinfo			user
	// RCX -> EPC page			enclave
	// RDX -> version array slot		enclave

	uint8_t block = (((uint32_t)(reg_status->rax) == 7) ? 1 : 0);
	struct sgx_pageinfo __user *tmp_pageinfo = (void __user *)reg_status->rbx;
	void *epc_page = (void *)reg_status->rcx;
	void *vaslot = (void *)reg_status->rdx;
	void __user *tmp_srcpge;
	void *secs;
	struct sgx_pcmd __user *pcmd;
	uint64_t arg_linaddr;
	uint8_t tmp_result;

	__uaccess_begin();
	tmp_srcpge = (void __user *)tmp_pageinfo->srcpage;
	secs = (void *)tmp_pageinfo->secs;
	pcmd = (void *)tmp_pageinfo->pcmd;
	arg_linaddr = tmp_pageinfo->linaddr;
	__uaccess_end();

	// Enforce EPC page alignment
	if (reg_status->rcx % 4096 != 0) {
		pr_info("vSGX: ELDB/ELDU: EPC page not aligned\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	// Enforce VA alignment
	if (reg_status->rdx % 8 != 0) {
		pr_info("vSGX: ELDB/ELDU: VA slot not aligned\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	reg_status->rax = EMUSGX_SUCCESS;
	reg_status->flags.ZF = 0;

	tmp_result = emusgx_validate_and_do_remote_for_eldb_eldu(tmp_srcpge, secs, vaslot, epc_page, pcmd, arg_linaddr, block);
	if (tmp_result == 1) {
		reg_status->rax = EMUSGX_MAC_COMPARE_FAIL;
	}
	if (tmp_result == 2) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	if (tmp_result == 3) {
		emusgx_pf(vaslot, fault_regs);
		return;
	}
	if (tmp_result == 4) {
		emusgx_pf(secs, fault_regs);
		return;
	}
	if (tmp_result == 5) {
		pr_info("vSGX: ELDB/ELDU: Remote returned GP\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	if (reg_status->rax != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
	
	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
}

static void emusgx_eblock(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	void *epc_page = (void *)reg_status->rcx;

	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	reg_status->flags.ZF = 0;
	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
	reg_status->rax = emusgx_do_remote_for_eblock(epc_page);
	if (reg_status->rax != EMUSGX_SUCCESS) {
		if (reg_status->rax == EMUSGX_ENTRYEPOCH_LOCKED ||
			reg_status->rax == EMUSGX_LOCKFAIL||
			reg_status->rax == EMUSGX_PG_INVLD) {
			reg_status->flags.ZF = 1;
		}
		else {
			reg_status->flags.CF = 1;
		}

		if (reg_status->rax == EMUSGX_GP) {
			emusgx_gp(0, fault_regs);
			return;
		}
	}
}

static void emusgx_epa(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> constant, PT_VA
	// RCX -> EPC page of the new version array	enclave
	void *epc_page = (void *)reg_status->rcx;
	uint8_t tmp_result;

	emusgx_debug_print("vSGX: entering EPA\n");
	// Must be PT_VA
	if (reg_status->rbx != SGX_PT_VA) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// Enforce enclave address alignment
	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	tmp_result = emusgx_validate_and_do_remote_for_epa(epc_page);
	emusgx_debug_print("vSGX: done remote epa with %d\n", tmp_result);
	if (tmp_result == 1) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	else if (tmp_result == 2) {
		emusgx_gp(0, fault_regs);
		return;
	}
}

static void emusgx_ewb(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> pageinfo		user
	// RCX -> EPC page		enclave
	// RDX -> VA slot		enclave
	struct sgx_pageinfo __user *tmp_pageinfo = (void __user *)reg_status->rbx;
	void *epc_page = (void *)reg_status->rcx;
	void *vaslot = (void *)reg_status->rdx;
	void __user *tmp_srcpge;
	struct sgx_pcmd __user *tmp_pcmd;
	uint64_t tmp_result;
	uint64_t ret_linaddr;

	__uaccess_begin();
	tmp_srcpge = (void __user *)tmp_pageinfo->srcpage;
	tmp_pcmd = (void __user *)tmp_pageinfo->pcmd;
	__uaccess_end();

	// Enforce in-enclave address alignment
	if (reg_status->rcx % 4096 != 0) {
		pr_info("vSGX: EWB: EPC page not aligned\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	if (reg_status->rdx % 8 != 0) {
		pr_info("vSGX: EWB: VA slot not aligned\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	// EPC page and VA slot cannot in the same page
	if (reg_status->rdx - reg_status->rcx >= 0 && reg_status->rdx - reg_status->rcx < 4096) {
		pr_info("vSGX: EWB: EPC and VA in the same page\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	__uaccess_begin();
	if (tmp_pageinfo->linaddr != 0 || tmp_pageinfo->secs != 0) {
		__uaccess_end();
		pr_info("vSGX: EWB: TMP_PAGEINFO's linaddr or secs not 0\n");
		emusgx_gp(0, fault_regs);
		return;
	}
	__uaccess_end();

	reg_status->flags.ZF = 0;
	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
	
	tmp_result = emusgx_validate_and_do_remote_for_ewb(epc_page, vaslot, tmp_pcmd, tmp_srcpge, &ret_linaddr);
	if (tmp_result == EMUSGX_GP) {
		pr_info("vSGX: EWB: Remote returned GP\n");
		emusgx_gp(0, fault_regs);
		return;
	}
	if (tmp_result == EMUSGX_PF_RCX) {
		pr_info("vSGX: EWB: EPC page PF\n");
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	if (tmp_result == EMUSGX_PF_RDX) {
		pr_info("vSGX: EWB:  VA PF \n");
		emusgx_pf(vaslot, fault_regs);
		return;
	}

	reg_status->rax = tmp_result;
	__uaccess_begin();
	tmp_pageinfo->linaddr = ret_linaddr;
	__uaccess_end();
	if (tmp_result != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
}

static void emusgx_eaug(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> PAGEINFO		user
	// RCX -> EPC page in enclave	enclave
	struct sgx_pageinfo __user *tmp_pageinfo = (void __user *)(reg_status->rbx);
	void *epc_page = (void *)(reg_status->rcx);
	uint8_t tmp_result = 0;
	void *arg_secs;
	uint64_t arg_linaddr;

	//pr_info("vSGX: EAUG 0x%016llX 0x%016llX\n", reg_status->rbx, reg_status->rcx);

	__uaccess_begin();
	arg_secs = (void *)tmp_pageinfo->secs;
	arg_linaddr = tmp_pageinfo->linaddr;
	__uaccess_end();

	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	__uaccess_begin();
	if (tmp_pageinfo->secs % 4096 != 0 || tmp_pageinfo->linaddr % 4096 != 0) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}

	if (tmp_pageinfo->srcpage != 0 || tmp_pageinfo->secinfo != 0) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}
	__uaccess_end();

	tmp_result = emusgx_validate_and_do_remote_for_eaug(arg_secs, arg_linaddr, epc_page);
	if (tmp_result == 1) {
		pr_info("vSGX: EAUG: SECS PF\n");
		emusgx_pf(arg_secs, fault_regs);
		return;
	}
	if (tmp_result == 2) {
		pr_info("vSGX: EAUG: EPC PF\n");
		emusgx_pf(epc_page, fault_regs);
		return;
	}
	if (tmp_result == 3) {
		pr_info("vSGX: EAUG: Remote returned GP\n");
		emusgx_gp(0, fault_regs);
		return;
	}
}

static void emusgx_emodpr(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> SECINFO		user
	// RCX -> EPC page		enclave
	struct sgx_secinfo __user *secinfo = (void __user *)reg_status->rbx;
	void *epc_page = (void *)reg_status->rcx;
	int i;
	uint8_t arg_R, arg_W, arg_X;

	// pr_info("vSGX: EMODPR 0x%016llX 0x%016llX", reg_status->rbx, reg_status->rcx);

	__uaccess_begin();
	arg_R = secinfo->flags.R;
	arg_W = secinfo->flags.W;
	arg_X = secinfo->flags.X;
	__uaccess_end();

	if (reg_status->rcx % 4096 != 0) {
		pr_info("vSGX: EMDPR EPC not aligned\n");
		emusgx_gp(0, fault_regs);
		return;
	}

	// Check for mis-configured SECINFO flags
	__uaccess_begin();
	if (secinfo->flags.reserved != 0 || secinfo->flags.reserved2 != 0) {
		__uaccess_end();
		pr_info("vSGX: EMODPR: SECINFO reserved not 0\n");
		emusgx_gp(0, fault_regs);
		return;
	}
	for (i = 0; i < 7; i++) {
		if (secinfo->reserved[i] != 0) {
			__uaccess_end();
			pr_info("vSGX: EMODPR: SECINFO reserved not 0\n");
			emusgx_gp(0, fault_regs);
			return;
		}
	}

	if (secinfo->flags.R == 0 && secinfo->flags.W != 0) {
		__uaccess_end();
		pr_info("vSGX: EMODPR: SECINFO RW flag misconfigured\n");
		emusgx_gp(0, fault_regs);
		return;
	}
	__uaccess_end();

	reg_status->rax = emusgx_validate_and_do_remote_for_emodpr(epc_page, arg_R, arg_W, arg_X);
	if (reg_status->rax != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
	else {
		reg_status->flags.ZF = 0;
	}

	if (reg_status->rax == EMUSGX_GP) {
		pr_info("vSGX: EMODPR: Remote returned GP\n");
		emusgx_gp(0, fault_regs);
		return;
	}
	else if (reg_status->rax == EMUSGX_PF_RCX) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}

	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
}

static void emusgx_emodt(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// RBX -> SECINFO		user
	// RCX -> EPC page		enclave
	struct sgx_secinfo __user *secinfo = (void __user *)reg_status->rbx;
	void *epc_page = (void *)reg_status->rcx;
	int i;
	uint8_t arg_R, arg_W, arg_page_type;

	// pr_info("vSGX: EMODT 0x%016llX 0x%016llX\n", reg_status->rbx, reg_status->rcx);

	__uaccess_begin();
	arg_R = secinfo->flags.R;
	arg_W = secinfo->flags.W;
	arg_page_type = secinfo->flags.page_type;
	__uaccess_end();

	if (reg_status->rcx % 4096 != 0) {
		emusgx_gp(0, fault_regs);
		return;
	}

	// Check for mis-configured SECINFO flags
	__uaccess_begin();
	if (secinfo->flags.reserved != 0 || secinfo->flags.reserved2 != 0) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}
	for (i = 0; i < 7; i++) {
		if (secinfo->reserved[i] != 0) {
			__uaccess_end();
			emusgx_gp(0, fault_regs);
			return;
		}
	}
	if (!(secinfo->flags.page_type == SGX_PT_TCS || secinfo->flags.page_type == SGX_PT_TRIM)) {
		__uaccess_end();
		emusgx_gp(0, fault_regs);
		return;
	}
	__uaccess_end();

	reg_status->rax = emusgx_validate_and_do_remote_for_emodt(epc_page, arg_R, arg_W, arg_page_type);
	if (reg_status->rax != EMUSGX_SUCCESS) {
		reg_status->flags.ZF = 1;
	}
	else {
		reg_status->flags.ZF = 0;
	}

	if (reg_status->rax == EMUSGX_GP) {
		emusgx_gp(0, fault_regs);
		return;
	}
	else if (reg_status->rax == EMUSGX_PF_RCX) {
		emusgx_pf(epc_page, fault_regs);
		return;
	}

	reg_status->flags.CF = 0;
	reg_status->flags.PF = 0;
	reg_status->flags.AF = 0;
	reg_status->flags.OF = 0;
	reg_status->flags.SF = 0;
}

static void (*emusgx_encls_handlers[16])(struct emusgx_regs*, struct pt_regs*) = {
	&emusgx_ecreate,
	&emusgx_eadd,
	&emusgx_einit,
	&emusgx_eremove,
	NULL, // NO EDBGRD
	NULL, // NO EDBGWR
	&emusgx_eextend,
	&emusgx_eldb_eldu,
	&emusgx_eldb_eldu,
	&emusgx_eblock,
	&emusgx_epa,
	&emusgx_ewb,
	NULL, // NO ETRACK
	&emusgx_eaug,
	&emusgx_emodpr,
	&emusgx_emodt
};

// Return 1 if still UD
uint8_t emusgx_handle_encls(struct emusgx_regs *reg_status, struct pt_regs *fault_regs) {
	// CPL must be 0
	// So the instruction cannot be referenced from the outside of the kernel

	// For testing purpose, we remove this restriction
	/*
	if (user_mode(fault_regs)) {
		// CPL is user
		// UD
		pr_info("EmuSGX: ENCLS is only available to callers with CPL of 0\n");
		return 1;
	}
	*/

	if ((uint32_t)(reg_status->rax) <= 15) {
		(*emusgx_encls_handlers[(uint32_t)(reg_status->rax)])(reg_status, fault_regs);
	}
	else {
		emusgx_gp(0, fault_regs);
		return 0;
	}
	return 0;
}
