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

struct emusgx_eenter_package {
	uint8_t instr;
	uint64_t tcs;
	uint64_t tcs_pa;
	uint64_t aep;
	uint64_t pid;
	struct emusgx_full_regs regs;
} __attribute__((__packed__));

static inline int vsgx_is_entry_pse(uint64_t entry) {
	return entry & _PAGE_PSE;
}

static inline int vsgx_pmd_huge(pmd_t pmd)
{
	return !pmd_none(pmd) &&
		(pmd_val(pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT;
}

static inline int vsgx_pud_huge(pud_t pud)
{
	return !!(pud_val(pud) & _PAGE_PSE);
}

/*
static int vsgx_find_pfn_kernel(unsigned long vaddr, unsigned long *pfn) {
	int level;
	pte_t *ptep;

	ptep = lookup_address(vaddr, &level);
	pfn = pte_pfn(*ptep);
	return 0;
	

	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(init_mm_p, vaddr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		// No PSE this leveel
		pr_info("EmuSGX: Page walk failed on PGD\n");
		goto out;
	}

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		// No PSE this level
		pr_info("EmuSGX: Page walk failed on P4D");
    		goto out;
	}

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || pud_bad(*pud)) {
		pr_info("EmuSGX: Page walk failed on PUD");
		goto out;
	}
	else if (vsgx_pud_huge(*pud)) {
		// PSE
		*pfn = pud_pfn(*pud) + ((vaddr & ~PUD_MASK) >> PAGE_SHIFT);
		return 0;
	}
	else if (pud_bad(*pud)) {
		pr_info("EmuSGX: Page walk failed on bad PUD");
		goto out;
	}

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		pr_info("EmuSGX: Page walk failed on PMD - none");
		goto out;
	}
	else if (vsgx_pmd_huge(*pmd)) {
		// PSE
		*pfn = pmd_pfn(*pmd) + ((vaddr & ~PMD_MASK) >> PAGE_SHIFT);
		return 0;
	}
	else if (pmd_bad(*pmd)) {
		pr_info("EmuSGX: Page walk failed on PMD - bad");
		goto out;
	}

	ptep = pte_offset_map(pmd, vaddr);
	if (!pte_present(*ptep)) {
		pr_info("EmuSGX: Page walk failed on PTE");
		goto out;
	}

	*pfn = pte_pfn(*ptep);
	return 0;
out:
	return -1;
}
*/

unsigned long vsgx_vma_get_user_paddr(struct mm_struct *mm, unsigned long vaddr) {
	struct vm_area_struct *vma;
	long pfn;
	int ret;
	unsigned long offset = vaddr & ~PAGE_MASK;

	vma = find_vma(mm, vaddr);
	if (!vma) {
		pr_err("vSGX: Failed to retrive user address 0x%016lX's VMA\n", vaddr);
		return 0;
		
	}
	ret = follow_pfn(vma, vaddr, &pfn);
	if (ret != 0) {
		pr_err("vSGX: Failed to follow pfn\n");
		return 0;
	}

	return __pfn_to_phys(pfn) + offset;
}


static inline unsigned long vsgx_vma_get_paddr(struct mm_struct *mm, unsigned long vaddr) {
/*	long pfn;
	int ret;
	unsigned long offset = vaddr & ~PAGE_MASK;

	if (vaddr == 0) {
		return 0;
	}

	ret = vsgx_find_pfn_kernel(vaddr, &pfn);
	if (ret != 0) {
		pr_err("vSGX: Failed to follow pfn\n");
		return 0;
	}
	
	return __pfn_to_phys(pfn) + offset;
*/
	return slow_virt_to_phys((void *)vaddr);
}

void emusgx_enter_enclave(void *tcs, void *aep, struct pt_regs *regs) {
	struct emusgx_eenter_package *package;
	uint64_t package_size = sizeof(struct emusgx_eenter_package);
	struct emusgx_response response;
	struct emusgx_full_regs *wb_regs;
	uint8_t is_aex = 0;
	struct vsgx_exit_info exit_info;
	int target_enclave;

	//uint64_t stamp_before;
	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EENTER;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		emusgx_gp(0, regs);
	}

	package->instr = EMUSGX_S_EENTER;
	package->tcs = (uint64_t)tcs; // This can be simply the user space address
	package->tcs_pa = (uint64_t)vsgx_vma_get_user_paddr(current->mm, (unsigned long)tcs);
	package->aep = (uint64_t)aep; // This can be simply the user space address
	package->pid = (uint64_t)current;
	package->regs.r15 = regs->r15;
	package->regs.r14 = regs->r14;
	package->regs.r13 = regs->r13;
	package->regs.r12 = regs->r12;
	package->regs.r11 = regs->r11;
	package->regs.r10 = regs->r10;
	package->regs.r9 = regs->r9;
	package->regs.r8 = regs->r8;
	package->regs.bp = regs->bp;
	package->regs.bx = regs->bx;
	package->regs.ax = regs->ax;
	package->regs.cx = regs->cx;
	package->regs.dx = regs->dx;
	package->regs.si = regs->si;
	package->regs.di = regs->di;
	package->regs.flags = regs->flags;
	package->regs.sp = regs->sp;
	package->regs.ip = regs->ip;

	target_enclave = emusgx_get_target_enclave_index(package->tcs_pa);

	emusgx_sync_manager_pages(target_enclave, 1); // Ensure changes are synced
	
	//stamp_before = ktime_get_real_ns();
	// Register eexit before sending data
	if (emusgx_register_eexit_request((uint64_t)current)) {
		pr_info("EmuSGX: Failed to register eexit request\n");
		emusgx_gp(0, regs);
		return;
	}

	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		emusgx_gp(0, regs);
		return;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		emusgx_gp(0, regs);
		return;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		emusgx_gp(0, regs);
		return;
	}

	// Response processing
	if (response.response == EMUSGX_GP) {
		emusgx_gp(0, regs);
		return;
	}
	if (response.response == EMUSGX_PF_RBX) {
		emusgx_pf(tcs, regs);
		return;
	}
	if (response.response == EMUSGX_PF_RCX) {
		// Not necessarily RCX, just take this retval as PF
		emusgx_pf((void *)(response.linaddr), regs);
		return;
	}
	if (response.response != 0) {
		pr_info("EmuSGX: Unexpected error code %lld\n", response.response);
		emusgx_gp(0, regs);
		return;
	}

	// It needs to sleep and wait until EEXIT
	// But first, let's register our eexit request
	wb_regs = kmalloc(sizeof(struct emusgx_full_regs), GFP_KERNEL);
	if (wb_regs == NULL) {
		kfree(wb_regs);
		emusgx_gp(0, regs);
		return;
	}
	
	// Now wait for EEXIT
	emusgx_debug_print("EmuSGX: EENTER successed. Now waiting for EEXIT\n");
	if (emusgx_wait_for_eexit_request((uint64_t)current, wb_regs, regs, &is_aex, &exit_info)) {
		pr_info("EmuSGX: Some one tries to kill me\n");
		kfree(wb_regs);
		// Why not GP? We need the signal to be properly handled
		return;
	}

	// Write back regs
	regs->r15 = wb_regs->r15;
	regs->r14 = wb_regs->r14;
	regs->r13 = wb_regs->r13;
	regs->r12 = wb_regs->r12;
	regs->r11 = wb_regs->r11;
	regs->r10 = wb_regs->r10;
	regs->r9 = wb_regs->r9;
	regs->r8 = wb_regs->r8;
	regs->bp = wb_regs->bp;
	regs->bx = wb_regs->bx;
	regs->ax = wb_regs->ax;
	regs->cx = wb_regs->cx;
	regs->dx = wb_regs->dx;
	regs->si = wb_regs->si;
	regs->di = wb_regs->di;
	regs->flags = wb_regs->flags;
	regs->sp = wb_regs->sp;
	regs->ip = wb_regs->ip;

	kfree(wb_regs);

	if (is_aex) {
		// Call fault handler
		vsgx_handle_aex(regs, &exit_info);
	}

	//pr_info("vSGX: ECall took %lld\n", ktime_get_real_ns() - stamp_before);

	return;
}

struct emusgx_eresume_package {
	uint8_t instr;
	uint64_t tcs_pa;
	uint64_t tcs;
	uint64_t aep;
	uint64_t pid;
} __attribute__((__packed__));

void emusgx_resume_enclave(void *tcs, void *aep, struct pt_regs *regs) {
	struct emusgx_eresume_package *package;
	uint64_t package_size = sizeof(struct emusgx_eresume_package);
	struct emusgx_response response;
	struct emusgx_full_regs *wb_regs;
	uint8_t is_aex = 0;
	struct vsgx_exit_info exit_info;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_ERESUME;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		emusgx_gp(0, regs);
	}
	
	// You don't know which manager you are entering
	// At least don't know the remote manager_nr
	// emusgx_sync_manager_pages()

	package->instr = EMUSGX_S_ERESUME;
	package->tcs = (uint64_t)tcs; // This can be simply the user space address
	package->tcs_pa = (uint64_t)vsgx_vma_get_user_paddr(current->mm, (unsigned long)tcs);
	package->aep = (uint64_t)aep; // This can be simply the user space address
	package->pid = (uint64_t)current;

	target_enclave = emusgx_get_target_enclave_index(package->tcs_pa);

	// Register eexit before sending data
	if (emusgx_register_eexit_request((uint64_t)current)) {
		pr_info("EmuSGX: Failed to register eexit request\n");
		emusgx_gp(0, regs);
		return;
	}

	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		emusgx_gp(0, regs);
		return;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		emusgx_gp(0, regs);
		return;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		emusgx_gp(0, regs);
		return;
	}

	// Response processing
	if (response.response == 3) {
		emusgx_gp(0, regs);
		return;
	}
	if (response.response == 2) {
		emusgx_pf((void __user *)response.linaddr, regs);
		return;
	}
	if (response.response == 1) {
		// Not necessarily RCX, just take this retval as PF
		emusgx_pf(tcs, regs);
		return;
	}
	if (response.response != 0) {
		pr_info("EmuSGX: Unexpected error code %lld\n", response.response);
		emusgx_gp(0, regs);
		return;
	}

	// It needs to sleep and wait until EEXIT
	// But first, let's register our eexit request
	wb_regs = kmalloc(sizeof(struct emusgx_full_regs), GFP_KERNEL);
	if (wb_regs == NULL) {
		kfree(wb_regs);
		emusgx_gp(0, regs);
		return;
	}
	
	// Now wait for EEXIT
	emusgx_debug_print("EmuSGX: ERESUME successed. Now waiting for EEXIT\n");
	if (emusgx_wait_for_eexit_request((uint64_t)current, wb_regs, regs, &is_aex, &exit_info)) {
		pr_info("EmuSGX: Some one tries to kill me\n");
		kfree(wb_regs);
		// Why not GP? We need the signal to be properly handled
		return;
	}

	// Write back regs
	regs->r15 = wb_regs->r15;
	regs->r14 = wb_regs->r14;
	regs->r13 = wb_regs->r13;
	regs->r12 = wb_regs->r12;
	regs->r11 = wb_regs->r11;
	regs->r10 = wb_regs->r10;
	regs->r9 = wb_regs->r9;
	regs->r8 = wb_regs->r8;
	regs->bp = wb_regs->bp;
	regs->bx = wb_regs->bx;
	regs->ax = wb_regs->ax;
	regs->cx = wb_regs->cx;
	regs->dx = wb_regs->dx;
	regs->si = wb_regs->si;
	regs->di = wb_regs->di;
	regs->flags = wb_regs->flags;
	regs->sp = wb_regs->sp;
	regs->ip = wb_regs->ip;

	kfree(wb_regs);

	if (is_aex) {
		vsgx_handle_aex(regs, &exit_info);
	}

	return;


}

struct emusgx_eadd_package {
	uint8_t instr;
	uint64_t secs;
	uint64_t linaddr;
	uint64_t epc_page;
	uint8_t srcpage[4096];
	struct sgx_secinfo secinfo;
} __attribute__((__packed__));

uint8_t emusgx_validate_and_do_remote_for_eadd(void *secs, void *epc_page, void *linaddr, void __user *srcpage, void __user *secinfo) {
	struct emusgx_eadd_package *package;
	uint64_t package_size = sizeof(struct emusgx_eadd_package);
	uint8_t gp_num = 3;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EADD;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		kfree(package);
		return gp_num;
	}

	package->instr = EMUSGX_S_EADD;
	package->secs = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)secs);
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	package->linaddr = (uint64_t)linaddr; // This is left unchanged
	__uaccess_begin();
	memcpy(package->srcpage, srcpage, 4096);
	memcpy(&(package->secinfo), secinfo, sizeof(struct sgx_secinfo));
	__uaccess_end();

	target_enclave = emusgx_get_target_enclave_index(package->secs);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		kfree(package);
		return gp_num;
	}

	if (!(uint8_t)(response.response)) {
		// Register epc_page to target_enclave only on a success EADD
		if (emusgx_register_epc_page(package->epc_page, target_enclave, NULL, 0)) {
			pr_err("EmuSGX: Failed to register EPC page for EADD\n");
			kfree(package);
			return gp_num;
		}
	}

	kfree(package);

	return (uint8_t)(response.response);
}

struct emusgx_eaug_package {
	uint8_t instr;
	uint64_t secs;
	uint64_t linaddr;
	uint64_t epc_addr;
} __attribute__((__packed__));

uint8_t emusgx_validate_and_do_remote_for_eaug(void *secs, uint64_t linaddr, void *epc_addr) {
	struct emusgx_eaug_package *package;
	uint64_t package_size = sizeof(struct emusgx_eaug_package);
	uint8_t gp_num = 3;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EAUG;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EAUG;
	package->secs = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)secs);
	package->epc_addr = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_addr);
	package->linaddr = (uint64_t)linaddr;

	target_enclave = emusgx_get_target_enclave_index(package->secs);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		kfree(package);
		return gp_num;
	}

	if (!(uint8_t)(response.response)) {
		// Register epc_page to target_enclave only on a success EAUG
		if (emusgx_register_epc_page(package->epc_addr, target_enclave, NULL, 0)) {
			pr_err("EmuSGX: Failed to register EPC page for EAUG\n");
			kfree(package);
			return gp_num;
		}
	}
	kfree(package);

	return (uint8_t)(response.response);
}

struct emusgx_eblock_package {
	uint8_t instr;
	uint64_t epc_page;
} __attribute__((__packed__));

uint64_t emusgx_do_remote_for_eblock(void *epc_page) {
	struct emusgx_eblock_package *package;
	uint64_t package_size = sizeof(struct emusgx_eblock_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EBLOCK;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EBLOCK;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);

	target_enclave = emusgx_get_target_enclave_index(package->epc_page);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return response.response;
}

struct emusgx_ecreate_package {
	uint8_t instr;
	uint8_t srcpage[4096];
	uint64_t epc_page;
} __attribute__((__packed__));

uint8_t emusgx_validate_and_do_remote_for_ecreate(void __user *srcpage, void *epc_page) {
	struct emusgx_ecreate_package *package;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_ECREATE;

	package = kmalloc(sizeof(struct emusgx_ecreate_package), GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return 2;
	}

	package->instr = EMUSGX_S_ECREATE;
	__uaccess_begin();
	memcpy(package->srcpage, srcpage, 4096);
	__uaccess_end();
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return 2;
	}

	// Send data
	if (emusgx_send_data(package, sizeof(struct emusgx_ecreate_package), target_enclave = emusgx_occupy_enclave_vm())) {
		// Failed to send
		kfree(package);
		return 2;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	if ((uint8_t)(response.response)) {
		// Failed to create new enclave
		// Put back enclave VM as free
		// Because we are doing it before the response is released, no race is happening
		emusgx_put_back_enclave_vm();
	}
	else {
		if (emusgx_register_epc_page(package->epc_page, target_enclave, NULL, 1)) {
			pr_info("vSGX: Failed to register SECS page for ECREATE\n");
		}
	}

	kfree(package);

	// Release response
	if (emusgx_release_response(&response)) {
		return 2;
	}

	return (uint8_t)(response.response);
}

struct emusgx_eextend_package {
	uint8_t instr;
	uint64_t addr;
} __attribute__((__packed__));

uint8_t emusgx_validate_and_do_remote_for_eextend(void *addr) {
	struct emusgx_eextend_package *package;
	uint64_t package_size = sizeof(struct emusgx_eextend_package);
	uint64_t gp_num = 2;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EEXTEND;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EEXTEND;
	package->addr = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)addr);

	target_enclave = emusgx_get_target_enclave_index(package->addr);

	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return (uint8_t)(response.response);
}

struct emusgx_einit_package {
	uint8_t instr;
	struct sgx_sigstruct sigstruct;
	uint64_t secs;
	struct sgx_einittoken einittoken;
} __attribute__((__packed__));

uint64_t emusgx_validate_and_do_remote_for_einit(struct sgx_sigstruct __user *sigstruct, void *secs, struct sgx_einittoken __user *einittoken) {
	struct emusgx_einit_package *package;
	uint64_t package_size = sizeof(struct emusgx_einit_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EINIT;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EINIT;
	package->secs = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)secs);
	__uaccess_begin();
	memcpy(&(package->sigstruct), sigstruct, sizeof(struct sgx_sigstruct));
	memcpy(&(package->einittoken), einittoken, sizeof(struct sgx_einittoken));
	__uaccess_end();

	target_enclave = emusgx_get_target_enclave_index(package->secs);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	//pr_info("vSGX_DEBUG: response = %lld\n", response.response);

	return response.response;
}

struct emusgx_eldb_eldu_package {
	uint8_t instr;
	uint8_t srcpage[4096];
	uint64_t secs;
	uint64_t vaslot;
	uint64_t epc_page;
	struct sgx_pcmd pcmd;
	uint64_t linaddr;
	uint8_t block;
	uint8_t va_page[4096];
	uint64_t va_mac[2];
} __attribute__((__packed__));

uint8_t emusgx_validate_and_do_remote_for_eldb_eldu(void __user *srcpage, void *secs, void *vaslot, void *epc_page, struct sgx_pcmd __user *pcmd, uint64_t linaddr, uint8_t block) {
	struct emusgx_eldb_eldu_package *package;
	uint64_t package_size = sizeof(struct emusgx_eldb_eldu_package);
	uint8_t gp_num = 5;
	struct emusgx_response response;
	int target_enclave;
	int new_secs;
	struct emusgx_version_array_page *va_info;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_ELDU;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_ELDU;
	package->secs = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)secs);
	package->vaslot = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)vaslot);
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	package->linaddr = linaddr;
	package->block = block;
	__uaccess_begin();
	memcpy(package->srcpage, srcpage, 4096);
	memcpy(&(package->pcmd), pcmd, sizeof(struct sgx_pcmd));
	__uaccess_end();
	
	if (package->pcmd.secinfo.flags.page_type == SGX_PT_VA) {
		va_info = kmalloc(sizeof(struct emusgx_version_array_page), GFP_KERNEL);
		memcpy(va_info->va_data, package->srcpage, 4096);
		memcpy(va_info->va_mac, package->pcmd.mac, 2 * sizeof(uint64_t));
		if (emusgx_register_epc_page(package->epc_page, -1, va_info, 0)) {
			pr_err("EmuSGX: Failed to register VA page for ELDB/ELDU\n");
			kfree(package);
			kfree(va_info);
			return gp_num;
		}
		return 0;
	}

	va_info = emusgx_get_version_array_page(package->vaslot);

	if (va_info == NULL) {
		pr_info("vSGX: ELDB/ELDU: Failed to get version array page\n");
		kfree(package);
		return gp_num;
	}

	memcpy(package->va_page, va_info->va_data, 4096);
	memcpy(package->va_mac, va_info->va_mac, 2 * sizeof(uint64_t));

	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	if (package->pcmd.secinfo.flags.page_type == SGX_PT_SECS) {
		new_secs = 1;
		target_enclave = emusgx_occupy_enclave_vm();
	}
	else {
		new_secs = 0;
		target_enclave = emusgx_get_target_enclave_index(package->secs);
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	if (!(uint8_t)(response.response)) {
		// Succeed. Register page
		if (emusgx_register_epc_page(package->epc_page, target_enclave, NULL, new_secs)) {
			pr_err("EmuSGX: Failed to register EPC page for ELDB/ELDU\n");
			kfree(package);
			return gp_num;
		}
	}

	if (((uint8_t)(response.response)) && new_secs) {
		// Failed to load back a SECS
		emusgx_put_back_enclave_vm();
	}

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return (uint8_t)(response.response);
}

struct emusgx_emodpr_package {
	uint8_t instr;
	uint64_t epc_page;
	uint8_t R;
	uint8_t W;
	uint8_t X;
} __attribute__((__packed__));

uint64_t emusgx_validate_and_do_remote_for_emodpr(void *epc_page, uint8_t R, uint8_t W, uint8_t X) {
	struct emusgx_emodpr_package *package;
	uint64_t package_size = sizeof(struct emusgx_emodpr_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EMODPR;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EMODPR;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	package->R = R;
	package->W = W;
	package->X = X;

	target_enclave = emusgx_get_target_enclave_index(package->epc_page);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return response.response;
}

struct emusgx_emodt_package {
	uint8_t instr;
	uint64_t epc_page;
	uint8_t R;
	uint8_t W;
	uint8_t page_type;
} __attribute__((__packed__));

uint64_t emusgx_validate_and_do_remote_for_emodt(void *epc_page, uint8_t R, uint8_t W, uint8_t page_type) {
	struct emusgx_emodt_package *package;
	uint64_t package_size = sizeof(struct emusgx_emodt_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EMODT;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EMODT;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	package->R = R;
	package->W = W;
	package->page_type = page_type;

	target_enclave = emusgx_get_target_enclave_index(package->epc_page);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	kfree(package);

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return response.response;
}


struct emusgx_epa_package {
	uint8_t instr;
	uint64_t epc_page;
} __attribute__((__packed__));

//static uint64_t epa_count = 0;

uint8_t emusgx_validate_and_do_remote_for_epa(void *epc_page) {
	struct emusgx_epa_package *package;
	uint64_t package_size = sizeof(struct emusgx_epa_package);
	uint8_t gp_num = 2;
	struct emusgx_response response;
	struct emusgx_version_array_page *va_info;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EPA;

//	pr_info("vSGX: EPA %lld\n", ++epa_count);

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EPA;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, 0)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	if ((uint8_t)response.response != 0) {
		// Just a raw response without page
		emusgx_release_response(&response);
		kfree(package);
		return (uint8_t)response.response;
	}

	va_info = kmalloc(sizeof(struct emusgx_version_array_page), GFP_KERNEL);

	memcpy(va_info->va_data, response.va_page, 4096);
	memcpy(va_info->va_mac, response.va_mac, 2 * sizeof(uint64_t));

	if (emusgx_register_epc_page(package->epc_page, -1, va_info, 0)) {
		pr_info("vSGX: Failed to register page for EPA\n");
		pr_info("vSGX: Was doing EPA 0x%016llX->0x%016llX\n", (uint64_t)epc_page, (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page));
	}

	kfree(package);

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return (uint8_t)(response.response);
}

struct emusgx_eremove_package {
	uint8_t instr;
	uint64_t epc_page;
} __attribute__((__packed__));

extern void vsgx_switchless_update_enclave_mm(struct mm_struct *mm, uint64_t manager_nr);

uint64_t emusgx_validate_and_do_remote_for_eremove(void *epc_page) {
	struct emusgx_eremove_package *package;
	uint64_t package_size = sizeof(struct emusgx_eremove_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;
	struct emusgx_version_array_page *va_info;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EREMOVE;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EREMOVE;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);

	target_enclave = emusgx_get_target_enclave_index(package->epc_page);

	if (target_enclave == -1) {
		// Check if it's a VA page
		if ((va_info = emusgx_get_version_array_page(package->epc_page)) != NULL) {
			// Is a VA page
			kfree(va_info);
			emusgx_deregister_epc_page(package->epc_page);
			kfree(package);
			return 0;
		}
		else {
			// Page not found
			kfree(package);
			return EMUSGX_PF_RCX;
		}
	}
	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	// Release response
	if (emusgx_release_response(&response)) {
		kfree(package);
		return gp_num;
	}

	if (response.response == EMUSGX_SUCCESS) {
		if (vsgx_is_epc_secs(package->epc_page)) {
			pr_info("vSGX: Destroying an enclave...\n");
			vsgx_switchless_update_enclave_mm(NULL, target_enclave);
		}

		emusgx_deregister_epc_page(package->epc_page);
	}
	kfree(package);

	return response.response;
}

struct emusgx_ewb_package {
	uint8_t instr;
	uint64_t epc_page;
	uint64_t vaslot;
	uint64_t linaddr;
	uint8_t va_page[4096];
	uint64_t va_mac[2];
} __attribute__((__packed__));

uint64_t emusgx_validate_and_do_remote_for_ewb(void *epc_page, void *vaslot, struct sgx_pcmd __user *pcmd, void __user *srcpage, uint64_t *linaddr) {
	struct emusgx_ewb_package *package;
	uint64_t package_size = sizeof(struct emusgx_ewb_package);
	uint64_t gp_num = EMUSGX_GP;
	struct emusgx_response response;
	int target_enclave;
	struct emusgx_version_array_page *va_info;
	struct emusgx_version_array_page *va_info_wb;

	response.ready = 0;
	response.write_back = 0;
	response.instr = EMUSGX_S_EWB;

	package = kmalloc(package_size, GFP_KERNEL);
	if (package == NULL) {
		// Out of mem
		// GP
		return gp_num;
	}

	package->instr = EMUSGX_S_EWB;
	package->epc_page = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)epc_page);
	package->vaslot = (uint64_t)vsgx_vma_get_paddr(current->mm, (unsigned long)vaslot);

	va_info = emusgx_get_version_array_page(package->vaslot);

	if (va_info == NULL) {
		pr_err("EmuSGX: Failed to get version array page\n");
		kfree(package);
		return gp_num;
	}

	target_enclave = emusgx_get_target_enclave_index(package->epc_page);

	if (target_enclave == -1) {
		if ((va_info_wb = emusgx_get_version_array_page(package->epc_page)) != NULL) {
			// Writing back a VA page
			memcpy(pcmd->mac, va_info_wb->va_mac, 2 * sizeof(uint64_t));
			pcmd->secinfo.flags.page_type = SGX_PT_VA;
			*linaddr = 0;
			memcpy(srcpage, va_info_wb->va_data, 4096);
			kfree(va_info_wb);
			emusgx_deregister_epc_page(package->epc_page);
			kfree(package);
			return EMUSGX_SUCCESS;
		}
		else {
			return EMUSGX_PF_RCX;
		}
	}

	memcpy(package->va_page, va_info->va_data, 4096);
	memcpy(package->va_mac, va_info->va_mac, 2 * sizeof(uint64_t));

	
	// Register response
	if (emusgx_register_response(&response, 0)) {
		// Failed to register response
		kfree(package);
		return gp_num;
	}

	// Send data
	if (emusgx_send_data(package, package_size, target_enclave)) {
		// Failed to send
		kfree(package);
		emusgx_release_response(&response);
		return gp_num;
	}

	// Wait for response
	emusgx_wait_for_response(0);

	if (response.response != 0) {
		// Just a raw response without page
		emusgx_release_response(&response);
		kfree(package);
		return response.response;
	}

	// We don't reuse an enclave VM so if an enclave VM is abandoned, its just gone
	// if (pcmd->secinfo.flags.page_type == SGX_PT_SECS) {
	// 	emusgx_put_back_enclave_vm();
	// }

	emusgx_deregister_epc_page(package->epc_page);
	kfree(package);

	*linaddr = response.linaddr;
	// These pages must be in the kernel.
	// Otherwise it should be used with uaccess already turned off
	
	__uaccess_begin();
	memcpy(pcmd, response.pcmd, sizeof(struct sgx_pcmd));
	memcpy(srcpage, response.srcpage, 4096);
	__uaccess_end();

	// Write back VA page
	memcpy(va_info->va_data, response.va_page, 4096);
	memcpy(va_info->va_mac, response.va_mac, 2 * sizeof(uint64_t));

	// Release response
	if (emusgx_release_response(&response)) {
		return gp_num;
	}

	return response.response;
}
