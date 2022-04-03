#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include <asm/cacheflush.h>
#include <asm/atomic.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#include "emusgx.h"
#include "emusgx_internal.h"
#include "emusgx_sender.h"
#include "emusgx_cpuid.h"
#include "emusgx_debug.h"
#include "emusgx_mm.h"

uint64_t emusgx_registered_enclave_vm_id[EMUSGX_MAXIMUM_ENCLAVES];
int emusgx_registered_enclave_vms = 0;
atomic_t emusgx_used_enclave_vms = (atomic_t)ATOMIC_INIT(0);

int emusgx_register_enclave_vm(uint64_t enclave_vm_id) {
	if (emusgx_registered_enclave_vms >= EMUSGX_MAXIMUM_ENCLAVES) {
		pr_err("EmuSGX: Registering more enclave VMs than I can handle\n");
		return -1;
	}
	pr_info("EmuSGX: Registered VM at %d with ID %lld\n", emusgx_registered_enclave_vms, enclave_vm_id);
	emusgx_registered_enclave_vm_id[emusgx_registered_enclave_vms++] = enclave_vm_id;
	return 0;
}

uint64_t emusgx_get_enclave_vm_id(int enclave_index) {
	if (enclave_index >= emusgx_registered_enclave_vms || enclave_index < 0) {
		pr_err("EmuSGX: Trying to get the ID for %d which does not exist\n", enclave_index);
		return 0;
	}
	return emusgx_registered_enclave_vm_id[enclave_index];
}

int emusgx_get_enclave_index(uint64_t enclave_vm_id) {
	int i;

	for (i = 0; i < emusgx_registered_enclave_vms; i++) {
		if (emusgx_registered_enclave_vm_id[i] == enclave_vm_id) {
			return i;
		}
	}

	return -1;
}

extern void vsgx_switchless_update_enclave_mm(struct mm_struct *mm, uint64_t manager_nr);

int emusgx_occupy_enclave_vm(void) {
	int manager_nr;
	manager_nr = atomic_inc_return(&emusgx_used_enclave_vms) - 1;
	vsgx_switchless_update_enclave_mm(current->mm, manager_nr);
	return manager_nr;
}

void emusgx_put_back_enclave_vm(void) {
	int manager_nr;
	manager_nr = atomic_dec_return(&emusgx_used_enclave_vms);
	vsgx_switchless_update_enclave_mm(NULL, manager_nr);
}

struct emusgx_epc_entry emusgx_epc_entries[EMUSGX_EPC_SIZE >> PAGE_SHIFT] = { [0 ... (EMUSGX_EPC_SIZE >> PAGE_SHIFT) - 1] = { -1, NULL } };

int emusgx_register_epc_page(uint64_t epc_addr, int enclave_vm_index, struct emusgx_version_array_page *va_info, uint8_t is_secs) {
	int epc_index;

	if (va_info != NULL && enclave_vm_index != -1) {
		pr_err("EmuSGX: Registering VA page with an enclave VM ID\n");
		return -1;
	}

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Registering a page outside the EPC @ 0x%016llX\n", epc_addr);
		return -1;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	if (emusgx_epc_entries[epc_index].enclave_vm_index != -1 || emusgx_epc_entries[epc_index].va_info != NULL) {
		pr_info("EmuSGX: WARNING: Overwriting a previously allocated page. That page should have been removed or this is a bad behaviour\n");
		pr_info("EmuSGX: EPC index = %d\n", epc_index);
		pr_info("EmuSGX: epc_addr = 0x%016llX, previous index = %d, previous VA info = 0x%016llX\n", epc_addr, emusgx_epc_entries[epc_index].enclave_vm_index, (uint64_t)emusgx_epc_entries[epc_index].va_info);
	}

	emusgx_epc_entries[epc_index].enclave_vm_index = enclave_vm_index;
	emusgx_epc_entries[epc_index].va_info = va_info;
	emusgx_epc_entries[epc_index].is_secs = is_secs;

	return 0;
}

int emusgx_deregister_epc_page(uint64_t epc_addr) {
	int epc_index;

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Deregistering a page outside the EPC @ 0x%016llX\n", epc_addr);
		return -1;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	if (emusgx_epc_entries[epc_index].enclave_vm_index == -1 && emusgx_epc_entries[epc_index].va_info == NULL) {
		pr_err("EmuSGX: EPC entry is empty\n");
		return -1;
	}

	emusgx_epc_entries[epc_index].enclave_vm_index = -1;
	emusgx_epc_entries[epc_index].va_info = NULL;

	return 0;
}

uint8_t vsgx_is_epc_secs(uint64_t epc_addr) {
	int epc_index;

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Deregistering a page outside the EPC @ 0x%016llX\n", epc_addr);
		return 0;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	if (emusgx_epc_entries[epc_index].enclave_vm_index == -1 && emusgx_epc_entries[epc_index].va_info == NULL) {
		pr_err("EmuSGX: EPC entry is empty\n");
		return 0;
	}

	return emusgx_epc_entries[epc_index].is_secs;
}

struct emusgx_version_array_page *emusgx_get_version_array_page(uint64_t epc_addr) {
	int epc_index;

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Getting a page outside the EPC @ 0x%016llX\n", epc_addr);
		return NULL;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	if (emusgx_epc_entries[epc_index].va_info == NULL) {
		pr_err("EmuSGX: EPC entry is empty or not a VA page\n");
		return NULL;
	}

	return emusgx_epc_entries[epc_index].va_info;
}

int emusgx_get_target_enclave_index(uint64_t epc_addr) {
	int epc_index;

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Getting a page outside the EPC @ 0x%016llX\n", epc_addr);
		return -1;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	return emusgx_epc_entries[epc_index].enclave_vm_index;
}

int emusgx_update_version_array_page(uint64_t epc_addr, struct emusgx_version_array_page *va_info) {
	int epc_index;

	if (epc_addr < EMUSGX_EPC_BASE || epc_addr >= EMUSGX_EPC_BASE + EMUSGX_EPC_SIZE) {
		pr_err("EmuSGX: Getting a page outside the EPC @ 0x%016llX\n", epc_addr);
		return -1;
	}

	epc_index = (epc_addr - EMUSGX_EPC_BASE) >> PAGE_SHIFT;

	if (emusgx_epc_entries[epc_index].va_info == NULL) {
		pr_err("EmuSGX: EPC entry is empty or not a VA page\n");
		return -1;
	}

	emusgx_epc_entries[epc_index].va_info = va_info;

	return 0;
}
