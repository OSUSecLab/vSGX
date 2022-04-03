#ifndef EMUSGX_MM_H
#define EMUSGX_MM_H

#include <linux/kernel.h>
#include <linux/mm.h>

extern void *emusgx_receive_page;
void emusgx_init_shared_page(void);

#define EMUSGX_EPC_BASE		0x80000000
#define EMUSGX_EPC_SIZE		0x15000000

struct emusgx_version_array_page {
	uint8_t va_data[4096];
	uint64_t va_mac[2];
	// We don't store an EPCM for this. If this page works,
	// the EPCM should be correct because what else can you expect
	// for an VA page?
	// struct emusgx_epcm
};

struct emusgx_epc_entry {
	int enclave_vm_index;
	struct emusgx_version_array_page *va_info;
	uint8_t is_secs;
};

extern struct emusgx_epc_entry emusgx_epc_entries[EMUSGX_EPC_SIZE >> PAGE_SHIFT];


#endif
