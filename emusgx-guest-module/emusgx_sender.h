#ifndef EMUSGX_SENDER_H
#define EMUSGX_SENDER_H

#define EMUSGX_PAYLOAD_SIZE (4096 - 7 * sizeof(uint64_t))

#define EMUSGX_MAX_SESSION_NUMBER_D64	512
#define EMUSGX_MAX_SESSION_NUMBER	(EMUSGX_MAX_SESSION_NUMBER_D64 * 64)

#define EMUSGX_S_ECREATE	0x00
#define EMUSGX_S_EADD		0x01
#define EMUSGX_S_EINIT		0x02
#define EMUSGX_S_EREMOVE	0x03
#define EMUSGX_S_EDBGRD		0x04
#define EMUSGX_S_EDBGWR		0x05
#define EMUSGX_S_EEXTEND	0x06
#define EMUSGX_S_ELDB		0x07
#define EMUSGX_S_ELDU		0x08
#define EMUSGX_S_EBLOCK		0x09
#define EMUSGX_S_EPA		0x0A
#define EMUSGX_S_EWB		0x0B
#define EMUSGX_S_ETRACK		0x0C
#define EMUSGX_S_EAUG		0x0D
#define EMUSGX_S_EMODPR		0x0E
#define EMUSGX_S_EMODT		0x0F

#define EMUSGX_S_EREPORT	0x10
#define EMUSGX_S_EGETKEY	0x11
#define EMUSGX_S_EENTER		0x12
#define EMUSGX_S_ERESUME	0x13
#define EMUSGX_S_EEXIT		0x14
#define EMUSGX_S_EACCEPT	0x15
#define EMUSGX_S_EMODPE		0x16
#define EMUSGX_S_EACCEPTCOPY	0x17

#define EMUSGX_S_PAGEREQ	0x18
#define EMUSGX_S_SWITCHLESS	0x19
#define EMUSGX_S_FAULT		0x20

#define EMUSGX_S_AEX		0x21

#define EMUSGX_S_REGISTER_EVM	0x22

#include "emusgx_arch.h"

// order starts from 0 and ends at total_pages - 1
struct emusgx_cross_vm_package {
	// Encrypted
	uint64_t session_number;
	uint64_t order;
	uint64_t total_pages;
	uint64_t total_size;
	uint64_t enclave_vm_id;

	uint8_t payload[EMUSGX_PAYLOAD_SIZE];

	// Non-encrypted MAC

	uint64_t mac[2];
} __attribute__((__packed__));

// response
struct emusgx_response {
	uint8_t ready;
	uint64_t response;
	uint64_t linaddr;
	uint8_t write_back;
	uint8_t with_va;
	void *srcpage;
	struct sgx_pcmd *pcmd;
	void *va_page;
	uint64_t *va_mac;
	uint8_t instr;
};

struct emusgx_raw_response {
	uint8_t instr;
	uint64_t response;
	uint64_t linaddr;
	uint8_t write_back;
	uint8_t with_va;
} __attribute__((__packed__));

struct emusgx_raw_response_with_va {
	uint8_t instr;
	uint64_t response;
	uint64_t linaddr;
	uint8_t write_back;
	uint8_t with_va;
	uint8_t va_page[4096];
	uint64_t va_mac[2];
} __attribute__((__packed__));

/*
struct emusgx_raw_response_with_page {
	uint8_t instr;
	uint64_t response;
	uint64_t linaddr;
	uint8_t write_back;
	uint8_t with_va;
	uint8_t page[4096];
	struct sgx_pcmd pcmd;
} __attribute__((__packed__));
*/

struct emusgx_raw_response_with_page_and_va {
	uint8_t instr;
	uint64_t response;
	uint64_t linaddr;
	uint8_t write_back;
	uint8_t with_va;
	uint8_t va_page[4096];
	uint64_t va_mac[2];
	uint8_t page[4096];
	struct sgx_pcmd pcmd;
} __attribute__((__packed__));

struct emusgx_full_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
/* Return frame for iretq */
	unsigned long ip;
	//unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	//unsigned long ss;
} __attribute__((__packed__));

#define EMUSGX_DISPATCH_SLOT_FREE	0
#define EMUSGX_DISPATCH_SLOT_INUSE	1

struct emusgx_dispatch_slot {
	uint8_t status;
	uint64_t session_number;
	uint64_t total_pages;
	uint64_t current_order;
	uint64_t total_size;
	uint64_t enclave_vm_id;
	void *data;
};

// Used for IRQ data dispatch
struct emusgx_request_queue_node {
	void *page;
	struct emusgx_request_queue_node *next;
};

struct emusgx_page_package {
	uint8_t instr;
	uint64_t addr;
	uint64_t id; // Use this as ID
	uint8_t page[4096];
	uint8_t mask[512]; // 4096-bit bitmap for each byte
} __attribute__((__packed__));

// slot field shall be allocated before registration
// data field in the slot field shall also be pre-allocated
struct emusgx_eexit_queue_node {
	struct emusgx_dispatch_slot *slot;
	struct semaphore semaphore;
	uint64_t pid;
	struct emusgx_eexit_queue_node *next;
};

struct emusgx_switchless_sync_queue_node {
	struct emusgx_dispatch_slot *slot;
	uint64_t addr;
	struct emusgx_switchless_sync_queue_node *next;
};

struct emusgx_eexit_package {
	uint8_t instr;
	uint64_t pid;
	struct emusgx_full_regs regs;
} __attribute__((__packed__));

struct emusgx_page_request_package {
	uint8_t instr;
	uint64_t addr;
	uint64_t semaphore_addr;
} __attribute__((__packed__));

struct emusgx_fault_package {
	uint8_t instr;
	uint8_t gp_or_pf;
	uint64_t val;
	uint64_t pid;
} __attribute__((__packed__));

struct emusgx_aex_package {
	uint8_t instr;
	uint64_t pid;
	struct emusgx_full_regs regs; // Synthetic state
	uint8_t exception_code;
	uint32_t error_code;
	uint64_t fault_addr;
} __attribute__((__packed__));

struct vsgx_exit_info {
	uint8_t exception_code;
	uint32_t error_code;
	uint64_t fault_addr;
};

struct emusgx_register_enclave_vm_package {
	uint8_t instr;
	uint64_t enclave_vm_id;
} __attribute__((__packed__));

extern spinlock_t emusgx_dispatcher_queue_lock;
extern struct semaphore emusgx_dispatcher_sem;
extern struct emusgx_request_queue_node *emusgx_request_queue;
extern struct emusgx_request_queue_node *emusgx_request_queue_tail;

extern char *emusgx_static_aad;
extern char *emusgx_internal_cr_cross_vm_key;

#endif
