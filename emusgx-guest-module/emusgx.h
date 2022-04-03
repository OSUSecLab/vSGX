#ifndef EMUSGX_H
#define EMUSGX_H

#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/interrupt.h>

#include "emusgx_arch.h"

#define EMUSGX_MAXIMUM_ENCLAVES 10

#define EMUSGX_ECREATE		0x00
#define EMUSGX_EADD		0x01
#define EMUSGX_EINIT		0x02
#define EMUSGX_EREMOVE		0x03
#define EMUSGX_EDBGRD		0x04
#define EMUSGX_EDBGWR		0x05
#define EMUSGX_EEXTEND		0x06
#define EMUSGX_ELDB		0x07
#define EMUSGX_ELDU		0x08
#define EMUSGX_EBLOCK		0x09
#define EMUSGX_EPA		0x0A
#define EMUSGX_EWB		0x0B
#define EMUSGX_ETRACK		0x0C
#define EMUSGX_EAUG		0x0D
#define EMUSGX_EMODPR		0x0E
#define EMUSGX_EMODT		0x0F

#define EMUSGX_EREPORT		0x00
#define EMUSGX_EGETKEY		0x01
#define EMUSGX_EENTER		0x02
#define EMUSGX_ERESUME		0x03
#define EMUSGX_EEXIT		0x04
#define EMUSGX_EACCEPT		0x05
#define EMUSGX_EMODPE		0x06
#define EMUSGX_EACCEPTCOPY	0x07

#define EMUSGX_SUCCESS			0
#define EMUSGX_INVALID_SIG_STRUCT	1
#define EMUSGX_INVALID_ATTRIBUTE	2
#define EMUSGX_BLKSTATE			3
#define EMUSGX_INVALID_MEASUREMENT	4
#define EMUSGX_NOTBLOCKABLE		5
#define EMUSGX_PG_INVLD			6
#define EMUSGX_LOCKFAIL			7
#define EMUSGX_INVALID_SIGNATURE	8
#define EMUSGX_MAC_COMPARE_FAIL		9
#define EMUSGX_PAGE_NOT_BLOCKED		10
#define EMUSGX_NOT_TRACKED		11
#define EMUSGX_VA_SLOT_OCCUPIED		12
#define EMUSGX_CHILD_PRESENT		13
#define EMUSGX_ENCLAVE_ACT		14
#define EMUSGX_ENTRYEPOCH_LOCKED	15
#define EMUSGX_INVALID_EINITTOKEN	16
#define EMUSGX_PREV_TRK_INCMPL		17
#define EMUSGX_PG_IS_SECS		18
#define EMUSGX_PAGE_ATTRIBUTES_MISMATCH	19
#define EMUSGX_PAGE_NOT_MODIFIABLE	20
#define EMUSGX_INVALID_CPUSVN		32
#define EMUSGX_INVALID_ISVSVN		64
#define EMUSGX_UNMASKED_EVENT		128
#define EMUSGX_INVALID_KEYNAME		256

#define EMUSGX_PF_RBX			508
#define EMUSGX_GP			509
#define EMUSGX_PF_RCX			510
#define EMUSGX_PF_RDX			511

struct emusgx_regs {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	union {
		unsigned long eflags;
		struct {
			uint8_t CF 		: 1;
			uint8_t Reserved1	: 1; // always 1
			uint8_t PF		: 1;
			uint8_t Reserved2	: 1; // always 0
			uint8_t AF		: 1;
			uint8_t Reserved3	: 1; // always 0
			uint8_t ZF		: 1;
			uint8_t SF		: 1;
			uint8_t TFIFDF		: 3; // don't care
			uint8_t OF		: 1;
			uint32_t DONOTCARE	: 20;
			uint32_t ZEROS		: 32;
		} __attribute__((__packed__)) flags;
	};
	
};

struct emusgx_epcm {
	uint8_t valid;
	uint8_t R;
	uint8_t W;
	uint8_t X;
	uint8_t page_type;
	struct sgx_secs *enclave_secs;
	void *enclave_address;
	uint8_t blocked;
	uint8_t pending;
	uint8_t modified;
};

void emusgx_handle_enclu(struct emusgx_regs *reg_status, struct pt_regs *regs);
uint8_t emusgx_handle_encls(struct emusgx_regs *reg_status, struct pt_regs *fault_regs);

void *emusgx_get_and_share_page(void);
void emusgx_free_shared_page(void *page_addr);
irqreturn_t emusgx_irq_handler(int irq, void *dev_id);

#endif // EMUSGX_H
