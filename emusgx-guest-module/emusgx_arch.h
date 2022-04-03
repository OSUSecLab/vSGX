#ifndef EMUSGX_ARCH_H
#define EMUSGX_ARCH_H

#include <linux/kernel.h>

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3476

struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssaframesize;
	uint32_t miscselect;
	uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
	union {
		uint64_t attributes;
		struct {
			uint8_t reserved1	: 1;
			uint8_t debug		: 1;
			uint8_t mod64bit	: 1;
			uint8_t reserved2	: 1;
			uint8_t provisionkey	: 1;
			uint8_t einittokenkey	: 1;
			uint64_t reserved3	: 58;
		}  __attribute__((__packed__)) attribute;
	};
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t	reserved3[SGX_SECS_RESERVED3_SIZE];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint64_t eid;
	uint8_t	padding[352];
	uint8_t reserved4[SGX_SECS_RESERVED4_SIZE];
} __attribute__((__packed__));

#define SGX_PT_SECS		0x00
#define SGX_PT_TCS		0x01
#define SGX_PT_REG		0x02
#define SGX_PT_VA		0x03
#define SGX_PT_TRIM		0x04

struct sgx_secinfo {
	struct {
		uint8_t R 		: 1;
		uint8_t W		: 1;
		uint8_t X		: 1;
		uint8_t pending		: 1;
		uint8_t modified	: 1;
		uint8_t reserved	: 3;
		uint8_t page_type	: 8;
		uint64_t reserved2	: 48;
	} flags;
	uint64_t reserved[7];
} __attribute__((__packed__));

#define SGX_LAUNCH_KEY 		0
#define SGX_PROVISION_KEY	1
#define SGX_PROVISION_SEAL_KEY	2
#define SGX_REPORT_KEY		3
#define SGX_SEAL_KEY		4

struct sgx_keyrequest {
	uint16_t keyname;
	union {
		uint16_t keypolicy;
		struct {
			uint8_t mrenclave	: 1;
			uint8_t mrsigner	: 1;
			uint32_t reserved	: 14;
		} __attribute__((__packed__)) policy;
	};
	uint16_t isvsvn;
	uint16_t reserved;
	uint64_t cpusvn[2];
	uint64_t attributemask[2];
	uint64_t keyid[4];
	uint32_t miscmask;
	uint8_t reserved2[436];
} __attribute__((__packed__));

struct sgx_targetinfo {
	uint32_t measurement[8];
	uint64_t attributes[2];
	uint32_t reserved1;
	uint32_t miscselect;
	uint8_t reserved2[456];
} __attribute__((__packed__));

struct sgx_report {
	uint64_t cpusvn[2];
	uint32_t miscselect;
	uint8_t reserved1[28];
	uint64_t attributes[2];
	uint32_t mrenclave[8]; 
	uint64_t reserved2[4];
	uint32_t mrsigner[8];
	uint8_t reserved3[96];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[60];
	uint8_t reportdata[64]; // 64 byte buffer
	uint64_t keyid[4];
	uint64_t mac[2];
} __attribute__((__packed__));

struct sgx_tcs {
	uint64_t reserved1;
	struct {
		uint8_t dbgoptin : 1;
		uint64_t reserved2 : 63;
	} __attribute__((__packed__)) flags;
	uint64_t ossa;
	uint32_t cssa;
	uint32_t nssa;
	uint64_t oentry;
	uint64_t reserved3;
	uint64_t ofsbasgx;
	uint64_t ogsbasgx;
	uint32_t fslimit;
	uint32_t gslimit;
	uint8_t reserved4[4024];
} __attribute__((__packed__));

struct sgx_pageinfo {
	uint64_t linaddr;
	uint64_t srcpage;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __attribute__((__packed__));

struct sgx_sigstruct {
	uint64_t header[2];
	uint32_t vendor;
	uint32_t date;
	uint64_t header2[2];
	uint32_t swdefined;
	uint8_t reserved1[84];
	uint8_t modulus[384];
	uint32_t exponent;
	uint8_t signature[384];
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[20];
	uint64_t attributes[2];
	uint64_t attributemask[2];
	uint8_t enclavehash[32];
	uint8_t reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[12];
	uint8_t q1[384];
	uint8_t q2[384];
} __attribute__((__packed__));

struct sgx_einittoken{
	uint32_t valid;
	uint8_t reserved1[44];
	uint64_t attributes[2];
	uint64_t attributemask[2];
	uint32_t mrenclave[8];
	uint8_t reserved2[32];
	uint32_t mrsigner[8];
	uint8_t reserved3[32];
	uint64_t cpusvnle[2];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved4[24];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle[2];
	uint64_t keyid[4];
	uint64_t mac[2];
} __attribute__((__packed__));

struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	uint64_t enclaveid;
	uint8_t reserved[40];
	uint64_t mac[2];
} __attribute__((__packed__));

#endif