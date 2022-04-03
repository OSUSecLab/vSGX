#ifndef EMUSGX_INTERNAL_H
#define EMUSGX_INTERNAL_H

#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

#include "emusgx_arch.h"
#include "emusgx_sender.h"
#include "emusgx_mm.h"

#define EMUSGX_SWITCHLESS_SLOT_COUNT	10

struct emusgx_tmp_key_dependencies {
	uint16_t keyname;
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint64_t ownerepoch[2];
	uint64_t attributes[2];
	uint64_t attributesmask;
	uint32_t mrenclave[8];
	uint32_t mrsigner[8];
	uint64_t keyid[4];
	uint64_t seal_key_fuses[2];
	uint64_t cpusvn[2];
	uint8_t	padding[352];
	uint32_t micselect;
	uint32_t miscmask;
};

void emusgx_gp(int code, struct pt_regs *ptrace_regs);
void emusgx_pf(void __user *addr, struct pt_regs *ptrace_regs);

// Returns a 128-bit secret key
// The user is resiponsible for freeing the key
uint64_t *emusgx_derive_key(const struct emusgx_tmp_key_dependencies *key_dependencies);

// Returns a 128-bit MAC
// The user is resiponsible for freeing the MAC
uint64_t *emusgx_cmac(const uint64_t *key, const void *data, const size_t size);

struct emusgx_epcm *emusgx_get_epcm(void *epc_page);
int emusgx_compare_cpusvn(const uint64_t *cpusvn1, const uint64_t *cpusvn2);

// Cross VM
void emusgx_init_and_share_page(void);
void emusgx_unshare_page(void);
int emusgx_send_data(void *addr, uint64_t size, int target_enclave);

uint8_t emusgx_validate_gpr(void *tcs, uint64_t base, uint32_t ssaframesize);
void emusgx_enter_enclave(void *tcs, void *aep, struct pt_regs *regs);
void emusgx_resume_enclave(void *tcs, void *aep, struct pt_regs *regs);

// return 0 if good
// return 1 if pf on secs
// return 2 if pf on epc_page
// return 3 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_eadd(void *secs, void *epc_page, void *linaddr, void *srcpage, void *secinfo);

// return 0 if good
// return 1 if pf on secs
// return 2 if pf on epc_addr
// return 3 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_eaug(void *secs, uint64_t linaddr, void *epc_addr);

// return rax value
uint64_t emusgx_do_remote_for_eblock(void *epc_page);

// return 0 if good
// return 1 if pf on epc_page
// return 2 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_ecreate(void __user *srcpage, void *epc_page);

// return 0 if good
// return 1 if pf on addr
// return 2 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_eextend(void *addr);

// return rax value
uint64_t emusgx_validate_and_do_remote_for_einit(struct sgx_sigstruct *sigstruct, void *secs, struct sgx_einittoken *einittoken);

// return 0 if good
// return 1 if SGX_MAC_COMPARE_FAIL
// return 2 if pf on EPC page
// return 3 if pf on vaslot
// return 4 if pf on secs
// return 5 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_eldb_eldu(void *srcpage, void *secs, void *vaslot, void *epc_page, struct sgx_pcmd *pcmd, uint64_t linaddr,uint8_t block);

// return rax value
uint64_t emusgx_validate_and_do_remote_for_emodpr(void *epc_page, uint8_t R, uint8_t W, uint8_t X);

// return rax value
uint64_t emusgx_validate_and_do_remote_for_emodt(void *epc_page, uint8_t R, uint8_t W, uint8_t page_type);

// return 0 if good
// return 1 if pf on EPC page
// return 2 if gp(0)
uint8_t emusgx_validate_and_do_remote_for_epa(void *epc_page);

// return rax value
uint64_t emusgx_validate_and_do_remote_for_eremove(void *epc_page);

// return rax value
uint64_t emusgx_validate_and_do_remote_for_ewb(void *epc_page, void *vaslot, struct sgx_pcmd *pcmd, void *srcpage, uint64_t *linaddr);

uint8_t emusgx_register_eexit_request(uint64_t pid);
uint8_t emusgx_wait_for_eexit_request(uint64_t pid, struct emusgx_full_regs *regs, struct pt_regs *fault_regs, uint8_t *is_aex, struct vsgx_exit_info* exit_info);

void vsgx_handle_aex(struct pt_regs *regs, struct vsgx_exit_info *exit_info);

// Responses
int emusgx_register_response(struct emusgx_response *response, uint64_t timeout);

// Crypto
int emusgx_aes_128_gcm_dec(uint8_t *key, uint64_t *counter, void *aad, size_t aad_size, 
				void *cipher_text, size_t cipher_size, void *plain_text, uint64_t *mac);

int emusgx_aes_128_gcm_enc(uint8_t *key, uint64_t *counter, void *aad, size_t aad_size, 
				void *plain_text, size_t plain_size, void *cipher_text, uint64_t *mac);

// Switchless
void vsgx_switchless_init_locks(void);
void emusgx_switchless_write_page(struct emusgx_page_package *package, uint64_t manager_nr);
int emusgx_switchless_new_slot(void *addr, void *original_content, uint64_t manager_nr);
int emusgx_switchless_get_slot(void *addr, uint64_t manager_nr);
void emusgx_sync_manager_pages(uint64_t manager_nr, char force_sync);
int emusgx_switchless_sync_worker(void *dummy);

// Response
int emusgx_release_response(struct emusgx_response *response);
int emusgx_wait_for_response(uint64_t timeout);
void emusgx_handle_response(struct emusgx_raw_response *response);

int emusgx_dispatcher(void *dummy);

int vsgx_run_worker_threads(void);
void vsgx_stop_worker_threads(void);

// Multi-VM
int emusgx_register_enclave_vm(uint64_t enclave_vm_id);
uint64_t emusgx_get_enclave_vm_id(int enclave_index);
int emusgx_get_enclave_index(uint64_t enclave_vm_id);
int emusgx_occupy_enclave_vm(void);
void emusgx_put_back_enclave_vm(void);

int emusgx_register_epc_page(uint64_t epc_addr, int enclave_vm_index, struct emusgx_version_array_page *va_info, uint8_t is_secs);
int emusgx_deregister_epc_page(uint64_t epc_addr);
uint8_t vsgx_is_epc_secs(uint64_t epc_addr);
int emusgx_get_target_enclave_index(uint64_t epc_addr);
struct emusgx_version_array_page *emusgx_get_version_array_page(uint64_t epc_addr);
int emusgx_update_version_array_page(uint64_t epc_addr, struct emusgx_version_array_page *va_info);

#endif
