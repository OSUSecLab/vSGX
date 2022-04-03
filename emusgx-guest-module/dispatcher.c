#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/uaccess.h>

#include <asm/cacheflush.h>

#include "emusgx.h"
#include "emusgx_internal.h"
#include "emusgx_sender.h"
#include "emusgx_debug.h"

// TODO: The 16 bytes key. In production environment
// shall be set before deploy
char *emusgx_internal_cr_cross_vm_key = "EmuSGX Cross VM";

extern struct mm_struct *vsgx_enclave_mm[EMUSGX_MAXIMUM_ENCLAVES];

struct emusgx_request_queue_node *emusgx_request_queue = NULL;
struct emusgx_request_queue_node *emusgx_request_queue_tail = NULL;
DEFINE_SPINLOCK(emusgx_dispatcher_queue_lock);
struct semaphore emusgx_dispatcher_sem = __SEMAPHORE_INITIALIZER(emusgx_dispatcher_sem, 0);

struct emusgx_eexit_queue_node *emusgx_eexit_queue = NULL;
struct emusgx_eexit_queue_node *emusgx_eexit_queue_tail = NULL;
DEFINE_MUTEX(emusgx_eexit_queue_lock);

struct emusgx_switchless_sync_queue_node *emusgx_switchless_sync_queue = NULL;
struct emusgx_switchless_sync_queue_node *emusgx_switchless_sync_queue_tail = NULL;
DEFINE_MUTEX(emusgx_switchless_sync_queue_lock);

struct emusgx_dispatch_slot emusgx_instruction_ret_slot = {.status = EMUSGX_DISPATCH_SLOT_FREE};

static uint64_t emusgx_used_session_number[EMUSGX_MAXIMUM_ENCLAVES][EMUSGX_MAX_SESSION_NUMBER_D64] = { { (uint64_t)0 } }; // Maximum session number = 4095, session number ranged from [0, 4095]

uint8_t emusgx_register_eexit_request(uint64_t pid) {
	struct emusgx_eexit_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_eexit_queue_lock)) {
		pr_info("vSGX: Register EEXIT request killed\n");
		return -1;
	}

	// Search for node
	current_node = emusgx_eexit_queue;
	while (current_node != NULL) {
		if (current_node->pid == pid) {
			break;
		}
		current_node = current_node->next;
	}

	// If found, unexpected
	if (current_node != NULL) {
		mutex_unlock(&emusgx_eexit_queue_lock);
		pr_info("EmuSGX: You've entered the enclave, haven't you? PID = %lld\n", pid);
		return -1;
	}
	else {
		current_node = kmalloc(sizeof(struct emusgx_eexit_queue_node), GFP_KERNEL);
		current_node->slot = kmalloc(sizeof(struct emusgx_dispatch_slot), GFP_KERNEL);
		current_node->slot->status = EMUSGX_DISPATCH_SLOT_FREE;
		current_node->semaphore = (struct semaphore)__SEMAPHORE_INITIALIZER(current_node->semaphore, 0);
		current_node->pid = pid;
		current_node->next = NULL;
		if (emusgx_eexit_queue_tail == NULL) {
			emusgx_eexit_queue = emusgx_eexit_queue_tail = current_node;
		}
		else {
			emusgx_eexit_queue_tail->next = current_node;
			emusgx_eexit_queue_tail = current_node;
		}
	}

	mutex_unlock(&emusgx_eexit_queue_lock);

	return 0;
}

uint8_t emusgx_wait_for_eexit_request(uint64_t pid, struct emusgx_full_regs *regs, struct pt_regs *fault_regs, uint8_t *is_aex, struct vsgx_exit_info* exit_info) {
	struct emusgx_eexit_queue_node *current_node;
	struct emusgx_eexit_queue_node *previous_node = NULL;
	struct emusgx_eexit_package *package;
	struct emusgx_aex_package *aex_package;
	struct emusgx_fault_package *fault_package;
	void *pf_addr;
	uint8_t instr;

	*is_aex = 0;

	// Sleepable
	if (mutex_lock_killable(&emusgx_eexit_queue_lock)) {
		pr_info("vSGX: Wait for EEXIT request killed when searching for node\n");
		return -1;
	}

	// Search for node
	current_node = emusgx_eexit_queue;
	while (current_node != NULL) {
		if (current_node->pid == pid) {
			break;
		}
		previous_node = current_node;
		current_node = current_node->next;
	}

	// If not found, unexpected
	if (current_node == NULL) {
		mutex_unlock(&emusgx_eexit_queue_lock);
		pr_info("EmuSGX: You have not been registered. PID = %lld\n", pid);
		return -1;
	}

	mutex_unlock(&emusgx_eexit_queue_lock);

	// Now wait for the response
	if (down_killable(&current_node->semaphore)) {
		pr_info("EmuSGX: Some one tries to kill me. PID = %lld\n", pid);
		kfree(current_node->slot->data);
		kfree(current_node->slot);
		kfree(current_node);
		return -1;
	}

	// First, find out if it's waking up from a fault
	instr = ((uint8_t *)(current_node->slot->data))[0];
	if (instr == EMUSGX_S_FAULT) {
		fault_package = current_node->slot->data;
		if (fault_package->gp_or_pf == 0) {
			// General protection fault
			kfree(current_node->slot->data);
			kfree(current_node->slot);
			kfree(current_node);
			emusgx_gp(0, fault_regs);
		}
		else {
			pf_addr = (void *)fault_package->val;
			kfree(current_node->slot->data);
			kfree(current_node->slot);
			kfree(current_node);
			emusgx_pf(pf_addr, fault_regs);
		}
		// It actually won't come to this step
		return -1;
	}
	else if (instr == EMUSGX_S_AEX) {
		*is_aex = 1;
		aex_package = current_node->slot->data;
		exit_info->exception_code = aex_package->exception_code;
		exit_info->error_code = aex_package->error_code;
		exit_info->fault_addr = aex_package->fault_addr;
		memcpy(regs, &(aex_package->regs), sizeof(struct emusgx_full_regs));

	}
	else if (instr == EMUSGX_S_EEXIT) {
		package = current_node->slot->data;
		memcpy(regs, &(package->regs), sizeof(struct emusgx_full_regs));
	}
	else {
		pr_info("vSGX: FATAL: Unexpected package in EEXIT handling\n");
		emusgx_gp(0, fault_regs);
	}

	if (mutex_lock_killable(&emusgx_eexit_queue_lock)) {
		pr_info("vSGX: Wait for EEXIT request killed after receiving the response\n");
		return -1;
	}

	// Clear up everything

	if (current_node == emusgx_eexit_queue) {
		// First node
		if (current_node->next == NULL) {
			// The only node
			emusgx_eexit_queue = NULL;
			emusgx_eexit_queue_tail = NULL;
		}
		else {
			emusgx_eexit_queue = current_node->next;
		}
	}
	else {
		previous_node->next = current_node->next;
		if (previous_node->next == NULL) {
			// Last node
			emusgx_eexit_queue_tail = previous_node;
		}
	}

	kfree(current_node->slot->data);
	kfree(current_node->slot);
	kfree(current_node);

	mutex_unlock(&emusgx_eexit_queue_lock);

	return 0;
}

struct emusgx_eexit_queue_node *emusgx_find_eexit_node(uint64_t pid) {
	struct emusgx_eexit_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_eexit_queue_lock)) {
		pr_info("vSGX: Find EEXIT node killed\n");
		return NULL;
	}

	current_node = emusgx_eexit_queue;
	while (current_node != NULL) {
		if (current_node->pid == pid) {
			mutex_unlock(&emusgx_eexit_queue_lock);
			return current_node;
		}
		current_node = current_node->next;
	}

	mutex_unlock(&emusgx_eexit_queue_lock);

	return NULL;
}

struct emusgx_eexit_queue_node *emusgx_find_eexit_node_with_session_number(uint64_t session_number, uint64_t enclave_vm_id) {
	struct emusgx_eexit_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_eexit_queue_lock)) {
		pr_info("vSGX: Find EEXIT node with session number killed\n");
		return NULL;
	}

	current_node = emusgx_eexit_queue;
	while (current_node != NULL) {
		if (current_node->slot->session_number == session_number && current_node->slot->enclave_vm_id == enclave_vm_id) {
			mutex_unlock(&emusgx_eexit_queue_lock);
			return current_node;
		}
		current_node = current_node->next;
	}

	mutex_unlock(&emusgx_eexit_queue_lock);

	return NULL;
}

struct emusgx_dispatch_slot *emusgx_register_switchless_sync_request_and_return_slot(uint64_t addr) {
	struct emusgx_switchless_sync_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_switchless_sync_queue_lock)) {
		pr_info("vSGX: Register switchless sync request killed\n");
		return NULL;
	}

	
	current_node = kmalloc(sizeof(struct emusgx_switchless_sync_queue_node), GFP_KERNEL);
	if (current_node == NULL) {
		pr_info("vSGX: Failed to allocate node for switchless sync request\n");
		mutex_unlock(&emusgx_switchless_sync_queue_lock);
		return NULL;
	}
	current_node->slot = kmalloc(sizeof(struct emusgx_dispatch_slot), GFP_KERNEL);
	if (current_node->slot == NULL) {
		pr_info("vSGX: Failed to allocate slot for switchless sync request\n");
		kfree(current_node);
		mutex_unlock(&emusgx_switchless_sync_queue_lock);
		return NULL;
	}
	current_node->slot->status = EMUSGX_DISPATCH_SLOT_INUSE;
	current_node->addr = addr;
	current_node->next = NULL;
	if (emusgx_switchless_sync_queue_tail == NULL) {
		emusgx_switchless_sync_queue = emusgx_switchless_sync_queue_tail = current_node;
	}
	else {
		emusgx_switchless_sync_queue_tail->next = current_node;
		emusgx_switchless_sync_queue_tail = current_node;
	}


	mutex_unlock(&emusgx_switchless_sync_queue_lock);

	return current_node->slot;
}

struct emusgx_switchless_sync_queue_node *emusgx_find_switchless_sync_node_with_session_number(uint64_t session_number, uint64_t enclave_vm_id) {
	struct emusgx_switchless_sync_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_switchless_sync_queue_lock)) {
		pr_info("vSGX: Find switchless sync node with session number killed\n");
		return NULL;
	}

	current_node = emusgx_switchless_sync_queue;
	while (current_node != NULL) {
		if (current_node->slot->session_number == session_number && current_node->slot->enclave_vm_id == enclave_vm_id) {
			mutex_unlock(&emusgx_switchless_sync_queue_lock);
			return current_node;
		}
		current_node = current_node->next;
	}

	mutex_unlock(&emusgx_switchless_sync_queue_lock);

	pr_info("vSGX: No slot is found for session %lld of enclave ID %lld in switchless sync queue\n", session_number, enclave_vm_id);
	return NULL;
}

void emusgx_dequeue_switchless_sync_node(struct emusgx_dispatch_slot *slot) {
	struct emusgx_switchless_sync_queue_node *previous_node = NULL;
	struct emusgx_switchless_sync_queue_node *current_node;

	// Sleepable
	if (mutex_lock_killable(&emusgx_switchless_sync_queue_lock)) {
		pr_info("vSGX: Dequeue switchless sync node killed\n");
		return;
	}

	current_node = emusgx_switchless_sync_queue;
	while (current_node != NULL) {
		if (current_node->slot == slot) {
			break;
		}
		previous_node = current_node;
		current_node = current_node->next;
	}

	if (current_node == NULL) {
		mutex_unlock(&emusgx_switchless_sync_queue_lock);
		return;
	}

	if (current_node == emusgx_switchless_sync_queue) {
		// First node
		if (current_node->next == NULL) {
			// The only node
			emusgx_switchless_sync_queue = NULL;
			emusgx_switchless_sync_queue_tail = NULL;
		}
		else {
			emusgx_switchless_sync_queue = current_node->next;
		}
	}
	else {
		previous_node->next = current_node->next;
		if (previous_node->next == NULL) {
			// Last node
			emusgx_switchless_sync_queue_tail = previous_node;
		}
	}

	kfree(current_node);

	mutex_unlock(&emusgx_switchless_sync_queue_lock);
}

struct emusgx_dispatch_slot *emusgx_get_slot_with_session_number(uint64_t session_number, uint64_t enclave_vm_id) {
	struct emusgx_eexit_queue_node *eexit_node;
	struct emusgx_switchless_sync_queue_node *switchless_sync_node;

	// First, the encls slot
	if (emusgx_instruction_ret_slot.status == EMUSGX_DISPATCH_SLOT_INUSE) {
		if (emusgx_instruction_ret_slot.session_number == session_number && emusgx_instruction_ret_slot.enclave_vm_id == enclave_vm_id) {
			return &(emusgx_instruction_ret_slot);
		}
	}

	// Next, eexitlist
	eexit_node = emusgx_find_eexit_node_with_session_number(session_number, enclave_vm_id);
	if (eexit_node != NULL) {
		// Found node
		// The slot in the queue will always be INUSE
		return eexit_node->slot;
	}

	// Finally we check switchless sync list
	switchless_sync_node = emusgx_find_switchless_sync_node_with_session_number(session_number, enclave_vm_id);
	if (switchless_sync_node != NULL) {
		// Found node
		return switchless_sync_node->slot;
	}

	return NULL;
}

// return 0 for usable
// 1 for unusable
uint8_t emusgx_check_session_number_usable(uint64_t session_number, uint64_t enclave_vm_id) {
	uint64_t group = session_number / 64;
	uint64_t bit = session_number % 64;
	int enclave_vm_index = emusgx_get_enclave_index(enclave_vm_id);

	// Check if the session number usable bit is 0
	if (session_number >= EMUSGX_MAX_SESSION_NUMBER) {
		pr_info("EmuSGX: Current session number is out of bound\n");
		return 1;
	}


	return (emusgx_used_session_number[enclave_vm_index][group] >> bit) & 1;
}

// return 0 for success
// 1 for unusable
uint8_t emusgx_register_session_number(uint64_t session_number, uint64_t enclave_vm_id) {
	uint64_t group = session_number / 64;
	uint64_t bit = session_number % 64;
	int i;
	int enclave_vm_index = emusgx_get_enclave_index(enclave_vm_id);

	if (enclave_vm_index == -1) {
		pr_err("EmuSGX: Enclave not found for enclave_vm_id %lld\n", enclave_vm_id);
		return 1;
	}

	// No session number collision should happen due to very high session number capacity
	// So no lock is needed
	// First check session number for safety
	if (emusgx_check_session_number_usable(session_number, enclave_vm_id)) {
		return 1;
	}

	// Register the session number
	emusgx_used_session_number[enclave_vm_index][group] |=  ((uint64_t)1 << bit);

	// Perform session number wrapping if the session number is comming to the upper limit
	// Our overhead limit is 20 but it could be changed
	if (EMUSGX_MAX_SESSION_NUMBER - session_number == 20) {
		for (i = 0; i < EMUSGX_MAX_SESSION_NUMBER_D64; i++) {
			emusgx_used_session_number[enclave_vm_index][i] = 0;
		}
	}

	return 0;
}

extern uint8_t vsgx_worker_threads_should_stop;

int emusgx_dispatcher(void *dummy) {
	int decrypt_ret;
	uint8_t instr;
	struct emusgx_request_queue_node *current_node;
	struct emusgx_page_package *page_package;
	struct emusgx_page_request_package *page_request;
	struct emusgx_eexit_queue_node *eexit_node;
	struct emusgx_fault_package *fault_package;
	struct emusgx_register_enclave_vm_package *register_package;
	struct emusgx_dispatch_slot *slot;
	uint64_t iv = 0;
	uint64_t manager_nr;
	unsigned long flags;

	struct emusgx_cross_vm_package *cipher_package;
	struct emusgx_cross_vm_package *plain_package;

	// This process is KILLABLE not INTERRUPTABLE
	// No one shall ever send any signal except for SIGKILL to this process
	while (!vsgx_worker_threads_should_stop) {
		// Down dispatcher
		emusgx_debug_print("EmuSGX: Waiting for package\n");
		if (down_killable(&(emusgx_dispatcher_sem))) {
			// Some one wants to kill me
			// Return
			if (vsgx_worker_threads_should_stop) {
				pr_info("vSGX: Dispatcher should stop\n");
				if (kthread_should_stop()) {
					pr_info("EmuSGX: Some one wants to kill me\n");
					return 0;
				}
			}
		}

		emusgx_debug_print("EmuSGX: Package received. Dispatching\n");

		// Get data
		spin_lock_irqsave(&emusgx_dispatcher_queue_lock, flags);

		// Be QUICK
		// Take out the first node and leave
		current_node = emusgx_request_queue;

		if (current_node == NULL) {
			// Shit happens
			pr_info("EmuSGX: Unexpected error in dispatch queue\n");
			spin_unlock_irqrestore(&emusgx_dispatcher_queue_lock, flags);
			continue;
		}

		emusgx_request_queue = current_node->next;
		if (emusgx_request_queue == NULL) {
			// First node
			emusgx_request_queue_tail = NULL;
		}

		spin_unlock_irqrestore(&emusgx_dispatcher_queue_lock, flags);

		// Decrypt the data
		cipher_package = current_node->page;
		plain_package = kmalloc(sizeof(struct emusgx_cross_vm_package), GFP_KERNEL);

		decrypt_ret = emusgx_aes_128_gcm_dec(emusgx_internal_cr_cross_vm_key, &iv, emusgx_static_aad, 16, cipher_package, 4096 - 16, plain_package, cipher_package->mac);
		free_page((uint64_t)cipher_package);
		free_page((uint64_t)current_node);
		if (decrypt_ret != 0) {
			pr_info("EmuSGX: Unexpected decryption issue\n");
			kfree(plain_package);
			// May be false package
			// Leave it and continue
			continue;
		}

		// Check if it is a new VM registration
		if (plain_package->order == 0) {
			// Check if it is a new VM registration
			if (*((uint8_t *)(plain_package->payload)) == EMUSGX_S_REGISTER_EVM) {
				// Good to go
				// Note that in this case session number 0 is jumped. However
				// since no one else can generate a new package with session 0,
				// we are safe.
				goto reg_evm_entry;
			}
		}
		
		// Now we have the package, to prevent replay attack,
		// we check the session number
		// Only drop the package if the package's order 
		// is 0 because only the first package will create a 
		// new slot and register itself
		if (plain_package->order == 0 && emusgx_check_session_number_usable(plain_package->session_number, plain_package->enclave_vm_id)) {
			// Replay attack is found
			// Drop the package
			pr_info("EmuSGX: Current session number %lld is unuseable for enclave VM %d\n", plain_package->session_number, emusgx_get_enclave_index(plain_package->enclave_vm_id));
			pr_info("EmuSGX: Group: 0x%016llX\n", emusgx_used_session_number[emusgx_get_enclave_index(plain_package->enclave_vm_id)][plain_package->session_number / 64]);
			kfree(plain_package);
			// Leave it and continue
			continue;
		}

		emusgx_debug_print("EmuSGX: Handling %lld/%lld of session %lld of enclave %d\n", plain_package->order, plain_package->total_pages, plain_package->session_number, emusgx_get_enclave_index(plain_package->enclave_vm_id));

		// Now we have the package, for the very first package,
		// we find the corresponding slot to store it
		if (plain_package->order == 0) {
			// Register the session_number
			if (emusgx_register_session_number(plain_package->session_number, plain_package->enclave_vm_id)) {
				// Should not happen
				pr_info("EmuSGX: Unexpected situation. Check if there's a bug\n");
				kfree(plain_package);
				continue;
			}

reg_evm_entry:
			// Generic package fields test
			if (plain_package->total_pages <= 0) {
				pr_info("EmuSGX: Invalid empty page package\n");
				kfree(plain_package);
				continue;
			}
			if (plain_package->total_pages != (plain_package->total_size / EMUSGX_PAYLOAD_SIZE + ((plain_package->total_size % EMUSGX_PAYLOAD_SIZE != 0) ? 1 : 0))) {
				pr_info("EmuSGX: Package total pages does not match total size\n");
				kfree(plain_package);
				continue;
			}

			// Find its type
			// The first uint8_t of every package is uint8_t instr
			// which indicates the type of the package
			instr = *((uint8_t *)(plain_package->payload));
			emusgx_debug_print("EmuSGX: instr = %d\n", instr);
			if (instr == EMUSGX_S_SWITCHLESS) {
				// Switchless 
				// Find the corresponding slot
				// We are now substitute the enclave index as the manager_nr
				manager_nr = emusgx_get_enclave_index(plain_package->enclave_vm_id);
				
				/*
				slot_index = emusgx_switchless_get_slot((void *)((struct emusgx_page_package *)(plain_package->payload))->addr, manager_nr);
				if (slot_index == -1) {
					// This page is swapped out of the sync list
					// Nothing is done. It's cool
					// Drop the package
					kfree(plain_package);
					continue;
				}
				*/
				// We must sync all of the received pages since a page might be synced whe it's dropped
				// It is the guest VM side who first drops the page
				// Note that this will not introduce new vulnerabilities because an enclave VM is 
				// fully trusted so that if it's compromised there will be no "safety" anymore

				// This is a huge difference between the enclave VM and the guest VM

				slot = emusgx_register_switchless_sync_request_and_return_slot(((struct emusgx_page_package *)(plain_package->payload))->addr);
				if (slot == NULL) {
					pr_info("vSGX: Failed to allocate slot for switchless syncing\n");
					kfree(plain_package);
					continue;
				}
				slot->data = kmalloc(plain_package->total_size, GFP_KERNEL);
				slot->session_number = plain_package->session_number;
				slot->total_pages = plain_package->total_pages;
				slot->current_order = plain_package->order; // Here must be zero
				slot->total_size = plain_package->total_size;
				slot->enclave_vm_id = plain_package->enclave_vm_id;
			}
			else if (instr == EMUSGX_S_PAGEREQ) {
				// There should be one and only one package
				if (plain_package->total_pages != 1) {
					pr_info("EmuSGX: More than one package for a page request???\n");
					kfree(plain_package);
					continue;
				}

				// On a regular Linux machine, you have to do a mlock to the page
				// But here we ignore it and assume that you turn off the swap feature
				// Get the page and send it
				page_request = (struct emusgx_page_request_package *)(plain_package->payload);
				page_package = kmalloc(sizeof(struct emusgx_page_package), GFP_KERNEL);
				if (page_package == NULL) {
					pr_info("EmuSGX: Failed to allocate page package\n");
					kfree(plain_package);
					continue;
				}
				page_package->instr = EMUSGX_S_PAGEREQ;
				page_package->addr = page_request->addr;
				page_package->id = page_request->semaphore_addr;

				kthread_use_mm(vsgx_enclave_mm[emusgx_get_enclave_index(plain_package->enclave_vm_id)]);
				//pr_info("vSGX_DEBUG: Requesting 0x%016llX\n", page_request->addr);
				//__uaccess_begin();
				//clflush_cache_range((void *)page_package->addr, 4096);
				//__uaccess_end();
				if (copy_from_user(page_package->page, (void __user *)page_request->addr, 4096)) {
					// Failed to copy the page due to *any* reason
					// Failed to fetch
					pr_info("EmuSGX: Failed to fetch page request at 0x%016llX\n", page_request->addr);
					kthread_unuse_mm(vsgx_enclave_mm[emusgx_get_enclave_index(plain_package->enclave_vm_id)]);
					page_package->addr = (uint64_t)NULL;
				}
				kthread_unuse_mm(vsgx_enclave_mm[emusgx_get_enclave_index(plain_package->enclave_vm_id)]);

				// Send the package back
				if (emusgx_send_data(page_package, sizeof(struct emusgx_page_package), emusgx_get_enclave_index(plain_package->enclave_vm_id))) {
					pr_info("EmuSGX: Failed to send back page request data\n");
				}

				emusgx_debug_print("EmuSGX: Requesting address of 0x%016llX", (uint64_t)page_request->addr);

				// Update the switchless syncing slot
				if (page_package->addr != (uint64_t)NULL) {
					kthread_use_mm(vsgx_enclave_mm[emusgx_get_enclave_index(plain_package->enclave_vm_id)]);
					emusgx_switchless_new_slot((void __user *)page_request->addr, page_package->page, emusgx_get_enclave_index(plain_package->enclave_vm_id));
					kthread_unuse_mm(vsgx_enclave_mm[emusgx_get_enclave_index(plain_package->enclave_vm_id)]);
				}
				kfree(page_package);
				kfree(plain_package);
				// It's done, just continue. No slot is needed
				continue;
			}
			else if (instr == EMUSGX_S_EEXIT) {
				// EEXIT handling
				// First we find corresponding waiting thread

				eexit_node = emusgx_find_eexit_node(((struct emusgx_eexit_package *)(plain_package->payload))->pid);
				if (eexit_node == NULL) {
					// No one is waiting for this eexit
					// This is a false package
					pr_info("EmuSGX: False eexit package is received\n");
					kfree(plain_package);
					continue;
				}

				if (eexit_node->slot->status != EMUSGX_DISPATCH_SLOT_FREE) {
					// Someone is transmitting the data already
					// This should not happen
					// Drop the package
					pr_info("EmuSGX: EEXIT already handled\n");
					kfree(plain_package);
					continue;
				}

				eexit_node->slot->status = EMUSGX_DISPATCH_SLOT_INUSE;
				eexit_node->slot->session_number = plain_package->session_number;
				eexit_node->slot->total_pages = plain_package->total_pages;
				eexit_node->slot->current_order = plain_package->order;
				eexit_node->slot->total_size = plain_package->total_size;
				eexit_node->slot->enclave_vm_id = plain_package->enclave_vm_id;
				eexit_node->slot->data = kmalloc(sizeof(struct emusgx_eexit_package), GFP_KERNEL);

				slot = eexit_node->slot;
			}
			else if (instr == EMUSGX_S_AEX) {
				// EEXIT handling
				// First we find corresponding waiting thread

				eexit_node = emusgx_find_eexit_node(((struct emusgx_aex_package *)(plain_package->payload))->pid);
				if (eexit_node == NULL) {
					// No one is waiting for this eexit
					// This is a false package
					pr_info("EmuSGX: False eexit package is received\n");
					kfree(plain_package);
					continue;
				}

				if (eexit_node->slot->status != EMUSGX_DISPATCH_SLOT_FREE) {
					// Someone is transmitting the data already
					// This should not happen
					// Drop the package
					pr_info("EmuSGX: EEXIT already handled\n");
					kfree(plain_package);
					continue;
				}

				eexit_node->slot->status = EMUSGX_DISPATCH_SLOT_INUSE;
				eexit_node->slot->session_number = plain_package->session_number;
				eexit_node->slot->total_pages = plain_package->total_pages;
				eexit_node->slot->current_order = plain_package->order;
				eexit_node->slot->total_size = plain_package->total_size;
				eexit_node->slot->enclave_vm_id = plain_package->enclave_vm_id;
				eexit_node->slot->data = kmalloc(sizeof(struct emusgx_aex_package), GFP_KERNEL);

				slot = eexit_node->slot;
			}
			else if (instr == EMUSGX_S_FAULT) {
				// There should be one and only one package
				if (plain_package->total_pages != 1) {
					pr_info("EmuSGX: More than one package for a page request???\n");
					kfree(plain_package);
					continue;
				}

				// We should grab the EEXIT slot
				fault_package = (struct emusgx_fault_package *)(plain_package->payload);
				eexit_node = emusgx_find_eexit_node(fault_package->pid);
				if (eexit_node == NULL) {
					// No one is waiting for this fault
					// This is a false package
					pr_info("EmuSGX: False fault package is received\n");
					kfree(plain_package);
					continue;
				}

				if (eexit_node->slot->status != EMUSGX_DISPATCH_SLOT_FREE) {
					// Someone is transmitting the data already
					// This should not happen
					// Drop the package
					pr_info("EmuSGX: EEXIT already handled\n");
					kfree(plain_package);
					continue;
				}

				eexit_node->slot->status = EMUSGX_DISPATCH_SLOT_INUSE;
				eexit_node->slot->session_number = plain_package->session_number;
				eexit_node->slot->total_pages = plain_package->total_pages;
				eexit_node->slot->current_order = plain_package->order;
				eexit_node->slot->total_size = plain_package->total_size;
				eexit_node->slot->enclave_vm_id = plain_package->enclave_vm_id;
				eexit_node->slot->data = kmalloc(sizeof(struct emusgx_fault_package), GFP_KERNEL);

				memcpy(eexit_node->slot->data, fault_package, sizeof(struct emusgx_fault_package));

				// Wake up the semaphore
				up(&eexit_node->semaphore);

				// The node will be freed by the woken-up thread
				// in emusgx_wait_for_eexit_request
				
				kfree(plain_package);
				// It's done, just continue. No slot is needed
				continue;
			}
			else if (instr == EMUSGX_S_REGISTER_EVM) {
				// There should be one and only one package
				if (plain_package->total_pages != 1) {
					pr_info("EmuSGX: More than one package for an enclave VM registration???\n");
					kfree(plain_package);
					continue;
				}

				// We don't have to use lock on this
				// The reason is that there is only one dispatcher thread in the guest VM
				// so no other thread will be trying to add a new enclave VM
				register_package = (struct emusgx_register_enclave_vm_package *)(plain_package->payload);
				emusgx_register_enclave_vm(register_package->enclave_vm_id);
				
				kfree(plain_package);
				continue;
			}
			else {
				// enclu and encls responses
				if (emusgx_instruction_ret_slot.status != EMUSGX_DISPATCH_SLOT_FREE) {
					// Not free, this should not happen
					// Drop the package
					pr_info("EmuSGX: Instruction response slot is in use\n");
					kfree(plain_package);
					continue;
				}
				emusgx_instruction_ret_slot.status = EMUSGX_DISPATCH_SLOT_INUSE;
				emusgx_instruction_ret_slot.session_number = plain_package->session_number;
				emusgx_instruction_ret_slot.total_pages = plain_package->total_pages;
				emusgx_instruction_ret_slot.current_order = plain_package->order;
				emusgx_instruction_ret_slot.total_size = plain_package->total_size;
				emusgx_instruction_ret_slot.enclave_vm_id = plain_package->enclave_vm_id;

				// Allocate the package data
				emusgx_instruction_ret_slot.data = kmalloc(plain_package->total_size, GFP_KERNEL);
				if (emusgx_instruction_ret_slot.data == NULL) {
					pr_info("EmuSGX: Failed to allocate data for instruction response\n");
					emusgx_instruction_ret_slot.status = EMUSGX_DISPATCH_SLOT_FREE;
					kfree(plain_package);
					continue;
				}

				slot = &emusgx_instruction_ret_slot;
			}
		}
		else {
			// Order 1 or above
			// First get the slot
			slot = emusgx_get_slot_with_session_number(plain_package->session_number, plain_package->enclave_vm_id);

			if (slot == NULL) {
				// No slot is found
				pr_info("EmuSGX: No slot is found for the session\n");
				kfree(plain_package);
				continue;
			}

			// Validate the slot
			if (slot->total_pages != plain_package->total_pages) {
				pr_info("EmuSGX: Package total pages mismatch\n");
				// Drop the package;
				kfree(plain_package);
				continue;
			}
			if (slot->current_order != plain_package->order - 1) { // Must be the next package
				pr_info("EmuSGX: Package order mismatch\n");
				// Drop the package;
				kfree(plain_package);
				continue;
			}
			if (slot->total_size != plain_package->total_size) {
				pr_info("EmuSGX: Package size mismatch\n");
				// Drop the package;
				kfree(plain_package);
				continue;
			}
			if (slot->total_pages <= plain_package->order) {
				pr_info("EmuSGX: Package order overflow\n");
				// Drop the package;
				kfree(plain_package);
				continue;
			}
			// enclave_vm_id and session_number must match because we found the slot using these two
			// Update the order
			slot->current_order += 1;
		}

		// Now we copy the data to the node
		if ((plain_package->order == plain_package->total_pages - 1) && (plain_package->total_size % EMUSGX_PAYLOAD_SIZE != 0)) {
			// The final bytes
			memcpy(slot->data + EMUSGX_PAYLOAD_SIZE * plain_package->order, &(plain_package->payload[0]), plain_package->total_size % EMUSGX_PAYLOAD_SIZE);
		}
		else {
			// Copy the whole payload
			memcpy(slot->data + EMUSGX_PAYLOAD_SIZE * plain_package->order, &(plain_package->payload[0]), EMUSGX_PAYLOAD_SIZE);
		}


		// plain_package is not used anymore
		// Free it
		kfree(plain_package);

		// Finalization: dispatch signal to the handler thread or just do it on our own
		if (slot->current_order == slot->total_pages - 1) {
			// Check the instr and dispatch
			instr = *((uint8_t *)(slot->data));
			if (instr == EMUSGX_S_SWITCHLESS) {
				page_package = slot->data;
				emusgx_dequeue_switchless_sync_node(slot);

				kthread_use_mm(vsgx_enclave_mm[emusgx_get_enclave_index(slot->enclave_vm_id)]);
				emusgx_switchless_write_page(page_package, emusgx_get_enclave_index(slot->enclave_vm_id));
				kthread_unuse_mm(vsgx_enclave_mm[emusgx_get_enclave_index(slot->enclave_vm_id)]);

				kfree(slot->data);
				kfree(slot);
			}
			/* else if (instr == EMUSGX_S_PAGEREQ) {
				// Not possible
				// Since we have handled it as soon as we received the package
			} */
			// encls and enclu
			// Have to be differentiated
			else if (instr == EMUSGX_S_EEXIT) {
				// EEXIT
				// Wake up the waiting handler
				eexit_node = emusgx_find_eexit_node(((struct emusgx_eexit_package *)(slot->data))->pid);
				if (eexit_node == NULL) {
					// Should not happen
					pr_info("EmuSGX: Unexpected eexit node not found\n");
				}

				// Wake up the semaphore
				up(&eexit_node->semaphore);

				// The node will be freed by the woken-up thread
				// in emusgx_wait_for_eexit_request
			}
			else if (instr == EMUSGX_S_AEX) {
				// AEX
				// Wake up the waiting handler
				eexit_node = emusgx_find_eexit_node(((struct emusgx_aex_package *)(slot->data))->pid);
				if (eexit_node == NULL) {
					// Should not happen
					pr_info("EmuSGX: Unexpected eexit node not found\n");
				}

				// Wake up the semaphore
				up(&eexit_node->semaphore);

				// The node will be freed by the woken-up thread
				// in emusgx_wait_for_eexit_request
			}
			/* else if (instr == EMUSG_S_FAULT) {
				// Not possible
				// Since we have handled it as soon as we received the package
			}*/
			else {
				// encls response
				// The slot is now filled
				// We shall call the response handler
				// pr_info("EmuSGX: Now handling ENCLS response\n");
				emusgx_handle_response(slot->data);
				
				// Clean up
				kfree(slot->data);

				// Slot is freed
				slot->status = EMUSGX_DISPATCH_SLOT_FREE;

			}
		}
	}
	return 0;
}
