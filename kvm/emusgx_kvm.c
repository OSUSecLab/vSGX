#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/bitops.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>

#include <asm/cacheflush.h>

#include "x86.h"
#include "irq.h"
#include "emusgx_kvm.h"

struct kvm_vcpu *emusgx_guest_vcpu = NULL;
struct kvm_vcpu *emusgx_enclave_vcpu[EMUSGX_MAXIMUM_ENCLAVE_VMS] = { NULL };
struct kvm *emusgx_enclave_kvm_identifier[EMUSGX_MAXIMUM_ENCLAVE_VMS] = { NULL };

void *emusgx_enclave_receive_page_gpa[EMUSGX_MAXIMUM_ENCLAVE_VMS] = { NULL };
void *emusgx_guest_receive_page_gpa = NULL;

int emusgx_regietered_enclave_vms = 0;
DEFINE_SPINLOCK(emusgx_register_enclave_vm_lock);

struct semaphore emusgx_enclave_sender_semaphore = __SEMAPHORE_INITIALIZER(emusgx_enclave_sender_semaphore, 0);
struct semaphore emusgx_guest_sender_semaphore = __SEMAPHORE_INITIALIZER(emusgx_guest_sender_semaphore, 0);

struct semaphore emusgx_enclave_sender_ack_semaphore = __SEMAPHORE_INITIALIZER(emusgx_enclave_sender_ack_semaphore, 0);
struct semaphore emusgx_guest_sender_ack_semaphore = __SEMAPHORE_INITIALIZER(emusgx_guest_sender_ack_semaphore, 0);

struct emusgx_simple_list_node *emusgx_enclave_send_queue = NULL;
struct emusgx_simple_list_node *emusgx_enclave_send_queue_tail = NULL;
DEFINE_SPINLOCK(emusgx_enclave_send_queue_lock);

struct emusgx_simple_list_node *emusgx_guest_send_queue = NULL;
struct emusgx_simple_list_node *emusgx_guest_send_queue_tail = NULL;
DEFINE_SPINLOCK(emusgx_guest_send_queue_lock);

struct task_struct *emusgx_enclave_sender_task = NULL;
struct task_struct *emusgx_guest_sender_task = NULL;

uint8_t emusgx_enclave_sender_should_stop = 0;
uint8_t emusgx_guest_sender_should_stop = 0;

void *emusgx_enclave_retrive_page = NULL;
void *emusgx_guest_retrive_page = NULL;

static uint64_t stamps_pushed[20];
static uint64_t stamps_acked[20];
static uint64_t stamp_i = 0;

int emusgx_is_sender_ready(void) {
	return (emusgx_enclave_sender_task != NULL) && (emusgx_guest_sender_task != NULL);
}

void emusgx_queue_package(void *data, int target_vm_id, uint8_t enclave_or_guest) {
	struct semaphore *semaphore;
	spinlock_t *lock;
	struct emusgx_simple_list_node **queue_head;
	struct emusgx_simple_list_node **queue_tail;
	struct emusgx_simple_list_node *current_node;

	if (enclave_or_guest == 0) {
		// Enclave
		semaphore = &emusgx_enclave_sender_semaphore;
		queue_head = &emusgx_enclave_send_queue;
		queue_tail = &emusgx_enclave_send_queue_tail;
		lock = &emusgx_enclave_send_queue_lock;
	}
	else {
		// Guest
		semaphore = &emusgx_guest_sender_semaphore;
		queue_head = &emusgx_guest_send_queue;
		queue_tail = &emusgx_guest_send_queue_tail;
		lock = &emusgx_guest_send_queue_lock;
	}

	current_node = kmalloc(sizeof(struct emusgx_simple_list_node), GFP_KERNEL);
	if (current_node == NULL) {
		pr_info("EmuSGX: Failed to allocate send node\n");
		return;
	}
	current_node->data = data;
	current_node->next = NULL;
	current_node->target_vm_id = target_vm_id;

	spin_lock(lock);

	if (*queue_head == NULL) {
		*queue_head = current_node;
		*queue_tail = current_node;
	}
	else {
		(*queue_tail)->next = current_node;
		*queue_tail = current_node;
	}

	spin_unlock(lock);

	up(semaphore);
}

int emusgx_retrive_page(struct kvm_vcpu *vcpu, uint64_t gpa, uint8_t enclave_or_guest) {
	gfn_t guest_fn;
	uint64_t hva;
	int write_ret_val;
	void *data;

	if (vcpu == NULL) {
		pr_info("EmuSGX: No guest found\n");
		return -1;
	}

	if (enclave_or_guest == 0) {
		// encalve
		// But we are reading from GUEST!
		data = emusgx_guest_retrive_page;
	}
	else {
		data = emusgx_enclave_retrive_page;
	}

	// Copy the page to the receive page
	//pr_info("EmuSGX: Signature: First: 0x%016llX. MAC: %016llX %016llX\n", *((uint64_t *)data), *((uint64_t *)((void *)data + 4096 - 16)), *((uint64_t *)((void *)data + 4096 - 8)));

	guest_fn = gpa >> PAGE_SHIFT;
	hva = gfn_to_hva(vcpu->kvm, guest_fn);
	write_ret_val = kvm_write_guest_page(vcpu->kvm, guest_fn, data, 0, 4096);
	if (write_ret_val) {
		pr_info("EmuSGX: Failed to fully write to the VM with %d bytes unwritten\n", write_ret_val);
		pr_info("EmuSGX: GPA = 0x%016llX\n", gpa);
	}
	__uaccess_begin();
	clflush_cache_range((void *)hva, 4096);
	__uaccess_end();

	return write_ret_val;
}

int emusgx_sender(void *args) {
	// args: uint8_t enclave_or_guest
	//               0 for enclave
	//               1 for guest
	uint8_t enclave_or_guest = (uint8_t)((uint64_t)args);
	struct kvm_vcpu *vcpu;
	void *receive_page_gpa;
	struct semaphore *semaphore;
	struct semaphore *ack_semaphore;
	spinlock_t *lock;
	struct emusgx_simple_list_node **queue_head;
	struct emusgx_simple_list_node **queue_tail;
	struct emusgx_simple_list_node *current_node;
	uint8_t *should_stop;
	uint64_t fail_counter = 1;
	char *receiver_name;

	pr_info("EmuSGX: Sender says hello\n");

	if (enclave_or_guest == 0) {
		// Enclave
		// We send to guest
		vcpu = emusgx_guest_vcpu;
		receive_page_gpa = emusgx_guest_receive_page_gpa;
		// But we are enclave
		semaphore = &emusgx_enclave_sender_semaphore;
		ack_semaphore = &emusgx_enclave_sender_ack_semaphore;
		queue_head = &emusgx_enclave_send_queue;
		queue_tail = &emusgx_enclave_send_queue_tail;
		lock = &emusgx_enclave_send_queue_lock;
		should_stop = &emusgx_enclave_sender_should_stop;
		receiver_name = "guest";
	}
	else {
		// Guest
		// We send to enclave
		// vcpu = emusgx_enclave_vcpu;
		// receive_page_gpa = emusgx_enclave_receive_page_gpa;
		// But we are guest
		semaphore = &emusgx_guest_sender_semaphore;
		ack_semaphore = &emusgx_guest_sender_ack_semaphore;
		queue_head = &emusgx_guest_send_queue;
		queue_tail = &emusgx_guest_send_queue_tail;
		lock = &emusgx_guest_send_queue_lock;
		should_stop = &emusgx_guest_sender_should_stop;
		receiver_name = "enclave";
	}

	*should_stop = 0;

	while(1) {
		// Update these variables every time
		
		if (*should_stop) {
			pr_info("EmuSGX: Sender says goodbye\n");
			return 1;
		}
		while (down_interruptible(semaphore)) {
			// A signal is comming
			// Should I die?
			if (*should_stop) {
				pr_info("EmuSGX: Sender says goodbye\n");
				return 1;
			}
		}

		// pr_info("EmuSGX: A new page is received\n");

		// Update these variables every time
		if (enclave_or_guest == 0) {
			// Enclave
			// We send to guest
			vcpu = emusgx_guest_vcpu;
			receive_page_gpa = emusgx_guest_receive_page_gpa;
			// But we are enclave
			queue_head = &emusgx_enclave_send_queue;
			queue_tail = &emusgx_enclave_send_queue_tail;
		}
		else {
			// Guest
			// We send to enclave
			// vcpu = emusgx_enclave_vcpu;
			// receive_page_gpa = emusgx_enclave_receive_page_gpa;
			// But we are guest
			queue_head = &emusgx_guest_send_queue;
			queue_tail = &emusgx_guest_send_queue_tail;
		}


		// Has new package to send
		// Sleepable
		spin_lock(lock);
		
		// Get the queue's head
		current_node = *queue_head;
		if (current_node == NULL) {
			spin_unlock(lock);
			pr_info("EmuSGX: Does not seem to have a package to send\n");
			continue;
		}

		// Pop the queue
		*queue_head = current_node->next;
		if (*queue_head == NULL) {
			*queue_tail = NULL;
		}

		spin_unlock(lock);
		
		// Ask the VM to retrive the page
		if (enclave_or_guest == 0) {
			emusgx_enclave_retrive_page = current_node->data;
		}
		else {
			emusgx_guest_retrive_page = current_node->data;
			vcpu = emusgx_enclave_vcpu[current_node->target_vm_id];
			receive_page_gpa = emusgx_enclave_receive_page_gpa[current_node->target_vm_id];
		}
resend_signal:
		while (ack_semaphore->count == 0) {
			if (kvm_arch_interrupt_allowed(vcpu) && ack_semaphore->count == 0) {
				//pr_info("EmuSGX: Ready to queue interrupt\n");
				kvm_set_irq(vcpu->kvm, KVM_USERSPACE_IRQ_SOURCE_ID, 10, 1, false);
				kvm_set_irq(vcpu->kvm, KVM_USERSPACE_IRQ_SOURCE_ID, 10, 0, false);
				// pr_info("EmuSGX: Sent request\n");
				break;
			}
			// Backoff 20us
			udelay(20);
		}
		if (stamp_i < 20 && enclave_or_guest != 0) {
			stamps_pushed[stamp_i] = ktime_get_real_ns();
		}

		// Wait for ack
		if (*should_stop) {
			pr_info("EmuSGX: Sender says goodbye\n");
			return 1;
		}
		while (down_timeout(ack_semaphore, HZ / 100)) {
			// If not receiving an ACK in 10 ms
			if (fail_counter % 300 == 0)
				pr_err("EmuSGX: Not receiving an ACK in 10 ms for %lld times from %s. Will try again\n", fail_counter, receiver_name);
			fail_counter += 1;
			goto resend_signal;
		}
		fail_counter = 1;
		if (stamp_i < 20 && enclave_or_guest != 0) {
			stamps_acked[stamp_i] = ktime_get_real_ns();
			stamp_i += 1;
		}
		if (stamp_i == 20 && enclave_or_guest != 0) {
			for (stamp_i = 0; stamp_i < 20; stamp_i++) {
				pr_info("EmuSGX: Pushed = %lld\n", stamps_pushed[stamp_i]);
			}
			for (stamp_i = 0; stamp_i < 20; stamp_i++) {
				pr_info("EmuSGX: Acked = %lld\n", stamps_acked[stamp_i]);
			}
			stamp_i = 100;
		}

		// Free the node
		kfree(current_node->data);
		kfree(current_node);
	}
	return 0;
}

void emusgx_stop_sender_threads(void) {
	if (emusgx_enclave_sender_task != NULL) {
		pr_info("EmuSGX: Sending stop to enclave sender task\n");
		emusgx_enclave_sender_should_stop = 1;
		// Send SIGKILL
		// kthread_stop(emusgx_enclave_sender_task);
		// priv = 1 to force it
		send_sig(SIGKILL, emusgx_enclave_sender_task, 1);
		pr_info("EmuSGX: Enclave sender task stopped\n");
	}
	emusgx_enclave_sender_task = NULL;
	if (emusgx_guest_sender_task != NULL) {
		pr_info("EmuSGX: Sending stop to guest sender task\n");
		emusgx_guest_sender_should_stop = 1;
		// Send SIGKILL
		// kthread_stop(emusgx_guest_sender_task);
		// priv = 1 to force it
		send_sig(SIGKILL, emusgx_guest_sender_task, 1);
		pr_info("EmuSGX: Guest sender task stopped\n");
	}
	emusgx_guest_sender_task = NULL;
	pr_info("EmuSGX: Senders are stopped\n");
}

int emusgx_run_sender_threads(void) {
	// Stop the old sender threads anyway
	emusgx_stop_sender_threads();
	emusgx_enclave_sender_task = kthread_run(emusgx_sender, (void *)0, "emusgx_enclave_sender_thread");
	if (IS_ERR(emusgx_enclave_sender_task)) {
		pr_info("EmuSGX: Failed to create enclave sender task\n");
		return -1;
	}
	emusgx_guest_sender_task = kthread_run(emusgx_sender, (void *)1, "emusgx_guest_sender_thread");
	if (IS_ERR(emusgx_guest_sender_task)) {
		pr_info("EmuSGX: Failed to create guest sender task\n");
		return -1;
	}
	pr_info("EmuSGX: Sender tasks successfully created\n");
	return 0;
}

void emusgx_reset_hypervisor(void) {
	struct emusgx_simple_list_node *current_node;
	int i;

	emusgx_stop_sender_threads();
	emusgx_guest_vcpu = NULL;
	for (i = 0; i < EMUSGX_MAXIMUM_ENCLAVE_VMS; i++) {
		emusgx_enclave_vcpu[i] = NULL;
		emusgx_enclave_receive_page_gpa[i] = NULL;
	}
	emusgx_guest_receive_page_gpa = NULL;
	emusgx_regietered_enclave_vms = 0;
	emusgx_enclave_sender_semaphore = (struct semaphore)__SEMAPHORE_INITIALIZER(emusgx_enclave_sender_semaphore, 0);
	emusgx_guest_sender_semaphore = (struct semaphore)__SEMAPHORE_INITIALIZER(emusgx_guest_sender_semaphore, 0);

	emusgx_enclave_sender_ack_semaphore = (struct semaphore)__SEMAPHORE_INITIALIZER(emusgx_enclave_sender_ack_semaphore, 0);
	emusgx_guest_sender_ack_semaphore = (struct semaphore)__SEMAPHORE_INITIALIZER(emusgx_guest_sender_ack_semaphore, 0);

	spin_lock(&emusgx_enclave_send_queue_lock);
	current_node = emusgx_enclave_send_queue;
	while (current_node != NULL) {
		kfree(current_node->data);
		emusgx_enclave_send_queue = current_node;
		current_node = current_node->next;
		kfree(emusgx_enclave_send_queue);
	}
	emusgx_enclave_send_queue = NULL;
	emusgx_enclave_send_queue_tail = NULL;
	spin_unlock(&emusgx_enclave_send_queue_lock);

	spin_lock(&emusgx_guest_send_queue_lock);
	current_node = emusgx_guest_send_queue;
	while (current_node != NULL) {
		kfree(current_node->data);
		emusgx_guest_send_queue = current_node;
		current_node = current_node->next;
		kfree(emusgx_guest_send_queue);
	}
	emusgx_guest_send_queue = NULL;
	emusgx_guest_send_queue_tail = NULL;
	spin_unlock(&emusgx_guest_send_queue_lock);

	stamp_i = 0;

	pr_info("EmuSGX: Done reseting hypervisor\n");
}
