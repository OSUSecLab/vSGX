#ifndef EMUSGX_KVM_H
#define EMUSGX_KVM_H

#define EMUSGX_MAXIMUM_ENCLAVE_VMS	10

extern struct kvm_vcpu *emusgx_guest_vcpu;
extern struct kvm_vcpu *emusgx_enclave_vcpu[EMUSGX_MAXIMUM_ENCLAVE_VMS];
extern struct kvm *emusgx_enclave_kvm_identifier[EMUSGX_MAXIMUM_ENCLAVE_VMS];

extern void *emusgx_enclave_receive_page_gpa[EMUSGX_MAXIMUM_ENCLAVE_VMS];
extern void *emusgx_guest_receive_page_gpa;

extern int emusgx_regietered_enclave_vms;

extern struct semaphore emusgx_enclave_sender_ack_semaphore;
extern struct semaphore emusgx_guest_sender_ack_semaphore;

extern spinlock_t emusgx_register_enclave_vm_lock;

struct emusgx_simple_list_node {
	void *data;
	int target_vm_id;
	struct emusgx_simple_list_node *next;
};

int emusgx_is_sender_ready(void);

void emusgx_queue_package(void *data, int target_vm_id, uint8_t enclave_or_guest);
int emusgx_run_sender_threads(void);
void emusgx_stop_sender_threads(void);

int emusgx_retrive_page(struct kvm_vcpu *vcpu, uint64_t gpa, uint8_t enclave_or_guest);

void emusgx_reset_hypervisor(void);

#endif
