#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <semaphore.h>

#include "manager.h"

static int esgxmgr(uint64_t action, uint64_t rbx_val, uint64_t rcx_val, uint64_t *handle_buffer_addr) {
	int result;
	uint64_t handle_buffer_addr_ret_val;
	asm volatile (
		".byte 0x0F\n"
		".byte 0x01\n"
		".byte 0xEB\n" // esgxmgr
		: "=a"(result), "=b"(handle_buffer_addr_ret_val)
		: "a"(action), "b"(rbx_val), "c"(rcx_val)
		: 
	);
	if (handle_buffer_addr != NULL) {
		*handle_buffer_addr = handle_buffer_addr_ret_val;
	}
	return result;
}

int manager_reg_self(uint64_t switchless_task_tid, uint64_t dispatcher_task_tid) {
	return esgxmgr(EMUSGX_MGROPS_REG_SELF, switchless_task_tid, dispatcher_task_tid, NULL);
}

int manager_init_sys() {
	return esgxmgr(EMUSGX_MGROPS_INIT_SYS, 0, 0, NULL);
}

int manager_set_epc(void *start, uint64_t size) {
	return esgxmgr(EMUSGX_MGROPS_SET_EPC, (uint64_t)start, size, NULL);
}

uint64_t manager_wait_for_action(void) {
	uint64_t handle_buffer_addr;
	int ret_val;
	while (esgxmgr(EMUSGX_MGROPS_WAIT_FOR_ACTION, 0, 0, &handle_buffer_addr)); // The action could return due to signals
	return handle_buffer_addr;
}

void manager_setup_thread(uint64_t handle_buffer_addr) {
	// It will enter the enclave and will not return back to
	// this function until EEXIT
	// RBX: handle buffer
	//printf("EmuSGX: Now setting up thread with handle_buffer_addr = 0x%016lX\n", handle_buffer_addr);
	esgxmgr(EMUSGX_MGROPS_SETUP_THREAD, handle_buffer_addr, 0, NULL);

	// The return value of esgxmgr must be EMUSGX_MGROPS_SETUP_THREAD
	// The esgxmgr will return after EEXIT
	// So here the enclave has successfully exited
	// This thread can be killed
}

/*
int manager_start_sender(void) {
	return esgxmgr(EMUSGX_MGROPS_START_SENDER, 0, 0, NULL);
}

int manager_stop_sender(void) {
	return esgxmgr(EMUSGX_MGROPS_STOP_SENDER, 0, 0, NULL);
}*/

int manager_check_sender(void) {
	return esgxmgr(EMUSGX_MGROPS_CHECK_SENDER, 0, 0, NULL);
}

void *switchless_worker(void *data) {
	uint64_t result;
	switchless_tid = syscall(SYS_gettid);
	sem_post(&necessary_tasks_sem);
	printf("vSGX: Switchless worker is on\n");
	while (1) {
		// Call the switchless esgxsl
		asm volatile (
			".byte 0x0F\n"
			".byte 0x01\n"
			".byte 0xEC\n" // esgxsl
			: "=a"(result)
			:
			: 
		);
		// Only SIGKILL will return to here
		// If that ever happens just let it die
	}
	return (void *)0;
}

void *dispatcher_worker(void *data) {
	uint64_t result;
	dispatcher_tid = syscall(SYS_gettid);
	sem_post(&necessary_tasks_sem);
	printf("vSGX: Dispatcher worker is on\n");
	while (1) {
		// Call the dispatcher esgxes
		asm volatile (
			".byte 0x0F\n"
			".byte 0x01\n"
			".byte 0xED\n" // esgxes
			: "=a"(result)
			:
			: 
		);
		// Only SIGKILL will return to here
		// If that ever happens just let it die
	}
	return (void *)0;
}

void *entry_worker(void *data) {
	// Data is the handle buffer
	manager_setup_thread((uint64_t)data);
	return (void *)0;
}
