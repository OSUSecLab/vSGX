#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <semaphore.h>

#include "manager.h"

const uint64_t epc_size = 0x15000000;

pid_t switchless_tid = 0;
pid_t dispatcher_tid = 0;
sem_t necessary_tasks_sem;

pthread_t switchless_thread;
pthread_t dispatcher_thread;

int main() {
	void *epc_base = (void *)0x80000000;
	uint64_t handle_buffer_addr;
	pthread_t tmp_thread;

	// With virtual address support this is not needed anymore
	// First let's setup EPC range
	// We will take 0x80000000 to 0xA0000000 as our EPC
	// The size is 16MB
	//epc_base = mmap((void *)0x80000000, epc_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	//if ((uint64_t)epc_base != 0x80000000) {
	//	printf("EmuSGX Manager: FATAL: Cannot allocate EPC\n");
	//	return -1;
	//}

	if (manager_init_sys()) {
		printf("vSGX Manager: FATAL: Failed to initialize the system\n");
		return -1;
	}

	// Set EPC page
	if (manager_set_epc(epc_base, epc_size)) {
		printf("EmuSGX Manager: FATAL: Cannot set EPC\n");
		return -1;
	}
	if (manager_check_sender()) {
		printf("EmuSGX Manager: FATAL: No senders are setup in hypervisor\n");
		return -1;
	}

	// Register the manager
	if (manager_reg_self(0, 0)) {
		printf("EmuSGX Manager: FATAL: Failed to register manager\n");
		return -1;
	}

	// Run the two threads
	if (sem_init(&necessary_tasks_sem, 0, 0) != 0) {
		printf("EmuSGX Manager: FATAL: Failed to initialize semaphore for the two necessary threads\n");
		return -1;
	}
	if (pthread_create(&switchless_thread, NULL, switchless_worker, NULL)) {
		printf("EmuSGX Manager: FATAL: Failed to create switchless worker\n");
		return -1;
	}
	if (pthread_create(&dispatcher_thread, NULL, dispatcher_worker, NULL)) {
		printf("EmuSGX Manager: FATAL: Failed to create dispatcher worker\n");
		pthread_kill(switchless_thread, SIGKILL);
		return -1;
	}
	// Wait for the two threads to get their PID
	while (sem_wait(&necessary_tasks_sem)); // One
	while (sem_wait(&necessary_tasks_sem)); // Two
	
	//manager_reg_self(0, 0);

	// Now we just wait for an action!
	while (1) {
		// Shall not return
		//printf("EmuSGX Manager: Waiting for action\n");
		handle_buffer_addr = manager_wait_for_action();
		//printf("EmuSGX Manager: Received action. Now creating thread\n");
		//printf("EmuSGX Manager: Kernel handle_buffer_addr = 0x%016lX\n", handle_buffer_addr);

		// Now create a new thread for EENTER
		if (pthread_create(&tmp_thread, NULL, entry_worker, (void *)handle_buffer_addr)) {
			printf("EmuSGX: FATAL: Failed to start a new enclave thread\n");
			continue;
		}

		pthread_detach(tmp_thread);
		// The thread will die on its own
		// We do not keep a track of the thread
	}

	return 0;
}
