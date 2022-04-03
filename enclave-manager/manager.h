#ifndef MANAGER_H
#define MANAGER_H

#include <sys/types.h>
#include <semaphore.h>

#define EMUSGX_MGROPS_REG_SELF		0
#define EMUSGX_MGROPS_SET_EPC		1
#define EMUSGX_MGROPS_GET_EPC		2
#define EMUSGX_MGROPS_SETUP_THREAD	3
#define EMUSGX_MGROPS_WAIT_FOR_ACTION	4
//#define EMUSGX_MGROPS_START_SENDER	5
//#define EMUSGX_MGROPS_STOP_SENDER	6
#define EMUSGX_MGROPS_CHECK_SENDER	7
#define EMUSGX_MGROPS_INIT_SYS		8

extern pid_t switchless_tid;
extern pid_t dispatcher_tid;
extern sem_t necessary_tasks_sem;

int manager_reg_self(uint64_t switchless_task_tid, uint64_t dispatcher_task_tid);
int manager_init_sys();
int manager_set_epc(void *start, uint64_t size);
uint64_t manager_wait_for_action(void);
void manager_setup_thread(uint64_t handle_buffer_addr);
int manager_check_sender(void);
void *switchless_worker(void *data);
void *dispatcher_worker(void *data);
void *entry_worker(void *data);

#endif
