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

#include "emusgx_internal.h"

uint8_t vsgx_worker_threads_should_stop = 0;

struct task_struct *vsgx_dispatcher_task = NULL;
struct task_struct *vsgx_switchless_task = NULL;

void vsgx_stop_worker_threads(void) {
	vsgx_worker_threads_should_stop = 1;
	if (vsgx_dispatcher_task != NULL) {
		pr_info("vSGX: Sending stop to dispatcher task\n");
		// Send SIGINT then stop
		send_sig(SIGKILL, vsgx_dispatcher_task, 1);
		kthread_stop(vsgx_dispatcher_task);
		// priv = 1 to force it
		// send_sig(SIGKILL, vsgx_dispatcher_task, 1);
		pr_info("vSGX: Dispatcher task stopped\n");
	}
	vsgx_dispatcher_task = NULL;
	if (vsgx_switchless_task != NULL) {
		pr_info("vSGX: Sending stop to switchless syncing task\n");
		// Send stop
		// No need to interrupt switchless
		kthread_stop(vsgx_switchless_task);
		// priv = 1 to force it
		// send_sig(SIGKILL, vsgx_switchless_task, 1);
		pr_info("vSGX: Switchless syncing task stopped\n");
	}
	vsgx_switchless_task = NULL;
	pr_info("vSGX: Worker threads are stopped\n");
}

int vsgx_run_worker_threads(void) {
	// Stop the old sender threads anyway
	// vsgx_stop_worker_threads();
	vsgx_dispatcher_task = kthread_run(emusgx_dispatcher, (void *)0, "vsgx_dispatcher_task");
	if (IS_ERR(vsgx_dispatcher_task)) {
		pr_info("vSGX: Failed to create dispatcher task\n");
		return -1;
	}
	vsgx_switchless_task = kthread_run(emusgx_switchless_sync_worker, (void *)1, "vsgx_switchless_task");
	if (IS_ERR(vsgx_switchless_task)) {
		pr_info("vSGX: Failed to create switchless syncing task\n");
		return -1;
	}
	pr_info("vSGX: Worker threads successfully created\n");
	return 0;
}
