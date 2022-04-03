#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>

#include <asm/cacheflush.h>
#include <asm/io.h>

#include "emusgx_sender.h"
#include "emusgx_cpuid.h"
#include "emusgx_mm.h"
#include "emusgx_debug.h"

irqreturn_t emusgx_irq_handler(int irq, void *dev_id) {
	unsigned long flags;
	void *page;
	struct emusgx_request_queue_node *new_node;
	int cpuid_success;
	uint64_t physical_page_addr;
	uint32_t physical_page_addr_upper;
	uint32_t physical_page_addr_lower;

	physical_page_addr = virt_to_phys(emusgx_receive_page);
	physical_page_addr_lower = (uint32_t)(physical_page_addr);
	physical_page_addr_upper = (uint32_t)((uint64_t)(physical_page_addr) >> 32);
 
	emusgx_debug_print("EmuSGX: IRQ received. Retriving data...\n");

	// First retrive data to the receive page
	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_GUEST_RETRIVE_PAGE), "b"(physical_page_addr_upper), "c"(physical_page_addr_lower)
		: "%rdx"
	);
	if (cpuid_success) {
		pr_info("EmuSGX: CPUID failed for retriving page\n");
		return IRQ_HANDLED;
	}

	//wbinvd_on_all_cpus();	
	clflush_cache_range(emusgx_receive_page, 4096);
	//mb();
	
	emusgx_debug_print("EmuSGX: Data retrived.\n");
	// New a page
	// CANNOT SLEEP!
	page = (void *)__get_free_page(GFP_ATOMIC);
	if (page == NULL) {
		pr_info("EmuSGX: Failed to create page\n");
		return IRQ_HANDLED;
	}

	// Copy the data to the page
	memcpy(page, emusgx_receive_page, 4096);

	// Create new node
	// CANNOT SLEEP!
	new_node = (void *)__get_free_page(GFP_ATOMIC);
	if (new_node == NULL) {
		pr_info("EmuSGX: Failed to create node\n");
		return IRQ_HANDLED;
	}

	new_node->next = NULL;
	new_node->page = page;

	// This is a MUST NOT SLEEP context
	spin_lock_irqsave(&emusgx_dispatcher_queue_lock, flags);

	// Add to the queue
	if (emusgx_request_queue_tail == NULL) {
		emusgx_request_queue = emusgx_request_queue_tail = new_node;
	}
	else {
		emusgx_request_queue_tail->next = new_node;
		emusgx_request_queue_tail = new_node;
	}

	//pr_info("EmuSGX: Queued the request\n");
	
	up(&(emusgx_dispatcher_sem));


	//pr_info("EmuSGX: Told the dispatcher\n");

	spin_unlock_irqrestore(&emusgx_dispatcher_queue_lock, flags);

	// Send acknowledge
	// We use KVM_CPUID_EMUSGX_ACK_PAGE to tell the hypervisor we are done
	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_GUEST_ACK_PAGE)
		: "%rcx", "%rdx"
	);

	return IRQ_HANDLED;
}
