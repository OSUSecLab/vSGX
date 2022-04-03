#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>

#include "emusgx_sender.h"
#include "emusgx_debug.h"

static struct emusgx_response *emusgx_registered_response = NULL;

static struct semaphore emusgx_response_avail_semaphore = __SEMAPHORE_INITIALIZER(emusgx_response_avail_semaphore, 1);
static struct semaphore emusgx_response_semaphore = __SEMAPHORE_INITIALIZER(emusgx_response_semaphore, 0);

// Blockable
int emusgx_register_response(struct emusgx_response *response, uint64_t timeout) {
	// Currently time out is ignored
	if (down_killable(&emusgx_response_avail_semaphore)) {
		pr_info("EmuSGX: Some one tries to kill me\n");
		return 1;
	}

	emusgx_registered_response = response;
	return 0;
}

int emusgx_release_response(struct emusgx_response *response) {
	int ret_val = 0;

	if (emusgx_registered_response != response) {
		pr_info("EmuSGX: Not a registered response\n");
		return -1;
	}

	// IS a registered response
	emusgx_registered_response = NULL;
	if (response->write_back) {
		if (response->srcpage == NULL) {
			// Unexpected
			pr_info("EmuSGX: Lost page field in response\n");
			ret_val = -1;
		}
		else {
			kfree(response->srcpage);
		}
		if (response->pcmd == NULL) {
			pr_info("EmuSGX: Lost PCMD in response\n");
			ret_val = -1;
		}
		else {
			kfree(response->pcmd);
		}
	}
	if (response->with_va) {
		if (response->va_page == NULL) {
			pr_info("EmuSGX: Lost VA page in response\n");
			ret_val = -1;
		}
		else {
			kfree(response->va_page);
		}
		if (response->va_mac == NULL) {
			pr_info("EmuSGX: Lost VA MAC in response\n");
			ret_val = -1;
		}
		else
		{
			kfree(response->va_mac);
		}
	}
	// response is a local variable so we do not free it

	// Now the response slot is available
	up(&emusgx_response_avail_semaphore);
	return ret_val;
}

int emusgx_wait_for_response(uint64_t timeout) {
	// Currently timeout is ignored

	if (down_killable(&emusgx_response_semaphore)) {
		pr_info("EmuSGX: Some one tries to kill me\n");
		return -1;
	}

	emusgx_debug_print("EmuSGX: Response received\n");

	return 0;
}

void emusgx_handle_response(struct emusgx_raw_response *response) {
	// Note that emusgx_raw_response is compatiable with emusgx_raw_response_with_va
	// and emusgx_raw_response_with_va is compatible with emusgx_raw_response_with_page_and_va
	struct emusgx_raw_response_with_va *response_with_va = (struct emusgx_raw_response_with_va *)response;
	struct emusgx_raw_response_with_page_and_va *response_with_page = (struct emusgx_raw_response_with_page_and_va *)response;

	if (emusgx_registered_response == NULL) {
		// No response is registered
		pr_info("EmuSGX: No response registered\n");
		return;
	}

	if (emusgx_registered_response->instr != response->instr) {
		// Does not match
		pr_info("EmuSGX: Registered response does not match. Reged: %d, response: %d\n", emusgx_registered_response->instr, response->instr);
		return;
	}

	// Now handle the response
	emusgx_registered_response->response = response->response;
	emusgx_registered_response->linaddr = response->linaddr;
	if (response->write_back) {
		/*if (emusgx_registered_response->write_back) {
			// Response does not match...?

			// Or a failed EWB
		}*/
		emusgx_registered_response->write_back = 1;
		emusgx_registered_response->srcpage = kmalloc(4096, GFP_KERNEL);
		if (emusgx_registered_response->srcpage == NULL) {
			pr_info("EmuSGX: Failed to allocate write back page buffer\n");
			return;
		}
		emusgx_registered_response->pcmd = kmalloc(sizeof(struct sgx_pcmd), GFP_KERNEL);
		if (emusgx_registered_response->pcmd == NULL) {
			pr_info("EmuSGX: Failed to allocate write back pcmd buffer\n");
			return;
		}
		memcpy(emusgx_registered_response->srcpage, response_with_page->page, 4096);
		memcpy(emusgx_registered_response->pcmd, &(response_with_page->pcmd), sizeof(struct sgx_pcmd));
	}
	else {
		emusgx_registered_response->write_back = 0;
	}

	if (response->with_va) {
		/*if (emusgx_registered_response->write_back) {
			// Response does not match...?

			// Or a failed EWB
		}*/
		emusgx_registered_response->with_va = 1;
		emusgx_registered_response->va_page = kmalloc(4096, GFP_KERNEL);
		if (emusgx_registered_response->va_page == NULL) {
			pr_info("EmuSGX: Failed to allocate VA page buffer\n");
			return;
		}
		emusgx_registered_response->va_mac = kmalloc(2 * sizeof(uint64_t), GFP_KERNEL);
		if (emusgx_registered_response->va_mac == NULL) {
			pr_info("EmuSGX: Failed to allocate write back pcmd buffer\n");
			return;
		}
		memcpy(emusgx_registered_response->va_page, response_with_va->va_page, 4096);
		memcpy(emusgx_registered_response->va_mac, &(response_with_va->va_mac), 2 * sizeof(uint64_t));
	}
	else {
		emusgx_registered_response->with_va = 0;
	}

	emusgx_registered_response->ready = 1;

	// Wake up the waiting thread
	up(&emusgx_response_semaphore);

	return;
}
