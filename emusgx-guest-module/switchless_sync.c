#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include <linux/sched/signal.h>

#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "emusgx.h"
#include "emusgx_internal.h"
#include "emusgx_sender.h"

#define EMUSGX_SWITCHLESS_SLOT_FREE	0
#define EMUSGX_SWITCHLESS_SLOT_INUSE	1
#define EMUSGX_SWITCHLESS_SLOT_SYNCING	2

struct emusgx_switchless_page_slot {
	uint8_t status;
	struct mutex lock;
	void *addr;
	uint8_t *original_content;
};

//extern void (*flush_tlb_mm_range_ptr)(struct mm_struct *mm, unsigned long start, unsigned long end, unsigned long stride_shift, bool freed_tables);

static uint64_t emusgx_switchless_sync_index[EMUSGX_MAXIMUM_ENCLAVES] = { 0 };
static DEFINE_MUTEX(emusgx_switchless_index_lock);

struct mm_struct *vsgx_enclave_mm[EMUSGX_MAXIMUM_ENCLAVES] = { [0 ... EMUSGX_MAXIMUM_ENCLAVES - 1] = NULL };
struct emusgx_switchless_page_slot emusgx_switchless_pages[EMUSGX_MAXIMUM_ENCLAVES][EMUSGX_SWITCHLESS_SLOT_COUNT] = { [0 ... EMUSGX_MAXIMUM_ENCLAVES - 1] = { [0 ... EMUSGX_SWITCHLESS_SLOT_COUNT - 1] = { .status = EMUSGX_SWITCHLESS_SLOT_FREE, .addr = NULL, .original_content = NULL } } };

void vsgx_switchless_init_locks() {
	int i, j;
	for (i = 0; i < EMUSGX_MAXIMUM_ENCLAVES; i++) {
		for (j = 0; j < EMUSGX_SWITCHLESS_SLOT_COUNT; j++) {
			emusgx_switchless_pages[i][j].lock = (struct mutex)__MUTEX_INITIALIZER(emusgx_switchless_pages[i][j].lock);
		}
	}
}

void vsgx_switchless_update_enclave_mm(struct mm_struct *mm, uint64_t manager_nr) {
	if (manager_nr < EMUSGX_MAXIMUM_ENCLAVES) {
		if (vsgx_enclave_mm[manager_nr] != NULL) {
			pr_info("vSGX: Warning: You are overwriting an enclave mm registry\n");
		}
		vsgx_enclave_mm[manager_nr] = mm;
		pr_info("vSGX: %lld's mm is set to 0x%016llX\n", manager_nr, (uint64_t)mm);
	}
	else {
		pr_info("vSGX: Warning: manager_nr overflow. manager_nr = %lld\n", manager_nr);
	}
}

void emusgx_switchless_write_page(struct emusgx_page_package *package, uint64_t manager_nr) {
	// Make sure the page still exists
	int i, group, bit;
	// uint64_t manager_nr = package->id;
	for (i = 0; i < EMUSGX_SWITCHLESS_SLOT_COUNT; i++) {
		// First grab the lock. Can sleep
		if (mutex_lock_killable(&emusgx_switchless_pages[manager_nr][i].lock)) {
			pr_info("vSGX: Switchless write page killed\n");
			return;
		}

		if (emusgx_switchless_pages[manager_nr][i].status != EMUSGX_SWITCHLESS_SLOT_INUSE) {
			mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
			// Go ahead
			continue;
		}

		if ((uint64_t)(emusgx_switchless_pages[manager_nr][i].addr) != package->addr) {
			mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
			// Go ahead
			continue;
		}
		else {
			goto copy_data;
			// Break with lock held so no one can free that page anyway
			// i is the slot
		}
	}

	// Not found
	// Due to swapped out pages. Still needs to be synced
	// but no "original_content" field needs to be written
	__uaccess_begin();
	clflush_cache_range((void *)package->addr, 4096);
	for (group = 0; group < 512; group++) {
		if (package->mask[group] == 0) // if a group is unmodified, then jump over it
			continue;
		for (bit = 0; bit < 8; bit++) {
			if (((package->mask[group]) >> bit) & 1) {
				((uint8_t *)(package->addr))[group * 8 + bit] = package->page[group * 8 + bit];
			}
		}
	}
	clflush_cache_range((void *)package->addr, 4096);
	__uaccess_end();
	return;

copy_data:
	// Check dirty?

	// Copy the data
	// We just copy the page to the corresponding address on our own
	__uaccess_begin();
	clflush_cache_range((void *)package->addr, 4096);
	for (group = 0; group < 512; group++) {
		if (package->mask[group] == 0) // if a group is unmodified, then jump over it
			continue;
		for (bit = 0; bit < 8; bit++) {
			if (((package->mask[group]) >> bit) & 1) {
				((uint8_t *)(package->addr))[group * 8 + bit] = package->page[group * 8 + bit];
				emusgx_switchless_pages[manager_nr][i].original_content[group * 8 + bit] = package->page[group * 8 + bit];
			}
		}
	}
	clflush_cache_range((void *)package->addr, 4096);
	clflush_cache_range(emusgx_switchless_pages[manager_nr][i].original_content, 4096);
	__uaccess_end();

	// Release the lock
	mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);

	// We do not clear the dirty bit since there's no way to tell if ant
	// threads changed our data during the writing process
	// We leave the task of checking if the page is real dirty to
	// emusgx_sync_on_dirty
}

// Must be called with the slot locked!
int emusgx_sync_on_dirty(int slot, int manager_nr, char force_sync) {
	uint64_t addr = (uint64_t)emusgx_switchless_pages[manager_nr][slot].addr;
	struct emusgx_page_package *package = NULL;
	int group, bit, need_to_send;

	// Get PTE
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct mm_struct *mm = current->mm;
	
//	if (force_sync)
//		goto out;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
	//	pr_info("EmuSGX: Page walk failed on PGD\n");
		goto out;
	}

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
	//	pr_info("EmuSGX: Page walk failed on  P4D");
    		goto out;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud)) {
	//	pr_info("EmuSGX: Page walk failed on  PUD");
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
	//	pr_info("EmuSGX: Page walk failed on PMD - none");
		goto out;
	}
	if (pmd_bad(*pmd)) {
	//	pr_info("EmuSGX: Page walk failed on PMD - bad");
		goto out;
	}

	pte = pte_offset_map(pmd, addr);
	if (!pte) {
	//	pr_info("EmuSGX: Page walk failed on PTE");
		goto out;
	}

	if (!pte_present(*pte)) {
	//	pr_info("EmuSGX: PTE not presenting\n");
		goto out;
	}
	
	//__flush_tlb_one_user(addr);
	// Check if the PTE is dirty
	if (pte_dirty(*pte)) {
		// Mark the page clear
		set_pte(pte, pte_mkclean(*pte));
		//__flush_tlb_all();
		__flush_tlb_one_user(addr);
		//(*flush_tlb_mm_range_ptr)(current->mm, addr, addr + 4096, PAGE_SHIFT, false);
out:
		package = kmalloc(sizeof(struct emusgx_page_package), GFP_KERNEL);
		if (package == NULL) {
			pr_info("EmuSGX: Failed to allocate package when swapping out the sync slot\n");
			return -1;
		}

		__uaccess_begin();

		// Write the mask
		clflush_cache_range(emusgx_switchless_pages[manager_nr][slot].addr, 4096);
		need_to_send = 0;
		for (group = 0; group < 512; group++) {
			package->mask[group] = 0;
			for (bit = 0; bit < 8; bit++) {
				package->page[group * 8 + bit] = ((uint8_t *)(emusgx_switchless_pages[manager_nr][slot].addr))[group * 8 + bit];
				if (emusgx_switchless_pages[manager_nr][slot].original_content[group * 8 + bit] != package->page[group * 8 + bit]) {
					// Set bit 1
					package->mask[group] |= ((uint64_t)1 << bit);
					emusgx_switchless_pages[manager_nr][slot].original_content[group * 8 + bit] = package->page[group * 8 + bit];
					need_to_send += 1;
				}
			}
		}
		clflush_cache_range(emusgx_switchless_pages[manager_nr][slot].original_content, 4096);
		//if (need_to_send)
		//	pr_info("vSGX: Need to sync %d 0x%016llX\n", need_to_send, (uint64_t)emusgx_switchless_pages[manager_nr][slot].addr);
		__uaccess_end();

		if (need_to_send) {
			package->instr = EMUSGX_S_SWITCHLESS;
			package->addr = (uint64_t)emusgx_switchless_pages[manager_nr][slot].addr;
			package->id = 0; // ID represents manager_nr
			if (emusgx_send_data(package, sizeof(struct emusgx_page_package), manager_nr)) {
				pr_info("EmuSGX: Failed to send package for swapped out page\n");
				kfree(package);
				return -1;
			}
		}

		kfree(package);

		return 0;
	}

	return 0;
}

void emusgx_clear_dirty(void *address) {
	uint64_t addr = (uint64_t)address;

	// Get PTE
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct mm_struct *mm = current->mm;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		//pr_info("EmuSGX: Page walk failed on PGD\n");
		goto out;
	}

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		//pr_info("EmuSGX: Page walk failed on  P4D");
    		goto out;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud)) {
		//pr_info("EmuSGX: Page walk failed on  PUD");
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		//pr_info("EmuSGX: Page walk failed on PMD - none");
		goto out;
	}
	if (pmd_bad(*pmd)) {
		//pr_info("EmuSGX: Page walk failed on PMD - bad");
		goto out;
	}

	pte = pte_offset_map(pmd, addr);
	if (!pte) {
		//pr_info("EmuSGX: Page walk failed on PTE");
		goto out;
	}

	if (!pte_present(*pte)) {
		//pr_info("EmuSGX: PTE not presenting\n");
		goto out;
	}

	set_pte(pte, pte_mkclean(*pte));
out:
	;
}

int emusgx_switchless_new_slot(void *addr, void *original_content, uint64_t manager_nr) {
	// The addr should be a valid address

	// When new a slot, several things are done
	// If we are taking a free slot then just copy data into it will be good enough
	// If we are taking an occupied slot, then we need to
	// 1. Check if the slot is dirty, if so, sync the data 
	//    to the guest VM
	// 2. Update the slot
	// We use a FIFO policy and the index will keep going up to max slot
	// then reset
	uint64_t index;

	if (manager_nr >= EMUSGX_MAXIMUM_ENCLAVES) {
		pr_info("vSGX: Switchless new slot for invalid manager %lld\n", manager_nr);
		return -1;
	}

	if (mutex_lock_killable(&emusgx_switchless_index_lock)) {
		pr_info("vSGX: Switchless new slot killed when getting index\n");
		return -1;
	}

	index = emusgx_switchless_sync_index[manager_nr];
	emusgx_switchless_sync_index[manager_nr] += 1;
	if (emusgx_switchless_sync_index[manager_nr] >= EMUSGX_SWITCHLESS_SLOT_COUNT) {
		emusgx_switchless_sync_index[manager_nr] = 0;
	}

	mutex_unlock(&emusgx_switchless_index_lock);

	// First, get the slot
	// Can-sleep
	if (mutex_lock_killable(&emusgx_switchless_pages[manager_nr][index].lock)) {
		pr_info("vSGX: Switchless new slot killed\n");
		return -1;
	}

	if (emusgx_switchless_pages[manager_nr][index].status == EMUSGX_SWITCHLESS_SLOT_FREE) {
		emusgx_switchless_pages[manager_nr][index].original_content = NULL;
	}
	//else {
		// Don't have to be synced since it is going to be swapped anyway
		// Sync for the last time
		// emusgx_sync_on_dirty(index, manager_nr);
		// Should not unmap like in the enclave
	//}

	// Update the slot
	emusgx_switchless_pages[manager_nr][index].status = EMUSGX_SWITCHLESS_SLOT_INUSE;
	emusgx_switchless_pages[manager_nr][index].addr = addr;
	// Lazy allocate, reuse if not NULL
	if (emusgx_switchless_pages[manager_nr][index].original_content == NULL) {
		emusgx_switchless_pages[manager_nr][index].original_content = kmalloc(4096, GFP_KERNEL);
	}
	if (emusgx_switchless_pages[manager_nr][index].original_content == NULL) {
		pr_info("EmuSGX: I cannot allocate data for the original_content\n");
		mutex_unlock(&emusgx_switchless_pages[manager_nr][index].lock);
		return -1;
	}
	// Update the original_content field
	memcpy(emusgx_switchless_pages[manager_nr][index].original_content, original_content, 4096);
	clflush_cache_range(emusgx_switchless_pages[manager_nr][index].original_content, 4096);

	mutex_unlock(&emusgx_switchless_pages[manager_nr][index].lock);

	// The slot is ready

	return 0;
}

int emusgx_switchless_get_slot(void *addr, uint64_t manager_nr) {
	// Make sure the page still exists
	int i;
	for (i = 0; i < EMUSGX_SWITCHLESS_SLOT_COUNT; i++) {
		if (mutex_lock_killable(&emusgx_switchless_pages[manager_nr][i].lock)) {
			pr_info("vSGX: Switchless get slot killed\n");
			return -1;
		}

		if (emusgx_switchless_pages[manager_nr][i].status == EMUSGX_SWITCHLESS_SLOT_INUSE) {
			if (emusgx_switchless_pages[manager_nr][i].addr == addr) {
				mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
				return i;
			}
		}

		mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
			
	}
	return -1;
}

atomic_t vsgx_force_sync_in_progress[EMUSGX_MAXIMUM_ENCLAVES] = { [0 ... EMUSGX_MAXIMUM_ENCLAVES - 1] = (atomic_t)ATOMIC_INIT(0) };

void emusgx_sync_manager_pages(uint64_t manager_nr, char force_sync) {
	int i, dummy;
	if (force_sync) {
		atomic_inc(&(vsgx_force_sync_in_progress[manager_nr]));
	}
	for (i = 0; i < EMUSGX_SWITCHLESS_SLOT_COUNT; i++) {
		if (atomic_read(&(vsgx_force_sync_in_progress[manager_nr])) && !force_sync) {
			// Someone is forcing a sync
			// So as a lazy syncer we will abort
			break;
		}
		if (mutex_lock_killable(&emusgx_switchless_pages[manager_nr][i].lock)) {
			return;
		}
		if (emusgx_switchless_pages[manager_nr][i].status == EMUSGX_SWITCHLESS_SLOT_INUSE) {
			// A hack to make sure that this page is in the memory
			if (!get_user(dummy, (int *)emusgx_switchless_pages[manager_nr][i].addr)) {
				__uaccess_begin();
				clflush_cache_range(emusgx_switchless_pages[manager_nr][i].addr, 4096);
				__uaccess_end();
				emusgx_sync_on_dirty(i, manager_nr, force_sync);
			}
		}
		else {
			mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
			break; // The rest of this manager is not used yet
		}
		mutex_unlock(&emusgx_switchless_pages[manager_nr][i].lock);
		// We don't care successful or not since we are doing lazy syncing
	}
	if (force_sync) {
		 atomic_dec(&(vsgx_force_sync_in_progress[manager_nr]));
	}
}

extern uint8_t vsgx_worker_threads_should_stop;

int emusgx_switchless_sync_worker(void *dummy) {
	uint64_t manager_nr;
	
	while(!vsgx_worker_threads_should_stop && !fatal_signal_pending(current)) {
		// every 100 ms we sync all slots on demand
		for (manager_nr = 0; manager_nr < EMUSGX_MAXIMUM_ENCLAVES; manager_nr++) {
			if (vsgx_enclave_mm[manager_nr] == NULL) {
				// Unused
				continue;
			}
			if (current->flags & PF_KTHREAD) {
				// Kernel thread. Swap to the manager's context
				kthread_use_mm(vsgx_enclave_mm[manager_nr]);
			}
			emusgx_sync_manager_pages(manager_nr, 1);
			if (current->flags & PF_KTHREAD) {
				kthread_unuse_mm(vsgx_enclave_mm[manager_nr]);
			}
		}

		// now wait for 100 ms
		msleep(100);
	}
	pr_info("vSGX: Switchless syncing worker exiting...\n");
	return 0;
}
