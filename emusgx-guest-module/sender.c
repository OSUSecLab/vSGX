#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/pgtable.h>

#include <asm/cacheflush.h>
#include <asm/atomic.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#include "emusgx.h"
#include "emusgx_internal.h"
#include "emusgx_sender.h"
#include "emusgx_cpuid.h"
#include "emusgx_debug.h"

void *emusgx_receive_page = NULL;

static uint64_t emusgx_session[EMUSGX_MAXIMUM_ENCLAVES] = { [0 ... EMUSGX_MAXIMUM_ENCLAVES - 1] = 0 };
static DEFINE_MUTEX(emusgx_session_number_lock);

// Only first 16 bytes are used
char *emusgx_static_aad = "EmuSGX AAD AAD AAD AAD";

static uint8_t emusgx_unset_c_bit(unsigned long addr, uint8_t is_unset)
{
	int level;
	pte_t *ptep;
	unsigned long pfn;
	pte_t new_pte;
	pgprot_t prot;
	pgprot_t old_prot;
	uint8_t ret_val = 0;

	ptep = lookup_address(addr, &level);
	if (level != PG_LEVEL_4K) {
		pr_info("vSGX: Page in high mem\n");
		goto out;
	}

	pfn = pte_pfn(*ptep);
	prot = pte_pgprot(*ptep);
	old_prot = prot;

	if (is_unset)
		pgprot_val(prot) &= ~_PAGE_ENC;
	else
		pgprot_val(prot) |= _PAGE_ENC;

	if (pgprot_val(prot) == pgprot_val(old_prot)) {
		pr_info("vSGX: PROT UNCHANGED\n");
		//ret_val = 1;
	}

	__flush_tlb_all();
	mb();

	new_pte = pfn_pte(pfn, prot);
	set_pte_atomic(ptep, new_pte);
	/*
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	// Do note that current->mm can be NULL for a kernel thread
	// The C-bit is only unset for a kernel page so we use the init_mm
	// struct mm_struct *mm = current->mm;

	pgd = pgd_offset(init_mm_p, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		pr_info("EmuSGX: Page walk failed on PGD\n");
		goto out;
	}

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		pr_info("EmuSGX: Page walk failed on P4D");
    		goto out;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud)) {
		pr_info("EmuSGX: Page walk failed on  PUD");
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		pr_info("EmuSGX: Page walk failed on PMD - none");
		goto out;
	}
	if (pmd_bad(*pmd)) {
		pr_info("EmuSGX: Page walk failed on PMD - bad");
		goto out;
	}


	pte = pte_offset_map(pmd, addr);
	if (!pte) {
		pr_info("EmuSGX: Page walk failed on PTE");
		goto out;
	}
	
	// Unset the 47th "C-bit"
	if (is_unset) {
		//pr_info("EmuSGX: PTE mask is 0x%016llX\n", (~((uint64_t)(1) << 47)));
		//pr_info("EmuSGX: PTE before is 0x%016lX\n", pte->pte);
		pte->pte &= (~((uint64_t)(1) << 47));
		pte->pte &= (~((uint64_t)(1) << 63));
		// pr_info("EmuSGX: PTE is 0x%016lX\n", pte->pte);
	}
	else {
		//pr_info("EmuSGX: PTE mask is 0x%016llX\n", ((uint64_t)(1) << 47));
		//pr_info("EmuSGX: PTE before is 0x%016lX\n", pte->pte);
		pte->pte |= ((uint64_t)(1) << 47);
		pte->pte |= ((uint64_t)(1) << 63);
		//pr_info("EmuSGX: PTE is 0x%016lX\n", pte->pte);
	}
	__flush_tlb_all();
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)(pte)));
	mb();
	rmb();
	wmb();
	barrier();*/
	return ret_val;

 out:
	pr_info("EmuSGX: Page addr is 0x%016lX\n", addr);
	return -1;
}

void *emusgx_get_and_share_page(void) {
	void *ret_addr = (void *)__get_free_page(GFP_DMA);
	// uint64_t phys_addr = virt_to_phys(ret_addr);
	// struct page *ret_valid = pfn_to_page(phys_addr >> PAGE_SHIFT);
	// char *string_addr = ret_addr;
	if (ret_addr == NULL) {
		pr_info("EmuSGX: Page in high mem\n");
		return NULL;
	}
	// pr_info("EmuSGX: real: 0x%016llX, get: 0x%016llX\n", (uint64_t)ret_addr_page, (uint64_t)ret_addr);
	//memcpy(string_addr, "hello", 6);
	//pr_info("EmuSGX: %s\n", string_addr);
	//pr_info("EmuSGX: shared page at 0x%016llX\n", (uint64_t)ret_addr);
	__flush_tlb_all();
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)(ret_addr)));
	mb();
	rmb();
	wmb();
	barrier();
	// Set the page shared
	if (emusgx_unset_c_bit((uint64_t)ret_addr, 1)) {
		pr_info("EmuSGX: Failed to finish page walk for the sharing page\n");
		free_page((uint64_t)ret_addr);
		return NULL;
	}
	__flush_tlb_all();
	mb();
	//rmb();
	//wmb();
	barrier();
	//string_addr[6] = 0;
	//pr_info("EmuSGX: %s\n", string_addr);
	//pr_info("EmuSGX: Encrypted hello signature = 0x%08X\n", ((uint32_t *)string_addr)[0]);
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)(ret_addr)));
	clflush_cache_range(ret_addr, 4096);
	mb();
	rmb();
	wmb();
	barrier();
	return ret_addr;
}

void emusgx_init_shared_page(void) {
	uint32_t cpuid_success;
	uint64_t physical_page_addr;

	pr_info("EmuSGX: Initializating shared page\n");

	emusgx_receive_page = emusgx_get_and_share_page();

	if (emusgx_receive_page == NULL) {
		pr_info("EmuSGX: Failed to init receive page\n");
		return;
	}

	physical_page_addr = virt_to_phys(emusgx_receive_page);

	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_GUEST_SHARE_PAGE), "c"(physical_page_addr)
		: "%rdx"
	);
	if (!cpuid_success) {
		pr_info("EmuSGX: CPUID failed\n");
	}

	pr_info("EmuSGX: Share page initialization is done\n");
}

void emusgx_free_shared_page(void *page_addr) {
	//pr_info("EmuSGX: Freeing page... Setting C-bit\n");
	if (emusgx_unset_c_bit((uint64_t)page_addr, 0)) {
		pr_info("EmuSGX: Failed to unset shared page\n");
	}
	//pr_info("EmuSGX: C-bit set back\n");
	mb();
	rmb();
	wmb();
	barrier();
	__flush_tlb_all();
	//pr_info("EmuSGX: TLB flushed. Now freeing\n");
	free_page((uint64_t)page_addr);
	//pr_info("EmuSGX: Page freed\n");
}

void emusgx_unshare_page(void) {
	uint32_t cpuid_success;

	emusgx_free_shared_page(emusgx_receive_page);

	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(KVM_CPUID_EMUSGX_GUEST_UNSHARE_PAGE)
		: "%rcx", "%rdx"
	);

	if (!cpuid_success) {
		pr_info("EmuSGX: CPUID failed\n");
	}
}

/*
static void emusgx_full_flush_page_cache(void *addr) {
	int i;

	for (i = 0; i < 4096; i++) {
		asm volatile("clflush %0" : "+m" (*(volatile char __force *)(&(((char *)addr)[i]))));
	}

	mb();
	rmb();
	wmb();
	barrier();
} */

static int sender_counter = 0;
static uint64_t time_1[20];
static uint64_t time_2_start[20];

static int emusgx_send_single_page(void *addr, uint64_t size, int target_enclave) {
	void *shared_page = NULL;
	uint64_t physical_page_addr;
	uint64_t rax_val;
	uint32_t cpuid_success = 0;
	int i;
	
	uint64_t time_0 = ktime_get_real_ns();

	if (size > 4096) {
		pr_info("EmuSGX: Data too large in pack_to_page\n");
		return -EINVAL;
	}

	if (shared_page == NULL) 
		shared_page = emusgx_get_and_share_page();

	for (i = 0; i < 10 && shared_page == NULL; i++) {
		shared_page = emusgx_get_and_share_page();
	}

	if (shared_page == NULL) {
		pr_info("EmuSGX: Failed to create shared page\n");
		return -EINVAL;
	}

	clflush_cache_range(shared_page, 4096);

	//pr_info("vSGX: Shared page @ 0x%016llX\n", (uint64_t)shared_page);

	memcpy(shared_page, addr, size);

	physical_page_addr = virt_to_phys(shared_page);

	// Make a full cache flush
	// emusgx_full_flush_page_cache(shared_page);
	clflush_cache_range(shared_page, 4096);
	// wbinvd_on_all_cpus();
		
	// We use KVM_CPUID_EMUSGX_SEND_PAGE to send data to hypervisor
	// The signature is the last 4 bytes of the page

	rax_val = ((uint64_t)((uint32_t)target_enclave)) << 32;
	rax_val |= KVM_CPUID_EMUSGX_GUEST_SEND_PAGE;

	//pr_info("vSGX: page_check_val = 0x%08X, rax = 0x%016llX\n", *((uint32_t *)(shared_page + 4092)), rax_val);

	if (sender_counter < 20) {
		time_2_start[sender_counter] = ktime_get_real_ns();
		time_1[sender_counter] = time_2_start[sender_counter] - time_0;
		sender_counter += 1;
	}

	asm volatile (
		"cpuid"
		: "=b"(cpuid_success)
		: "a"(rax_val), "c"(physical_page_addr)
		: 
	);

	/*
	if (sender_counter == 20) {
		for (i = 0 ; i < 20; i++) {
			pr_info("vSGX: Time 1 = %lld\n", time_1[i]);
		}
		for (i = 0; i < 20; i++) {
			pr_info("vSGX: Time 2 Start = %lld\n", time_2_start[i]);
		}
		sender_counter = 100;
	}*/
	
	//pr_info("vSGX: Shared page @ 0x%016llX\n", (uint64_t)shared_page);
	emusgx_free_shared_page(shared_page);
	if (!cpuid_success) {
		pr_info("EmuSGX: CPUID failed");
		return -EINVAL;
	}
	return 0;
}

void emusgx_print_page(void *page) {
	uint64_t *ptr = page;
	int i;
	for (i = 0; i < 512; i++) {
		pr_info("EmuSGX: %016llX\n", ptr[i]);
	}
}

int emusgx_send_data(void *addr, uint64_t size, int target_enclave) {
	uint64_t turns;
	uint64_t final;
	uint64_t i;
	uint64_t total_packages;
	struct emusgx_cross_vm_package *package;
	struct emusgx_cross_vm_package *plain_package;
	uint64_t current_session;
	int encrypt_ret;
	uint64_t iv = 0;
	uint64_t enclave_vm_id;

	package = kmalloc(sizeof(struct emusgx_cross_vm_package), GFP_KERNEL);
	plain_package = kmalloc(sizeof(struct emusgx_cross_vm_package), GFP_KERNEL);

	// First we get our session number
	// Can-sleep environment
	if (mutex_lock_killable(&emusgx_session_number_lock)) {
		pr_info("vSGX: Send data killed\n");
		return -1;
	}
	current_session = emusgx_session[target_enclave]++;
	if (emusgx_session[target_enclave] >= EMUSGX_MAX_SESSION_NUMBER) {
		// Reset session number
		emusgx_session[target_enclave] = 0;
	}
	mutex_unlock(&emusgx_session_number_lock);

	// Next pack data into pages and send them
	turns = size / EMUSGX_PAYLOAD_SIZE;
	final = size % EMUSGX_PAYLOAD_SIZE;
	total_packages = turns + ((final != 0) ? 1 : 0);
	if (final == 0) {
		final = EMUSGX_PAYLOAD_SIZE;
	}
	enclave_vm_id = emusgx_get_enclave_vm_id(target_enclave);
	//pr_info("vSGX_DEBUG: Sending %d\n", ((char *)addr)[0]);
	for (i = 0; i < total_packages; i++) {
		// Capsulate the data
		plain_package->session_number = current_session;
		plain_package->order = i;
		plain_package->total_pages = total_packages;
		plain_package->total_size = size;
		plain_package->enclave_vm_id = enclave_vm_id;

		// Copy data
		if (i == total_packages - 1) {
			memcpy(plain_package->payload, addr + (i * EMUSGX_PAYLOAD_SIZE), final);
		}
		else {
			memcpy(plain_package->payload, addr + (i * EMUSGX_PAYLOAD_SIZE), EMUSGX_PAYLOAD_SIZE);
		}


		//pr_info("======================\n");
		//emusgx_print_page(plain_package);
		//pr_info("======================\n");

		// Encrypt and get MAC
		encrypt_ret = emusgx_aes_128_gcm_enc(emusgx_internal_cr_cross_vm_key, &iv, emusgx_static_aad, 16, plain_package, 4096 - 16, package, package->mac);
		if (encrypt_ret != 0) {
			pr_info("EmuSGX: Unexpected encryption issue\n");
			kfree(package);
			kfree(plain_package);
			return -EINVAL;
		}

		//emusgx_debug_print("EmuSGX: Signature: First: 0x%016llX. MAC: %016llX %016llX\n", ((uint64_t *)package)[0], package->mac[0], package->mac[1]);

		//emusgx_print_page(package);

		// Send single page
		if (emusgx_send_single_page(package, 4096, target_enclave)) {
			kfree(package);
			kfree(plain_package);
			return -EINVAL;
		}
		
		//emusgx_debug_print("EmuSGX: Sent package %lld/%lld for session %lld\n", i, total_packages, current_session);
	}
	
	kfree(package);
	kfree(plain_package);

	return 0;
}
