#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/mm.h>

#include <crypto/aead.h>

#include "emusgx_internal.h"
#include "emusgx_debug.h"

int emusgx_aes_128_gcm_dec(uint8_t *key, uint64_t *counter, void *aad, size_t aad_size, 
				void *cipher_text, size_t cipher_size, void *plain_text, uint64_t *mac) {
	struct scatterlist plain_list[2];
	struct scatterlist cipher_list[3];

	struct crypto_aead *tfm = NULL;
        struct aead_request *req;
	char *algo = "gcm(aes)";
	int ret;

	char *iv;
	uint64_t ivsize;

	void *aad_page;
	void *cipher_text_page;
	void *plain_text_page;
	void *mac_page;

	if (cipher_size > 4096) {
		pr_info("EmuSGX: Cannot do GCM(AES) for data more than a page\n");
		return -1;
	}

	// Everything must be reallocated into pages
	aad_page = (void *)get_zeroed_page(GFP_KERNEL);
	cipher_text_page = (void *)get_zeroed_page(GFP_KERNEL);
	plain_text_page = (void *)get_zeroed_page(GFP_KERNEL);
	mac_page = (void *)get_zeroed_page(GFP_KERNEL);

	memcpy(aad_page, aad, aad_size);
	memcpy(cipher_text_page, cipher_text, cipher_size);
	memcpy(mac_page, mac, 16);

	// Allocate a cipher handle for AEAD
	tfm = crypto_alloc_aead(algo, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "EmuSGX: Failed to create cipher handle\n");
		ret = -1;
		goto out1;
	}

	// Allocate AEAD request
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (req == NULL) {
		printk(KERN_INFO "EmuSGX: Failed to create aead request\n");
		ret = -1;
		goto out2;
	}

	// Synchronized
	crypto_aead_clear_flags(tfm, ~0);

	// Set key
	if ((ret = crypto_aead_setkey(tfm, key, 16) != 0)) {
		printk(KERN_INFO "EmuSGX: Return value for setkey is %d\n", ret);
		printk(KERN_INFO "EmuSGX: key could not be set\n");
		ret = -1;
		goto out3;
	}

	// Set tag size (CMAC)
	if (crypto_aead_setauthsize(tfm, 16)) {
		pr_info("EmuSGX: Failed to set tag size\n");
		ret = -1;
		goto out3;
	}

	// Get iv size
	ivsize = crypto_aead_ivsize(tfm);
	if (!(ivsize)){
		pr_info("IV size could not be authenticated\n");
		ret = -1;
		goto out3;
	}

	// Set initialization vector
	iv = (void *)get_zeroed_page(GFP_KERNEL);
	// iv shall be 12 bytes in gcm(aes), but our counter is 8 bytes
	// so we leave other bits 0
	// memset(iv, 0, ivsize);
	memcpy(iv, counter, 8);

	sg_init_table(plain_list, 2);
	sg_set_buf(&plain_list[0], aad_page, aad_size);
	sg_set_buf(&plain_list[1], plain_text_page, cipher_size);

	sg_init_table(cipher_list, 3);
	sg_set_buf(&cipher_list[0], aad_page, aad_size);
	sg_set_buf(&cipher_list[1], cipher_text_page, cipher_size);
	sg_set_buf(&cipher_list[2], mac_page, 16);

	// For unknown reason, the decrypt size needs to add AAD
	aead_request_set_crypt(req, cipher_list, plain_list, cipher_size + aad_size, iv);
	aead_request_set_ad(req, aad_size);

	ret = crypto_aead_decrypt(req);
	if (ret != 0) {
		if (ret == -EBADMSG) {
			pr_info("EmuSGX: Decrypt failed due to MAC mismatch\n");
		}
		else {
			pr_info("EmuSGX: Decrypt failed due to some wired reason\n");
		}
	}
	else {
		memcpy(plain_text, plain_text_page, cipher_size);
	}

	// Freeup things
	free_page((uint64_t)iv);
out3:
	aead_request_free(req);
out2:
	crypto_free_aead(tfm);
out1:
	free_page((uint64_t)aad_page);
	free_page((uint64_t)plain_text_page);
	free_page((uint64_t)cipher_text_page);
	free_page((uint64_t)mac_page);

	return ret;
}

int emusgx_aes_128_gcm_enc(uint8_t *key, uint64_t *counter, void *aad, size_t aad_size, 
				void *plain_text, size_t plain_size, void *cipher_text, uint64_t *mac) {
	struct scatterlist plain_list[2];
	struct scatterlist cipher_list[3];

	struct crypto_aead *tfm = NULL;
        struct aead_request *req;
	char *algo = "gcm(aes)";
	int ret;

	char *iv;
	uint64_t ivsize;

	void *aad_page;
	void *cipher_text_page;
	void *plain_text_page;
	void *mac_page;

	if (plain_size > 4096) {
		pr_info("EmuSGX: Cannot do GCM(AES) for data more than a page\n");
		return -1;
	}

	// Everything must be reallocated into pages
	aad_page = (void *)get_zeroed_page(GFP_KERNEL);
	cipher_text_page = (void *)get_zeroed_page(GFP_KERNEL);
	plain_text_page = (void *)get_zeroed_page(GFP_KERNEL);
	mac_page = (void *)get_zeroed_page(GFP_KERNEL);

	memcpy(aad_page, aad, aad_size);
	memcpy(plain_text_page, plain_text, plain_size);

	// Allocate a cipher handle for AEAD
	tfm = crypto_alloc_aead(algo, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "EmuSGX: Failed to create cipher handle\n");
		ret = -1;
		goto out1;
	}

	// Allocate AEAD request
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (req == NULL) {
		printk(KERN_INFO "EmuSGX: Failed to create aead request\n");
		ret = -1;
		goto out2;
	}

	// Synchronized
	crypto_aead_clear_flags(tfm, ~0);

	// Set key
	if ((ret = crypto_aead_setkey(tfm, key, 16) != 0)) {
		printk(KERN_INFO "EmuSGX: Return value for setkey is %d\n", ret);
		printk(KERN_INFO "EmuSGX: key could not be set\n");
		ret = -1;
		goto out3;
	}

	// Set tag size (CMAC)
	if (crypto_aead_setauthsize(tfm, 16)) {
		pr_info("EmuSGX: Failed to set tag size\n");
		ret = -1;
		goto out3;
	}

	// Get iv size
	ivsize = crypto_aead_ivsize(tfm);
	if (!(ivsize)){
		pr_info("IV size could not be authenticated\n");
		ret = -1;
		goto out3;
	}

	// Set initialization vector
	iv = (void *)get_zeroed_page(GFP_KERNEL);
	// iv shall be 12 bytes in gcm(aes), but our counter is 8 bytes
	// so we leave other bits 0
	// memset(iv, 0, ivsize);
	memcpy(iv, counter, 8);

	sg_init_table(plain_list, 2);
	sg_set_buf(&plain_list[0], aad_page, aad_size);
	sg_set_buf(&plain_list[1], plain_text_page, plain_size);

	sg_init_table(cipher_list, 3);
	sg_set_buf(&cipher_list[0], aad_page, aad_size);
	sg_set_buf(&cipher_list[1], cipher_text_page, plain_size);
	sg_set_buf(&cipher_list[2], mac_page, 16);

	// For unknown reason, the encrypt size does not need to add AAD
	aead_request_set_crypt(req, plain_list, cipher_list, plain_size, iv);
	aead_request_set_ad(req, aad_size);

	ret = crypto_aead_encrypt(req);
	if (ret != 0) {
		pr_info("EmuSGX: Decrypt failed due to some wired reason\n");
	}
	else {
		memcpy(cipher_text, cipher_text_page, plain_size);
		memcpy(mac, mac_page, 16);
	}

	// Freeup things
	free_page((uint64_t)iv);
out3:
	aead_request_free(req);
out2:
	crypto_free_aead(tfm);
out1:
	free_page((uint64_t)aad_page);
	free_page((uint64_t)plain_text_page);
	free_page((uint64_t)cipher_text_page);
	free_page((uint64_t)mac_page);

	return ret;
}
