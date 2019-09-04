#include <openssl/cpu.h>

#ifdef OPENSSL_S390X
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include "fipsmodule/aes/internal.h"
#include "fipsmodule/des/internal.h"
#include "fipsmodule/sha/internal.h"
#include "cpu-s390x.h"

static void *handle = NULL;

int CRYPTO_is_s390x_capable(void)
{
    handle = dlopen("libica.so",RTLD_NOW);
     if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return(1);
}

/**
 * AES Support
 */
unsigned static char AES_NIST_IV[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int aes_hw_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key) {

    key->rounds = bits/8;
    memcpy((void *) &key->rd_key, (void *) user_key, bits/8);
 	return (1);
}

int aes_hw_set_decrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key) {

    key->rounds = bits/8;
    memcpy((void *) &key->rd_key, (void *) user_key, bits/8);
 	return (1);
}

void aes_hw_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t length, const AES_KEY *key,
                                       uint8_t *ivec, int enc) {

    static char epName[] = "ica_aes_cbc";
	static unsigned int (*ica_aes_cbc)(const unsigned char *, unsigned char *,
                                      unsigned long, unsigned char *,
                                      unsigned int, unsigned char *,
                                      unsigned int) = NULL;

 	if (ica_aes_cbc == NULL) {
		ica_aes_cbc = dlsym(handle, epName);
        if (ica_aes_cbc == NULL) {
            perror("Error locating symbol ica_aes_cbc");
            abort();
        }
	}
    (void) ica_aes_cbc(in, out, length, (unsigned char *) key->rd_key, key->rounds, AES_NIST_IV, ICA_ENCRYPT);
}

void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) 
{
    static char epName[] = "ica_aes_ecb";
	static unsigned int (*ica_aes_ecb)(const unsigned char *, unsigned char *,
                                       unsigned long, unsigned char *,
                                       unsigned int, 
                                       unsigned int) = NULL;

 	if (ica_aes_ecb == NULL) {
        if (ica_aes_ecb == NULL) {
            perror("Error locating symbol ica_aes_ecb");
            abort();
        }
		ica_aes_ecb = dlsym(handle, epName);
	}

    (void) ica_aes_ecb(in, out, AES_BLOCK_SIZE, (unsigned char *) key->rd_key, key->rounds, ICA_ENCRYPT);
}

void aes_hw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) 
{
    static char epName[] = "ica_aes_ecb";
    unsigned int (*ica_aes_ecb)(const unsigned char *, unsigned char *,
                                unsigned long, unsigned char *,
                                unsigned int,
                                unsigned int) = NULL;

 	if (ica_aes_ecb == NULL) {
        if (ica_aes_ecb == NULL) {
            perror("Error locating symbol ica_aes_ecb");
            abort();
        }
		ica_aes_ecb = dlsym(handle, epName);
	}

    (void) ica_aes_ecb(in, out, AES_BLOCK_SIZE, (unsigned char *) key->rd_key, key->rounds, ICA_DECRYPT);
}

void aes_hw_ctr128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const AES_KEY *key, uint8_t ivec[AES_BLOCK_SIZE],
                           uint8_t ecount_buf[AES_BLOCK_SIZE], unsigned int *num)
{
    static char epName[] = "ica_aes_ctr";
    unsigned int (*ica_aes_ctr)(const unsigned char *, unsigned char *,
                                unsigned long, 
                                unsigned char *, unsigned int, 
                                unsigned char *, unsigned int,
                                unsigned int) = NULL;

 	if (ica_aes_ctr == NULL) {
        if (ica_aes_ctr == NULL) {
            perror("Error locating symbol ica_aes_ecb");
            abort();
        }
		ica_aes_ctr = dlsym(handle, epName);
	}

    (void) ica_aes_ctr(in, out, len, (unsigned char *) key->rd_key, key->rounds, ecount_buf, *num, ICA_ENCRYPT);
}

void aes_hw_ctr32_encrypt_blocks (const uint8_t *in, uint8_t *out,
                                  size_t len, const AES_KEY *key,
                                  const uint8_t ivec[16]) 
{
    static char epName[] = "ica_aes_ctr";
    unsigned int (*ica_aes_ctr)(const unsigned char *, unsigned char *,
                                unsigned long, 
                                unsigned char *, unsigned int, 
                                unsigned char *, unsigned int,
                                unsigned int) = NULL;
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned int num = 1;

 	if (ica_aes_ctr == NULL) {
        if (ica_aes_ctr == NULL) {
            perror("Error locating symbol ica_aes_ecb");
            abort();
        }
		ica_aes_ctr = dlsym(handle, epName);
	}

    (void) ica_aes_ctr(in, out, len, (unsigned char *) key->rd_key, key->rounds, ecount_buf, num, ICA_ENCRYPT);
}

void SHA256_hw(const uint8_t *data, size_t len, uint8_t out[SHA512_DIGEST_LENGTH])
{
    static char epName[] = "ica_sha256";
	static int (*ica_sha256)(unsigned int,
			unsigned int , unsigned char *, sha256_context_t *,
			unsigned char *) = NULL;
    sha256_context_t ctx;

 	if (ica_sha256 == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_sha256 = dlsym(handle, epName);
	}
    memset((void *) &ctx, 0, sizeof(ctx));
    (void) ica_sha256(SHA_MSG_PART_ONLY, len, (unsigned char *) data, &ctx ,out);

}

void SHA512_hw(const uint8_t *data, size_t len, uint8_t out[SHA512_DIGEST_LENGTH])
{
    static char epName[] = "ica_sha512";
	static int (*ica_sha512)(unsigned int,
			uint64_t ,unsigned char *, sha512_context_t *, unsigned char *) = NULL;
    sha512_context_t ctx;

 	if (ica_sha512 == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_sha512 = dlsym(handle, epName);
	}
    memset((void *) &ctx, 0, sizeof(ctx));
    (void) ica_sha512(SHA_MSG_PART_ONLY, len, (unsigned char *) data, &ctx ,out);
}


#endif
