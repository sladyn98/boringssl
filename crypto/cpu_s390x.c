
#include <openssl/base.h>
#include "../../internal.h"
#include <stdio.h>
#include <map>
#include <stdlib.h>
#include <dlfcn.h>




int is_s390x_capable(){
    void *handle;
    int  *iptr;
    int *pointerArray[100]; // To be used to store the addresses of the symbols.
    handle = dlopen("filename",RTLD_NOW);
     if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    
}


int aes_hw_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key) {

    aeskey->rounds = bits/8;
    memcpy(aeskey->rd_key, bits/8, key);
 	return (1);
}

#define ICA_ENCRYPT 1
#define ICA_DECRYPT 0

void aes_hw_cbc_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t length, const AES_KEY *key,
                                       uint8_t *ivec, int enc) {

    static char *epName = "ica_aes_cbc";
	static int (*ica_aes_cbc)(const unsigned char *, unsigned char *,
                         unsigned long, unsigned char *,
                         unsigned char *,
                         unsigned int) = NULL;

 	if (ica_aes_cbc == NULL) {
        handle = dlopen("filename",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_aes_cbc = dlsym(handle, epName);
	}
    ica_aes_cbc(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_ENCRYPT);
}