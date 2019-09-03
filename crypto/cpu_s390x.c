
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
    handle = dlopen("libica.so",RTLD_NOW);
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

int aes_hw_set_decrypt_key(const uint8_t *user_key, const int bits,
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
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_aes_cbc = dlsym(handle, epName);
	}
    ica_aes_cbc(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_ENCRYPT);
}

void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {

    static char *epName = "ica_aes_encrypt";
	static int (*ica_aes_encrypt)(unsigned int, unsigned int, unsigned char *,
			     ica_aes_vector_t *, unsigned int, unsigned char *,
			     unsigned char *) = NULL;

 	if (ica_aes_encrypt == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_aes_encrypt = dlsym(handle, epName);
	}

    (void) ica_aes_cbc(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_ENCRYPT);

}

void aes_hw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {

    static char *epName = "ica_aes_decrypt";
	static int (*ica_aes_encrypt)(unsigned int, unsigned int, unsigned char *,
			     ica_aes_vector_t *, unsigned int, unsigned char *,
			     unsigned char *) = NULL;

 	if (ica_aes_encrypt == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_aes_encrypt = dlsym(handle, epName);
	}

    (void) ica_aes_cbc(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_DECRYPT);
}

// void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
//                                  const AES_KEY *key, const uint8_t ivec[16]) {

//     static char *epName = "ica_aes_ctr";
// 	static int (*unsigned int ica_aes_ctr(const unsigned char *, unsigned char *,
// 			 unsigned long, unsigned char *, unsigned int, unsigned char *, unsigned int,
// 			 unsigned int); = NULL;

//  	if (ica_aes_ctr == NULL) {
//         handle = dlopen("filename",RTLD_NOW);
//         if (!handle) {
//             fprintf(stderr, "%s\n", dlerror());
//             exit(EXIT_FAILURE);
//         }
// 		ica_aes_ctr = dlsym(handle, epName);
// 	}

//     (void) ica_aes_ctr(in_data, out_data,  data_length,aes->rd_key, key_length, *ctr, 16,ICA_ENCRYPT);

// }


void des_hw_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const DES_KEY *key, uint8_t *ivec, const int enc){

    static char *epName = "ica_des_decrypt";
	static int (*ica_aes_encrypt)(const unsigned char *, unsigned char *,
			 unsigned long, unsigned char *, unsigned char *, unsigned int) = NULL;

 	if (ica_des_encrypt == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_des_encrypt = dlsym(handle, epName);
	}

    (void) ica_des_cbc(in_data, out_data, data_length, deskey, key_length, ICA_ENCRYPT);
}


void des_hw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {

    static char *epName = "ica_des_decrypt";
	static int (*ica_des_decrypt)(unsigned int, unsigned int,
			     unsigned char, ica_des_vector_t *, ica_des_key_single_t *,
			     unsigned char *) = NULL;

 	if (ica_des_decrypt == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_des_decrypt = dlsym(handle, epName);
	}
    (void) ica_des_decrypt(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_DECRYPT);
}

void des_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {

    static char *epName = "ica_des_encrypt";
	static int (*ica_des_encrypt)(unsigned int, unsigned int ,
			     unsigned char, ica_des_vector_t *, ica_des_key_single_t *,
			     unsigned char *) = NULL;

 	if (ica_des_encrypt == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_des_encrypt = dlsym(handle, epName);
	}
    (void) ica_des_decrypt(in_data, out_data, data_length, aeskey->rd_key, key_length, ICA_ENCRYPT);
}

int des_hw_set_encrypt_key(const uint8_t *user_key, const int bits,
                           DES_KEY *key) {

    deskey->rounds = bits/8;
    memcpy(deskey->rd_key, bits/8, key);
 	return (1);
}

int des_hw_set_decrypt_key(const uint8_t *user_key, const int bits,
                           DES_KEY *key) {

    deskey->rounds = bits/8;
    memcpy(deskey->rd_key, bits/8, key);
 	return (1);
}


c {

    static char *epName = "ica_sha256";
	static int (*ica_sha256)(unsigned int,
			unsigned int , unsigned char *, sha256_context_t *,
			unsigned char *) = NULL;

 	if (ica_sha256 == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_sha256 = dlsym(handle, epName);
	}
    (void) ica_sha256(data, len, in, ctx ,out);

}

void sha512_block_data_order(uint64_t *state, const uint8_t *in,
                             size_t num_blocks) {

    static char *epName = "ica_sha512";
	static int (*ica_sha512)(unsigned int,
			uint64_t ,unsigned char *, sha512_context_t *, unsigned char *) = NULL;

 	if (ica_sha512 == NULL) {
        handle = dlopen("libica.so",RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            exit(EXIT_FAILURE);
        }
		ica_sha512 = dlsym(handle, epName);
	}
    (void) ica_sha512(data, len, in, ctx ,out);
}

