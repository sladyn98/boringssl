
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

int ica_aes_cbc(char *x, int y, void *handle) {
	static char *epName = "ica_aes_cbc";
	static int (*ica_aes_cbc)(char *, int) = NULL;
	
	if (ica_aes_cbc == NULL) {
		ica_aes_cbc = dlsym(handle, epName);
	}
	
	return (*(ica_aes_cbc)(x, y));
}
