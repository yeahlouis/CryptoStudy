#include <stdio.h>
#include <stdlib.h>

#include "sha256.h"


int main ()
{
    int ret = EXIT_FAILURE;
    char *stra[] = {
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        NULL
    };
     
    unsigned char hash[32];

    int i, j;
    
    for (i = 0; i < sizeof(stra) / sizeof(stra[0]); i ++) {
        if (NULL == stra[i]) {
            break;
        }

        memset(hash, 0x00, sizeof(hash));
        sha256_simple((unsigned char *)stra[i], strlen(stra[i]), hash);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));
        printf("SHA256(\"%s\")=\n", stra[i]); 
        for (j = 0; j < sizeof(hash); j ++) {
            printf("%02x", hash[j]);
        } 
        printf("\n\n"); 
    }

    printf("\n"); 



    ret = EXIT_SUCCESS;
    return (ret);
}
