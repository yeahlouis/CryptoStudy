/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <stdint.h>

/*
 * Included for memcpy & memset
 */
#include <string.h>
/*
 * Included for snprintf
 */
#include <stdio.h>

#include "sm3.h"

#define SM3_GET_UINT32(b) ( \
	((uint32_t)((b)[0] & 0xFF) << 24) | \
	((uint32_t)((b)[1] & 0xFF) << 16) | \
	((uint32_t)((b)[2] & 0xFF) <<  8) | \
	((uint32_t)((b)[3] & 0xFF)))
	

#define SM3_PUT_UINT32(dst, x)              \
    do {                                \
	    (dst)[0] = ((x) >> 24) & 0xFF;  \
	    (dst)[1] = ((x) >> 16) & 0xFF;  \
	    (dst)[2] = ((x) >>  8) & 0xFF;  \
	    (dst)[3] = (x) & 0xFF;          \
    } while (0)



unsigned char PADDING[] = {
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void sm3_transform(uint32_t state[8], const unsigned char block[64]) {

	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];

    unsigned int SS1, SS2, TT1, TT2, W[68],W1[64];
	unsigned int T[64];
	unsigned int Temp1,Temp2,Temp3,Temp4,Temp5;
	int j;


 	for(j=0; j < 68; j++)
 		W[j] = 0;
 	for(j=0; j < 64; j++)
 		W1[j] = 0;
	
	for(j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for(j =16; j < 64; j++)
		T[j] = 0x7A879D8A;

    W[ 0] = SM3_GET_UINT32(&block[ 0] );
    W[ 1] = SM3_GET_UINT32(&block[ 4] );
    W[ 2] = SM3_GET_UINT32(&block[ 8] );
    W[ 3] = SM3_GET_UINT32(&block[12] );
    W[ 4] = SM3_GET_UINT32(&block[16] );
    W[ 5] = SM3_GET_UINT32(&block[20] );
    W[ 6] = SM3_GET_UINT32(&block[24] );
    W[ 7] = SM3_GET_UINT32(&block[28] );
    W[ 8] = SM3_GET_UINT32(&block[32] );
    W[ 9] = SM3_GET_UINT32(&block[36] );
    W[10] = SM3_GET_UINT32(&block[40] );
    W[11] = SM3_GET_UINT32(&block[44] );
    W[12] = SM3_GET_UINT32(&block[48] );
    W[13] = SM3_GET_UINT32(&block[52] );
    W[14] = SM3_GET_UINT32(&block[56] );
    W[15] = SM3_GET_UINT32(&block[60] );



#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

	for(j = 16; j < 68; j++ )
	{
		//W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
		//Why thd release's result is different with the debug's ?
		//Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.
		
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}


	for(j =  0; j < 64; j++)
	{
        W1[j] = W[j] ^ W[j+4];
	}


	for(j =0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(a,12) + e + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(a,12);
		TT1 = FF0(a,b,c) + d + SS2 + W1[j];
		TT2 = GG0(e,f,g) + h + SS1 + W[j];
		d = c;
		c = ROTL(b,9);
		b = a;
		a = TT1;
		h = g;
		g = ROTL(f,19);
		f = e;
		e = P0(TT2);
	}
	
	for(j =16; j < 64; j++)
	{
        /**
         * 做移位运算时，为避免编译器引起歧义，！！不要！！让移位数量出现负数、或超过字长！！！！
         */
		SS1 = ROTL((ROTL(a,12) + e + ROTL(T[j],j % 32)), 7);
		SS2 = SS1 ^ ROTL(a,12);
		TT1 = FF1(a,b,c) + d + SS2 + W1[j];
		TT2 = GG1(e,f,g) + h + SS1 + W[j];
		d = c;
		c = ROTL(b,9);
		b = a;
		a = TT1;
		h = g;
		g = ROTL(f,19);
		f = e;
		e = P0(TT2);
	}

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;


    /* Wipe variables */
    a = b = c = d = e = f = g = h = 0;
}


void sm3_init(sm3_ctx *ctx) {
	ctx->count[0] = 0;
	ctx->count[1] = 0;

    /* SM3 initialization constants */
	ctx->state[0] = 0x7380166F;
	ctx->state[1] = 0x4914B2B9;
	ctx->state[2] = 0x172442D7;
	ctx->state[3] = 0xDA8A0600;
	ctx->state[4] = 0xA96F30BC;
	ctx->state[5] = 0x163138AA;
	ctx->state[6] = 0xE38DEE4D;
	ctx->state[7] = 0xB0FB0E4E;
}


void sm3_update(sm3_ctx *ctx, const unsigned char *input, unsigned int len)
{
	uint32_t i = 0, index = 0, partlen = 0;
    uint32_t inputlen = len; 

    /* Compute number of bytes mod 64 */
	index = (ctx->count[0] >> 3) & 0x3F;
	partlen = 64 - index; //first, index is 0, partlen is 64

	ctx->count[0] += inputlen << 3;
	if(ctx->count[0] < (inputlen << 3)) {
		ctx->count[1]++;
	}

	ctx->count[1] += inputlen >> 29;


	if(inputlen >= partlen) {
		memcpy(&ctx->buffer[index],input,partlen);
    
		sm3_transform(ctx->state,ctx->buffer);
		for(i = partlen;i+64 <= inputlen;i+=64) {
			sm3_transform(ctx->state,&input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&ctx->buffer[index],&input[i],inputlen-i);
}

/* Add padding and return the message digest. */
void sm3_final(sm3_ctx *ctx, unsigned char digest[SM3_DIGEST_SIZE]) {
    int i;
	unsigned int index = 0,padlen = 0;
	unsigned char bits[8];
	index = (ctx->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
    
    
    //高位在前
    SM3_PUT_UINT32(&bits[0], ctx->count[1]);
    SM3_PUT_UINT32(&bits[4], ctx->count[0]);

	sm3_update(ctx,PADDING,padlen);
	sm3_update(ctx,bits, sizeof(bits));

    for (i = 0; i < 8; i ++) {
        SM3_PUT_UINT32(&digest[i * 4], ctx->state[i]);
    }
}


void sm3_sample(const unsigned char *input, unsigned int len, unsigned char *digest, unsigned int digest_size) {
    unsigned char digest_inside[SM3_DIGEST_SIZE];
	sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, input, len);
    sm3_final(&ctx, digest_inside);
    memcpy(digest, digest_inside, digest_size);
}

void sm3_hexstr(const unsigned char *input, unsigned int len, char *hexstr, unsigned int hexstr_size) {
    int i;
    unsigned char digest_inside[SM3_DIGEST_SIZE];
	sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, input, len);
    sm3_final(&ctx, digest_inside);
    
    for (i = 0; i < sizeof(digest_inside) && hexstr_size > (i * 2) + 1; i ++) {
        snprintf(hexstr + (i * 2), hexstr_size - (i * 2), "%02x", (digest_inside[i] & 0xFF)); 
    }
}


#ifdef __SM3_DIGEST_TEST__
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int check_cpu() 
{
    union w
    {
        int a;
        char b;
    } c;
    c.a = 1;
    return (1 == c.b);
}

int sm3_file(const char *path)
{
    int ret = -1, err;
    int i;
    FILE *fp = NULL;
    unsigned char buff[1024];
    unsigned char hash[SM3_DIGEST_SIZE];
    char hash_tmp[SM3_DIGEST_HEXSTR_LEN];
	sm3_ctx ctx;


    if (NULL == path || strlen(path) <= 0) {
        return (ret);
    }
    if ((fp = fopen(path, "rb")) == NULL) {
        err = errno ? errno : -1;
        printf("Unable to open file.[%s](%s)\n", path, strerror(err));
        return (ret);
    }

    sm3_init(&ctx);
    while (!feof(fp)) {
       i = fread(buff, 1, sizeof(buff), fp); 
       sm3_update(&ctx, (const unsigned char *)buff, (unsigned int)i);
    }
    fclose(fp);
    fp = NULL;
    sm3_final(&ctx, hash);

    for (i = 0; i < sizeof(hash); i ++) {
        snprintf(hash_tmp + (i * 2), sizeof(hash_tmp) - (i * 2), "%02x", (hash[i] & 0xFF)); 
    }
    printf("\ncalculating SM3 on [%s]\n[%s]\n", path, hash_tmp);

    ret = 0;
    return (ret);
}

int test()
{
    int ret = -1;
    int i, j;
	sm3_ctx ctx;
    unsigned char hash[SM3_DIGEST_SIZE];
    char hash_tmp[SM3_DIGEST_HEXSTR_LEN];
    char hash_str[SM3_DIGEST_HEXSTR_LEN];
    const char *stra[] = {
        "",
        "0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261",
        "a",
        "f25da39f798e9249762df48f3647f5d84d9cdac5ed6e496482b49b798d49517e",
        "abc",
        "8112d24a09eeda43ea595f3cfefb2a34856977ce4ac1d03fcc2067ae64c5e3f1",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "eda26e42c6b10299c03bdd74eb72b9f8fce9f0f028db4650fbf7e3dad21085cb",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "eda26e42c6b10299c03bdd74eb72b9f8fce9f0f028db4650fbf7e3dad21085cb",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "508a0a252ca751f120c4d2f9afb4de58149067e68db1a0c1ea7a7ffed90daf5f",
        NULL,
        NULL,
        NULL,
        NULL,
    };
    
    
    const char *strb[] = {
        "a",
        "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3",
        NULL,
        NULL,
        NULL,
        NULL,
    };
    

    printf("+++++++++++++++++++++++++\n");
    printf("sizeof(stra)/sizeof(stra[0] = [%lu]\n", sizeof(stra) / sizeof(stra[0]));
    printf("sizeof(hash) = [%lu]\n", sizeof(hash));
    printf("sizeof(hash_str) = [%lu]\n", sizeof(hash_str));

    for (i = 0; i < sizeof(stra) / sizeof(stra[0]); i += 2) {
        if (NULL == stra[i]) {
            break;
        }

        printf("\n--->i = [%d][%s]\n", i, stra[i]);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));

        sm3_sample((const unsigned char *)stra[i], strlen(stra[i]), hash, sizeof(hash));
        for (j = 0; j < sizeof(hash); j ++) {
            snprintf(hash_tmp + (j * 2), sizeof(hash_tmp) - (j * 2), "%02x", (hash[j] & 0xFF)); 
        }

        sm3_hexstr((const unsigned char *)stra[i], strlen(stra[i]), hash_str, sizeof(hash_str));
        printf("SM3(\"%s\")=\n[%s]-sm3_smaple\n[%s]-sm3_hexstr\n[%s]\n", stra[i], hash_tmp, hash_str, stra[i + 1]);
        if (strcmp((const char *)hash_str, stra[i + 1]) == 0 && strcmp((const char *)hash_tmp, stra[i + 1]) == 0) {
            printf("--->success...\n");
        } else {
            printf("----failure!!!\n");
            printf("-------------------------\n\n");
            return (ret);
        }
    }

    sm3_init(&ctx);
    for (i = 0; i < 1000000; i ++) {
        sm3_update(&ctx, (const unsigned char *)strb[0], (unsigned int)strlen(strb[0]));
    }
    sm3_final(&ctx, hash);
    for (j = 0; j < sizeof(hash); j ++) {
        snprintf(hash_tmp + (j * 2), sizeof(hash_tmp) - (j * 2), "%02x", (hash[j] & 0xFF)); 
    }
    printf("\ncalculating SM3 on A million repetitions of \"a\"('a' * 1,000,000)\n[%s]-sm3\n[%s]\n", hash_tmp, strb[1]);
    if (strcmp((const char *)hash_tmp, strb[1]) == 0) {
        printf("--->success...\n");
    } else {
        printf("----failure!!!\n");
        printf("-------------------------\n\n");
        return (ret);
    }

    printf("+++++++++++++++++++++++++\n");

    ret = 0;
    return (ret);
}

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    char hash_str[SM3_DIGEST_HEXSTR_LEN];
    

    if (check_cpu()) {
        printf("--->This is a little-endian machine.\n");
    } else {
        printf("--->This is a big-endian machine!!!!\n");
    }

    //printf("argc = [%d]\n", argc);
    if (argc < 2) {
        if (0 == test()) {
            ret = EXIT_SUCCESS;
        }
    } else if (argc == 2) {
        if (NULL != argv[1]) {
            sm3_hexstr((const unsigned char *)argv[1], strlen(argv[1]), hash_str, sizeof(hash_str));
            printf("SM3(\"%s\")=\n[%s]\n", argv[1], hash_str);
        } 
    } else if (argc == 3) {
        if (NULL != argv[1] && NULL != argv[2] && strcmp("-f", argv[1]) == 0) {
            if (0 == sm3_file(argv[2])) {
                ret = EXIT_SUCCESS;
            }
        }
    }
    
    return (ret);
}
// gcc -Wall -D__SM3_DIGEST_TEST__ sm3.c
#endif /* end of __SM3_DIGEST_TEST__*/


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
