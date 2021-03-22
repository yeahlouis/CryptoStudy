/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <stdint.h>

/*
 * Included for memcpy & memset
 */
#include <string.h>

#include "sha256.h"

#define SHA256_GET_UINT32(b) ( \
	((uint32_t)((b)[0] & 0xFF) << 24) | \
	((uint32_t)((b)[1] & 0xFF) << 16) | \
	((uint32_t)((b)[2] & 0xFF) <<  8) | \
	((uint32_t)((b)[3] & 0xFF)))
	

#define SHA256_PUT_UINT32(dst, x)              \
    do {                                \
	    (dst)[0] = ((x) >> 24) & 0xFF;  \
	    (dst)[1] = ((x) >> 16) & 0xFF;  \
	    (dst)[2] = ((x) >>  8) & 0xFF;  \
	    (dst)[3] = (x) & 0xFF;          \
    } while (0)

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

#define T0(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define T1(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

#define CH(a, b, c) (((a) & (b)) ^ ((~(a)) & (c)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define WW(i) (w[i] = w[i - 16] + S0(w[i - 15]) + w[i - 7] + S1(w[i - 2]))

#define ROUND(a, b, c, d, e, f, g, h, k, w) \
    do { \
	    uint32_t tmp0 = h + T0(e) + CH(e, f, g) + k + w; \
	    uint32_t tmp1 = T1(a) + MAJ(a, b, c); \
	    h = tmp0 + tmp1; \
	    d += tmp0; \
    } while (0)


unsigned char PADDING[] = {
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA256Transform(unsigned int state[8], unsigned char block[64]) {
	const uint32_t rk [64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];
	uint32_t w[64];

    int i;
	for (i = 0; i < 16; i++)
   	    w[i] = SHA256_GET_UINT32(&block[4 * i]);


	for (i = 0; i < 16; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, rk[i    ], w[i    ]);
		ROUND(h, a, b, c, d, e, f, g, rk[i + 1], w[i + 1]);
		ROUND(g, h, a, b, c, d, e, f, rk[i + 2], w[i + 2]);
		ROUND(f, g, h, a, b, c, d, e, rk[i + 3], w[i + 3]);
		ROUND(e, f, g, h, a, b, c, d, rk[i + 4], w[i + 4]);
		ROUND(d, e, f, g, h, a, b, c, rk[i + 5], w[i + 5]);
		ROUND(c, d, e, f, g, h, a, b, rk[i + 6], w[i + 6]);
		ROUND(b, c, d, e, f, g, h, a, rk[i + 7], w[i + 7]);
	}
	
	for (i = 16; i < 64; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, rk[i    ], WW(i    ));
		ROUND(h, a, b, c, d, e, f, g, rk[i + 1], WW(i + 1));
		ROUND(g, h, a, b, c, d, e, f, rk[i + 2], WW(i + 2));
		ROUND(f, g, h, a, b, c, d, e, rk[i + 3], WW(i + 3));
		ROUND(e, f, g, h, a, b, c, d, rk[i + 4], WW(i + 4));
		ROUND(d, e, f, g, h, a, b, c, rk[i + 5], WW(i + 5));
		ROUND(c, d, e, f, g, h, a, b, rk[i + 6], WW(i + 6));
		ROUND(b, c, d, e, f, g, h, a, rk[i + 7], WW(i + 7));
	}

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    /* Wipe variables */
    a = b = c = d = e = f = g = h = 0;
}


void SHA256Init(SHA256_CTX *context) {
	context->count[0] = 0;
	context->count[1] = 0;

    /* SHA256 initialization constants */
	context->state[0] = 0x6a09e667;
	context->state[1] = 0xbb67ae85;
	context->state[2] = 0x3c6ef372;
	context->state[3] = 0xa54ff53a;
	context->state[4] = 0x510e527f;
	context->state[5] = 0x9b05688c;
	context->state[6] = 0x1f83d9ab;
	context->state[7] = 0x5be0cd19;
}


void SHA256Update(SHA256_CTX *context,unsigned char *input,unsigned int inputlen)
{
	unsigned int i = 0,index = 0,partlen = 0;

    /* Compute number of bytes mod 64 */
	index = (context->count[0] >> 3) & 0x3F;
	partlen = 64 - index; //first, index is 0, partlen is 64

	context->count[0] += inputlen << 3;
	if(context->count[0] < (inputlen << 3)) {
		context->count[1]++;
	}

	context->count[1] += inputlen >> 29;


	if(inputlen >= partlen) {
		memcpy(&context->buffer[index],input,partlen);
    
		SHA256Transform(context->state,context->buffer);
		for(i = partlen;i+64 <= inputlen;i+=64) {
			SHA256Transform(context->state,&input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&context->buffer[index],&input[i],inputlen-i);
}

/* Add padding and return the message digest. */
void SHA256Final(SHA256_CTX *context,unsigned char digest[SHA256_DIGEST_LENGTH]) {
	unsigned int index = 0,padlen = 0;
	unsigned char bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
    
    //int i;
    
    //高位在前
    SHA256_PUT_UINT32(&bits[0], context->count[1]);
    SHA256_PUT_UINT32(&bits[4], context->count[0]);

	SHA256Update(context,PADDING,padlen);
	SHA256Update(context,bits, sizeof(bits));

    SHA256_PUT_UINT32(&digest[ 0], context->state[0]);
    SHA256_PUT_UINT32(&digest[ 4], context->state[1]);
    SHA256_PUT_UINT32(&digest[ 8], context->state[2]);
    SHA256_PUT_UINT32(&digest[12], context->state[3]);
    SHA256_PUT_UINT32(&digest[16], context->state[4]);
    SHA256_PUT_UINT32(&digest[20], context->state[5]);
    SHA256_PUT_UINT32(&digest[24], context->state[6]);
    SHA256_PUT_UINT32(&digest[28], context->state[7]);

	//memset(context, 0x00, sizeof(SHA256_CTX));
}



#ifdef __SHA256_TEST__
/*  static const struct {
 *      char *msg;
 *      unsigned char hash[32];
 *  } tests[] = {
 *    { "abc",
 *      { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
 *        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
 *        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
 *        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
 *   },
 *   { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
 *     { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
 *       0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
 *       0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
 *       0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
 *   },
 * };
 * 
 */


/*
gcc -Wall -D__SHA256_TEST__ sha256.c
**/
#include <stdio.h>
int main()
{
    int i, j;
    unsigned char SHA256_hash[SHA256_DIGEST_LENGTH];
    char *stra[] = {
        "",
        "a",
        "abc",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        NULL
    };
    
    char ch = 0xEF;

	SHA256_CTX SHA256_ctx;

    printf("\n=========================\n");
    printf("SHA1 (\"\") = da39a3ee5e6b4b0d3255bfef95601890afd80709\n");
    printf("SHA1 (\"a\") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\n");
    printf("SHA1 (\"abc\") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    printf("SHA1 (\"message digest\") = f96b697d7cb7938d525a2f31aaf161d0\n");
    printf("SHA1 (\"abcdefghijklmnopqrstuvwxyz\") = c3fcd3d76192e4007dfb496cca67e13b\n");
    printf("SHA1 (\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\") =\n"
    "d174ab98d277d9f5a5611c2c9f419d9f\n");
    printf("SHA1 (\"123456789012345678901234567890123456789012345678901234567890123456\n"
    "78901234567890\") = 50abf5706a150990a08b2c5ea40fa0e585554732\n");
    printf("=========================\n");
    
    printf("ch = [%#X][%u][%d]\n", ch, ch, ch);
    printf("sizeof(stra)/sizeof(stra[0] = [%lu]\n", sizeof(stra) / sizeof(stra[0]));

    for (i = 0; i < sizeof(stra) / sizeof(stra[0]); i ++) {
        if (NULL == stra[i]) {
            break;
        }
        printf("--->i = [%d][%s]\n", i, stra[i]);
        SHA256Init(&SHA256_ctx);
	    SHA256Update(&SHA256_ctx, (unsigned char *)stra[i], strlen(stra[i]));
	    SHA256Final(&SHA256_ctx, SHA256_hash);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));
        printf("SHA256(\"%s\")=\n", stra[i]); 
        for (j = 0; j < sizeof(SHA256_hash); j ++) {
            printf("%02x", SHA256_hash[j]);
        } 
        printf("\n\n"); 
    }

    printf("\n"); 
    
    return 0;
}
#endif


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
