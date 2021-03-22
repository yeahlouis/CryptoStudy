/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <stdint.h>

/*
 * Included for memcpy & memset
 */
#include <string.h>

#include "sha512.h"

#define GET_UINT64(b) ( \
	((uint64_t)((b)[0] & 0xFF) << 56) | \
	((uint64_t)((b)[1] & 0xFF) << 48) | \
	((uint64_t)((b)[2] & 0xFF) << 40) | \
	((uint64_t)((b)[3] & 0xFF) << 32) | \
	((uint64_t)((b)[4] & 0xFF) << 24) | \
	((uint64_t)((b)[5] & 0xFF) << 16) | \
	((uint64_t)((b)[6] & 0xFF) <<  8) | \
	((uint64_t)((b)[7] & 0xFF)      ))

#define PUT_UINT64(dst, x) \
    do { \
	    (dst)[0] = ((x) >> 56) & 0xFF; \
	    (dst)[1] = ((x) >> 48) & 0xFF; \
	    (dst)[2] = ((x) >> 40) & 0xFF; \
	    (dst)[3] = ((x) >> 32) & 0xFF; \
	    (dst)[4] = ((x) >> 24) & 0xFF; \
	    (dst)[5] = ((x) >> 16) & 0xFF; \
	    (dst)[6] = ((x) >>  8) & 0xFF; \
	    (dst)[7] = (x)         & 0xFF; \
    } while (0)

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define S1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))

#define T0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define T1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define CH(a, b, c) (((a) & (b)) ^ ((~(a)) & (c)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define WW(i) (w[i] = w[i - 16] + S0(w[i - 15]) + w[i - 7] + S1(w[i - 2]))

#define ROUND(a, b, c, d, e, f, g, h, k, w) \
    do { \
	    uint64_t tmp0 = h + T1(e) + CH(e, f, g) + k + w; \
	    uint64_t tmp1 = T0(a) + MAJ(a, b, c); \
	    h = tmp0 + tmp1; \
	    d += tmp0; \
    } while (0)


unsigned char PADDING[] = {
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


static void SHA512Transform(uint64_t state[8], unsigned char block[128]) {
	const uint64_t rk [80] = {
		0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 
		0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 
		0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 
		0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 
		0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 
		0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 
		0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 
		0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 
		0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 
		0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 
		0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 
		0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 
		0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL, 
		0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 
		0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 
		0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };

	uint64_t a = state[0];
	uint64_t b = state[1];
	uint64_t c = state[2];
	uint64_t d = state[3];
	uint64_t e = state[4];
	uint64_t f = state[5];
	uint64_t g = state[6];
	uint64_t h = state[7];
	uint64_t w[128];

    int i;
	for (i = 0; i < 16; i++)
   	    w[i] = GET_UINT64(&block[8 * i]);


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
	
	for (i = 16; i < 80; i += 8) {
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
    a = b = c = d = e = f = g = h = 0ULL;
}


void SHA512Init(SHA512_CTX *context) {
	context->count[0] = 0ULL;
	context->count[1] = 0ULL;

    /* SHA512 initialization constants */
	context->state[0] = 0x6a09e667f3bcc908ULL;
	context->state[1] = 0xbb67ae8584caa73bULL;
	context->state[2] = 0x3c6ef372fe94f82bULL;
	context->state[3] = 0xa54ff53a5f1d36f1ULL;
	context->state[4] = 0x510e527fade682d1ULL;
	context->state[5] = 0x9b05688c2b3e6c1fULL;
	context->state[6] = 0x1f83d9abfb41bd6bULL;
	context->state[7] = 0x5be0cd19137e2179ULL;
}


void SHA512Update(SHA512_CTX *context,unsigned char *input, uint64_t inputlen)
{
	uint64_t i = 0,index = 0,partlen = 0;

    /* Compute number of bytes mod 64 */
	index = (context->count[0] >> 3) & 0x7F;
	partlen = 128 - index; 

	context->count[0] += inputlen << 3;
	if(context->count[0] < (inputlen << 3)) {
		context->count[1]++;
	}

	context->count[1] += inputlen >> 61;


	if(inputlen >= partlen) {
		memcpy(&context->buffer[index],input,partlen);
    
		SHA512Transform(context->state,context->buffer);
		for(i = partlen;i+128 <= inputlen;i+=128) {
			SHA512Transform(context->state,&input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&context->buffer[index],&input[i],inputlen-i);
}

/* Add padding and return the message digest. */
void SHA512Final(SHA512_CTX *context,unsigned char digest[SHA512_DIGEST_LENGTH]) {
    int i;
	uint64_t index = 0,padlen = 0;
	unsigned char bits[16];
	index = (context->count[0] >> 3) & 0x7F;
	padlen = (index < 112)?(112-index):(240-index);
    
    
    //高位在前
    PUT_UINT64(&bits[0], context->count[1]);
    PUT_UINT64(&bits[8], context->count[0]);

	SHA512Update(context,PADDING,(uint64_t)padlen);
	SHA512Update(context,bits,16);

    for (i = 0; i < 8; i ++) {
        PUT_UINT64(&digest[i * 8], context->state[i]);
    }

	memset(context, 0x00, sizeof(SHA512_CTX));
}



#ifdef __SHA512_TEST__
/* static const struct {
 *     char *msg;
 *     unsigned char hash[64];
 * } tests[] = {
 *   { "abc",
 *    { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
 *      0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
 *      0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
 *      0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
 *      0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
 *      0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
 *      0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
 *      0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
 *   },
 *   { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
 *    { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
 *      0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
 *      0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
 *      0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
 *      0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
 *      0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
 *      0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
 *      0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
 *   },
 * };
 * 
 */ 

 /*
 gcc -Wall -D__SHA512_TEST__ sha512.c
 **/
 #include <stdio.h>
 int main()
 {
     int i, j;
     unsigned char SHA512_hash[SHA512_DIGEST_LENGTH];
     char *stra[] = {
         "",
         "a",
        "abc",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        NULL
    };
    
    char ch = 0xEF;

	SHA512_CTX SHA512_ctx;

    printf("\n=========================\n");
    printf("SHA1 (\"\") = da39a3ee5e6b4b0d3255bfef95601890afd80709\n");
    printf("SHA512 (\"a\")   = 1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75\n");
    printf("SHA512 (\"abc\") = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f\n");

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
        memset(SHA512_hash, 0x00, sizeof(SHA512_hash));

        SHA512Init(&SHA512_ctx);
	    SHA512Update(&SHA512_ctx, (unsigned char *)stra[i], (uint64_t)strlen(stra[i]));
	    SHA512Final(&SHA512_ctx, SHA512_hash);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));
        printf("SHA512(\"%s\")=\n", stra[i]); 
        for (j = 0; j < sizeof(SHA512_hash); j ++) {
            printf("%02x", SHA512_hash[j]);
        } 
        printf("\n\n"); 
    }

    printf("\n"); 
    
    return 0;
}
#endif


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
