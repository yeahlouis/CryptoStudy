/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <string.h>
#include <netinet/in.h>	/* htonl() */
#include "sha1.h"



#define SHA1_GET_UINT32(b) ( \
	((uint32_t)((b)[3] & 0xFF) << 24) | \
	((uint32_t)((b)[2] & 0xFF) << 16) | \
	((uint32_t)((b)[1] & 0xFF) <<  8) | \
	((uint32_t)((b)[0] & 0xFF)))
	

#define SHA1_PUT_UINT32(dst, x)              \
    do {                                \
	    (dst)[0] = ((x) >> 24) & 0xFF;  \
	    (dst)[1] = ((x) >> 16) & 0xFF;  \
	    (dst)[2] = ((x) >>  8) & 0xFF;  \
	    (dst)[3] = (x) & 0xFF;          \
    } while (0)


#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (x[i] = htonl(x[i]))
#define blk(i) (x[i&15] = rol(x[(i+13)&15]^x[(i+8)&15] \
    ^x[(i+2)&15]^x[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


unsigned char PADDING[] = {
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA1Transform(unsigned int state[5], unsigned char block[64]) {
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t x[16];

    int i;
	for (i = 0; i < 16; i++)
   	    x[i] = SHA1_GET_UINT32(&block[4 * i]);

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
}


void SHA1Init(SHA1_CTX *context) {
	context->count[0] = 0;
	context->count[1] = 0;

    /* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
}


void SHA1Update(SHA1_CTX *context,unsigned char *input,unsigned int inputlen)
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
		SHA1Transform(context->state,context->buffer);
		for(i = partlen;i+64 <= inputlen;i+=64) {
			SHA1Transform(context->state,&input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&context->buffer[index],&input[i],inputlen-i);
}

/* Add padding and return the message digest. */
void SHA1Final(SHA1_CTX *context,unsigned char digest[SHA1_DIGEST_LENGTH]) {
	unsigned int index = 0,padlen = 0;
	unsigned char bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
    
    //int i;
    
    //高位在前
    SHA1_PUT_UINT32(&bits[0], context->count[1]);
    SHA1_PUT_UINT32(&bits[4], context->count[0]);

	SHA1Update(context,PADDING,padlen);
	SHA1Update(context,bits,8);

    SHA1_PUT_UINT32(&digest[ 0], context->state[0]);
    SHA1_PUT_UINT32(&digest[ 4], context->state[1]);
    SHA1_PUT_UINT32(&digest[ 8], context->state[2]);
    SHA1_PUT_UINT32(&digest[12], context->state[3]);
    SHA1_PUT_UINT32(&digest[16], context->state[4]);
}



#ifdef __SHA1_TEST__
/*
 * SHA-1 in C
 * Test Vectors 
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
 */
/*
gcc -Wall -D__SHA1_TEST__ sha1.c

https://www.rfc-editor.org/info/rfc3174
https://www.rfc-editor.org/rfc/rfc3174.txt

SHA1 test suite:
SHA1 ("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA1 ("a") = 0cc175b9c0f1b6a831c399e269772661
SHA1 ("abc") = 900150983cd24fb0d6963f7d28e17f72
SHA1 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
SHA1 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
SHA1 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
d174ab98d277d9f5a5611c2c9f419d9f
SHA1 ("123456789012345678901234567890123456789012345678901234567890123456
78901234567890") = 57edf4a22be3c955ac49da2e2107b67a
**/
#include <stdio.h>
int main()
{
    int i, j;
    unsigned char SHA1_hash[SHA1_DIGEST_LENGTH];
    //char *str = "123456789012345678901234567890123456789012345678901234567890"
    //"12345678901234567890";
    char *stra[] = {
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        NULL
    };
    
    char ch = 0xEF;

	SHA1_CTX SHA1_ctx;


    printf("\n=========================\n");
    printf("SHA1 (\"\") = da39a3ee5e6b4b0d3255bfef95601890afd80709\n");
    printf("SHA1 (\"a\") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8\n");
    printf("SHA1 (\"abc\") = a9993e364706816aba3e25717850c26c9cd0d89d\n");
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
        SHA1Init(&SHA1_ctx);
	    SHA1Update(&SHA1_ctx, (unsigned char *)stra[i], strlen(stra[i]));
	    SHA1Final(&SHA1_ctx, SHA1_hash);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));
        printf("SHA1(\"%s\")=\n", stra[i]); 
        for (j = 0; j < sizeof(SHA1_hash); j ++) {
            printf("%02x", SHA1_hash[j]);
        } 
        printf("\n\n"); 
    }

    printf("\n"); 
    
    return 0;
}
#endif


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
