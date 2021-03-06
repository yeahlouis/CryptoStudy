/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#include <string.h>
#include "md5.h"


#define MD5_GET_UINT32(b) ( \
	((uint32_t)((b)[3] & 0xFF) << 24) | \
	((uint32_t)((b)[2] & 0xFF) << 16) | \
	((uint32_t)((b)[1] & 0xFF) <<  8) | \
	((uint32_t)((b)[0] & 0xFF)))

#define MD5_PUT_UINT32(dst, x)              \
    do {                                \
	    (dst)[0] = (x) & 0xFF;          \
	    (dst)[1] = ((x) >>  8) & 0xFF;  \
	    (dst)[2] = ((x) >> 16) & 0xFF;  \
	    (dst)[3] = ((x) >> 24) & 0xFF;  \
    } while (0)

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) \
	{ \
		a += F(b,c,d) + x + ac; \
		a = ROTATE_LEFT(a,s); \
		a += b; \
	}
#define GG(a,b,c,d,x,s,ac) \
	{ \
		a += G(b,c,d) + x + ac; \
		a = ROTATE_LEFT(a,s); \
		a += b; \
	}
#define HH(a,b,c,d,x,s,ac) \
	{ \
		a += H(b,c,d) + x + ac; \
		a = ROTATE_LEFT(a,s); \
		a += b; \
	}
#define II(a,b,c,d,x,s,ac) \
	{ \
		a += I(b,c,d) + x + ac; \
		a = ROTATE_LEFT(a,s); \
		a += b; \
	}


unsigned char PADDING[] = {
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

void MD5Transform(unsigned int state[4], unsigned char block[64]) {
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t x[16];

    int i;
	for (i = 0; i < 16; i++)
   	    x[i] = MD5_GET_UINT32(&block[4 * i]);

    /* Round 1 */
	FF(a, b, c, d, x[ 0],  7, 0xd76aa478);
	FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
	FF(c, d, a, b, x[ 2], 17, 0x242070db);
	FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
	FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);
	FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
	FF(c, d, a, b, x[ 6], 17, 0xa8304613);
	FF(b, c, d, a, x[ 7], 22, 0xfd469501);
	FF(a, b, c, d, x[ 8],  7, 0x698098d8);
	FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
	FF(c, d, a, b, x[10], 17, 0xffff5bb1);
	FF(b, c, d, a, x[11], 22, 0x895cd7be);
	FF(a, b, c, d, x[12],  7, 0x6b901122);
	FF(d, a, b, c, x[13], 12, 0xfd987193);
	FF(c, d, a, b, x[14], 17, 0xa679438e);
	FF(b, c, d, a, x[15], 22, 0x49b40821);

    /* Round 2 */
	GG(a, b, c, d, x[ 1],  5, 0xf61e2562);
	GG(d, a, b, c, x[ 6],  9, 0xc040b340);
	GG(c, d, a, b, x[11], 14, 0x265e5a51);
	GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
	GG(a, b, c, d, x[ 5],  5, 0xd62f105d);
	GG(d, a, b, c, x[10],  9, 0x02441453);
	GG(c, d, a, b, x[15], 14, 0xd8a1e681);
	GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
	GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);
	GG(d, a, b, c, x[14],  9, 0xc33707d6);
	GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
	GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
	GG(a, b, c, d, x[13],  5, 0xa9e3e905);
	GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
	GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
	GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    /* Round 3 */
	HH(a, b, c, d, x[ 5],  4, 0xfffa3942);
	HH(d, a, b, c, x[ 8], 11, 0x8771f681);
	HH(c, d, a, b, x[11], 16, 0x6d9d6122);
	HH(b, c, d, a, x[14], 23, 0xfde5380c);
	HH(a, b, c, d, x[ 1],  4, 0xa4beea44);
	HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
	HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
	HH(b, c, d, a, x[10], 23, 0xbebfbc70);
	HH(a, b, c, d, x[13],  4, 0x289b7ec6);
	HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
	HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
	HH(b, c, d, a, x[ 6], 23, 0x04881d05);
	HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);
	HH(d, a, b, c, x[12], 11, 0xe6db99e5);
	HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
	HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    /* Round 4 */
	II(a, b, c, d, x[ 0],  6, 0xf4292244);
	II(d, a, b, c, x[ 7], 10, 0x432aff97);
	II(c, d, a, b, x[14], 15, 0xab9423a7);
	II(b, c, d, a, x[ 5], 21, 0xfc93a039);
	II(a, b, c, d, x[12],  6, 0x655b59c3);
	II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
	II(c, d, a, b, x[10], 15, 0xffeff47d);
	II(b, c, d, a, x[ 1], 21, 0x85845dd1);
	II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
	II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
	II(c, d, a, b, x[ 6], 15, 0xa3014314);
	II(b, c, d, a, x[13], 21, 0x4e0811a1);
	II(a, b, c, d, x[ 4],  6, 0xf7537e82);
	II(d, a, b, c, x[11], 10, 0xbd3af235);
	II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
	II(b, c, d, a, x[ 9], 21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void MD5Init(MD5_CTX *context) {
	context->count[0] = 0;
	context->count[1] = 0;

    /* Load magic initialization constants. */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
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
		MD5Transform(context->state,context->buffer);
		for(i = partlen;i+64 <= inputlen;i+=64) {
			MD5Transform(context->state,&input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&context->buffer[index],&input[i],inputlen-i);
}


void MD5Final(MD5_CTX *context,unsigned char digest[16]) {
	unsigned int index = 0,padlen = 0;
	unsigned char bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
    
	//MD5Encode(bits,context->count,8);
    //低位在前
    MD5_PUT_UINT32(&bits[0], context->count[0]);
    MD5_PUT_UINT32(&bits[4], context->count[1]);

	MD5Update(context,PADDING,padlen);
	MD5Update(context,bits,8);

    MD5_PUT_UINT32(&digest[ 0], context->state[0]);
    MD5_PUT_UINT32(&digest[ 4], context->state[1]);
    MD5_PUT_UINT32(&digest[ 8], context->state[2]);
    MD5_PUT_UINT32(&digest[12], context->state[3]);
	//MD5Encode(digest,context->state,16);
}

#ifdef __MD5_TEST__
/*
gcc -Wall -D__MD5_TEST__ md5.c

https://www.rfc-editor.org/info/rfc1321
https://www.rfc-editor.org/rfc/rfc1321.txt

MD5 test suite:
MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
d174ab98d277d9f5a5611c2c9f419d9f
MD5 ("123456789012345678901234567890123456789012345678901234567890123456
78901234567890") = 57edf4a22be3c955ac49da2e2107b67a
**/
#include <stdio.h>
int main()
{
    int i;
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    char *str = "123456789012345678901234567890123456789012345678901234567890"
    "12345678901234567890";
	MD5_CTX md5_ctx;


    printf("\n=========================\n");
    printf("MD5 (\"\") = d41d8cd98f00b204e9800998ecf8427e\n");
    printf("MD5 (\"a\") = 0cc175b9c0f1b6a831c399e269772661\n");
    printf("MD5 (\"abc\") = 900150983cd24fb0d6963f7d28e17f72\n");
    printf("MD5 (\"message digest\") = f96b697d7cb7938d525a2f31aaf161d0\n");
    printf("MD5 (\"abcdefghijklmnopqrstuvwxyz\") = c3fcd3d76192e4007dfb496cca67e13b\n");
    printf("MD5 (\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\") =\n"
    "d174ab98d277d9f5a5611c2c9f419d9f\n");
    printf("MD5 (\"123456789012345678901234567890123456789012345678901234567890123456\n"
    "78901234567890\") = 57edf4a22be3c955ac49da2e2107b67a\n");
    printf("=========================\n");
    
    MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, (unsigned char *)str, strlen(str));
	MD5Final(&md5_ctx, md5_hash);
    
    printf("strlen(str) = [%zu]\n", strlen(str));

    printf("\nMD5(\"%s\")=\n", str); 
    for (i = 0; i < sizeof(md5_hash); i ++) {
        printf("%02x", md5_hash[i]);
    } 
    printf("\n\n"); 
    
    return 0;
}
#endif


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
