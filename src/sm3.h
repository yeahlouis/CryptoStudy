/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef __SM3_H_
#define __SM3_H_

#include <stdint.h>

#define SM3_DIGEST_SIZE (256 / 8)
#define SM3_BLOCK_SIZE  (512 / 8)
#define SM3_DIGEST_HEXSTR_LEN (SM3_DIGEST_SIZE * 2 + 1)

# ifdef  __cplusplus
extern "C" {
# endif

/* SM3 context */
typedef struct
{
	uint32_t state[8];
	uint32_t count[2];
	unsigned char buffer[64];
}sm3_ctx;

void sm3_init(sm3_ctx *ctx);
void sm3_update(sm3_ctx *ctx, const unsigned char *input, unsigned int inputlen);
void sm3_final(sm3_ctx *ctx, unsigned char digest[SM3_DIGEST_SIZE]);


void sm3_sample(const unsigned char *input, unsigned int len, unsigned char *digest, unsigned int digest_size);
void sm3_hexstr(const unsigned char *input, unsigned int len, char *hexstr, unsigned int hexstr_size);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef __SM3_H_ */

