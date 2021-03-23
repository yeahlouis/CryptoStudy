/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_DIGEST_SIZE (256 / 8)
#define SHA256_BLOCK_SIZE  (512 / 8)
#define SHA256_DIGEST_HEXSTR_LEN (SHA256_DIGEST_SIZE * 2 + 1)

# ifdef  __cplusplus
extern "C" {
# endif

/* SHA256 context */
typedef struct
{
	uint32_t state[8];
	uint32_t count[2];
	unsigned char buffer[64];
}sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *input, unsigned int inputlen);
void sha256_final(sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_SIZE]);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef SHA256_H */

