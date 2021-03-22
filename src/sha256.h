/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	65

# ifdef  __cplusplus
extern "C" {
# endif

/* SHA256 context */
typedef struct
{
	uint32_t state[8];
	uint32_t count[2];
	unsigned char buffer[64];
}SHA256_CTX;

void SHA256Init(SHA256_CTX *context);
void SHA256Update(SHA256_CTX *context,unsigned char *input,unsigned int inputlen);
void SHA256Final(SHA256_CTX *context,unsigned char digest[SHA256_DIGEST_LENGTH]);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef SHA256_H */

