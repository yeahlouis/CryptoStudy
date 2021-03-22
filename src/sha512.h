/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	129

# ifdef  __cplusplus
extern "C" {
# endif

/* SHA512 context */
typedef struct
{
	uint64_t state[8];
	uint64_t count[2];
	unsigned char buffer[128];
}SHA512_CTX;

void SHA512Init(SHA512_CTX *context);
void SHA512Update(SHA512_CTX *context,unsigned char *input,uint64_t inputlen);
void SHA512Final(SHA512_CTX *context,unsigned char digest[SHA512_DIGEST_LENGTH]);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef SHA512_H */

