/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

#define SHA1_DIGEST_LENGTH		20
#define SHA1_DIGEST_STRING_LENGTH	41

# ifdef  __cplusplus
extern "C" {
# endif

/* rfc3174 */        
/* SHA1 context */
typedef struct
{
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
}SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context,unsigned char *input,unsigned int inputlen);
void SHA1Final(SHA1_CTX *context,unsigned char digest[SHA1_DIGEST_LENGTH]);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef SHA1_H */

