/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef __HMAC_SHA256_H__
#define __HMAC_SHA256_H__

#include "sha256.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct {
    sha256_ctx ctx_inside;
    sha256_ctx ctx_outside;

    /* for hmac_reinit */
    sha256_ctx ctx_inside_reinit;
    sha256_ctx ctx_outside_reinit;

    unsigned char block_ipad[SHA256_BLOCK_SIZE];
    unsigned char block_opad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;


void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void hmac_sha256_reinit(hmac_sha256_ctx *ctx);
void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac);

void hmac_sha256_sample(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned int mac_size);

void hmac_sha256_hexstr(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 char *mac_hexstr, unsigned int mac_hexstr_size);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef __HMAC_SHA256_H__ */

