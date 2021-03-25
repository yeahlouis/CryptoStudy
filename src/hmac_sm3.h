/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

#ifndef __HMAC_SM3_H__
#define __HMAC_SM3_H__

#include "sm3.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct {
    sm3_ctx ctx_inside;
    sm3_ctx ctx_outside;

    /* for hmac_reinit */
    sm3_ctx ctx_inside_reinit;
    sm3_ctx ctx_outside_reinit;

    unsigned char block_ipad[SM3_BLOCK_SIZE];
    unsigned char block_opad[SM3_BLOCK_SIZE];
} hmac_sm3_ctx;


void hmac_sm3_init(hmac_sm3_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void hmac_sm3_reinit(hmac_sm3_ctx *ctx);
void hmac_sm3_update(hmac_sm3_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void hmac_sm3_final(hmac_sm3_ctx *ctx, unsigned char *mac);

void hmac_sm3_sample(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned int mac_size);

void hmac_sm3_hexstr(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 char *mac_hexstr, unsigned int mac_hexstr_size);

# ifdef  __cplusplus
extern "C" {
# endif


#endif /* end of #ifndef __HMAC_SM3_H__ */

