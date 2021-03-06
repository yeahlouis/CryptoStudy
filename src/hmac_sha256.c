/*
 * Copyright (c) 2021 Louis Suen
 * Licensed under the MIT License. See the LICENSE file for the full text.
 */

/*
 * Included for memcpy & memset
 */
#include <string.h>
/*
 * Included for snprintf
 */
#include <stdio.h>

#include "hmac_sha256.h"

/**
 * HMAC_k(m) = H((k ^ opad), H((k ^ ipad), m))
 * pseudo-code:
 * function hmac(key, message)
 *	opad = [0x5c * blocksize]
 *	ipad = [0x36 * blocksize]
 *	if (length(key) > blocksize) then
 *		key = hash(key)
 *	end if
 *	for i from 0 to length(key) - 1 step 1
 *		ipad[i] = ipad[i] XOR key[i]
 *		opad[i] = opad[i] XOR key[i]
 *	end for
 *	return hash(opad || hash(ipad || message))
 * end function
 */

/* HMAC-SHA-256 functions */

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key,
                      unsigned int key_size)
{
    unsigned char key_tmp[SHA256_DIGEST_SIZE];
    int i;

#if 0
    if (key_size > SHA256_BLOCK_SIZE) {
        memset(&ctx->block_ipad, 0x00, sizeof(ctx->block_ipad));
        sha256_sample(key, key_size, key_tmp, sizeof(key_tmp));
        memcpy(&ctx->block_ipad, key_tmp, sizeof(key_tmp));
        memcpy(&ctx->block_opad, &ctx->block_ipad, sizeof(ctx->block_ipad));
    } else {
        memset(&ctx->block_ipad, 0x00, sizeof(ctx->block_ipad));
        memcpy(&ctx->block_ipad, key, key_size);
        memcpy(&ctx->block_opad, &ctx->block_ipad, sizeof(ctx->block_ipad));
        
    }

    //a ^ 0 = a 就相当于赋值
    for (i = 0; i < sizeof(ctx->block_ipad); i++) {
        ctx->block_ipad[i] ^= 0x36;
        ctx->block_opad[i] ^= 0x5c;
    }
#else
    unsigned int fill;
    unsigned int num;
    const unsigned char *key_used;

    if (key_size == SHA256_BLOCK_SIZE) {
        key_used = key;
        num = SHA256_BLOCK_SIZE;
    } else {
        if (key_size > SHA256_BLOCK_SIZE){
            num = SHA256_DIGEST_SIZE;
            sha256_sample(key, key_size, key_tmp, sizeof(key_tmp));
            key_used = key_tmp;
        } else { /* key_size > SHA256_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA256_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }
#endif

    sha256_init(&ctx->ctx_inside);
    sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);

    sha256_init(&ctx->ctx_outside);
    sha256_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA256_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha256_ctx));
}

void hmac_sha256_reinit(hmac_sha256_ctx *ctx)
{
    //ctx->block_ipad 和 ctx->block_opad 是不变的
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha256_ctx));
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message,
                        unsigned int message_len)
{
    sha256_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char mac[SHA256_DIGEST_SIZE])
{
    unsigned char digest_inside[SHA256_DIGEST_SIZE];

    sha256_final(&ctx->ctx_inside, digest_inside);
    sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->ctx_outside, mac);
}

void hmac_sha256_sample(const unsigned char *key, unsigned int key_size,
          const unsigned char *message, unsigned int message_len,
          unsigned char *mac, unsigned int mac_size)
{
    unsigned char mac_inside[SHA256_DIGEST_SIZE];
    hmac_sha256_ctx ctx;


    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, message, message_len);
    hmac_sha256_final(&ctx, mac_inside);
    memcpy(mac, mac_inside, mac_size);
}


void hmac_sha256_hexstr(const unsigned char *key, unsigned int key_size,
          const unsigned char *message, unsigned int message_len,
          char *mac_hexstr, unsigned int mac_hexstr_size)
{
    int i;
    unsigned char mac_inside[SHA256_DIGEST_SIZE];
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, message, message_len);
    hmac_sha256_final(&ctx, mac_inside);

    for (i = 0; i < sizeof(mac_inside) && mac_hexstr_size > (i * 2) + 1; i ++) {
        snprintf(mac_hexstr + (i * 2), mac_hexstr_size - (i * 2), "%02x", mac_inside[i]); 
    }
}

#ifdef __HMAC_SHA256_TEST__
/*
 * gcc -Wall -D__HMAC_SHA256_TEST__ hmac_sha256.c sha256.c
 */
#include <stdio.h>
#include <stdlib.h>
int main()
{
    int ret = EXIT_FAILURE;
    int i;
    char hash_str[SHA256_DIGEST_HEXSTR_LEN];
    const char *stra[] = {
        "",
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        "a",
        "3ecf5388e220da9e0f919485deb676d8bee3aec046a779353b463418511ee622",
        "abc",
        "2f02e24ae2e1fe880399f27600afa88364e6062bf9bbe114b32fa8f23d03608a",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "29dc3b24e96ab703b3cdad77288ad2d7e4c9129ab46558afe24e23431e436108",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "2ce14d787b67f396724f2e046073d2ce32e45bc7d66bb7ef955341beaeeebae3",
        NULL,
        NULL,
        NULL,
        NULL,
    };
    

    printf("+++++++++++++++++++++++++\n");
    
    printf("sizeof(stra)/sizeof(stra[0] = [%lu]\n", sizeof(stra) / sizeof(stra[0]));
    printf("sizeof(hash_str) = [%lu]\n", sizeof(hash_str));

    for (i = 0; i < sizeof(stra) / sizeof(stra[0]); i += 2) {
        if (NULL == stra[i]) {
            break;
        }
        hmac_sha256_hexstr((const unsigned char *)stra[i], strlen(stra[i]), (const unsigned char *)stra[i], strlen(stra[i]), hash_str, sizeof(hash_str));
        printf("\n--->i = [%d][%s]\n", i, stra[i]);
        printf("strlen(stra) = [%zu]\n", strlen(stra[i]));
        printf("HMAC_SHA256(\"%s\")=\n[%s]\n[%s]\n", stra[i], hash_str, stra[i + 1]);
        if (strcmp((const char *)hash_str, stra[i + 1]) == 0) {
            printf("--->success...\n");
        } else {
            printf("----failure!!!\n");
            printf("-------------------------\n\n");
            return (ret);
        }
    }

    printf("+++++++++++++++++++++++++\n");

    ret = EXIT_SUCCESS;
    
    return (ret);
}
#endif


/* vim:tw=78:ft=c:tabstop=4:expandtabs:shiftwidth=4 */
