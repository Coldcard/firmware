/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "basics.h"
#include "console.h"
#include "faster_sha256.h"
#include "stm32l4xx_hal.h"
#include <string.h>

void sha256_init(SHA256_CTX *ctx)
{
    memset(ctx, 0, sizeof(SHA256_CTX));

    ctx->num_pending = 0;
    ctx->hh.Init.DataType = HASH_DATATYPE_8B;

    HAL_HASH_Init(&ctx->hh);
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], uint32_t len)
{
    HAL_StatusTypeDef rv;

    // clear out any pending bytes
    if(ctx->num_pending + len >= 4) {
        while(ctx->num_pending != 4) {
            ctx->pending[ctx->num_pending++] = *data;
            data += 1;
            len -= 1;
            if(!len) break;
        }
        if(ctx->num_pending == 4) {
            rv = HAL_HASHEx_SHA256_Accumulate(&ctx->hh, ctx->pending, 4);
            ASSERT(rv == HAL_OK);
            ctx->num_pending = 0;
        }
    }

    // write full blocks
    uint32_t blocks = len / 4;
    if(blocks) {
        rv = HAL_HASHEx_SHA256_Accumulate(&ctx->hh, (uint8_t *)data, blocks*4);
        ASSERT(rv == HAL_OK);
        len -= blocks*4;
        data += blocks*4;
    }

    // save runt for later
    ASSERT(len <= 3);
    while(len) {
        ctx->pending[ctx->num_pending++] = *data;
        data++;
        len--;
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[32])
{
    // Do final 0-3 bytes, pad and return digest.
    HAL_StatusTypeDef rv = HAL_HASHEx_SHA256_Start(&ctx->hh,
                                ctx->pending, ctx->num_pending, digest, HAL_MAX_DELAY);

    ASSERT(rv == HAL_OK);
}

// sha256_single()
//
// single-shot version (best)
//
    void
sha256_single(const uint8_t data[], uint32_t len, uint8_t digest[32])
{
    HASH_HandleTypeDef  hh = {0};

    hh.Init.DataType = HASH_DATATYPE_8B;

    HAL_HASH_Init(&hh);

    // It's called "Start" but it handles the runt packet, so really can only
    // be used once at end of message, or for whole message.
    HAL_StatusTypeDef rv = HAL_HASHEx_SHA256_Start(&hh, (uint8_t *)data, len,
                                                    digest, HAL_MAX_DELAY);
    ASSERT(rv == HAL_OK);
}


#ifndef RELEASE
//#pragma GCC push_options
//#pragma GCC optimize ("O0")


    void
sha256_selftest(void) 
{
    SHA256_CTX      ctx;
    uint8_t         md[32], md2[32];

    puts("sha256 selftest start");

    sha256_single((uint8_t *)"a", 1, md);
    ASSERT(md[0] == 0xca);
    ASSERT(md[31] == 0xbb);

    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t *)"a", 1);
    sha256_final(&ctx, md2);
    ASSERT(memcmp(md, md2, 32) == 0);

    const uint8_t     *pat = (const uint8_t *)BL_FLASH_BASE;

    for(int len=1; len<96; len+=17) {
        sha256_single(pat, len, md);

        for(int st=1; st<len; st++) {
#if 0
            puts2("st = ");
            puthex2(st);
            puts2(" len = ");
            puthex2(len);
#endif

            sha256_init(&ctx);
            sha256_update(&ctx, pat, st);
            sha256_update(&ctx, pat+st, len-st);
            sha256_final(&ctx, md2);

            ASSERT(memcmp(md, md2, 32) == 0);
//            puts(" ... PASS");
        }
    }

    puts("sha256 selftest PASS");
}

#endif

// EOF
