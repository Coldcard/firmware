/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "basics.h"
#include "console.h"
#include "faster_sha256.h"
#include "stm32l4xx_hal.h"
#include <string.h>

// so we don't need stm32l4xx_hal_hash_ex.c
HAL_StatusTypeDef HAL_HASHEx_SHA256_Accmlt(HASH_HandleTypeDef *hhash, uint8_t *pInBuffer, uint32_t Size)
{
  return HASH_Accumulate(hhash, pInBuffer, Size,HASH_ALGOSELECTION_SHA256);
}

HAL_StatusTypeDef HAL_HASHEx_SHA256_Start(HASH_HandleTypeDef *hhash, uint8_t *pInBuffer, uint32_t Size, uint8_t* pOutBuffer, uint32_t Timeout)
{
  return HASH_Start(hhash, pInBuffer, Size, pOutBuffer, Timeout, HASH_ALGOSELECTION_SHA256);
}

HAL_StatusTypeDef HAL_HMACEx_SHA256_Start(HASH_HandleTypeDef *hhash, uint8_t *pInBuffer, uint32_t Size, uint8_t* pOutBuffer, uint32_t Timeout)
{
  return HMAC_Start(hhash, pInBuffer, Size, pOutBuffer, Timeout, HASH_ALGOSELECTION_SHA256);
}

void sha256_init(SHA256_CTX *ctx)
{
    memset(ctx, 0, sizeof(SHA256_CTX));

#if 1
    ctx->num_pending = 0;
    ctx->hh.Init.DataType = HASH_DATATYPE_8B;
    HAL_HASH_Init(&ctx->hh);
#else
    MODIFY_REG(HASH->CR, HASH_CR_DATATYPE, HASH_DATATYPE_8B);

    __HAL_HASH_RESET_MDMAT();

    MODIFY_REG(HASH->CR, HASH_CR_LKEY|HASH_CR_ALGO|HASH_CR_MODE|HASH_CR_INIT,
            HASH_ALGOSELECTION_SHA256 | HASH_CR_INIT);
#endif
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
#if 1
            rv = HAL_HASHEx_SHA256_Accumulate(&ctx->hh, ctx->pending, 4);
            ASSERT(rv == HAL_OK);
#else
            HASH->DIN = *(uint32_t*)&ctx->pending;
#endif
            ctx->num_pending = 0;
        }
    }

    // write full blocks
    uint32_t blocks = len / 4;
    if(blocks) {
#if 1
        rv = HAL_HASHEx_SHA256_Accumulate(&ctx->hh, (uint8_t *)data, blocks*4);
        ASSERT(rv == HAL_OK);
#else
        for(int i=0; i<blocks*4; i++) {
            uint32_t    tmp;
            memcpy(&tmp, data, 4);
            HASH->DIN = tmp;
        }
#endif
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
#if 1
    HAL_StatusTypeDef rv = HAL_HASHEx_SHA256_Start(&ctx->hh,
                                ctx->pending, ctx->num_pending, digest, HAL_MAX_DELAY);
    ASSERT(rv == HAL_OK);
#else
    if(ctx->num_pending) {
        MODIFY_REG(HASH->STR, HASH_STR_NBLW, ctx->num_pending);
        HASH->DIN = *(uint32_t*)&ctx->pending;
    }

    __HAL_HASH_START_DIGEST();

    while(__HAL_HASH_GET_FLAG(HASH_FLAG_DCIS) == RESET) {
    }


    // Read out the message digest
    uint8_t     *out = digest;
    uint32_t    tmp;

    tmp = __REV(HASH->HR[0]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH->HR[1]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH->HR[2]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH->HR[3]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH->HR[4]);
    memcpy(out, &tmp, 4); out += 4;

    tmp = __REV(HASH_DIGEST->HR[5]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH_DIGEST->HR[6]);
    memcpy(out, &tmp, 4); out += 4;
    tmp = __REV(HASH_DIGEST->HR[7]);
    memcpy(out, &tmp, 4);
#endif
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

//
// HMAC-SHA256
//

// hmac_sha256_init()
//
    void
hmac_sha256_init(HMAC_CTX *ctx)
{
    memset(ctx, 0, sizeof(HMAC_CTX));
}

// hmac_sha256_update()
//
    void
hmac_sha256_update(HMAC_CTX *ctx, const uint8_t data[], uint32_t len)
{
    // simple append
    ASSERT(ctx->num_pending + len < sizeof(ctx->pending));

    memcpy(ctx->pending+ctx->num_pending, data, len);

    ctx->num_pending += len;
}

// hmac_sha256_final()
//
    void
hmac_sha256_final(HMAC_CTX *ctx, const uint8_t key[32], uint8_t digest[32])
{
    HASH_HandleTypeDef  hh = {0};

    hh.Init.DataType = HASH_DATATYPE_8B;
    hh.Init.pKey = (uint8_t *)key;      // const viol due to API dumbness
    hh.Init.KeySize = 32;

    HAL_HASH_Init(&hh);

    HAL_StatusTypeDef rv = HAL_HMACEx_SHA256_Start(&hh,
                                ctx->pending, ctx->num_pending, digest, HAL_MAX_DELAY);
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

    puts2("sha256 selftest: ");

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

    // HMAC
    //  from hashlib import sha256
    //  from hmac import HMAC
    //  >>> HMAC(key=bytes(range(32)), msg=b'abcd', digestmod=sha256).hexdigest()
    //  'ce5ab0733fe9b6f0767e841868c523e7db0c60d1fe6f276399fdee63d61d6c5b'

    {   HMAC_CTX c2;
        static const uint8_t key[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        static const uint8_t hexpect[32] = { 206, 90, 176, 115, 63, 233, 182, 240,
            118, 126, 132, 24, 104, 197, 35, 231, 219, 12, 96, 209, 254, 111, 39, 99,
            153, 253, 238, 99, 214, 29, 108, 91 };

        hmac_sha256_init(&c2);
        hmac_sha256_update(&c2, (uint8_t *)"abcd", 4);
        hmac_sha256_final(&c2, key, md);
        ASSERT(memcmp(md, hexpect, 32) == 0);

        // empty msg case
        //  >>> HMAC(key=bytes(range(32)), msg=b'', digestmod=sha256).hexdigest()
        //  'd38b42096d80f45f826b44a9d5607de72496a415d3f4a1a8c88e3bb9da8dc1cb'
        static const uint8_t hexpect2[32] = { 0xd3, 0x8b, 0x42, 0x9, 0x6d, 0x80, 0xf4, 0x5f,
            0x82, 0x6b, 0x44, 0xa9, 0xd5, 0x60, 0x7d, 0xe7, 0x24, 0x96, 0xa4, 0x15, 0xd3, 0xf4,
            0xa1, 0xa8, 0xc8, 0x8e, 0x3b, 0xb9, 0xda, 0x8d, 0xc1, 0xcb };
        hmac_sha256_init(&c2);
        hmac_sha256_final(&c2, key, md);
        ASSERT(memcmp(md, hexpect2, 32) == 0);
    }

    puts("PASS");
}
#endif

// EOF
