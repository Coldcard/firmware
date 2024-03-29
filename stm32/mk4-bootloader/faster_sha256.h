/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdint.h>
#include "stm32l4xx_hal.h"

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

// hardware state is the context, altho singleton
typedef struct {
    HASH_HandleTypeDef   hh;
    uint8_t   pending[4];       //  __attribute__((aligned(4)));
    uint8_t   num_pending;      // up to 3 bytes might be waiting from last call
} SHA256_CTX;

// compatible API
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], uint32_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t digest[32]);

// single-shot version (best)
void sha256_single(const uint8_t data[], uint32_t len, uint8_t digest[32]);

// HMAC-SHA256
typedef struct {
    uint8_t   pending[256];
    uint32_t  num_pending;
} HMAC_CTX;
void hmac_sha256_init(HMAC_CTX *ctx);
void hmac_sha256_update(HMAC_CTX *ctx, const uint8_t data[], uint32_t len);
void hmac_sha256_final(HMAC_CTX *ctx, const uint8_t key[32], uint8_t digest[32]);

#ifndef RELEASE
void sha256_selftest(void);
#endif

// EOF
