/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdint.h>
#include "stm32l4xx_hal.h"

// NOTE: Always using AES-256-CTR mode.

#define AES_BLOCK_SIZE      16            // regardless of keysize

// hardware state is the context, altho singleton
typedef struct {
    CRYP_HandleTypeDef  hh;
    uint8_t             pending[512] __attribute__((aligned(4))); 
    int                 num_pending;
} AES_CTX;

void aes_init(AES_CTX *ctx);
void aes_add(AES_CTX *ctx, const uint8_t data_in[], uint32_t len);
void aes_done(AES_CTX *ctx, uint8_t data_out[], uint32_t len, const uint8_t key[32], const uint8_t nonce[AES_BLOCK_SIZE]);

#ifndef RELEASE
void aes_selftest(void);
#endif

// EOF
