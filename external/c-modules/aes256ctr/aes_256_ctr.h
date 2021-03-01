#pragma once
#include <stdint.h>

typedef struct param {
    uint8_t nonce[12];
    uint8_t ctr[4];
    uint8_t rk[15*16];
} param;

extern void AES_256_keyschedule(const uint8_t *key, uint8_t *);
extern void AES_256_encrypt_ctr(param const *, const uint8_t *, uint8_t *, uint32_t);

