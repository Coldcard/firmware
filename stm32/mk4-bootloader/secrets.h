/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdint.h>

// This is what we're keeping secret... Kept in flash, written exactly once.
// field groups must be **64-bit=8byte** aligned so they can be written independently.
// - contents cannot be changed once unit is "bagged" and flash protection set
typedef struct {
    // Pairing secret: picked once at factory when turned on
    // for the first time, along with most values here.
    //
    uint8_t  pairing_secret[32];
    uint8_t  pairing_secret_xor[32];
    uint64_t ae_serial_number[2];       // 9 bytes active
    uint8_t  bag_number[32];            // 32 bytes max, zero padded string

    uint8_t  hash_cache_secret[32];     // encryption for cached pin hash value
    uint8_t  mcu_hmac_key[32];          // used in final HMAC over the parts of seed secret key

    // SE2 items
    struct _se2_secrets_t {
        uint8_t  pairing[32];
        uint8_t  pubkey_A[64];
        uint8_t  romid[8];              // serial number for SE2 chip
        uint8_t  spare[24];
        uint8_t  tpin_key[32];          // hmac secret for tricky-pin hashing
        uint8_t  auth_pubkey[64];       // aka pubkey C (AUTH) in SE2, and privkey in SE1
    } se2;

    // ... plus lots more unused space ...
} rom_secrets_t;

// Replaceable MCU keys; can be overwritten; use first non zero/ones value.
typedef struct _mcu_key_t {
    uint8_t  value[32];
} mcu_key_t;

// This area is defined in linker script as last 2 pages of boot loader flash.
#define rom_secrets         ((const rom_secrets_t *)BL_NVROM_BASE)

#define MCU_KEYS            ((mcu_key_t *)(BL_NVROM_BASE + 0x2000))
#define NUM_MCU_KEYS        (0x2000 / 32)

typedef struct _se2_secrets_t se2_secrets_t;

// EOF
