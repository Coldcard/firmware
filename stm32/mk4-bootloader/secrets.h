#pragma once
#include <stdint.h>

// This is what we're keeping secret... Kept in flash, written mostly once.
// field groups must be **64-bit** aligned so they can be written independently
typedef struct {
    // Pairing secret: picked once at factory when turned on
    // for the first time, along with most values here.
    //
    uint8_t  pairing_secret[32];
    uint8_t  pairing_secret_xor[32];
    uint64_t ae_serial_number[2];       // 9 bytes active
    uint8_t  bag_number[32];            // 32 bytes max, zero padded string

    uint8_t  otp_key[72];               // DELME
    uint8_t  otp_key_long[416];         // DELME
    uint8_t  hash_cache_secret[32];     // encryption for cached pin hash value
    uint8_t  padding1[8];     

    // SE2 items
    struct _se2_secrets_t {
        uint8_t  pairing[32];
        uint8_t  pubkey_A[64];
        uint8_t  romid[8];              // serial number for SE2 chip
        uint8_t  spare[24];
        uint8_t  tpin_key[32];          // hmac secret for tricky-pin hashing
        uint8_t  auth_pubkey[64];       // aka pubkey C (AUTH) in SE2, and privkey in SE1
    } se2;

    uint8_t  mcu_hmac_key[32];          // used in final HMAC over parts of seed secret key

    // Replaceable MCU keys; can be overwritten; use first non zero/ones value.
    struct _mcu_key_t {
        uint8_t  value[32];
    } mcu_keys[32];

    // ... plus lots more space ...
} rom_secrets_t;

// This area is defined in linker script as last page of boot loader flash.
#define rom_secrets         ((rom_secrets_t *)BL_NVROM_BASE)


typedef struct _se2_secrets_t se2_secrets_t;
typedef struct _mcu_key_t mcu_key_t;

// EOF
