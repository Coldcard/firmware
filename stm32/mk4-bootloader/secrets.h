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
    struct _se2_secrets {
        uint8_t  pairing[32];
        uint8_t  pubkey_A[64];
        uint8_t  romid[8];              // serial number for SE2 chip
        uint8_t  spare[24];
        uint8_t  tpin_key[32];          // hmac secret for tricky-pin hashing
        uint8_t  auth_pubkey[64];       // aka pubkey C (AUTH) in SE2, and privkey in SE1
    } se2;

    // replaceable MCU key; can be overwritten; use last one in series
    // - 64 bytes because of flash write alignment limitations
    uint8_t     mcu_key1[32];           // fixed key
    uint8_t     mcu_key2[32];           // fixed key
    struct _mcu_keys {
        uint8_t  key[64];
    } mcu_keys[12];

    // ... plus lots more space ...
} rom_secrets_t;

// This area is defined in linker script as last page of boot loader flash.
#define rom_secrets         ((rom_secrets_t *)BL_NVROM_BASE)


