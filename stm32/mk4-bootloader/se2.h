/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * se2.c -- Talk to DS28C36B chip which is our second secure element.
 *
 */
#pragma once
#include <stdint.h>

void se2_setup(void);
void se2_probe(void);           // crashes if problem
void se2_setup_config(void);
void se2_clear_volatile(void);  // not fast, and very visible on bus

#define NUM_TRICKS          14
#define TC_WIPE             0x8000
#define TC_BRICK            0x4000
#define TC_FAKE_OUT         0x2000
#define TC_WORD_WALLET      0x1000
#define TC_XPRV_WALLET      0x0800
#define TC_DELTA_MODE       0x0400
#define TC_REBOOT           0x0200
#define TC_RFU              0x0100
// other codes reserved for mpy, plus "tc_arg" field

// these flags are masked-out from mpy so even it can't tell they happened
// - not not deltamode, since mpy need to know
#define TC_HIDDEN_MASK      0xf800

typedef struct __PACKED {
    int         slot_num;           // or -1 if not found
    uint16_t    tc_flags;           // TC_* bitmask
    uint16_t    tc_arg;             // extra argument is stored for mpy usage (mostly)
    uint8_t     xdata[64];          // 32 or 64 bytes of stored entropy (seed words or xprv)
    char        pin[16];            // ascii
    int         pin_len;
    uint32_t    blank_slots;        // 1 indicates unused slot
    uint32_t    spare[8];           // RFU
} trick_slot_t;

// search if this PIN code should trigger a "trick"
// - if not in safety mode, the side-effect (brick, etc) will have happened before this returns
// - will always check all slots so bus traffic doesn't change based on result.
bool se2_test_trick_pin(const char *pin, int pin_len, trick_slot_t *found, bool safety_mode);

// Save trick setup, T if it fails; might be EPIN_ err code
int se2_save_trick(const trick_slot_t *config);

// read 1 or 2 data slots that immediately follow a trick PIN slot
void se2_read_trick_data(int slot_num, uint16_t tc_flags, uint8_t data[64]);

// wipe all the trick PIN's and their side effects
void se2_clear_tricks(void);

// do our hashing of a possible PIN code
void trick_pin_hash(const char *pin, int pin_len, uint8_t tpin_hash[32]);

// record and enable an ECC pubkey for SE1+SE2 joining purposes
void se2_save_auth_pubkey(const uint8_t pubkey[64]);

// call if a completely unknown PIN is provided
void se2_handle_bad_pin(int num_fails);

// hash up a PIN code for login attempt: to tie it into SE2's contents
void se2_pin_hash(uint8_t digest_io[32], uint32_t purpose);

#if 0
// secp256r1 curve functions.
bool p256_verify(const uint8_t pubkey[64], const uint8_t digest[32], const uint8_t signature[64]);
void p256_gen_keypair(uint8_t privkey[32], uint8_t pubkey[64]);
void p256_sign(const uint8_t privkey[32], const uint8_t digest[32], uint8_t signature[64]);
void ps256_ecdh(const uint8_t pubkey[64], const uint8_t privkey[32], uint8_t result[32]);
#endif

// Encrypt the main wallet secret.
// - will pick a new mcu_key if was blank before (during encrypt)
// - during decrypt if we are missing MCU key, will be invalid, consider it zeros
// - you'll need the hash of the main PIN
// - if check_value not provided, won't be validated/produced.

bool se2_encrypt_secret(const uint8_t secret[], int secret_len, int offset,
        uint8_t main_slot[], uint8_t *check_value,
        const uint8_t pin_digest[32]);

void se2_decrypt_secret(uint8_t secret[], int secret_len, int offset,
        const uint8_t main_slot[], const uint8_t *check_value,
        const uint8_t pin_digest[32], bool *is_valid);

// Read some random bytes, which we know cannot be MitM'ed.
void se2_read_rng(uint8_t value[8]);

// EOF
