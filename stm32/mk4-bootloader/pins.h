/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * pins.h -- everything to do with PIN's and their policies
 *
 */
#pragma once
#include "basics.h"
#include "ae.h"
#include "pins.h"

// We hash it like we don't care, but PIN code is expected to be
// just digits, no punctuation, and up to this many chars long.
// Using pin+len rather than c-strings. Use zero-length for "blank" or "undefined" pins.
//
#define MAX_PIN_LEN             32

// Number of bytes (per pin) we are keeping secret.
// ATECC[56]08A limitation/feature caps this at weird 72 byte value.
#define AE_SECRET_LEN           72

// .. but on 608a, we can use this one weird data slot with more space
#define AE_LONG_SECRET_LEN      416

// For change_flags field: choose one secret and/or one PIN only.
#define CHANGE_WALLET_PIN           0x001
#define CHANGE_DURESS_PIN           0x002
#define CHANGE_BRICKME_PIN          0x004
#define CHANGE_SECRET               0x008
#define CHANGE_DURESS_SECRET        0x010
#define CHANGE_SECONDARY_WALLET_PIN 0x020     // when used from main wallet only (obsolete)
#define CHANGE_FIRMWARE             0x040     // when providing firmware via PSRAM
#define CHANGE_LS_OFFSET            0xf00     // v2: which 32-byte part of long-secret to affect
#define CHANGE__MASK                0xf7f

// Magic value and/or version number.
#define PA_MAGIC_V1         0x2eaf6311          // before v3.0.0 of main firmware (508a, mk1/2)
#define PA_MAGIC_V2         0x2eaf6312

// For state_flags field: report only covers current wallet (primary vs. secondary)
#define PA_SUCCESSFUL         0x01
#define PA_IS_BLANK           0x02          // blank pin (empty/unset)
#define PA_HAS_DURESS         0x04          // obsolete
#define PA_HAS_BRICKME        0x08          // obsolete
#define PA_ZERO_SECRET        0x10          // no secret yet or is wiped

typedef struct {
    uint32_t    magic_value;            // = PA_MAGIC
    int         is_secondary;           // (bool) primary or secondary [obsolete]
    char        pin[MAX_PIN_LEN];       // value being attempted
    int         pin_len;                // valid length of pin
    uint32_t    delay_achieved;         // so far, how much time wasted? [obsolete: mk4=arg]
    uint32_t    delay_required;         // how much will be needed? [obsolete: mk4=masked flags]
    uint32_t    num_fails;              // for UI: number of fails PINs
    uint32_t    attempts_left;          // trys left until bricking
    uint32_t    state_flags;            // what things have been setup/enabled already
    uint32_t    private_state;          // some internal (encrypted) state
    uint8_t     hmac[32];               // my hmac over above, or zeros
    // remaining fields are return values, or optional args;
    int         change_flags;           // bitmask of what to do
    char        old_pin[MAX_PIN_LEN];   // (optional) old PIN value
    int         old_pin_len;            // (optional) valid length of old_pin, can be zero
    char        new_pin[MAX_PIN_LEN];   // (optional) new PIN value
    int         new_pin_len;            // (optional) valid length of new_pin, can be zero
    uint8_t     secret[AE_SECRET_LEN];  // secret to be changed / return value
    // may grow from here in future versions.
    uint8_t     cached_main_pin[32];    // iff they provided right pin already
} pinAttempt_t;

// For binary compatibility with Mark1/2 bootroms, the cached_main_pin is optional
#define PIN_ATTEMPT_SIZE_V1        (176+AE_SECRET_LEN)
#define PIN_ATTEMPT_SIZE_V2        (176+AE_SECRET_LEN+32)

// Errors codes
enum {
    EPIN_HMAC_FAIL          = -100,
    EPIN_HMAC_REQUIRED      = -101,
    EPIN_BAD_MAGIC          = -102,
    EPIN_RANGE_ERR          = -103,
    EPIN_BAD_REQUEST        = -104,     // bad change flags
    EPIN_I_AM_BRICK         = -105,     // chip has been bricked
    EPIN_AE_FAIL            = -106,     // low-level fails; retry ok
    EPIN_MUST_WAIT          = -107,     // you haven't waited long enough
    EPIN_PIN_REQUIRED       = -108,     // must be non-zero length
    EPIN_WRONG_SUCCESS      = -109,     // success field is not what is needs to be 
    EPIN_OLD_ATTEMPT        = -110,     // tried to recycle older attempt
    EPIN_AUTH_MISMATCH      = -111,     // need pin1 to change duress1, etc.
    EPIN_AUTH_FAIL          = -112,     // pin is wrong
    EPIN_OLD_AUTH_FAIL      = -113,     // existing pin is wrong (during change attempt)
    EPIN_PRIMARY_ONLY       = -114,     // only primary pin can change brickme
    EPIN_SE2_FAIL           = -115,     // (mk4) some issue w/ SE2
};

// Get number of failed attempts on a PIN, since last success. Calculate
// required delay, and setup initial struct for later attempts. Does not
// attempt the PIN or return secrets if right.
int pin_setup_attempt(pinAttempt_t *args);

// Delay for one time unit, and prove it. Doesn't check PIN value itself.
int pin_delay(pinAttempt_t *args);

// Do the PIN check, and return a value. Or fail.
int pin_login_attempt(pinAttempt_t *args);

// Verify we know the main PIN, but don't do anything
int pin_check_logged_in(const pinAttempt_t *args, bool *is_trick);

// Change the PIN and/or secrets (must also know the value, or it must be blank)
int pin_change(pinAttempt_t *args);

// To encourage not keeping the secret in memory, a way to fetch it after already prove you
// know the PIN right.
int pin_fetch_secret(pinAttempt_t *args);

// Record current flash checksum and make green light go on.
int pin_firmware_greenlight(pinAttempt_t *args);

// Return 32 bits of bits which are presistently mapped from pin code; for anti-phishing feature.
int pin_prefix_words(const char *pin_prefix, int prefix_len, uint32_t *result);

// Read/write the long secret. 32 bytes at a time, all read all at one if dest!=NULL
int pin_long_secret(pinAttempt_t *args, uint8_t *dest);

// Start firmware upgrade using data in PSRAM.
int pin_firmware_upgrade(pinAttempt_t *args);

// EOF
