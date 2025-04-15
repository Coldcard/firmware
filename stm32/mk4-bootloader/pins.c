/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * pins.c -- PIN codes and security issues
 *
 */
#include "pins.h"
#include "ae_config.h"
#include "se2.h"
#include <string.h>
#include "faster_sha256.h"
#include "delay.h"
#include "rng.h"
#include "verify.h"
#include "constant_time.h"
#include "storage.h"
#include "clocks.h"
#include "aes.h"
#include "psram.h"

// Number of iterations for KDF
#define KDF_ITER_WORDS      6           // about 1.4s (measured)
#define KDF_ITER_PIN        8          // about ? seconds (measured in-system)

// We try to keep at least this many PIN attempts available to legit users
// - challenge: comparitor resolution is only 32 units (5 LSB not implemented)
// - solution: adjust both the target and counter (upwards)
#define MAX_TARGET_ATTEMPTS     13

// Hash up a PIN for indicated purpose.
static void pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose);

// early setup
void pin_setup0(void)
{
    // Pick nonce for this power-up
    //
    // We want to block any cached PIN value from previous runs working 
    // after a reboot, so we include a non-secret nonce that is picked at
    // power up. Challenge is we don't have any non-volatile RAM space.
    // Ideally, this value would not be changable by mpy, but we don't have any of that.

    // Populate unused registers in CRC unit w/ some noise
    __HAL_RCC_CRC_CLK_ENABLE();

    CRC->INIT = rng_sample();
    CRC->POL = rng_sample();
}

// reboot_nonce()
//
    static inline void
reboot_nonce(SHA256_CTX *ctx)
{
    uint32_t    a = CRC->INIT;
    sha256_update(ctx, (const uint8_t *)&a, 4);

    a = CRC->POL;
    sha256_update(ctx, (const uint8_t *)&a, 4);
}

// pin_is_blank()
//
// Is a specific PIN defined already? Not safe to expose this directly to callers!
//
    static bool
pin_is_blank(uint8_t keynum)
{
    uint8_t blank[32] = {0};

    ae_reset_chip();
    ae_pair_unlock();

    // Passing this check with zeros, means PIN was blank.
    // Failure here means nothing (except not blank).
    int is_blank = (ae_checkmac_hard(keynum, blank) == 0);

    // CAUTION? We've unlocked something maybe, but it's blank, so...
    ae_reset_chip();

    return is_blank;
}

// is_main_pin()
//
// Do the checkmac thing using a PIN, and if it works, great.
//
    static bool
is_main_pin(const uint8_t digest[32])
{
    ae_reset_chip();
    ae_pair_unlock();

    return (ae_checkmac_hard(KEYNUM_main_pin, digest) == 0);
}


// pin_hash()
//
// Hash up a string of digits into 32-bytes of goodness.
//
    static void
pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose)
{
    ASSERT(pin_len <= MAX_PIN_LEN);

    if(pin_len == 0) {
        // zero-length PIN is considered the "blank" one: all zero
        memset(result, 0, 32);

        return;
    }

	SHA256_CTX ctx;
    sha256_init(&ctx);

    sha256_update(&ctx, rom_secrets->hash_cache_secret, 32);
    sha256_update(&ctx, (uint8_t *)&purpose, 4);
    sha256_update(&ctx, (uint8_t *)pin, pin_len);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);

    sha256_final(&ctx, result);

    // and run that thru SE2 as well
    se2_pin_hash(result, purpose);

    // and a second-sha256 on that, just in case.
    sha256_single(result, 32, result);
}

// pin_hash_attempt()
//
// Go from PIN to heavily hashed 32-byte value, suitable for testing against device.
//
    static int
pin_hash_attempt(const char *pin, int pin_len, uint8_t result[32])
{
    uint8_t tmp[32]; 

    if(pin_len == 0) {
        // zero len PIN is the "blank" value: all zeros, no hashing
        memset(result, 0, 32);

        return 0;
    }

    // quick local hashing
    pin_hash(pin, pin_len, tmp, PIN_PURPOSE_NORMAL);

    // do mega hashing
    int rv = ae_stretch_iter(tmp, result, KDF_ITER_PIN);
    if(rv) return EPIN_AE_FAIL;

    // CAUTION: at this point, we just read the value off the bus
    // in clear text. Don't use that value directly.
    memcpy(tmp, result, 32);
    ae_mixin_key(KEYNUM_pin_attempt, tmp, result);

    return 0;
}

// pin_cache_get_key()
//
    void
pin_cache_get_key(uint8_t key[32])
{
    // per-boot unique key.
	SHA256_CTX ctx;

    sha256_init(&ctx);
    reboot_nonce(&ctx);
    sha256_update(&ctx, rom_secrets->hash_cache_secret, 32);

    sha256_final(&ctx, key);
}

// pin_cache_save()
//
    static void
pin_cache_save(pinAttempt_t *args, const uint8_t digest[32])
{
    // encrypt w/ rom secret + SRAM seed value
    uint8_t     value[32];

    if(!check_all_zeros(digest, 32)) {
        pin_cache_get_key(value);
        xor_mixin(value, digest, 32);
    } else {
        memset(value, 0, 32);
    }

    ASSERT(args->magic_value == PA_MAGIC_V2);
    memcpy(args->cached_main_pin, value, 32);
}

// pin_cache_restore()
//
    static void
pin_cache_restore(const pinAttempt_t *args, uint8_t digest[32])
{
    // decrypt w/ rom secret + SRAM seed value

    ASSERT(args->magic_value == PA_MAGIC_V2);
    memcpy(digest, args->cached_main_pin, 32);

    if(!check_all_zeros(digest, 32)) {
        uint8_t     key[32];
        pin_cache_get_key(key);

        xor_mixin(digest, key, 32);
    }
}

// _make_trick_aes_key()
//
    static void
_make_trick_aes_key(const pinAttempt_t *args, uint8_t key[32])
{
    // key is args->private_state (4 bytes) + 28 bytes from hash_cache_secret
    memcpy(key, &args->private_state, sizeof(args->private_state));
    memcpy(key+4, rom_secrets->hash_cache_secret+4, sizeof(rom_secrets->hash_cache_secret)-4);

}

// get_is_trick()
//
    static bool
get_is_trick(const pinAttempt_t *args, trick_slot_t *slot)
{
    // read and "decrypt" our one flag bit
    // - optional: aes-decrypt some more details about the trick slot
    bool is_trick = ((args->private_state ^ rom_secrets->hash_cache_secret[0]) & 0x1);

    if(!slot || !is_trick) return is_trick;

    memset(slot, 0, sizeof(trick_slot_t));

    if(args->delay_required & TC_DELTA_MODE) {
        // in delta mode, we are using the cached_main_pin for real PIN (hash)
        // so we cannot restore details
        slot->tc_flags = args->delay_required;
        slot->tc_arg = 0;           // unknown
        slot->slot_num = -1;        // unknown
    } else {
        // read more detail from cache area
        // - also read up to 2 more slots of raw seed data needed.
        uint8_t     key[32];
        _make_trick_aes_key(args, key);


        STATIC_ASSERT(sizeof(args->cached_main_pin) == 32);
        STATIC_ASSERT(offsetof(trick_slot_t, tc_flags) < 32);
        STATIC_ASSERT(offsetof(trick_slot_t, tc_arg) < 32);
        STATIC_ASSERT(sizeof(trick_slot_t) >= 32);

        // decode first 32 bytes of trick slot info into place
        AES_CTX ctx;
        aes_init(&ctx);
        aes_add(&ctx, args->cached_main_pin, 32);
        aes_done(&ctx, (uint8_t *)slot, 32, key, NULL);

        if(slot->tc_flags & (TC_WORD_WALLET|TC_XPRV_WALLET)) {
            // read 1 or 2 data slots that immediately follow a trick PIN slot
            se2_read_trick_data(slot->slot_num, slot->tc_flags, slot->xdata);
        }
    }

    return true;;
}

// set_is_trick()
//
    static void
set_is_trick(pinAttempt_t *args, const trick_slot_t *slot)
{
    // Set and "encrypt" our one flag bit
    bool is_trick_pin = !!slot;

    args->private_state = ((rng_sample() & ~1) | is_trick_pin) ^ rom_secrets->hash_cache_secret[0];

    if(!slot) {
        args->delay_required = 0;
        args->delay_achieved = 0;

        return;
    }

    // Hints for other mpy firmware to implement more trick features
    // impt detail: 
    // - duress wallet case, and many others will still read as zero here.
    // - mpy *does* need to know about TC_DELTA_MODE case, but not PIN digit-details
    args->delay_required = (slot->tc_flags & ~TC_HIDDEN_MASK);

    if(slot->tc_flags & TC_DELTA_MODE) {
        args->delay_achieved = 0;

        return;
    }

    args->delay_achieved = slot->tc_arg;

    // save more detail into cache area, for our use only
    uint8_t     key[32];
    _make_trick_aes_key(args, key);

    // capture first 32 bytes of slot info
    AES_CTX ctx;
    aes_init(&ctx);
    aes_add(&ctx, (uint8_t *)slot, 32);
    aes_done(&ctx, args->cached_main_pin, 32, key, NULL);
}

// pin_prefix_words()
//
// Look up some bits... do HMAC(words secret) and return some LSB's
//
// CAUTIONS: 
// - rate-limited by the chip, since it takes many iterations of HMAC(key we dont have)
// - hash generated is shown on bus (but further hashing happens after that)
//
    int
pin_prefix_words(const char *pin_prefix, int prefix_len, uint32_t *result)
{
    uint8_t     tmp[32];
    uint8_t     digest[32];

    // hash it up, a little
    pin_hash(pin_prefix, prefix_len, tmp, PIN_PURPOSE_WORDS);

    // Using 608a, we can do key stretching to get good built-in delays
    ae_setup();

    int rv = ae_stretch_iter(tmp, digest, KDF_ITER_WORDS);

    ae_reset_chip();
	if(rv) return -1;

    // take just 32 bits of that (only 22 bits shown to user)
    memcpy(result, digest, 4);

    return 0;
}

// _hmac_attempt()
//
// Maybe should be proper HMAC from fips std? Can be changed later.
//
    static void
_hmac_attempt(const pinAttempt_t *args, uint8_t result[32])
{
	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    reboot_nonce(&ctx);
    sha256_update(&ctx, (uint8_t *)args, offsetof(pinAttempt_t, hmac));

    if(args->magic_value == PA_MAGIC_V2) {
        sha256_update(&ctx, (uint8_t *)args->cached_main_pin,
                                msizeof(pinAttempt_t, cached_main_pin));
    }

    sha256_final(&ctx, result);

    // and a second-sha256 on that, just in case.
    sha256_single(result, 32, result);
}

// _validate_attempt()
//
    static int
_validate_attempt(const pinAttempt_t *args, bool first_time)
{
    if(first_time) {
        // no hmac needed for setup call
    } else {
        // if hmac is defined, better be right.
        uint8_t     actual[32];

        _hmac_attempt(args, actual);

        if(!check_equal(actual, args->hmac, 32)) {
            // hmac is wrong?
            return EPIN_HMAC_FAIL;
        }
    }

    // check fields.
    if(args->magic_value == PA_MAGIC_V2) {
        // ok
    } else {
        return EPIN_BAD_MAGIC;
    }

    // check fields
    if(args->pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if(args->old_pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if(args->new_pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if((args->change_flags & CHANGE__MASK) != args->change_flags) return EPIN_RANGE_ERR;

    if((args->is_secondary & 0x1) != args->is_secondary) return EPIN_RANGE_ERR;
        
    return 0;
}

// _sign_attempt()
//
// Provide our "signature" validating struct contents as coming from us.
//
    static void
_sign_attempt(pinAttempt_t *args)
{
    _hmac_attempt(args, args->hmac);
}

// _read_slot_as_counter()
//
    static int
_read_slot_as_counter(uint8_t slot, uint32_t *dest)
{
    // Read (typically a) counter value held in a dataslot.
    // Important that this be authenticated.
    //
    // - using first 32-bits only, others will be zero/ignored
    // - but need to read whole thing for the digest check

    uint32_t padded[32/4] = { 0 };
    ae_pair_unlock();
    if(ae_read_data_slot(slot, (uint8_t *)padded, 32)) return -1;

    uint8_t tempkey[32];
    ae_pair_unlock();
    if(ae_gendig_slot(slot, (const uint8_t *)padded, tempkey)) return -1;

    if(!ae_is_correct_tempkey(tempkey)) fatal_mitm();

    *dest = padded[0];

    return 0;
}


// get_last_success()
//
// Read state about previous attempt(s) from AE. Calculate number of failures,
// and how many attempts are left. The need for verifing the values from AE is
// not really so strong with the 608, since it's all enforced on that side, but
// we'll do it anyway.
//
    static int __attribute__ ((noinline))
get_last_success(pinAttempt_t *args)
{
    const int slot = KEYNUM_lastgood;

    ae_pair_unlock();

    // Read counter value of last-good login. Important that this be authenticated.
    // - using first 32-bits only, others will be zero
    uint32_t padded[32/4] = { 0 };
    if(ae_read_data_slot(slot, (uint8_t *)padded, 32)) return -1;

    uint8_t tempkey[32];
    ae_pair_unlock();
    if(ae_gendig_slot(slot, (const uint8_t *)padded, tempkey)) return -1;

    if(!ae_is_correct_tempkey(tempkey)) fatal_mitm();

    // Read two values from data slots
    uint32_t lastgood=0, match_count=0, counter=0;
    if(_read_slot_as_counter(KEYNUM_lastgood, &lastgood)) return -1;
    if(_read_slot_as_counter(KEYNUM_match_count, &match_count)) return -1;

    // Read the monotonically-increasing counter
    if(ae_get_counter(&counter, 0)) return -1;

    if(lastgood > counter) {
        // monkey business, but impossible, right?!
        args->num_fails = 99;
    } else {
        args->num_fails = counter - lastgood;
    }

    // NOTE: 5LSB of match_count should be stored as zero.
    match_count &= ~31;
    if(counter < match_count) {
        // typical case: some number of attempts left before death
        args->attempts_left = match_count - counter;
    } else if(counter >= match_count) {
        // we're a brick now, but maybe say that nicer to customer
        args->attempts_left = 0;
    }

    return 0;
}

// warmup_ae()
//
    static int
warmup_ae(void)
{
    ae_setup();

    for(int retry=0; retry<5; retry++) {
        if(!ae_probe()) break;
    }

    if(ae_pair_unlock()) return -1;

    // reset watchdog timer
    ae_keep_alive();

    return 0;
}

// calc_delay_required()
//
    uint32_t
calc_delay_required(int num_fails)
{
    // With the 608a, we let the slow KDF and the auto counter incr
    // protect against rate limiting... no need to do our own.
    return 0;
}

// pin_setup_attempt()
//
// Get number of failed attempts on a PIN, since last success. Calculate
// required delay, and setup initial struct for later attempts.
//
    int
pin_setup_attempt(pinAttempt_t *args)
{
    STATIC_ASSERT(sizeof(pinAttempt_t) == PIN_ATTEMPT_SIZE_V2);

    int rv = _validate_attempt(args, true);
    if(rv) return rv;

    // NOTE: Can only attempt primary pin. If it happens to
    // match a trick PIN, then perhaps something happens.

    if(args->is_secondary) {
        // secondary PIN feature has been removed
        return EPIN_PRIMARY_ONLY;
    }

    // wipe most of struct, keep only what we expect and want!
    // - old firmware wrote zero to magic before this point, and so we set it here

    char    pin_copy[MAX_PIN_LEN];
    int     pin_len = args->pin_len;
    memcpy(pin_copy, args->pin, pin_len);

    memset(args, 0, PIN_ATTEMPT_SIZE_V2);

    args->state_flags = 0;
    args->magic_value = PA_MAGIC_V2;
    args->pin_len = pin_len;
    memcpy(args->pin, pin_copy, pin_len);

    // unlock the AE chip
    if(warmup_ae()) {
        return EPIN_I_AM_BRICK;
    }

    // read counters, and calc number of PIN attempts left
    if(get_last_success(args)) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    // delays now handled by chip and our KDF process directly
    args->delay_required = 0;
    args->delay_achieved = 0;

    // need to know if we are blank/unused device
    if(pin_is_blank(KEYNUM_main_pin)) {
        args->state_flags |= PA_SUCCESSFUL | PA_IS_BLANK;

        // We need to save this 'zero' value because it's encrypted, and/or might be 
        // un-initialized memory. 
        const uint8_t zeros[32] = {0};
        pin_cache_save(args, zeros);

        // need legit value in here, saying not a trick
        set_is_trick(args, NULL);
    }

    _sign_attempt(args);

    return 0;
}

// pin_delay()
//
// Delay for one time unit, and prove it. Doesn't check PIN value itself.
//
    int
pin_delay(pinAttempt_t *args)
{
    // not required since Mk2
    return 0;
}

// updates_for_good_login()
//
    static int
updates_for_good_login(uint8_t digest[32])
{
    // User got the main PIN right: update the attempt counters,
    // to document this (lastgood) and also bump the match counter if needed

    uint32_t count;
    int rv = ae_get_counter(&count, 0);
    if(rv) goto fail;

    // Challenge: Have to update both the counter, and the target match value because
    // no other way to have exact value.

    uint32_t mc = (count + MAX_TARGET_ATTEMPTS + 32) & ~31;
    ASSERT(mc >= count);

    int bump = (mc - MAX_TARGET_ATTEMPTS) - count;
    ASSERT(bump >= 1);
    ASSERT(bump <= 32);     // assuming MAX_TARGET_ATTEMPTS < 30

    // Would rather update the counter first, so that a hostile interruption can't increase
    // attempts (altho the attacker knows the pin at that point?!) .. but chip won't
    // let the counter go past the match value, so that has to be first.

    // set the new "match count"
    {   uint32_t    tmp[32/4] = {mc, mc} ;
        rv = ae_encrypted_write(KEYNUM_match_count, KEYNUM_main_pin, digest, (void *)tmp, 32);
        if(rv) goto fail;
    }

    // incr the counter a bunch to get to that-13
    uint32_t new_count = 0;
    rv = ae_add_counter(&new_count, 0, bump);
    if(rv) goto fail;

    ASSERT(new_count == count + bump);
    ASSERT(mc > new_count);

    // Update the "last good" counter
    {   uint32_t    tmp[32/4] = {new_count, 0 };
        rv = ae_encrypted_write(KEYNUM_lastgood, KEYNUM_main_pin, digest, (void *)tmp, 32);
        if(rv) goto fail;
    }

    // NOTE: Some or all of the above writes could be blocked (trashed) by an
    // active MitM attacker, but that would be pointless since these are authenticated
    // writes, which have a MAC. They can't change the written value, due to the MAC, so
    // all they can do is block the write, and not control it's value. Therefore, they will
    // just be reducing attempts.

    return 0;

fail:
    ae_reset_chip();
    return EPIN_AE_FAIL;
}

// apply_pin_delta()
//
    static void
apply_pin_delta(char *pin, int pin_len, uint16_t replacement, char *tmp_pin)
{
    // Starting with provided on pin as a string, change the last few digits
    // given to be replacement value which gives true pin.
    // - encoding: BCD with 0xf for unchanged
    
    memcpy(tmp_pin, pin, pin_len);
    tmp_pin[pin_len] = 0;

    char *p = &tmp_pin[pin_len-1];

    for(int i=0; i<4; i++, p--) {
        if(*p == '-') p--;

        int here = replacement & 0xf;
        replacement >>= 4;

        if((here >= 0) && (here <= 9)) {
            *p = '0' + here; 
        }
    }
}

// pin_login_attempt()
//
// Do the PIN check, and return a value. Or fail.
//
    int
pin_login_attempt(pinAttempt_t *args)
{
    bool deltamode = false;
    char tmp_pin[32];

    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if(args->state_flags & PA_SUCCESSFUL) {
        // already worked, or is blank
        return EPIN_WRONG_SUCCESS;
    }

    // Mk4: Check SE2 first to see if this is a "trick" pin.
    // - this call may have side-effects, like wiping keys, bricking, etc.
    trick_slot_t    slot;
    bool is_trick = se2_test_trick_pin(args->pin, args->pin_len, &slot, false);
    
    if(is_trick) {
        // They gave a trick PIN. Implement it.

        // Mark as success
        args->state_flags = PA_SUCCESSFUL;
        args->num_fails = 0;
        args->attempts_left = MAX_TARGET_ATTEMPTS;

        bool wipe = (slot.tc_flags & TC_WIPE) && !(slot.tc_flags & (TC_WORD_WALLET|TC_XPRV_WALLET));
        if(check_all_zeros(slot.xdata, 32) || wipe) {
            args->state_flags |= PA_ZERO_SECRET;
        }
            
        // this encodes one bit, and picks a nonce; also saves hint to mpy if appropriate
        // - encrypts and saves slot# and tc_flags as well for duress wallet cases
        // - but only 32 byte there, so store just the slot number and tc_flags
        set_is_trick(args, &slot);

        if(slot.tc_flags & TC_DELTA_MODE) {
            // Thug gave wrong PIN, but we are going to let them 
            // past (by calculating correct PIN, up to 4 digits different),
            // and the mpy firmware can do tricky stuff to protect funds
            // even though the private key is known at that point.
            deltamode = true;
            apply_pin_delta(args->pin, args->pin_len, slot.tc_arg, tmp_pin);

            goto real_login;
        }
        _sign_attempt(args);

        return 0;
    }

real_login:
    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // hash up the pin now, assuming we'll use it on main PIN
    uint8_t     digest[32];
    rv = pin_hash_attempt(deltamode ? tmp_pin : args->pin, args->pin_len, digest);
    if(rv) return EPIN_AE_FAIL;

    // It is not a "trick pin", so assume it's the real PIN, and register
    // as an attempt on that.
    if(!is_main_pin(digest)) {
        // PIN code is just wrong.
        // - nothing to update, since the chip's done it already
        // - but maybe there are consequences to a wrong pin
        se2_handle_bad_pin(args->num_fails + 1);

        return EPIN_AUTH_FAIL;
    }

    // change the various counters, since this worked
    rv = updates_for_good_login(digest);
    if(rv) return EPIN_AE_FAIL;

    // SUCCESS! "digest" holds a working value. Save it.
    pin_cache_save(args, digest);

    // ASIDE: even if the above was bypassed, the following code will
    // fail when it tries to read/update the corresponding slots in the SE

    // mark as success
    args->state_flags = PA_SUCCESSFUL;

    // these are constants, and user doesn't care because they got in... but consistency.
    args->num_fails = 0;
    args->attempts_left = MAX_TARGET_ATTEMPTS;

    // I used to always read the secret, since it's so hard to get to this point,
    // but now just indicating if zero or non-zero so that we don't contaminate the
    // caller w/ sensitive data that they may not want yet.
    {   uint8_t ts[AE_SECRET_LEN];

        rv = ae_encrypted_read(KEYNUM_secret, KEYNUM_main_pin, digest, ts, AE_SECRET_LEN);
        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }
        ae_reset_chip();

        // if mcu_key empty, then that's also "zero"
        bool mcu_key_valid;
        mcu_key_get(&mcu_key_valid);

        // new fresh system comes here comes w/ zeros (plaintext) in secret slot of SE1
        if(check_all_zeros(ts, AE_SECRET_LEN) || !mcu_key_valid) {
            args->state_flags |= PA_ZERO_SECRET;
        }
    }

    // indicate what features already enabled/non-blank
    //      args->state_flags |= (PA_HAS_DURESS | PA_HAS_BRICKME);
    // - mk3 and earlier set these flags, but that's obsolete now
    // - mk4 requires knowledge of the specific trick PIN flags/args (censored lightly)
    if(!deltamode) {
        set_is_trick(args, NULL);
    }

    _sign_attempt(args);

    return 0;
}

// keynum_for_secret()
//
// Mk4 supports additional secret storage: spares. Map to key number, or -1 if range error
//
    static int
keynum_for_secret(const pinAttempt_t *args)
{
    int which = (args->change_flags >> 8) & 0xf;

    switch(which) {
        case 0:
            return KEYNUM_secret;
        case 1:
            return KEYNUM_spare_1;
        case 2:
            return KEYNUM_spare_2;
        case 3:
            return KEYNUM_spare_3;

        default:
            return -1;
    }
}

// pin_check_logged_in()
//
// Verify we know the main PIN, but don't do anything with it.
//
    int
pin_check_logged_in(const pinAttempt_t *args, bool *is_trick)
{
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    if(get_is_trick(args, NULL)) {
        // they used a trick pin to get this far. Amuse them more.
        *is_trick = true;

        // should calibrate this, but smart money will just look at the bus
        delay_ms(10);
        rng_delay();
    } else {
        *is_trick = false;

        // check we know the right PIN
        uint8_t auth_digest[32]; 
        pin_cache_restore(args, auth_digest);

        ae_pair_unlock();
        int rv = ae_checkmac(KEYNUM_main_pin, auth_digest);
        if(rv) return EPIN_AUTH_FAIL;
    }

    return 0;
}

// pin_change()
//
// Change the PIN and/or the secret. (Must also know the previous value, or it must be blank)
//
    int
pin_change(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    if(args->state_flags & PA_IS_BLANK) {
        // if blank, must provide blank value
        if(args->pin_len) return EPIN_RANGE_ERR;
    }

    // Look at change flags.
    const uint32_t cf = args->change_flags;

    ASSERT(!args->is_secondary);
    if(cf & CHANGE_SECONDARY_WALLET_PIN) {
        // obsolete secondary support, can't support.
        return EPIN_BAD_REQUEST;
    }
    if(cf & (CHANGE_DURESS_PIN | CHANGE_DURESS_SECRET | CHANGE_BRICKME_PIN)) {
        // we need some new API for trick PIN lookup/changes. 
        return EPIN_BAD_REQUEST;
    }
    if(!(cf & (CHANGE_WALLET_PIN | CHANGE_SECRET))) {
        return EPIN_RANGE_ERR;
    }

    // Must be here to do something.
    if(cf == 0) return EPIN_RANGE_ERR;

    // If they authorized w/ a trick PIN, new policy is to wipe ourselves if
    // they try to change PIN code or the secret.
    //  - it's hard to fake them out here, and they may be onto us.
    //  - this protects the seed, but does end the game somewhat
    //  - all trick PINs will still be in effect, and looks like random reset
    if(get_is_trick(args, NULL)) {
        // User is a thug.. kill secret and reboot w/o any notice
        fast_wipe();

        // NOT-REACHED
        return EPIN_BAD_REQUEST;
    }

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // No need to re-prove PIN knowledge.
    // If they tricked us to get to this point, doesn't matter as
    // below SE1 validates it all again.

    // Restore cached version of PIN digest: fast
    uint8_t required_digest[32]; 
    pin_cache_restore(args, required_digest);

    // Calculate new PIN hashed value: will be slow to do
    if(cf & CHANGE_WALLET_PIN) {
        uint8_t new_digest[32]; 
        rv = pin_hash_attempt(args->new_pin, args->new_pin_len, new_digest);
        if(rv) goto ae_fail;

        if(ae_encrypted_write(KEYNUM_main_pin, KEYNUM_main_pin, required_digest, new_digest, 32)) {
            goto ae_fail;
        }

        memcpy(required_digest, new_digest, 32);

        // main pin is changing; reset counter to zero (good login) and our cache
        pin_cache_save(args, new_digest);

        updates_for_good_login(new_digest);
    }

    // Recording new secret.
    // Note the required_digest might have just changed above.
    if(cf & CHANGE_SECRET) {
        // encrypt new secret... not simple!
        uint8_t     tmp[AE_SECRET_LEN];
        uint8_t     check[32];

        // what slot (key number) are updating? (probably: KEYNUM_secret)
        int         target_slot = keynum_for_secret(args);
        if(target_slot < 0) return EPIN_RANGE_ERR;

        se2_encrypt_secret(args->secret, AE_SECRET_LEN, 0, tmp, check, required_digest);

        // write into two slots
        if(ae_encrypted_write(target_slot, KEYNUM_main_pin,
                                        required_digest, tmp, AE_SECRET_LEN)){
            goto ae_fail;
        }
        if(ae_encrypted_write32(KEYNUM_check_secret, 0, KEYNUM_main_pin, required_digest, check)){
            goto ae_fail;
        }

        // update the zero-secret flag to be correct.
        if(cf & CHANGE_SECRET) {
            if(check_all_zeros(args->secret, AE_SECRET_LEN)) {
                args->state_flags |= PA_ZERO_SECRET;
            } else {
                args->state_flags &= ~PA_ZERO_SECRET;
            }
        }
    }

    ae_reset_chip();

    // need to pass back the (potentially) updated cache value and some flags.
    _sign_attempt(args);

    return 0;

ae_fail:
    ae_reset_chip();

    return EPIN_AE_FAIL;
}

// pin_fetch_secret()
//
// To encourage not keeping the secret in memory, a way to fetch it after you've already
// proven you know the PIN.
//
    int
pin_fetch_secret(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }
    if(args->change_flags & CHANGE_DURESS_SECRET) {
        // obsolete API: reading the duress secret from main PIN code (was never used)
        return EPIN_BAD_REQUEST;
    }

    // fetch the already-hashed pin
    // - no real need to re-prove PIN knowledge.
    // - if they tricked us, doesn't matter as below the SE validates it all again
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // determine if we should proceed under duress
    trick_slot_t slot;
    bool is_trick = get_is_trick(args, &slot);

    if(is_trick && !(slot.tc_flags & TC_DELTA_MODE)) {
        // emulate a 24-word wallet, or xprv based wallet
        // see stash.py for encoding details
        memset(args->secret, 0, AE_SECRET_LEN);

        if(slot.tc_flags & TC_WORD_WALLET) {
            if(check_all_zeros(&slot.xdata[16], 16)) {
                // 2nd half is zeros, must be 12-word wallet
                args->secret[0] = 0x80;         // 12 word phrase
                memcpy(&args->secret[1], slot.xdata, 16);
            } else {
                // normal 24-word seed
                args->secret[0] = 0x82;         // 24 word phrase
                memcpy(&args->secret[1], slot.xdata, 32);
            }
        } else if(slot.tc_flags & TC_XPRV_WALLET) {
            args->secret[0] = 0x01;         // XPRV mode
            memcpy(&args->secret[1], slot.xdata, 64);
        } else {
            // legit case: a blank duress wallet
            // (nothing to do, already zeros)
        }

        return 0;
    }

    // need to read a bunch now
    uint8_t    tmp[AE_SECRET_LEN];
    uint8_t    check[32];

    // default, zero: main secret, otherwise, the spares.
    int kn = keynum_for_secret(args);
    if(kn < 0) return EPIN_RANGE_ERR;

    // read out the secret that corresponds to pin
    // - seeing occasional comms failures here, so retry
    for(int retry=0; retry<3; retry++) {
        rv = ae_encrypted_read(kn, KEYNUM_main_pin, digest, tmp, AE_SECRET_LEN);
        if(rv) continue;

        rv = ae_encrypted_read32(KEYNUM_check_secret, 0, KEYNUM_main_pin, digest, check);
        if(rv) continue;

        break;
    }
    if(rv) goto fail;

    // decrypt via a complex process.
    bool is_valid;
    se2_decrypt_secret(args->secret, AE_SECRET_LEN, 0, tmp, check, digest, &is_valid);

    if(!is_valid) {
        // means the MCU key has been wiped; so effectively our secret is zeros
        // - also happens in case of any corruption with SE1/SE2 contents
        rv = 0;
        memset(args->secret, 0, AE_SECRET_LEN);

        if(!(args->state_flags & PA_ZERO_SECRET)) {
            // we didn't know yet that we are blank, update that
        mark_zero:
            args->state_flags |= PA_ZERO_SECRET;

            _sign_attempt(args);
        }
    } else {
        // even if valid, stored all-zeros are not expected at higher
        // levels, and it needs flag to be set correctly.
        if(!args->secret[0] && check_all_zeros(args->secret, AE_SECRET_LEN)) {
            goto mark_zero;
        }
    }

fail:
    ae_reset_chip();

    if(rv) return EPIN_AE_FAIL;

    return 0;
}

// pin_long_secret()
//
// Read or write the "long" secret: an additional 416 bytes.
//
// - new API so whole thing provided in one shot? encryption issues: provide
//   "dest" and all 416 bytes end up there (read case only).
//
    int
pin_long_secret(pinAttempt_t *args, uint8_t *dest)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    // determine if we should proceed under duress/in some trick way
    bool is_trick = get_is_trick(args, NULL);

    if(is_trick) {
        // Not supported in trick mode. Pretend it's all zeros. Accept all writes.
        memset(args->secret, 0, 32);
        if(dest) memset(dest, 0, AE_LONG_SECRET_LEN);

        return 0;
    }

    // which 32-byte section?
    STATIC_ASSERT(CHANGE_LS_OFFSET == 0xf00);
    int blk = (args->change_flags >> 8) & 0xf;
    if(blk > 13) return EPIN_RANGE_ERR;

    // fetch the already-hashed pin
    // - no real need to re-prove PIN knowledge.
    // - if they tricked us, doesn't matter as below the SE validates it all again
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // read/write exactly 32 bytes
    if(!(args->change_flags & CHANGE_SECRET)) {
        if(!dest) {
            uint8_t     tmp[32];

            rv = ae_encrypted_read32(KEYNUM_long_secret, blk, KEYNUM_main_pin, digest, tmp);
            if(rv) goto fail;

            bool is_valid;
            se2_decrypt_secret(args->secret, 32, blk*32, tmp, NULL, digest, &is_valid);
            if(!is_valid) {
                // no encryption key yet, so assume blank
                memset(args->secret, 0, 32);
                rv = 0;
            }
        } else {
            uint8_t *p = dest;
            for(blk=0; blk<13; blk++, p += 32) {
                rv = ae_encrypted_read32(KEYNUM_long_secret, blk, KEYNUM_main_pin, digest, p);
                if(rv) goto fail;
            }
            ASSERT(p == dest+AE_LONG_SECRET_LEN);

            // decrypt in one step (big time savings here)
            bool is_valid;
            se2_decrypt_secret(dest, AE_LONG_SECRET_LEN, 0, dest, NULL, digest, &is_valid);
            if(!is_valid) {
                // no encryption key yet, so assume blank
                memset(dest, 0, AE_LONG_SECRET_LEN);
                rv = 0;
            }
        }
    } else {
        // write case, does not update check
        uint8_t tmp[32] = {0};

        if(se2_encrypt_secret(args->secret, 32, blk*32, tmp, NULL, digest)) {
            // can happen if secret not set yet, can't work since we can't
            // write the check value.
            goto se2_fail;
        }

        rv = ae_encrypted_write32(KEYNUM_long_secret, blk, KEYNUM_main_pin, digest, tmp);
    }

fail:
    ae_reset_chip();

    if(rv) return EPIN_AE_FAIL;

    return 0;

se2_fail:
    ae_reset_chip();

    return EPIN_SE2_FAIL;
}

// pin_firmware_greenlight()
//
// Record current flash checksum and make green light go on.
//
    int
pin_firmware_greenlight(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    if(args->is_secondary) {
        // only main PIN holder can do this
        return EPIN_PRIMARY_ONLY;
    }

    // load existing PIN's hash
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // step 1: calc the value to use
    uint8_t fw_check[32], world_check[32];
    checksum_flash(fw_check, world_check, 0);

    // step 2: write it out to chip.
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // under duress, we can't fake this, but we go through the motions anyway
    if(!get_is_trick(args, NULL)) {
        rv = ae_encrypted_write(KEYNUM_firmware, KEYNUM_main_pin, digest, world_check, 32);

        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }
    }

    // turn on light
    rv = ae_set_gpio_secure(world_check);
    if(rv) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    return 0;
}

// pin_firmware_upgrade()
//
// Update the system firmware via file in PSRAM. Arrange for 
// light to stay green through out process.
//
    int
pin_firmware_upgrade(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login
        return EPIN_WRONG_SUCCESS;
    }

    if(args->change_flags != CHANGE_FIRMWARE) {
        return EPIN_BAD_REQUEST;
    }

    // expecting start/length relative to psram start
    uint32_t *about = (uint32_t *)args->secret;
    uint32_t start = about[0];
    uint32_t len = about[1];

    if(len < 32768) return EPIN_RANGE_ERR;
    if(len > 2<<20) return EPIN_RANGE_ERR;
    if(start+len > PSRAM_SIZE) return EPIN_RANGE_ERR;

    const uint8_t *data = (const uint8_t *)PSRAM_BASE+start;

    // verify a firmware image that's in RAM, and calc its digest
    // - also applies watermark policy, etc
    uint8_t world_check[32];
    bool ok = verify_firmware_in_ram(data, len, world_check);
    if(!ok) {
        return EPIN_AUTH_FAIL;
    }

    // under duress, we can't fake this, so kill ourselves.
    if(get_is_trick(args, NULL)) {
        // User is a thug.. kill secret and reboot w/o any notice
        fast_wipe();

        // NOT-REACHED
        return EPIN_BAD_REQUEST;
    }

    // load existing PIN's hash
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // step 1: calc the value to use, see above
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // step 2: write it out to chip.
    rv = ae_encrypted_write(KEYNUM_firmware, KEYNUM_main_pin, digest, world_check, 32);
    if(rv) goto fail;

    // this turns on green light
    rv = ae_set_gpio_secure(world_check);
    if(rv) goto fail;

    // -- point of no return -- 

    // burn it, shows progress
    psram_do_upgrade(data, len);

    // done and reboot
    NVIC_SystemReset();

    return 0;

fail:
    ae_reset_chip();

    return EPIN_AE_FAIL;
}

// EOF
