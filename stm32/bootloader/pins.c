/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 *
 * pins.c -- PIN codes and security issues
 *
 */
#include "pins.h"
#include "ae_config.h"
#include <string.h>
#include "sha256.h"
#include "delay.h"
#include "rng.h"
#include "verify.h"
#include "constant_time.h"
#include "storage.h"
#include "clocks.h"

// Number of iterations for KDF
#define KDF_ITER_WORDS      12
#define KDF_ITER_PIN        8          // about ? seconds (measured in-system)

// We try to keep at least this many PIN attempts available to legit users
// - challenge: comparitor resolution is only 32 units (5 LSB not implemented)
// - solution: adjust both the target and counter (upwards)
#define MAX_TARGET_ATTEMPTS     13

#if FOR_508
#error "only supports 608 now"
#endif

// Pretty sure it doesn't matter, but adding some salt into our PIN->bytes[32] code
// based on the purpose of the PIN code.
//
#define PIN_PURPOSE_NORMAL          0x334d1858
#define PIN_PURPOSE_WORDS           0x2e6d6773

// Temporary hack only!
extern uint8_t      transitional_pinhash_cache[32];        // see linker-script

// See linker script; special read-only RAM memory (not secret)
extern uint8_t      reboot_seed_base[32];        // constant per-boot

// Hash up a PIN for indicated purpose.
static void pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose);

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

// is_duress_pin()
//
    static bool
is_duress_pin(const uint8_t digest[32], bool is_blank, int *pin_kn)
{
    // duress PIN can never be blank; that means it wasn't set yet
    if(is_blank) return false;

    const int kn = KEYNUM_duress_pin;

    // LIMITATION: an active MitM could change what we write
    // to something else (wrong) and thus we'd never see that
    // the duress PIN was used.

    ae_reset_chip();
    ae_pair_unlock();
    if(ae_checkmac(kn, digest) == 0) {
        *pin_kn = kn;

        return true;
    }

    return false;
}

// is_main_pin()
//
// Do the checkmac thing using a PIN, and if it works, great.
//
    static bool
is_main_pin(const uint8_t digest[32], int *pin_kn)
{
    int kn = KEYNUM_main_pin;

    ae_reset_chip();
    ae_pair_unlock();

    if(ae_checkmac_hard(kn, digest) == 0) {
        *pin_kn = kn;

        return true;
    }

    return false;
}


// pin_hash()
//
// Hash up a string of digits in 32-byte goodness.
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

    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, (uint8_t *)&purpose, 4);
    sha256_update(&ctx, (uint8_t *)pin, pin_len);

    sha256_final(&ctx, result);

    // and a second-sha256 on that, just in case.
    sha256_init(&ctx);
    sha256_update(&ctx, result, 32);
    sha256_final(&ctx, result);
}

// pin_hash_attempt()
//
// Go from PIN to heavily hashed 32-byte value, suitable testing against device.
//
// - brickme pin doesn't do the extra KDF step, so it can be fast
// - call with target_kn == 0 to return a mid-state that can be used for both main and duress
//
    static int
pin_hash_attempt(uint8_t target_kn, const char *pin, int pin_len, uint8_t result[32])
{
    uint8_t tmp[32]; 

    if(pin_len == 0) {
        // zero len PIN is the "blank" value: all zeros, no hashing
        memset(result, 0, 32);

        return 0;
    }

    // quick local hashing
    pin_hash(pin, pin_len, tmp, PIN_PURPOSE_NORMAL);

    if(target_kn == KEYNUM_brickme) {
        // no extra KDF for brickme case
        memcpy(result, tmp, 32);

        return 0;
    }

    // main, duress pins need mega hashing
    int rv = ae_stretch_iter(tmp, result, KDF_ITER_PIN);
    if(rv) return EPIN_AE_FAIL;

    // CAUTION: at this point, we just read the value off the bus
    // in clear text. Don't use that value directly.

    if(target_kn == 0) {
        // let the caller do either/both of the below mixins
        return 0;
    }

    memcpy(tmp, result, 32);
    if(target_kn == KEYNUM_main_pin) {
        ae_mixin_key(KEYNUM_pin_attempt, tmp, result);
    } else {
        ae_mixin_key(0, tmp, result);
    }

    return 0;
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
    sha256_update(&ctx, reboot_seed_base, 32);
    sha256_update(&ctx, (uint8_t *)args, offsetof(pinAttempt_t, hmac));

    if(args->magic_value == PA_MAGIC_V2) {
        sha256_update(&ctx, (uint8_t *)args->cached_main_pin,
                                msizeof(pinAttempt_t, cached_main_pin));
    }

    sha256_final(&ctx, result);

    // and a second-sha256 on that, just in case.
    sha256_init(&ctx);
    sha256_update(&ctx, result, 32);
    sha256_final(&ctx, result);
}

// _validate_attempt()
//
    static int
_validate_attempt(pinAttempt_t *args, bool first_time)
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
    if(args->magic_value == PA_MAGIC_V1) {
        // ok
    } else if(args->magic_value == PA_MAGIC_V2) {
        // ok
    } else if(first_time && args->magic_value == 0) {
        // allow it if first time: implies V1 api
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
// not really so strong with the 608a, since it's all enforced on that side, but
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
    uint32_t lastgood=0, match_count=0, counter=0, duress_lastgood=0;
    if(_read_slot_as_counter(KEYNUM_lastgood, &lastgood)) return -1;
    if(_read_slot_as_counter(KEYNUM_duress_lastgood, &duress_lastgood)) return -1;
    if(_read_slot_as_counter(KEYNUM_match_count, &match_count)) return -1;

    // Read the monotonically-increasing counter
    if(ae_get_counter(&counter, 0)) return -1;

    // Has the duress PIN been used more recently than real PIN?
    // if so, lie about # of failures to make things look like good login
    if(duress_lastgood > lastgood) {
        // lie about # of failures, but keep the pin-rate limiting
        args->num_fails = 0;
        args->attempts_left = MAX_TARGET_ATTEMPTS;;
    } else {
        if(lastgood > counter) {
            // monkey business, but impossible, right?!
            args->num_fails = 99;
        } else {
            args->num_fails = counter - lastgood;
        }
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

// maybe_brick_myself()
//
// Attempt the provided pin against the "brickme" slot, and if it
// works, immediately destroy the pairing secret so that we become
// a useless brick.
//
    static int
maybe_brick_myself(const char *pin, int pin_len)
{
    uint8_t     digest[32];
    int         rv = 0;

    if(!pin_len) return 0;

    pin_hash(pin, pin_len, digest, PIN_PURPOSE_NORMAL);

    ae_reset_chip();
    rv = ae_pair_unlock();
    if(rv) return rv;

    // Concern: MitM could block this by trashing our write
    // - but they have to do it without causing CRC or other comm error

    if(ae_checkmac(KEYNUM_brickme, digest) == 0) {
        // success... kinda: brick time.
        ae_destroy_key(KEYNUM_pairing);

        rv = 1;
    }

    ae_reset_chip();

    return rv;
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

    // NOTE: Can only attempt primary and secondary pins. If it happens to
    // match duress or brickme pins, then perhaps something happens,
    // but not allowed to test for those cases even existing.

    if(args->is_secondary) {
        // secondary PIN feature has been removed, might be old main firmware tho
        return EPIN_PRIMARY_ONLY;
    }

    // wipe most of struct, keep only what we expect and want!
    // - old firmware wrote zero to magic before this point, and so we set it here
    uint32_t given_magic = args->magic_value;
    bool    old_firmware = (given_magic != PA_MAGIC_V2);

    char    pin_copy[MAX_PIN_LEN];
    int     pin_len = args->pin_len;
    memcpy(pin_copy, args->pin, pin_len);

    memset(args, 0, old_firmware ? PIN_ATTEMPT_SIZE_V1 : PIN_ATTEMPT_SIZE_V2);

    // indicate our policies will be different from Mark 1/2
    args->state_flags = PA_HAS_608A;

    args->magic_value = given_magic?:PA_MAGIC_V1;
    args->pin_len = pin_len;
    memcpy(args->pin, pin_copy, pin_len);

    // unlock the AE chip
    if(warmup_ae()) {
        return EPIN_I_AM_BRICK;
    }

    if(args->pin_len) {
        // Implement the brickme feature here, nice and early: Immediate brickage if
        // provided PIN matches that special PIN.
        if(maybe_brick_myself(args->pin, args->pin_len)) {
            return EPIN_I_AM_BRICK;
        }
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
    // not required for 608a case, shouldn't be called
#if 0
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    // prevent any monkey business w/ systick rate
    // - we don't use interrupts, but this code is called after mpy starts sometimes,
    //   and in those cases, we want to keep their interrupt support working.
    uint32_t b4 = SysTick->CTRL;
    systick_setup();
    SysTick->CTRL |= (b4 & SysTick_CTRL_TICKINT_Msk);

    delay_ms(500);

    args->delay_achieved += 1;

    _sign_attempt(args);
#endif

    return 0;
}

// updates_for_duress_login()
//
    static int
updates_for_duress_login(uint8_t digest[32])
{
    // We keep another "good" login counter for duress, so we can 
    // show correctly-fake "num fails" and similar

    uint32_t count;
    int rv = ae_get_counter(&count, 0);
    if(rv) return EPIN_AE_FAIL;

    // update the "last good" counter for duress purposes
    uint32_t    tmp[32/4] = {0};
    tmp[0] = count;

    rv = ae_encrypted_write(KEYNUM_duress_lastgood, KEYNUM_duress_pin, digest, (void *)tmp, 32);
    if(rv) {
        ae_reset_chip();
        return EPIN_AE_FAIL;
    }

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
    ASSERT(bump < 32);

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
    // just be reducing attempt. Also, rate limiting not affected by anything here.

    return 0;

fail:
    ae_reset_chip();
    return EPIN_AE_FAIL;
}

// pin_cache_get_key()
//
    void
pin_cache_get_key(uint8_t key[32])
{
    // per-boot unique key.
	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, reboot_seed_base, 32);
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
    pin_cache_get_key(value);

    xor_mixin(value, digest, 32);

    if(args->magic_value == PA_MAGIC_V2) {
        memcpy(args->cached_main_pin, value, 32);
    } else {
        // short-term hack .. only applies if old firmware (not v3+) is used on
        // mark3 hardware.
        memcpy(transitional_pinhash_cache, value, 32);
    }
}

// pin_cache_restore()
//
    static void
pin_cache_restore(pinAttempt_t *args, uint8_t digest[32])
{
    // decrypt w/ rom secret + SRAM seed value

    if(args->magic_value == PA_MAGIC_V2) {
        memcpy(digest, args->cached_main_pin, 32);
    } else {
        // short-term hack .. only applies if old firmware (not v3+) is used on
        // mark3 hardware.
        memcpy(digest, transitional_pinhash_cache, 32);
    }

    uint8_t     key[32];
    pin_cache_get_key(key);

    xor_mixin(digest, key, 32);
}

// get_is_duress()
//
    static bool
get_is_duress(pinAttempt_t *args)
{
    // read and "decrypt" our one flag bit
    return ((args->private_state ^ rom_secrets->hash_cache_secret[0]) & 0x1);
}


// pin_login_attempt()
//
// Do the PIN check, and return a value. Or fail.
//
    int
pin_login_attempt(pinAttempt_t *args)
{
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    // OBSOLETE: did they wait long enough?
    // if(args->delay_achieved < args->delay_required) return EPIN_MUST_WAIT;

    if(args->state_flags & PA_SUCCESSFUL) {
        // already worked, or is blank
        return EPIN_WRONG_SUCCESS;
    }

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    int pin_kn = -1;
    bool is_duress = false;
    int secret_kn = -1;

    // hash up the pin now, assuming we'll use it on main PIN *OR* duress PIN
    uint8_t     mid_digest[32], digest[32];
    rv = pin_hash_attempt(0, args->pin, args->pin_len, mid_digest);
    if(rv) return EPIN_AE_FAIL;

    // Do mixin for duress case.
    rv = ae_mixin_key(0, mid_digest, digest);
    if(rv) return EPIN_AE_FAIL;

    if(is_duress_pin(digest, (args->pin_len == 0), &pin_kn)) {
        // they gave the duress PIN for this wallet... try to continue w/o any indication
        is_duress = true;

        secret_kn = KEYNUM_duress_secret;

        // for next run, we need to pretend like no failures (a little -- imperfect)
        rv = updates_for_duress_login(digest);
        if(rv) return EPIN_AE_FAIL;

    } else {
        // It is not the "duress pin", so assume it's the real PIN, and register
        // as an attempt on that.
        rv = ae_mixin_key(KEYNUM_pin_attempt, mid_digest, digest);
        if(rv) return EPIN_AE_FAIL;

        if(!is_main_pin(digest, &pin_kn)) {
            // PIN code is just wrong.
            // - nothing to update, since the chip's done it already
            return EPIN_AUTH_FAIL;
        }

        secret_kn = KEYNUM_secret;

        // change the various counters, since this worked
        rv = updates_for_good_login(digest);
        if(rv) return EPIN_AE_FAIL;
    }

    // SUCCESS! "digest" holds a working value. Save it.
    pin_cache_save(args, digest);

    // ASIDE: even if the above was bypassed, the following code will
    // fail when it tries to read/update the corresponding slots in the SE

    // mark as success
    args->state_flags = PA_SUCCESSFUL | PA_HAS_608A;

    // these are constants, and user doesn't care because they got in... but consistency.
    args->num_fails = 0;
    args->attempts_left = MAX_TARGET_ATTEMPTS;

    // I used to always read the secret, since it's so hard to get to this point,
    // but now just indicating if zero or non-zero so that we don't contaminate the
    // caller w/ sensitive data that they may not want yet.
    {   uint8_t ts[AE_SECRET_LEN];

        rv = ae_encrypted_read(secret_kn, pin_kn, digest, ts, AE_SECRET_LEN);
        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }
        ae_reset_chip();

        if(check_all_zeros(ts, AE_SECRET_LEN)) {
            args->state_flags |= PA_ZERO_SECRET;
        }
    }

    // indicate what features already enabled/non-blank
    if(is_duress) {
        // provide false answers to status of duress and brickme
        args->state_flags |= (PA_HAS_DURESS | PA_HAS_BRICKME);
    } else {
        // do we have duress password?
        if(!pin_is_blank(KEYNUM_duress_pin)) {
            args->state_flags |= PA_HAS_DURESS;
        }

        // do we have brickme set?
        if(!pin_is_blank(KEYNUM_brickme)) {
            args->state_flags |= PA_HAS_BRICKME;
        }
    }

    // In mark1/2, was thinking of maybe storing duress flag into private state,
    // but no real need, but testing for it is expensive in mark3, so going to use
    // LSB here for that. Xor's with a secret only we have.
    args->private_state = ((rng_sample() & ~1) | is_duress) ^ rom_secrets->hash_cache_secret[0];

    _sign_attempt(args);

    return 0;
}

// pin_change()
//
// Change the PIN and/or secrets (must also know the value, or it must be blank)
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

    // Obsolete secondary support, can't support.
    ASSERT(!args->is_secondary);
    if(cf & CHANGE_SECONDARY_WALLET_PIN) {
        return EPIN_BAD_REQUEST;
    }

    // Must be here to do something.
    if(cf == 0) return EPIN_RANGE_ERR;

    if(cf & CHANGE_BRICKME_PIN) {
        if(cf != CHANGE_BRICKME_PIN) {
            // only pin can be changed, nothing else.
            return EPIN_BAD_REQUEST;
        }
    }
    if((cf & CHANGE_DURESS_SECRET) && (cf & CHANGE_SECRET)) {
        // can't change two secrets at once.
        return EPIN_BAD_REQUEST;
    }

    // ASIDE: Can always change a PIN you already know
    // but can only prove you know the primary pin up
    // to this point (via login process)... none of the others.
    // That's why we need old_pin fields.

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // what pin do they need to know to make their change?
    int required_kn = -1;
    // what slot (key number) are updating?
    int target_slot = -1;

    // If they authorized w/ the duress password, we let them
    // change it (the duress one) while they think they are changing
    // the main one. Always pretend like the duress wallet is already enabled.
    // But if they try to change duress wallet PIN, we can't actually work.
    // Same for brickme PIN.

    // SO ... we need to know if they started w/ a duress wallet.
    bool is_duress = get_is_duress(args);

    if(is_duress) {
        // user is a thug.. limit what they can do

        // check for brickme pin on everything here.
        if(maybe_brick_myself(args->old_pin, args->old_pin_len)
                || maybe_brick_myself(args->new_pin, args->new_pin_len)
        ) {
            return EPIN_I_AM_BRICK;
        }

        if((cf & CHANGE_WALLET_PIN) != cf) {
            // trying to do anything but change PIN must fail.
            ae_reset_chip();

            return EPIN_OLD_AUTH_FAIL;
        }

        required_kn = target_slot = KEYNUM_duress_pin;
    } else {
        // No real need to re-prove PIN knowledge.
        // If they tricked us to get to this point, doesn't matter as
        // below the SE validates it all again.
        required_kn = KEYNUM_main_pin;

        if(cf & CHANGE_WALLET_PIN) {
            target_slot = KEYNUM_main_pin;
        } else if(cf & CHANGE_SECRET) {
            target_slot = KEYNUM_secret;
        } else if(cf & CHANGE_DURESS_PIN) {
            required_kn = KEYNUM_duress_pin;
            target_slot = KEYNUM_duress_pin;
        } else if(cf & CHANGE_DURESS_SECRET) {
            required_kn = KEYNUM_duress_pin;
            target_slot = KEYNUM_duress_secret;
        } else if(cf & CHANGE_BRICKME_PIN) {
            required_kn = KEYNUM_brickme;       // but main_pin would be better: rate limited
            target_slot = KEYNUM_brickme;
        } else {
            return EPIN_RANGE_ERR;
        }
    }

    // Determine they know hash protecting the secret/pin to be changed.
    uint8_t required_digest[32]; 
    if(   (!is_duress && required_kn == KEYNUM_main_pin) 
        || (is_duress && required_kn == KEYNUM_duress_pin)
    ) {
        // Restore cached version of PIN digest: faster
        pin_cache_restore(args, required_digest);
    } else {
        // Construct hash of pin needed.
        pin_hash_attempt(required_kn, args->old_pin, args->old_pin_len, required_digest);

        // Check the old pin provided, is right.
        ae_pair_unlock();
        if(ae_checkmac(required_kn, required_digest)) {
            // they got old PIN wrong, we won't be able to help them
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the change to the dataslot below will fail due to wrong PIN.

            return EPIN_OLD_AUTH_FAIL;
        }
    }

    // Calculate new PIN hashed value: will be slow for main pin.
    if(cf & (CHANGE_WALLET_PIN | CHANGE_DURESS_PIN | CHANGE_BRICKME_PIN)) {

        uint8_t new_digest[32]; 
        rv = pin_hash_attempt(required_kn, args->new_pin, args->new_pin_len, new_digest);
        if(rv) goto ae_fail;

        if(ae_encrypted_write(target_slot, required_kn, required_digest, new_digest, 32)) {
            goto ae_fail;
        }

        if(target_slot == required_kn) {
            memcpy(required_digest, new_digest, 32);
        }

        if(target_slot == KEYNUM_main_pin) {
            // main pin is changing; reset counter to zero (good login) and our cache
            pin_cache_save(args, new_digest);

            updates_for_good_login(new_digest);
        }
        if(is_duress && (target_slot == KEYNUM_duress_pin)) {
            // duress pin changed, and we're the duress thug, so update cache
            pin_cache_save(args, new_digest);
        }
    }

    // Record new secret.
    // Note the required_digest might have just changed above.
    if(cf & (CHANGE_SECRET | CHANGE_DURESS_SECRET)) {
        int secret_kn = (required_kn == KEYNUM_main_pin) ? KEYNUM_secret : KEYNUM_duress_secret;

        bool is_all_zeros = check_all_zeros(args->secret, AE_SECRET_LEN);

        // encrypt new secret, but only if not zeros!
        uint8_t     tmp[AE_SECRET_LEN] = {0};
        if(!is_all_zeros) {
            xor_mixin(tmp, rom_secrets->otp_key, AE_SECRET_LEN);
            xor_mixin(tmp, args->secret, AE_SECRET_LEN);
        }

        if(ae_encrypted_write(secret_kn, required_kn,
                                        required_digest, tmp, AE_SECRET_LEN)){
            goto ae_fail;
        }

        // update the zero-secret flag to be correct.
        if(cf & CHANGE_SECRET) {
            if(is_all_zeros) {
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
// To encourage not keeping the secret in memory, a way to fetch it after already
// have proven you know the PIN.
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

    // fetch the already-hashed pin
    // - no real need to re-prove PIN knowledge.
    // - if they tricked us, doesn't matter as below the SE validates it all again
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // determine if we should proceed under duress
    bool is_duress = get_is_duress(args);

    int pin_kn = is_duress ? KEYNUM_duress_pin : KEYNUM_main_pin;
    int secret_slot = is_duress ? KEYNUM_duress_secret : KEYNUM_secret;

    if(args->change_flags & CHANGE_DURESS_SECRET) {
        // Let them know the duress secret, iff: 
        // - they are logged into corresponding primary pin (not duress) 
        // - and they know the duress pin as well.
        // LATER: this feature not being used since we only write the duress secret
        if(is_duress) return EPIN_AUTH_FAIL;

        pin_kn = KEYNUM_duress_pin;
        secret_slot = KEYNUM_duress_secret;

        rv = pin_hash_attempt(pin_kn, args->old_pin, args->old_pin_len, digest);
        if(rv) goto fail;

        // Check the that pin is right (optional, but if wrong, encrypted read gives garb)
        ae_pair_unlock();
        if(ae_checkmac(pin_kn, digest)) {
            // They got old duress PIN wrong, we won't be able to help them.
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the decryption of the secret below will fail if we had been lied to.
            return EPIN_AUTH_FAIL;
        }
    }

    // read out the secret that corresponds to that pin
    rv = ae_encrypted_read(secret_slot, pin_kn, digest, args->secret, AE_SECRET_LEN);

    bool is_all_zeros = check_all_zeros(args->secret, AE_SECRET_LEN);

    // decrypt the secret, but only if not zeros!
    if(!is_all_zeros) xor_mixin(args->secret, rom_secrets->otp_key, AE_SECRET_LEN);

fail:
    ae_reset_chip();

    if(rv) return EPIN_AE_FAIL;

    return 0;
}

// pin_long_secret()
//
// Read or write the "long" secret: an additional 416 bytes on 608a only.
//
    int
pin_long_secret(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    // fetch the already-hashed pin
    // - no real need to re-prove PIN knowledge.
    // - if they tricked us, doesn't matter as below the SE validates it all again
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // determine if we should proceed under duress
    bool is_duress = get_is_duress(args);

    if(is_duress) {
        // Not supported in duress mode. Pretend it's all zeros. Accept all writes.
        memset(args->secret, 0, 32);

        return 0;
    }

    // which 32-byte section?
    STATIC_ASSERT(CHANGE_LS_OFFSET == 0xf00);
    int blk = (args->change_flags >> 8) & 0xf;
    if(blk > 13) return EPIN_RANGE_ERR;

    // read/write exactly 32 bytes
    if(!(args->change_flags & CHANGE_SECRET)) {
        rv = ae_encrypted_read32(KEYNUM_long_secret, blk, KEYNUM_main_pin, digest, args->secret);
        if(rv) goto fail;

        if(!check_all_zeros(args->secret, 32)) {
            xor_mixin(args->secret, rom_secrets->otp_key_long+(32*blk), 32);
        }
    } else {
        // write case
        uint8_t tmp[32] = {0};

        if(!check_all_zeros(args->secret, 32)) {
            xor_mixin(tmp, args->secret, 32);
            xor_mixin(tmp, rom_secrets->otp_key_long+(32*blk), 32);
        }

        rv = ae_encrypted_write32(KEYNUM_long_secret, blk, KEYNUM_main_pin, digest, tmp);
        if(rv) goto fail;
    }

fail:
    ae_reset_chip();

    if(rv) return EPIN_AE_FAIL;

    return 0;
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
    checksum_flash(fw_check, world_check);

    // step 2: write it out to chip.
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // under duress, we can't fake this, but we go through the motions,
    bool is_duress = get_is_duress(args);
    if(!is_duress) {
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


// EOF
