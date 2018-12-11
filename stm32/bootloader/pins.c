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

typedef enum {
    PIN_primary = 0,
    PIN_secondary = 1,
    PIN_primary_duress = 2,
    PIN_secondary_duress = 3,
    PIN_brickme = 4,
} whichPin_t;
#define PIN__max    5

// Pretty sure it doesn't matter, but adding some salt into our PIN->bytes[32] code
// based on the purpose of the PIN code.
//
#define PIN_PURPOSE_NORMAL          0x334d1858
#define PIN_PURPOSE_WORDS           0x2e6d6773

// Hash up a PIN for indicated purpose.
static void pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose);

// pin_is_blank()
//
// Is a specific PIN defined already? Not safe to expose this directly to callers!
//
    static bool
pin_is_blank(whichPin_t which)
{
    int keynum = -1;

    switch(which) {
        case PIN_primary:
            keynum = KEYNUM_pin_1;
            break;

        case PIN_secondary:
            keynum = KEYNUM_pin_2;
            break;

        case PIN_primary_duress:
            keynum = KEYNUM_pin_3;
            break;

        case PIN_secondary_duress:
            keynum = KEYNUM_pin_4;
            break;

        case PIN_brickme:
            keynum = KEYNUM_brickme;
            break;

        default:
            INCONSISTENT("kn");
    }

    uint8_t blank[32];
    memset(blank, 0, sizeof(blank));

    ae_reset_chip();
    ae_pair_unlock();

    // Passing this check with zeros, means PIN was blank.
    int is_blank = (ae_checkmac_hard(keynum, blank) == 0);

    // CAUTION? We've unlocked something maybe, but it's blank, so...
    ae_reset_chip();

    return is_blank;
}

// lookup_secret_lastgood()
//
// Map from PIN keynum to corresponding secret key number, and last good counter (if any).
//
    static void
lookup_secret_lastgood(int kn, int *secret_kn, int *lastgood_kn)
{
    switch(kn) {
        case KEYNUM_pin_1:
            *secret_kn = KEYNUM_secret_1;
            *lastgood_kn = KEYNUM_lastgood_1;
            break;

        case KEYNUM_pin_2:
            *secret_kn = KEYNUM_secret_2;
            *lastgood_kn = KEYNUM_lastgood_2;
            break;

        case KEYNUM_pin_3:
            *secret_kn = KEYNUM_secret_3;
            *lastgood_kn = -1;
            break;

        case KEYNUM_pin_4:
            *secret_kn = KEYNUM_secret_4;
            *lastgood_kn = -1;
            break;

        default:
            INCONSISTENT("kn");
    }
}

// is_duress_pin()
//
    static bool
is_duress_pin(bool is_secondary, const uint8_t digest[32], bool is_blank, int *pin_kn)
{
    // duress PIN can never be blank; that means it wasn't set yet
    if(is_blank) return false;

    int kn = is_secondary ? KEYNUM_pin_4 : KEYNUM_pin_3;

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

// is_real_pin()
//
// Do the checkmac thing using a PIN, and if it works, great.
//
// Important that every code path leading here is rate-limited, and also incr the counter.
//
    static bool
is_real_pin(bool is_secondary, const uint8_t digest[32], bool is_blank, int *pin_kn)
{
    int kn = is_secondary ? KEYNUM_pin_2 : KEYNUM_pin_1;

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

// pin_prefix_words()
//
// Look up some bits... do HMAC(words secret) and return some LSB's
//
// CAUTIONS: 
// - should be rate-limited (or liked to PIN code rate-limiting somehow)
// - hash generated here is shown plaintext on bus (for HMAC operation).
//
    int
pin_prefix_words(const char *pin_prefix, int prefix_len, uint32_t *result)
{
    uint8_t     tmp[32];
    uint8_t     digest[32];

    // hash it up real good
    pin_hash(pin_prefix, prefix_len, tmp, PIN_PURPOSE_WORDS);

    // some very weak rate limiting...
    uint32_t count = backup_data_get(IDX_WORD_LOOKUPS_USED);
    backup_data_set(IDX_WORD_LOOKUPS_USED, count+1);

    if(count > 25) {
        // there is hacking. no human does this many.
        fatal_mitm();
    }

    delay_ms((count < 10) ? 150 : 2500);

    // bounce it off chip in HMAC mode, using dedicated key for that purpose.
    ae_setup();
    ae_pair_unlock();
	int rv = ae_hmac32(KEYNUM_words, tmp, digest);
    ae_reset_chip();

	if(rv) return -1;

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
    extern uint8_t      reboot_seed_base[32];        // constant per-boot

	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, reboot_seed_base, 32);
    sha256_update(&ctx, (uint8_t *)args, offsetof(pinAttempt_t, hmac));
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
    if(args->magic_value != PA_MAGIC) {
        if(first_time && args->magic_value == 0) {
            // allow it if first time
        } else {
            return EPIN_BAD_MAGIC;
        }
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
    args->magic_value = PA_MAGIC;

    _hmac_attempt(args, args->hmac);
}

// get_last_success()
//
// Read state about previous attempt(s) from AE. Chip already unlocked.
//
    static int __attribute__ ((noinline))
get_last_success(bool is_secondary, uint32_t *counter, uint32_t *lastgood)
{
    int slot = is_secondary ? KEYNUM_lastgood_2 : KEYNUM_lastgood_1;

    ae_pair_unlock();

    // Read counter value of last-good login. Important that this be authenticated.
    // - using first 32-bits only, others will be zero
    uint32_t padded[32/4] = { 0 };
    if(ae_read_data_slot(slot, (uint8_t *)padded, 32)) return -1;

    uint8_t tempkey[32];
    if(ae_gendig_slot(slot, (const uint8_t *)padded, tempkey)) return -1;

    if(!ae_is_correct_tempkey(tempkey)) {
        fatal_mitm();
    }

    // now we can trust the value.
    *lastgood = padded[0];

    // NOTE: to prevent **active** attackers on the bus, it is critical
    // this counter read is authenticated via the shared secret,
    // using GenDig(counter) and then MAC(shared secret). That check is
    // now part of ae_get_counter().

    return ae_get_counter(counter, is_secondary ? 1 : 0, false);
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

// _calc_delay_required()
//
    uint32_t
_calc_delay_required(int num_fails)
{
#ifndef RELEASE
    // DEBUG/dev only!
    return num_fails;
#else
    // implement our PIN retry delay policy
    // - 500ms ticks
#define SECONDS(n)          ((n)*2)
#define MINUTES(n)          ((n)*2*60)

    switch(num_fails) {
        case 0:          return 0;
        case 1 ... 2:    return SECONDS(15);
        case 3 ... 4:    return MINUTES(1);
        case 5 ... 9:    return MINUTES(5);
        case 10 ... 19:  return MINUTES(30);
        case 20 ... 49:  return MINUTES(120);
        default:         return MINUTES(8*60);
    }
#undef SECONDS
#undef MINUTES
#endif
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
    ae_pair_unlock();

    // XXX MitM could block this by trashing our write

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
    STATIC_ASSERT(sizeof(pinAttempt_t) == PIN_ATTEMPT_SIZE);

    int rv = _validate_attempt(args, true);
    if(rv) return rv;

    // NOTE: Can only attempt primary and secondary pins. If it happens to
    // match duress or brickme pins, then perhaps something happens,
    // but not allowed to test for those cases even existing.

    // wipe most of struct, keep only what we expect and want!
    int is_secondary = args->is_secondary;
    char    pin_copy[MAX_PIN_LEN];
    int     pin_len = args->pin_len;
    memcpy(pin_copy, args->pin, pin_len);

    memset(args, 0, sizeof(pinAttempt_t));

    args->magic_value = PA_MAGIC;
    args->is_secondary = is_secondary;
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

    uint32_t count = 0, last_good = 0;
    if(get_last_success(args->is_secondary, &count, &last_good)) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    ae_reset_chip();

    args->attempt_target = count+1;

    if(last_good > count) {
        // huh? monkey business
        args->num_fails = 99;
    } else {
        args->num_fails = count - last_good;
    }

    // has the duress pin (this wallet) been used this power cycle?
    uint32_t fake_lastgood = backup_data_get(args->is_secondary 
                                        ? IDX_DURESS_LASTGOOD_2 : IDX_DURESS_LASTGOOD_1);
    if(fake_lastgood) {
        // lie about # of failures, but keep the pin-rate limiting
        args->num_fails = 0;
    }

    args->delay_required = _calc_delay_required(args->num_fails);
    args->delay_achieved = 0;

    // need to know if we are blank/unused device
    if(pin_is_blank(args->is_secondary ? PIN_secondary : PIN_primary)) {
        args->state_flags = PA_SUCCESSFUL | PA_IS_BLANK;
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

    return 0;
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

    // did they wait long enough?
    if(args->delay_achieved < args->delay_required) {
        return EPIN_MUST_WAIT;
    }

    if(args->state_flags & PA_SUCCESSFUL) {
        // already worked, or is blank
        return EPIN_WRONG_SUCCESS;
    }

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    int pin_kn = -1;
    bool is_duress = false;

    // hash up the pin now.
    uint32_t new_count = ~0;
    uint8_t     digest[32];
    pin_hash(args->pin, args->pin_len, digest, PIN_PURPOSE_NORMAL);

    if(is_duress_pin(args->is_secondary, digest, (args->pin_len == 0), &pin_kn)) {
        // they gave the duress PIN for this wallet... try to continue w/o any indication
        is_duress = true;

        // record this!
        backup_data_set(args->is_secondary ? IDX_DURESS_LASTGOOD_2 : IDX_DURESS_LASTGOOD_1,
                                args->attempt_target+1);
    } else {
        // Assume it's the real PIN, and register as an attempt on that.

        // Is this attempt for the right count? Also, increament it.

        rv = ae_get_counter(&new_count, args->is_secondary ? 1 : 0, true);
        if(rv) return EPIN_AE_FAIL;

        if(args->attempt_target != new_count) {
            // they just cost themselves an attempt too! (only hackers would come here)
            return EPIN_OLD_ATTEMPT;
        }

        // try it out / and determine if we should proceed
        if(!is_real_pin(args->is_secondary, digest, (args->pin_len == 0), &pin_kn)) {
            // code is just wrong.
            return EPIN_AUTH_FAIL;
        }
    }

    // SUCCESS! "digest" holds a working value.

    // reset rate-limiting on word lookups
    backup_data_set(IDX_WORD_LOOKUPS_USED, 0);

    // ASIDE: even if the above was bypassed, the following code will
    // fail when it tries to read/update the corresponding slots in the 508a.

    int secret_kn = -1, lastgood_kn = -1;
    lookup_secret_lastgood(pin_kn, &secret_kn, &lastgood_kn);

    if(lastgood_kn != -1) {

        // update the "last good" counter
        uint32_t    tmp[32/4] = {0};
        tmp[0] = new_count;

        rv = ae_encrypted_write(lastgood_kn, pin_kn, digest, (void *)tmp, 32);
        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }

        // CONCERN: the above write could be blocked (fake success) by an active
        // MitM attacker, but that would be pointless since it would only slow future
        // login attempts. Plus he's already got the right PIN at this point, so...
    }

    // mark as success
    args->state_flags = PA_SUCCESSFUL;

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


    // indicate what featurs already enabled/non-blank
    if(is_duress) {
        // provide false answers to status of duress and brickme
        args->state_flags |= (PA_HAS_DURESS | PA_HAS_BRICKME);
    } else {
        // do we have duress password?
        if(!pin_is_blank(args->is_secondary ? PIN_secondary_duress : PIN_primary_duress)) {
            args->state_flags |= PA_HAS_DURESS;
        }

        // do we have brickme set?
        if(!pin_is_blank(PIN_brickme)) {
            args->state_flags |= PA_HAS_BRICKME;
        }
    }

    // I was thinking of maybe storing duress flag into private state,
    // but no real need. Preserve for future usage and make sure upper
    // layers preserve it.
    args->private_state = rng_sample();

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

    // must be here to do something.
    if(cf == 0) return EPIN_RANGE_ERR;

    if(cf & CHANGE_BRICKME_PIN) {
        if(args->is_secondary) {
            // only main PIN holder can define brickme PIN
            return EPIN_PRIMARY_ONLY;
        }
        if(cf != CHANGE_BRICKME_PIN) {
            // only pin can be changed, nothing else.
            return EPIN_BAD_REQUEST;
        }
    }
    if((cf & CHANGE_DURESS_SECRET) && (cf & CHANGE_SECRET)) {
        // can't change two secrets at once.
        return EPIN_BAD_REQUEST;
    }

    if(cf & CHANGE_SECONDARY_WALLET_PIN) {
        if(args->is_secondary) {
            // only main user uses this call 
            return EPIN_BAD_REQUEST;
        }
        if(cf != CHANGE_SECONDARY_WALLET_PIN) {
            // only changing PIN, no secret-setting
            return EPIN_BAD_REQUEST;
        }
    }

    // ASIDE: Can always change a PIN you already know
    // but can only prove you know the primary/secondary
    // pin up to this point ... none of the others.
    // That's why we need old_pin fields.

    // hash it up real good
    uint8_t     digest[32];
    pin_hash(args->pin, args->pin_len, digest, PIN_PURPOSE_NORMAL);

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // If they authorized w/ the duress password, we let them
    // change it (the duress one) while they think they are changing
    // the main one. Always pretend like the duress wallet is already enabled.
    // But if they try to change duress wallet PIN, we can't actually work.
    // Same for brickme PIN.

    // SO ... we need to know if they started w/ a duress wallet.

    int pin_kn = -1;
    bool is_duress = false;
    if(is_duress_pin(args->is_secondary, digest, (args->pin_len == 0), &pin_kn)) {
        is_duress = true;
    } else {
        // no real need to re-prove PIN knowledge.
        // if they tricked us, doesn't matter as below the 580a validates it all again
        pin_kn = (args->is_secondary || (cf & CHANGE_SECONDARY_WALLET_PIN))
                        ? KEYNUM_pin_2 : KEYNUM_pin_1;
    }

    // what key number are updating?
    int target_kn = -1;

    if(is_duress) {
        // user is a thug.. limit what they can do

        // check for brickme pin on everything here.
        if(maybe_brick_myself(args->old_pin, args->old_pin_len)
                || maybe_brick_myself(args->new_pin, args->new_pin_len)
        ) {
            return EPIN_I_AM_BRICK;
        }

        // - pretend they got the validating PIN wrong
        if((cf & (CHANGE_WALLET_PIN | CHANGE_SECRET)) != cf) {
            ae_reset_chip();

            return EPIN_OLD_AUTH_FAIL;
        }
    }

    if(cf & (CHANGE_WALLET_PIN | CHANGE_SECRET | CHANGE_SECONDARY_WALLET_PIN)) {
        target_kn = pin_kn;
    } else if(cf & (CHANGE_DURESS_PIN | CHANGE_DURESS_SECRET)) {
        target_kn = args->is_secondary ?  KEYNUM_pin_4 : KEYNUM_pin_3;
    } else if(cf & CHANGE_BRICKME_PIN) {
        target_kn = KEYNUM_brickme;
    } else {
        return EPIN_RANGE_ERR;
    }

    // Determine the hash protecting the secret/pin to be changed.
    uint8_t target_digest[32]; 
    if((target_kn != pin_kn) || (cf & CHANGE_SECONDARY_WALLET_PIN)) {
        pin_hash(args->old_pin, args->old_pin_len, target_digest, PIN_PURPOSE_NORMAL);

        // Check the old pin is right.
        ae_pair_unlock();
        if(ae_checkmac(target_kn, target_digest)) {
            // they got old PIN wrong, we won't be able to help them
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the change to the keyslot below will fail due to wrong PIN.

            return EPIN_OLD_AUTH_FAIL;
        }
    } else {
        memcpy(target_digest, digest, 32);
    }

    // Record new PIN value.
    if(cf & (CHANGE_WALLET_PIN | CHANGE_DURESS_PIN 
                | CHANGE_BRICKME_PIN | CHANGE_SECONDARY_WALLET_PIN)) {

        uint8_t new_digest[32]; 
        pin_hash(args->new_pin, args->new_pin_len, new_digest, PIN_PURPOSE_NORMAL);

        if(ae_encrypted_write(target_kn, target_kn, target_digest, new_digest, 32)) {
            goto ae_fail;
        }

        memcpy(target_digest, new_digest, 32);
    }

    // Record new secret.
    // Note the digest might have just changed above.
    if(cf & (CHANGE_SECRET | CHANGE_DURESS_SECRET)) {
        int secret_kn = -1, lastgood_kn = -1;
        lookup_secret_lastgood(target_kn, &secret_kn, &lastgood_kn);

        if(ae_encrypted_write(secret_kn, target_kn, target_digest, args->secret, AE_SECRET_LEN)){
            goto ae_fail;
        }

        // update the zero-secret flag to be correct.
        if(cf & CHANGE_SECRET) {
            if(check_all_zeros(args->secret, AE_SECRET_LEN)) {
                args->state_flags |= PA_ZERO_SECRET;
            } else {
                args->state_flags &= ~PA_ZERO_SECRET;
            }
            _sign_attempt(args);
        }
    }

    ae_reset_chip();

    // NOTE: do **not** update args here, definately not with success or something! 

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

    // just in case? covered already by successful state_flags
    if(args->delay_achieved < args->delay_required) {
        return EPIN_MUST_WAIT;
    }

    // hash up the pin now.
    uint8_t     digest[32];
    pin_hash(args->pin, args->pin_len, digest, PIN_PURPOSE_NORMAL);

    // try it out / and determine if we should proceed under duress
    int pin_kn = -1;
    bool is_duress = false;
    if(is_duress_pin(args->is_secondary, digest, (args->pin_len == 0), &pin_kn)) {
        is_duress = true;
    } else {
        // no real need to re-prove PIN knowledge.
        // if they tricked us, doesn't matter as below the 580a validates it all again
        pin_kn = args->is_secondary ? KEYNUM_pin_2 : KEYNUM_pin_1;
    }

    if(args->change_flags & CHANGE_DURESS_SECRET) {
        // let them know the duress secret, iff: they are logged into
        // corresponding primary pin (not duress) and they know the duress
        // pin as well.
        // LATER: this feature not being used since we only write the duress secret
        if(is_duress) return EPIN_AUTH_FAIL;

        int target_kn = args->is_secondary ?  KEYNUM_pin_4 : KEYNUM_pin_3;

        uint8_t target_digest[32]; 
        pin_hash(args->old_pin, args->old_pin_len, target_digest, PIN_PURPOSE_NORMAL);

        // Check the that pin is right (optional, but if wrong, encrypted read gives garb)
        ae_pair_unlock();
        if(ae_checkmac(target_kn, target_digest)) {
            // they got old PIN wrong, we won't be able to help them
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the decryption of the secret below will fail if we had been lied to.

            return EPIN_AUTH_FAIL;
        }

        int secret_kn = -1, lastgood_kn = -1;
        lookup_secret_lastgood(target_kn, &secret_kn, &lastgood_kn);

        rv = ae_encrypted_read(secret_kn, target_kn, target_digest, args->secret, AE_SECRET_LEN);
    } else {
        int secret_kn = -1, lastgood_kn = -1;
        lookup_secret_lastgood(pin_kn, &secret_kn, &lastgood_kn);

        // read out the secret that corresponds to that pin
        rv = ae_encrypted_read(secret_kn, pin_kn, digest, args->secret, AE_SECRET_LEN);
    }

    if(rv) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    ae_reset_chip();

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

    // just in case?
    if(args->delay_achieved < args->delay_required) {
        return EPIN_MUST_WAIT;
    }

    // step 1: calc the value to use
    uint8_t fw_check[32], world_check[32];
    checksum_flash(fw_check, world_check);

    // re-calc correct PIN
    uint8_t     digest[32];
    pin_hash(args->pin, args->pin_len, digest, PIN_PURPOSE_NORMAL);

    // write it out to chip.
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    rv = ae_encrypted_write(KEYNUM_firmware, KEYNUM_pin_1, digest, world_check, 32);
    if(rv) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
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
