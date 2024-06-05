/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * se2.c -- Talk to DS28C36B chip which is our second secure element.
 *
 */
#include "basics.h"
#include "main.h"
#include "se2.h"
#include "ae.h"
#include "ae_config.h"
#include "aes.h"
#include "secrets.h"
#include "verify.h"
#include "psram.h"
#include "faster_sha256.h"
#include "oled.h"
#include SCREENS_H
#include "console.h"
#include "constant_time.h"
#include "misc.h"
#include "rng.h"
#include "gpio.h"
#include "delay.h"
#include "pins.h"
#include "storage.h"
#include <string.h>
#include "micro-ecc/uECC.h"
#include <setjmp.h>

static I2C_HandleTypeDef   i2c_port;

static jmp_buf error_env;
#define CALL_CHECK(cond)       if((cond)) longjmp(error_env, __LINE__)
#define CHECK_RIGHT(cond)      if(!(cond)) longjmp(error_env, __LINE__)

// fixed value for DS28C36B part
static const uint8_t DEV_MANID[2] = { 0x00, 0x80 };

// DEBUG / setup time.
static se2_secrets_t _tbd;
#define SE2_SECRETS         (rom_secrets->se2.pairing[0] == 0xff ? &_tbd : &rom_secrets->se2)

// HAL API requires shift here.
#define I2C_ADDR        (0x1b << 1)

// Result codes from chip
// - the meaning depends on the command
#define RC_SUCCESS      0xAA
#define RC_BAD_PARAM    0x77
#define RC_PROTECTED    0x55
#define RC_INVALID_SEQ  0x33
#define RC_NO_ACK       0x0f            // mine: no ack on something
#define RC_WRONG_SIZE   0x1f            // mine: response wrong size
#define RC_WRITE_FAIL   0x2f            // mine: sending command failed
#define RC_READ_FAIL    0x3f            // mine: reading response failed

// page numbers (Table 1)
#define PGN_PUBKEY_A		16        // also +1
#define PGN_PUBKEY_B		18        // also +1
#define PGN_PUBKEY_C		20        // also +1
#define PGN_PRIVKEY_A		22
#define PGN_PRIVKEY_B		23
#define PGN_PRIVKEY_C		24
#define PGN_SECRET_A		25
#define PGN_SECRET_B		26
#define PGN_DEC_COUNTER		27
#define PGN_ROM_OPTIONS		28
#define PGN_GPIO    		29
#define PGN_PUBKEY_S		30        // also 31, volatile

// our page allocations: mostly for trick pins+their data
#define PGN_TRICK(n)        (n)
#define PGN_LAST_TRICK      NUM_TRICKS-1
#define PGN_SE2_EASY_KEY    14
#define PGN_SE2_HARD_KEY    15

// page protection bitmask (Table 11)
#define PROT_RP	    	0x01
#define PROT_WP	    	0x02
#define PROT_EM	    	0x04
#define PROT_APH		0x08
#define PROT_EPH		0x10
#define PROT_AUTH		0x20
#define PROT_ECH		0x40            // requires ECW too
#define PROT_ECW		0x80

// Debug output interferes with "--metal" testing mode.
//#ifndef RELEASE
#if 0
# define DEBUG(s)        puts(s)
# define DEBUG_OUTPUT    1
#else
# define DEBUG(s)
#endif

// forward defs...
void se2_read_encrypted(uint8_t page_num, uint8_t data[32], int keynum, const uint8_t *secret);
static bool se2_read_hard_secret(uint8_t hard_key[32], const uint8_t pin_digest[32]);

// se2_write1()
//
    static bool
se2_write1(uint8_t cmd, uint8_t arg)
{
    uint8_t data[3] = { cmd, 1, arg };

    HAL_StatusTypeDef rv = HAL_I2C_Master_Transmit(&i2c_port, I2C_ADDR, 
                                                    data, sizeof(data), HAL_MAX_DELAY);

    return (rv != HAL_OK);
}

// se2_write2()
//
    static bool
se2_write2(uint8_t cmd, uint8_t arg1, uint8_t arg2)
{
    uint8_t data[4] = { cmd, 2, arg1, arg2 };

    HAL_StatusTypeDef rv = HAL_I2C_Master_Transmit(&i2c_port, I2C_ADDR,
                                                    data, sizeof(data), HAL_MAX_DELAY);

    return (rv != HAL_OK);
}

// se2_write_n()
//
    static bool
se2_write_n(uint8_t cmd, uint8_t *param1, const uint8_t *data_in, uint8_t len)
{
    uint8_t data[2 + (param1?1:0) + len], *p = data;

    *(p++) = cmd;
    *(p++) = sizeof(data) - 2;
    if(param1) {
        *(p++) = *param1;
    }
    if(len) {
        memcpy(p, data_in, len);
    }

    HAL_StatusTypeDef rv = HAL_I2C_Master_Transmit(&i2c_port, I2C_ADDR,
                                                    data, sizeof(data), HAL_MAX_DELAY);

    return (rv != HAL_OK);
}

// se2_read_n()
//
    static uint8_t
se2_read_n(uint8_t len, uint8_t *rx)
{
    // Response time of the chip varies from 0ms (read buffer), is typically
    // 3ms for simple things, and peaks at 200ms for complex ECC stuff.
    // Poll until chip provides an answer.
    ASSERT(len >= 2);

    for(int tries=0; tries<300; tries++) {
        HAL_StatusTypeDef rv = HAL_I2C_Master_Receive(&i2c_port, I2C_ADDR, rx, len, HAL_MAX_DELAY);
        if(rv == HAL_OK) {
            if(rx[0] != len-1) {
                return RC_WRONG_SIZE;
            }

            return rx[1];
        }

        delay_ms(1);
    }

    // timeout
    return RC_NO_ACK;
}

// se2_read1()
//
    static uint8_t
se2_read1(void)
{
    // many commands return a single (framed) status byte, where 0xAA == success
    uint8_t rx[2];

    return se2_read_n(2, rx);
}

// se2_write_buffer()
//
    static void
se2_write_buffer(const uint8_t *data, int len)
{
    // no response to this command, just blindly write it
    CALL_CHECK(se2_write_n(0x87, NULL, data, len));
}

// se2_write_page()
//
// Caution: Can be read and/or intercepted.
//
    void
se2_write_page(uint8_t page_num, const uint8_t data[32])
{
    CALL_CHECK(se2_write_n(0x96, &page_num, data, 32));

    CHECK_RIGHT(se2_read1() == RC_SUCCESS);
}

// se2_pick_keypair()
//
    void
se2_pick_keypair(uint8_t pubkey_num, bool lock)
{
    // use device RNG to pick a keypair
    ASSERT(pubkey_num < 2);

    int wpe = lock ? 0x1 : 0x0;
    CALL_CHECK(se2_write1(0xcb, (wpe <<6) | pubkey_num));

    CHECK_RIGHT(se2_read1() == RC_SUCCESS);
}

// se2_verify_page()
//
    bool
se2_verify_page(uint8_t page_num, uint8_t data[32], int keynum, const uint8_t *secret)
{
    // "Compute and Read Page Authentication" using HMAC secret A or S

    // .. pick a nonce
    uint8_t chal[32];
    rng_buffer(chal, sizeof(chal));
    se2_write_buffer(chal, sizeof(chal));
    
    // .. do it (HMAC method, not ECDSA)
    CALL_CHECK(se2_write1(0xa5, (keynum<<5) | page_num));

    uint8_t check[34];
    CHECK_RIGHT(se2_read_n(sizeof(check), check) == RC_SUCCESS);

    // .. see if we can arrive at same HMAC result.

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);

    //  msg = self.rom_id + expected + chal + bytes([page_num]) + self.manid
    hmac_sha256_update(&ctx, SE2_SECRETS->romid, 8);
    hmac_sha256_update(&ctx, data, 32);
    hmac_sha256_update(&ctx, chal, 32);
    hmac_sha256_update(&ctx, &page_num, 1);
    hmac_sha256_update(&ctx, DEV_MANID, 2);

    uint8_t expect[32];
    hmac_sha256_final(&ctx, secret, expect);

    return check_equal(expect, check+2, 32);
}

// se2_read_page()
//
// Must always authenticate what we read, because just normal read (no encryption)
// does not have any MiTM protection at all.
//
    void
se2_read_page(uint8_t page_num, uint8_t data[32], bool verify)
{
    CALL_CHECK(se2_write1(0x69, page_num));

    uint8_t rx[2+32];
    CHECK_RIGHT(se2_read_n(sizeof(rx), rx) == RC_SUCCESS);

    CHECK_RIGHT(rx[0] == 33);
    CHECK_RIGHT(rx[1] == RC_SUCCESS);

    memcpy(data, rx+2, 32);

    if(!verify) return;

    CHECK_RIGHT(se2_verify_page(page_num, data, 0, SE2_SECRETS->pairing));
}

// se2_write_encrypted()
//
// - encrypt and write a value.
// - needs existing value to pass auth challenge (so we re-read it)
// - so cannot be used on read-protected pages like keys
//
    void
se2_write_encrypted(uint8_t page_num, const uint8_t data[32], int keynum, const uint8_t *secret)
{
    // only supporting secret A or S.
    ASSERT((keynum == 0) || (keynum == 2));

    // need old value to for authentication purposes
    uint8_t     old_data[32];
    se2_read_encrypted(page_num, old_data, keynum, secret);

    uint8_t PGDV = page_num | 0x80;

    // pick a nonce
    // (hmac auth + chal) will be written to the "buffer"
    uint8_t chal_check[32+8];
    rng_buffer(&chal_check[32], 8);

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);

    // msg = chal + self.rom_id + PGDV + self.manid
    hmac_sha256_update(&ctx, &chal_check[32], 8);
    hmac_sha256_update(&ctx, SE2_SECRETS->romid, 8);
    hmac_sha256_update(&ctx, &PGDV, 1);
    hmac_sha256_update(&ctx, DEV_MANID, 2);
    ASSERT(ctx.num_pending == 19);

    uint8_t otp[32];
    hmac_sha256_final(&ctx, secret, otp);

    // encrypt new value
    uint8_t tmp[32];
    memcpy(tmp, data, 32);
    xor_mixin(tmp, otp, 32);

    // "tmp" now encrypted, but also need right auth value in buffer

    // msg2 = self.rom_id + old_data + new_data + PGDV + self.manid
    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, SE2_SECRETS->romid, 8);
    hmac_sha256_update(&ctx, old_data, 32);
    hmac_sha256_update(&ctx, data, 32);
    hmac_sha256_update(&ctx, &PGDV, 1);
    hmac_sha256_update(&ctx, DEV_MANID, 2);

    ASSERT(ctx.num_pending == 75);
    hmac_sha256_final(&ctx, secret, chal_check);

    // send chip both our nonce (challenge) and also HMAC auth check value
    se2_write_buffer(chal_check, sizeof(chal_check));

    // send encrypted data now
    uint8_t pn = (keynum << 6) | page_num;
    CALL_CHECK(se2_write_n(0x99, &pn, tmp, 32));

    CHECK_RIGHT(se2_read1() == RC_SUCCESS);
}



// se2_read_encrypted()
//
// - use key to read, but must also do verify because no replay protection otherwise
// - page must be protected with EPH or ECH, and of course !RP
//
    void
se2_read_encrypted(uint8_t page_num, uint8_t data[32], int keynum, const uint8_t *secret)
{
    // only supporting secret A or S.
    ASSERT((keynum == 0) || (keynum == 2));

    CALL_CHECK(se2_write1(0x4b, (keynum << 6) | page_num));

    uint8_t rx[2+8+32];
    CHECK_RIGHT(se2_read_n(sizeof(rx), rx) == RC_SUCCESS);

    CHECK_RIGHT(rx[1] == RC_SUCCESS);

    // .. decrypt result.
    uint8_t *chal = rx+2;
    memcpy(data, rx+2+8, 32);

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);

    //  msg = chal + self.rom_id + bytes([page_num]) + self.manid
    hmac_sha256_update(&ctx, chal, 8);
    hmac_sha256_update(&ctx, SE2_SECRETS->romid, 8);
    hmac_sha256_update(&ctx, &page_num, 1);
    hmac_sha256_update(&ctx, DEV_MANID, 2);

    uint8_t otp[32];
    hmac_sha256_final(&ctx, secret, otp);

    xor_mixin(data, otp, 32);

    // CRITICAL: verify right result using a nonce we pick!
    CHECK_RIGHT(se2_verify_page(page_num, data, keynum, secret));
}


// se2_get_protection()
//
// Caution: Use only in a controlled environment! No MiTM protection.
//
    uint8_t
se2_get_protection(uint8_t page_num)
{
    CALL_CHECK(se2_write1(0xaa, page_num));

    return se2_read1();
}

// se2_set_protection()
//
// Caution: Use only in a controlled environment! No MiTM protection.
//
    void
se2_set_protection(uint8_t page_num, uint8_t flags)
{
    if(se2_get_protection(page_num) == flags) {
        return;
    }

    CALL_CHECK(se2_write2(0xc3, page_num, flags));

    CHECK_RIGHT(se2_read1() == RC_SUCCESS);
}

// se2_probe()
//
    void
se2_probe(void)
{
    // error handling.
    if(setjmp(error_env)) {
        oled_show(screen_se2_issue);
        LOCKUP_FOREVER();
        // not reached
    }

    // See what's attached. Read serial number and verify it using shared secret
    rng_delay();
    if(rom_secrets->se2.pairing[0] == 0xff) {
        // chip not setup yet, ok in factory
    } else {
        // This is also verifying the pairing secret, effectively.
        uint8_t tmp[32];
        se2_read_page(PGN_ROM_OPTIONS, tmp, true);

        CHECK_RIGHT(check_equal(&tmp[24], rom_secrets->se2.romid, 8));
    }
}

// se2_clear_volatile()
//
// No command to reset the volatile state on this chip! Could
// be sensitive at times. 608 has a watchdog for this!!
//
    void
se2_clear_volatile(void)
{
    // funny business means MitM?
    if(setjmp(error_env)) fatal_mitm();

    uint8_t z32[32] = {0};

    se2_write_page(PGN_PUBKEY_S+0, z32);
    se2_write_page(PGN_PUBKEY_S+1, z32);

    se2_write_buffer(z32, 32);

    // rotate the secret S ... not ideal but only way I've got to change it
    // - also clears ECDH_SECRET_S flag
    CALL_CHECK(se2_write2(0x3c, (2<<6), 0));
    CHECK_RIGHT(se2_read1() == RC_SUCCESS);
}


// se2_set_counter()
//
// Can only be done once. Trusted env.
//
    static void
se2_set_counter(uint32_t val)
{
    uint8_t tmp[32];

    se2_read_page(PGN_DEC_COUNTER, tmp, false);

    // datasheet says will read as "random data" if not yet set, but
    // observed 0xff, 0xff, 0xff, 0...0 (which is an illegal value, since only 17 bits)
    if(tmp[2] == 0xff) {
        tmp[0] = val & 0x0ff;
        tmp[1] = (val >> 8) & 0x0ff;
        tmp[2] = (val >> 16) & 0x01;

        se2_write_page(PGN_DEC_COUNTER, tmp);
    } else {
        puts("ctr set?");        // not expected, but keep going
    }
}

// se2_setup_config()
//
// One-time config and lockdown of the SE2 chip.
//
// CONCERN: Must not be possible to call this function after replacing
// the chip deployed originally. But key secrets would have been lost
// by then anyway... looks harmless, and regardless once the slots
// are locked, none of this code will work... but:
//
// IMPORTANT: If they blocked the real chip, and provided a blank one for
// us to write the (existing) pairing secret into, they would see the pairing
// secret in cleartext. They could then restore original chip and access freely.
//
// But once started, we assume operation in a safe trusted environment
// (ie. the Coinkite factory in Toronto).
//
    void
se2_setup_config(void)
{
    // error handling.
    if((setjmp(error_env))) {
        oled_show(screen_se2_issue);

        LOCKUP_FOREVER();
    }

    if(rom_secrets->se2.pairing[0] != 0xff) {
        // we've been here, so nothing more to do / anything we do will fail, etc.
        return;
    }

    // Global (ram) copy of values to be writen, so we can use them during setup
    memset(&_tbd, 0xff, sizeof(_tbd));

    // pick internal keys
    rng_buffer(_tbd.tpin_key, 32);

    // capture serial of device
    uint8_t tmp[32];
    se2_read_page(PGN_ROM_OPTIONS, tmp, false);

    ASSERT(tmp[1] == 0x00);     // check ANON is not set

    memcpy(_tbd.romid, tmp+24, 8);

    // forget a secret - B (will not be saved)
    rng_buffer(tmp, 32);
    se2_write_page(PGN_SECRET_B, tmp);

    // have chip pick a keypair, record public part for later
    se2_pick_keypair(0, true);
    se2_read_page(PGN_PUBKEY_A,   &_tbd.pubkey_A[0], false);
    se2_read_page(PGN_PUBKEY_A+1, &_tbd.pubkey_A[32], false);

    // Burn privkey B with garbage. Invalid ECC key like this cannot
    // be used (except to make errors)
    memset(tmp, 0, 32);
    se2_write_page(PGN_PRIVKEY_B, tmp);
    se2_write_page(PGN_PRIVKEY_B+1, tmp);
    se2_write_page(PGN_PUBKEY_B, tmp);
    se2_write_page(PGN_PUBKEY_B+1, tmp);

    // pick a paring secret (A)
    do {
        rng_buffer(_tbd.pairing, 32);
    } while(_tbd.pairing[0] == 0xff);
    se2_write_page(PGN_SECRET_A, _tbd.pairing);

    // called the "easy" key, this one requires only SE2 pairing to read/write
    // - so we can wipe it anytime as part of bricking (maybe)
    // - but also so that more than just the paired pubkey w/ SE1 is needed
    rng_buffer(tmp, 32);
    se2_write_page(PGN_SE2_EASY_KEY, tmp);

    // wipe all trick pins and data slots
    memset(tmp, 0, 32);
    for(int pn=0; pn <= PGN_LAST_TRICK; pn++) {
        se2_write_page(pn, tmp);
    }

    // save the shared secrets for ourselves, in flash
    flash_save_se2_data(&_tbd);

    // Now safe to lock down the SE2; failures up to this point could be
    // recovered by picking new values. After this, if main flash corrupt, no
    // way to read these values back, nor replace them with new ones.
    se2_set_protection(PGN_SECRET_A, PROT_WP);
    se2_set_protection(PGN_SECRET_B, PROT_WP);
    se2_set_protection(PGN_PUBKEY_A, PROT_WP);
    se2_set_protection(PGN_PUBKEY_B, PROT_WP);

    se2_set_protection(PGN_SE2_EASY_KEY, PROT_EPH);
    for(int pn=0; pn <= PGN_LAST_TRICK; pn++) {
        se2_set_protection(pn, PROT_EPH);
    }

    se2_set_protection(PGN_ROM_OPTIONS, PROT_APH);       // not planning to change

    // Need known value in counter, write once.
    se2_set_counter(128);

    // NOTE: PGN_SE2_HARD_KEY and PUBKEY_C not yet known
}

// se2_save_auth_pubkey()
//
// Record and enable an ECC pubkey for joining purposes.
// - trusted env. so no need for encrypted comms
//
    void
se2_save_auth_pubkey(const uint8_t pubkey[64])
{
    if(setjmp(error_env)) fatal_mitm();

    ASSERT(check_all_ones(rom_secrets->se2.auth_pubkey, 64));
    memcpy(&_tbd, &rom_secrets->se2, sizeof(_tbd));

    // pick the "hard" key now
    uint8_t     tmp[32];
    rng_buffer(tmp, 32);
    se2_write_page(PGN_SE2_HARD_KEY, tmp);

    // save SE1 pubkey into "pubkey C"
    se2_write_page(PGN_PUBKEY_C, &pubkey[0]);
    se2_write_page(PGN_PUBKEY_C+1, &pubkey[32]);

    memcpy(_tbd.auth_pubkey, pubkey, 64);

    // commit pubkey to mcu flash
    flash_save_se2_data(&_tbd);

    // lock it all up
    se2_set_protection(PGN_SE2_HARD_KEY, PROT_WP | PROT_ECH | PROT_ECW);
    se2_set_protection(PGN_PUBKEY_C, PROT_WP | PROT_RP | PROT_AUTH);
}

// se2_clear_tricks()
//
// Wipe all the trick PIN's and their data.
//
    void
se2_clear_tricks(void)
{
    se2_setup();

    // funny business means MitM?
    if(setjmp(error_env)) fatal_mitm();

    // wipe with all zeros
    uint8_t tmp[32] = {0};
    for(int pn=0; pn <= PGN_LAST_TRICK; pn++) {
        se2_write_encrypted(pn, tmp, 0, SE2_SECRETS->pairing);
    }
}

// se2_read_trick_data()
//
// Read 1 or 2 data slots that immediately follow a trick PIN slot.
//
    void
se2_read_trick_data(int slot_num, uint16_t tc_flags, uint8_t data[64])
{
    if(setjmp(error_env)) fatal_mitm();

    se2_setup();
    se2_read_encrypted(slot_num+1, &data[0], 0, SE2_SECRETS->pairing);

    if(tc_flags & TC_XPRV_WALLET) {
        se2_read_encrypted(slot_num+2, &data[32], 0, SE2_SECRETS->pairing);
    }
}

// se2_test_trick_pin()
//
// Search if this PIN code should trigger a "trick"
// - if not in safety mode, the side-effect (brick, etc) will have happened before this returns
// - will always check all slots so bus traffic doesn't change based on result.
//
    bool
se2_test_trick_pin(const char *pin, int pin_len, trick_slot_t *found_slot, bool safety_mode)
{
    se2_setup();

    // error handling.
    if(setjmp(error_env)) {
        // remember messing w/ i2c bus during operation could lead here.
        if(!safety_mode) fatal_mitm();

        return false;
    }

    // zero-length pin not allowed
    if(!pin_len) return false;

    uint8_t     tpin_hash[32];
    trick_pin_hash(pin, pin_len, tpin_hash);

    // always read all data first, and without any time differences
    uint8_t slots[NUM_TRICKS][32];
    int pn = PGN_TRICK(0);
    for(int i=0; i<NUM_TRICKS; i++, pn++) {
        se2_read_encrypted(pn, slots[i], 0, SE2_SECRETS->pairing);
    }
    se2_clear_volatile();
    
    // Look for matches
    int found = -1;
    uint32_t blank = 0;
    for(int i=0; i<NUM_TRICKS; i++) {
        uint8_t *here = &slots[i][0];
        if(check_equal(here, tpin_hash, 28)) {
            // we have a winner... but keep checking
            found = i;
        }
        blank |= (!!check_all_zeros(here, 32)) << i;
    }
    rng_delay();

    memset(found_slot, 0, sizeof(trick_slot_t));

    if(safety_mode) {
        // tell them which slots are available, iff working after main pin is set
        found_slot->blank_slots = blank;
    }

    if(found >= 0) {
        // match found
        found_slot->slot_num = found;

        // 28 bytes are the PIN hash, last 4 bytes is our meta-data.
        // - xor to pin value to hide flag/arg values (impt for deltamode)
        // - following slot(s) may hold wallet data (32-64 bytes)
        uint8_t     meta[4];
        memcpy(meta, &slots[found][28], 4);
        xor_mixin(meta, &tpin_hash[28], 4);

        memcpy(&found_slot->tc_flags, &meta[0], 2);
        memcpy(&found_slot->tc_arg, &meta[2], 2);

        uint16_t todo = found_slot->tc_flags;

        // hmm: don't need this data if safety is off.. but we have it anyway
        if(found_slot->tc_flags & TC_WORD_WALLET) {
            // it's a 12/24-word BIP-39 seed phrase, un-encrypted.
            if(found+1 < NUM_TRICKS) {
                memcpy(found_slot->xdata, &slots[found+1][0], 32);
            }
        } else if(found_slot->tc_flags & TC_XPRV_WALLET) {
            // it's an xprv-based wallet
            if(found+2 < NUM_TRICKS) {
                memcpy(&found_slot->xdata[0], &slots[found+1][0], 32);
                memcpy(&found_slot->xdata[32], &slots[found+2][0], 32);
            }
        }

        if(!safety_mode && todo) {
#ifdef DEBUG_OUTPUT
            puts2("Trick activated: ");
            puthex4(todo);
            putchar(' ');
#endif

            // code here to brick or wipe
            if(todo & TC_WIPE) {
                // wipe keys - useful to combine with other stuff
                // .. see below if not combined w/ a fatal action
                mcu_key_clear(NULL);
                DEBUG("wiped");

                if(todo == TC_WIPE) {
                    // we wiped, but no faking it out or rebooting, so
                    // show attacker we are wiped, and die.
                    // - need to still allow WIPE+WALLET case
                    oled_show(screen_wiped);
                    LOCKUP_FOREVER();
                }
            }
            if(todo & TC_BRICK) {
                fast_brick();
                // NOT REACHED; unit locks up w/ msg shown
            }
            if(todo & TC_REBOOT) {
                // just reboot, but might look like we wiped secret
                NVIC_SystemReset();
            }
            if(todo & TC_FAKE_OUT) {
                // Pretend PIN was not found...
                // - probably combined w/ wipe above.
                DEBUG("fakeout");
                goto fake_out;
            }
            // TC_DELTA_MODE implemented by caller
        }

        return true;
    } else {
    fake_out:
        // do similar work? 
        found_slot->slot_num = -1;
        rng_delay();

        return false;
    }
}

// se2_save_trick()
//
// Save trick setup. T if okay
//
    int
se2_save_trick(const trick_slot_t *config)
{
    se2_setup();
    if(setjmp(error_env)) {
        return EPIN_SE2_FAIL;
    }

    if((config->slot_num < 0) || (config->slot_num >= NUM_TRICKS) ) {
        return EPIN_RANGE_ERR;
    }
    if((config->slot_num >= NUM_TRICKS-1) && (config->tc_flags & TC_WORD_WALLET) ) {
        // last slot cannot hold a seed-word wallet.
        return EPIN_RANGE_ERR;
    }
    if((config->slot_num >= NUM_TRICKS-2) && (config->tc_flags & TC_XPRV_WALLET) ) {
        // last slot cannot hold an xprv wallet.
        return EPIN_RANGE_ERR;
    }
    if(config->pin_len > sizeof(config->pin)) {
        return EPIN_RANGE_ERR;
    }

    if(config->blank_slots) {
        // blank indicated slots
        uint8_t zeros[32] = { 0 };

        for(int i=0; i<NUM_TRICKS; i++) {
            uint32_t mask = (1 << i);

            if(mask & config->blank_slots) {
                se2_write_encrypted(PGN_TRICK(i), zeros, 0, SE2_SECRETS->pairing);
            }
        }
    } else {
        // construct data to save
        uint8_t     tpin_digest[32];
        trick_pin_hash(config->pin, config->pin_len, tpin_digest);

        // save meta data, xor'd with pin hash
        uint8_t     meta[4];
        memcpy(&meta[0], &config->tc_flags, 2);
        memcpy(&meta[2], &config->tc_arg, 2);
        xor_mixin(&tpin_digest[28], meta, 4);

        // write into SE2
        se2_write_encrypted(PGN_TRICK(config->slot_num), tpin_digest, 0, SE2_SECRETS->pairing);

        if(config->tc_flags & (TC_WORD_WALLET | TC_XPRV_WALLET)) {
            se2_write_encrypted(PGN_TRICK(config->slot_num+1), &config->xdata[0],
                                                                    0, SE2_SECRETS->pairing);
        }
        if(config->tc_flags & TC_XPRV_WALLET) {
            se2_write_encrypted(PGN_TRICK(config->slot_num+2), &config->xdata[32],
                                                                    0, SE2_SECRETS->pairing);
        }
    }

    return 0;
}

// se2_handle_bad_pin()
//
// Attacker (or confused owner) has just given a wrong PIN code (didn't match true
// PIN nor any trick PIN)... maybe do something special.
//
    void 
se2_handle_bad_pin(int num_fails)
{
    trick_slot_t    slot;

    bool is_trick = se2_test_trick_pin("!p", 2, &slot, true);
    if(!is_trick) return;

    // Are we configured to do something in this case?
    if(num_fails >= slot.tc_arg) {
        if(slot.tc_flags & TC_WIPE) {
            // Wipe keys and stop. They can power cycle and keep trying
            // so only do this if a valid key currently exists.
            if(slot.tc_flags & TC_BRICK) {
                // special case TC_WIPE|TC_BRICK
                bool valid;
                const mcu_key_t *cur = mcu_key_get(&valid);
                if(valid) {
                    mcu_key_clear(cur);
                    oled_show(screen_wiped);
                    LOCKUP_FOREVER();
                }
                // else fall-thru if no keys to wipe and WIPE|BRICK mode, will now brick
                // used in "Last Chance" mode

            } else {
                mcu_key_clear(NULL);  // does valid key check
                if(slot.tc_flags == TC_WIPE) {
                    oled_show(screen_wiped);
                    LOCKUP_FOREVER();
                }
            }
        }

        if(slot.tc_flags & TC_BRICK) {
            // Not mutually exclusive: if both flags are set, the first
            // time it's triggered the seed will be wiped (and then lockup)
            // Next wrong pin will not have a seed to clear, and so this
            // brick code will happen.
            fast_brick();
        }

        if(slot.tc_flags & TC_REBOOT) {
            NVIC_SystemReset();
        }
        //if(slot.tc_flags & TC_FAKE_OUT) {//nothing to do here - Silent Wipe}
        //     only used together with TC_WIPE. At this point we are already wiped
        //     EPIN_AUTH_FAIL handled by caller
    }
}

// trick_pin_hash()
//
// Do our hashing of a possible PIN code. Must be:
// - unique per device
// - unrelated to hashing of any other PIN codes
// - so doing hmac-sha256 with unique key
//
    void
trick_pin_hash(const char *pin, int pin_len, uint8_t tpin_hash[32])
{
    ASSERT(pin_len >= 0);           // 12-12 typical, but empty = blank PIN

    HMAC_CTX ctx;

    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, (uint8_t *)pin, pin_len);
    hmac_sha256_final(&ctx, SE2_SECRETS->tpin_key, tpin_hash);

    // and a double SHA for good measure
    sha256_single(tpin_hash, 32, tpin_hash);
    sha256_single(tpin_hash, 32, tpin_hash);
}


// rng_for_uECC()
//
    static int
rng_for_uECC(uint8_t *dest, unsigned size)
{
    /* The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
    'dest' was filled with random data, or 0 if the random data could not be generated.
    The filled-in values should be either truly random, or from a cryptographically-secure PRNG.

    typedef int (*uECC_RNG_Function)(uint8_t *dest, unsigned size);
    */
    rng_buffer(dest, size);

    return 1;
}


// p256_gen_keypair()
//
    void
p256_gen_keypair(uint8_t privkey[32], uint8_t pubkey[64])
{
    uECC_set_rng(rng_for_uECC);

    int ok = uECC_make_key(pubkey, privkey, uECC_secp256r1());
    ASSERT(ok == 1);
}

#if 0
// p256_sign()
//
    void
p256_sign(const uint8_t privkey[32], const uint8_t digest[32], uint8_t signature[64])
{
    uECC_set_rng(rng_for_uECC);

    int ok = uECC_sign(privkey, digest, 32, signature, uECC_secp256r1());
    ASSERT(ok == 1);
}

// p256_verify()
//
    bool
p256_verify(const uint8_t pubkey[64], const uint8_t digest[32], const uint8_t signature[64])
{
    return uECC_verify(pubkey, digest, 32, signature, uECC_secp256r1());
}
#endif


// ps256_ecdh()
//
    void
ps256_ecdh(const uint8_t pubkey[64], const uint8_t privkey[32], uint8_t result[32])
{
    uECC_set_rng(rng_for_uECC);

    int ok = uECC_shared_secret(pubkey, privkey, result, uECC_secp256r1());
    ASSERT(ok == 1);
}


// se2_setup()
//
    void
se2_setup(void)
{
    if(i2c_port.Instance == I2C2) {
        return;
    }

    STATIC_ASSERT(sizeof(trick_slot_t) == 128);
    STATIC_ASSERT(offsetof(trick_slot_t, slot_num) == 0);
    STATIC_ASSERT(offsetof(trick_slot_t, tc_flags) == 4);
    STATIC_ASSERT(offsetof(trick_slot_t, tc_arg) == 6);
    STATIC_ASSERT(offsetof(trick_slot_t, xdata) == 8);
    STATIC_ASSERT(offsetof(trick_slot_t, pin) == 8+64);
    STATIC_ASSERT(offsetof(trick_slot_t, pin_len) == 8+64+16);
    STATIC_ASSERT(offsetof(trick_slot_t, blank_slots) == 8+64+16+4);
    STATIC_ASSERT(offsetof(trick_slot_t, spare) == 8+64+16+4+4);

    // unlikely we need:
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_I2C2_CLK_ENABLE();

    // I2C2 bus is dedicated to our DS28C36B part.
    // - B13 and B14
    GPIO_InitTypeDef setup = {
        .Pin = GPIO_PIN_13 | GPIO_PIN_14,
        .Mode = GPIO_MODE_AF_OD,
        .Pull = GPIO_NOPULL,
        .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
        .Alternate = GPIO_AF4_I2C2,
    };
    HAL_GPIO_Init(GPIOB, &setup);

    // Setup HAL device
    memset(&i2c_port, 0, sizeof(i2c_port));
    i2c_port.Instance = I2C2;

    // see I2C_InitTypeDef
    i2c_port.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    //i2c_port.Init.Timing = 0x0050174f;     // ie. 1Mhz "fast mode plus" in CubeMX @ 120Mhz
    i2c_port.Init.Timing = 0x00b03fb8;     // 400khz "fast mode" in CubeMX @ 120Mhz (measured ok)
    //i2c_port.Init.Timing = 0xf01075ff;     // 40khz "std mode" in CubeMX @ 120Mhz (works)
    i2c_port.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;

    HAL_StatusTypeDef rv = HAL_I2C_Init(&i2c_port);
    ASSERT(rv == HAL_OK);

    // compile time checks
    STATIC_ASSERT(offsetof(rom_secrets_t, se2) % 8 == 0);
    STATIC_ASSERT(PGN_LAST_TRICK < PGN_SE2_EASY_KEY);
}

// se2_read_hard_secret()
//
    static bool
se2_read_hard_secret(uint8_t hard_key[32], const uint8_t pin_digest[32])
{
    if(setjmp(error_env)) {
        DEBUG("se2_read_hard_secret");
        return true;
    }

    // To read the "hard" key from SE1, we need to prove we know the
    // pubkey_C private key by signing a message. That message is the pubkey
    // we want to used for ECDH on our side. Doing ECDH with SE1 will
    // generate a shared secret for decryption (held in "secret S" of SE2).
    // SE1 holds the auth keypair (private part), and that slot is authorized
    // by main pin.
    // 
    // - tell se2 the pubkey for this op
    // - sign a 64 byte msg, which includes that pubkey
    // - use the pubkey A value (from SE1) to do ECDH => shared secret
    // - use shared secret to read slot w/ the hard key in it.
    //
    SHA256_CTX ctx;

    // pick a temp key pair, share public part w/ SE2
    uint8_t tmp_privkey[32], tmp_pubkey[64];
    p256_gen_keypair(tmp_privkey, tmp_pubkey);

    // - this can be mitm-ed, but we sign it next so doesn't matter
    se2_write_page(PGN_PUBKEY_S, &tmp_pubkey[0]);
    se2_write_page(PGN_PUBKEY_S+1, &tmp_pubkey[32]);

    // pick nonce
    uint8_t chal[32+32];
    rng_buffer(chal, sizeof(chal));
    se2_write_buffer(chal, sizeof(chal));

    // md = ngu.hash.sha256s(T_pubkey + chal[0:32])
    sha256_init(&ctx);
    sha256_update(&ctx, tmp_pubkey, 64);
    sha256_update(&ctx, chal, 32);      // only first 32 bytes

    uint8_t md[32];
    sha256_final(&ctx, md);

    // Get that digest signed by SE1 now, and doing that requires
    // the main pin, because the required slot requires auth by that key.
    // - this is the critical step attackers would not be able to emulate w/o SE1 contents
    // - fails here if PIN wrong
    uint8_t signature[64];
    int arc = ae_sign_authed(KEYNUM_joiner_key, md, signature, KEYNUM_main_pin, pin_digest);
    CHECK_RIGHT(arc == 0);

    // "Authenticate ECDSA Public Key" = 0xA8
    // cs_offset=32   ecdh_keynum=0=pubA ECDH=1 WR=0
    uint8_t param = ((32-1) << 3) | (0 << 2) | 0x2;
    se2_write_n(0xA8, &param, signature, 64);
    CHECK_RIGHT(se2_read1() == RC_SUCCESS);

    uint8_t shared_x[32], shared_secret[32];
    ps256_ecdh(rom_secrets->se2.pubkey_A, tmp_privkey, shared_x);

    // shared secret S will be SHA over X of shared ECDH point + chal[32:]
    //  s = ngu.hash.sha256s(x + chal[32:])
    sha256_init(&ctx);
    sha256_update(&ctx, shared_x, 32);
    sha256_update(&ctx, &chal[32], 32);      // second half
    sha256_final(&ctx, shared_secret);

    se2_read_encrypted(PGN_SE2_HARD_KEY, hard_key, 2, shared_secret);

    // CONCERN: secret "S" is retained in SE2's sram. No API to clear it.
    // - but you'd need to see our copy of that value to make use of it
    // - and PIN checked already to get here, so you could re-do anyway
    se2_clear_volatile();

    return false;
}

// se2_calc_seed_key()
//
    static bool
se2_calc_seed_key(uint8_t aes_key[32], const mcu_key_t *mcu_key, const uint8_t pin_digest[32])
{
    // Gather key parts from all over. Combine them w/ HMAC into a AES-256 key
    uint8_t se1_easy_key[32], se1_hard_key[32];
    se2_read_encrypted(PGN_SE2_EASY_KEY, se1_easy_key, 0, rom_secrets->se2.pairing);

    if(se2_read_hard_secret(se1_hard_key, pin_digest)) return true;

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, mcu_key->value, 32);
    hmac_sha256_update(&ctx, se1_hard_key, 32);
    hmac_sha256_update(&ctx, se1_easy_key, 32);

    // combine them all using anther MCU key via HMAC-SHA256
    hmac_sha256_final(&ctx, rom_secrets->mcu_hmac_key, aes_key);
    hmac_sha256_init(&ctx);     // clear secrets

    return false;
}

// se2_encrypt_secret()
//
    bool
se2_encrypt_secret(const uint8_t secret[], int secret_len, int offset, 
    uint8_t main_slot[], uint8_t *check_value,
    const uint8_t pin_digest[32])
{
    se2_setup();

    bool is_valid;
    const mcu_key_t *cur = mcu_key_get(&is_valid);

    if(!is_valid) {
        if(!check_value) {
            // problem: we are not writing the check value but it would be changed.
            // ie: change long secret before real secret--unlikely
            return true;
        }

        // pick a fresh MCU key if we don't have one; can do that
        // because we are encryption and saving (presumably for first time)
        // - will become a brick if no more slots
        cur = mcu_key_pick();     
    }

    uint8_t aes_key[32];
    if(se2_calc_seed_key(aes_key, cur, pin_digest)) return true;

    uint8_t nonce[16];
    memcpy(nonce, rom_secrets->mcu_hmac_key, sizeof(nonce)-1);
    nonce[15] = offset / AES_BLOCK_SIZE;

    // encrypt the secret
    AES_CTX ctx;
    aes_init(&ctx);
    aes_add(&ctx, secret, secret_len);
    aes_done(&ctx, main_slot, secret_len, aes_key, nonce);

    if(check_value) {
        // encrypt the check value: 32 zeros
        aes_init(&ctx);
        ctx.num_pending = 32;
        aes_done(&ctx, check_value, 32, aes_key, nonce);
    }

    return false;
}

// se2_decrypt_secret()
//
    void
se2_decrypt_secret(uint8_t secret[], int secret_len, int offset,
        const uint8_t main_slot[], const uint8_t *check_value,
        const uint8_t pin_digest[32], bool *is_valid)
{
    se2_setup();

    const mcu_key_t *cur = mcu_key_get(is_valid);
    if(!*is_valid) {
        // no key set? won't be able to decrypt.
        return;
    }

    int line_num;
    if((line_num = setjmp(error_env))) {
        // internal failures / broken i2c buses will come here
        *is_valid = false;
        return;
    }

    AES_CTX ctx;
    uint8_t aes_key[32];
    if(se2_calc_seed_key(aes_key, cur, pin_digest)) {
        // key fetch, perhaps pin digest wrong?
        *is_valid = false;
        return;
    }

    uint8_t nonce[16];
    memcpy(nonce, rom_secrets->mcu_hmac_key, sizeof(nonce)-1);
    nonce[15] = offset / AES_BLOCK_SIZE;

    if(check_value) {
        // decrypt the check value
        aes_init(&ctx);
        aes_add(&ctx, check_value, 32);
        uint8_t got[32];
        aes_done(&ctx, got, 32, aes_key, nonce);

        // does it work?
        if(!check_all_zeros(got, 32)) {
            DEBUG("bad chk");
            *is_valid = false;

            return;
        }
    }

    // decrypt the real data
    aes_init(&ctx);
    aes_add(&ctx, main_slot, secret_len);
    aes_done(&ctx, secret, secret_len, aes_key, nonce);
}

// Key-stretching iteration count. Targeting 1s to rate-limit pin attempts
// 150 =>  881ms
// 170 =>  999.2ms
// 175 => 1028ms
// 180 => 1058ms
// 200 => 1175ms
#define SE2_STRETCH_ITER        170

// se2_pin_hash()
//
// Hash up a PIN code for login attempt: to tie it into SE2's contents.
//
    void
se2_pin_hash(uint8_t digest_io[32], uint32_t purpose)
{
    if(purpose != PIN_PURPOSE_NORMAL) {
        // do nothing except for real PIN case (ie. not for prefix words)
        return;
    }

    se2_setup();
    if((setjmp(error_env))) {
        oled_show(screen_se2_issue);

        LOCKUP_FOREVER();
    }

    uint8_t     rx[34];     // 2 bytes of len+status, then 32 bytes of data
    uint8_t     tmp[32];
    HMAC_CTX    ctx;

    // HMAC(key=tpin_key, msg=given hash so far)
    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, digest_io, 32);
    hmac_sha256_update(&ctx, (uint8_t *)&purpose, 4);
    hmac_sha256_final(&ctx, SE2_SECRETS->tpin_key, tmp);

    // NOTE: exposed as cleartext here
    se2_write_buffer(tmp, 32);

    for(int i=0; i<SE2_STRETCH_ITER; i++) {
        if(i) {
            se2_write_buffer(rx+2, 32);
        }

        // HMAC(key=secret-B, msg=consts+easy_key+buffer+consts)
        // - result put in secret-S (ram)
        CALL_CHECK(se2_write2(0x3c, (2<<6) | (1<<4) | PGN_SE2_EASY_KEY, 0));
        CHECK_RIGHT(se2_read1() == RC_SUCCESS);

        // HMAC(key=S, msg=counter+junk), so we have something to read out
        // - not 100% clear what contents of 'buffer' are here, but seems
        //   to be deterministic and unchanged from prev command
        CALL_CHECK(se2_write1(0xa5, (2<<5) | PGN_DEC_COUNTER));

        CHECK_RIGHT(se2_read_n(sizeof(rx), rx) == RC_SUCCESS);
        CHECK_RIGHT(rx[1] == RC_SUCCESS);
    }

    // one final HMAC because we had to read cleartext from bus
    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, rx+2, 32);
    hmac_sha256_update(&ctx, digest_io, 32);
    hmac_sha256_final(&ctx, SE2_SECRETS->tpin_key, digest_io);
}

// se2_read_rng()
//
// Read some random bytes, which we know cannot be MitM'ed.
//
    void
se2_read_rng(uint8_t value[8])
{
    // funny business means MitM here
    se2_setup();
    if(setjmp(error_env)) fatal_mitm();

    // read a field with "RPS" bytes, and verify those were read true
    uint8_t tmp[32];
    se2_read_page(PGN_ROM_OPTIONS, tmp, true);

    memcpy(value, &tmp[4], 8);
}

// EOF
