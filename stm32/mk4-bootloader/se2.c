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
#include "assets/screens.h"
#include "console.h"
#include "constant_time.h"
#include "misc.h"
#include "rng.h"
#include "gpio.h"
#include "delay.h"
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
#define PGN_TRICK_PIN(n)    (0+(2*(n)))
#define PGN_TRICK_DATA(n)   (1+(2*(n)))
#define PGN_LAST_TRICK      PGN_TRICK_DATA(NUM_TRICKS-1)
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

// forward defs...
void se2_read_encrypted(uint8_t page_num, uint8_t data[32], int keynum, const uint8_t *secret);

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
    if(!keynum) {
        CHECK_RIGHT(se2_verify_page(page_num, data, keynum, secret));
    } else {
        CHECK_RIGHT(se2_verify_page(page_num, data, 0, rom_secrets->se2.pairing));
    }
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
    bool
se2_probe(void)
{
    // error handling.
    int line_num;
    if((line_num = setjmp(error_env))) {
        puts2("se2_probe: se2.c:");
        putdec4(line_num);
        putchar('\n');

        oled_show(screen_se2_issue);

        return true;
    }

    // See what's attached. Read serial number and verify it using shared secret
    rng_delay();
    if(rom_secrets->se2.pairing[0] == 0xff) {
        // chip not setup yet, ok in factory
        return false;
    } else {
        // This is also verifying the pairing secret, effectively.
        uint8_t tmp[32];
        se2_read_page(PGN_ROM_OPTIONS, tmp, true);

        CHECK_RIGHT(check_equal(&tmp[24], rom_secrets->se2.romid, 8));
    }

    return false;
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

// se2_setup_config()
//
// One-time config and lockdown of the SE2 chip.
//
// CONCERN: Must not be possible to call this function after replacing
// the chip deployed originally. But key secrets would have been lost
// by then anyway... looks harmless, and regardless once the datazone
// is locked, none of this code will work... but:
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
    int line_num;
    if((line_num = setjmp(error_env))) {
        puts2("se2_setup_config: se2.c:");
        putdec4(line_num);
        putchar('\n');

        oled_show(screen_se2_issue);

        LOCKUP_FOREVER();
    }

    if(rom_secrets->se2.pairing[0] != 0xff) {
        // we've been here, so nothing more to do
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

    // forget a secret - B
    rng_buffer(tmp, 32);
    se2_write_page(PGN_SECRET_B, tmp);

    // have chip pick a keypair, record public part for later
    se2_pick_keypair(0, false);
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
    //se2_set_protection(PGN_SECRET_A, PROT_RP|PROT_WP);

    // called the "easy" key, this one requires only SE2 pairing to read/write
    // - so we can wipe it anytime as part of bricking maybe
    // - but also so that more than just the paired pubkey w/ SE1 is needed
    rng_buffer(tmp, 32);
    se2_set_protection(PGN_SE2_EASY_KEY, PROT_EPH);
    se2_write_encrypted(PGN_SE2_EASY_KEY, tmp, 0, _tbd.pairing);

    // wipe all trick pins and their data slots
    memset(tmp, 0, 32);
    for(int pn=0; pn < PGN_LAST_TRICK; pn++) {
        se2_set_protection(pn, PROT_EPH);
        se2_write_encrypted(pn, tmp, 0, _tbd.pairing);
    }

    // TODO: check slot protections.
    //se2_set_protection(PGN_ROM_OPTIONS, PROT_WP); // untested, not indicated in datasheet

    // save the shared secrets for ourselves, in flash
    flash_save_se2_data(&_tbd);
}

// se2_save_auth_pubkey()
//
// Record and enable an ECC pubkey for joining purposes.
// - trusted env. no need for encrypted comms
//
    void
se2_save_auth_pubkey(const uint8_t pubkey[64])
{
    if(setjmp(error_env)) fatal_mitm();

    ASSERT(check_all_ones(rom_secrets->se2.auth_pubkey, 64));
    memcpy(&_tbd, &rom_secrets->se2, sizeof(_tbd));

    // pick the "hard" key now, while it's easy to set
    uint8_t     tmp[32];
    rng_buffer(tmp, 32);
    se2_write_page(PGN_SE2_HARD_KEY, tmp);

    // save to "pubkey C"
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
    // funny business means MitM?
    if(setjmp(error_env)) fatal_mitm();

    // wipe with all zeros
    uint8_t tmp[32] = {0};
    for(int pn=0; pn < PGN_LAST_TRICK; pn++) {
        se2_write_encrypted(pn, tmp, 0, SE2_SECRETS->pairing);
    }
}

// se2_test_trick_pin()
//
// search if this PIN code should trigger a "trick"
// - if not in safety mode, the side-effect (brick, etc) will have happened before this returns
// - will always check all slots so bus traffic doesn't change based on result.
//
    bool
se2_test_trick_pin(const uint8_t tpin_hash[32], trick_slot_t *found_slot, bool safety_mode)
{
    // error handling.
    int line_num;
    if((line_num = setjmp(error_env))) {
        puts2("se2_test_trick_pin: se2.c:"); putdec4(line_num); putchar('\n');

        return false;
    }

    // always read all data first, and without any time differences
    uint8_t slots[NUM_TRICKS*2][32];

    int pn = PGN_TRICK_PIN(0);
    for(int i=0; i<NUM_TRICKS; i++, pn++) {
        se2_read_encrypted(pn, slots[i], 0, SE2_SECRETS->pairing);
    }
    se2_clear_volatile();
    
    // Look for matches
    int found = -1;
    uint32_t blank = 0;
    for(int i=0; i<NUM_TRICKS; i++) {
        uint8_t *here = &slots[i*2][0];
        if(check_equal(here, tpin_hash, 32)) {
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

        // 32 bytes available... first 2 are if all the same, it's just a code.
        uint16_t *data = (uint16_t *)&slots[(found*2) + 1][0];
        bool all_same = true;
        for(int j=1; j<16; j++) {
            if(data[0] != data[j]) {
                all_same = false;
            }
        }
        rng_delay();

        if(all_same) {
            found_slot->tc_flags = data[0] >> 8;
            found_slot->arg = data[0] & 0xff;

            uint8_t todo = found_slot->tc_flags & TC_BOOTROM_MASK;

            if(!safety_mode && todo) {
                puts2("Trick activated: ");
                puthex2(todo);
                putchar(' ');

                // code here to brick or wipe
                if(todo & (TC_WIPE | TC_BRICK)) {
                    // wipe keys
                    mcu_key_clear(NULL);
                    puts2("wiped ");
                }
                if(todo & TC_BRICK) {
                    puts2("bricked ");

                    mcu_fast_brick();
                    // NOT REACHED
                }
                if(todo & TC_FAKE_OUT) {
                    // was probably combined w/ wipe above.
                    puts("fakeout");
                    goto fake_out;
                }
                putchar('\n');
            }
        } else {
            // it's a 24-word BIP-39 seed phrase, un-encrypted.
            found_slot->tc_flags = TC_WALLET;
            memcpy(found_slot->seed_words, data, 32);
        }

        return true;
    } else {
    fake_out:
        // do similar work? 
        found_slot->slot_num = -1;
        rng_delay();
        rng_delay();

        return false;
    }
}

// se2_setup_trick()
//
// Save trick setup. T if okay
//
    bool
se2_setup_trick(const trick_slot_t *config)
{
    return false;
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
    ASSERT(pin_len >= 5);           // 12-12

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


// p256_verify()
//
    bool
p256_verify(const uint8_t pubkey[64], const uint8_t digest[32], const uint8_t signature[64])
{
    return uECC_verify(pubkey, digest, 32, signature, uECC_secp256r1());
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

// p256_sign()
//
    void
p256_sign(const uint8_t privkey[32], const uint8_t digest[32], uint8_t signature[64])
{
    uECC_set_rng(rng_for_uECC);

    int ok = uECC_sign(privkey, digest, 32, signature, uECC_secp256r1());
    ASSERT(ok == 1);
}


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

    // compile time, but not quite
    ASSERT((((uint32_t)&rom_secrets->se2) & 0x3f) == 0);

    STATIC_ASSERT(PGN_LAST_TRICK < PGN_SE2_EASY_KEY);

#if 0
    while(1) {
        uint8_t data[3] = { 0x69, 1, 28 };
        rv = HAL_I2C_Master_Transmit(&i2c_port, I2C_ADDR, data, sizeof(data), HAL_MAX_DELAY);
        if(rv != HAL_OK) {
            puts("tx fail");
        }

        delay_ms(3);

        uint8_t rx[32+2] = {};
        rv = HAL_I2C_Master_Receive(&i2c_port, I2C_ADDR, rx, sizeof(rx), HAL_MAX_DELAY);
        if(rv != HAL_OK) {
            puts("rx fail");
        }

        //delay_ms(5);
    }
#endif
#if 0
    while(1) {
        if(se2_write1(0x69, 28)) {
            puts("tx fail");
            continue;
        }

        uint8_t rx[34];
        if(se2_read_n(sizeof(rx), rx)) {
            puts("rx fail");
            continue;
        }
        //hex_dump(rx+2, 32);
    }
#endif
}

// se2_read_hard_secret()
//
    void
se2_read_hard_secret(uint8_t hard_key[32], const uint8_t pin_digest[32])
{
    int line_num;
    if((line_num = setjmp(error_env))) {
        puts2("se2_read_hard_secret: se2.c:"); putdec4(line_num); putchar('\n');
//      INCONSISTENT("hard");
        return;
    }

    // To read the "hard" key from SE1, we need to prove we know the
    // pubkey_C private key by signing a message. Then we do ECDH to
    // generate a shared secret for decryption (held in S). Only SE2 has
    // the private key and we need to work via it's API.
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
    uint8_t signature[64];
    int arc = ae_sign_authed(KEYNUM_joiner_key, md, signature, KEYNUM_main_pin, pin_digest);
    CHECK_RIGHT(arc == 0);

    // "Authenticate ECDSA Public Key" = 0xA8
    // cs_offset=32   ecdh_keynum=0=pubA ECDH=1 WR=0
    uint8_t param = ((32-1) << 3) | (0 << 2) | 0x2;
    se2_write_n(0xA8, &param, signature, 64);
    CHECK_RIGHT(se2_read1() == RC_SUCCESS);

    uint8_t shared_x[32], shared_secret[32];
    uint8_t his_pubkey[64];
    se2_read_page(PGN_PUBKEY_A, &his_pubkey[0], false);
    se2_read_page(PGN_PUBKEY_A+1, &his_pubkey[32], false);
    ps256_ecdh(his_pubkey, tmp_privkey, shared_x);
    //ps256_ecdh(rom_secrets->se2.pubkey_A, tmp_privkey, shared_x);

    // shared secret S will be SHA over X of shared ECDH point + chal[32:]
    //  s = ngu.hash.sha256s(x + chal[32:])
    sha256_init(&ctx);
    sha256_update(&ctx, shared_x, 32);
    sha256_update(&ctx, &chal[32], 32);      // second half
    sha256_final(&ctx, shared_secret);

    puts2("got shared sec: "); hex_dump(shared_secret, 32);

    se2_read_encrypted(PGN_SE2_HARD_KEY, hard_key, 2, shared_secret);

    puts2("hard: ");
    hex_dump(hard_key, 32);

#if 0
>>> SE2.read_enc_page(14, 2)
b'\xd4]\xef\x00\x01\xb3\xd6\xac\xe2\x06u^k\x9fr\xafi\xff\xbb\xef\xea\xd5:\r\x05\x04m\xc3\xc2\xedz"'
>>> 
>>> SE2.read_enc_page(15, 2)
b'\x1d\xfc\xe3\xb0\xcdP\x1e\x8a\xc8G\x07B\xc2\x88$\x11\xaah\xf0\xa7\x1f-\xf7\x8e\x98 Ep\xab\x8e:\x03'
#endif

#if 0
    def setup_auth(self, ecdh_kn=0):
        # do "Authenticate ECDSA Public Key" proving we know the privkey for
        # pubkey held in slot C. Set volatile state: AUTH and maybe W_PUB_KEY and S
        # - must enable ECDH because we want to read using this authority
        # - lengths/offsets are all messed in spec
        # - only supporting READ; we will do our writes before locking page(s)

        # this is remembered in SRAM, but needed in general
        self.write_page(PGN_PUBKEY_S+0, T_pubkey[:32])
        self.write_page(PGN_PUBKEY_S+1, T_pubkey[32:])

        chal = ngu.random.bytes(32+32)
        self.write_buffer(chal)

        cs_offset = 32      # very confusing, might be implied by buffer length?

        md = ngu.hash.sha256s(T_pubkey + chal[0:32])

        args = bytearray(T_privkey + md + bytes(64))
        rv = ckcc.gate(32, args, 0)
        assert rv == 0

        sig = bytes(args[-64:])

        args = bytearray()
        args.append( ((cs_offset-1) << 3) | (ecdh_kn << 2) | 0x2 )
        args.extend(sig)

        self._write(0xa8, args)
        self._check_result(self._read1())

        print('auth ok')

        # ecdh multi
        pubkey_pn = PGN_PUBKEY_A + (ecdh_kn*2)
        their_pubkey = self.read_page(pubkey_pn) + self.read_page(pubkey_pn+1)

        args = bytearray(their_pubkey + T_privkey + bytes(32))
        rv = ckcc.gate(33, args, 0)
        assert rv == 0
        x = args[-32:]

        # shared secret S will be SHA over X of shared ECDH point + chal[32:]
        s = ngu.hash.sha256s(x + chal[32:])

        self.shared_secret = s

        return True
#endif

}

// se2_calc_seed_key()
//
    static void
se2_calc_seed_key(uint8_t aes_key[32], const mcu_key_t *mcu_key, const uint8_t pin_digest[32])
{
    // Gather key parts from all over. Combine them w/ HMAC into a AES-256 key

    uint8_t se1_easy_key[32], se1_hard_key[32];
    se2_read_encrypted(PGN_SE2_EASY_KEY, se1_easy_key, 0, rom_secrets->se2.pairing);

    se2_read_hard_secret(se1_hard_key, pin_digest);

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);
    hmac_sha256_update(&ctx, mcu_key->value, 32);
    hmac_sha256_update(&ctx, se1_hard_key, 32);
    hmac_sha256_update(&ctx, se1_easy_key, 32);

    // combine them all using anther MCU key via HMAC-SHA256
    hmac_sha256_final(&ctx, rom_secrets->mcu_hmac_key, aes_key);
    hmac_sha256_init(&ctx);     // clear secrets
}

// se2_encrypt_secret()
//
    void
se2_encrypt_secret(const uint8_t secret[], int secret_len, 
    uint8_t main_slot[], uint8_t check_value[32],
    const uint8_t pin_digest[32])
{
    bool is_valid;
    const mcu_key_t *cur = mcu_key_get(&is_valid);

    if(!is_valid) {
        // pick a fresh MCU key if we don't have one; can do that
        // because we are encryption and saving (presumably for first time)
        // - will become a brick if no more slots
        cur = mcu_key_pick();     
    }

    uint8_t aes_key[32];
    se2_calc_seed_key(aes_key, cur, pin_digest);

    // encrypt the secret
    AES_CTX ctx;
    aes_init(&ctx);
    aes_add(&ctx, secret, secret_len);
    aes_done(&ctx, main_slot, secret_len, aes_key, rom_secrets->mcu_hmac_key);

    // encrypt the check value: 32 zeros
    aes_init(&ctx);
    ctx.num_pending = 32;
    aes_done(&ctx, check_value, 32, aes_key, rom_secrets->mcu_hmac_key);
}

// se2_decrypt_secret()
//
    void
se2_decrypt_secret(uint8_t secret[], int secret_len, 
        const uint8_t main_slot[], const uint8_t check_value[32],
        const uint8_t pin_digest[32], bool *is_valid)
{
    const mcu_key_t *cur = mcu_key_get(is_valid);
    if(!*is_valid) {
        puts("?blk");
        return;
    }

    uint8_t aes_key[32];
    se2_calc_seed_key(aes_key, cur, pin_digest);

    // decrypt the check value
    AES_CTX ctx;
    aes_init(&ctx);
    aes_add(&ctx, check_value, 32);
    uint8_t got[32];
    aes_done(&ctx, got, 32, aes_key, rom_secrets->mcu_hmac_key);

    if(!check_all_zeros(got, 32)) {
        puts("!chk");
        *is_valid = false;

        return;
    }

    // decrypt the real data
    aes_init(&ctx);
    aes_add(&ctx, main_slot, secret_len);
    aes_done(&ctx, secret, secret_len, aes_key, rom_secrets->mcu_hmac_key);
}

void se2_testcode(void)
{
    uint8_t pin_digest[32] = { 0 };
    uint8_t msg[72] = { 1,2,3};

#if 1
    uint8_t main_slot[72], check[32];

    se2_encrypt_secret(msg, sizeof(msg), main_slot, check, pin_digest);
    return;
#else
    uint8_t main_slot[72] = {0x71, 0xde, 0xae, 0x7f, 0x1, 0xca, 0x23, 0x4d, 0xcc, 0x9c, 0xfc, 0x3a, 
  0x37, 0xd0, 0x4b, 0xc5, 0xa2, 0xb1, 0x24, 0x4c, 0x43, 0xcd, 0x56, 0xf7, 
  0x6b, 0xa9, 0xba, 0x7e, 0x31, 0x4a, 0x1a, 0x81, 0x6c, 0xb3, 0x96, 0xed, 
  0x2f, 0xb4, 0x6e, 0x9b, 0xf8, 0xe4, 0x4f, 0xe0, 0xc, 0xc7, 0xbb, 0x69, 0xd3, 
  0x65, 0x4c, 0x19, 0x39, 0x29, 0xa8, 0x24, 0x6e, 0x23, 0x55, 0xe3, 0xea, 
  0x1b, 0x84, 0x9d, 0xf, 0xf5, 0x3b, 0x2f, 0x57, 0xd1, 0x6, 0x1f };
    uint8_t check[32] = { 0x70, 0xdc, 0xad, 0x7f, 0x1, 0xca, 0x23, 0x4d, 0xcc, 0x9c, 0xfc, 0x3a, 
  0x37, 0xd0, 0x4b, 0xc5, 0xa2, 0xb1, 0x24, 0x4c, 0x43, 0xcd, 0x56, 0xf7, 
  0x6b, 0xa9, 0xba, 0x7e, 0x31, 0x4a, 0x1a, 0x81 };
#endif

    uint8_t result[72];
    bool worked;
    se2_decrypt_secret(result, 72, main_slot, check, pin_digest, &worked);

    ASSERT(worked);
    ASSERT(check_equal(result, msg, 72));
}

// EOF
