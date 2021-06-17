/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * se2.c -- Talk to DS28C36B chip which is our second secure element.
 *
 */
#include "basics.h"
#include "se2.h"
#include "verify.h"
#include "psram.h"
#include "faster_sha256.h"
#include "assets/screens.h"
#include "oled.h"
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

// page protection bitmask (Table 11)
#define PROT_RP	    	0x01
#define PROT_WP	    	0x02
#define PROT_EM	    	0x04
#define PROT_APH		0x08
#define PROT_EPH		0x10
#define PROT_AUTH		0x20
#define PROT_ECH		0x40
#define PROT_ECW		0x80


#if 0
// se2_write0()
//
    static bool
se2_write0(uint8_t cmd)
{
    HAL_StatusTypeDef rv = HAL_I2C_Master_Transmit(&i2c_port, I2C_ADDR, &cmd, 1, HAL_MAX_DELAY);

    return (rv != HAL_OK);
}
#endif

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

#if 0
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
#endif

// se2_write_n()
//
    static bool
se2_write_n(uint8_t cmd, const uint8_t *args, uint8_t len)
{
    uint8_t data[2+len];
    data[0] = cmd;
    data[1] = len;
    memcpy(data+2, args, len);

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
    CALL_CHECK(se2_write_n(0x87, data, len));
}

// se2_read_page()
//
// Must always authenticate what we read, because just normal read (no encryption)
// does not have any MiTM protection at all.
//
    void
se2_read_page(uint8_t page_num, uint8_t data[32])
{
    CALL_CHECK(se2_write1(0x69, page_num));

    uint8_t rx[2+32];
    CHECK_RIGHT(se2_read_n(sizeof(rx), rx) == RC_SUCCESS);

    CHECK_RIGHT(rx[0] == 33);
    CHECK_RIGHT(rx[1] == RC_SUCCESS);

    memcpy(data, rx+2, 32);

    // "Compute and Read Page Authentication" using HMAC secret A

    // .. pick a nonce
    uint8_t chal[32];
    rng_buffer(chal, sizeof(chal));
    se2_write_buffer(chal, sizeof(chal));
    
    // .. do it
    CALL_CHECK(se2_write1(0xa5, (0<<5) | page_num));

    uint8_t check[34];
    CHECK_RIGHT(se2_read_n(sizeof(check), check) == RC_SUCCESS);

    // .. see if we can arrive at same HMAC result.


    const uint8_t *romid = rom_secrets->se2_romid;
    if(check_all_ones(romid, 8)) {
        // We don't know romid at this point. Trust their answer for now (factory case).
        CHECK_RIGHT(page_num == PGN_ROM_OPTIONS);
        romid = &data[24];
    }

    HMAC_CTX ctx;
    hmac_sha256_init(&ctx);

    //  msg = self.rom_id + expected + chal + bytes([page_num]) + self.manid
    hmac_sha256_update(&ctx, romid, 8);
    hmac_sha256_update(&ctx, data, 32);
    hmac_sha256_update(&ctx, chal, 32);
    hmac_sha256_update(&ctx, &page_num, 1);
    hmac_sha256_update(&ctx, DEV_MANID, 2);

    uint8_t expect[32];
    hmac_sha256_final(&ctx, rom_secrets->se2_pairing, expect);

    CHECK_RIGHT(check_equal(expect, check+2, 32));
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

        return true;
    }

    // See what's attached. Read serial number and verify it using shared secret
    // - if we haven't setup chip, the secret is all ones, but still needs to check
    uint8_t tmp[32];

    se2_read_page(PGN_ROM_OPTIONS, tmp);


    return false;
}

// se2_setup_config()
//
// One-time config and lockdown of the chip
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
    void
se2_setup_config(void)
{
    // XXX
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


// EOF
