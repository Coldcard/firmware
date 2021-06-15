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
#include "misc.h"
#include "rng.h"
#include "gpio.h"
#include "delay.h"
#include "storage.h"
#include <string.h>
#include "micro-ecc/uECC.h"

typedef int (*uECC_RNG_Function)(uint8_t *dest, unsigned size);

// rng_for_uECC()
//
    static int
rng_for_uECC(uint8_t *dest, unsigned size)
{
    /* The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
    'dest' was filled with random data, or 0 if the random data could not be generated.
    The filled-in values should be either truly random, or from a cryptographically-secure PRNG.
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

// EOF
