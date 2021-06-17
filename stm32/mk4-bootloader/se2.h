/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * se2.c -- Talk to DS28C36B chip which is our second secure element.
 *
 */
#pragma once
#include <stdint.h>

void se2_setup(void);
bool se2_probe(void);       // T if problem

// secp256r1 curve functions.
bool p256_verify(const uint8_t pubkey[64], const uint8_t digest[32], const uint8_t signature[64]);
void p256_gen_keypair(uint8_t privkey[32], uint8_t pubkey[64]);
void p256_sign(const uint8_t privkey[32], const uint8_t digest[32], uint8_t signature[64]);
void ps256_ecdh(const uint8_t pubkey[64], const uint8_t privkey[32], uint8_t result[32]);

// EOF
