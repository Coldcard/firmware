/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * based on ../../rng.c but more paranoid
 *
 */
/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <string.h>
#include <stdbool.h>

#include "py/obj.h"
#include "py/runtime.h"
#include "py/mperrno.h"
#include "rng.h"

#if MICROPY_HW_ENABLE_RNG
#error "this code replaces normal RNG module"
#endif

void random_buffer(uint8_t *p, size_t count);

static void rng_init(void) {
    if (!(RNG->CR & RNG_CR_RNGEN)) {
        __HAL_RCC_RNG_CLK_ENABLE();
        RNG->CR |= RNG_CR_RNGEN;

        // first samples after enable are discarded by rng_selftest() at boot
    }
}

#define RNG_TIMEOUT_MS      (10)
#define RNG_MAX_ATTEMPTS    (3)

// Clock-error flags (CEIS/CECS) are intentionally ignored: per RM0432
// section 32.3.7, "the clock error has no impact on generated random
// numbers", and ST's errata (ES0250/ES0335) confirm a clock error neither
// stops generation nor invalidates RNG_DR when DRDY is set. A dead clock
// still fails closed via the DRDY timeout below. CEIS is left set on
// purpose: clearing it is a no-op while RNG interrupts stay disabled.
#define RNG_SEED_ERROR_MASK (RNG_SR_SEIS | RNG_SR_SECS)

static uint32_t last_value;

// Counting is armed only by rng_selftest() for a few words at boot, then
// disabled permanently. Not exposed anywhere (no Python, no USB).
static bool rng_count_active;
static uint32_t rng_count;

// Recover from a seed error.
static void rng_recover(void)
{
    // Ensure the peripheral is clocked before touching its registers.
    __HAL_RCC_RNG_CLK_ENABLE();

    // Clear sticky SEIS and cycle RNGEN (ST HAL recommendation).
    RNG->SR &= ~RNG_SR_SEIS;
    RNG->CR &= ~RNG_CR_RNGEN;
    RNG->CR |= RNG_CR_RNGEN;

    // RM0432 32.3.7: after clearing SEIS, read out 12 words from RNG_DR and
    // discard each of them to clean the pipeline of pre-error residue.
    // Bounded: if the error recurs or DRDY stops arriving, bail out and let
    // the next attempt's flag checks and DRDY timeout handle it.
    for (int i = 0; i < 12; i++) {
        uint32_t start = HAL_GetTick();

        while (!(RNG->SR & RNG_SR_DRDY)) {
            if (RNG->SR & RNG_SEED_ERROR_MASK) {
                return;
            }
            if (HAL_GetTick() - start >= RNG_TIMEOUT_MS) {
                return;
            }
        }

        (void)RNG->DR;
    }
}

// Make one bounded attempt to obtain a trustworthy, non-zero word.
static bool rng_try_once(uint32_t *value)
{
    uint32_t start = HAL_GetTick();

    // Seed errors can suppress DRDY, so check for them while polling.
    while (1) {
        uint32_t sr = RNG->SR;

        if (sr & RNG_SEED_ERROR_MASK) {
            return false;
        }

        if (sr & RNG_SR_DRDY) {
            break;
        }

        if (HAL_GetTick() - start >= RNG_TIMEOUT_MS) {
            return false;
        }
    }

    uint32_t sample = RNG->DR;

    // Recheck after reading DR to close the polling race; zero is also suspect.
    if (!sample || (RNG->SR & RNG_SEED_ERROR_MASK)) {
        return false;
    }

    *value = sample;
    return true;
}

static uint32_t rng_get_or_fault(void)
{
    rng_init();

    // Retry transient failures, recovering only between attempts.
    for (int attempt = 0; attempt < RNG_MAX_ATTEMPTS; attempt++) {
        uint32_t value;

        if (rng_try_once(&value)) {
            last_value = value;

            if (rng_count_active) rng_count++;

            return last_value;
        }

        if (attempt + 1 < RNG_MAX_ATTEMPTS) {
            rng_recover();
        }
    }

    // Persistent hardware failure: never return suspect randomness.
    mp_raise_OSError(MP_EFAULT);
    return last_value;
}

uint32_t rng_get(void)
{
    return rng_get_or_fault();
}

// rng_selftest()
//
// Boot-time proof that rng_get() -- the exact symbol libngu's
// CHIP_TRNG_32() and the rest of the firmware's entropy consumers link
// against -- enters the hardware read path above. Peripheral health
// itself (seed/clock error flags, recovery, zero-word rejection) is
// enforced per-call by rng_get_or_fault(); here we only check linkage.
// Runs before the Python VM exists, so failure is fatal.
//
extern void __fatal_error(const char *msg);     // NORETURN, ports/stm32/main.c

void rng_selftest(void)
{
    rng_init();

    // Wait at register level for the first word: proves entropy is flowing,
    // and guarantees the rng_get() calls below find DRDY set and can never
    // reach their mp_raise() timeout path (no VM/nlr handler installed
    // yet, so an exception here would be an uncontrolled crash).
    uint32_t start = HAL_GetTick();
    while(!(RNG->SR & RNG_SR_DRDY)) {
        if(HAL_GetTick() - start >= RNG_TIMEOUT_MS) {
            __fatal_error("rng: no entropy");
        }
    }

    rng_count = 0;
    rng_count_active = true;

    // discard these warm-up words; not exposed anywhere
    for(int i = 0; i < 8; i++) {
        (void)rng_get();
    }

    rng_count_active = false;

    if(rng_count != 8) {
        // rng_get() did not pass through the hardware read path: it must
        // have resolved to a non-hardware implementation
        __fatal_error("rng: bad linkage");
    }
}

/// \function pyb_rng_get()
//
/// Return a 30-bit hardware generated random number: or fail!
//
STATIC mp_obj_t pyb_rng_get(void)
{
    // Get and return the new random number
    return mp_obj_new_int(rng_get_or_fault() >> 2);
}

/// \function rng_get_bytes()
/// Fill a buffer with random bits; caller must provide sized buffer.
STATIC mp_obj_t pyb_rng_get_bytes(mp_obj_t buffer_io) {

    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(buffer_io, &bufinfo, MP_BUFFER_WRITE);

    mp_uint_t count = bufinfo.len;
    if(count < 1) {
        mp_raise_ValueError(NULL);
    }

    // Read 32-bit words and unpack into provided buffer
    random_buffer(bufinfo.buf, count);

    return mp_const_none;
}

MP_DEFINE_CONST_FUN_OBJ_0(pyb_rng_get_obj, pyb_rng_get);
MP_DEFINE_CONST_FUN_OBJ_1(pyb_rng_get_bytes_obj, pyb_rng_get_bytes);


// compat/replacement for trezor-crypto/rand.[ch]

// random32()
//
    uint32_t
random32(void)
{
    uint32_t rv;

    random_buffer((uint8_t *)&rv, sizeof(uint32_t));

    return rv;
}

// random_buffer()
//
    void
random_buffer(uint8_t *p, size_t count)
{
    uint32_t last = last_value;

    while(count) {
        uint32_t next = rng_get_or_fault();

        if(next == last) {
            // if rng_init0 isn't called at boot time, then this fault will happen! Very Bad!
            mp_raise_OSError(MP_EEXIST);
        }

        int here = MIN(4, count);

        memcpy(p, &next, here);
        p += here;
        count -= here;

        last = next;
    }
}
