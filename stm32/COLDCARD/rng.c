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

        // TODO: throw out some samples?
    }
}


#define RNG_TIMEOUT_MS (10)

static uint32_t last_value;

static uint32_t rng_get_or_fault(void)
{
    // Enable the RNG peripheral if it's not already enabled
    rng_init();

    // Wait for a new random number to be ready, takes on the order of 10us
    uint32_t start = HAL_GetTick();

    while (!(RNG->SR & RNG_SR_DRDY)) {
        if (HAL_GetTick() - start >= RNG_TIMEOUT_MS) {
            // hardware failure... do not return anything!
            mp_raise_OSError(MP_EFAULT);
        }
    }

    // Get and return the new random number
    last_value = RNG->DR;

    return last_value;
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

