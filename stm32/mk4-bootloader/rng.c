/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include <string.h>
#include "rng.h"
#include "basics.h"
#include "stm32l4xx_hal.h"

#define RNG_MAX_ATTEMPTS (3)

// Clock-error flags (CEIS/CECS) are intentionally ignored: per RM0432
// section 32.3.7, "the clock error has no impact on generated random
// numbers", and ST's errata (ES0250/ES0335) confirm a clock error neither
// stops generation nor invalidates RNG_DR when DRDY is set. A dead clock
// still fails closed via the intentionally unbounded DRDY wait below.
// CEIS is left set on purpose: clearing it is a no-op while RNG interrupts
// stay disabled.
#define RNG_SEED_ERROR_MASK (RNG_SR_SEIS | RNG_SR_SECS)

// Recover from a seed error.
static void
rng_recover(void)
{
    // Ensure the peripheral is clocked before touching its registers.
    __HAL_RCC_RNG_CLK_ENABLE();

    // Clear sticky SEIS, then cycle RNGEN per the STM32L4 recovery sequence.
    RNG->SR &= ~RNG_SR_SEIS;
    RNG->CR &= ~RNG_CR_RNGEN;
    RNG->CR |= RNG_CR_RNGEN;
}

// rng_setup()
//
    void
rng_setup(void)
{
    if(RNG->CR & RNG_CR_RNGEN) {
        // already setup
        return;
    }

    // Enable the Peripheral
    __HAL_RCC_RNG_CLK_ENABLE();

    // Turn on feature.
    RNG->CR |= RNG_CR_RNGEN;

    // Sample twice to be sure that we have a 
    // valid RNG result.
    uint32_t chk = rng_sample();
    uint32_t chk2 = rng_sample();

    // die if we are clearly not getting random values
    if(chk == 0 || chk == ~0
        || chk2 == 0 || chk2 == ~0
        || chk == chk2
    ) {
        INCONSISTENT("bad rng");

        while(1) ;
    }
}

// rng_sample()
//
    uint32_t
rng_sample(void)
{
    static uint32_t last_rng_result;

    // Attempts bound seed-error recovery; DRDY polling remains intentionally unbounded.
    for(int attempt = 0; attempt < RNG_MAX_ATTEMPTS; attempt++) {
        while(1) {
            uint32_t sr = RNG->SR;

            if(sr & RNG_SEED_ERROR_MASK) {
                break;
            }

            if(!(sr & RNG_FLAG_DRDY)) {
                // Missing clocks are a hard failure. Preserve the existing
                // fail-closed behaviour and wait rather than use bad data.
                continue;
            }

            uint32_t rv = RNG->DR;

            // Recheck after reading DR to close the documented polling race.
            if(RNG->SR & RNG_SEED_ERROR_MASK) {
                break;
            }

            if(rv != last_rng_result && rv) {
                last_rng_result = rv;

                return rv;
            }

            // Zero or repeat: poll for another word without consuming an attempt.
        }

        if(attempt + 1 < RNG_MAX_ATTEMPTS) {
            rng_recover();
        }
    }

    fatal_error("rng");
}

// rng_buffer()
//
    void
rng_buffer(uint8_t *result, int len)
{
    while(len > 0) {
        uint32_t    t = rng_sample();

        memcpy(result, &t, MIN(4, len));

        len -= 4;
        result += 4;
    }
}

// rng_delay()
//
// Call anytime. Delays for a random time period to fustrate glitchers.
//
    void
rng_delay(void)
{
    uint32_t    r = rng_sample() % 8;
    uint32_t    cnt = (1<<r);

    while(cnt) {
        asm("nop");         // need this to keep from being optimized away, check bootloader.lss
        cnt--;
    }
}

// EOF
