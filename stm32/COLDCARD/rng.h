/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

uint32_t rng_get(void);

// Boot-time self-test: hard-faults unless rng_get() verifiably passes
// through the hardware read path.
void rng_selftest(void);

// Set when rng_selftest() passes at boot.
extern bool rng_boot_selftest_ok;

MP_DECLARE_CONST_FUN_OBJ_0(pyb_rng_get_obj);
MP_DECLARE_CONST_FUN_OBJ_1(pyb_rng_get_bytes_obj);
