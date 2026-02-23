/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

// set directions, lock critical ones, etc.
void gpio_setup(void);

#ifdef FOR_Q1_ONLY
// kill system power; instant
extern void turn_power_off(void);
#endif

// sample the strapping pin to know if mk4 or 5
extern bool is_mk5(void);

// EOF
