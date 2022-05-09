/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

#define HCLK_FREQUENCY      120000000

// very early setup/chip reset stuff
void system_init0(void);

// call once at startup
void clocks_setup(void);

// the 1ms systick value. call anytime
void systick_setup(void);
