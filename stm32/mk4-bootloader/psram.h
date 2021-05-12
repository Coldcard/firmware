/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"

// 8 bytes of unique data from chip
extern uint8_t psram_chip_eid[8];

extern void psram_setup(void);

// EOF
