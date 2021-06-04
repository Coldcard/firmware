/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"

// 8 megabytes of RAM
#define PSRAM_BASE      0x90000000
#define PSRAM_SIZE      0x00800000

extern void psram_setup(void);

extern void psram_wipe(void);

bool psram_recover_firmware(void);

void psram_do_upgrade(const uint8_t *start, uint32_t size);

// EOF
