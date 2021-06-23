/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"

// This magic value indicates we should go direct into DFU on this reboot.
// Arbitrary SRAM1 location, random magic values. Also what screen to show.
#define REBOOT_TO_DFU       "Boot2DFU"
typedef struct {
    char            magic[8];
    const uint8_t  *screen;
} dfu_flag_t;
#define dfu_flag        ((dfu_flag_t *)0x20008000)

// location defined by link-script.ld, and documented in sigheader.h
extern uint32_t     shared_bootflags;

// Clear all SRAM memory, except that we're using ourselves
void wipe_all_sram(void);

// Entry point
void system_startup(void);

void __attribute__((noreturn)) fatal_mitm(void);

// EOF
