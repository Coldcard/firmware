// (c) Copyright 2020-2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// AUTO-generated.
//
//   built: 2026-03-05
// version: 1.4.0Q
//
#include <stdint.h>

// this overrides ports/stm32/fatfs_port.c
uint32_t get_fattime(void) {
    return 0x5c650880UL;
}
