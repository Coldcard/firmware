
// (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// AUTO-generated.
//
//   built: 2021-04-20
// version: 4.0.3
//
#include <stdint.h>

// this overrides ports/stm32/fatfs_port.c
uint32_t get_fattime(void) {
    return 0x52942000UL;
}
