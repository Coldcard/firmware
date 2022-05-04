
// (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// AUTO-generated.
//
//   built: 2022-05-04
// version: 4.1.5
//
#include <stdint.h>

// this overrides ports/stm32/fatfs_port.c
uint32_t get_fattime(void) {
    return 0x54a42020UL;
}
