//
// (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// nmi.c - handle a NMI errors (at least the flash sources for them) and try to recover.
// 
#include "py/mphal.h"

// replace stub from stm32_it.c
void NMI_Handler(void) {
    printf("NMI\n");
}

// EOF
