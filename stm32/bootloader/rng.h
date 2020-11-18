/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"

void rng_setup(void);
uint32_t rng_sample(void);
void rng_buffer(uint8_t *result, int len);

