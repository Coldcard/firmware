/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#pragma once
#include "basics.h"

void rng_setup(void);
uint32_t rng_sample(void);
void rng_buffer(uint8_t *result, int len);

