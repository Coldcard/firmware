/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#pragma once

// Go into DFU mode, and certainly clear things.
void enter_dfu(void) __attribute__((noreturn));

// Start DFU, or return doing nothing if chip is secure (no DFU possible).
void dfu_by_request(void);
