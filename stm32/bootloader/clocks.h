/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#pragma once

// call once at startup
void clocks_setup(void);

// the 1ms systick value. call anytime
void systick_setup(void);
