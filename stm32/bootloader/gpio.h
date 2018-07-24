/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#pragma once

// set directions, lock critical ones, etc.
void gpio_setup(void);

// sample the DFU button
bool dfu_button_pressed(void);


