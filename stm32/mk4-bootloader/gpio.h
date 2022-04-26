/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

// set directions, lock critical ones, etc.
void gpio_setup(void);

// sample the DFU button
inline bool dfu_button_pressed(void) { return false; }


