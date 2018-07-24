/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#include "basics.h"

// need this many bytes for any update
#define OLED_DRAW_SIZE      1024

extern void oled_setup(void);

// send a pre-compressed image to screen (complete)
extern void oled_show(const uint8_t *pixels);

// .. same but add a progress bar
extern void oled_show_progress(const uint8_t *pixels, int percent);

// send some bytes to screen
extern void oled_show_raw(uint32_t len, const uint8_t *pixels);

// delay loop
void sleep_ms(int n);
