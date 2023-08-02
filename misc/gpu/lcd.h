/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

typedef struct {
    bool        activity_bar:1;
    bool        test_pattern:1;     // self clearing

    bool        solid_cursor:1;
    bool        outline_cursor:1;
    bool        dbl_wide:1;
    bool        cur_flash:1;        // clear when changing pos/type/enable

    uint8_t     cursor_x, cursor_y;
} lcd_state_t;

extern lcd_state_t lcd_state;

void lcd_setup(void);
void lcd_animate(void);
void lcd_test_pattern(void);

// EOF
