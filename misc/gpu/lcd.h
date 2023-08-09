/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

static const uint8_t NO_CURSOR = 0;
static const uint8_t CURSOR_SOLID = 0x01;
static const uint8_t CURSOR_OUTLINE = 0x02;
static const uint8_t CURSOR_MENU = 0x03;
static const uint8_t CURSOR_DW_OUTLINE = 0x11;
static const uint8_t CURSOR_DW_SOLID = 0x12;


typedef struct {
    bool        activity_bar:1;
    bool        test_pattern:1;     // self clearing

    bool        cur_flash:1;        // clear when changing pos/type/enable
    uint8_t     cursor_type;

    uint8_t     cursor_x, cursor_y;
} lcd_state_t;

extern lcd_state_t lcd_state;

void lcd_setup(void);
void lcd_animate(void);
void lcd_test_pattern(void);

// EOF
