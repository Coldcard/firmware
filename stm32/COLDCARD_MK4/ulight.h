/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

// active-high LED on this pin
#define USB_LED_PIN         pin_C6

// set this whenever something happens over USB; makes the light flash
extern bool ckcc_usb_active;

// call once
void ulight_setup(void);

static inline void ulight_off(void) {
    mp_hal_pin_low(USB_LED_PIN);
}

// EOF
