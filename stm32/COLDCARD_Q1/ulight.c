//
// (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// ulight.c - handle a flashing USB activity light on Mk4 rev B and later.
// 
#include "py/mphal.h"
#include "softtimer.h"
#include "ulight.h"

// set this whenever something happens over USB; makes the light flash
bool ckcc_usb_active;

// period for blinking (ms)
#define BLINK_RATE          150

static soft_timer_entry_t  led_blinktimer;

STATIC mp_obj_t led_blinker(mp_obj_t unused_obj)
{
    // Called at 150 ms rate.

    // if something happened in previous time period, keep flashing.
    bool active = false;
    if(ckcc_usb_active) {
        ckcc_usb_active = false;
        active = true;
    }

    static bool led_on;
    if(!active) {
        if(led_on) {
            mp_hal_pin_low(USB_LED_PIN);
            led_on = false;
        }
    } else {
        led_on = !led_on;
        mp_hal_pin_write(USB_LED_PIN, led_on);
    }

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_1(led_blinker_obj, led_blinker);

// ulight_setup()
//
    void
ulight_setup(void)
{
    // setup USB activity light
    led_blinktimer.mode = SOFT_TIMER_MODE_PERIODIC;
    led_blinktimer.delta_ms = BLINK_RATE;
    led_blinktimer.callback = (void *)&led_blinker_obj;
    led_blinktimer.pairheap.base.type = MP_ROM_NONE;      // not needed

    soft_timer_insert(&led_blinktimer);
}

// EOF
