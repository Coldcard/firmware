/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include <string.h>

#include "py/runtime.h"
#include "py/mperrno.h"
#include "py/mphal.h"
#include "extmod/misc.h"
#include "usb.h"
#include "uart.h"

extern bool ckcc_vcp_enabled;

// replacements for more permissive versions found in stm32/mphalport.c
// - we don't support any h/w UARTs 
// - USB VCP only sometimes, not all the time.
// - this only disconnects the REPL; can still open the VCP and read/write

void mp_hal_stdout_tx_strn(const char *str, size_t len) {

    if(ckcc_vcp_enabled && usb_vcp_is_enabled()) {
        usb_vcp_send_strn(str, len);
    }
}

int mp_hal_stdin_rx_chr(void) {
    for (;;) {
        byte c;

        if (usb_vcp_recv_byte(&c) != 0) {
            if(ckcc_vcp_enabled) {
                return c;
            }
        }

        MICROPY_EVENT_POLL_HOOK
    }
}

