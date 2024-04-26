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
#include "lib/utils/interrupt_char.h"       // for mp_interrupt_char

// is the REPL enabled by user (default: no)
bool ckcc_vcp_enabled;

// mp_hal_stdin_rx_chr()
//
// - replaces code in stm32/mphalport.c
// - ignore all keys unless in REPL mode
//
    int
mp_hal_stdin_rx_chr(void) {
    for (;;) {
        if (MP_STATE_PORT(pyb_stdio_uart) != NULL && uart_rx_any(MP_STATE_PORT(pyb_stdio_uart))) {
            // consume it, but forward only if enabled.
            int ch = uart_rx_char(MP_STATE_PORT(pyb_stdio_uart));

#if COLDCARD_DEBUG
            return ch;
#else
            if(ckcc_vcp_enabled) return ch;
#endif
        }

        // USB virtual comm port Rx support -- always disabled on Mk4 by design
#if 0
        int dupterm_c = mp_uos_dupterm_rx_chr();
        if (dupterm_c >= 0) {
            if(ckcc_vcp_enabled) {
                return dupterm_c;
            }
        }
#endif

        MICROPY_EVENT_POLL_HOOK
    }
}

// mp_hal_set_interrupt_char()
//
    void
mp_hal_set_interrupt_char(int c)
{
    // Replaces content of l-mpy/lib/utils/interrupt_char.c
    // - many things call this at many times.
    // - instead, use our ckcc.vcp_enable() call
#if COLDCARD_DEBUG
    mp_interrupt_char = 3;
#else
    mp_interrupt_char = -1;
#endif
}

// mp_hal_stdout_tx_strn()
//
    void
mp_hal_stdout_tx_strn(const char *str, size_t len)
{
#if !COLDCARD_DEBUG
    if(!ckcc_vcp_enabled) {
        // allow the copyright notice and version string, then no more output
        static int so_far = 0;

        if(so_far > 84) return;
        so_far += len;
    }
#endif

    if (MP_STATE_PORT(pyb_stdio_uart) != NULL) {
        uart_tx_strn(MP_STATE_PORT(pyb_stdio_uart), str, len);
    }
    mp_uos_dupterm_tx_strn(str, len);
}

// EOF
