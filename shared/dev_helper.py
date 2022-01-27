# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# dev_helper.py - Debug code, not shipped.
#
import ckcc, pyb
from uasyncio import sleep_ms
        
async def usb_keypad_emu():
    # Take keypresses on USB virtual serial port (when not in REPL mode)
    # and converts them into keypad events. Super handy for UX testing/dev.
    #
    # IMPORTANT: 
    # - code is **not** used in real product, but left here for devs to use
    # - this code isn't even included in the build normally
    #
    await sleep_ms(1000)        # avoid slowing the startup

    from ux import the_ux
    from menu import MenuSystem
    from seed import WordNestMenu
    import gc

    u = pyb.USB_VCP()

    remap = {  '\r': 'y',
             '\x1b': 'x', 
           '\x1b[A': '5', 
           '\x1b[B': '8', 
           '\x1b[C': '9', 
           '\x1b[D': '7' }

    while 1:
        await sleep_ms(100)

        while u.isconnected() and u.any():
            from glob import numpad

            k = u.read(3).decode()

            if k in '\x04':     # ^D
                # warm reset
                from machine import soft_reset
                soft_reset()

            if k == 'T':
                ckcc.vcp_enabled(True)
                print("Repl")
                continue

            if k == 'm':
                print("free = %d" % gc.mem_free())
                continue

            if k in remap:
                k = remap[k]

            if k in '0123456789xy':
                numpad.inject(k)
                continue

def setup():
    from imptask import IMPT
    IMPT.start_task('usb_keypad_emu', usb_keypad_emu())

# EOF
