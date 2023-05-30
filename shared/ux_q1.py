# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux_q1.py - UX/UI interactions that are Q1 specific and use big screen, keyboard.
#
from uasyncio import sleep_ms
import utime, gc
from charcodes import *

CURSOR = '█ '

class PressRelease:
    def __init__(self, need_release=KEY_SELECT+KEY_CANCEL):
        # Manage key-repeat: track last key, measure time it's held down, etc.
        self.need_release = need_release
        self.last_key = None
        self.num_repeats = 0

    async def wait(self):
        from glob import numpad

        armed = None

        while 1:
            # two values here:
            #  - (ms) time to wait before first key-repeat
            #  - (ms) time between 2nd and Nth repeated events
            #  - these values approved by @nvk
            rep_delay = 200 if not self.num_repeats else 20
            so_far = 0

            while numpad.empty():
                if self.last_key and numpad.key_pressed == self.last_key:
                    if so_far >= rep_delay:
                        self.num_repeats += 1
                        return self.last_key

                await sleep_ms(1)
                so_far += 1

            ch = numpad.get_nowait()

            if ch == numpad.ABORT_KEY:
                raise AbortInteraction()

            self.num_repeats = 0

            if len(ch) > 1:
                # multipress: cancel press/release cycle and be a keyup
                # for other keys.
                armed = None
                continue

            if ch == '':
                self.last_key = None
                if armed:
                    return armed
            elif ch in self.need_release:
                # no key-repeat on these ones
                armed = ch
            else:
                self.last_key = ch
                return ch

async def ux_enter_number(prompt, max_value, can_cancel=False):
    # return the decimal number which the user has entered
    # - default/blank value assumed to be zero
    # - clamps large values to the max
    from glob import dis
    from math import log

    # allow key repeat on X only?
    press = PressRelease()

    value = ''
    max_w = int(log(max_value, 10) + 1)

    dis.clear()
    dis.text(None, -1, "CANCEL or SELECT when done.")

    while 1:
        # TODO: check width, go to two lines if needed?
        bx = dis.text(2, 4, prompt + ' ' + value + CURSOR)

        ch = await press.wait()
        if ch == KEY_SELECT:

            if not value:
                return 0

            return min(max_value, int(value))

        elif ch == KEY_DELETE:
            if value:
                value = value[0:-1]
        elif ch == KEY_CANCEL:
            return None
        elif '0' <= ch <= '9':
            if len(value) == max_w:
                value = value[0:-1] + ch
            else:
                value += ch

            # cleanup leading zeros and such
            value = str(min(int(value), max_value))

async def ux_input_numbers(val, validate_func):
    # collect a series of digits
    # - not wanted on Q1; just get the digits w/ the text.
    pass

async def ux_input_text(value, confirm_exit=True, hex_only=False, max_len=100):
    # Allow them to pick each digit using "D-pad"
    # - Should allow full unicode, NKDN
    # - but our font is mostly just ascii
    # - no control chars allowed either
    from glob import dis
    from lcd_display import CHARS_W
    from ux import ux_show_story

    dis.clear()
    dis.text(None, -2, "Use |-> to auto-complete words.")
    dis.text(None, -1, "CANCEL or SELECT when done.")

    # TODO:
    # - left/right to edit in middle
    # - multi line support
    # - add prompt text?

    # no key-repeat on certain keys
    press = PressRelease()
    while 1:

        dis.text(1, 1, value + CURSOR)

        ch = await press.wait()
        if ch == KEY_SELECT:
            return str(value, 'ascii')
        elif ch == KEY_DELETE:
            if len(value) > 0:
                # delete current char
                value = value[:-1]
        elif ch == KEY_CANCEL:
            if confirm_exit:
                pp = await ux_show_story(
                    "OK to leave without any changes? Or CANCEL to avoid leaving.")
                if pp == KEY_CANCEL: continue
            return None
        elif ' ' <= ch < chr(127):
            value += ch

# EOF
