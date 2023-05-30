# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux_q1.py - UX/UI interactions that are Q1 specific and use big screen, keyboard.
#
from uasyncio import sleep_ms
import utime, gc
from charcodes import *

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
        bx = dis.text(2, 4, prompt + ' ' + value + '█ ')

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
    from glob import dis

    press = PressRelease()

    footer = "CANCEL or SELECT when done."
    lx = 6
    y = 16
    here = ''

    dis.clear()
    dis.text(None, -1, footer, FontTiny)
    dis.save()

    while 1:
        dis.restore()

        # text centered
        msg = here
        by = y
        bx = dis.text(lx, y, msg[0:16])
        dis.text(lx, y - 9, str(val, 'ascii').replace(' ', '_'), FontTiny)

        if len(msg) > 16:
            # second line when needed (left just)
            by += 15
            bx = dis.text(lx, by, msg[16:])

        if len(here) < 32:
            dis.icon(bx, by - 2, 'sm_box')

        dis.show()

        ch = await press.wait()
        if ch == 'y':
            val += here
            validate_func()
            return val
        elif ch == 'x':
            if here:
                here = here[0:-1]
            else:
                # quit if they press X on empty screen
                return
        else:
            if len(here) < 32:
                here += ch

async def ux_input_text(pw, confirm_exit=True, hex_only=False, max_len=100):
    # Allow them to pick each digit using "D-pad"
    from glob import dis
    from display import FontTiny, FontSmall

    # Should allow full unicode, NKDN
    # - but limited to what we can show in FontSmall
    # - so really just ascii; not even latin-1
    # - 8-bit codepoints only
    my_rng = range(32, 127)  # FontSmall.code_range
    if hex_only:
        new_expand = "0"
        symbols = b"0123456789abcdef"
    else:
        new_expand = " "
        symbols = b' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        letters = b'abcdefghijklmnopqrstuvwxyz'
        Letters = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        numbers = b'1234567890'
    # assert len(set(symbols+letters+Letters+numbers)) == len(my_rng)

    if hex_only:
        footer1 = "Enter Hexidecimal Number"
        footer2 = "58=Change 9=Next 7=Back"
    else:
        footer1 = "1=Letters  2=Numbers  3=Symbols"
        footer2 = "4=SwapCase  0=HELP"

    y = 20
    pw = bytearray(pw or ('0' if hex_only else 'A'))

    pos = len(pw) - 1  # which part being changed
    n_visible = const(9)
    scroll_x = max(pos - n_visible, 0)

    def cycle_set(which, direction=1):
        # pick next item in set of choices
        for n, s in enumerate(which):
            if pw[pos] == s:
                try:
                    pw[pos] = which[n + direction]
                except IndexError:
                    pw[pos] = which[0 if direction == 1 else -1]
                return
        pw[pos] = which[0]

    def change(dx):
        # next/prev within the same subset of related chars
        ch = pw[pos]
        if hex_only:
            return cycle_set(symbols, dx)
        for subset in [symbols, letters, Letters, numbers]:
            if ch in subset:
                return cycle_set(subset, dx)

        # probably unreachable code: numeric up/down
        ch = pw[pos] + dx
        if ch not in my_rng:
            ch = (my_rng.stop - 1) if dx < 0 else my_rng.start
            assert ch in my_rng
        pw[pos] = ch

    # pre-render the fixed stuff
    dis.clear()
    dis.text(None, -10, footer1, FontTiny)
    dis.text(None, -1, footer2, FontTiny)
    dis.save()

    # no key-repeat on certain keys
    press = PressRelease('4xy')
    while 1:
        dis.restore()

        lr = pos - scroll_x  # left/right distance of cursor
        if lr < 4 and scroll_x:
            scroll_x -= 1
        elif lr < 0:
            scroll_x = pos
        elif lr >= (n_visible - 1):
            # past right edge
            scroll_x += 1

        for i in range(n_visible):
            # calc abs position in string
            ax = scroll_x + i
            x = 4 + (13 * i)
            try:
                ch = pw[ax]
            except IndexError:
                continue

            if ax == pos:
                # draw cursor
                if not hex_only and (len(pw) < 2 * n_visible):
                    dis.text(x - 4, y - 19, '0x%02X' % ch, FontTiny)
                dis.icon(x - 2, y - 10, 'spin')

            if ch == 0x20:
                dis.icon(x, y + 11, 'space')
            else:
                dis.text(x, y, chr(ch) if ch in my_rng else chr(215), FontSmall)

        if scroll_x > 0:
            dis.text(2, y - 14, str(pw, 'ascii')[0:scroll_x].replace(' ', '_'), FontTiny)
        if scroll_x + n_visible < len(pw):
            dis.text(-1, 1, "MORE>", FontTiny)

        dis.show()

        ch = await press.wait()
        if ch == 'y':
            return str(pw, 'ascii')
        elif ch == 'x':
            if len(pw) > 1:
                # delete current char
                pw = pw[0:pos] + pw[pos + 1:]
                if pos >= len(pw):
                    pos = len(pw) - 1
            else:
                if confirm_exit:
                    pp = await ux_show_story(
                        "OK to leave without any changes? Or X to cancel leaving.")
                    if pp == 'x': continue
                return None

        elif ch == '7':  # left
            pos -= 1
            if pos < 0: pos = 0
        elif ch == '9':  # right
            pos += 1
            if pos >= len(pw):
                if len(pw) < max_len and pw[-3:] != b'   ':
                    # expands with space in normal mode
                    # expands with 0 in hex_only mode
                    pw += new_expand
                else:
                    pos -= 1  # abort addition

        elif ch == '5':  # up
            change(1)
        elif ch == '8':  # down
            change(-1)
        elif hex_only:
            # just got back at the beginning of the loop
            # below branches are unreachable for hex_only mode
            pass
        elif ch == '1':  # alpha
            cycle_set(b'Aa')
        elif ch == '4':  # toggle case
            if (pw[pos] & ~0x20) in range(65, 91):
                pw[pos] ^= 0x20
        elif ch == '2':  # numbers
            cycle_set(numbers)
        elif ch == '3':  # symbols (all of them)
            cycle_set(symbols)
        elif ch == '0':  # help
            help_msg = '''\
Use arrow keys (5789) to select letter and move around. 

1=Letters (Aa..)
2=Numbers (12..)
3=Symbols (!@#&*)
4=Swap Case (q/Q)
X=Delete char

Add more characters by moving past end (right side).'''

            if confirm_exit:
                help_msg += '\nTo quit without changes, delete everything.'
            await ux_show_story(help_msg)
