# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux_mk4.py - UX/UI interactions that are Mk1-4 specific
#
from uasyncio import sleep_ms
from utils import pretty_short_delay
from exceptions import AbortInteraction

class PressRelease:
    def __init__(self, need_release='xy'):
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
            
            
async def ux_confirm(msg):
    # confirmation screen, with stock title and Y=of course.
    from ux import ux_show_story

    resp = await ux_show_story("Are you SURE ?!?\n\n" + msg)

    return resp == 'y'

async def ux_enter_number(prompt, max_value, can_cancel=False):
    # return the decimal number which the user has entered
    # - default/blank value assumed to be zero
    # - clamps large values to the max
    from glob import dis
    from display import FontTiny
    from math import log

    # allow key repeat on X only
    press = PressRelease('1234567890y')

    y = 26
    value = ''
    max_w = int(log(max_value, 10) + 1)

    dis.clear()
    dis.text(0, 0, prompt)
    dis.text(None, -1, ("X to CANCEL, or OK when DONE." if can_cancel else 
                        "X to DELETE, or OK when DONE."), FontTiny)
    dis.save()

    while 1:
        dis.restore()

        # text centered
        if value:
            bx = dis.text(None, y, value)
            dis.icon(bx+1, y+11, 'space')
        else:
            dis.icon(64-7, y+11, 'space')

        dis.show()

        ch = await press.wait()
        if ch == 'y':

            if not value: return 0
            return min(max_value, int(value))

        elif ch == 'x':
            if value:
                value = value[0:-1]
            elif can_cancel:
                # quit if they press X on empty screen
                return None
        else:
            if len(value) == max_w:
                value = value[0:-1] + ch
            else:
                value += ch

            # cleanup leading zeros and such
            value = str(min(int(value), max_value))

async def ux_input_numbers(val, prompt=None, maxlen=32):
    # collect a series of digits
    from glob import dis
    from display import FontTiny

    # allow key repeat on X only
    press = PressRelease('1234567890y')

    footer = "X to DELETE, or OK when DONE."
    lx = 6
    y = 16
    here = ''

    dis.clear()
    dis.text(None, -1, footer, FontTiny)

    if prompt:
        dis.text(0, 0, prompt)
        y += 8

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
            return val
        elif ch == 'x':
            if here:
                here = here[0:-1]
            else:
                # quit if they press X on empty screen
                return
        else:
            if len(here) < maxlen:
                here += ch

async def ux_input_text(pw, confirm_exit=True, hex_only=False, max_len=100, min_len=0, **_kws):
    # Allow them to pick each digit using "D-pad"
    # - Q1 version of this function can do much more w/ more keyword args
    from glob import dis
    from display import FontTiny, FontSmall
    from ux import ux_show_story

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
            if len(pw) < min_len:
                ch = await ux_show_story('Need %d characters at least. Press OK '
                                         'to continue X to exit.' % min_len, escape="xy",
                                         strict_escape=True)
                if ch == "x": return
                continue
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

def ux_show_phish_words(dis, words):
    # Show the 2 words during login/pin change process
    from display import FontLarge, FontTiny

    y = 15
    x = 18
    dis.text(x, y,    words[0], FontLarge)
    dis.text(x, y+18, words[1], FontLarge)
    dis.text(None, -1, "X to CANCEL, or OK to CONTINUE", FontTiny)

def ux_show_pin(dis, pin, subtitle, prefix, is_confirmation, force_draw,
                    footer=None, randomize=None):

    # Draw PIN during login process, as they enter it.
    from display import FontTiny, FontLarge

    is_first_part = not bool(prefix)

    if randomize:
        # screen redraw, when we are "randomized"
        # - only used at login, none of the other cases

        if force_draw:
            dis.clear()

            # prompt
            dis.text(5+3, 2, "ENTER PIN")
            dis.text(5+6, 17, ('1st part' if is_first_part else '2nd part'))

            # remapped keypad
            y = 2
            x = 89
            h = 16
            for i in range(0, 10, 3):
                if i == 9:
                    dis.text(x, y, '  %s' % randomize[0])
                else:
                    dis.text(x, y, ' '.join(randomize[1+i:1+i+3]))
                y += h
        else:
            # just clear what we need to: the PIN area
            dis.clear_rect(0, 40, 88, 20)

        # placeholder text
        msg = '[' + ('*'*len(pin)) + ']'
        x = 40 - ((10*len(msg))//2)
        dis.text(x, 40, msg, FontLarge)

        dis.show()

        return

    filled = len(pin)
    y = 27

    if force_draw:
        dis.clear()

        if is_first_part:
            prompt="Enter PIN Prefix" 
        else:
            prompt="Enter rest of PIN" 


        if subtitle:
            dis.text(None, 0, subtitle)
            dis.text(None, 16, prompt, FontTiny)
        else:
            dis.text(None, 4, prompt)

        if footer:
            pass
        elif is_confirmation:
            footer = "CONFIRM PIN VALUE"
        elif is_confirmation:
            footer = "X to CANCEL, or OK when DONE"
        else:
            footer = "X to CANCEL, or OK to CONTINUE"

        dis.text(None, -1, footer, FontTiny)

    else:
        # just clear what we need to: the PIN area
        dis.clear_rect(0, y, 128, 21)

    w = 18

    # extra (empty) box after
    if not filled:
        dis.icon(64-(w//2), y, 'box')
    else:
        x = 64 - ((w*filled)//2)
        # filled boxes
        for idx in range(filled):
            dis.icon(x, y, 'xbox')
            x += w

    dis.show()

async def ux_login_countdown(sec):
    # Show a countdown, which may need to
    # run for multiple **days**
    from glob import dis
    from display import FontSmall, FontLarge
    from utime import ticks_ms, ticks_diff

    # pre-render fixed parts
    dis.clear()
    y = 0
    dis.text(None, y, 'Login countdown in', font=FontSmall); y += 14
    dis.text(None, y, 'effect. Must wait:', font=FontSmall); y += 14
    y += 5
    dis.save()

    st = ticks_ms()
    while sec > 0:
        dis.restore()
        dis.text(None, y, pretty_short_delay(sec), font=FontLarge)

        dis.show()
        dis.busy_bar(1)

        # this should be more accurate, errors were accumulating
        now = ticks_ms()
        dt = 1000 - ticks_diff(now, st)
        await sleep_ms(dt)
        st = ticks_ms()

        sec -= 1

    dis.busy_bar(0)

def ux_dice_rolling():
    from glob import dis
    from display import FontTiny, FontLarge

    # draw fixed parts of screen
    dis.clear()
    y = 38
    dis.text(0, y, "Press 1-6 for each dice"); y += 13
    dis.text(0, y, "roll to mix in.")
    dis.save()

    def update(count, hx=None):
        dis.restore()
        dis.text(None, 0, '%d rolls' % count, FontLarge)

        if hx is not None:
            dis.text(0, 20, hx[0:32], FontTiny)
            dis.text(0, 20+7, hx[32:], FontTiny)

        dis.show()

    # return funct to draw updating part
    return update

def ux_render_words(words, **kws):
    # caution: text layout here, and flag sensitive=T trigger side-channel defenses
    return '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))

# EOF
