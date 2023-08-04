# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux_q1.py - UX/UI interactions that are Q1 specific and use big screen, keyboard.
#
from uasyncio import sleep_ms
import utime, gc
from charcodes import *
from lcd_display import CHARS_W, CursorSpec
from exceptions import AbortInteraction
import bip39

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
    dis.text(None, -1, "CANCEL or SELECT when done." if can_cancel else
                       "Enter number, SELECT when done.")

    while 1:
        # TODO: check width, go to two lines if needed? depends on prompt text
        bx = dis.text(2, 4, prompt + ' ' + value)
        dis.show(cursor=CursorSpec(bx, 4))

        ch = await press.wait()
        if ch == KEY_SELECT:

            if not value:
                return 0

            return min(max_value, int(value))

        elif ch == KEY_DELETE:
            if value:
                value = value[0:-1]
        elif ch == KEY_CLEAR:
            value = ''
            dis.text(0, 4, ' '*CHARS_W)
        elif ch == KEY_CANCEL:
            if can_cancel:
                # quit if they press X on empty screen
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

async def ux_input_text(value, confirm_exit=True, hex_only=False, max_len=100,
            prompt='Enter value', min_len=0, b39_complete=False, scan_ok=False, num_words=0):
    # Get a text string.
    # - Should allow full unicode, NKDN
    # - but our font is mostly just ascii
    # - no control chars allowed either
    # - TODO: press QR -> do scan and use that text
    # - TODO: regex validation for derviation paths
    # - TODO: assume phrase seed entry
    from glob import dis
    from ux import ux_show_story

    dis.clear()
    if num_words:
        b39_complete = True
        max_len = 216
        min_len = 36
        got_words = []

    if b39_complete:
        dis.text(None, -2, "↦ to auto-complete. (QR) to scan.")

    dis.text(None, -1, "CANCEL or SELECT when done.")

    # TODO:
    # - left/right to edit in middle
    # - multi line support
    # - add prompt text?

    # map from what they entered, to allowed char. None if not allowed char
    # - can case fold if desired
    ch_remap = lambda ch: ch if ' ' <= ch < chr(127) else None
    if hex_only:
        ch_remap = lambda ch: ch.lower() if ch in '0123456789abcdefABCDEF' else None
    if num_words:
        ch_remap = lambda ch: ch.lower() if ch==' ' or ch.isalpha() else None


    y = 2
    if max_len <= CHARS_W-2:
        # single-line or perhaps shorter value
        line_len = max_len
        num_lines = 1
        y = 4
    elif max_len == 100:
        # passphrase case, handle nicely
        line_len = 25
        num_lines = 4
    else:
        # multi-line mode: just do a box for most of screen
        num_lines = 6
        line_len = CHARS_W-2

    dis.text(None, y-2, prompt)
    x = dis.draw_box(None, y-1, line_len, num_lines)

    # NOTE:
    #  - x,y here are top left of entry area
    #  - not allow cursor movement, always appending to end

    # no key-repeat on certain keys
    err_msg = last_err = None
    press = PressRelease()
    while 1:
        dis.clear_box(x, y, line_len, num_lines)

        # show error msg, until they type anything to clear it
        if err_msg:
            dis.text(None, y+num_lines+1, err_msg)
            err_msg = None
            last_err = True
        elif last_err:
            dis.text(None, y+num_lines+1, '')
            last_err = False

        if not value:
            bx = 0
            n = 0
        else:
            for n, ln_pos in enumerate(range(0, len(value), line_len)):
                ln = value[ln_pos:ln_pos+line_len]
                dis.text(x, y+n, ln)
                bx = len(ln)

        # decide cursor appearance
        cur = CursorSpec(x+bx, y+n, 0, 0)
        if cur.x >= x+line_len:
            # outline mode if on final possible location
            cur = CursorSpec(x+line_len-1, y+n, 0, True)     

        dis.show(cursor=cur)

        ch = await press.wait()

        if ch == KEY_SELECT:
            if num_words:
                if len(got_words) == num_words:
                    break
                err_msg = 'Need exactly %d words.' % num_words
            elif len(value) >= min_len:
                break
            else:
                err_msg = 'Need %d characters at least.' % min_len
        elif ch == KEY_DELETE or ch == KEY_LEFT:
            if len(value) > 0:
                # delete last char
                value = value[:-1]
        elif ch == KEY_CLEAR:
            value = ''
        elif ch == KEY_CANCEL:
            if confirm_exit:
                pp = await ux_show_story(
                    "OK to leave without any changes? Or CANCEL to avoid leaving.")
                if pp == KEY_CANCEL:
                    continue
            value = None
            break

        elif b39_complete and ch == KEY_TAB:
            # match case and auto-complete BIP-39 word if we can
            # - search backwards for alpha chars, up to 5
            # - stop on first non-letter
            # - break if case changes, so "ZooAct" gives "Act"
            pref = []
            for b in reversed(value[-4:]):
                if not b: break
                if 'a' <= b.lower() <= 'z':
                    pref.insert(0, b)
                    if len(pref)>=1 and b.isupper() != pref[0].isupper():
                        break
                else:
                    break
            if not pref:
                #err_msg = 'Need some letters first.'
                continue

            pref = ''.join(pref)
            exact, nextchars, is_word = bip39.next_char(pref.lower())
            print('%s => exact=%s nextchars=%s is_word=%s' % (pref, exact, nextchars, is_word))

            if not is_word and len(nextchars) == 1:
                # only one possible next char, so complete for them
                # example "yo" => "you"
                is_word = pref + nextchars[0]

            #N OTE: if exact and not is_word:
            # example "act" -> could be "act" or "actor" etc.
            # but they pressed auto-complete and not space, so they want next char info
                
            if is_word:
                # got a match; append it
                if pref.isupper():
                    # all upper case, so append w/ same
                    # - Titlecase will just happen w/o any code here
                    is_word = is_word.upper()

                value += is_word[len(pref):]
                if num_words:
                    got_words.append(exact)
                    if len(got_words) < num_words:
                        value += ' '
            elif not nextchars:
                err_msg = 'Not a BIP-39 word: ' + pref
            elif len(nextchars) < 12:
                # 'sta' and other s-prefixes
                err_msg = 'Press next key: ' + nextchars
            else:
                err_msg = 'Need more letters.'

        elif num_words and ch == ' ':
            # doing a space during seed-word entry: must be forming a 
            # valid word, or fail
            last = value.split(' ')[-1]
            if last:
                exact, nextchars, is_word = bip39.next_char(last)
                if exact and not is_word:
                    is_word = last      # "act " case
                if is_word:
                    got_words.append(is_word)
                    value += ' ' 
                else:
                    err_msg = 'Not a BIP-39 word: ' + last
        else:
            ch = ch_remap(ch)
            if ch is not None:
                if len(value) < max_len:
                    value += ch
                else:
                    value = value[0:max_len-1] + ch

            if num_words and ch != ' ':
                last = value.split(' ')[-1]
                if len(last) >= 4:
                    exact, nextchars, is_word = bip39.next_char(last)
                    if not exact:
                        err_msg = 'Not a BIP-39 prefix: ' + last
                    else:
                        got_words.append(is_word)
                        value = value + is_word[len(last):] + ' '
                
                

    if num_words:
        return got_words

    return value


def ux_show_pin(dis, pin, subtitle, is_first_part, is_confirmation, force_draw,
                    footer=None, randomize=None):

    # Draw PIN during entry / reentry / changing or setting

    msg = ('※ ' * len(pin))
    y = 1 if randomize else 2

    if force_draw:
        dis.clear()

    if randomize and force_draw:
        # screen redraw, when we are "randomized"
        # - only used at login, none of the other cases
        # - test w/ "simulator.py --q1 -g --eff --set rngk=1"

        # show mapping of numbers vs. PIN digits
        dis.text(1, -5, '  ' + '  '.join(randomize[1:]) + '  ' + randomize[0] + '  ', invert=1)
        dis.text(1, -4, '↳ 1  2  3  4  5  6  7  8  9  0')

    if force_draw:

        if is_first_part:
            prompt="Enter FIRST part of PIN (xxx-)" 
        else:
            prompt="Enter SECOND part of PIN (-yyy)" 

        if subtitle:
            # "New Main PIN" ... so not really a SUB title.
            dis.text(None, 0, subtitle)
            dis.text(None, y, prompt)
        else:
            dis.text(None, y, prompt)

        if footer:
            # ie. '1 failures, 12 tries left'
            dis.text(None, -2, footer)

        if is_confirmation:
            cta = "Confirm pin value"
        if is_confirmation:
            cta = "CANCEL or SELECT when done"
        else:
            cta = "CANCEL or SELECT to continue"

        dis.text(None, -1, cta)

    y += 2
    x = dis.text(None, y, msg)
    if not msg:
        x -= 1      # to get exactly in center when empty

    dis.show(cursor=CursorSpec(x, y, True, False))

async def ux_login_countdown(sec):
    # Show a countdown, which may need to
    # run for multiple **days**
    # - test with: ./simulator.py --q1 -g --eff --set lgto=60
    # - test with: ./simulator.py --q1 -g --eff --set lgto=3600
    # - test with: ./simulator.py --q1 -g --eff --set lgto=2419200
    from glob import dis
    from utime import ticks_ms, ticks_diff
    from utils import pretty_short_delay, pretty_delay

    y = 1
    dis.clear()
    dis.text(None, y, "Login countdown in effect.", invert=1)
    dis.text(None, y+2, "Must wait:")

    st = ticks_ms()
    while sec > 0:
        txt = pretty_delay(sec) if sec > 12*3600 else pretty_short_delay(sec)
        dis.text(None, y+4, txt)
        dis.busy_bar(1)

        # this should be more accurate, errors were accumulating
        now = ticks_ms()
        dt = 1000 - ticks_diff(now, st)
        await sleep_ms(dt)
        st = ticks_ms()

        sec -= 1

    dis.busy_bar(0)

async def seed_word_entry(prompt, num_words, has_checksum=True, done_cb=None):
    # Accept a seed phrase
    # - replaces WordNestMenu()'s constructor
    # - return a function that will be called w/ menu details (dont care)
    assert num_words and prompt and done_cb

    v = await ux_input_text('', confirm_exit=False, prompt=prompt, num_words=num_words)
    if not v:
        return

    await done_cb(v)

# EOF
