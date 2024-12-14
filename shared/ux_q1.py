# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux_q1.py - UX/UI interactions that are Q1 specific and use big screen, keyboard.
#
import utime, gc, ngu, sys
import uasyncio as asyncio
from uasyncio import sleep_ms
from charcodes import *
from lcd_display import CHARS_W, CHARS_H, CursorSpec, CURSOR_SOLID, CURSOR_OUTLINE
from exceptions import AbortInteraction, QRDecodeExplained
import bip39
from decoders import decode_qr_result
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from utils import problem_file_line
from glob import numpad         # may be None depending on import order, careful

class PressRelease:
    def __init__(self, need_release=KEY_ENTER+KEY_CANCEL):
        # Manage key-repeat: track last key, measure time it's held down, etc.
        self.need_release = need_release
        self.last_key = None
        self.num_repeats = 0

        global numpad
        if not numpad:
            from glob import numpad

    async def wait(self):

        armed = None
        while 1:
            # two values here:
            #  - (ms) time to wait before first key-repeat
            #  - (ms) time between 2nd and Nth repeated events
            #  - these values approved by @nvk
            rep_delay = 20 if self.num_repeats else 200

            # busy-wait on key arrivial
            # - would like to use asyncio.wait_for_ms but causes random CancelledError's elsewhere
            for i in range(rep_delay//2):
                if not numpad.empty():
                    break
                await sleep_ms(2)

            if numpad.empty():
                # nothing changed, do key repeat
                if self.last_key and numpad.key_pressed == self.last_key:
                    self.num_repeats += 1
                    return self.last_key
                continue

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
                # all keys are now UP
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

    resp = await ux_show_story(msg, title="Are you SURE ?!?")

    return resp == 'y'

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
    dis.text(None, -1, "CANCEL or ENTER when done." if can_cancel else
                       "Enter number, ENTER when done.")

    while 1:
        # check width, go to two lines if needed? depends on prompt text
        if len(prompt) + 1 + max_w >= CHARS_W:
            dis.text(0, 3, prompt[-CHARS_W:])      # may still be truncated, oh well.
            if len(prompt) > CHARS_W:
                dis.text(0, 3, '⋯')
            bx = dis.text(2, 4, value)
        else:
            bx = dis.text(2, 4, prompt + ' ' + value)
        dis.show(cursor=CursorSpec(bx, 4, CURSOR_SOLID))

        ch = await press.wait()
        if ch == KEY_ENTER:

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
    # - not wanted on Q1; just get the digits mixed in w/ the text.
    pass

async def ux_input_text(value, confirm_exit=False, hex_only=False, max_len=100,
            prompt='Enter value', min_len=0, b39_complete=False, scan_ok=False,
            placeholder=None, funct_keys=None, force_xy=None):
    # Get a text string.
    # - Should allow full unicode, NKDN
    # - but our font is mostly just ascii
    # - no control chars allowed either
    # - press QR -> do scan and use that text
    # - funct_keys => CTA msg, and map of Fn key to async-function which takes and returns new text
    # - TODO: regex validation for derviation paths?
    # - TODO: arrowing around, insertion cursor, delete-left vs -right, etc
    # - if unlimited length, then we allow newlines and CANCEL is only way out.
    # - multiline entries don't mean newlines are allowed, because we often have to wrap
    #   to make longer single-line value onto screen
     # - confirm_exit default False here, because so easy to re-enter w/ qwerty, True on mk4
    from glob import dis
    from ux import ux_show_story

    MAX_LINES = 7        # without scroll
    can_scroll = False

    value = value or ''

    # map from what they entered, to allowed char. None if not allowed char
    # - can case fold if desired
    ch_remap = lambda ch: ch if ' ' <= ch < chr(127) else None
    if hex_only:
        ch_remap = lambda ch: ch.lower() if ch in '0123456789abcdefABCDEF' else None

    line_len = CHARS_W-2
    y = 2
    if max_len is None:
        # try hard to support "unlimited" entry, with scrolling and all that.
        num_lines = CHARS_H-2
        line_len = CHARS_W
        can_scroll = True
    elif max_len <= line_len:
        # single-line or perhaps shorter value
        line_len = max_len
        num_lines = 1
        y = 4
    elif max_len == 100:
        # passphrase case, handle nicely
        line_len = 25
        num_lines = 4
    else:
        # non-scrolling but still multi-line mode
        num_lines, runt = divmod(max_len, line_len)
        if runt:
            num_lines += 1
        assert num_lines <= MAX_LINES, num_lines       # too big to fit w/o scroll

    if force_xy:
        x, y = force_xy
    else:
        dis.clear()

    if not can_scroll and not force_xy:
        # Normal, no-scrolling case
        if funct_keys:
            msg, funct_keys = funct_keys
            dis.text(None, -2, msg, dark=True)

        if b39_complete or scan_ok:
            msg = []
            if b39_complete:
                msg.append(KEY_TAB + " to auto-complete.")
            if scan_ok:
                msg.append(KEY_QR + " to scan.")
            dis.text(None, -1, ' '.join(msg), dark=True)

        elif num_lines <= 2:
            # show this dumb CTA only if screen mostly blank
            dis.text(None, -1, "CANCEL or ENTER when done.", dark=True)

        dis.text(None, y-2, prompt)
        x = dis.draw_box(None, y-1, line_len, num_lines, dark=True)
    elif can_scroll:
        # Scrolling, max-screen space mode (unlimited length for notes)
        dis.text(None, 0, prompt)

        # maybe some guide "icons" in top-left
        msg = ''
        if scan_ok:
            msg += KEY_QR
        if b39_complete:
            msg += KEY_TAB
        if msg:
            dis.text(-1, 0, msg, dark=True)

        dis.text(0, 0, KEY_TAB, dark=True)

        dis.text(None, 1, '┅'*CHARS_W, dark=True)
        x = 0
        y = 2

    # NOTE:
    #  - x,y here are top left of entry area
    #  - does not allow cursor movement, always appending to end (for now)

    # no key-repeat on certain keys
    err_msg = last_err = None
    press = PressRelease()
    exit_armed = False
    while 1:
        dis.clear_box(x, y, line_len, num_lines)

        if not can_scroll:
            # show error msg, until they type anything to clear it
            if err_msg:
                dis.text(None, y+num_lines+1, err_msg, dark=True)
                err_msg = None
                last_err = True
            elif last_err:
                dis.text(None, y+num_lines+1, '')
                last_err = False

        if not can_scroll or not value:
            if not value:
                bx = 0
                n = 0
                if placeholder:
                    dis.text(x, y, placeholder, dark=True)
            elif not can_scroll:
                for n, ln_pos in enumerate(range(0, len(value), line_len)):
                    ln = value[ln_pos:ln_pos+line_len]
                    dis.text(x, y+n, ln)
                    bx = len(ln)
        else:
            # scrollable case
            lines = []
            for ln in value.split('\n'):
                if len(ln) <= line_len:
                    lines.append(ln)
                else:
                    for pp in range(0, len(ln), line_len):
                        lines.append(ln[pp:pp+line_len])

            for n, ln in enumerate(lines[-MAX_LINES:]):
                dis.text(x, y+n, ln)
                bx = len(ln)

            top_y = max(0, len(lines) - MAX_LINES)
            if top_y:
                dis.scroll_bar(top_y, len(lines), MAX_LINES)

        # decide cursor location
        # - if on final possible location, adjust over top of final char
        cur = CursorSpec(min(x+bx, x+line_len-1), y+n, CURSOR_OUTLINE)
        dis.show(cursor=cur)

        ch = await press.wait()

        if ch != KEY_CANCEL:
            exit_armed = False

        if ch == KEY_ENTER:
            if can_scroll:
                value += '\n'
            else:
                if len(value) >= min_len:
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
                if exit_armed:
                    value = None
                    break
                err_msg = 'Confirm exit w/o change?'
                exit_armed = True
                continue
            else:
                if can_scroll:
                    # CANCEL/TAB are only way out in scrolling mode
                    # - cleanup blank lines at end, etc
                    value = value.strip()
                    break
                value = None
                break
        elif can_scroll and ch == KEY_TAB:
            # allow tab as escape from multiline mode
            value = value.strip()
            break

        elif ch == KEY_QR and scan_ok:
            # Insert or replace? I think replace in most cases, but not if long msg.
            # - always show result
            ss = dis.save_state()
            zz = QRScannerInteraction()
            got = await zz.scan_text('Scan any QR or Barcode for text.')
            if got:     # not canceled, etc
                if not value or not can_scroll:
                    # whole QR should be it, no more editing
                    # - but not if too long
                    if not max_len or len(got) <= max_len:
                        value = got
                        if len(value) >= 60:
                            break
                    else:
                        err_msg = "QR data too long! (max %d)" % max_len
                else:
                    # add onto end, if inf length supported, and they aren't on first char
                    # - adds a line break for them too
                    if value[-1] != '\n':
                        value += '\n'
                    value += got

            dis.restore_state(ss)

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

            elif not nextchars:
                err_msg = 'Not a BIP-39 word: ' + pref
            elif len(nextchars) < 18:
                # 'sta' and other s-prefixes can have many choices!
                # 'act' could be by itself, or 'actual', etc.
                if exact:
                    nextchars += '␣'
                err_msg = 'Press next key: ' + nextchars
            else:
                err_msg = 'Need more letters.'

        elif funct_keys and (ch in funct_keys):
            # replace w/ function output ... might do a transform, or not
            value = await funct_keys[ch](value)
        else:
            ch = ch_remap(ch)
            if ch is not None:
                if not max_len or len(value) < max_len:
                    value += ch
                else:
                    value = value[0:max_len-1] + ch

    return value

def ux_show_phish_words(dis, words):
    # Show the anti-phishing words
    x = 34//2
    y = 7
    if not words:
        # just clear line
        dis.clear_box(0, y, CHARS_W, 1)
    else:
        dis.text(x - len(words[0]) - 1, y,   words[0])
        dis.text(x + 1, y, words[1])

def ux_show_pin(dis, pin, subtitle, prefix, is_confirmation, force_draw,
                    footer=None, randomize=None):

    # Draw PIN during entry / reentry / changing or setting

    # verticals
    rnd_y = 0           # jammed in at top; doesn't look great but rarely used?
    foot_y = -1         # footer at foot
    y = 4               # main focus area, center line
    if randomize: 
        y += 1

    # for MAX_PIN_PART_LEN==6, and one char margin both sides
    x = 6
    w = 8

    # position of prefix/suffix digits
    ppx = x + 2
    ssx = x + w + 6

    if force_draw:
        dis.clear()

        if randomize:
            # screen redraw, when we are "randomized"
            # - only used at login, none of the other cases
            # - test w/ "simulator.py --q1 -g --eff --set rngk=1"

            # show mapping of numbers vs. PIN digits
            dis.text(1, rnd_y+0, '  ' + '  '.join(randomize[1:]) +'  '+ randomize[0] + '  ', invert=1)
            dis.text(1, rnd_y+1, '↳ 1  2  3  4  5  6  7  8  9  0')

        dis.text(x+w+2, y, '⋯', dark=True)

        if footer:
            # ie. '1 failures, 12 tries left'
            dis.text(None, foot_y, footer, dark=True)
        elif is_confirmation:
            dis.text(None, foot_y, "Confirm PIN value")
    else:
        dis.clear_box(ppx, y, 6, 1)
        dis.clear_box(ssx, y, 6, 1)
        if not prefix:
            ux_show_phish_words(dis, None)

    # prefix/not prefix can change anytime, so redraw this stuff
    dis.draw_box(x, y-1, w, 1, dark=bool(prefix))
    dis.draw_box(x+w+4, y-1, w, 1, dark=not bool(prefix))

    prompt = "Enter first part of PIN" if not prefix else "Enter second part of PIN" 

    if not subtitle:
        dis.text(None, y-2, prompt)
    else:
        # "New Main PIN" and similar
        dis.text(None, y-3, subtitle, dark=False)
        dis.text(None, y-2, prompt, dark=True)

    # show dots            
    active = '•' * len(prefix or pin)

    if prefix:
        # show both first part and second
        suffix = '•' * len(pin)
        dis.text(ppx, y, active, dark=True)
        cur_x = dis.text(ssx, y, suffix)
    else:
        # just showing first part
        cur_x = dis.text(ppx, y, active)
        dis.clear_box(ssx, y, 6, 1)

    if len(pin) == 6:
        # cursor on final 6th digit
        dis.show(cursor=CursorSpec(cur_x-1, y, CURSOR_OUTLINE))
    else:
        dis.show(cursor=CursorSpec(cur_x, y, CURSOR_SOLID))

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

def ux_render_words(words, leading_blanks=1):
    # re-use word-list rendering code to show as a string in a story.
    # - because I want them all on-screen at once, and not simple to do that
    buf = [bytearray(CHARS_W) for y in range(CHARS_H)]

    rv = [''] * leading_blanks

    num_words = len(words)
    if num_words == 12:
        for y in range(6):
            rv.append('%2d: %-8s   %2d: %s' % (y+1, words[y], y+7, words[y+6]))
    else:
        lines = 6 if num_words == 18 else 8
        for y in range(lines):
            rv.append('%d:%-8s %2d:%-8s %2d:%s' % (y+1, words[y], 
                    y+lines+1, words[y+lines], 
                    y+(lines*2)+1, words[y+(lines*2)]))

    return '\n'.join(rv)
    

def ux_draw_words(y, num_words, words):
    # Draw seed words on single screen (hard) and return x/y position of start of each
    from glob import dis

    if num_words == 12:
        cols = 2
        xpos = [2, 18]
    else:
        cols = 3
        xpos = [0, 11, 23]

    n_per_c = num_words // cols     #   6/4/8

    rv = []
    for n, word in enumerate(words, 1):
        if num_words == 12:
            # luxious space after colon
            msg = ('%2d: ' % n) + word
            x_off = 3
        else:
            if n <= n_per_c:
                # no space in front of 1: thru N: in leftmost column of 3
                msg = ('%d:' % n) + word
                x_off = 2
            else:
                msg = ('%2d:' % n) + word
                x_off = 3

        X, Y = xpos[(n-1) // n_per_c], y + ((n-1) % n_per_c)
        dis.text(X, Y, msg)
        rv.append( (X+x_off, Y) )

    return rv

async def seed_word_entry(prompt, num_words, has_checksum=True, done_cb=None):
    # Accept a seed phrase, only
    # - replaces WordNestMenu on Q1
    # - max word length is 8, min is 3
    # - useful: simulator.py --q1 --eff --seq 'aa ee 4i '
    from glob import dis

    assert num_words and prompt and done_cb

    def redraw_words(wrds=None):
        if not wrds:
            wrds = ['' for _ in range(num_words)]

        dis.clear()
        dis.text(None, 0, prompt, invert=1)
        p = ux_draw_words(2 if num_words != 24 else 1, num_words, wrds)
        return wrds, p

    words, pos = redraw_words()

    word_num = 0
    value = ''
    err_msg = last_err = None
    press = PressRelease()
    last_words = []
    while 1:
        final = (word_num == num_words)
        if final:
            # useful to show final word on screen, even tho confirm not needed
            err_msg = 'Press ENTER if all done.' if not has_checksum else \
                      'Valid words! Press ENTER.'
            cur = None
        else:
            x, y = pos[word_num]
            ln = len(value)
            if ln == 8:
                # outline-style cursor if on top of final possible location
                cur = CursorSpec(x+ln-1, y, CURSOR_OUTLINE)
            else:
                cur = CursorSpec(x+ln, y, CURSOR_SOLID)

            dis.text(x, y, '%-8s' % value)

        # show error msg, until they type anything to clear it
        if err_msg:
            dis.text(None, -1, err_msg, dark=True)
            err_msg = None
            last_err = True
        elif last_err:
            dis.text(None, -1, '')
            last_err = False

        dis.show(cursor=cur)
        ch = await press.wait()

        commit = False
        if ch == KEY_QR:
            try:
                got = await QRScannerInteraction.scan('Scan seed from a QR code')
                what, vals = decode_qr_result(got, expect_secret=True)
            except QRDecodeExplained as e:
                err_msg = str(e)
                redraw_words()
                continue

            if what != "words":
                err_msg = "Must be seed words, not %s" % what
            elif num_words != len(vals[0]):
                err_msg = "Must be seed of length %d, not %s" % (num_words, len(vals[0]))
            else:
                words = vals[0]
                # offer just the actual imported csum if user deletes csum word
                last_words = [words[-1]]
                word_num = num_words

            # needs redraw, empty on error with error below
            # if success, qr imported words shown to user
            redraw_words(words)

        elif ch == KEY_ENTER:
            if final:
                break
            commit = True
        elif (ch == KEY_DELETE) or (ch == KEY_LEFT):
            # delete last char
            if len(value) > 0:
                value = value[:-1]
            elif word_num:
                # go to prev word
                word_num -= 1
                words[word_num] = value = ''
                
        elif ch == KEY_CLEAR:
            value = ''
        elif ch == KEY_CANCEL:
            if word_num >= 2:
                tmp = dis.save_state()
                ok = await ux_confirm("Everything you've entered will be lost.")
                if not ok: 
                    dis.restore_state(tmp)
                    continue
            return None
        elif final:
            # below options not allowed if all words already provided
            continue
        elif ch in {' ', KEY_TAB, KEY_DOWN, KEY_RIGHT}:
            # re-consider if word done, like "act" and other 3-letter cases
            commit = True
        elif ch.isalpha():
            value += ch.lower()
        else:
            continue

        if has_checksum and (word_num == num_words-1) and ((len(value) >= 1) or commit):
            assert last_words
            if value not in last_words:
                maybe = [i for i in last_words if i.startswith(value)]
                if len(maybe) == 1:
                    value = maybe[0]
                elif len(maybe) == 0:
                    if len(last_words) == 8:        # 24 words case
                        ll = ''.join(sorted(set([w[0] for w in last_words])))
                        err_msg = 'Final word starts with: ' + ll
                    else:
                                   ##################################
                        err_msg = "Final word cannot start with: " + value
                    value = value[:-1]
                    continue
                else:
                    nextchars = ''.join(sorted(set(i[len(value)] for i in maybe)))
                    err_msg = 'Next key: ' + nextchars
                    continue

            if value in last_words:
                dis.text(x, y, '%-8s' % value)
                words[word_num] = value
                word_num += 1
                value = ''
                continue
        
        if len(value) >= 2:
            exact, nextchars, is_word = bip39.next_char(value)
            #print('%s => exact=%s nextchars=%s is_word=%s' % (value, exact, nextchars, is_word))

            if exact and not is_word and commit:
                # they pressed space after a valid 3 letter prefix (act vs actor)
                is_word = value

            if is_word:
                # word is from list, so we are done... move to next word
                words[word_num] = is_word
                dis.text(x, y, '%-8s' % is_word)
                word_num += 1
                value = ''

                if has_checksum and word_num == num_words-1:
                    # calc all possible final words
                    # 12 -> 128, 18->32, 24->8
                    last_words = list(bip39.a2b_words_guess(words[:-1]))

            elif not nextchars:
                err_msg = 'Not a BIP-39 word: ' + value
                value = value[0:3]
            else:
                err_msg = 'Next key: ' + nextchars

    await done_cb(words)

def ux_dice_rolling():
    from glob import dis

    # draw fixed parts of screen
    dis.clear()
    dis.text(0, 1, "Press 1-6 for each dice roll")
    dis.text(0, 2, "to mix in.")

    def update(count, hx=None):
        dis.text(None, 4, '%d rolls so far' % count, invert=1)

        if hx is not None:
            dis.text(0, -2, hx[0:32]+'-', dark=True)
            dis.text(2, -1, ''+hx[32:], dark=True)

        dis.show()

    # return funct to draw updating part
    return update

class QRScannerInteraction:
    def __init__(self):
        pass

    @staticmethod
    async def scan(prompt, line2=None):
        # draw animation, while waiting for them to scan something
        # - CANCEL to abort
        # - returns a string, BBQr object or None.
        from glob import dis, SCAN
        from ux import ux_wait_keydown
        frames = [ 1, 2, 3, 4, 5, 4, 3, 2 ]

        if not SCAN:
            raise QRDecodeExplained("Hardware fault.")

        dis.clear()
        dis.text(None, -2, prompt)
        if line2:
            dis.text(None, -1, line2, dark=True)
        dis.show()

        task = asyncio.create_task(SCAN.scan_once())

        ph = 0
        while 1:
            if task.done():
                data = await task
                #print("Scanned: %r" % data)
                break

            dis.image(None, 40, 'scan_%d' % frames[ph])
            ph  = (ph + 1) % len(frames)

            # wait for key or 250ms animation delay
            ch = await ux_wait_keydown(KEY_CANCEL, 250)

            if ch == KEY_CANCEL:
                data = None
                break

        task.cancel()

        # clear screen right away so user knows we got it
        dis.clear()
        dis.show()

        return data

    async def scan_general(self, prompt, convertor):
        # Scan stuff, and parse it .. raise QRDecodeExplained if you don't like it
        # continues until something is accepted
        problem = None

        while 1:
            try:
                got = await self.scan(prompt, line2=problem)
                if got is None:
                    return None

                # Decode BBQr but not anything more complex
                return convertor(got)
            except QRDecodeExplained as exc:
                problem = str(exc)
                continue
            except Exception as exc:
                #import sys; sys.print_exception(exc)
                problem = "Unable to decode QR"
                continue


    async def scan_text(self, prompt):
        # Scan and return a text string. For things like BIP-39 passphrase
        # and perhaps they are re-using a QR from something else. Don't act on contents.
        def convertor(got):
            return decode_qr_result(got, expect_text=True)
        return await self.scan_general(prompt, convertor)

    async def scan_json(self, prompt):
        # Scan for a BBQr and a BBQr object. Converts sometimes?
        def convertor(got):
            file_type, _, data = decode_qr_result(got, expect_bbqr=True)
            if file_type == 'U':
                data = data.strip()
                if data[0] == '{' and data[-1] == '}':
                    file_type = 'J'
            if file_type != 'J':
                raise QRDecodeExplained('Expected JSON data')
            try:
                import json
                return json.loads(data)
            except:
                raise QRDecodeExplained('Unable to decode JSON data')
            
        return await self.scan_general(prompt, convertor)


    async def scan_anything(self, expect_secret=False, tmp=False):
        # start a QR scan, and act on what we find, whatever it may be.
        problem = None
        while 1:
            prompt = 'Scan any QR code, or CANCEL' if not expect_secret else \
                        'Scan XPRV or Seed Words, or CANCEL'

            try:
                got = await self.scan(prompt, line2=problem)
                if got is None:
                    return

                # Figure out what we got.
                what, vals = decode_qr_result(got, expect_secret=expect_secret)
            except QRDecodeExplained as exc:
                problem = str(exc)
                continue
            except Exception as exc:
                import sys; sys.print_exception(exc)
                problem = "Unable to decode QR"
                continue

            if what == 'xprv':
                from actions import import_extended_key_as_secret
                text_xprv, = vals
                await import_extended_key_as_secret(text_xprv, tmp)
                return

            if what == 'words':
                from seed import commit_new_words, set_ephemeral_seed_words       # dirty API
                words, = vals
                if tmp:
                    await set_ephemeral_seed_words(words, 'From QR')
                else:
                    await commit_new_words(words)

                return

            if what == 'psbt':
                decoder, psbt_len, got = vals
                await qr_psbt_sign(decoder, psbt_len, got)
                return

            if what == 'txn':
                bin_txn, = vals
                await ux_visualize_txn(bin_txn)
                return 

            if what == 'addr':
                proto, addr, args = vals
                await ux_visualize_bip21(proto, addr, args)
                return

            if what in ("multi", "minisc"):
                from auth import maybe_enroll_xpub
                from ux import ux_show_story
                ms_config, = vals
                try:
                    maybe_enroll_xpub(config=ms_config,
                                      miniscript=False if what == "multi" else None)
                except Exception as e:
                    await ux_show_story(
                        'Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))
                return

            if what == "wif":
                data, = vals
                wif_str, key_pair, compressed, testnet = data
                await ux_visualize_wif(wif_str, key_pair, compressed, testnet)
                return

            if what == 'text' or what == 'xpub':
                # we couldn't really decode it.
                txt, = vals
                await ux_visualize_textqr(txt)
                return 

            # not reached?
            problem = 'Unhandled: ' + what
            

async def qr_psbt_sign(decoder, psbt_len, raw):
    # Got a PSBT coming in from QR scanner. Sign it.
    # - similar to auth.sign_psbt_file()
    from auth import UserAuthorizedAction, ApproveTransaction, try_push_tx
    from utils import CapsHexWriter
    from glob import dis, PSRAM
    from ux import show_qr_code, the_ux, ux_show_story
    from ux_q1 import show_bbqr_codes
    from sffile import SFFile
    from auth import MAX_TXN_LEN, TXN_INPUT_OFFSET, TXN_OUTPUT_OFFSET

    if raw != 'PSRAM':      # might already be in place

        if isinstance(raw, str):
            raw = raw.encode()

        # copy to PSRAM, and convert encoding at same time
        total = 0
        with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
            if not decoder:
                total += out.write(raw)
            else:
                for here in decoder.more(raw):
                    out.write(here)
                    total += len(here)

        # might have been whitespace inflating initial estimate of PSBT size
        assert total <= psbt_len
        psbt_len = total

    async def done(psbt):
        dis.fullscreen("Wait...")
        txid = None

        with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as psram:

            # save transaction, as hex into PSRAM
            with CapsHexWriter(psram) as fd:
                if psbt.is_complete():
                    txid = psbt.finalize(fd)
                else:
                    psbt.serialize(fd)

            data_len, sha = psram.tell(), fd.checksum.digest()

        UserAuthorizedAction.cleanup()

        # Show the result as a QR, perhaps many BBQr's
        # - note: already HEX here!
        here = PSRAM.read_at(TXN_OUTPUT_OFFSET, data_len)
        if txid and await try_push_tx(a2b_hex(here), txid, sha):
            return  # success, exit

        try:
            await show_qr_code(here.decode(), is_alnum=True,
                               msg=(txid or 'Partly Signed PSBT'))
        except (ValueError, RuntimeError):
            await show_bbqr_codes('T' if txid else 'P', here,
                                  (txid or 'Partly Signed PSBT'),
                                  already_hex=True)

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, approved_cb=done)
    the_ux.push(UserAuthorizedAction.active_request)

async def ux_visualize_txn(bin_txn):
    # Show the user a signed transaction on-screen.
    # - longer-term we may offer more data about address ownership, etc
    # - be careful not to claim things we cannot prove w/o UTXO from confirmed blocks
    # - .. like the fee, which would be useful
    from ux import ux_show_story
    from io import BytesIO
    from psbt import  calc_txid
    from serializations import CTransaction

    txn = CTransaction()

    try:
        txn.deserialize(BytesIO(bin_txn))

        if (n := len(txn.vin)) == 1:
            msg = '1 input, '
        else: 
            msg = '%d inputs, ' % n

        if (n := len(txn.vout)) == 1:
            msg += '1 output'
        else: 
            msg += '%d outputs' % n

        # add txid
        txid = calc_txid(BytesIO(bin_txn), (0, len(bin_txn)))
        msg += '\n\nTxid:\n' + b2a_hex(txid).decode()

    except Exception as exc:
        sys.print_exception(exc)
        msg = "Unable to deserialize"

    await ux_show_story(msg, title="Signed Transaction")


async def ux_visualize_bip21(proto, addr, args):
    # Show details of BIP-21 URL
    # - imho, a bare address is a valid BIP-21 URL so we come here too
    # - validate address ownership on request
    from ux import ux_show_story

    msg = addr + '\n\n'
    args = args or {}

    if 'amount' in args:
        msg += 'Amount: '
        try:
            amt = args.pop('amount')
            whole, frac = amt.split('.', 1)
            frac = int(frac) if frac else 0
            whole = int(whole) if whole else 0
            msg += '%d.%08d BTC\n' % (whole, frac)
        except:
            msg += '(corrupt)\n'

    for fn in ['label', 'message', 'lightning']:
        if fn in args:
            val = args.pop(fn)
            msg += '%s%s: %s\n' % (fn[0].upper(), fn[1:], val)

    if args:
        msg += 'And values for: ' + ', '.join(args)
        msg += "\n"

    msg += '\nPress (1) to verify ownership.'
    
    ch = await ux_show_story(msg, title="Payment Address", escape='1')

    if ch == '1':
        from ownership import OWNERSHIP
        await OWNERSHIP.search_ux(addr)

async def ux_visualize_wif(wif_str, kp, compressed, testnet):
    from ux import ux_show_story
    msg = wif_str + "\n\n"
    msg += "chain: %s\n\n" % ("XTN" if testnet else "BTC")
    msg += "private key hex:\n" + b2a_hex(kp.privkey()).decode() + "\n\n"
    msg += "public key sec:\n" + b2a_hex(kp.pubkey().to_bytes(not compressed)).decode() + "\n\n"
    await ux_show_story(msg, title="WIF")

async def ux_visualize_textqr(txt, maxlen=200):
    # Show simple text. Don't crash on huge things, but be
    # able to show a full xpub.
    from ux import ux_show_story
    if len(txt) > maxlen:
        txt = txt[0:maxlen] + '...'

    await ux_show_story("%s\n\nAbove is text that was scanned. "
            "We can't do any more with it." % txt, title="Simple Text")

async def show_bbqr_codes(type_code, data, msg, already_hex=False):
    # Compress, encode and split data, then show it animated...
    # - happily goes to version 40 if needed
    # - needs to pre-render the QR to get animation to be faster
    # - version of first QR is used for all ther others
    # - screen resolution is considered when picking QR version number
    # - data may point to output side of PSRAM area
    # - Should always do zlib compression (because it nearly always helps)
    #    - BUT: need zlib compress (not present) .. delayed for now
    from bbqr import TYPE_LABELS, int2base36, b32encode, num_qr_needed
    from glob import PSRAM, dis
    from ux import ux_wait_keyup, ux_wait_keydown
    import uqr

    assert not PSRAM.is_at(data, 0)     # input data would be overwritten with our work
    assert type_code in TYPE_LABELS

    dis.fullscreen('Generating BBQr...', .1)

    if already_hex:
        encoding = 'H'
        data_len = len(data) // 2
    else:
        # default to Base32, because always best option
        encoding = '2'
        data_len = len(data)

    # try a few select resolutions (sizes) in order such that we use either single QR
    # or the least-dense option that gives reasonable number of QR's
    target_vers, num_parts, part_size = num_qr_needed(encoding, data_len)

    assert num_parts * part_size >= data_len

    pos = 0
    force_version = 40
    for pkt in range(num_parts):
        # BBQr header
        hdr = 'B$' + encoding + type_code + int2base36(num_parts) + int2base36(pkt)

        # encode the bytes
        assert pos < data_len, (pkt, pos, data_len)
        if already_hex:
            # not encoding, just chars->bytes
            hp = pos*2
            body = data[hp:hp+(part_size*2)].decode()
        else:
            # base32 encoding
            body = b32encode(data[pos:pos+part_size])

        pos += part_size

        # do the hard work
        qr_data = uqr.make(hdr+body, min_version=(10 if pkt == 0 else force_version),
                                    max_version=force_version, encoding=uqr.Mode_ALPHANUMERIC)

        # save the rendered QR
        if pkt == 0:
            # common values for all parts
            scan_w, w, raw = qr_data.packed()
            raw_qr_size = len(raw)
            qr_size = (raw_qr_size + 3) & ~0x3        # align4
            force_version = qr_data.version()
            assert force_version <= target_vers
        else:
            _, _, raw = qr_data.packed()

        PSRAM.write_at(qr_size * pkt, qr_size)[0:raw_qr_size] = raw

        del qr_data

        dis.progress_bar_show((pkt+1) / num_parts)
    
    # display rate (plus time to send to display, etc)
    ms_per_each = 200

    # hide Generating... text
    dis.fullscreen(' ', 1)
    dis.show()

    ch = None
    while not ch:
        for pkt in range(num_parts):
            buf = PSRAM.read_at(qr_size * pkt, raw_qr_size)
            dis.draw_qr_display( (scan_w, w, buf), msg, True, None, None, False, 
                                    partial_bar=((pkt, num_parts) if num_parts else None))

            if num_parts == 1:
                # no need for animation
                ch = await ux_wait_keydown()
                break

            # wait for key or animation delay
            ch = await ux_wait_keydown(None, ms_per_each)
            if ch: break

    # after QR drawing, we need to correct some pixels
    dis.real_clear()


# EOF
