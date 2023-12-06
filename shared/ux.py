# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux.py - UX/UI related helper functions
#
from uasyncio import sleep_ms
from queues import QueueEmpty
import utime, gc
from utils import word_wrap

DEFAULT_IDLE_TIMEOUT = const(4*3600)      # (seconds) 4 hours

# This signals the need to switch from current
# menu (or whatever) to show something new. The
# stack has already been updated, but the old 
# top-of-stack code was waiting for a key event.
#
class AbortInteraction(BaseException):
    pass

class UserInteraction:
    def __init__(self):
        self.stack = []

    def top_of_stack(self):
        return self.stack[-1] if self.stack else None

    def reset(self, new_ux):
        self.stack.clear()
        gc.collect()
        self.push(new_ux)

    async def interact(self):
        # this is called inside a while(1) all the time
        # - execute top of stack item
        try:
            await self.stack[-1].interact()
        except AbortInteraction:
            pass

    def push(self, new_ux):
        self.stack.append(new_ux)

    def replace(self, new_ux):
        old = self.stack.pop()
        del old
        self.stack.append(new_ux)

    def pop(self):
        if len(self.stack) < 2:
            # top of stack, do nothing
            return True

        old = self.stack.pop()
        del old

    def parent_of(self, child_ux):
        for n, x in enumerate(self.stack):
            if x == child_ux and n:
                return self.stack[n-1]
        return None

# Singleton. User interacts with this "menu" stack.
the_ux = UserInteraction()

def ux_clear_keys(no_aborts=False):
    # flush any pending keypresses
    from glob import numpad

    try:
        while 1:
            ch = numpad.get_nowait()

            if not no_aborts and ch == numpad.ABORT_KEY:
                raise AbortInteraction()

    except QueueEmpty:
        return

async def ux_wait_keyup(expected=None):
    # Wait for single keypress in 'expected' set, return it
    # no visual feedback, no escape
    from glob import numpad

    armed = None
    while 1:
        ch = await numpad.get()

        if ch == numpad.ABORT_KEY:
            raise AbortInteraction()

        if len(ch) > 1:
            # multipress
            continue

        if expected and (ch not in expected):
            # unwanted
            continue

        if ch == '' and armed:
            return armed

        armed = ch

def ux_poll_key():
    # non-blocking check if any key is pressed
    # - responds to key down only
    from glob import numpad

    try:
        ch = numpad.get_nowait()

        if ch == numpad.ABORT_KEY:
            raise AbortInteraction()
    except QueueEmpty:
        return None

    return ch

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

# how many characters can we fit on each line?
# (using FontSmall)
CH_PER_W = const(17)

async def ux_show_story(msg, title=None, escape=None, sensitive=False, strict_escape=False):
    # show a big long string, and wait for XY to continue
    # - returns character used to get out (X or Y)
    # - can accept other chars to 'escape' as well.
    # - accepts a stream or string
    from glob import dis, numpad
    from display import FontLarge

    lines = []
    if title:
        # kinda weak rendering but it works.
        lines.append('\x01' + title)

    if hasattr(msg, 'readline'):
        msg.seek(0)
        for ln in msg:
            if ln[-1] == '\n': 
                ln = ln[:-1]

            if len(ln) > CH_PER_W:
                lines.extend(word_wrap(ln, CH_PER_W))
            else:
                # ok if empty string, just a blank line
                lines.append(ln)

        # no longer needed & rude to our caller, but let's save the memory
        msg.close()
        del msg
        gc.collect()
    else:
        for ln in msg.split('\n'):
            if len(ln) > CH_PER_W:
                lines.extend(word_wrap(ln, CH_PER_W))
            else:
                # ok if empty string, just a blank line
                lines.append(ln)

    # trim blank lines at end, add our own marker
    while not lines[-1]:
        lines = lines[:-1]

    lines.append('EOT')

    top = 0
    H = 5
    ch = None
    pr = PressRelease()
    while 1:
        # redraw
        dis.clear()

        y=0
        for ln in lines[top:top+H]:
            if ln == 'EOT':
                dis.hline(y+3)
            elif ln and ln[0] == '\x01':
                dis.text(0, y, ln[1:], FontLarge)
                y += 21
            else:
                dis.text(0, y, ln)

                if sensitive and len(ln) > 3 and ln[2] == ':':
                    dis.mark_sensitive(y, y+13)

                y += 13

        dis.scroll_bar(top / len(lines))
        dis.show()

        # wait to do something
        ch = await pr.wait()
        if escape and (ch == escape or ch in escape):
            # allow another way out for some usages
            return ch
        elif ch in 'xy':
            if not strict_escape:
                return ch
        elif ch == '0':
            top = 0
        elif ch == '7':     # page up
            top = max(0, top-H)
        elif ch == '9':     # page dn
            top = min(len(lines)-2, top+H)
        elif ch == '5':     # scroll up
            top = max(0, top-1)
        elif ch == '8':     # scroll dn
            top = min(len(lines)-2, top+1)

        

async def idle_logout():
    import glob
    from glob import settings

    while not glob.hsm_active:
        await sleep_ms(5000)

        if not glob.numpad.last_event_time:
            continue

        now = utime.ticks_ms() 
        dt = utime.ticks_diff(now, glob.numpad.last_event_time)

        # they may have changed setting recently
        timeout = settings.get('idle_to', DEFAULT_IDLE_TIMEOUT)*1000        # ms

        if timeout and dt > timeout:
            # user has been idle for too long: do a logout
            print("Idle!")

            from actions import logout_now
            await logout_now()
            return              # not reached
            
async def ux_confirm(msg):
    # confirmation screen, with stock title and Y=of course.

    resp = await ux_show_story("Are you SURE ?!?\n\n" + msg)

    return resp == 'y'


async def ux_dramatic_pause(msg, seconds):
    from glob import dis, hsm_active

    if hsm_active:
        return

    # show a full-screen msg, with a dramatic pause + progress bar
    n = seconds * 8
    dis.fullscreen(msg)
    for i in range(n):
        dis.progress_bar_show(i/n)
        await sleep_ms(125)

    ux_clear_keys()

def show_fatal_error(msg):
    # show a multi-line error message, over some kinda "fatal" banner
    from glob import dis
    from display import FontTiny

    dis.clear()
    lines = msg.split('\n')[-6:]
    dis.text(None, 1, '>>>> Yikes!! <<<<')

    y = 13+2
    for num, ln in enumerate(lines):
        ln = ln.strip()

        if ln[0:6] == 'File "':
            # convert: File "main.py", line 63, in interact
            #    into: main.py:63  interact
            ln = ln[6:].replace('", line ', ':').replace(', in ', '  ')

        dis.text(0, y + (num*8), ln, FontTiny)

    dis.show()

async def ux_aborted():
    # use this when dangerous action is not performed due to confirmations
    await ux_dramatic_pause('Aborted.', 2)
    return None

def restore_menu():
    # redraw screen contents after distrupting it w/ non-ux things (usb upload)
    m = the_ux.top_of_stack()

    if hasattr(m, 'update_contents'):
        m.update_contents()

    if hasattr(m, 'show'):
        m.show()

def abort_and_goto(m):
    # cancel any menu drill-down and show them some UX
    from glob import numpad
    the_ux.reset(m)
    numpad.abort_ux()

def abort_and_push(m):
    # keep menu position, but interrupt it with a new UX
    from glob import numpad
    the_ux.push(m)
    numpad.abort_ux()

async def show_qr_codes(addrs, is_alnum, start_n):
    from qrs import QRDisplaySingle
    o = QRDisplaySingle(addrs, is_alnum, start_n, sidebar=None)
    await o.interact_bare()

async def show_qr_code(data, is_alnum, msg=None):
    from qrs import QRDisplaySingle
    o = QRDisplaySingle([data], is_alnum, sidebar=msg)
    await o.interact_bare()

async def ux_enter_bip32_index(prompt, can_cancel=False, unlimited=False):
    if unlimited:
        max_value = (2 ** 31) - 1  # we handle hardened
    else:
        max_value = 9999
    return await ux_enter_number(prompt=prompt, max_value=max_value, can_cancel=can_cancel)

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

async def ux_input_numbers(val, validate_func):
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

# EOF
