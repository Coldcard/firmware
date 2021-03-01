# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux.py - UX/UI related helper functions
#
from uasyncio import sleep_ms
from queues import QueueEmpty
import utime, gc

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

def ux_poll_once(expected='x'):
    # non-blocking check if key is pressed
    # - ignore and suppress any key not in expected
    # - responds to key down only
    # - eats any existing key presses
    from glob import numpad

    while 1:
        try:
            ch = numpad.key_pressed
            while not ch:
                ch = numpad.get_nowait()

                if ch == numpad.ABORT_KEY:
                    raise AbortInteraction()
        except QueueEmpty:
            return None

        for c in ch:
            if c in expected:
                return c

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

def word_wrap(ln, w):
    while ln:
        sp = ln.rfind(' ', 0, w)

        if sp == -1:
            # bad-break the line
            sp = min(len(ln), w)
            nsp = sp
        else:
            nsp = sp+1

        left = ln[0:sp]
        ln = ln[nsp:]

        if len(left) + 1 + len(ln) <= CH_PER_W:
            left = left + ' ' + ln
            ln = ''

        yield left

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

    #print("story:\n\n\"" + '"\n"'.join(lines))
    #lines[0] = '111111111121234567893'

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
    from nvstore import settings

    while not glob.hsm_active:
        await sleep_ms(250)

        # they may have changed setting recently
        timeout = settings.get('idle_to', DEFAULT_IDLE_TIMEOUT)*1000        # ms
        if timeout == 0:
            continue

        now = utime.ticks_ms() 

        if not glob.numpad.last_event_time:
            continue

        if now > glob.numpad.last_event_time + timeout:
            # do a logout now.
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
    o = QRDisplay(addrs, is_alnum, start_n, sidebar=None)
    await o.interact_bare()

class QRDisplay(UserInteraction):
    # Show a QR code for (typically) a list of addresses. Can only work on Mk3

    def __init__(self, addrs, is_alnum, start_n=0, sidebar=None):
        self.is_alnum = is_alnum
        self.idx = 0             # start with first address
        self.invert = False      # looks better, but neither mode is ideal
        self.addrs = addrs
        self.sidebar = sidebar
        self.start_n = start_n
        self.qr_data = None

    def render_qr(self, msg):
        # Version 2 would be nice, but can't hold what we need, even at min error correction,
        # so we are forced into version 3 = 29x29 pixels
        # - see <https://www.qrcode.com/en/about/version.html>
        # - to display 29x29 pixels, we have to double them up: 58x58
        # - not really providing enough space around it
        # - inverted QR (black/white swap) still readable by scanners, altho wrong

        from utils import imported

        with imported('uqr') as uqr:
            if self.is_alnum:
                # targeting 'alpha numeric' mode, typical len is 42
                enc = uqr.Mode_ALPHANUMERIC
                assert len(msg) <= 47
                msg = msg.upper()
            else:
                # has to be 'binary' mode, altho shorter msg, typical 34-36
                enc = uqr.Mode_BYTE
                assert len(msg) <= 42

            self.qr_data = uqr.make(msg, min_version=3, max_version=3, encoding=enc)


    def redraw(self):
        # Redraw screen.
        from glob import dis
        from display import FontSmall, FontTiny


        # what we are showing inside the QR
        msg = self.addrs[self.idx]

        # make the QR, if needed.
        if not self.qr_data:
            dis.busy_bar(True)

            self.render_qr(msg)

        # draw display
        dis.clear()

        w = 29          # because version=3
        XO,YO = 7, 3    # offsets

        if not self.invert:
            dis.dis.fill_rect(XO-YO, 0, 64, 64, 1)

        inv = self.invert
        for x in range(w):
            for y in range(w):
                px = self.qr_data.get(x, y)
                X = (x*2) + XO
                Y = (y*2) + YO
                dis.dis.fill_rect(X,Y, 2,2, px if inv else (not px))

        x, y = 73, 0 if self.is_alnum else 2
        sidebar, ll = self.sidebar or (msg, 7)
        for i in range(0, len(sidebar), ll):
            dis.text(x, y, sidebar[i:i+ll], FontSmall)
            y += 10 if self.is_alnum else 12

        if not inv and len(self.addrs) > 1:
            # show path number, very tiny
            ai = str(self.start_n + self.idx)
            if len(ai) == 1:
                dis.text(0, 30, ai[0], FontTiny)
            else:
                dis.text(0, 27, ai[0], FontTiny)
                dis.text(0, 27+7, ai[1], FontTiny)

        dis.busy_bar(False)     # includes show


    async def interact_bare(self):
        self.redraw()

        while 1:
            ch = await ux_wait_keyup()

            if ch == '1':
                self.invert = not self.invert
                self.redraw()
                continue
            elif ch in 'xy':
                break
            elif ch == '5' or ch == '7':
                if self.idx > 0:
                    self.idx -= 1
            elif ch == '8' or ch == '9':
                if self.idx != len(self.addrs)-1:
                    self.idx += 1
            else:
                continue

            # self.idx has changed, so need full re-render
            self.qr_data = None
            self.redraw()

    async def interact(self):
        await self.interact_bare()
        the_ux.pop()


async def ux_enter_number(prompt, max_value):
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
    dis.text(None, -1, "X to DELETE, or OK when DONE.", FontTiny)
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
            else:
                # quit if they press X on empty screen
                return 0
        else:
            if len(value) == max_w:
                value = value[0:-1] + ch
            else:
                value += ch

            # cleanup leading zeros and such
            value = str(int(value))

# EOF
