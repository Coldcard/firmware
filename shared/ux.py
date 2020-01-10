# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# ux.py - UX/UI related helper functions
#
# NOTE: do not import from main at top.
from uasyncio import sleep_ms
from uasyncio.queues import QueueEmpty
import utime, gc

DEFAULT_IDLE_TIMEOUT = const(4*3600)      # (seconds) 4 hours

# This signals the need to switch from current
# menu (or whatever) to show something new. The
# stack has already been updated, but the old 
# top-of-stack code was waiting for a key event.
#
class AbortInteraction(Exception):
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
    from main import numpad

    try:
        while 1:
            ch = numpad.get_nowait()

            if not no_aborts and ch == numpad.ABORT_KEY:
                raise AbortInteraction

    except QueueEmpty:
        return

async def ux_wait_keyup(expected=None):
    # Wait for single keypress in 'expected' set, return it
    # no visual feedback, no escape
    from main import numpad

    armed = None
    while 1:
        ch = await numpad.get()

        if ch == numpad.ABORT_KEY:
            raise AbortInteraction

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
    from main import numpad

    while 1:
        try:
            ch = numpad.key_pressed
            while not ch:
                ch = numpad.get_nowait()

                if ch == numpad.ABORT_KEY:
                    raise AbortInteraction
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
        from main import numpad

        armed = None

        while 1:
            rep_delay = numpad.repeat_delay if not self.num_repeats else 100
            so_far = 0

            while 1:
                try:
                    # Poll for an event
                    ch = numpad.get_nowait()
                    break
                except QueueEmpty:
                    so_far += 5
                    await sleep_ms(5)

                    if self.last_key and numpad.key_pressed == self.last_key:
                        if so_far >= rep_delay:
                            self.num_repeats += 1
                            return self.last_key

                    continue

            if ch == numpad.ABORT_KEY:
                raise AbortInteraction

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

async def ux_press_release(need_release='xy', key_repeat=None):
    # Wait for single char press event, 
    # except for need_release keys, which must be released before they
    # are sent as events, and no corresponding release event (already consumed).
    #
    from main import numpad

    # never do key-repeat on keys that need "ups"
    if key_repeat and key_repeat in need_release:
        key_repeat = None

    armed = None
    while 1:
        if key_repeat and numpad.key_pressed == key_repeat:
            await sleep_ms(100)     # key repeat-rate, also key-repeat delay time
            if numpad.key_pressed == key_repeat:
                return key_repeat

        ch = await numpad.get()

        if ch == numpad.ABORT_KEY:
            raise AbortInteraction

        if len(ch) > 1:
            # multipress: cancel press/release cycle and be a keyup
            # for other keys.
            armed = None
            continue

        if ch == '':
            if armed:
                return armed
        elif ch in need_release:
            armed = ch
        else:
            return ch

async def ux_all_up():
    # wait until all keys are released
    from main import numpad

    while 1:
        ch = await numpad.get()
        if ch == numpad.ABORT_KEY:
            raise AbortInteraction
        if ch == '':
            return

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
    from main import dis, numpad
    from display import FontLarge

    assert not numpad.disabled      # probably inside a CardSlot context

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
    from main import numpad, settings
    from hsm import hsm_active

    while not hsm_active:
        await sleep_ms(250)

        # they may have changed setting recently
        timeout = settings.get('idle_to', DEFAULT_IDLE_TIMEOUT)*1000        # ms
        if timeout == 0:
            continue

        now = utime.ticks_ms() 

        if not numpad.last_event_time:
            continue

        if now > numpad.last_event_time + timeout:
            # do a logout now.
            print("Idle!")

            from actions import logout_now
            await logout_now()
            return              # not reached

    print("Idle TO undone")
            
async def ux_confirm(msg):
    # confirmation screen, with stock title and Y=of course.

    resp = await ux_show_story("Are you SURE ?!?\n\n" + msg)

    return resp == 'y'


async def ux_dramatic_pause(msg, seconds):
    from main import dis

    # show a full-screen msg, with a dramatic pause + progress bar
    n = seconds * 8
    dis.fullscreen(msg)
    for i in range(n):
        dis.progress_bar_show(i/n)
        await sleep_ms(125)

    ux_clear_keys()

def show_fatal_error(msg):
    # show a multi-line error message, over some kinda "fatal" banner
    from main import dis
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
    # us this when dangerous action is not performed due to confirmations
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
    from main import numpad

    the_ux.reset(m)

    numpad.abort_ux()

# EOF
