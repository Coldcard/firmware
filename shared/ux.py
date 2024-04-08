# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ux.py - UX/UI related helper functions
#
from uasyncio import sleep_ms
from queues import QueueEmpty
import utime, gc, version
from utils import word_wrap
from charcodes import (KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN, KEY_HOME, KEY_NFC, KEY_QR,
                        KEY_END, KEY_PAGE_UP, KEY_PAGE_DOWN, KEY_ENTER, KEY_CANCEL)
from exceptions import AbortInteraction

DEFAULT_IDLE_TIMEOUT = const(4*3600)      # (seconds) 4 hours

# See ux_mk or ux_q1 for some display functions now
if version.has_qwerty:
    from lcd_display import CHARS_W, CHARS_H
    CH_PER_W = CHARS_W
    STORY_H = CHARS_H
    from ux_q1 import PressRelease, ux_enter_number, ux_input_numbers, ux_input_text, ux_show_pin
    from ux_q1 import ux_login_countdown, ux_confirm, ux_dice_rolling, ux_render_words
    from ux_q1 import ux_show_phish_words

    def q1_reword(msg):
        return msg.replace('\nX ', 'CANCEL ').replace(' X ', ' CANCEL ').replace('OK', 'ENTER')
else:
    # How many characters can we fit on each line? How many lines?
    # (using FontSmall)
    CH_PER_W = 17
    STORY_H = 5
    from ux_mk4 import PressRelease, ux_enter_number, ux_input_numbers, ux_input_text, ux_show_pin
    from ux_mk4 import ux_login_countdown, ux_confirm, ux_dice_rolling, ux_render_words
    from ux_mk4 import ux_show_phish_words
    q1_reword = lambda m: m

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

async def ux_wait_keyup(expected=None, flush=False):
    # Wait for single keypress in 'expected' set, return it
    # no visual feedback, no escape
    # - can be canceled anytime, using wait_for_ms to create a timeout
    from glob import numpad

    if flush:
        armed = False
    else:
        armed = numpad.key_pressed or False

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

async def ux_wait_keydown(allowed=None, timeout_ms=None):
    # Wait for PRESS (not press+release) of any key. Return it and arrange so
    # that the later release doesn't cause confusion.
    # - no key repeat here
    from glob import numpad

    t = 0
    while 1:
        if numpad.empty():
            await sleep_ms(1)
            t += 1
            if timeout_ms and t >= timeout_ms:
                return None
            continue

        ch = numpad.get_nowait()

        if ch == numpad.ABORT_KEY:
            raise AbortInteraction()

        if ch == '' or (allowed and (ch not in allowed)):
            # keyup or unwanted
            continue

        numpad.clear_pressed()
        return ch

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


async def ux_show_story(msg, title=None, escape=None, sensitive=False,
                        strict_escape=False, scrollbar=True, hint_icons=None):
    # show a big long string, and wait for XY to continue
    # - returns character used to get out (X or Y)
    # - can accept other chars to 'escape' as well.
    # - accepts a stream or string
    # - on Q, will show icons in top-right if hint_icons is provided
    from glob import dis

    lines = []
    if title:
        # kinda weak rendering but it works.
        lines.append('\x01' + title)

        if version.has_qwerty:
            # big screen always needs blank after title
            lines.append('')

    if hasattr(msg, 'readline'):
        # coming from in-memory file for larger messages
        msg.seek(0)
        for ln in msg:
            if ln[-1] == '\n': 
                ln = ln[:-1]

            ln = q1_reword(ln)

            lines.extend(word_wrap(ln, CH_PER_W))

        # no longer needed & rude to our caller, but let's save the memory
        msg.close()
        del msg
        gc.collect()
    else:
        # simple string being shown
        msg = q1_reword(msg)

        for ln in msg.split('\n'):
            lines.extend(word_wrap(ln, CH_PER_W))

    # trim blank lines at end, add our own marker
    while not lines[-1]:
        lines = lines[:-1]

    lines.append('EOT')

    top = 0
    ch = None
    pr = PressRelease()
    while 1:
        # redraw
        dis.draw_story(lines[top:top+STORY_H], top, len(lines), sensitive, hint_icons=hint_icons)

        # wait to do something
        ch = await pr.wait()
        if escape and (ch in escape):
            # allow another way out for some usages
            return ch
        elif ch == KEY_ENTER:
            if not strict_escape:
                return 'y'      # translate for Mk4 code
        elif ch == KEY_CANCEL:
            if not strict_escape:
                return 'x'      # translate for Mk4 code
        elif ch in 'xy':
            if not strict_escape:
                return ch
        elif ch == KEY_END:
            top = max(0, len(lines)-(STORY_H//2))
        elif ch == '0' or ch == KEY_HOME:
            top = 0
        elif ch == '7' or ch == KEY_PAGE_UP or ch == KEY_UP:
            top = max(0, top-STORY_H)
        elif ch == '9' or ch == KEY_PAGE_DOWN or ch == KEY_DOWN:
            top = min(len(lines)-2, top+STORY_H)
        elif ch == '5':
            # line up/down only on Mk4; too slow w/ Q1's big screen
            top = max(0, top-1)
        elif ch == '8':
            top = min(len(lines)-2, top+1)
        elif not strict_escape:
            if ch in { KEY_NFC, KEY_QR }:
                return ch

        

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

    lines = msg.split('\n')[-6:]
    dis.show_yikes(lines)

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

async def show_qr_code(data, is_alnum=False, msg=None):
    from qrs import QRDisplaySingle
    o = QRDisplaySingle([data], is_alnum, msg=msg)
    await o.interact_bare()

async def ux_enter_bip32_index(prompt, can_cancel=False, unlimited=False):
    if unlimited:
        max_value = (2 ** 31) - 1  # we handle hardened
    else:
        max_value = 9999

    return await ux_enter_number(prompt=prompt, max_value=max_value, can_cancel=can_cancel)

def _import_prompt_builder(title, no_qr, no_nfc, slot_b_only=False):
    from version import has_qwerty, num_sd_slots, has_qr
    from glob import NFC, VD

    prompt, escape = None, KEY_CANCEL+"x"

    if (NFC or VD) or num_sd_slots>1:
        if slot_b_only and (num_sd_slots>1):
            prompt = "Press (B) to import %s from lower slot SD Card" % title
            escape += "b"
        else:
            prompt = "Press (1) to import %s from SD Card" % title
            escape += "1"
            if num_sd_slots == 2:
                prompt += ", (B) for lower slot"
                escape += "ab"

        if VD is not None:
            prompt += ", press (2) to import from Virtual Disk"
            escape += "2"
        if (NFC is not None) and not no_nfc:
            if has_qwerty:
                prompt += ", press " + KEY_NFC + " to import via NFC"
                escape += KEY_NFC
            else:
                prompt += ", press (3) to import via NFC"
                escape += "3"

        if has_qwerty and not no_qr:
            prompt += ", " + KEY_QR + " to scan QR code"
            escape += KEY_QR

        prompt += "."

    return prompt, escape


def export_prompt_builder(what_it_is, no_qr=False, no_nfc=False, key0=None):
    # Build the prompt for export
    # - key0 can be for special stuff
    from version import has_qwerty, num_sd_slots, has_qr
    from glob import NFC, VD

    prompt, escape = None, KEY_CANCEL+"x"

    if (NFC or VD) or num_sd_slots>1 or key0:
        # no need to spam with another prompt, only option is SD card

        prompt = "Press (1) to save %s to SD Card" % what_it_is
        escape += "1"
        if num_sd_slots == 2:
            # MAYBE: show this only if both slots have cards inserted?
            prompt += ", (B) for lower slot"
            escape += "ab"

        if VD is not None:
            prompt += ", press (2) to save to Virtual Disk"
            escape += "2"

        if (NFC is not None) and not no_nfc:
            if has_qwerty:
                prompt += ", press " + KEY_NFC + " to share via NFC"
                escape += KEY_NFC
            else:
                prompt += ", press (3) to share via NFC"
                escape += "3"

        if not no_qr:
            if has_qwerty:
                prompt += ", "+KEY_QR+" to show QR code"
                escape += KEY_QR
            else:
                prompt += ", (4) to show QR code"
                escape += '4'

        if key0:
            prompt += ', (0) ' + key0
            escape += '0'

        prompt += "."

    return prompt, escape

def import_export_prompt_decode(ch):
    # We showed a prompt from _import_prompt_builder() and now need to 
    # figure out what they want to do.
    # - illegal choices should have been already blocked by "escape" on ux_story

    force_vdisk = False
    slot_b = None       # ie. don't care / either

    if ch in "3"+KEY_NFC:
        return KEY_NFC
    elif ch in "4"+ KEY_QR:
        return KEY_QR
    elif ch == "2":
        force_vdisk = True
    elif ch == 'b':
        slot_b = True
    elif ch == 'a':
        # not documented on-screen? easter egg really. forces slot A if both in use.
        slot_b = False
    elif ch == '1':
        slot_b = None
    elif ch == 'x':
        return KEY_CANCEL
    else:
        # Includes: '0': special "other" case
        # - cancel, enter, etc
        return ch

    # return extra arguments to files.file_picker() or CardSlot()
    return dict(force_vdisk=force_vdisk, slot_b=slot_b)

async def import_export_prompt(what_it_is, is_import=False, no_qr=False,
                               no_nfc=False, title=None, intro='', footnotes='',
                               slot_b_only=False):
    # Show story allowing user to select source for importing/exporting
    # - return either str(mode) OR dict(file_args)
    # - KEY_NFC or KEY_QR for those sources
    # - KEY_CANCEL for abort by user
    # - dict() => do file system thing, using file_args to control vdisk vs. SD vs slot_b

    if is_import:
        prompt, escape = _import_prompt_builder(what_it_is, no_qr, no_nfc, slot_b_only)
    else:
        prompt, escape = export_prompt_builder(what_it_is, no_qr, no_nfc)

    # TODO: detect if we're only asking A or B, when just one card is inserted
    # - assume that's what they want to do
    # - but if NFC, QR or Virtdisk is option, then we need to prompt

    if not prompt:
        # they don't have NFC nor VD enabled, and no second slots... so will be file.
        return dict(force_vdisk=False, slot_b=None)
    else:
        ch = await ux_show_story(intro+prompt+footnotes, escape=escape, title=title,
                                 strict_escape=True)

        return import_export_prompt_decode(ch)

# EOF
