# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# qrs.py - QR Display related UX
#
import framebuf, math, uqr
from ux import UserInteraction, ux_wait_keyup, the_ux 
from utils import word_wrap
from ubinascii import hexlify as b2a_hex
from charcodes import (KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN, KEY_HOME,
                        KEY_END, KEY_PAGE_UP, KEY_PAGE_DOWN, KEY_SELECT, KEY_CANCEL)
from version import has_qwerty

class QRDisplaySingle(UserInteraction):
    # Show a single QR code for (typically) a list of addresses, or a single value.

    def __init__(self, addrs, is_alnum, start_n=0, sidebar=None):
        self.is_alnum = is_alnum
        self.idx = 0             # start with first address
        self.invert = False      # looks better, but neither mode is ideal
        self.addrs = addrs
        self.sidebar = sidebar
        self.start_n = start_n
        self.qr_data = None

    def calc_qr(self, msg):
        # Version 2 would be nice, but can't hold what we need, even at min error correction,
        # so we are forced into version 3 = 29x29 pixels
        # - see <https://www.qrcode.com/en/about/version.html>
        # - version=3 => to display 29x29 pixels, we have to double them up: 58x58
        # - version=4..11 => single pixel per module
        # - not really providing enough space around these, shrug
        # - inverted QR (black/white swap) still readable by scanners, altho wrong
        if self.is_alnum:
            # targeting 'alpha numeric' mode, nice and dense; caps only tho
            enc = uqr.Mode_ALPHANUMERIC
            msg = msg.upper()
        else:
            # has to be 'binary' mode, altho shorter msg, typical 34-36
            enc = uqr.Mode_BYTE

        # can fail if not enough space in QR
        self.qr_data = uqr.make(msg, min_version=3,
                                    max_version=11 if not has_qwerty else 40,
                                    encoding=enc)

    def redraw(self):
        # Redraw screen.
        from glob import dis

        # what we are showing inside the QR
        msg = self.addrs[self.idx]

        # make the QR, if needed.
        if not self.qr_data:
            dis.busy_bar(True)

            self.calc_qr(msg)

        # draw display
        idx_hint = str(self.start_n + self.idx) if len(self.addrs) > 1 else None
        dis.draw_qr_display(self.qr_data, msg, self.is_alnum,
                                        self.sidebar, idx_hint, self.invert)


    async def interact_bare(self):
        from glob import NFC
        self.redraw()

        while 1:
            ch = await ux_wait_keyup()

            was = self.idx
            if ch == '1' or ch == 'i':
                self.invert = not self.invert
                self.redraw()
                continue
            elif NFC and (ch == '3' or ch == KEY_NFC):
                # Share any QR over NFC!
                await NFC.share_text(self.addrs[self.idx])
                self.redraw()
                continue
            elif ch in 'xy'+KEY_SELECT+KEY_CANCEL:
                break
            elif len(self.addrs) == 1:
                continue
            elif ch == '5' or ch == '7' or ch == KEY_UP:
                if self.idx > 0:
                    self.idx -= 1
            elif ch == '8' or ch == '9' or ch == KEY_DOWN:
                if self.idx != len(self.addrs)-1:
                    self.idx += 1
            elif ch == KEY_HOME:
                self.idx = 0
            elif ch == KEY_END:
                self.idx = len(self.addrs)-1
            else:
                continue

            if self.idx != was:
                # self.idx has changed, so need full re-render
                self.qr_data = None
                self.redraw()

    async def interact(self):
        await self.interact_bare()
        the_ux.pop()

# EOF
