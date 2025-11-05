# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# qrs.py - QR Display related UX
#
import framebuf, uqr
from ux import UserInteraction, ux_wait_keyup, the_ux
from version import has_qwerty
from exceptions import QRTooBigError
from charcodes import (KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN, KEY_HOME, KEY_NFC,
                       KEY_END, KEY_ENTER, KEY_CANCEL)

# TODO: This class has a terrible API!

# Max in a V11 as bytes (not alnum) ... the limit on Mk4 screen
MAX_V11_CHAR_LIMIT = const(321)

class QRDisplaySingle(UserInteraction):
    # Show a single QR code for (typically) a list of addresses, or a single value.

    def __init__(self, addrs, is_alnum, start_n=0, sidebar=None, msg=None,
                 is_addrs=False, force_msg=False, allow_nfc=True, is_secret=False,
                 change_idxs=None, can_raise=True):
        self.is_alnum = is_alnum
        self.idx = 0             # start with first address
        self.invert = False      # looks better, but neither mode is ideal
        self.addrs = addrs
        self.sidebar = sidebar
        self.start_n = start_n
        self.is_addrs = is_addrs
        self.msg = msg
        self.qr_data = None
        self.force_msg = force_msg
        self.allow_nfc = allow_nfc
        # only used for NFC sharing secret material - full chip wipe if is_secret=True
        self.is_secret = is_secret
        self.change_idxs = change_idxs or []
        self.can_raise = can_raise

    def calc_qr(self, msg):
        # Version 2 would be nice, but can't hold what we need, even at min error correction,
        # so we are forced into version 3 = 29x29 pixels
        # - see <https://www.qrcode.com/en/about/version.html>
        # - version=3 => to display 29x29 pixels, we have to double them up: 58x58
        # - version=4..11 => single pixel per module
        # - not really providing enough space around these, shrug
        # - inverted QR (black/white swap) still readable by scanners, altho wrong
        # - on Q: ver 25 => 117x117 is largest that can be pixel-doubled
        # - on Q: v40 is possible at at 1:1, but most find that unreadable, so avoid 1:1
        if self.is_alnum:
            # targeting 'alpha numeric' mode, nice and dense; caps only tho
            enc = uqr.Mode_ALPHANUMERIC if not msg.isdigit() else uqr.Mode_NUMERIC
            msg = msg.upper()
        else:
            # has to be 'binary' mode, altho shorter msg, typical 34-36
            enc = uqr.Mode_BYTE

        # can fail if not enough space in QR
        self.qr_data = uqr.make(msg, min_version=2,
                                max_version=11 if not has_qwerty else 25,
                                encoding=enc)

    def idx_hint(self):
        # draw_qr_display takes this and renders hint in the top right corner
        # this member function decides what type of hint will be shown
        # numbers, letters, etc.
        return str(self.start_n + self.idx) if len(self.addrs) > 1 else None

    def is_change(self):
        if self.idx in self.change_idxs:
            return True
        return False

    def redraw(self):
        # Redraw screen.
        from glob import dis
        dis.clear()

        # what we are showing inside the QR
        body = self.addrs[self.idx]
        idx_hint = self.idx_hint()

        msg = None
        if self.msg:
            msg = self.msg
        else:
            if isinstance(body, str):
                # sanity check
                msg = body

        # make the QR, if needed.
        if not self.qr_data:
            dis.busy_bar(True)
            try:
                self.calc_qr(body)
            except Exception:
                dis.busy_bar(False)
                if not self.can_raise:
                    dis.draw_qr_error(idx_hint, msg)
                    return

                # other code paths require raise to switch to BBQr
                raise QRTooBigError

        # draw display
        dis.busy_bar(False)
        dis.draw_qr_display(self.qr_data, msg, self.is_alnum,
                            self.sidebar, idx_hint, self.invert,
                            is_addr=self.is_addrs, force_msg=self.force_msg,
                            is_change=self.is_change())

    async def interact_bare(self):
        from glob import NFC, dis
        self.redraw()

        while 1:
            ch = await ux_wait_keyup(flush=True)

            was = self.idx
            if ch == '1' or ch == 'i':
                self.invert = not self.invert
                self.redraw()
                continue
            elif NFC and (ch == '3' or ch == KEY_NFC):
                if not self.allow_nfc:
                    # not a valid as text over NFC sometimes; treat as cancel
                    break
                else:
                    # Share any QR over NFC!
                    await NFC.share_text(self.addrs[self.idx], is_secret=self.is_secret)
                    self.redraw()
                continue
            elif ch in 'xy'+KEY_ENTER+KEY_CANCEL:
                break
            elif len(self.addrs) == 1:
                continue
            elif ch in '57' + KEY_UP + KEY_LEFT:
                if self.idx > 0:
                    self.idx -= 1
            elif ch in '89' + KEY_DOWN + KEY_RIGHT:
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

        # bugfix
        if dis.has_lcd:
            dis.real_clear()

    async def interact(self):
        await self.interact_bare()
        the_ux.pop()


class XORQRDisplaySingle(QRDisplaySingle):
    def idx_hint(self):
        if len(self.addrs) > 1:
            return chr(65+int(self.start_n + self.idx))

# EOF
