# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# qrs.py - QR Display related UX
#
import framebuf, math, uqr
from ux import UserInteraction, ux_wait_keyup, the_ux 
from utils import word_wrap
from version import has_fatram
from ubinascii import hexlify as b2a_hex

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
        self.qr_data = uqr.make(msg, min_version=3, max_version=11, encoding=enc)

    def redraw(self):
        # Redraw screen.
        from glob import dis
        from display import FontSmall, FontTiny

        # what we are showing inside the QR
        msg = self.addrs[self.idx]

        # make the QR, if needed.
        if not self.qr_data:
            dis.busy_bar(True)

            self.calc_qr(msg)

        # draw display
        dis.clear()

        w = self.qr_data.width()
        if w == 29:
            # version 3 => we can double-up the pixels
            XO,YO = 4, 3    # offsets
            dbl = True
            bw = 62
            lm, tm = 2, 1           # left, top margin
        else:
            # v4+ => just one pixel per module, might not be easy to read
            # - vert center, left justify; text on space to right
            dbl = False
            YO = max(0, (64 - w) // 2)
            XO,lm = 6, 4
            bw = w + lm
            tm = (64 - bw) // 2

        inv = self.invert
        if dbl:
            if not inv:
                dis.dis.fill_rect(lm, tm, bw, bw, 1)
            else:
                dis.dis.fill_rect(lm, tm, bw, bw, 0)

            for x in range(w):
                for y in range(w):
                    if not self.qr_data.get(x, y):
                        continue
                    X = (x*2) + XO
                    Y = (y*2) + YO
                    dis.dis.fill_rect(X,Y, 2,2, inv)
        else:
            # direct "bilt" .. faster. Does not support inversion.
            dis.dis.fill_rect(lm, tm, bw, bw, 1)
            _, _, packed = self.qr_data.packed()
            packed = bytes(i^0xff for i in packed)
            gly = framebuf.FrameBuffer(bytearray(packed), w, w, framebuf.MONO_HLSB)
            dis.dis.blit(gly, XO, YO, 1)

        if not self.sidebar and len(msg) > (5*7):
            # use FontTiny and word wrap (will just split if no spaces)
            x = bw + lm + 4
            ww = ((128 - x)//4) - 1        # char width avail
            y = 1
            parts = list(word_wrap(msg, ww))
            if len(parts) > 8:
                parts = parts[:8]
                parts[-1] = parts[-1][0:-3] + '...'
            elif len(parts) <= 5:
                parts.insert(0, '')
    
            for line in parts:
                dis.text(x, y, line, FontTiny)
                y += 8
        else:
            # hand-positioned for known cases
            # - self.sidebar = (text, #of char per line)
            x, y = 73, (0 if self.is_alnum else 2)
            dy = 10 if self.is_alnum else 12
            sidebar, ll = self.sidebar if self.sidebar else (msg, 7)

            for i in range(0, len(sidebar), ll):
                dis.text(x, y, sidebar[i:i+ll], FontSmall)
                y += dy

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

            was = self.idx
            if ch == '1':
                self.invert = not self.invert
                self.redraw()
                continue
            elif ch in 'xy':
                break
            elif len(self.addrs) == 1:
                continue
            elif ch == '5' or ch == '7':
                if self.idx > 0:
                    self.idx -= 1
            elif ch == '8' or ch == '9':
                if self.idx != len(self.addrs)-1:
                    self.idx += 1
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
