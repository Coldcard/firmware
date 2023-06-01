# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# lcd_display.py - LCD rendering for Q1's 320x240 pixel *colour* display!
#
import machine, uzlib, ckcc, utime, struct, array, sys
import framebuf
import uasyncio
from uasyncio import sleep_ms
from graphics_q1 import Graphics
from graphics import Graphics as obsoleteGraphics
import sram2
from st7788 import ST7788

# we support 4 fonts
from zevvpeep import FontSmall, FontLarge, FontTiny
FontFixed = object()    # ugly 8x8 PET font

from font_iosevka import CELL_W, CELL_H, TEXT_PALETTE, TEXT_PALETTE_INV
from font_iosevka import FontIosevka

# free unused screen buffers, we will make bigger ones
del sram2.display_buf
del sram2.display2_buf

# one byte per pixel; fixed palette maps to BGR565 in C code
display2_buf = bytearray(320 * 240)

#WIDTH = const(320)
#HEIGHT = const(240)
LEFT_MARGIN = const(7)
TOP_MARGIN = const(15)
ACTIVE_H = const(240 - TOP_MARGIN)
CHARS_W = const(34)
CHARS_H = const(10)

# colouuurs: RGB565
COL_WHITE = 0xffff
COL_BLACK = 0x0000

def grey_level(amt):
    # give percent 0..1.0
    r = int(amt * 0x1f)
    g = int(amt * 0x3f)
    #b = int(amt * 0x1f)

    return (r<<11) | (g << 5) | r

def get_sys_status():
    # read current values for all status-bar items
    # - normally we update as we go along.
    # - return a dict
    from q1 import get_batt_threshold

    rv = dict(shift=0, caps=0, symbol=0)
    b = get_batt_threshold()
    if b is None:
        rv['plugged'] = True
    else:
        rv['bat'] = b

    from stash import bip39_passphrase
    rv['bip39'] = int(bool(bip39_passphrase))

    from pincodes import pa
    rv['tmp'] = int(bool(pa.tmp_value))

    from version import is_edge, is_devmode
    if is_edge:
        rv['edge'] = 1
    elif is_devmode:
        rv['devmode'] = 1

    return rv
    

class Display:

    # XXX move  to global, but rest of system looks at these member vars
    WIDTH = 320
    HEIGHT = 240

    # use these negative X values for auto layout features
    CENTER = -2
    RJUST = -1

    # icon names and their values (0 / 1)
    status_icons = {}

    def __init__(self):
        self.dis = ST7788()

        self.last_bar_update = 0
        self.dis.fill_screen()
        self.draw_status(full=True)

    def redraw_metakeys(self, new_state):
        # called when metakeys have changed state
        self.draw_status(**new_state)

    async def async_draw_status(self, **kws):
        self.draw_status(**kws)

    def draw_status(self, full=False, **kws):
        if full:
            y = TOP_MARGIN
            self.dis.fill_rect(0, 0, WIDTH, y-2, 0x0)
            self.dis.fill_rect(0, y-1, WIDTH, 1, grey_level(0.25))
            kws = get_sys_status()

        b_x = 290
        if 'bat' in kws:
            self.image(b_x, 0, 'bat_%d' % kws['bat'])
        if 'plugged' in kws:
            self.image(b_x, 0, 'plugged')

        if 'bip39' in kws:
            self.image(120, 0, 'bip39_%d' % kws['bip39'])

        if 'tmp' in kws:
            self.image(200, 0, 'tmp_%d' % kws['tmp'])

        if 'edge' in kws:
            self.image(260, 0, 'edge')
        elif 'devmode' in kws:
            self.image(260, 0, 'devmode')

        for x, meta in [(7, 'shift'), (38, 'symbol'), (65, 'caps')]:
            if meta in kws:
                self.image(x, 0, '%s_%d' % (meta, kws[meta]))

    def width(self, msg, font):
        if font == FontFixed:
            return len(msg) * 8
        else:
            return sum(font.lookup(ord(ch)).w for ch in msg)

    def image(self, x, y, name):
        # display a graphics image, immediately
        w,h, data = getattr(Graphics, name)
        if x == None:
            x = max(0, (WIDTH - w) // 2)
        self.dis.show_zpixels(x, y, w, h, data)

    def icon(self, x, y, name, invert=0):
        # XXX plan is these are chars or images
        return 10, 10

    def XXX_text(self, x,y, msg, font=FontSmall, invert=0):
        # Draw at x,y (top left corner of first letter)
        # using font. Use invert=1 to get reverse video

        if x is None or x < 0:
            # center/rjust
            w = self.width(msg, font)
            if x == None:
                x = max(0, (WIDTH - w) // 2)
            else:
                # measure from right edge (right justify)
                x = max(0, WIDTH - w + 1 + x)

        if y < 0:
            # measure up from bottom edge
            y = HEIGHT - font.height + 1 + y

        if font == FontFixed:
            # use font provided by Micropython: 8x8
            self.dis.text(msg, x, y)

            return x + (len(msg) * 8)

        for ch in msg:
            fn = font.lookup(ord(ch))
            if fn is None:
                # use last char in font as error char for junk we don't
                # know how to render
                fn = font.lookup(font.code_range.stop)
            bits = bytearray(fn.w * fn.h)
            bits[0:len(fn.bits)] = fn.bits
            if invert:
                bits = bytearray(i^0xff for i in bits)
            gly = framebuf.FrameBuffer(bits, fn.w, fn.h, framebuf.MONO_HLSB)
            self.dis.blit(gly, x, y, invert)
            x += fn.w

        return x

    def text(self, x,y, msg, font=None, invert=0):
        # Draw at x,y (in cell positions, not pixels)
        # Use invert=1 to get reverse video

        if x is None or x < 0:
            w = len(msg)
            if x == None:
                # center: also blanks rest of line
                x = max(0, (CHARS_W - w) // 2)
                msg = ((' '*x) + msg + (' ' * CHARS_W))[0:CHARS_W]
                x = 0
            else:
                # measure from right edge (right justify)
                x = max(0, CHARS_W - w + 1 + x)

        if y < 0:
            # measure up from bottom edge
            y = CHARS_H + y

        if y >= CHARS_H: 
            print("Draw '%s' at y=%d" % (msg, y))
            return     # past bottom

        # convert to pixels
        x = LEFT_MARGIN + (x * CELL_W)
        y = TOP_MARGIN + (y * CELL_H)

        for ch in msg:
            fn = FontIosevka.lookup(ch)
            if fn is None:
                # draw blanks for unknowns
                x += CELL_W
                continue

            self.dis.show_pal_pixels(x, y, fn.w, fn.h, 
                TEXT_PALETTE if not invert else TEXT_PALETTE_INV, fn.bits)
            x += fn.w

            if x >= WIDTH: break

    def clear(self):
        # fill to black, but only text area
        # - not status bar
        self.dis.fill_rect(0, TOP_MARGIN, WIDTH, HEIGHT-TOP_MARGIN, 0x0)

    def clear_rect(self, x,y, w,h):
        self.dis.fill_rect(x,y, w,h, 0x0000)

    def show(self):
        #self.dis.show()
        pass

    # rather than clearing and redrawing, use this buffer w/ fixed parts of screen
    def save(self):
        display2_buf[:] = self.dis.buffer
    def restore(self):
        self.dis.buffer[:] = display2_buf

    def hline(self, y):
        self.dis.fill_rect(0,y, WIDTH, 1, 0xffff)
    def vline(self, x):
        self.dis.fill_rect(x,TOP_MARGIN, 1, ACTIVE_H, 0xffff)

    def scroll_bar(self, fraction):
        # along right edge
        self.dis.fill_rect(WIDTH-5, 0, 5, HEIGHT, 0)
        #self.icon(WIDTH-3, 1, 'scroll');      // dots + arrow
        mm = HEIGHT-6
        pos = min(int(mm*fraction), mm)
        self.dis.fill_rect(WIDTH-2, pos, 1, 16, 1)

    def fullscreen(self, msg, percent=None):
        # show a simple message "fullscreen". 
        self.clear()
        self.text(None, CHARS_H // 3, msg)
        if percent is not None:
            self.progress_bar(percent)

    def splash(self):
        # display a splash screen with some version numbers
        self.clear()
        self.image(None, 24, 'splash')

        from version import get_mpy_version
        timestamp, label, *_ = get_mpy_version()

        y = HEIGHT-CELL_H-2
        self.text(0,  -1, 'Version '+label)
        self.text(-1, -1, timestamp)

    def splash_text(self, msg):
        # additional progress during splash/startup screen
        self.text(None, 6, msg)

    def progress_bar(self, percent):
        # Horizontal progress bar
        # takes 0.0 .. 1.0 as fraction of doneness
        percent = max(0, min(1.0, percent))
        x = int(WIDTH * percent)
        self.dis.fill_rect(0, HEIGHT-3, x, 3, COL_WHITE)
        self.dis.fill_rect(x, HEIGHT-3, WIDTH-x, 3, COL_BLACK)

    def progress_sofar(self, done, total):
        # Update progress bar, but only if it's been a while since last update
        if utime.ticks_diff(utime.ticks_ms(), self.last_bar_update) < 100:
            return
        self.last_bar_update = utime.ticks_ms()
        self.progress_bar_show(done / total)

    def progress_bar_show(self, percent):
        # useful as a callback
        self.progress_bar(percent)

    def mark_sensitive(self, from_y, to_y):
        return # XXX maybe TODO ? or remove ... LCD doesnt have issue
        wx = WIDTH-4       # avoid scroll bar
        for y in range(from_y, to_y):
            ln = max(2, ckcc.rng() % 32)
            self.dis.line(wx-ln, y, wx, y, 1)

    def busy_bar(self, enable, speed_code=5):
        # TODO: activate the GPU to render/animate this.
        print("busy_bar: %s" % enable)
        return

    def set_brightness(self, val):
        # normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        # XXX maybe control BL_ENABLE timing? or not required.
        return 

    def menu_draw(self, ry, msg, is_sel, is_checked, space_indicators):
        # draw a menu item, perhaps selected, checked.
        assert CHARS_W == 34

        if ry >= CHARS_H:
            # higher layer tries to draw partial line past bottom, and that's
            # ok because needed on mk4
            return

        if msg[0] == ' ' and space_indicators:
            msg = '_' + msg[1:]        # XXX improve me w/ special char

        ln = ('⏵ ' if is_sel else '  ') + ('%-32s' % msg)

        if is_checked:
            ln = ln[:CHARS_W-3] + '✓ '

        self.text(0, ry, ln, invert=is_sel)


    def show_yikes(self, lines):
        # dump a stack trace
        # - intended for photos, sent to support!
        from utils import word_wrap

        self.clear()
        self.text(None, 0, '>>>> Yikes!! <<<<')

        y = 1
        for num, ln in enumerate(lines):
            ln = ln.strip()

            if ln[0:6] == 'File "':
                # convert: File "main.py", line 63, in interact
                #    into: main.py:63  interact
                ln = ln[6:].replace('", line ', ':').replace(', in ', '  ')
                if ln[0] == '/':
                    ln = ln.split('/')[-1]

            for second, l in enumerate(word_wrap(ln, CHARS_W)):
                self.text(1 if second else 0, y, l)
                y += 1

    def draw_story(self, lines, top, num_lines, is_sensitive):
        self.clear()

        y=0
        for ln in lines:
            if ln == 'EOT':
                self.hline( TOP_MARGIN + (y*CELL_H) )
                continue
            elif ln and ln[0] == '\x01':
                # title ... but we have no special font?
                self.text(0, y, ln[1:], invert=1)
            else:
                self.text(0, y, ln)

            y += 1

            if is_sensitive and len(ln) > 3 and ln[2] == ':':
                self.mark_sensitive(y, y+13)

        self.scroll_bar(top / num_lines)
        self.show()

    def draw_qr_display(self, qr_data, msg, is_alnum, sidebar, idx_hint, invert):
        # Show a QR code on screen w/ some text under it
        # - invert not supported on Q1
        # - sidebar not supported here (see users.py)
        # - we need one more (white) pixel on all sides
        from utils import word_wrap

        assert not sidebar

        if msg:
            if len(msg) <= CHARS_W:
                parts = [msg]
            elif ' ' not in msg and (len(msg) <= CHARS_W*2):
                # fits in two lines, but has no spaces (ie. payment addr)
                # so split nicely, and shift off center
                hh = len(msg) // 2
                parts = [msg[0:hh] + '  ', '  '+msg[hh:]]
            else:
                # do word wrap
                parts = list(word_wrap(msg, CHARS_W))

            num_lines = len(parts)
        else:
            num_lines = 0

        if num_lines > 2:
            # show no text if it would be too big (case: 18, 24 seed words)
            num_lines = 0
            del parts

        w = qr_data.width()

        # always draw as large as possible (vertical is limit)
        expand = max(1, (ACTIVE_H - (num_lines * CELL_H))  // (w+2))
        qw = (w+2) * expand

        # horz/vert center in available space
        y = (ACTIVE_H - (num_lines * CELL_H) - qw) // 2
        x = (WIDTH - qw) // 2

        # send packed pixel data to C level to decode and exand to LCD
        # - 8-bit aligned rows of data
        scan_w, _, data = qr_data.packed()

        self.clear()
        self.dis.show_qr_data(x, TOP_MARGIN + y, w, expand, scan_w, data)

        if num_lines:
            # centered text under that
            y = CHARS_H - num_lines
            for line in parts:
                self.text(None, y, line, FontTiny)
                y += 1

        if idx_hint:
            # show path index number: just 1 or 2 digits
            self.text(-1, 0, idx_hint)

        self.busy_bar(False)     # includes show

        
# here for mpy reasons
WIDTH = const(320)
HEIGHT = const(240)

# EOF
