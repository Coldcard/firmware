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
from utils import xfp2str

# the one font: fixed-width (except for a few double-width chars)
from font_iosevka import CELL_W, CELL_H, TEXT_PALETTE, TEXT_PALETTE_INV, COL_TEXT
from font_iosevka import FontIosevka

# free unused screen buffers, we don't work that way
del sram2.display_buf
del sram2.display2_buf

# one byte per pixel; fixed palette maps to BGR565 in C code
#display2_buf = bytearray(320 * 240)

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
COL_PROGRESS = COL_TEXT

FLAG_INVERT = 0x8000
ATTR_MASK = 0x8000

# text display attributes, ie. colours
AT_INVERT = 0x1
AT_GREY25 = 0x1
AT_GREY50 = 0x1
AT_RED = 0x1
AT_GREEN = 0x1

def grey_level(amt):
    # give percent 0..1.0
    r = int(amt * 0x1f)
    g = int(amt * 0x3f)
    #b = int(amt * 0x1f)        # same as Red

    return (r<<11) | (g << 5) | r

def rgb(r,g,b):
    # as if 24-bit, but we're 16
    r = int(r/255 * 0x1f)
    g = int(g/255 * 0x3f)
    b = int(b/255 * 0x1f)
    return (r<<11) | (g << 5) | b


def get_sys_status():
    # Read current values for all status-bar items
    # - normally we update as we go along.
    # - return a dict
    from q1 import get_batt_threshold

    rv = dict(shift=0, caps=0, symbol=0, brand=1)
    b = get_batt_threshold()
    if b is None:
        rv['plugged'] = True
    else:
        rv['bat'] = b

    from stash import bip39_passphrase
    rv['bip39'] = int(bool(bip39_passphrase))

    from pincodes import pa
    rv['tmp'] = int(bool(pa.tmp_value))

    from glob import settings
    if settings:
        rv['xfp'] = settings.get('xfp')

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

    # use this to know if on Q1 or earlier 
    has_lcd = True

    # icon names and their values (0 / 1)
    status_icons = {}

    def __init__(self):
        self.dis = ST7788()

        self.last_buf = self.make_buf(0)
        self.next_buf = self.make_buf(32)

        # state of progress bar
        self.last_prog_x = -1
        self.next_prog_x = 0

        self.last_bar_update = 0
        #self.dis.fill_screen()     # defer a bit
        self.draw_status(full=True)

    def make_buf(self, ch):
        return [array.array('H', (ch for i in range(CHARS_W))) for y in range(CHARS_H)]

    def redraw_metakeys(self, new_state):
        # called when metakeys have changed state
        self.draw_status(**new_state)

    async def async_draw_status(self, **kws):
        self.draw_status(**kws)

    def draw_status(self, full=False, **kws):
        if full:
            y = TOP_MARGIN
            self.dis.fill_rect(0, 0, WIDTH, y-1, 0x0)
            self.dis.fill_rect(0, y-1, WIDTH, 1, grey_level(0.25))
            kws = get_sys_status()

        if 'brand' in kws:
            self.image(4, 0, 'brand')

        b_x = 290
        if 'bat' in kws:
            self.image(b_x, 0, 'bat_%d' % kws['bat'])
        if 'plugged' in kws:
            self.image(b_x, 0, 'plugged')

        if 'bip39' in kws:
            self.image(108, 0, 'bip39_%d' % kws['bip39'])

        if 'tmp' in kws:
            self.image(165, 0, 'tmp_%d' % kws['tmp'])

        xfp = kws.get('xfp', None)      # expects an integer
        if xfp != None:
            x = 215
            for ch in xfp2str(xfp).lower():
                self.image(x, 0, 'ch_'+ch)
                x += 6

        x = 265
        if 'edge' in kws:
            self.image(x, 0, 'edge')
        elif 'devmode' in kws:
            self.image(x+5, 0, 'devmode')

        x = 16
        for dx, meta in [(7, 'shift'), (38, 'symbol'), (65, 'caps')]:
            if meta in kws:
                self.image(x+dx, 0, '%s_%d' % (meta, kws[meta]))

    def image(self, x, y, name):
        # display a graphics image, immediately
        w,h, data = getattr(Graphics, name)
        if x == None:
            x = max(0, (WIDTH - w) // 2)
        self.dis.show_zpixels(x, y, w, h, data)
        self.mark_correct(x, y, w, h)

    def mark_lines_dirty(self, rng):
        # mark a bunch of lines as needing redraw
        # - for QR which covers most of screen
        # - DELME
        for y in rng:
            self.last_buf[y] = array.array('H', (0xfffe for i in range(CHARS_W)))
            self.next_buf[y] = array.array('H', (0xfffe for i in range(CHARS_W)))

    def mark_correct(self, px, py, w, h):
        # mark a subset of the screen as already drawn correctly
        # - because we drew an image in that spot already (immediate)
        # - hard: need to convert from pixel coord space to chars
        if py < TOP_MARGIN:
            # status icons not a concern
            return

        cy = (py - TOP_MARGIN) // CELL_H
        cx = (px - LEFT_MARGIN) // CELL_W
        cw = (w+CELL_W) // CELL_W
        ch = (h+CELL_H) // CELL_H
        #print('pixel %dx%d @ (%d,%d) => %dx%d @ (%d,%d)' % (w, h, px,py,  cw, ch, cx,cy))

        for y in range(cy, cy+ch+1):
            for x in range(cx, cx+cw+1):
                try:
                    self.last_buf[y][x] = self.next_buf[y][x] = 0xfffe
                except IndexError:
                    pass
        self.show()

    def icon(self, x, y, name, invert=0):
        # plan is these are chars or images
        raise NotImplementedError

    def width(self, msg):
        # length of text msg in char cells
        # - typically 1:1 but we have a few double-width chars
        rv = len(msg)
        rv += sum(1 for ch in msg if ch in FontIosevka.DOUBLE_WIDE)
        return rv

    def text(self, x,y, msg, font=None, invert=0, attr=None):
        # Draw at x,y (in cell positions, not pixels)
        # Use invert=1 to get reverse video

        if x is None or x < 0:
            w = self.width(msg)
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
            print("BAD Draw '%s' at y=%d" % (msg, y))
            return     # past bottom

        for ch in msg:
            if x >= CHARS_W: break
            self.next_buf[y][x] = ord(ch) + (FLAG_INVERT if invert else 0)
            x += 1
            if ch in FontIosevka.DOUBLE_WIDE:
                self.next_buf[y][x] = 0
                x += 1

    def real_clear(self, _internal=False):
        # fill to black, but only text area, not status bar
        if not _internal:
            self.dis.fill_rect(0, TOP_MARGIN, WIDTH, HEIGHT-TOP_MARGIN, 0x0)
        self.last_buf = self.make_buf(32)
        self.next_buf = self.make_buf(32)
        self.next_prog_x = 0

    def clear(self):
        # clear text
        self.next_buf = self.make_buf(32)
        # clear progress bar
        self.next_prog_x = 0

    def show(self, just_lines=None):
        # Push internal screen representation to device, effeciently
        lines = just_lines or range(CHARS_H)
        for y in lines:
            x = 0
            while x < CHARS_W:
                if self.next_buf[y][x] == self.last_buf[y][x]:
                    # already correct
                    x += 1
                    continue

                py = TOP_MARGIN + (y * CELL_H)
                px = LEFT_MARGIN + (x * CELL_W)
                ch = chr(self.next_buf[y][x] & ~ATTR_MASK)
                attr = (self.next_buf[y][x] & ATTR_MASK)

                if ch == ' ':
                    # space - look for horz runs & fill w/ blank
                    run = 1
                    for x2 in range(x+1, CHARS_W):
                        if self.next_buf[y][x] != self.next_buf[y][x2]:
                            break                                        
                        run += 1

                    self.dis.fill_rect(px, py, run*CELL_W, CELL_H, 
                                COL_TEXT if attr == FLAG_INVERT else 0)
                    x += run
                    continue

                fn = FontIosevka.lookup(ch)
                if not fn:
                    # unknown char
                    x += 1
                    continue

                self.dis.show_pal_pixels(px, py, fn.w, fn.h, 
                    TEXT_PALETTE if not (attr == FLAG_INVERT) else TEXT_PALETTE_INV, fn.bits)

                x += fn.w // CELL_W

            self.last_buf[y][:] = self.next_buf[y]

        # maybe update progress bar
        if self.next_prog_x != self.last_prog_x:
            x = self.next_prog_x
            if x:
                self.dis.fill_rect(0, HEIGHT-3, x, 3, COL_PROGRESS)
            if x != WIDTH:
                self.dis.fill_rect(x, HEIGHT-3, WIDTH-x, 3, COL_BLACK)
            self.last_prog_x = x
                

    # rather than clearing and redrawing, use this buffer w/ fixed parts of screen
    # - obsolete concept
    def save(self):
        pass
    def restore(self):
        pass
    def clear_rect(self, x,y, w,h):
        raise NotImplementedError

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

    def DELME_splash(self):
        # test code
        from qrs import QRDisplaySingle
        import glob, time
        glob.dis = self
        #q = QRDisplaySingle(['mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'], is_alnum=True)
        #q2 = QRDisplaySingle(['R5bcepvg91mVPdDSAj62BmZYE9PyBVSHtm'], is_alnum=True)
        q = QRDisplaySingle(['a'*2953], is_alnum=False)
        q2 = QRDisplaySingle(['b'*2953], is_alnum=False)
        q.redraw()
        while 1:
            #time.sleep_ms(250)
            q2.redraw()
            #time.sleep_ms(250)
            q.redraw()
        assert False

    def splash(self):
        # display a splash screen with some version numbers
        self.real_clear()

        y = 6
        self.image(None, 90, 'splash')
        self.text(None, y, "Don't Trust. Verify.")

        from version import get_mpy_version
        timestamp, label, *_ = get_mpy_version()

        self.text(0,  -1, 'Version '+label)
        self.text(-1, -1, timestamp)
        self.show([y, CHARS_H-1])


    def splash_text(self, msg):
        # additional progress during splash/startup screen
        # - not sure any of this occurs during normal login sequence
        y = 1
        self.text(None, y, msg)
        self.show([y])

    def progress_bar(self, percent):
        # Horizontal progress bar
        # takes 0.0 .. 1.0 as fraction of doneness
        percent = max(0, min(1.0, percent))
        self.next_prog_x = int(WIDTH * percent)

    def progress_sofar(self, done, total):
        # Update progress bar, but only if it's been a while since last update
        if utime.ticks_diff(utime.ticks_ms(), self.last_bar_update) < 100:
            return
        self.last_bar_update = utime.ticks_ms()
        self.progress_bar_show(done / total)

    def progress_bar_show(self, percent):
        # useful as a callback
        self.progress_bar(percent)
        self.show()

    def mark_sensitive(self, from_y, to_y):
        # XXX maybe TODO ? or remove ... LCD doesnt have issue
        return

    def busy_bar(self, enable, speed_code=5):
        # TODO: activate the GPU to render/animate this.
        #print("busy_bar: %s" % enable)

        # impt, this show() is relied-upon by callers
        self.next_prog_x = 0
        self.show()

    def set_brightness(self, val):
        # normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        # XXX maybe control BL_ENABLE timing? or not required.
        return 

    def menu_draw(self, ry, msg, is_sel, is_checked, space_indicators):
        # draw a menu item, perhaps selected, checked.
        assert CHARS_W == 34

        if ry >= CHARS_H:
            # higher layer tries to draw partial line past bottom, and that's
            # ok because the mk4 had a 5th, half-line as a hint
            return

        if msg[0] == ' ' and space_indicators:
            # unused, but might need?
            msg = '␣' + msg[1:]

        x = 0
        self.text(x, ry, ' '+msg+' ', invert=is_sel)

        if is_checked:
            #self.text(CHARS_W-3, ry, '✔︎')
            self.text(len(msg)+2, ry, '✔︎')

        if 0:
            if is_sel:
                #ln = '▶ %s ◀' % msg
                #ln = '█▌%s▐█' % msg
                ln = '█▌%-29s▐█' % msg
            else:
                ln = '  ' + msg

            if is_checked:
                ln = '%-34s' % ln
                ln = ln[:CHARS_W-3] + '✓'

            self.text(0, ry, ln)


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

        self.show()

    def draw_story(self, lines, top, num_lines, is_sensitive):
        self.clear()

        y=0
        for ln in lines:
            if ln == 'EOT':
                self.text(0, y, '─'*CHARS_W, attr=AT_GREY25)
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

        # send packed pixel data to C level to decode and expand onto LCD
        # - 8-bit aligned rows of data
        scan_w, _, data = qr_data.packed()

        self.real_clear(_internal=True)
        self.dis.show_qr_data(x, TOP_MARGIN + y, w, expand, scan_w, data)
        self.mark_correct(x, TOP_MARGIN + y, qw, qw)

        if num_lines:
            # centered text under that
            y = CHARS_H - num_lines
            for line in parts:
                self.text(None, y, line)
                y += 1

        if idx_hint:
            # show path index number: just 1 or 2 digits
            self.text(-1, 0, idx_hint)

        self.busy_bar(False)

        
# here for mpy reasons
WIDTH = const(320)
HEIGHT = const(240)

# EOF
