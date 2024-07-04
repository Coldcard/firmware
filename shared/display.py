# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# display.py - OLED rendering
#
import machine, uzlib, ckcc, utime
from ssd1306 import SSD1306_SPI
from version import is_devmode, is_edge
import framebuf
from graphics_mk4 import Graphics

# we support 4 fonts
from zevvpeep import FontSmall, FontLarge, FontTiny
FontFixed = object()    # ugly 8x8 PET font
display2_buf = bytearray(1024)


class Display:

    WIDTH = 128
    HEIGHT = 64

    # use these negative X values for auto layout features
    CENTER = -2
    RJUST = -1

    # use this to know if on Q1 or earlier 
    has_lcd = False

    def __init__(self):
        from machine import Pin

        spi = machine.SPI(1)
        reset_pin = Pin('PA6', Pin.OUT)
        dc_pin = Pin('PA8', Pin.OUT)
        cs_pin = Pin('PA4', Pin.OUT)

        try:
            self.dis = SSD1306_SPI(128, 64, spi, dc_pin, reset_pin, cs_pin)
        except OSError:
            print("OLED unplugged?")
            raise

        self.last_bar_update = 0
        self.clear()
        self.show()

    def width(self, msg, font):
        if font == FontFixed:
            return len(msg) * 8
        else:
            return sum(font.lookup(ord(ch)).w for ch in msg)

    def icon(self, x, y, name, invert=0):
        if isinstance(name, tuple):
            w,h, bw, wbits, data = name
        else:
            # see graphics.py (auto generated file) for names
            w,h, bw, wbits, data = getattr(Graphics, name)

        if wbits:
            data = uzlib.decompress(data, wbits)

        if invert:
            data = bytearray(i^0xff for i in data)

        gly = framebuf.FrameBuffer(bytearray(data), w, h, framebuf.MONO_HLSB)
        self.dis.blit(gly, x, y, invert)

        return (w, h)

    def text(self, x,y, msg, font=FontSmall, invert=0):
        # Draw at x,y (top left corner of first letter)
        # using font. Use invert=1 to get reverse video

        if x is None or x < 0:
            # center/rjust
            w = self.width(msg, font)
            if x == None:
                x = max(0, (self.WIDTH - w) // 2)
            else:
                # measure from right edge (right justify)
                x = max(0, self.WIDTH - w + 1 + x)

        if y < 0:
            # measure up from bottom edge
            y = self.HEIGHT - font.height + 1 + y

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

    def clear(self):
        self.dis.fill(0x0)

    def clear_rect(self, x,y, w,h):
        self.dis.fill_rect(x,y, w,h, 0)

    def show(self):
        self.dis.show()

    # rather than clearing and redrawing, use this buffer w/ fixed parts of screen
    def save(self):
        display2_buf[:] = self.dis.buffer
    def restore(self):
        self.dis.buffer[:] = display2_buf

    def hline(self, y):
        self.dis.line(0, y, 128, y, 1)
    def vline(self, x):
        self.dis.line(x, 0, x, 64, 1)

    def scroll_bar(self, offset, count, per_page):
        # along right edge, height is proportional to page size
        num_pages = max(count / per_page, 2)
        bh = max(int(64 / num_pages), 4)
        pos = int((64 - bh) * (offset / count))

        if offset and (offset + per_page >= count):
            # force last page to be at end
            pos = 64 - bh

        self.dis.fill_rect(128-5, 0, 5, 64, 0)
        self.icon(128-3, 1, 'scroll')
        self.dis.fill_rect(128-2, pos, 1, bh, 1)

        if is_devmode and not ckcc.is_simulator():
            self.dis.fill_rect(128-6, 20, 5, 21, 1)
            self.text(-2, 21, 'D', font=FontTiny, invert=1)
            self.text(-2, 28, 'E', font=FontTiny, invert=1)
            self.text(-2, 35, 'V', font=FontTiny, invert=1)
        elif is_edge:
            self.dis.fill_rect(128 - 6, 19, 5, 26, 1)
            self.text(-2, 20, 'E', font=FontTiny, invert=1)
            self.text(-2, 27, 'D', font=FontTiny, invert=1)
            self.text(-2, 33, 'G', font=FontTiny, invert=1)
            self.text(-2, 39, 'E', font=FontTiny, invert=1)

    def fullscreen(self, msg, percent=None, line2=None):
        # show a simple message "fullscreen". 
        # - 'line2' not supported on smaller screen sizes, ignore
        self.clear()
        y = 14
        self.text(None, y, msg, font=FontLarge)

        if percent is not None:
            self.progress_bar(percent)
        self.show()

    def splash(self):
        # display a splash screen with some version numbers
        self.clear()
        y = 4
        self.text(None,    y, 'COLDCARD', font=FontLarge)
        self.text(None, y+20, 'Wallet', font=FontLarge)

        from version import get_mpy_version
        timestamp, label, *_ = get_mpy_version()

        y = self.HEIGHT-10
        self.text(0,  y, 'Version '+label, font=FontTiny)
        self.text(-1, y, timestamp, font=FontTiny)
        
        self.show()

    def progress_bar(self, percent):
        # Horizontal progress bar
        # takes 0.0 .. 1.0 as fraction of doneness
        percent = max(0, min(1.0, percent))
        self.dis.hline(0, self.HEIGHT-1, int(self.WIDTH * percent), 1)

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
        wx = self.WIDTH-4       # avoid scroll bar
        for y in range(from_y, to_y):
            ln = max(2, ckcc.rng() % 32)
            self.dis.line(wx-ln, y, wx, y, 1)

    def busy_bar(self, enable):
        # Render a continuous activity (not progress) bar in lower 8 lines of display
        # - using OLED itself to do the animation, so smooth and CPU free
        # - cannot preserve bottom 8 lines, since we have to destructively write there
        # - assumes normal horz addr mode: 0x20, 0x00
        # - speed_code=>framedelay: 0=5fr, 1=64fr, 2=128, 3=256, 4=3, 5=4, 6=25, 7=2frames
        #   unused: assert 0 <= speed_code <= 7

        setup = bytes([
            0x21, 0x00, 0x7f,       # setup column address range (start, end): 0-127
            0x22, 7, 7,             # setup page start/end address: page 7=last 8 lines
        ])
        animate = bytes([ 
            0x2e,               # stop animations in progress
            0x26,               # scroll leftwards (stock ticker mode)
                0,              # placeholder
                7,              # start 'page' (vertical)
                5,              # "speed_code" # scroll speed: 7=fastest, but no order to it
                7,              # end 'page'
                0, 0xff,        # placeholders
            0x2f                # start
        ])

        cleanup = bytes([
            0x2e,               # stop animation
            0x20, 0x00,         # horz addr-ing mode
            0x21, 0x00, 0x7f,   # setup column address range (start, end): 0-127
            0x22, 7, 7,         # setup page start/end address: page 7=last 8 lines
        ])

        if not enable:
            # stop animation, and redraw old (new) screen
            self.write_cmds(cleanup)
            self.show()
        else:

            # a pattern that repeats nicely mod 128
            # - each byte here is a vertical column, 8 pixels tall, MSB at bottom
            data = bytes(0x80 if (x%4)<2 else 0x0 for x in range(128))

            if ckcc.is_simulator():
                # just show as static pattern
                t = self.dis.buffer[:-128] + data
                self.dis.write_data(t)
            else:
                self.write_cmds(setup)
                self.dis.write_data(data)
                self.write_cmds(animate)

    def write_cmds(self, cmds):
        for c in cmds:
            self.dis.write_cmd(c)

    def set_brightness(self, val):
        # normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        self.dis.write_cmd(0x81)        # Set Contrast Control
        self.dis.write_cmd(val)

    def menu_draw(self, ry, msg, is_sel, is_checked, space_indicators):
        # draw a menu item, perhaps selected, checked.
        x, y = (10, 2)
        h = 14
        y += ry * h

        if is_sel:
            self.dis.fill_rect(0, y, Display.WIDTH, h-1, 1)
            self.icon(2, y, 'wedge', invert=1)
            self.text(x, y, msg, invert=1)
        else:
            self.text(x, y, msg)

        # LATER: removed because caused confusion w/ underscore
        #if msg[0] == ' ' and space_indicators:
            # see also graphics/mono/space.txt
            #self.icon(x-2, y+9, 'space', invert=is_sel)

        if is_checked:
            self.icon(108, y, 'selected', invert=is_sel)

    def menu_show(self, *a):
        self.show()

    def show_yikes(self, lines):
        self.clear()
        self.text(None, 1, '>>>> Yikes!! <<<<')

        y = 13+2
        for num, ln in enumerate(lines):
            ln = ln.strip()

            if ln[0:6] == 'File "':
                # convert: File "main.py", line 63, in interact
                #    into: main.py:63  interact
                ln = ln[6:].replace('", line ', ':').replace(', in ', '  ')

            self.text(0, y + (num*8), ln, FontTiny)

        self.show()

    def draw_story(self, lines, top, num_lines, is_sensitive, **ignored):
        self.clear()

        y=0
        for ln in lines:
            if ln == 'EOT':
                self.hline(y+3)
            elif ln and ln[0] == '\x01':
                self.text(0, y, ln[1:], FontLarge)
                y += 21
            else:
                self.text(0, y, ln)

                if is_sensitive and len(ln) > 3 and ln[2] == ':':
                    self.mark_sensitive(y, y+13)

                y += 13

        self.scroll_bar(top, num_lines, 4)
        self.show()

    def draw_status(self, **k):
        # no status bar on Mk4
        return

    def draw_qr_display(self, qr_data, msg, is_alnum, sidebar, idx_hint, invert):
        # 'sidebar' is a pre-formated obj to show to right of QR -- oled life
        # - 'msg' will appear to right if very short, else under in tiny
        from utils import word_wrap

        self.clear()

        w = qr_data.width()
        if w <= 29:
            # version 1,2,3 => we can double-up the pixels
            dbl = True
            lm = 5 if idx_hint else 2  # do not overlap with idx
            h = w * 2
            bw = h + 4  # 2 white pixels from each side
            tm = (self.HEIGHT - bw) // 2
            XO, YO = lm + 2, tm + 2  # two white pixel around QR
        else:
            # v4+ => just one pixel per module, might not be easy to read
            # - vert center, left justify; text on space to right
            dbl = False
            YO = max(0, (64 - w) // 2)
            XO,lm = 6, 4
            bw = w + lm
            tm = (64 - bw) // 2

        if dbl:
            if not invert:
                self.dis.fill_rect(lm, tm, bw, bw, 1)
            else:
                self.dis.fill_rect(lm, tm, bw, bw, 0)

            for x in range(w):
                for y in range(w):
                    if not qr_data.get(x, y):
                        continue
                    X = (x*2) + XO
                    Y = (y*2) + YO
                    self.dis.fill_rect(X,Y, 2,2, invert)
        else:
            # direct "bilt" .. faster. Does not support inversion.
            self.dis.fill_rect(lm, tm, bw, bw, 1)
            _, _, packed = qr_data.packed()
            packed = bytes(i^0xff for i in packed)
            gly = framebuf.FrameBuffer(bytearray(packed), w, w, framebuf.MONO_HLSB)
            self.dis.blit(gly, XO, YO, 1)

        if not sidebar and not msg:
            pass
        elif not sidebar and len(msg) > (5*7):
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
                self.text(x, y, line, FontTiny)
                y += 8
        else:
            # hand-positioned for known cases
            # - sidebar = (text, #of char per line)
            x, y = 73, (0 if is_alnum else 2)
            dy = 10 if is_alnum else 12
            sidebar, ll = sidebar if sidebar else (msg, 7)

            for i in range(0, len(sidebar), ll):
                self.text(x, y, sidebar[i:i+ll], FontSmall)
                y += dy

        if not invert and idx_hint:
            # show path number, very tiny: vertical left edge
            assert len(idx_hint) <= 10
            y = 2
            for c in idx_hint:
                self.text(0, y, c, FontTiny)
                y += 6  # number is 5px + 1px space

        self.busy_bar(False)     # includes show

    def bootrom_takeover(self):
        # we are going to go into the bootrom and have it do stuff on the
        # screen... nothing needed on here, since we redraw completely
        pass

# EOF
