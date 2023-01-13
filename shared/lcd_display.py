# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# lcd_display.py - LCD rendering for Q1's 320x240 pixel *colour* display!
#
import machine, uzlib, ckcc, utime
from version import is_devmode
import framebuf
import uasyncio
from uasyncio import sleep_ms
from graphics import Graphics
from sram2 import display2_buf, display_buf
import struct

# we support 4 fonts
from zevvpeep import FontSmall, FontLarge, FontTiny
FontFixed = object()    # ugly 8x8 PET font

SPI_RATE = const(40000000)        # max chip can do, just past legal range for display

# few key commands
CASET = const(0x2a)
RASET = const(0x2b)
RAMWR = const(0x2c)

class ST7788(framebuf.FrameBuffer):
    def __init__(self, width, height, spi, dc, cs):
        # assume the Bootrom setup the interface and LCD correctly already
        # - its fairly slow, complex and no need to change
        dc.init(dc.OUT, value=0)
        cs.init(cs.OUT, value=1)
        spi.init(baudrate=SPI_RATE, polarity=0, phase=0)
        self.spi = spi
        self.dc = dc
        self.cs = cs

        # for framebuf.FrameBuffer
        self.width = width
        self.height = height
        self.pages = self.height // 8
        self.buffer = display_buf

        assert len(self.buffer) == self.pages * self.width

        super().__init__(self.buffer, self.width, self.height, framebuf.MONO_HLSB)

    def write_cmd(self, cmd, args=None):
        # send a command byte and a number of arguments
        self.cs(1)
        self.dc(0)
        self.cs(0)
        try:
            self.spi.write(bytes([cmd]))
        except:
            print("SPI[cmd]: %r" % self.spi)

        if args:
            self.dc(1)
            try:
                self.spi.write(args)
            except:
                print("SPI[arg]: %r" % self.spi)

        self.cs(1)

    def write_data(self, buf):
        # just send data bytes; lcd needs to be right mode already
        self.cs(1)
        self.dc(1)
        self.cs(0)
        try:
            self.spi.write(buf)
        except:
            print("SPI[data]: %r" % self.spi)
        self.cs(1)


    def _set_window(self, x, y, w=320, h=240):
        #self.write_cmd(0x2a, 0, LCD_WIDTH-1)         # CASET - Column address set range (x)
        #self.write_cmd(0x2b, y, LCD_HEIGHT-1)        # RASET - Row address set range (y)
        a = struct.pack('>HH', x, x+w-1)
        self.write_cmd(CASET, a)

        a = struct.pack('>HH', y, y+h-1)
        self.write_cmd(RASET, a)

    def show(self):
        # send self.buffer to display now
        # - compat mode: each pixel becomes 2x3 spot, centered in available space
        self._set_window(32, 24, 128*2, 64*3)
        self.write_cmd(RAMWR)            # RAMWR - memory write

        row = bytearray(128*2*2)
        for row_start in range(0, 1024, 128//8):
            pos = 0
            for x in range(128//8):
                b = self.buffer[row_start + x]
                mask = 0x80
                while mask:
                    col = 0xff if (b & mask) else 0x00
                    for i in range(4):
                        row[pos+i] = col
                    pos += 4
                    mask >>= 1

            # output a triple row
            self.write_data(row)
            self.write_data(row)
            self.write_data(row)

class Display:

    WIDTH = 128
    HEIGHT = 64

    # use these negative X values for auto layout features
    CENTER = -2
    RJUST = -1

    def __init__(self):
        from machine import Pin

        spi = machine.SPI(1)
        #reset_pin = Pin('PA6', Pin.OUT)        # not using
        dc_pin = Pin('PA8', Pin.OUT)
        cs_pin = Pin('PA4', Pin.OUT)

        self.dis = ST7788(128, 64, spi, dc_pin, cs_pin)

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

    def scroll_bar(self, fraction):
        # along right edge
        self.dis.fill_rect(128-5, 0, 5, 64, 0)
        self.icon(128-3, 1, 'scroll');
        mm = 64-6
        pos = min(int(mm*fraction), mm)
        self.dis.fill_rect(128-2, pos, 1, 8, 1)

        if is_devmode and not ckcc.is_simulator():
            self.dis.fill_rect(128-6, 20, 5, 21, 1)
            self.text(-2, 21, 'D', font=FontTiny, invert=1)
            self.text(-2, 28, 'E', font=FontTiny, invert=1)
            self.text(-2, 35, 'V', font=FontTiny, invert=1)

    def fullscreen(self, msg, percent=None, line2=None):
        # show a simple message "fullscreen". 
        self.clear()
        if line2:
            y = 10
            self.text(None, y, msg, font=FontLarge)
            y += 24
            self.text(None, y, line2, font=FontSmall)
        else:
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
        self.progress_bar(done / total)
        self.show()

    def progress_bar_show(self, percent):
        # useful as a callback
        self.progress_bar(percent)
        self.show()

    def mark_sensitive(self, from_y, to_y):
        wx = self.WIDTH-4       # avoid scroll bar
        for y in range(from_y, to_y):
            ln = max(2, ckcc.rng() % 32)
            self.dis.line(wx-ln, y, wx, y, 1)

    def busy_bar(self, enable, speed_code=5):
        print("busy_bar")       # XXX TODO
        return
        # Render a continuous activity (not progress) bar in lower 8 lines of display
        # - using OLED itself to do the animation, so smooth and CPU free
        # - cannot preserve bottom 8 lines, since we have to destructively write there
        # - assumes normal horz addr mode: 0x20, 0x00
        # - speed_code=>framedelay: 0=5fr, 1=64fr, 2=128, 3=256, 4=3, 5=4, 6=25, 7=2frames
        assert 0 <= speed_code <= 7

        setup = bytes([
            0x21, 0x00, 0x7f,       # setup column address range (start, end): 0-127
            0x22, 7, 7,             # setup page start/end address: page 7=last 8 lines
        ])
        animate = bytes([ 
            0x2e,               # stop animations in progress
            0x26,               # scroll leftwards (stock ticker mode)
                0,              # placeholder
                7,              # start 'page' (vertical)
                speed_code,     # scroll speed: 7=fastest, but no order to it
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
        print('wr cmds?')
        return 

    def set_brightness(self, val):
        # normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        # XXX control BL_ENABLE timing
        return 

# EOF
