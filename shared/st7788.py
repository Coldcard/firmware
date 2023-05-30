# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# st7788.py - LCD communications for Q1's 320x240 pixel *colour* display!
#
import machine, uzlib, ckcc, utime, struct, array, sys
from version import is_devmode
import framebuf
import uasyncio
from uasyncio import sleep_ms
from graphics import Graphics
import sram2

# few key commands for this display
CASET = const(0x2a)
RASET = const(0x2b)
RAMWR = const(0x2c)

# TODO: move fully into C code
# - w/ zlib expansion
# - with window control
# - with font lookups / a text-only layer
# - maybe: with QR module expansion?
# - clear to pixel value
# - palette + xy/wh + nible-packed palette lookup (for font)
from ckcc import lcd_blast

class ST7788():
    def __init__(self):
        # assume the Bootrom setup the interface and LCD correctly already
        # - its fairly slow, complex and no need to change
        from machine import Pin
        from pyb import Timer       # not from machine

        self.spi = machine.SPI(1, baudrate=60_000_000, polarity=0, phase=0)
        #reset_pin = Pin('PA6', Pin.OUT)        # not using
        self.dc = Pin('PA8', Pin.OUT, value=0)
        self.cs = Pin('PA4', Pin.OUT, value=1)

        if 0:
            # BUST - just fades away
            # backlight control - will not see display with it off!
            self.bl_enable = Pin('BL_ENABLE', Pin.OUT, value=1)
            t = Timer(3, freq=100_000)
            # must be channel 3 because BL_ENABLE=>PE3?
            self.dimmer = t.channel(3, Timer.PWM, pin=self.bl_enable)

        # for framebuf.FrameBuffer
        self.width = 320
        self.height = 240
        #self.buffer = bytearray(320*240)

        #super().__init__(self.buffer, self.width, self.height, framebuf.GS8)

    def write_cmd(self, cmd, args=None):
        # send a command byte and a number of arguments
        self.cs(1)
        self.dc(0)
        self.cs(0)
        self.spi.write(bytes([cmd]))

        if args:
            self.dc(1)
            self.spi.write(args)

        self.cs(1)

    def write_data(self, buf):
        # just send data bytes; lcd needs to be right mode already
        self.cs(1)
        self.dc(1)
        self.cs(0)
        self.spi.write(buf)
        self.cs(1)

    def write_pixel_data(self, buf):
        # lcd_blast expands 1-byte per pixel to BGR565
        self.cs(1)
        self.dc(1)
        self.cs(0)
        try:
            lcd_blast(self.spi, buf)
        except:
            print('lcd_blast fail')
        self.cs(1)


    def _set_window(self, x, y, w=320, h=240):
        #self.write_cmd(0x2a, 0, LCD_WIDTH-1)         # CASET - Column address set range (x)
        #self.write_cmd(0x2b, y, LCD_HEIGHT-1)        # RASET - Row address set range (y)
        a = struct.pack('>HH', x, x+w-1)
        self.write_cmd(CASET, a)

        a = struct.pack('>HH', y, y+h-1)
        self.write_cmd(RASET, a)

        self.write_cmd(RAMWR)            # RAMWR - memory write

        # .. follow with w*h*2 bytes of pixel data

    def show_partial(self, y, h):
        # update just a few rows of the display
        assert h >= 1
        self._set_window(0, y, h=h)
        rows = memoryview(self.buffer)[320*y:320*(y+h)]
        self.write_pixel_data(rows)

    def show_zpixels(self, x, y, w, h, zpixels):
        # display compressed pixel data
        print('st7788.show_zpixels ... write me')

    def show_pal_pixels(self, x, y, w, h, palette, pixels):
        # show 4-bit packed paletted lookup pixels; used for fonts, icons
        assert len(palette) == 2 * 16

    def show(self):
        # send entire frame buffer
        self._set_window(0, 0)
        self.write_pixel_data(self.buffer)

    def fill_rect(self, x,y, w,h, pixel=0x0000):
        # need C code
        pass

    def fill_screen(self, pixel=0x0000):
        # clear screen to indicated pixel value
        # XXX need C code
        pass

# EOF 
