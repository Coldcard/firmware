# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# st7788.py - LCD communications for Q1's 320x240 pixel *colour* display!
#
import machine, uzlib, utime, struct, sys


# few key commands for this display
CASET = const(0x2a)
RASET = const(0x2b)
RAMWR = const(0x2c)

# Lots of drawing code now in C code:
# - font lookups / a text-only layer
# - QR module expansion
# - clear to pixel value
# - (MAYBE NOT) palette + xy/wh + nible-packed palette lookup (for font)
# - (NOT) zlib expansion
# - see stm32/COLDCARD_Q1/modlcd.c for code
import lcd

class ST7788():
    def __init__(self):
        # assume the Bootrom setup the interface and LCD correctly already
        # - its fairly slow, complex and no need to change
        from machine import Pin
        from pyb import LED

        # - max baud of display is unclear, but 80Mhz SATSLINK works
        # - 60Mhz is max on this chip, because it's half of 120Mhz which is APB1 freq
        self.spi = machine.SPI(1, baudrate=60_000_000, polarity=0, phase=0)

        # do not change careful GPIO setup from bootloader (outputs)
        #reset_pin = Pin('LCD_RESET', Pin.OUT)        # not using
        self.dc = Pin('LCD_DATA_CMD')
        self.cs = Pin('LCD_CS')

        # control backlight brightness via this object
        self.backlight = LED(1)
        self.backlight.on()

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

    def _set_window(self, x, y, w=320, h=240):
        # CASET - Column address set range (x)
        # RASET - Row address set range (y)
        a = struct.pack('>HH', x, x+w-1)
        self.write_cmd(CASET, a)

        a = struct.pack('>HH', y, y+h-1)
        self.write_cmd(RASET, a)

        self.write_cmd(RAMWR)            # RAMWR - memory write

        # Must follow with w*h*2 bytes of pixel data.

    def fill_screen(self, pixel=0x0000):
        # clear ENTIRE screen to indicated pixel value
        self.fill_rect(0,0, 320, 240, pixel)

    def show_zpixels(self, x, y, w, h, zpixels):
        # display compressed pixel data, used for images/icons
        # - keeping in mpy since C version would be same speed
        data = uzlib.decompress(zpixels, -10)
        self._set_window(x, y, w, h)
        self.write_data(data)

    def show_pal_pixels(self, x, y, w, h, palette, pixels):
        # show 4-bit packed paletted lookup pixels; used for fonts
        #assert len(palette) == 2 * 16
        lcd.send_packed(self.spi, x, y, w, h, palette, pixels)

    def show_qr_data(self, x, y, w, expand, scan_w, packed_data, trim_lines=0):
        # 8-bit packed QR data, and where to draw it, expanded by 'expand'
        assert len(packed_data) == (scan_w*w) // 8
        lcd.send_qr(self.spi, x, y, w, expand, scan_w, packed_data, trim_lines)

    def fill_rect(self, x,y, w,h, pixel=0x0000):
        # set a rectangle to a single colour
        if not w or not h: return
        lcd.fill_rect(self.spi, x, y, w, h, pixel)

# EOF 
