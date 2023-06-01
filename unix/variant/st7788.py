# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# st7788.py - LCD communications for Q1's 320x240 pixel *colour* display!
#
import struct, sys
import framebuf
import uasyncio

class ST7788:
    def __init__(self):
        # for framebuf.FrameBuffer
        self.width = 320
        self.height = 240
        #self.buffer = bytearray(320*240)

        self.pipe = open(int(sys.argv[1]), 'wb')

        #super().__init__(self.buffer, self.width, self.height, framebuf.GS8)

    def show_partial(self, y, h):
        # update just a few rows of the display
        assert h >= 1
        assert h < 120      # sim limitation
        rows = memoryview(self.buffer)[320*y:320*(y+h)]
        hdr = struct.pack('<s5H', 'p', 0, y, 320, h, len(rows))
        self.pipe.write(hdr + rows)

    def show(self):
        # send entire frame buffer, but two packets
        hdr = struct.pack('<s5H', 'p', 0, 0, 320, 120, 320*120)
        self.pipe.write(hdr + self.buffer[0:320*120])

        hdr = struct.pack('<s5H', 'p', 0, 120, 320, 120, 320*120)
        self.pipe.write(hdr + self.buffer[320*120:])

    def show_zpixels(self, x, y, w, h, zpixels):
        # display compressed pixel data
        hdr = struct.pack('<s5H', 'z', x, y, w, h, len(zpixels))
        self.pipe.write(hdr + zpixels)

    def fill_screen(self, pixel=0x0000):
        # clear screen to indicated pixel value
        self.fill_rect(0,0, 320,240, pixel)

    def fill_rect(self, x,y, w,h, pixel=0x0000):
        msg = struct.pack('<s5HH', 'f', x, y, w, h, 2, pixel)
        self.pipe.write(msg)

    def show_pal_pixels(self, x, y, w, h, palette, pixels):
        # show 4-bit packed paletted lookup pixels; used for fonts, icons
        assert len(palette) == 2 * 16
        assert len(pixels) == w * h // 2

        if 0:
            # do palette lookup now
            tmp = bytearray(2 * w * h)
            pos = 0
            for px in pixels:
                col = (px >> 4)
                tmp[pos:pos+2] = palette[col:col+2]
                col = px & 0xf
                tmp[pos+2:pos+4] = palette[col:col+2]
                pos += 4

            hdr = struct.pack('<s5H', 'r', x, y, w, h, len(tmp))
            self.pipe.write(hdr + tmp)
        else:
            # assumes simulator has same palette
            hdr = struct.pack('<s5H', 't' if palette[0] == 0 else 'i', x, y, w, h, len(pixels))
            self.pipe.write(hdr + pixels)

    def show_qr_data(self, x, y, w, expand, scan_w, packed_data):
        # 8-bit packed QR data, and where to draw it, expanded
        assert len(packed_data) == (scan_w*w) // 8, [len(packed_data), w, scan_w]
        hdr = struct.pack('<s5H', 'q', x, y, w, expand, len(packed_data))
        self.pipe.write(hdr + packed_data)

    def save_snapshot(self, full_path):
        # save into PNG in local filesystem, return file name
        hdr = struct.pack('<s5H', 's', 0, 0, 0, 0, len(full_path))
        self.pipe.write(hdr + full_path.encode())

# EOF 
