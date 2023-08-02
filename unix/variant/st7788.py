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

        # also used by variant/gpu.py
        self.pipe = open(int(sys.argv[1]), 'wb')

    def gpu_send(self, cmd, *args):
        # for use by variant/gpu.py code
        if len(args) < 4:
            args += (0,)*(4-len(args))
        hdr = struct.pack('<s5H', cmd, *args)
        self.pipe.write(hdr)

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

        hdr = struct.pack('<s5H', 't', x, y, w, h, len(pixels)+len(palette))
        self.pipe.write(hdr + palette + pixels)

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
