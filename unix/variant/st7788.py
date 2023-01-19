# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# st7788.py - LCD communications for Q1's 320x240 pixel *colour* display!
#
import struct, sys
import framebuf
import uasyncio

class ST7788(framebuf.FrameBuffer):
    def __init__(self):
        # for framebuf.FrameBuffer
        self.width = 320
        self.height = 240
        self.buffer = bytearray(320*240)

        self.pipe = open(int(sys.argv[1]), 'wb')

        super().__init__(self.buffer, self.width, self.height, framebuf.GS8)

    def show_partial(self, y, h):
        # update just a few rows of the display
        assert h >= 1
        assert h < 120      # sim limitation
        hdr = struct.pack('<4H', 0, y, 320, h)
        rows = memoryview(self.buffer)[320*y:320*(y+h)]
        self.pipe.write(hdr + rows)

    def show(self):
        # send entire frame buffer, but two packets
        hdr = struct.pack('<4H', 0, 0, 320, 120)
        self.pipe.write(hdr + self.buffer[0:320*120])

        hdr = struct.pack('<4H', 0, 120, 320, 120)
        self.pipe.write(hdr + self.buffer[320*120:])

# EOF 
