# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# variant/gpu.py - Simulate GPU co-processor access and support.
#
# - see notes in misc/gpu/README.md
#
import utime, struct
import uasyncio as asyncio
from ustruct import pack
import glob

class GPUAccess:
    def __init__(self):
        self.i_have_spi = True

    def reset(self):
        pass

    def get_version(self):
        # bogus
        import gpu_binary
        return gpu_binary.VERSION

    def take_spi(self):
        # stop any on-going animation
        if self.i_have_spi:
            return
        glob.dis.dis.gpu_send('T')
        self.i_have_spi = True

    def give_spi(self):
        # not used, implicit in other cmds
        raise NotImplementedError

    def have_spi(self):
        # do we control the display?
        return self.i_have_spi

    def busy_bar(self, enable):
        if enable:
            # start the bar
            glob.dis.dis.gpu_send('B')
            self.i_have_spi = False
        else:
            # stop showing it
            self.take_spi()

    def cursor_off(self):
        # stop showing the cursor
        self.take_spi()
        
    def cursor_at(self, x, y, dbl_wide=False, outline=False):
        # use outline to leave most of the cell unaffects (just 1px inside border)
        glob.dis.dis.gpu_send('C', x, y, int(dbl_wide), int(outline))
        self.i_have_spi = False

    def upgrade(self):
        # do in-circuit programming of GPU chip -- not simulated
        import gpu_binary
        return gpu_binary.VERSION

# EOF
