# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psram.py -- access PSRAM chip on Mk4
#
import version, uctypes

# already started and memory mapped by bootrom.

class PSRAMWrapper:
    base = 0x9000_0000     # OCTOSPI1
    length = 0x40_0000     # 4 meg (lower half)

    def __init__(self):
        self._wr = uctypes.bytearray_at(self.base, self.length)

    def read_at(self, offset, ln):
        # one-copy byte-wise access
        return uctypes.bytes_at(self.base+offset, ln)

    def write_at(self, offset, ln):
        # word-aligned writes only
        assert offset % 4 == 0, offset
        assert ln % 4 == 0, ln
        assert offset + ln <= self.length, (offset+ln)
        
        return memoryview(self._wr)[offset:offset+ln]

    def is_at(self, ptr, offset):
        # is bytes() object really one we created at read_at
        return uctypes.addressof(ptr) == self.base+offset

    # Be compatible with SPIFlash class...

    def read(self, address, buf, cmd=None):
        buf[:] = self.read_at(address, len(buf))

    def write(self, address, buf):
        ln = len(buf)
        if ln % 4:
            assert address % 4 == 0, address
            runt = ln % 4
            tb = buf + bytes(4-runt)
            self.write_at(address, len(tb))[:] = tb
        else:
            self.write_at(address, ln)[:] = buf

    def is_busy(self):
        return False
    def wait_done(self):
        return

    # we are not flash
    def chip_erase(self):
        return
    def sector_erase(self, address):
        return
    def block_erase(self, address):
        return

    def wipe_all(self):
        # works, but code in bootrom is much faster and better (rng values used)
        from glob import dis

        z = bytes(16384)
        for pos in range(0, self.length, len(z)):
            self.write_at(pos, len(z))[:] = z

            dis.progress_bar_show(pos / self.length)

# EOF
