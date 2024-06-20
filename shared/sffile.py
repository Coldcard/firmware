# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sffile.py - file-like objects stored in PSRAM (Mk4+) (used to be SPI Flash)
#
# - implements stream IO protoccol
# - random read, sequential write
# - only a few of these are possible
# - the offset is the file name
#
from uhashlib import sha256

# Use PSRAM chip
from glob import PSRAM
blksize = 4

def ALIGN4(n):
     return n & ~0x3

class SFFile:
    def __init__(self, start, length=0, max_size=None, message=None):
        # Operate in PSRAM and pretend to be a filesystem's file
        assert start % blksize == 0     # 'misaligned'
        self.start = start
        self.pos = 0
        self.length = length        # byte-wise length
        self.message = message
        self.runt = False

        if max_size != None:
            # Write
            self.max_size = max_size
            self.readonly = False
            self.checksum = sha256()

            # up to 3 bytes that haven't been written-out yet
            self.runt = bytearray()
            self.wr_pos = 0
        else:
            # Read
            self.readonly = True

    def tell(self):
        # where are we?
        return self.pos

    def is_eof(self):
        # we are positioned at end of file
        return (self.pos >= self.length)

    def seek(self, offset, whence=0):
        # whence:
        #   0 -- start of stream (the default); offset should be zero or positive
        #   1 -- current stream position; offset may be negative
        #   2 -- end of stream; offset is usually negative
        # except no clipping; force their math to be right.

        if whence == 0:
            pass
        elif whence == 1:
            # move relative
            offset = self.pos + offset
        elif whence == 2:
            offset = self.length + offset
        else:
            raise ValueError(whence)
        
        assert 0 <= offset <= self.length # "bad offset"
        self.pos = offset

    async def erase(self):
        # must be used by caller before writing any bytes
        # - now just checks, used to be a slow erase cycle
        assert not self.readonly
        assert self.length == 0         # 'already wrote?'
        return

    def __enter__(self):
        if self.message:
            from glob import dis
            dis.fullscreen(self.message)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush_out()

        if self.message:
            from glob import dis
            dis.progress_bar_show(1)

        return False

    def flush_out(self):
        # PSRAM might leave a little behind
        if self.runt:
            # write final runt, might be up to 3 bytes (padding w/ zeros)
            assert len(self.runt) <= 3      # , 'rl=%d'%len(self.runt)
            assert self.wr_pos + len(self.runt) == self.pos
            self.runt.extend(bytes(4-len(self.runt)))
            PSRAM.write(self.start + self.wr_pos, self.runt)

            self.runt = None
            self.wr_pos = self.pos

    def write(self, b):
        # immediate write, no buffering
        assert not self.readonly
        assert self.pos == self.length              # "can only append"
        assert self.pos + len(b) <= self.max_size   # "past end"

        left = len(b)

        # PSRAM is memory-mapped, but can only do word-aligned writes!
        self.checksum.update(b)

        self.runt.extend(b)
        here = ALIGN4(len(self.runt))
        if here:
            PSRAM.write(self.start + self.wr_pos, self.runt[0:here])
            self.wr_pos += here
            self.runt = self.runt[here:]

        self.pos += left
        self.length = self.pos

        if self.message:
            from glob import dis
            dis.progress_sofar(self.pos, self.length)

        return left

    def read(self, ll=None):
        if ll == 0:
            return b''
        elif ll is None:
            ll = self.length - self.pos
        else:
            ll = min(ll, self.length - self.pos)

        if ll <= 0:
            # at EOF
            return b''

        rv = bytearray(ll)
        if self.runt and self.pos + ll > self.wr_pos:
            # put the runt data into place, because we are about to read it
            t = bytearray(self.runt)
            t.extend(bytes(4-len(t)))
            PSRAM.write(self.start + self.wr_pos, t)

        PSRAM.read(self.start + self.pos, rv)

        self.pos += ll

        # altho tempting to return a bytearray (which we already have) many
        # callers expect return to be bytes and have those methods, like "find"
        return bytes(rv)

    def readinto(self, b):
        # limitation: this will read past end of file, but not tell the caller
        actual = min(self.length - self.pos, len(b))
        if actual <= 0:
            return 0

        PSRAM.read(self.start + self.pos, b)

        self.pos += actual

        return actual


class SizerFile(SFFile):
    # looks like a file, but forgets everything except file position
    # - used to measure length of an output
    def __init__(self):
        self.pos = self.length = 0

    async def erase(self):
        return

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def write(self, b):
        # immediate write, no buffering
        assert self.pos == self.length # "can only append"

        here = len(b)

        self.pos += here
        self.length += here

        return here

    def read(self, ll=None):
        raise ValueError

    def readinto(self, b):
        raise ValueError

    def close(self):
        pass

# EOF
