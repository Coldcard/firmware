# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# sffile.py - file-like objects stored in SPI Flash
#
# - implements stream IO protoccol
# - does erasing for you
# - random read, sequential write
# - only a few of these are possible
# - the offset is the file name
# - last 64k of memory reserved for settings
#
import tcc
from uasyncio import sleep_ms
from uio import BytesIO

# this code works on large "blocks" defined by the chip as 64k
blksize = const(65536)

def PADOUT(n):
    # rounds up
    return (n + blksize - 1) & ~(blksize-1)

class SFFile:
    def __init__(self, start, length=0, max_size=None, message=None, pre_erased=False):
        if not pre_erased:
            assert start % blksize == 0 # 'misaligned'
        self.start = start
        self.pos = 0
        self.length = length        # byte-wise length
        self.message = message

        if max_size != None:
            self.max_size = PADOUT(max_size) if not pre_erased else max_size
            self.readonly = False
            self.checksum = tcc.sha256()
        else:
            self.readonly = True

        from main import sf
        self.sf = sf

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
        assert not self.readonly
        assert self.length == 0 # 'already wrote?'

        for i in range(0, self.max_size, blksize):
            self.sf.block_erase(self.start + i)

            if i and self.message:
                from main import dis
                dis.progress_bar_show(i/self.max_size)

            # expect block erase to take up to 2 seconds
            while self.sf.is_busy():
                await sleep_ms(50)

    def __enter__(self):
        if self.message:
            from main import dis
            dis.fullscreen(self.message)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.message:
            from main import dis
            dis.progress_bar_show(1)

        return False

    def wait_writable(self):
        # TODO: timeouts here
        while self.sf.is_busy():
            pass

    def write(self, b):
        # immediate write, no buffering
        assert not self.readonly
        assert self.pos == self.length # "can only append"
        assert self.pos + len(b) <= self.max_size # "past end: %r" % [self.pos, len(b), self.max_size]

        left = len(b)
    
        # must perform page-aligned (256) writes, but can start
        # anywhere in the page, and can write just one byte
        sofar = 0

        while left:
            if (self.pos + sofar) % 256 != 0:
                # start is unaligned, do a partial write to align
                assert sofar == 0 #, (sofar, (self.pos+sofar))       # can only happen on first page
                runt = min(left, 256 - (self.pos % 256))
                here = memoryview(b)[0:runt]
                assert len(here) == runt
            else:
                # write full pages, or final runt
                here = memoryview(b)[sofar:sofar+256]
                assert 1 <= len(here) <= 256

            self.wait_writable()

            self.sf.write(self.start + self.pos + sofar, here)

            left -= len(here)
            sofar += len(here)
            self.checksum.update(here)

            assert left >= 0

        assert sofar == len(b)
        self.pos += sofar
        self.length = self.pos

        return sofar

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
        self.sf.read(self.start + self.pos, rv)

        self.pos += ll

        if self.message and ll > 1:
            from main import dis
            dis.progress_bar_show(self.pos / self.length)

        # altho tempting to return a bytearray (which we already have) many
        # callers expect return to be bytes and have those methods, like "find"
        return bytes(rv)

    def read_into(self, b):
        # limitation: this will read past end of file, but not tell the caller
        actual = min(self.length - self.pos, len(b))
        if actual <= 0:
            return 0

        self.sf.read(self.start + self.pos, b)

        self.pos += actual

        return actual

    def close(self):
        pass

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

    def wait_writable(self):
        return

    def write(self, b):
        # immediate write, no buffering
        assert self.pos == self.length # "can only append"

        here = len(b)

        self.pos += here
        self.length += here

        return here

    def read(self, ll=None):
        raise ValueError

    def read_into(self, b):
        raise ValueError

    def close(self):
        pass

# EOF
