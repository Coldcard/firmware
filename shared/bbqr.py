# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# bbqr.py - Implement BBQr protocol for multiple QR support (also compression and filetype info)
#
import utime, uzlib
import uasyncio as asyncio
from struct import pack, unpack
from utils import B2A
from imptask import IMPT
from queues import Queue

# For BBQr support
import ngu
b32encode = ngu.codecs.b32_encode
b32decode = ngu.codecs.b32_decode
from ubinascii import unhexlify as a2b_hex

TYPE_LABELS = dict(P='PSBT File', T='Transaction', J='JSON', C='CBOR', U='Unicode Text')

def int2base36(n):
    # convert an integer to two digits of base 36 string. 00 thu ZZ
    # converse is just int(s, base=36)

    tostr = lambda x: chr(48+x) if x < 10 else chr(65+x-10)

    a, b = divmod(n, 36)
    assert 0 <= a < 36

    return tostr(a) + tostr(b)


class BBQrHeader:
    def __init__(self, taste):
        # parse header based on standard
        # expects a string
        assert len(taste) >= 8
        assert taste[0:2] == 'B$'

        self.encoding, self.file_type = taste[2:4]
        self.num_parts = int(taste[4:6], 36)
        self.which = int(taste[6:8], 36)
    
        assert 1 <= self.num_parts
        assert 0 <= self.which < self.num_parts

    def __repr__(self):
        return '<BBQr: %d of %d parts, enc=%s ft=%s>' % (self.which, self.num_parts,
                                                    self.encoding, self.file_type)

    def is_compat(self, other):
        # Does this header match previous ones seen?
        return (self.encoding == other.encoding and 
                self.file_type == other.file_type and
                self.num_parts == other.num_parts)

    def decode_body(self, scan):
        # perform the decoding implied by header (but not decompression)
        body = bytes(memoryview(scan)[8:])

        if self.encoding == 'H':
            rv = a2b_hex(body)
        else:
            rv = b32decode(body)

        return rv

    def file_label(self):
        # provide a string as hint to user of what they are getting
        if self.file_type in TYPE_LABELS:
            return TYPE_LABELS[self.file_type]
        else:
            return 'Unknown: %s' % self.file_type
        
            
class BBQrState:
    def __init__(self):
        self.reset()

    def reset(self):
        self._psb = None        # hack, to be removed
        self.hdr = None
        self.parts = set()
        self.runt = None
        self.runt_size = None
        self.blksize = None

    def upper_bound(self):
        # max size we are expecting
        return self.blksize * self.hdr.num_parts

    def is_valid(self):
        return bool(self.hdr) and len(self.parts) == self.hdr.num_parts

    def collect(self, scan):
        # Another BBQr has come in; track it.
        # - return T while more parts are still needed
        # - updates UX to show the progress
        from glob import dis

        hdr = BBQrHeader(scan)

        print("Got " + repr(hdr))

        if not self.hdr or not self.hdr.is_compat(hdr):
            # New or incompatible header, they might have changed their
            # minds and are now trying to scan something else; recover
            self.reset()
            self.hdr = hdr

        if hdr.which not in self.parts:
            # we've NOT YET seen this one

            # convert back to binary
            raw = hdr.decode_body(scan)

            if hdr.which and (hdr.which == hdr.num_parts-1) and not self.parts:
                # Problem: this is a runt and we saw it first, we have no idea
                # where to put it; store as tmp for now.
                self.runt = (hdr.which, raw)
            else:
                # based on (required) assumption that all parts are equal, we know
                # where to put this data, so do that.
                self.parts.add(hdr.which)

                if self.blksize is None:
                    self.blksize = len(raw)

                self.save_packet(hdr.which, raw)

                # seeing any other packet is enough to decide where to put the runt
                if self.runt:
                    wh, raw = self.runt
                    self.save_packet(wh, raw)
                    self.parts.add(wh)
                    self.runt = None

        # provide UX
        dis.draw_bbqr_progress(hdr.which, list(self.parts), hdr.num_parts, hdr.file_label())

        # do we need more still?
        return (len(self.parts) < hdr.num_parts)

    def save_packet(self, which, data):
        # override this on other projects... which don't have stupid PSRAM like this
        # - can only write 4-aligned data to PSRAM, and typically the parts will not be
        #   4-aligned because base32 yields 5 byte quantities
        # - TODO: keep up num_parts of 3-byte runts, etc. {offset:bytes} and flush aligned
        #   parts each time we get more data
        assert self.blksize is not None

        if which == None:
            # we are supposed to be done, return w/ complete length
            final_size = (self.blksize * (self.hdr.num_parts-1)) + self.runt_size
            return final_size, self._psb[0:final_size]

        if which == self.hdr.num_parts-1:
            self.runt_size = len(data)

        offset = which * self.blksize
        if not self._psb:
            self._psb = bytearray(self.upper_bound())

        self._psb[offset:offset+len(data)] = data

    def finalize(self):
        # got all the parts, so maybe decompress
        # - return number of bytes waiting at start of PSRAM, and the filetype code
        assert len(self.parts) == self.hdr.num_parts, "still missing parts"

        # flush out data we have
        final_size, raw = self.save_packet(None, None)

        if self.hdr.encoding == 'Z':
            # do in-place Zlib decompression (TODO)
            raw = uzlib.decompress(raw, -10)
            final_size = len(raw)

        return self.hdr.file_type, final_size, raw
        

# EOF
