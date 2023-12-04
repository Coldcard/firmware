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
from exceptions import QRDecodeExplained

# For BBQr support
import ngu
b32encode = ngu.codecs.b32_encode
b32decode = ngu.codecs.b32_decode
from ubinascii import unhexlify as a2b_hex

TYPE_LABELS = dict(P='PSBT File', T='Transaction', J='JSON', C='CBOR', U='Unicode Text',
                        X='Executable', B='Binary')

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
        return '<BBQr: %dof%d parts, enc=%s ft=%s>' % (self.which+1, self.num_parts,
                                                        self.encoding, self.file_type)

    def is_compat(self, other):
        # Does this header match previous ones seen?
        return (self.encoding == other.encoding and 
                self.file_type == other.file_type and
                self.num_parts == other.num_parts)

    def decode_body(self, scan):
        # perform the decoding implied by header (but not decompression)
        body = bytes(memoryview(scan)[8:])

        if b'B$' in body:
            # happens if we have an Rx overlow, and see two codes mushed together
            raise ValueError("Overlapped BBQrs!")

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
    def __init__(self, storage):
        self.storage = storage
        self.reset()

    def reset(self):
        self.hdr = None
        self.parts = set()
        self.runt = None
        self.blksize = None

    def is_complete(self):
        return bool(self.hdr) and len(self.parts) == self.hdr.num_parts and not self.runt

    def collect(self, scan):
        # Another BBQr has come in; track it.
        # - return T while more parts are still needed
        # - updates UX to show the progress
        from glob import dis

        hdr = BBQrHeader(scan)

        #print("Got %r have %r" % (hdr, self.parts))

        if not self.hdr or not self.hdr.is_compat(hdr):
            # New or incompatible header, they might have changed their
            # minds and are now trying to scan something else; recover
            self.reset()
            self.hdr = hdr

        if hdr.which not in self.parts:
            # we've NOT YET seen this one

            # convert back to binary
            try:
                raw = hdr.decode_body(scan)
            except Exception as exc:
                # can happen if QR got corrupted between scanner and us (overlap)
                # or back BBQr implementation
                print("corrupt QR: %s" % scan)
                import sys; sys.print_exception(exc)

                dis.draw_bbqr_progress(hdr, self.parts, corrupt=True)
                return True

            if hdr.which and (hdr.which == hdr.num_parts-1) and not self.parts:
                # Problem: this is a runt and we saw it first, we have no idea
                # where to put it; store as tmp for now.
                self.runt = (hdr.which, raw)
                self.parts.add(hdr.which)
            else:
                # based on (required) assumption that all parts are equal, we know
                # where to put this data, so do that.
                self.parts.add(hdr.which)

                if self.blksize is None:
                    self.blksize = len(raw)

                self.storage.save_packet(self.blksize, hdr, hdr.which, raw)

        # seeing any other packet is enough to decide where to put the runt
        if self.runt and self.blksize:
            wh, raw = self.runt
            self.storage.save_packet(self.blksize, hdr, wh, raw)
            self.runt = None

        # provide UX -- even if we didn't use it
        dis.draw_bbqr_progress(hdr, self.parts)

        # do we need more still?
        return (len(self.parts) < hdr.num_parts) or self.runt

class BBQrStorage:
    # override this on other projects... which don't have enough ram for whole thing

    def __init__(self):
        self.buf = None
        self.hdr = None                 # could be any header in series
        self.runt_size = None
        self.final_size = None

    def save_packet(self, blksize, hdr, which, data):
        # Record bytes (after deserialization, Base32/Hex decoding)
        # - might be zlib compressed still, but certainly binary
        assert blksize

        if not self.hdr:
            self.hdr = hdr
        else:
            assert self.hdr.is_compat(hdr)

        if which == hdr.num_parts-1:
            # size of runt determines final complete size
            self.runt_size = len(data)
            self.final_size = (blksize * (hdr.num_parts-1)) + self.runt_size

        if not self.buf:
            # memory alloc now
            upper_bound = blksize * hdr.num_parts
            self.alloc_buf(upper_bound)

        offset = which * blksize
        self.write_pkt(offset, data)

    def alloc_buf(self, upper_bound):
        # set aside space needed for whole thing
        try:
            self.buf = bytearray(upper_bound)
        except MemoryError:
            raise QRDecodeExplained("Too big")

    def write_pkt(self, offset, data):
        # save binary of one QR payload
        self.buf[offset:offset+len(data)] = data

    def zlib_decompress(self):
        # do in-place Zlib decompression, update final_size
        try:
            self.buf = uzlib.decompress(self.buf, -10)
        except:
            # corrupt data / data underruns trigger here
            raise RuntimeError("Zlib fail")

        self.final_size = len(raw)

    def _finalize(self):
        pass

    def get_buffer(self):
        return self.buf

    def finalize(self):
        # Got all the parts, so maybe decompress. Return details of what we got
        # - return: file type, exact final size
        self._finalize()

        if self.hdr.encoding == 'Z':
            self.zlib_decompress()

        return self.hdr.file_type, self.final_size, self.get_buffer()
        

class BBQrPsramStorage(BBQrStorage):
    # specialized verison for use on funky PSRAM chip of Q

    def __init__(self):
        super().__init__()
        self.frags = dict()
        self.psr_offset = 0

    def alloc_buf(self, upper_bound):
        # using first part of PSRAM

        from public_constants import MAX_TXN_LEN_MK4

        if upper_bound >= MAX_TXN_LEN_MK4:
            raise QRDecodeExplained("Too big")

        # If data is compressed, write tmp (compressed) copy into top half of PSRAM
        # and we'll put final, decompressed copy at zero offset (later)
        self.psr_offset = MAX_TXN_LEN_MK4 if self.hdr.encoding == 'Z' else 0

        self.buf = True

    def write_pkt(self, offset, data):
        # Save indicated data, but problems:
        # - writes to PSRAM must be 4-aligned
        # - due to base32 math, typically incoming data will not be
        # - write what we can, keep the rest around in normal memory
        from glob import PSRAM

        #print("write_pkt: @ %d for %d" % (offset, len(data)))

        # our offset into PSRAM
        offset += self.psr_offset       # will be aligned

        # some at the start might be unaligned
        off = 4 - (offset % 4)
        if off != 4:
            # up to 3 bytes at start
            self.frags[offset] = bytes(data[0:off])
            assert 1 <= len(self.frags[offset]) < 4

            offset += off
            data = memoryview(data)[off:]

        ln = len(data)
        ln4 = ln & ~3

        # aligned middle (most times)
        if ln4:
            PSRAM.write_at(offset, ln4)[:] = data[0:ln4]

        # maybe a part at end
        runt = ln - ln4
        if runt:
            assert 1 <= runt < 4
            p = bytes(data[ln4:])
            self.frags[offset+ln4] = p
            assert 1 <= len(p) == runt < 4

    def _finalize(self):
        # flush out fragments to where they actually belong
        from glob import PSRAM

        while self.frags:
            off, data = self.frags.popitem()

            off4 = off & ~3         # can be aligned already (1-3 byte runt)
            tmp = bytearray(PSRAM.read_at(off4, 4))
            tmp[off-off4:off-off4+len(data)] = data
            assert len(tmp) == 4
            PSRAM.write_at(off4, 4)[:] = tmp

    def zlib_decompress(self):
        # do in-place Zlib decompression, update final_size
        # - except in-place decompression is not possible in general
        # - so go PSRAM(top half) -> PSRAM(bot half)
        from glob import PSRAM, dis
        from uzlib import DecompIO
        from io import BytesIO
        from public_constants import MAX_TXN_LEN_MK4

        dis.fullscreen('Decompressing...')

        off = 0
        buf = b''
        with BytesIO(PSRAM.read_at(self.psr_offset, self.final_size)) as fd:
            decoded = DecompIO(fd, -10)
            while 1:
                try:
                    here = decoded.read(1024)
                    if not here: break
                except:
                    # corrupt data / data underruns trigger here
                    raise RuntimeError("Zlib fail")

                # aligned writes
                buf += here
                ln = len(buf) & ~3

                if off+ln > MAX_TXN_LEN_MK4:
                    # test with: `yes | dd bs=1000 count=2700 | bbqr make - | pbcopy`
                    raise QRDecodeExplained("Too big")
                
                if ln:
                    PSRAM.write_at(off, ln)[:] = buf[0:ln]
                    buf = buf[ln:]
                    off += ln

                dis.progress_sofar(fd.tell(), self.final_size)

            # true final size
            self.final_size = off + len(buf)

            if buf:
                # write final bit, perhaps some extra zeros after that too
                pad = 4 - (len(buf) % 4)
                if pad < 4:
                    buf += bytes(pad)
                PSRAM.write_at(off, len(buf))[:] = buf

    def get_buffer(self):
        # give a pointer into PSRAM
        from glob import PSRAM
        return PSRAM.read_at(0, self.final_size)


# EOF
