# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# bbqr.py - Implement BBQr protocol for multiple QR support (also compression and filetype info)
#
import utime, uzlib, ngu
from utils import problem_file_line
from exceptions import QRDecodeExplained
from ubinascii import unhexlify as a2b_hex
from version import MAX_TXN_LEN

b32encode = ngu.codecs.b32_encode
b32decode = ngu.codecs.b32_decode

TYPE_LABELS = dict(P='PSBT File', T='Transaction', J='JSON', C='CBOR', U='Unicode Text',
                        X='Executable', B='Binary', 
                        R='KT Rx', S='KT Tx', E='KT PSBT')

def int2base36(n):
    # convert an integer to two digits of base 36 string. 00 thu ZZ as bytes
    # - converse is just: int(s, base=36)

    tostr = lambda x: chr(48+x) if x < 10 else chr(65+x-10)

    a, b = divmod(n, 36)
    assert 0 <= a < 36

    return tostr(a) + tostr(b)

def calc_num_qr(char_capacity, char_len, split_mod):
    # Determine number of QR's would be needed to hold char_len alnum characters,
    # if each QR holds char_capacity of chars max.
    # - when 2 or more QR, consider the exact split point cannot be between encoded symbols
    # - accounts for BBRq header
    # - returns (number of QR needed), (# of chars in each)
    from math import ceil

    cap = char_capacity - 8         # 8==HEADER_LEN

    if char_len <= cap:
        # no alignment concerns
        return 1, char_len

    # max per non-final qr
    cap2 = cap - (cap % split_mod)
    need = ceil(char_len / cap2)

    assert need >= 2

    # Going to be 2 or more, gotta be precise
    # - final part doesn't need to be "encoding aligned"
    actual = ((need - 1) * cap2) + cap
    #print("act=%d char_len=%d   need=%d  c=%d c2=%d" % (actual, char_len, need, cap, cap2))

    if char_len > actual:
        need += 1

    # Challenge: the final QR might have just a a few chars in it, if we redistribute
    # the data into the other parts, then each QR can have more forward error correction
    # and be more robust. Must respect split_mod alignment tho.
    level = ceil(char_len / need)
    if level % split_mod:
        level += split_mod - (level % split_mod)

    assert level % split_mod == 0, level
    assert level <= cap2, (level, cap2)

    return need, level

def num_qr_needed(encoding, data_len):
    # returns (QR version, num_parts, part_size[bytes]) 
    # - lots of Q-related policy here

    # Just a few key values, picked because the height of the QR must
    # fit vertically (240 px tall) ... see "bbqr table"
    CHARS_PER_VERSION = [
        # (QR version, alnum capacity)
        # first entry will be used for tiny BBQr that don't need animation
        (15, 758),       # 77px x 3: 77*3 = 231px tall
        (25, 1853),      # 117px, doubled: 234px tall
        (40, 4296),      # 177px tall, shown 1:1 pixels -- phones can scan fine
        # last entry will be used for huge BBQr that have > 12 frames
    ]

    if encoding == 'H':
        char_len = data_len * 2
        split_mod = 2
    else:
        # plan for Base32, always best option
        # - five inputs bytes => 8 alnum chars
        # - for final set of 1-5 we remove padding == , so between 2..7 chars
        char_len = ((data_len//5) * 8) + { 0:0, 1:2, 2:4, 3:5, 4:7 }[data_len % 5]
        split_mod = 8

    # Try a few select resolutions (sizes) in order such that we use either single QR
    # or the least-dense option that gives reasonable number of QR's
    for target_vers, capacity in CHARS_PER_VERSION:
        num_parts, part_size = calc_num_qr(capacity, char_len, split_mod)
        if num_parts == 1:
            # great, no animation needed!
            break
        if target_vers == 15 and num_parts == 2:
            # it fits in two v15, but would be a single v25; so prefer that
            continue
        if target_vers < 40 and num_parts <= 12:
            # will be reasonable animation, so use this size
            break

    # convert # of chars per QR, into bytes per each (last one may be less)
    if num_parts > 1:
        assert part_size % split_mod == 0
        if encoding == 'H':
            pkt_size = part_size // 2
        else:
            pkt_size = part_size * 5 // 8
    else:
        pkt_size = data_len

    #print('bbqr: %d bytes => %d chars (%s enc) => v%d in %d parts of %d char / %d bytes each'
    #           % (data_len, char_len, encoding, target_vers, num_parts, part_size, pkt_size))

    assert num_parts * pkt_size >= data_len

    #assert part_size % split_mod == 0, (target_vers, part_size, split_mod, char_len, data_len)
    return target_vers, num_parts, pkt_size



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

        try:
            hdr = BBQrHeader(scan)
        except Exception as exc:
            raise QRDecodeExplained("Bad header: %s" % problem_file_line(exc))

        if not self.hdr or not self.hdr.is_compat(hdr):
            # New or incompatible header, they might have changed their
            # minds and are now trying to scan something else; recover
            self.reset()
            self.storage.reset()
            self.hdr = hdr

        if hdr.which not in self.parts:
            # we've NOT YET seen this one

            # convert back to binary
            try:
                raw = hdr.decode_body(scan)
            except Exception as exc:
                # can happen if QR got corrupted between scanner and us (overlap)
                # or back BBQr implementation
                #print("corrupt QR: %s" % scan)
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
    # Store BBQr in normal RAM. Simple. Pure.

    def __init__(self):
        self.reset()

    def reset(self):
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

        self.final_size = len(self.buf)

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

        if upper_bound >= MAX_TXN_LEN:
            raise QRDecodeExplained("Too big")

        # If data is compressed, write tmp (compressed) copy into top half of PSRAM
        # and we'll put final, decompressed copy at zero offset (later)
        self.psr_offset = MAX_TXN_LEN if self.hdr.encoding == 'Z' else 0

        self.buf = True

    def write_pkt(self, offset, data):
        # Save indicated data, but problems:
        # - writes to PSRAM must be 4-aligned
        # - due to base32 math, typically incoming data will not be aligned
        # - write what we can, keep the rest around in normal memory
        from glob import PSRAM

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

                if off+ln > MAX_TXN_LEN:
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
