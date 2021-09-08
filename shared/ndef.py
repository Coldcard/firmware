# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ndef.py -- NDEF records: making them and parsing them.
#
# - see ../docs/nfc-on-coldcard.md for background.
# - cross platform file
#
from struct import pack, unpack
from binascii import hexlify as b2a_hex

# From ST AN4911 - Fixed CC file that uses E2 to indicate 2-byte lengths
# - allocates entire memory (64k) to tag usage, read only
# - followed the "NDEF File Control TLV" tag (0x03) but not the length
CC_FILE = bytes([0xE2, 0x43, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00,   0x03])

# When we are writable, empty file is given
CC_WR_FILE = bytes([0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00,
        0x03, 0x00,  # empty
        0xfe,        # end marker
])

class ndefMaker:
    '''
        make a few different types of NDEF records, very limited and only
        for our use-cases
    '''
    def __init__(self):
        # ndef records: len, TNF value, type (byte string), payload (bytes)
        self.lst = []

    def add_text(self, msg):
        # assume: english, utf-8
        ln = len(msg) + 3
        self.lst.append( (ln, 0x1, b'T', b'\x02en' + msg.encode()) )

    def add_url(self, url, https=True):
        # always https since we're in Bitcoin, or else full URL
        # - ascii only
        proto_code = b'\x04' if https else b'\x00'
        self.lst.append( (len(url)+1, 0x1, b'U', proto_code + url.encode()) )

    def add_large_object(self, ext_type, offset, obj_len):
        # zero-copy a binary file from PSRAM into NFC flash
        # - or accept bytes
        if isinstance(offset, int):
            from glob import PSRAM
            self.lst.append( (obj_len, 0x4, ext_type.encode(),
                                                PSRAM.read_at(offset, obj_len)) )
        else:
            self.add_custom(ext_type, offset)

    def add_custom(self, ext_type, payload):
        # "NFC Forum external Type" using bitcoin.org domain
        self.lst.append( (len(payload), 0x4, ext_type.encode(), payload) )

    def bytes(self):
        # Walk list of records, and set various framing bits to first bytes of each
        # and concat.
        # - resist urge to make this a generator, it's not worth it.
        rv = bytearray(CC_FILE)

        # calc total length of all records
        ln = sum((3 if ln <= 255 else 6) + len(ntype) + len(rec) 
                            for (ln, _, ntype, rec) in self.lst)
        if ln <= 0xfe:
            rv.append(ln)
        else:
            rv.append(0xff)
            rv.extend(pack('>H', ln))

        last = len(self.lst) - 1
        for n, (ln, tnf, ntype, rec) in enumerate(self.lst):
            # First byte of the NDEF record: it's a bitmask + TNF 3-bit value
            
            # TNF=1 => well-known type
            # TNF=2 => mime-type from RFC 2046
            # TNF=4 => NFC Forum external type
            assert 0 < tnf < 7
            first = tnf

            if ln <= 255:
                first |= 0x10   # SR=1

            if n == 0:
                first |= 0x80   # = MB Message Begin
            if n == last:
                first |= 0x40   # = ME Message End

            rv.append(first)        # NDEF header byte
            rv.append(len(ntype))   # type-length always one, if well-known
            if ln <= 255:
                rv.append(ln)           # value-length 
            else:
                rv.extend(pack('>I', ln))
            rv.extend(ntype)
            rv.extend(rec)

        rv.append(0xfe)          # Terminator TLV

        return rv

def ccfile_decode(taste):
    # Given first 16 bytes of tag's memory (user memory):
    # - returns start and length of real Ndef records
    # - and is_writable flag
    # - and max size of tag memory capacity, in bytes (poorly spec'ed / compat issues)
    ex, b1, b2 = taste[0:3]
    assert b1 & 0xf0 == 0x40        # bad version.
    if ex == 0xE1:
        # "one byte addressing mode" -- max of 2040 bytes, 4-6 byte header
        if b2 != 0x00:
            st = 4
            mlen = b2     # aka MLEN
        else:
            st = 6
            mlen = unpack('>H', taste[4:4+2])[0]
    elif ex == 0xE2:
        # 8-byte CC Field, allows 2 byte address mode
        st = 8
        mlen = unpack('>H', taste[6:6+2])[0]
    else:
       raise ValueError("bad first byte")       # not one of 2 magic values we support

    assert taste[st] == 0x03        # special first TLV
    st += 1
    ll = taste[st:st+3]
    if ll[0] == 0xff:
        ll = unpack('>H', ll[1:])[0]
        st += 3
    else:
        ll = ll[0]
        st += 1

    assert 0 <= ll < 8196           # 64kbit max part

    return st, ll, ((b1 & 3) == 0), mlen*4

def record_parser(msg):
    # Given body of ndef records, yield a tuple for each record:
    # - type info, as urn string
    # - bytes of body
    # - dict of meta data, appropriate to type
    # - we gag on chunks
    pos = 0
    while 1:
        meta = {}
        hdr = msg[pos]

        MB = hdr & 0x80
        ME = hdr & 0x40
        CF = hdr & 0x20
        SR = hdr & 0x10
        IL = hdr & 0x08
        TNF = hdr & 0x7

        assert not CF                       # no chunks please
        assert (pos == 0) == bool(MB)       # first one needs MB set

        ty_len = msg[pos+1]
        pos += 2

        if SR:      # short record: one byte for payload length
            pl_len = msg[pos] 
            pos += 1
        else:
            pl_len = unpack('>I', msg[pos:pos+4])[0]
            pos += 4

        id_len = 0 
        if IL:
            id_len = msg[pos]
            pos += 1

        urn = None
        
        # type is next
        ty = msg[pos:pos+ty_len]
        pos += ty_len

        if TNF == 0x0:      # empty
            assert ty_len == pl_len == 0
            urn = None
        elif TNF == 0x1:        # WKT
            urn = 'urn:nfc:wkt:'
            urn += ty.decode()

            if ty == b'T':
                # unwrap Text
                hdr2 = msg[pos]
                assert hdr2 & 0xc0 == 0x00      # only UTF supported
                lang_len = hdr2 & 0x3f

                meta['lang'] = msg[pos+1:pos+1 + lang_len].decode()
                skip = 1 + lang_len
                pl_len -= skip
                pos += skip

            if ty == b'U':
                # limited URL support
                meta['prefix'] = msg[pos]
                pos += 1
                pl_len -= 1

        elif TNF == 0x2:        # mime-type, like 'image/png'
            urn = ty.decode()
        elif TNF == 0x3:        # absolute URI??
            urn = 'uri'
        elif TNF == 0x4:        # NFC forum external type
            urn = 'urn:nfc:ext:'
            urn += ty.decode()
        else:
            raise ValueError("TNF")     # unknown/reserved/not handled.

        if IL:
            meta['ident'] = bytes(msg[pos:pos+id_len])
            pos += id_len

        yield urn, memoryview(msg)[pos:pos+pl_len], meta

        if ME: return

        pos += pl_len
        assert pos < len(msg)       # missing ME/truncated


# EOF

# from NXP:
# E1 40 80 09  03 10  D1 01 0C 55 01 6E 78 70 2E 63 6F 6D 2F 6E 66 63 FE 00

# ST AN5439 -- works
# 4-byte CCfile  then "NDEF File Control TLV": 
#   E1 40 40 00  03 2A   
# NDef records:
#   D1012655016578616D706C652E636F6D2F74656D703D303030302F746170636F756E7465723D30303030FE000000
#
# m=b'\xe1@@\x00\x03*\xd1\x01&U\x01example.com/temp=0000/tapcounter=0000\xfe\x00\x00\x00'
