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
        from glob import PSRAM
        self.lst.append( (obj_len, 0x4, ext_type.encode(),
                                                PSRAM.read_at(offset, obj_len)) )

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
