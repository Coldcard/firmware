# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# nfc.py -- Add some NFC tag-like features to Mk4
#
# - using ST ST25DV64KC
# - on it's own I2C bus (not shared)
# - has GPIO signal "??" which is multipurpose on its own pin
# - this chip chosen because it can disable RF interaction
#
from utime import sleep_ms
from utils import B2A
from ustruct import pack, unpack
from ubinascii import hexlify as b2a_hex
import ngu, ckcc
from utime import sleep_ms

# i2c address (7-bits) is not simple...
# - assume defaults of E0=1 and I2C_DEVICE_CODE=0xa 
# - also 0x2d which isn't documented and no idea what it is
I2C_ADDR_USER = const(0x53)
I2C_ADDR_SYS  = const(0x57)
I2C_ADDR_RF_ON = const(0x51)
I2C_ADDR_RF_OFF  = const(0x55)

# Dynamic regs
GPO_CTRL_Dyn = const(0x2000) # GPO control
EH_CTRL_Dyn = const(0x2002)  # Energy Harvesting management & usage status
RF_MNGT_Dyn = const(0x2003)  # RF interface usage management
I2C_SSO_Dyn = const(0x2004)  # I2C security session status
IT_STS_Dyn = const(0x2005)   # Interrupt Status
MB_CTRL_Dyn = const(0x2006)  # Fast transfer mode control and status
MB_LEN_Dyn = const(0x2007)   # Length of fast transfer mode message

# Sys config area
I2C_PWD = const(0x900)      # I2C security session password, 8 bytes
RF_MNGT = const(0x03)       # RF interface state after Power ON
I2C_CFG = const(0x0e)

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
        # ndef records, without first byte (bitmask) and type lenght byte
        self.lst = []

    def tlen(self, ln):
        # variable-length encoding of a number for TLV thing
        if ln < 0xfe:
            return pack('B', ln)
        else:
            return b'\xff' + pack('>H', ln)

    def add_text(self, msg):
        # assume: english, utf-8
        ln = len(msg) + 3
        hdr = self.tlen(ln) + b'T\x02en'
        self.lst.append(hdr + msg.encode())

    def add_url(self, url, https=True):
        # always https since we're in Bitcoin, or else full URL
        # - ascii only
        proto_code = b'U\x04' if https else b'U\x00'
        hdr = pack('B', len(url) + 1) + proto_code
        self.lst.append(hdr + url.encode())

    def bytes(self):
        # walk list of records, and various framing bits to first bytes of each
        # and concat
        rv = bytearray(CC_FILE)

        # estimate? length of all records
        ln = sum(2 + len(r) for r in self.lst)
        rv.extend(self.tlen(ln))

        last = len(self.lst) - 1
        for n, rec in enumerate(self.lst):
            # first byte of the NDEF record: it's a bitmask + TNF 3-bit value
            # - only support well-known tags, less 250 bytes, no chunking
            first = 0x11        # TNF=1 SR=1
            if n == 0:
                first |= 0x80           # = MB Message Begin
            if n == last:
                first |= 0x40           # = ME Message End

            rv.append(first)        # NDEF header byte
            rv.append(0x1)          # type-length always one, because well-known
            rv.extend(rec)

        return rv
        

class NFCHandler:
    def __init__(self):
        from machine import I2C, Pin
        self.i2c = I2C(1, freq=400000)
        self.pin_ed = Pin('NFC_ED', mode=Pin.IN, pull=Pin.PULL_UP)

    # flash memory access (fixed tag data): 0x0 to 0x2000
    def read(self, offset, count):
        return self.i2c.readfrom_mem(I2C_ADDR_USER, offset, count, addrsize=16)
    def write(self, offset, data):
        # various limits in place here? Not clear
        #assert offset+len(data) < 256
        self.i2c.writeto_mem(I2C_ADDR_USER, offset, data, addrsize=16)

    def big_write(self, data):
        # write lots to start of flash (new ndef records)
        for pos in range(0, len(data), 256):
            here = memoryview(data)[pos:pos+256]
            self.i2c.writeto_mem(I2C_ADDR_USER, pos, here, addrsize=16)
            sleep_ms(100)     # 6ms per 16 byte row, worst case

    # system config area (flash cells, but affect operation): table 12
    def read_config(self, offset, count):
        return self.i2c.readfrom_mem(I2C_ADDR_SYS, offset, count, addrsize=16)
    def write_config(self, offset, data):
        # not all areas are writable
        self.i2c.writeto_mem(I2C_ADDR_SYS, offset, data, addrsize=16)
    def read_config1(self, offset):
        return self.i2c.readfrom_mem(I2C_ADDR_SYS, offset, 1, addrsize=16)[0]
    def write_config1(self, offset, value):
        self.i2c.writeto_mem(I2C_ADDR_SYS, offset, bytes([value]), addrsize=16)

    # dynamic registers (state control, bytes): table 13
    def read_dyn(self, offset):
        assert 0x2000 <= offset < 0x2008
        return self.i2c.readfrom_mem(I2C_ADDR_USER, offset, 1, addrsize=16)[0]
    def write_dyn(self, offset, val):
        assert 0x2000 <= offset < 0x2008
        m = bytes([val])
        self.i2c.writeto_mem(I2C_ADDR_USER, offset, m, addrsize=16)

    def is_rf_disabled(self):
        # not checking if disable/sleep vs. off
        return (self.read_dyn(RF_MNGT_Dyn) != 0)

    def set_rf_disable(self, val):
        # using stronger "off" rather than sleep/disable
        if val:
            self.i2c.writeto(I2C_ADDR_RF_OFF, b'')
            assert self.read_dyn(RF_MNGT_Dyn) & 0x4
        else:
            self.i2c.writeto(I2C_ADDR_RF_ON, b'')
            self.write_dyn(RF_MNGT_Dyn, 0)
            assert self.read_dyn(RF_MNGT_Dyn) == 0x0

    def send_pw(self, pw=None):
        # show we know a password (but sent cleartext, very lame)
        pw = pw or bytes(8)
        assert len(pw) == 8

        msg = pw + b'\x09' + pw
        self.write_config(I2C_PWD, msg)

        return (self.read_dyn(I2C_SSO_Dyn) & 0x1 == 0x1)      # else "wrong pw"
        
    def firsttime_setup(self):
        # always setup IC_RF_SWITCHOFF_EN bit in I2C_CFG register
        # - so we can module RF support with special i2c addresses
        # - keep default other bits: 0x1a (i2c base address)
        print("NFC: first time")
        self.write_config1(I2C_CFG, 0x3a)

        # set to no RF when first powered up (so CC is quiet when system unpowered)
        # - side-effect: sets rf to sleep now too
        self.write_config1(RF_MNGT, 2)
        

    def setup(self):
        # check if present, alive
        uid = self.read_config(0x18, 8)

        assert uid[-1] == 0xe0      # ST manu code
        uid = ':'.join('%02x'% i for i in reversed(uid))

        # read size of memory
        self.mem_size = (unpack('<H', self.read_config(0x14, 2))[0] + 1) * 4

        # chip revision, expect 0x11 perhaps "1.1"?
        rev = self.read_config(0x20, 1)[0]

        print("NFC: uid=%s size=%d rev=%x" % (uid, self.mem_size, rev))

        self.send_pw()
        
        if self.read_config1(I2C_CFG) != 0x3a:
            # chip probably blank...
            self.firsttime_setup()

        self.set_rf_disable(1)
    
    def test_code(self):
        # test code
        self.set_rf_disable(0)

        ndef = ndefMaker()
        ndef.add_text('abcd'*500)
        ndef.add_url("store.coinkite.com")
        #ndef.add_text("this is simple text")
        self.big_write(ndef.bytes())

        # always disable RF before we have data
        #self.set_rf_disable(1)

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
