# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# nfc.py -- Add some NFC tag-like features to Mk4
#
# - using ST ST25DV64KC
# - on it's own I2C bus (not shared)
# - has GPIO signal "??" which is multipurpose on its own pin
# - this chip chosen because it can disable RF interaction
#
import ngu, ckcc
from utime import sleep_ms
from utils import B2A
from ustruct import pack, unpack
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from ux import ux_wait_keyup, ux_show_story
from ndef import ndefMaker

# practical limit for things to share: 8k part, minus overhead
MAX_NFC_SIZE = 8000

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
        print('big write...', end='')
        for pos in range(0, len(data), 256):
            here = memoryview(data)[pos:pos+256]
            self.i2c.writeto_mem(I2C_ADDR_USER, pos, here, addrsize=16)
            sleep_ms(100)     # 6ms per 16 byte row, worst case
        print('.. done')

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

    async def share_signed_txn(self, txid, file_offset, txn_len, txn_sha):
        # we just signed something, share it over NFC
        if txn_len >= MAX_NFC_SIZE:
            await ux_show_story("Transaction is too large to share over NFC")
            return

        ndef = ndefMaker()
        if txid is not None:
            ndef.add_text('Signed Transaction: ' + txid)
            ndef.add_custom('bitcoin.org:txid', a2b_hex(txid))          # want binary
        ndef.add_custom('bitcoin.org:sha256', txn_sha)
        ndef.add_large_object('bitcoin.org:txn', file_offset, txn_len)
        
        await self.share_start(ndef)

    async def share_psbt(self, file_offset, psbt_len, psbt_sha, label=None):
        # we just signed something, share it over NFC
        if psbt_len >= MAX_NFC_SIZE:
            await ux_show_story("PSBT is too large to share over NFC")
            return

        ndef = ndefMaker()
        ndef.add_text(label or 'Partly signed PSBT')
        ndef.add_custom('bitcoin.org:sha256', psbt_sha)

        ndef.add_large_object('bitcoin.org:psbt', file_offset, psbt_len)

        await self.share_start(ndef)
        
    async def share_deposit_address(self, addr):
        ndef = ndefMaker()
        ndef.add_text('Deposit Address')
        ndef.add_custom('bitcoin.org:addr', addr.encode())
        await self.share_start(ndef)

    async def share_text(self, data):
        # share text from a list of values
        # - just a text file, no multiple records; max usability!
        ndef = ndefMaker()
        ndef.add_text(data)

        await self.share_start(ndef)


    async def share_start(self, ndef):
        # do the UX while we are sharing a value over NFC
        # - assumpting is people know what they are scanning
        # - any key to quit
        # - maybe add a timeout for safety reasons?
        from glob import dis

        self.big_write(ndef.bytes())
        self.set_rf_disable(0)

        dis.fullscreen("NFC")
        dis.busy_bar(1)
        await ux_wait_keyup()
        dis.busy_bar(0)

        self.set_rf_disable(1)
        

    def dump_ndef(self):
        # dump what we are showing, skipping the CCFILE and wrapping
        # - used in test cases
        ll = self.read(8+1, 3)
        if ll[0] == 0xff:
            ll = unpack('>H', ll[1:])[0]
            st = 12
        else:
            ll = ll[0]
            st = 10
        return self.read(st, ll)
    
    def test_code(self):
        # test code
        self.set_rf_disable(0)

        ndef = ndefMaker()
        #ndef.add_text('abcd'*2000)
        #ndef.add_url("store.coinkite.com")
        #ndef.add_text("this is simple text")
        ndef.add_custom('bitcoin.org:txid', b2a_hex(bytes(range(32))))

        self.big_write(ndef.bytes())

        # always disable RF before we have data
        #self.set_rf_disable(1)

# EOF
