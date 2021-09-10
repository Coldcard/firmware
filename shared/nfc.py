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
import ndef

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

    @classmethod
    def startup(cls):
        import glob
        n = cls()
        try:
            n.setup()
            glob.NFC = n
        except BaseException as exc:
            sys.print_exception(exc)        # debug only remove me
            print("NFC absent/disabled")
            del n

    def shutdown(self):
        # we aren't wanted anymore
        self.set_rf_disable(True)
        import glob
        glob.NFC = None

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
        
    def get_uid(self):
        # Unique id for chip. Required for RF protocol.
        return ':'.join('%02x'% i for i in reversed(self.uid))

    def dump_ndef(self):
        # dump what we are showing, skipping the CCFILE and wrapping
        # - used in test cases, and psbt rx
        taste = self.read(0, 16)
        st, ll, _, _ = ndef.ccfile_decode(taste)
        return self.read(st, ll)
        
    def firsttime_setup(self):
        # always setup IC_RF_SWITCHOFF_EN bit in I2C_CFG register
        # - so we can module RF support with special i2c addresses
        # - keep default other bits: 0x1a (i2c base address)
        print("NFC: first time")
        self.write_config1(I2C_CFG, 0x3a)

        # set to no RF when first powered up (so CC is quiet when system unpowered)
        # - side-effect: sets rf to sleep now too
        self.write_config1(RF_MNGT, 2)

        # XXX locking stuff?

    def setup(self):
        # check if present, alive
        self.uid = self.read_config(0x18, 8)

        assert self.uid[-1] == 0xe0      # ST manu code

        # read size of memory
        self.mem_size = (unpack('<H', self.read_config(0x14, 2))[0] + 1) * 4

        # chip revision, expect 0x11 perhaps "1.1"?
        rev = self.read_config(0x20, 1)[0]

        print("NFC: uid=%s size=%d rev=%x" % (self.get_uid(), self.mem_size, rev))

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

        n = ndef.ndefMaker()
        if txid is not None:
            n.add_text('Signed Transaction: ' + txid)
            n.add_custom('bitcoin.org:txid', a2b_hex(txid))          # want binary
        n.add_custom('bitcoin.org:sha256', txn_sha)
        n.add_large_object('bitcoin.org:txn', file_offset, txn_len)
        
        await self.share_start(n)

    async def share_psbt(self, file_offset, psbt_len, psbt_sha, label=None):
        # we just signed something, share it over NFC
        if psbt_len >= MAX_NFC_SIZE:
            await ux_show_story("PSBT is too large to share over NFC")
            return

        n = ndef.ndefMaker()
        n.add_text(label or 'Partly signed PSBT')
        n.add_custom('bitcoin.org:sha256', psbt_sha)

        n.add_large_object('bitcoin.org:psbt', file_offset, psbt_len)

        await self.share_start(n)
        
    async def share_deposit_address(self, addr):
        n = ndef.ndefMaker()
        n.add_text('Deposit Address')
        n.add_custom('bitcoin.org:addr', addr.encode())
        await self.share_start(n)

    async def share_text(self, data):
        # share text from a list of values
        # - just a text file, no multiple records; max usability!
        n = ndef.ndefMaker()
        n.add_text(data)

        await self.share_start(n)

    async def ux_animation(self, write_mode):
        from glob import dis

        self.set_rf_disable(0)
        dis.fullscreen("NFC", line2="Tap phone onto 8")
        dis.busy_bar(1)

        # TODO: detect when we are written, or key to exit
        ch = await ux_wait_keyup()
        dis.busy_bar(0)
        self.set_rf_disable(1)

        return ch

    async def share_start(self, obj):
        # do the UX while we are sharing a value over NFC
        # - assumpting is people know what they are scanning
        # - any key to quit
        # - maybe add a timeout for safety reasons?
        from glob import dis

        self.big_write(obj.bytes())

        await self.ux_animation(False)

    async def start_nfc_rx(self):
        # pretend to be a big warm empty tag ready to be stuffed with data
        from auth import psbt_encoding_taster, TXN_INPUT_OFFSET
        from auth import UserAuthorizedAction, ApproveTransaction
        from ux import abort_and_goto
        from sffile import SFFile

        self.big_write(ndef.CC_WR_FILE)
        await self.ux_animation(True)

        taste = self.read(0, 16)
        st, ll, _, _ = ndef.ccfile_decode(taste)

        if not ll:
            # they wrote nothing / failed to do anything
            await ux_show_story("No tag data was written?", title="Sorry!")
            return

        # copy to ram
        data = self.read(st, ll)
        psbt_in = None
        psbt_sha = None
        for urn, msg, meta in ndef.record_parser(data):
            if len(msg) > 100:
                # attempt to decode any large object, ignore type for max compat
                try:
                    decoder, output_encoder, psbt_len = \
                        psbt_encoding_taster(msg[0:10], len(msg))
                    psbt_in = msg
                except ValueError:
                    continue

            if urn == 'urn:nfc:ext:bitcoin.org:sha256' and len(msg) == 32:
                # probably produced by another Coldcard: SHA256 over expected contents
                psbt_sha = bytes(msg)

        if psbt_in is None:
            await ux_show_story("Could not find PSBT", title="Sorry!")
            return

        # Decode into PSRAM at start
        total = 0
        with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
            if not decoder:
                total = out.write(psbt_in)
            else:
                for here in decoder.more(psbt_in):
                    total += out.write(here)

        # might have been whitespace inflating initial estimate of PSBT size, adjust
        assert total <= psbt_len
        psbt_len = total

        # start signing UX
        UserAuthorizedAction.cleanup()
        UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, 0x0, psbt_sha=psbt_sha,
                                                approved_cb=self.signing_done)
        # kill any menu stack, and put our thing at the top
        abort_and_goto(UserAuthorizedAction.active_request)

    async def signing_done(self, psbt):
        # User approved the PSBT, and signing worked... share result over NFC (only)
        from auth import TXN_OUTPUT_OFFSET
        from public_constants import MAX_TXN_LEN
        from sffile import SFFile

        txid = None

        # asssume they want final transaction when possible, else PSBT output
        is_comp = psbt.is_complete()

        # re-serialize the PSBT back out (into PSRAM)
        with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as fd:
            if is_comp:
                txid = psbt.finalize(fd)
            else:
                psbt.serialize(fd)

            fd.close()
            self.result = (fd.tell(), fd.checksum.digest())

        out_len, out_sha = self.result

        if is_comp:
            await self.share_signed_txn(txid, TXN_OUTPUT_OFFSET, out_len, out_sha)
        else:
            await self.share_psbt(TXN_OUTPUT_OFFSET, out_len, out_sha)

        # ? show txid on screen ?
        # thank them?



# EOF
