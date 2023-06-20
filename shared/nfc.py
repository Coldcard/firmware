# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# nfc.py -- Add some NFC tag-like features to Mk4
#
# - using ST ST25DV64KC
# - on it's own I2C bus (not shared)
# - has GPIO signal "??" which is multipurpose on its own pin
# - this chip chosen because it can disable RF interaction
#
import ngu, utime, ngu, ndef
from uasyncio import sleep_ms
from ustruct import pack, unpack
from ubinascii import unhexlify as a2b_hex
from ubinascii import b2a_base64, a2b_base64

from ux import ux_show_story, ux_poll_key
from utils import B2A, problem_file_line, parse_addr_fmt_str
from public_constants import AF_CLASSIC


# practical limit for things to share: 8k part, minus overhead
MAX_NFC_SIZE = const(8000)

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
GPO1_CFG = const(0x00)       # GPIO config 1
GPO2_CFG = const(0x01)       # GPIO config 2
RF_MNGT = const(0x03)       # RF interface state after Power ON
I2C_CFG = const(0x0e)
I2C_PWD = const(0x900)      # I2C security session password, 8 bytes

class NFCHandler:
    def __init__(self):
        from machine import I2C, Pin
        self.i2c = I2C(1, freq=400000)
        self.last_edge = 0
        self.pin_ed = Pin('NFC_ED', mode=Pin.IN, pull=Pin.PULL_UP)

        # track time of last edge
        def _irq(x):
            self.last_edge = utime.ticks_ms()
        self.pin_ed.irq(_irq, Pin.IRQ_FALLING)
        

    @classmethod
    def startup(cls):
        import glob
        n = cls()
        try:
            n.setup()
            glob.NFC = n
        except BaseException as exc:
            # i2c comms errors probably
            #sys.print_exception(exc)        # debug only remove me
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
        self.i2c.writeto_mem(I2C_ADDR_USER, offset, data, addrsize=16)

    async def big_write(self, data):
        # write lots to start of flash (new ndef records)
        for pos in range(0, len(data), 256):
            here = memoryview(data)[pos:pos+256]
            self.i2c.writeto_mem(I2C_ADDR_USER, pos, here, addrsize=16)
            # 6ms per 16 byte row, worst case, so ~100ms here!
            await self.wait_ready()

    async def wipe(self, full_wipe):
        # Tag value is stored in flash cells, so want to clear
        # once we're done in case it's sensitive. But too slow to
        # clear entire chip most of time, just do first 512 bytes,
        # and dont wait for last to complete
        from glob import dis
        here = bytes(256)
        end = 8196
        for pos in range(0, end, 256) :
            self.i2c.writeto_mem(I2C_ADDR_USER, pos, here, addrsize=16)
            if pos == 256 and not full_wipe: break

            # 6ms per 16 byte row, worst case, so ~100ms here per iter! 3.2seconds total
            if full_wipe:
                dis.progress_bar_show(pos / end)
            await self.wait_ready()

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
            return

        # re-enable (turn on)
        for i in range(10):
            try:
                self.i2c.writeto(I2C_ADDR_RF_ON, b'')
                self.write_dyn(RF_MNGT_Dyn, 0)
                assert self.read_dyn(RF_MNGT_Dyn) == 0x0

                return
            except:         # assertion, OSError(ENODEV)
                # handle no-ACK cases (sometimes, after bigger write to flash)
                utime.sleep_ms(25)
        else:
            raise RuntimeError("timeout")

    def send_pw(self, pw=None):
        # show we know a password (but sent cleartext, very lame)
        # - keeping as zeros for now, so pointless anyway
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
        self.write_config1(I2C_CFG, 0x3a)

        utime.sleep_ms(10)      # required

        # set to no RF when first powered up (so CC is quiet when system unpowered)
        # - side-effect: sets rf to sleep now too
        self.write_config1(RF_MNGT, 2)

        utime.sleep_ms(10)      # might be needed?

        # XXX locking stuff?

    def setup(self):
        # check if present, alive
        self.uid = self.read_config(0x18, 8)

        assert self.uid[-1] == 0xe0      # ST manu code

        # read size of memory
        mem_size = (unpack('<H', self.read_config(0x14, 2))[0] + 1) * 4
        assert mem_size == 8192          # require 64kbit part

        # chip revision, saw 0x11 perhaps means "1.1"?
        #rev = self.read_config(0x20, 1)[0]
        #print("NFC: uid=%s size=%d rev=%x" % (self.get_uid(), mem_size, rev))

        self.send_pw()
        
        if self.read_config1(I2C_CFG) != 0x3a:
            # chip probably blank...
            self.firsttime_setup()

        self.set_rf_disable(1)

    async def share_signed_txn(self, txid, file_offset, txn_len, txn_sha):
        # we just signed something, share it over NFC
        if txn_len >= MAX_NFC_SIZE:
            await ux_show_story("Transaction is too large to share via NFC")
            return

        n = ndef.ndefMaker()
        if txid is not None:
            n.add_text('Signed Transaction: ' + txid)
            n.add_custom('bitcoin.org:txid', a2b_hex(txid))          # want binary
        n.add_custom('bitcoin.org:sha256', txn_sha)
        n.add_large_object('bitcoin.org:txn', file_offset, txn_len)
        
        return await self.share_start(n)

    async def share_psbt(self, file_offset, psbt_len, psbt_sha, label=None):
        # we just signed something, share it over NFC
        if psbt_len >= MAX_NFC_SIZE:
            await ux_show_story("PSBT is too large to share via NFC")
            return

        n = ndef.ndefMaker()
        n.add_text(label or 'Partly signed PSBT')
        n.add_custom('bitcoin.org:sha256', psbt_sha)
        n.add_large_object('bitcoin.org:psbt', file_offset, psbt_len)

        return await self.share_start(n)
        
    async def share_deposit_address(self, addr):
        n = ndef.ndefMaker()
        n.add_text('Deposit Address')
        n.add_custom('bitcoin.org:addr', addr.encode())
        return await self.share_start(n)

    async def share_json(self, json_data):
        # a text file of JSON for programs to read
        n = ndef.ndefMaker()
        n.add_mime_data('application/json', json_data)

        return await self.share_start(n)

    async def share_text(self, data):
        # share text from a list of values
        # - just a text file, no multiple records; max usability!
        n = ndef.ndefMaker()
        n.add_text(data)

        return await self.share_start(n)

    async def wait_ready(self):
        # block until chip ready to continue (ACK happens)
        # - especially after any flash write, which is very slow: 5.5ms per 16byte
        while 1:
            try:
                self.i2c.readfrom_mem(I2C_ADDR_USER, 0, 0, addrsize=16)
                return
            except OSError:
                await sleep_ms(3)

    async def setup_gpio(self):
        # setup GPIO (ED) signal for detecting activity
        # - GPO1_CFG seems to be a flash cell, and takes time to write
        want = 0x1 | 0x80 | 0x04  # enable, and RF_ACTIVITY_EN | RF_WRITE_EN

        if self.read_config1(GPO1_CFG) != want:
            self.write_config1(GPO1_CFG, want)
            # not clear how much delay is needed, but need some
            await self.wait_ready()

        self.last_edge = 0
        self.write_dyn(GPO_CTRL_Dyn, 0x01)      # GPO_EN
        self.read_dyn(IT_STS_Dyn)               # clear interrupt

    async def ux_animation(self, write_mode):
        # Run the pretty animation, and detect both when we are written, and/or key to exit/abort.
        # - similar when "read" and then removed from field
        # - return T if aborted by user
        from glob import dis
        from graphics_mk4 import Graphics

        await self.wait_ready()
        self.set_rf_disable(0)
        await self.setup_gpio()

        frames = [getattr(Graphics, 'mk4_nfc_%d'%i) for i in range(1, 5)]

        aborted = True
        phase = -1
        last_activity = None

        # (ms) How long to wait after RF field comes and goes
        # - user can press OK during this period if they know they are done
        min_delay = (3000 if write_mode else 1000)

        while 1:
            phase = (phase + 1) % 4
            dis.clear()
            dis.icon(0, 8, frames[phase])
            dis.show()
            await sleep_ms(250)

            if self.last_edge:
                self.last_edge = 0

                # detect various types of RF activity, so we can clear screen automatically
                await self.wait_ready()
                try:
                    events = self.read_dyn(IT_STS_Dyn)
                except OSError:     # ENODEV
                    #print("r_dyn fail")
                    events = 0

                if events & 0x02:
                    # 0x2 = RF activity
                    last_activity = utime.ticks_ms()

            # X or OK to quit, with slightly different meanings
            ch = ux_poll_key()
            if ch and ch in 'xy': 
                aborted = (ch == 'x')
                break

            if last_activity:
                dt = utime.ticks_diff(utime.ticks_ms(), last_activity)
                if dt >= min_delay:
                    # They acheived some RF activity and then nothing for some time, so
                    # we are done w/ success.
                    aborted = False
                    break

        self.set_rf_disable(1)
        if not write_mode:
            await self.wipe(False)

        return aborted

    async def share_start(self, ndef_obj):
        # do the UX while we are sharing a value over NFC
        # - assumpting is people know what they are scanning
        # - x key to abort early, but also self-clears

        await self.big_write(ndef_obj.bytes())

        return await self.ux_animation(False)

    async def start_nfc_rx(self):
        # Pretend to be a big warm empty tag ready to be stuffed with data
        await self.big_write(ndef.CC_WR_FILE)

        # wait until something is written
        aborted = await self.ux_animation(True)
        if aborted: return

        # read CCFILE area (header)
        prob = taste = ''
        try:
            taste = self.read(0, 16)
            st, ll, _, _ = ndef.ccfile_decode(taste)
        except Exception as e:
            # robustness; need to handle all failures here
            prob = str(e)
            ll = None

        if not ll or prob:
            # they wrote nothing / failed write something we could parse
            msg = "No tag data was written?"
            if taste:
                msg += '\n\n' + B2A(taste)
            if prob:
                msg += '\n\n' + prob
            await ux_show_story(msg, title="Sorry!")
            return

        # copy to ram, wipe
        rv = self.read(st, ll)
        await self.wipe(False)
        return rv


    async def start_psbt_rx(self):
        from auth import psbt_encoding_taster, TXN_INPUT_OFFSET
        from auth import UserAuthorizedAction, ApproveTransaction
        from ux import the_ux
        from sffile import SFFile

        data = await self.start_nfc_rx()
        if not data: return

        psbt_in = None
        psbt_sha = None
        try:
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
        except Exception as e:
            # dont crash when given garbage
            import sys; sys.print_exception(e)
            pass

        if psbt_in is None:
            await ux_show_story("Could not find PSBT in what was written.", title="Sorry!")
            return

        # decode into PSRAM
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
        the_ux.push(UserAuthorizedAction.active_request)

    async def signing_done(self, psbt):
        # User approved the PSBT, and signing worked... share result over NFC (only)
        from auth import TXN_OUTPUT_OFFSET
        from version import MAX_TXN_LEN
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

    @classmethod
    async def selftest(cls):
        # check for chip present, field present .. and that it works
        n = cls()
        n.setup()
        assert n.uid

        aborted = await n.share_text("NFC is working: %s" % n.get_uid())
        assert not aborted, "Aborted"

    
    async def share_file(self):
        # Pick file from SD card and share over NFC...
        from actions import file_picker
        from files import CardSlot, CardMissingError, needs_microsd

        def is_suitable(fname):
            f = fname.lower()
            return f.endswith('.psbt') or f.endswith('.txn') or f.endswith('.txt')

        msg = "Lists PSBT, text, and TXN files on MicroSD. Select to share contents via NFC."

        while 1:
            fn = await file_picker(msg, min_size=10, max_size=MAX_NFC_SIZE, taster=is_suitable)
            if not fn: return

            basename = fn.split('/')[-1]
            ctype = fn.split('.')[-1].lower()

            try:
                with CardSlot() as card:
                    with open(fn, 'rb') as fp:
                        data = fp.read(MAX_NFC_SIZE)

            except CardMissingError:
                await needs_microsd()
                return

            if data[2:6] == b'000000' and ctype == 'txn':
                # it's a txn, and we wrote as hex
                data = a2b_hex(data)

            if ctype == 'psbt':
                sha = ngu.hash.sha256s(data)
                await self.share_psbt(data, len(data), sha, label="PSBT file: " + basename)
            elif ctype == 'txn':
                sha = ngu.hash.sha256s(data)
                txid = basename[0:64]
                if len(txid) != 64:
                    # maybe some other txn file?
                    txid = None
                await self.share_signed_txn(txid, data, len(data), sha)
            elif ctype == 'txt':
                await self.share_text(data.decode())
            else:
                raise ValueError(ctype)

    async def import_ephemeral_seed_words_nfc(self, *a):
        data = await self.start_nfc_rx()
        if not data: return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode().strip()        # from memory view
            split_msg = msg.split(" ")
            if len(split_msg) in (12, 18, 24):
                winner = split_msg
                break

        if not winner:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        try:
            from seed import set_ephemeral_seed_words
            await set_ephemeral_seed_words(winner)
        except Exception as e:
            #import sys; sys.print_exception(e)
            await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

    async def confirm_share_loop(self, string):
        while True:
            # added loop here as NFC send can fail, or not send the data
            # and in that case one would have to start from beginning (send us cmd, approve, etc.)
            # => get chance to check if you received the data and if something went wrong - retry just send
            await self.share_text(string)
            ch = await ux_show_story(title="Shared", msg="Press OK to share again, otherwise X to stop.")
            if ch != "y":
                break

    async def address_show_and_share(self):
        from auth import show_address, ApproveMessageSign

        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode()  # from memory view
            split_msg = msg.split("\n")
            if 1 <= len(split_msg) <= 2:
                winner = split_msg
                break

        if not winner:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        if len(winner) == 1:
            subpath = winner[0]
            addr_fmt = AF_CLASSIC
        else:
            subpath, addr_fmt_str = winner
            try:
                addr_fmt = parse_addr_fmt_str(addr_fmt_str)
            except AssertionError as e:
                await ux_show_story(str(e))
                return

        active_request = show_address(addr_fmt, subpath, restore_menu=True)
        from ux import the_ux
        the_ux.push(active_request)
        await the_ux.interact()  # need this otherwise NFC animation takes over

    async def start_msg_sign(self):
        from auth import UserAuthorizedAction, ApproveMessageSign
        from ux import the_ux

        UserAuthorizedAction.cleanup()

        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode()  # from memory view
            split_msg = msg.split("\n")
            if 1 <= len(split_msg) <= 3:
                winner = split_msg
                break

        if not winner:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        if len(winner) == 1:
            text = winner[0]
            subpath = "m"
            addr_fmt = AF_CLASSIC
        elif len(winner) == 2:
            text, subpath = winner
            addr_fmt = AF_CLASSIC  # maybe default to native segwit?
        else:
            # len(winner) == 3
            text, subpath, addr_fmt = winner

        UserAuthorizedAction.check_busy(ApproveMessageSign)
        try:
            UserAuthorizedAction.active_request = ApproveMessageSign(
                text, subpath, addr_fmt, approved_cb=self.msg_sign_done
            )
            the_ux.push(UserAuthorizedAction.active_request)
        except AssertionError as exc:
            await ux_show_story("Problem: %s\n\nMessage to be signed must be a single line of ASCII text." % exc)
            return

    async def msg_sign_done(self, signature, address, text):
        from auth import rfc_signature_template_gen

        sig = b2a_base64(signature).decode('ascii').strip()
        armored_str = "".join(rfc_signature_template_gen(addr=address, msg=text, sig=sig))
        await self.confirm_share_loop(armored_str)

    async def verify_sig_nfc(self):
        from auth import verify_armored_signed_msg

        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode()  # from memory view
            if "SIGNED MESSAGE" in msg:
                winner = msg.strip()
                break

        await verify_armored_signed_msg(winner, digest_check=False)

    async def read_extended_private_key(self):
        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode()  # from memory view
            if "prv" in msg:
                winner = msg.strip()
                break

        if not winner:
            await ux_show_story('Unable to find extended private key in NDEF data')
            return

        return winner

    async def read_tapsigner_b64_backup(self):
        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode()  # from memory view
            try:
                if 150 <= len(msg) <= 280:
                    winner = a2b_base64(msg)
                    break
            except:
                pass

        if not winner:
            await ux_show_story('Unable to find base64 encoded TAPSIGNER backup in NDEF data')
            return

        return winner


    async def read_bsms_token(self):
        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode().strip()  # from memory view
            try:
                int(msg, 16)
                winner = msg
                break
            except: pass

        if not winner:
            await ux_show_story('Unable to find BSMS token in NDEF data')
            return

        return winner

    async def read_bsms_data(self):
        data = await self.start_nfc_rx()
        if not data:
            await ux_show_story('Unable to find data expected in NDEF')
            return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg).decode().strip()  # from memory view
            try:
                if "BSMS" in msg:
                    # unencrypted case
                    winner = msg
                    break
                elif int(msg[:6], 16):
                    # encrypted hex case
                    winner = msg
                    break
                else:
                    continue
            except: pass

        if not winner:
            await ux_show_story('Unable to find BSMS data in NDEF data')
            return

        return winner

    async def import_miniscript_nfc(self, legacy_multisig=False):
        data = await self.start_nfc_rx()
        if not data: return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            if len(msg) < 70: continue
            msg = bytes(msg).decode()        # from memory view
            if 'pub' in msg:
                winner = msg
                break

        if not winner:
            await ux_show_story('Unable to find miniscript descriptor expected in NDEF')
            return

        from auth import maybe_enroll_xpub
        try:
            maybe_enroll_xpub(config=winner, miniscript=not legacy_multisig)
        except Exception as e:
            await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

# EOF
