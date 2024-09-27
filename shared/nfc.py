# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# nfc.py -- Add some NFC tag-like features to Mk4
#
# - using ST ST25DV64KC
# - on it's own I2C bus (not shared)
# - has GPIO signal "??" which is multipurpose on its own pin
# - this chip chosen because it can disable RF interaction
#
import utime, ngu, ndef, stash, chains
from uasyncio import sleep_ms
import uasyncio as asyncio
from ustruct import pack, unpack
from ubinascii import unhexlify as a2b_hex
from ubinascii import b2a_base64, a2b_base64

from ux import ux_show_story, ux_wait_keydown, OK, X
from utils import B2A, problem_file_line, txid_from_fname
from public_constants import AF_CLASSIC
from charcodes import KEY_ENTER, KEY_CANCEL

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

        try:
            # Q1 and maybe later Mk4's have a light
            self.active_led = Pin('NFC_ACTIVE', mode=Pin.OUT, value=0)
        except ValueError:
            self.active_led = lambda n: None

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
        # set light to match state
        self.active_led(not val)

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

    async def share_push_tx(self, url, txid, txn, txn_sha, line2=None):
        # Given a signed TXN, we convert to URL which a web backend can broadcast directly
        # - using base64url encoding
        # - just appends to provided URL
        # - keeps showing it until they press CANCEL
        # - may fail late if txn is too big.. not clear what limit is
        #
        from utils import b2a_base64url
        from chains import current_chain

        is_https = url.startswith('https://')
        if is_https:
            url = url[8:]

        url += 't=' + b2a_base64url(txn) + '&c=' + b2a_base64url(txn_sha[-8:])

        ch = current_chain()
        if ch.ctype != 'BTC':
            url += '&n=' + ch.ctype         # XTN or XRT

        if len(url) >= MAX_NFC_SIZE:
            # ignoring overhead, this will not fit: so fail
            raise ValueError("too big")

        n = ndef.ndefMaker()
        n.add_url(url, https=is_https)

        if line2 is None:
            line2 = "Signed TXID: %s⋯%s" % (txid[0:8], txid[-8:])

        while 1:
            done = await self.share_start(n, prompt="Tap to broadcast, CANCEL when done", 
                                                line2=line2)

            if done: break

    async def share_2fa_link(self, wallet_name, shared_secret):
        #
        # Share complex NFC deeplink into 2fa backend; returns expected code to prompt for
        #
        from utils import b2a_base64url, url_encode
        from version import has_qr

        prefix = 'coldcard.com/2fa?'

        # random nonce: if we get this back, then server approves of TOTP answer
        if has_qr:
            # data for a QR
            nonce = a2b_hex(ngu.random.bytes(32)).upper()
        else:
            # 8 digits
            nonce = str(ngu.random.uniform(1_0000_0000))

        qs = 'g=%s&ss=%s%nm=%sq=%d' % (nonce, shared_secret, url_encode(wallet_name), has_qr)

        # TODO: encryption and base64 here

        n = ndef.ndefMaker()
        n.add_url(prefix + qs, https=True)

        aborted = await self.share_start(n, prompt="Tap for 2FA Authentication",
                                                line2="Wallet: " + wallet_name)

        return None if aborted else nonce

    async def push_tx_from_file(self):
        # Pick (signed txn) file from SD card and broadcast via PushTx
        # - assumes .txn extension (required)
        # - hex encoding or binary
        # - txid is filename, if 64 chars long; else shown on-screen
        # - assumes txn on same chain as this CC is; ie. not testnet typically
        from actions import file_picker
        from files import CardSlot, CardMissingError, needs_microsd
        from glob import settings

        def is_suitable(fname):
            return fname.lower().endswith('.txn')

        url = settings.get('ptxurl', False)
        assert url      # or else not in menu, cant get here.

        while 1:
            fn = await file_picker(min_size=10, max_size=MAX_NFC_SIZE*2, taster=is_suitable)
            if not fn: return

            basename = fn.split('/')[-1]

            try:
                with CardSlot() as card:
                    with open(fn, 'rb') as fp:
                        data = fp.read(MAX_NFC_SIZE*2).strip()  # newlines and carriage returns
                        assert len(data) < MAX_NFC_SIZE*2, "bad read"
            except CardMissingError:
                await needs_microsd()
                return
            except Exception as e:
                await ux_show_story(
                    title="ERROR",
                    msg='Read failed!\n\n%s\n%s' % (e, problem_file_line(e))
                )
                return

            # maybe decode
            # targeting last three zero bytes of tx version
            if data[2:8] == b'000000':
                # it's a txn, and we wrote as hex
                data = a2b_hex(data)
            elif data[1:4] == bytes(3):
                # looks like binary
                pass
            else:
                raise ValueError("Doesn't look like txn?")

            sha = ngu.hash.sha256s(data)

            txid = txid_from_fname(basename)
            line2 = None
            if not txid:
                # assume a r random filename, and not easy to recalc txid here
                # so show filename instead
                line2 = 'File: ' + basename
                if len(line2) > 34:      # CHARS_W
                    line2 = line2[:32]+'⋯'      # 34-2=32 => because double-width char

            await self.share_push_tx(url, txid, data, sha, line2=line2)

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
        
    async def share_deposit_address(self, addr, **kws):
        n = ndef.ndefMaker()
        n.add_text('Deposit Address')
        n.add_custom('bitcoin.org:addr', addr.encode())
        return await self.share_start(n, **kws)

    async def share_json(self, json_data, **kws):
        # a text file of JSON for programs to read
        n = ndef.ndefMaker()
        n.add_mime_data('application/json', json_data)

        return await self.share_start(n, **kws)

    async def share_text(self, data, **kws):
        # share text from a list of values
        # - just a text file, no multiple records; max usability!
        n = ndef.ndefMaker()
        n.add_text(data)

        return await self.share_start(n, **kws)

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

    async def ux_animation(self, write_mode, allow_enter=True, prompt=None, line2=None):
        # Run the pretty animation, and detect both when we are written, and/or key to exit/abort.
        # - similar when "read" and then removed from field
        # - return T if aborted by user
        from glob import dis, numpad

        await self.wait_ready()
        self.set_rf_disable(0)
        await self.setup_gpio()

        if dis.has_lcd:
            dis.real_clear()        # bugfix
            dis.text(None, -2, prompt or 'Tap phone to screen, or CANCEL.', dark=True)
            if line2:
                dis.text(None, -3, line2)
        else:
            from graphics_mk4 import Graphics
            frames = [getattr(Graphics, 'mk4_nfc_%d'%i) for i in range(1, 5)]

        aborted = True
        phase = -1
        last_activity = None

        # (ms) How long to wait after RF field comes and goes
        # - user can press OK during this period if they know they are done
        min_delay = (3000 if write_mode else 1000)

        while 1:
            if dis.has_lcd:
                phase = (phase + 1) % 2
                dis.image(None, 59, 'nfc_%d' % phase)
            else:
                dis.clear()
                phase = (phase + 1) % 4
                dis.icon(0, 8, frames[phase])
                dis.show()

            # wait for key or 250ms animation delay
            ch = await ux_wait_keydown(KEY_ENTER+KEY_CANCEL+'xy', 250)

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

            # X or OK to quit, but with slightly different meanings
            if ch:
                if ch in 'x'+KEY_CANCEL:
                    aborted = True
                    break
                elif allow_enter and ch in 'y'+KEY_ENTER:
                    aborted = False
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

    async def share_start(self, ndef_obj, **kws):
        # do the UX while we are sharing a value over NFC
        # - assumpting is people know what they are scanning
        # - x key to abort early, but also self-clears

        await self.big_write(ndef_obj.bytes())

        return await self.ux_animation(False, **kws)

    async def start_nfc_rx(self, **kws):
        # Pretend to be a big warm empty tag ready to be stuffed with data
        await self.big_write(ndef.CC_WR_FILE)

        # wait until something is written
        aborted = await self.ux_animation(True, **kws)
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
        from auth import TXN_OUTPUT_OFFSET, try_push_tx
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

            self.result = (fd.tell(), fd.checksum.digest())

        out_len, out_sha = self.result

        if is_comp:
            if txid and await try_push_tx(out_len, txid, out_sha):
                return  # success, exit

            await self.share_signed_txn(txid, TXN_OUTPUT_OFFSET, out_len, out_sha)
        else:
            await self.share_psbt(TXN_OUTPUT_OFFSET, out_len, out_sha)

        # ? show txid on screen ?
        # thank them?

    @classmethod
    async def selftest(cls):
        # Check for chip present, field present .. and that it works
        # - important: do not allow user (tester) to quit without sending anything over link
        n = cls()
        n.setup()
        assert n.uid

        aborted = await n.share_text("NFC is working: %s" % n.get_uid(), allow_enter=False)
        assert not aborted, "Aborted"

    
    async def share_file(self):
        # Pick file from SD card and share over NFC...
        from actions import file_picker
        from files import CardSlot, CardMissingError, needs_microsd

        def is_suitable(fname):
            f = fname.lower()
            return f.endswith('.psbt') or f.endswith('.txn') \
                or f.endswith('.txt') or f.endswith('.json') or f.endswith('.sig')

        while 1:
            fn = await file_picker(min_size=10, max_size=MAX_NFC_SIZE, taster=is_suitable)
            if not fn: return

            basename = fn.split('/')[-1]
            ext = fn.split('.')[-1].lower()

            try:
                with CardSlot() as card:
                    with open(fn, 'rb') as fp:
                        data = fp.read(MAX_NFC_SIZE)

            except CardMissingError:
                await needs_microsd()
                return

            if ext == 'txn':
                txid = txid_from_fname(basename)
                if data[2:8] == b'000000':
                    # it's a txn, and we wrote as hex
                    data = a2b_hex(data)
                else:
                    assert data[2:8] == bytes(6)
                sha = ngu.hash.sha256s(data)
                await self.share_signed_txn(txid, data, len(data), sha)
            elif ext == 'psbt':
                sha = ngu.hash.sha256s(data)
                await self.share_psbt(data, len(data), sha, label="PSBT file: " + basename)
            elif ext in ('txt', 'sig'):
                await self.share_text(data.decode())
            elif ext == 'json':
                await self.share_json(data.decode())
            else:
                raise ValueError(ext)

    async def import_multisig_nfc(self, *a):
        # user is pushing a file downloaded from another CC over NFC
        # - would need an NFC app in between for the sneakernet step
        # get some data
        def f(m):
            if len(m) < 70:
                return
            m = m.decode()

            # multi( catches both multi( and sortedmulti(
            if 'pub' in m or "multi(" in m:
                return m

        winner = await self._nfc_reader(f, 'Unable to find multisig descriptor.')

        if winner:
            from auth import maybe_enroll_xpub
            try:
                maybe_enroll_xpub(config=winner)
            except Exception as e:
                #import sys; sys.print_exception(e)
                await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

    async def import_ephemeral_seed_words_nfc(self, *a):
        def f(m):
            sm = m.decode().strip().split(" ")
            if len(sm) in stash.SEED_LEN_OPTS:
                return sm

        winner = await self._nfc_reader(f, 'Unable to find seed words')

        if winner:
            try:
                from seed import set_ephemeral_seed_words
                await set_ephemeral_seed_words(winner, meta='NFC Import')
            except Exception as e:
                #import sys; sys.print_exception(e)
                await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

    async def confirm_share_loop(self, string):
        while True:
            # added loop here as NFC send can fail, or not send the data
            # and in that case one would have to start from beginning (send us cmd, approve, etc.)
            # => get chance to check if you received the data and if something went wrong - retry just send
            await self.share_text(string)
            ch = await ux_show_story(title="Shared", msg="Press %s to share again, otherwise %s to stop." % (OK, X))
            if ch != "y":
                break

    async def address_show_and_share(self):
        from auth import show_address

        def f(m):
            sm = m.decode().split("\n")
            if 1 <= len(sm) <= 2:
                return sm

        winner = await self._nfc_reader(f, 'Expected address and derivation path.')

        if not winner:
            return

        if len(winner) == 1:
            subpath = winner[0]
            addr_fmt = AF_CLASSIC
        else:
            subpath, addr_fmt_str = winner
            try:
                addr_fmt = chains.parse_addr_fmt_str(addr_fmt_str)
            except AssertionError as e:
                await ux_show_story(str(e))
                return

        active_request = show_address(addr_fmt, subpath, restore_menu=True)
        from ux import the_ux
        the_ux.push(active_request)
        await the_ux.interact()  # need this otherwise NFC animation takes over

    async def start_msg_sign(self):
        from auth import approve_msg_sign

        def f(m):
            m = m.decode()
            split_msg = m.split("\n")
            if 1 <= len(split_msg) <= 3:
                return m

        winner = await self._nfc_reader(f, 'Unable to find correctly formated message to sign.')
        if not winner:
            return

        await approve_msg_sign(None, None, None, approved_cb=self.msg_sign_done,
                               msg_sign_request=winner)


    async def msg_sign_done(self, signature, address, text):
        from auth import rfc_signature_template_gen

        sig = b2a_base64(signature).decode('ascii').strip()
        armored_str = "".join(rfc_signature_template_gen(addr=address, msg=text, sig=sig))
        await self.confirm_share_loop(armored_str)

    async def verify_sig_nfc(self):
        from auth import verify_armored_signed_msg

        f = lambda x: x.decode().strip() if b"SIGNED MESSAGE" in x else None
        winner = await self._nfc_reader(f, 'Unable to find signed message.')

        if winner:
            await verify_armored_signed_msg(winner, digest_check=False)

    async def read_address(self):
        # Read an address or BIP-21 url and parse out addr (just one)
        from utils import decode_bip21_text

        def f(m):
            m = m.decode()
            what, vals = decode_bip21_text(m)
            if what == 'addr':
                return vals[1]

        winner = await self._nfc_reader(f, 'Unable to find address from NFC data.')

        return winner

    async def verify_address_nfc(self):
        # Get an address or complete bip-21 url even and search it... slow.
        winner = await self.read_address()
        if winner:
            from ownership import OWNERSHIP
            await OWNERSHIP.search_ux(winner)

    async def read_extended_private_key(self):
        f = lambda x: x.decode().strip() if b"prv" in x else None
        return await self._nfc_reader(f, 'Unable to find extended private key.')

    async def read_tapsigner_b64_backup(self):
        f = lambda x: a2b_base64(x.decode()) if 150 <= len(x) <= 280 else None
        return await self._nfc_reader(f, 'Unable to find base64 encoded TAPSIGNER backup.')

    async def _nfc_reader(self, func, fail_msg):
        data = await self.start_nfc_rx()
        if not data: return

        winner = None
        for urn, msg, meta in ndef.record_parser(data):
            msg = bytes(msg)
            try:
                r = func(msg)
                if r is not None:
                    winner = r
                    break
            except:
                pass

        if not winner:
            await ux_show_story(fail_msg)
            return

        return winner

# EOF
