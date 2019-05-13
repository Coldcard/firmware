# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# nvstore.py - manage a few key values that aren't super secrets
#
# Goals:
# - handle multiple wallets in same memory that don't know each other
# - some deniability
# - recover from empty/blank/failed chips w/o user action
#
# Result:
# - up to 4k of values supported (after json encoding)
# - encrypted and stored in SPI flash, in last 128k area
# - AES encryption key is derived from actual wallet secret
# - if logged out, then use fixed key instead (ie. it's public)
# - to support multiple wallets and plausible deniablity, we 
#   will preserve any noise already there, and only replace our own stuff
# - you cannot move data between slots because AES-CTR with CTR seed based on slot #
# - SHA check on decrypted data
#
import os, ujson, tcc, ustruct, ckcc, gc
from uasyncio import sleep_ms
from uio import BytesIO
from sffile import SFFile

# Setting values:
#   xfp = master xpub's fingerprint (32 bit unsigned)
#   xpub = master xpub in base58
#   chain = 3-letter codename for chain we are working on (BTC)
#   words = (bool) BIP39 seed words exist (else XPRV or master secret based)
#   b39skip = (bool) skip discussion about use of BIP39 passphrase
#   idle_to = idle timeout period (seconds)
#   _age = internal verison number for data (see below)
#   _skip_pin = hard code a PIN value (dangerous, only for debug)
#   terms_ok = customer has signed-off on the terms of sale
#   tested = selftest has been completed successfully
#   multisig = list of defined multisig wallets (complex)
#


# where in SPI Flash we work (last 128k)
SLOTS = range((1024-128)*1024, 1024*1024, 4096)

# Altho seems bad to statically alloc this big block, it solves
# concerns with heap fragmentation, and saving settings is clearly
# core to our mission!
# 4k, but last 32 bytes are a SHA (itself encrypted)
#_tmp = bytearray(4096-32)
from sram2 import nvstore_buf
_tmp = nvstore_buf

class SettingsObject:

    def __init__(self, loop=None):
        self.loop = loop
        self.is_dirty = 0
        self.my_pos = 0

        self.nvram_key = b'\0'*32
        self.current = self.default_values()
        self.overrides = {}     # volatile overide values

        self.load()

    def get_aes(self, mode,  pos):
        # Build AES key for en/decrypt of specific block.
        # Include the slot number as part of the initial counter (CTR)
        return tcc.AES(tcc.AES.CTR | mode, self.nvram_key, ustruct.pack('<4I', 4, 3, 2, pos))

    def set_key(self, new_secret=None):
        # System settings (not secrets) are stored in SPI Flash, encrypted with this
        # key that is derived from main wallet secret. Call this method when the secret
        # is first loaded, or changes for some reason.
        from main import pa
        from stash import blank_object

        key = None
        mine = False

        if not new_secret:
            if not pa.is_successful() or pa.is_secret_blank():
                # simple fixed key allows us to store a few things when logged out
                key = b'\0'*32
            else:
                # read secret and use it.
                new_secret = pa.fetch()
                mine = True

        if new_secret:
            # hash up the secret... without decoding it or similar
            assert len(new_secret) >= 32
            
            s = tcc.sha256(new_secret)

            for round in range(5):
                s.update('pad')
            
                s = tcc.sha256(s.digest())

            key = s.digest()

            if mine:
                blank_object(new_secret)

        # for restore from backup case, or when changing (created) the seed
        self.nvram_key = key

    def load(self):
        # Search all slots for any we can read, decrypt that,
        # and pick the newest one (in unlikely case of dups)
        from main import sf

        # reset
        self.current.clear()
        self.overrides.clear()
        self.my_pos = 0
        self.is_dirty = 0

        # 4k, but last 32 bytes are a SHA (itself encrypted)
        global _tmp

        buf = bytearray(4)
        empty = 0
        for pos in SLOTS:
            gc.collect()

            sf.read(pos, buf)
            if buf[0] == buf[1] == buf[2] == buf[3] == 0xff:
                # erased (probably)
                empty += 1
                continue

            # check if first 2 bytes makes sense for JSON
            aes = self.get_aes(tcc.AES.Encrypt, pos)
            chk = aes.update(b'{"')

            if chk != buf[0:2]:
                # doesn't look like JSON meant for me
                continue

            # probably good, read it
            aes = self.get_aes(tcc.AES.Encrypt, pos)

            chk = tcc.sha256()
            expect = None

            with SFFile(pos, length=4096, pre_erased=True) as fd:
                for i in range(4096/32):        
                    b = aes.update(fd.read(32))
                    if i != 127:
                        _tmp[i*32:(i*32)+32] = b
                        chk.update(b)
                    else:
                        expect = b

            try:
                # verify checksum in last 32 bytes
                assert expect == chk.digest()

                # loads() can't work from a byte array, and converting to 
                # bytes here would copy it; better to use file emulation.
                d = ujson.load(BytesIO(_tmp))
            except:
                # One in 65k or so chance to come here w/ garbage decoded, so
                # not an error.
                continue

            got_age = d.get('_age', 0)
            if got_age > self.current.get('_age', -1):
                # likely winner
                self.current = d
                self.my_pos = pos
                #print("NV: data @ %d w/ age=%d" % (pos, got_age))
            else:
                # stale data seen; clean it up.
                assert self.current['_age'] > 0
                print("NV: cleanup @ %d" % pos)
                sf.sector_erase(pos)
                sf.wait_done()

        # 4k is a large object, sigh, for us right now. cleanup
        gc.collect()

        # done, if we found something
        if self.my_pos:
            return 

        # nothing found.
        self.my_pos = 0
        self.current = self.default_values()

        if empty == len(SLOTS):
            # Whole thing is blank. Bad for plausible deniability. Write 3 slots
            # with garbage. They will be wasted space until it fills.
            blks = list(SLOTS)
            tcc.random.shuffle(blks)

            for pos in blks[0:3]:
                for i in range(0, 4096, 256):
                    h = tcc.random.bytes(256)
                    sf.wait_done()
                    sf.write(pos+i, h)

    def get(self, kn, default=None):
        if kn in self.overrides:
            return self.overrides.get(kn)
        else:
            return self.current.get(kn, default)

    def changed(self):
        self.is_dirty += 1
        if self.is_dirty < 2 and self.loop:
            self.loop.call_later_ms(250, self.write_out())

    def put(self, kn, v):
        self.current[kn] = v
        self.changed()

    def put_volatile(self, kn, v):
        self.overrides[kn] = v

    set = put

    def clear(self):
        # could be just:
        #       self.current = {}
        # but accomidating the simulator here
        rk = [k for k in self.current if k[0] != '_']
        for k in rk:
            del self.current[k]
            
        self.overrides.clear()
        self.changed()
        
    async def write_out(self):
        # delayed write handler
        if not self.is_dirty:
            # someone beat me to it
            return

        # Was sometimes running low on memory in this area: recover
        try:
            gc.collect()
            self.save()
            #print("settings committed")
        except MemoryError:
            print("write_out retry")
            self.loop.call_later_ms(250, self.write_out())

    def find_spot(self, not_here=0):
        # search for a blank sector to use 
        # - check randomly and pick first blank one (wear leveling, deniability)
        # - we will write and then erase old slot
        # - if "full", blow away a random one
        from main import sf

        options = [s for s in SLOTS if s != not_here]
        tcc.random.shuffle(options)

        buf = bytearray(16)
        for pos in options:
            sf.read(pos, buf)
            if set(buf) == {0xff}:
                # blank
                return sf, pos

        # No where to write! (probably a bug because we have lots of slots)
        # ... so pick a random slot and kill what it had
        #print("ERROR: nvram full?")

        victem = options[0]
        sf.sector_erase(victem)
        sf.wait_done()

        return sf, victem

    def save(self):
        # render as JSON, encrypt and write it.

        self.current['_age'] = self.current.get('_age', 1) + 1

        sf, pos = self.find_spot(self.my_pos)

        aes = self.get_aes(tcc.AES.Encrypt, pos)

        with SFFile(pos, max_size=4096, pre_erased=True) as fd:
            chk = tcc.sha256()

            # first the json data
            d = ujson.dumps(self.current)

            # pad w/ zeros
            pad_len = (4096-32) - len(d)
            assert pad_len >= 0, 'too big'

            fd.write(aes.update(d))
            chk.update(d)
            del d

            while pad_len > 0:
                here = min(32, pad_len)

                pad = bytes(here)
                fd.write(aes.update(pad))
                chk.update(pad)

                pad_len -= here
        
            fd.write(aes.update(chk.digest()))
            assert fd.tell() == 4096

        # erase old copy of data
        if self.my_pos and self.my_pos != pos:
            sf.wait_done()
            sf.sector_erase(self.my_pos)
            sf.wait_done()

        self.my_pos = pos
        self.is_dirty = 0
        #print("NV: wrote @ %d" % pos)

    def merge(self, prev):
        # take a dict of previous values and merge them into what we have
        self.current.update(prev)

    def blank(self):
        # erase current copy of values in nvram; older ones may exist still
        # - use when clearing the seed value
        from main import sf

        if self.my_pos:
            sf.wait_done()
            sf.sector_erase(self.my_pos)
            self.my_pos = 0

        # act blank too, just in case.
        self.current.clear()
        self.overrides.clear()
        self.is_dirty = 0

    @staticmethod
    def default_values():
        # Please try to avoid defaults here... It's better to put into code
        # where value is used, and treat undefined as the default state.

        if ckcc.is_simulator():
            from sim_settings import sim_defaults
            return dict(sim_defaults)
        
        return dict(_age=0)

# EOF
