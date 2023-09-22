# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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
# - you cannot move data between slots because AES-CTR with CTR seed based on slot #
# - SHA-256 check on decrypted data
# - (Mk4) each slot is a file on /flash/settings 
#
import os, ujson, ustruct, ckcc, gc, ngu, aes256ctr
from uhashlib import sha256
from random import randbelow
from utils import call_later_ms
from version import mk_num, is_devmode

# TODO fs.sync

# Setting values:
#   xfp = master xpub's fingerprint (32 bit unsigned)
#   xpub = master xpub in base58
#   chain = 3-letter codename for chain we are working on (BTC)
#   words = {0/12/18/24} nummber of BIP-39 seed words exist (default: 24, 0=XPRV, etc)
#   b39skip = (bool) skip discussion about use of BIP-39 passphrase
#   idle_to = idle timeout period (seconds)
#   _age = internal verison number for data (see below)
#   tested = selftest has been completed successfully
#   multisig = list of defined multisig wallets (complex)
#   pms = trust/import/distrust xpubs found in PSBT files
#   axi = index of last selected address in explorer
#   lgto = (minutes) how long to wait for Login Countdown feature [pre v4.0.2]
#   usr = (dict) map from username to their secret, as base32
#   ovc = (list) "outpoint value cache"; only for segwit UTXO inputs (see history.py)
#   del = (int) 0=normal 1=overwrite+delete input PSBT's, rename outputs
#   axskip = (bool) skip warning about addr explorer
#   du = (bool) if set, disable the USB port at all times
#   rz = (int) display value resolution/units: 8=BTC 5=mBTC 2=bits 0=sats
#   tp = (complex) trick pins' config on Mk4
#   nfc = (bool) if set, enable the NFC feature; default is OFF=>DISABLED (mk4+)
#   vdsk = (bool) if set, enable the Virtual Disk features in pre 5.0.6 version; [OBSOLETE]
#   vidsk = (bool) if set, enable the Virtual Disk features after v5.0.6
#   emu = (bool) if set, enables the USB Keyboard emulation (BIP-85 password entry)
#   wa = (bool) if set, enables menu wraparound
#   hsmcmd = (bool) if set, enables all user management and hsm-only USB commands
#   sd2fa = (list of strings): track which SD card is needed for login
#   bkpw = (string): last backup password, so can be re-used easily
#   sighshchk = (bool) set if sighash checks are disabled

# Stored w/ key=00 for access before login
#   _skip_pin = hard code a PIN value (dangerous, only for debug)
#   nick = optional nickname for this coldcard (personalization)
#   rngk = randomize keypad for PIN entry
#   lgto = (minutes) how long to wait for Login Countdown feature [in v4.0.2+]
#   cd_lgto = [<=mk3] minutes to show in countdown (in countdown-to-brick mode)
#   cd_mode = [<=mk3] set to enable some less-destructive modes
#   cd_pin = [<=mk3] pin code which enables "countdown to brick" mode
#   kbtn =  (1 char) '1'-'9' that will wipe seed during login process (mk4+)
#   terms_ok = customer has signed-off on the terms of sale

# settings linked to seed
# LINKED_SETTINGS = ["multisig", "tp", "ovc", "xfp", "xpub", "words"]
# settings that does not make sense to copy to ephemeral secret
# LINKED_SETTINGS += ["sd2fa", "usr", "axi", "hsmcmd"]
# prelogin settings - do not need to be part of other saved settings
# PRELOGIN_SETTINGS = ["_skip_pin", "nick", "rngk", "lgto", "kbtn", "terms_ok"]
# settings that need to be copied to any newly loaded settings as they describe state as is (a.k.a current state)
KEEP_SETTINGS = ["du", "nfc", "vidsk"]
# keep these settings only if unspecified on the other end
KEEP_IF_BLANK_SETTINGS = ["bkpw", "wa", "sighshchk", "emu", "rz",
                          "axskip", "del", "pms", "idle_to", "b39skip"]


NUM_SLOTS = const(100)
SLOTS = range(NUM_SLOTS)
MK4_WORKDIR = '/flash/settings/'


# for mk4: we store binary files on LFS2 filesystem
def MK4_FILENAME(slot):
    return MK4_WORKDIR + ('%03x.aes' % slot)


class SettingsObject:

    def __init__(self, dis=None):
        self.is_dirty = 0
        self.my_pos = None

        self.nvram_key = b'\0'*32
        self.capacity = 0
        self.current = self.default_values()

        self.load(dis)

    def get_aes(self, pos):
        # Build AES object for en/decrypt of specific block.
        # Include the slot number as part of the initial counter (CTR)
        ctr = ustruct.pack('<4I', 4, 3, 2, pos)
        return aes256ctr.new(self.nvram_key, ctr)

    def set_key(self, new_secret=None):
        # System settings (not secrets) are stored in flash, encrypted with this
        # key that is derived from main wallet secret. Call this method when the secret
        # is first loaded, or changes for some reason.
        from pincodes import pa
        from stash import blank_object, SensitiveValues

        key = None
        mine = False

        if not new_secret:
            if not pa.is_successful() or pa.is_secret_blank():
                # simple fixed key allows us to store a few things when logged out
                key = bytes(32)
            else:
                # read secret and use it.
                new_secret = pa.fetch()
                mine = True
                SensitiveValues.cache_secret(new_secret)

        if new_secret:
            # hash up the secret... without decoding it or similar
            assert len(new_secret) >= 32
            
            s = sha256(new_secret)

            for round in range(5):
                s.update('pad')
            
                s = sha256(s.digest())

            key = s.digest()

            if mine:
                blank_object(new_secret)

        # for restore from backup case, or when changing (created) the seed
        self.nvram_key = key

    def get_capacity(self):
        # could use whole filesystem, so use that as imprecise proxy
        _, _, blocks, bfree, *_ = os.statvfs(MK4_WORKDIR)

        return (blocks-bfree) / blocks
            

    def _open_file(self, pos, mode='rb'):
        return open(MK4_FILENAME(pos), mode)

    def _slot_is_blank(self, pos, buf):
        # read a few bytes from start of slot
        try:
            with self._open_file(pos) as fd:
                fd.readinto(buf)
            return False
        except:
            return True

    def _wipe_slot(self, pos):
        # blank out a slot
        fn = MK4_FILENAME(pos)
        try:
            os.remove(fn)
        except:
            # Error (ENOENT) expected here when saving first time, because the
            # "old" slot was not in use
            pass

    def _deny_slot(self, pos):
        # write garbage to look legit in a slot
        with self._open_file(pos, 'wb') as fd:
            for i in range(0, 4096, 256):
                h = ngu.random.bytes(256)
                fd.write(h)

    def _read_slot(self, pos, decryptor):
        # Mk4 is just reading a binary file and decrypt as we go.
        with self._open_file(pos) as fd:
            # missing ftell(), so emulate
            ln = fd.seek(0, 2)
            fd.seek(0, 0)

            buf = fd.read(ln - 32)
            assert len(buf) == ln-32

            rv = decryptor(buf)
            digest = ngu.hash.sha256s(rv)

            expect = decryptor(fd.read(32))
            assert len(expect) == 32

            return rv, expect, digest

    def _write_slot(self, pos, aes):
        # SHA-256 over plaintext
        chk = sha256()

        # serialize the data into JSON
        d = ujson.dumps(self.current)

        with self._open_file(pos, 'wb') as fd:
            # pad w/ zeros at least to 4k, but allow larger
            dat_len = len(d)
            pad_len = (4096-32) - dat_len

            fd.write(aes(d))
            assert fd.tell() == dat_len
            chk.update(d)
            del d

            while pad_len > 0:
                here = min(32, pad_len)

                pad = bytes(here)
                fd.write(aes(pad))
                chk.update(pad)

                pad_len -= here

            fd.write(aes(chk.digest()))

    def _used_slots(self):
        # mk4: faster list of slots in use; doesn't open them
        files = os.listdir(MK4_WORKDIR)
        return [int(fn[0:-4], 16) for fn in files if fn.endswith('.aes')]

    def _nonempty_slots(self, dis=None):
        # generate slots that are non-empty
        taste = bytearray(4)
        # use directory listing
        files = self._used_slots()
        self.num_empty = NUM_SLOTS - len(files)

        for i, pos in enumerate(files):
            if dis:
                dis.progress_bar_show(i / len(files))

            if self._slot_is_blank(pos, taste):
                # unlikely case, but easy to handle
                continue

            yield pos, taste

    def load(self, dis=None):
        # Search all slots for any we can read, decrypt that,
        # and pick the newest one (in unlikely case of dups)
        # reset
        self.current.clear()
        self.my_pos = None
        self.is_dirty = 0
        self.capacity = 0
        nonempty = set()

        for pos, taste in self._nonempty_slots(dis):
            # check if first 2 bytes makes sense for JSON
            aes = self.get_aes(pos)
            chk = aes.copy().cipher(b'{"')
            nonempty.add(pos)

            if chk != taste[0:2]:
                # doesn't look like JSON meant for me
                continue

            # probably good, read it
            aes = aes.cipher
            json_data, expect, actual = self._read_slot(pos, aes)
            try:
                # verify checksum in last 32 bytes
                assert expect == actual

                d = ujson.loads(json_data)
            except:
                # Good chance to come here w/ garbage decoded, so not an error.
                continue

            got_age = d.get('_age', 0)
            if got_age > self.current.get('_age', -1):
                # likely winner
                self.current = d
                self.my_pos = pos
            else:
                # stale data seen; clean it up.
                assert self.current['_age'] > 0
                self._wipe_slot(pos)

        # 4k is a large object, sigh, for us right now. cleanup
        gc.collect()

        # done, if we found something
        if self.my_pos is not None:
            return

        # nothing found, use defaults
        self.current = self.default_values()

        # pick a (new) random home
        self.my_pos = self.find_spot(-1)

        if is_devmode:
            self.current['chain'] = 'XTN'

    def get(self, kn, default=None):
        return self.current.get(kn, default)

    def changed(self):
        self.is_dirty += 1
        if self.is_dirty < 2:
            call_later_ms(250, self.write_out)

    def save_if_dirty(self):
        # call when system is about to stop
        if self.is_dirty:
            self.save()

    def put(self, kn, v):
        self.current[kn] = v
        self.changed()

    set = put

    def remove_key(self, kn):
        self.current.pop(kn, None)
        self.changed()

    def merge_previous_active(self, previous):
        for k in KEEP_SETTINGS:
            if k not in previous:
                self.current.pop(k, None)
            else:
                self.current[k] = previous[k]

        for k in KEEP_IF_BLANK_SETTINGS:
            if previous.get(k, None) and not self.current.get(k, None):
                self.current[k] = previous[k]

        self.changed()

    def clear(self):
        # could be just:
        #       self.current = {}
        # but accommodating the simulator here
        rk = [k for k in self.current if k[0] != '_']
        for k in rk:
            del self.current[k]

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
        except MemoryError:
            call_later_ms(250, self.write_out)

    def find_spot(self, not_here=0):
        # search for a blank sector to use
        # - check randomly and pick first blank one (wear leveling, deniability)
        # - we will write and then erase old slot
        # - if "full", blow away a random one
        # on mk4, use the filesystem to see what's already taken
        avail = set(SLOTS) - set(self._used_slots())
        avail.discard(not_here)

        if avail:
            return avail.pop()

        # TODO destructive
        victim = randbelow(NUM_SLOTS)
        self._wipe_slot(victim)

        return victim

    def save(self):
        # render as JSON, encrypt and write it.
        self.current['_age'] = self.current.get('_age', 1) + 1
        pos = self.find_spot(self.my_pos)

        aes = self.get_aes(pos).cipher

        self._write_slot(pos, aes)

        # erase old copy of data
        if (self.my_pos is not None) and (self.my_pos != pos):
            self._wipe_slot(self.my_pos)

        self.my_pos = pos
        self.is_dirty = 0

    def blank(self):
        # erase current copy of values in nvram; older ones may exist still
        # - use when clearing the seed value
        if self.my_pos is not None:
            self._wipe_slot(self.my_pos)
            self.my_pos = 0

        # act blank too, just in case.
        self.current.clear()
        self.is_dirty = 0
        self.capacity = 0

    @staticmethod
    def default_values():
        # Please try to avoid defaults here... It's better to put into code
        # where value is used, and treat undefined as the default state.
        return dict(_age=0)

# EOF
