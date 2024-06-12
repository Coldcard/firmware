# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ownership.py - store a cache of hashes related to addresses we might control.
#
import os, sys, chains, ngu, struct, version
from glob import settings
from ucollections import namedtuple
from ubinascii import hexlify as b2a_hex
from exceptions import UnknownAddressExplained
from public_constants import AFC_SCRIPT, AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH_P2SH, AF_P2TR

# Track many addresses, but in compressed form
# - map from random Bech32/Base58 payment address to (wallet) + keypath
# - only normal (external, not change) addresses, and won't consider
#   any keypath that does not end in 0/*
# - store only hints, since we can re-construct any address and want to fully verify
# - try to keep private between different duress wallets, and seed vaults
# - storing bulk data into LFS, not settings
# - okay to wipe, can restore anytime; with CPU cost
# - doesn't really have a gap limit concept, but limited to first N addresses in a wallet
# - cannot be used to accelerate address explorer because we don't store full addresses
# - data stored in binary, fixed-length header, then fixed-length records
# - multisig and single sig, and someday taproot, miniscript too
# - searching leaves behind a cache for next time
# - data building/saves happens when are searching, but might grab some during addr expl export?
# - performance: 1m40s for one P2PKH wallet (change, and external addresses: 1528 in all)
#

# length of hashed & truncated address record
HASH_ENC_LEN = const(2)

# File header
OwnershipFileHdr = namedtuple('OwnershipFileHdr', 'file_magic change_idx flags')
OWNERSHIP_FILE_HDR = 'HHI'
OWNERSHIP_FILE_HDR_LEN = 8

OWNERSHIP_MAGIC = 0x10A0            # "Address Ownership" v1.0
# flags: none yet, but 32 bits reserved

# target 3 flash blocks, max file size => 764 addresses
MAX_ADDRS_STORED = const(764)       # =((3*512) - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN
BONUS_GAP_LIMIT = const(20)

def encode_addr(addr, salt):
    # Convert text address to something we can store while preserving privacy.
    return ngu.hash.sha256s(salt + addr)[0:HASH_ENC_LEN]

class AddressCacheFile:

    def __init__(self, wallet, change_idx):
        self.wallet = wallet
        self.change_idx = change_idx
        desc = wallet.to_descriptor().to_string(internal=False)
        h = b2a_hex(ngu.hash.sha256d(wallet.chain.ctype + desc))
        self.fname = h[0:32] + '-%d.own' % change_idx
        self.salt = h[32:]
        self.count = 0
        self.hdr = None

        self.peek()

    def nice_name(self):
        rv = self.wallet.name
        if self.change_idx:
            rv += ' (change)'
        return rv

    def exists(self):
        return bool(self.count)

    def peek(self):
        # see what we have on-disk; just reads header.
        try:
            with open(self.fname, 'rb') as fd:
                hdr = fd.read(OWNERSHIP_FILE_HDR_LEN)
                assert len(hdr) == OWNERSHIP_FILE_HDR_LEN
                flen = fd.seek(0, 2)
            self.hdr = OwnershipFileHdr(*struct.unpack(OWNERSHIP_FILE_HDR, hdr))
            assert self.hdr.file_magic == OWNERSHIP_MAGIC
            assert self.hdr.change_idx == self.change_idx
        except OSError:
            return
        except Exception as exc:
            sys.print_exception(exc)
            self.count = 0
            self.hdr = None
            return

        self.count = (flen - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN

    def setup(self, change_idx, start_idx):
        assert self.change_idx == change_idx

        if self.count or self.hdr:
            assert start_idx == self.count, 'not an append'

            # Open for append, header should be right already
            self.fd = open(self.fname, 'ab')
        else:
            # Start new file
            assert start_idx == 0
            self.fd = open(self.fname, 'wb')
            self.hdr = OwnershipFileHdr(OWNERSHIP_MAGIC, self.change_idx, 0x0)
            hdr = struct.pack(OWNERSHIP_FILE_HDR, *self.hdr)
            self.fd.write(hdr)

    def append(self, addr):
        if addr is None:
            # close file, done
            self.fd.close()
            del self.fd
            return

        assert '_' not in addr
        self.fd.write(encode_addr(addr, self.salt))

    def fast_search(self, addr):
        # Do the easy part of the searching, using the existing file's contents.
        # - generates candidate path subcomponents; might be false positive
        # - working in-memory, since complete file isn't very large, and speed
        from glob import dis

        if not self.hdr or not self.count:
            return

        with open(self.fname, 'rb') as fd:
            fd.seek(OWNERSHIP_FILE_HDR_LEN)
            buf = fd.read(self.count * HASH_ENC_LEN)

        assert len(buf) == (self.count * HASH_ENC_LEN)

        chk = encode_addr(addr, self.salt)
        for idx in range(self.count):
            if buf[idx*HASH_ENC_LEN : (idx*HASH_ENC_LEN)+HASH_ENC_LEN] == chk:
                yield (self.change_idx, idx)

            dis.progress_sofar(idx, self.count)

    def check_match(self, want_addr, subpath):
        # need to double-check matches, to get rid of false positives.
        got = self.wallet.render_address(*subpath)
        # chg, idx = subpath
        #print('(%d, %d) => %s ?= %s' % (chg, idx, got, want_addr))
        return want_addr == got

    def build_and_search(self, addr):
        # build many more addresses
        # - return subpath for a hit or None
        from glob import dis

        bonus = 0
        match = None

        start_idx = self.count
        count = MAX_ADDRS_STORED - start_idx

        if count <= 0:
            return None

        self.setup(self.change_idx, start_idx)

        # change_idx is used as flag here
        for idx,here,*_ in self.wallet.yield_addresses(start_idx, count, self.change_idx):

            if here == addr:
                # Found it! But keep going a little for next time.
                match = (self.change_idx, idx)

            self.append(here)
            self.count += 1
            if match:
                bonus += 1

            if match and bonus >= BONUS_GAP_LIMIT:
                self.append(None)
                return match

            dis.progress_sofar(idx-start_idx, count)

        self.append(None)

        return None

class OwnershipCache:

    @classmethod
    def saver(cls, wallet, change_idx, start_idx):
        # when we are generating many addresses for export, capture them
        # as we go with this function
        # - not change -- only main addrs
        file = AddressCacheFile(wallet, change_idx)

        if file.exists():
            # don't save to existing file, has some already
            return None

        try:
            file.setup(change_idx, start_idx)
        except:
            # in some cases we don't want to save anything, not an error
            return None

        return file.append

    @classmethod
    def search(cls, addr):
        # Find it!
        # - returns wallet object, and tuple2 of final 2 subpath components
        # - if you start w/ testnet, we'll follow that
        from multisig import MultisigWallet
        from miniscript import MiniScriptWallet
        from glob import dis

        ch = chains.current_chain()

        addr_fmt = ch.possible_address_fmt(addr)
        if not addr_fmt:
            # might be valid address over on testnet vs mainnet
            nm = ch.name if ch.ctype != 'BTC' else 'Bitcoin Mainnet'
            raise UnknownAddressExplained('That address is not valid on ' + nm)

        possibles = []

        msc_exists = MiniScriptWallet.exists()[0]

        if addr_fmt == AF_P2TR and msc_exists:
            possibles.extend([w for w in MiniScriptWallet.iter_wallets() if w.addr_fmt == AF_P2TR])

        if addr_fmt & AFC_SCRIPT:
            # multisig or script at least.. must exist already
            possibles.extend(MultisigWallet.iter_wallets(addr_fmt=addr_fmt))
            msc = [w for w in MiniScriptWallet.iter_wallets() if w.addr_fmt == addr_fmt]
            possibles.extend(msc)

            if addr_fmt == AF_P2SH:
                # might look like P2SH but actually be AF_P2WSH_P2SH
                possibles.extend(MultisigWallet.iter_wallets(addr_fmt=AF_P2WSH_P2SH))
                msc = [w for w in MiniScriptWallet.iter_wallets() if w.addr_fmt == AF_P2WSH_P2SH]
                possibles.extend(msc)

                # Might be single-sig p2wpkh wrapped in p2sh ... but that was a transition
                # thing that hopefully is going away, so if they have any multisig wallets,
                # defined, assume that that's the only p2sh address source.
                addr_fmt = AF_P2WPKH_P2SH

        try:
            # Construct possible single-signer wallets, always at least account=0 case
            from wallet import MasterSingleSigWallet
            w = MasterSingleSigWallet(addr_fmt, account_idx=0)
            possibles.append(w)

            # add all account idx they have ever looked at, w/ this addr fmt (single sig)
            ex = settings.get('accts', [])
            for af, acct_num in ex:
                if af == addr_fmt and acct_num:
                    w = MasterSingleSigWallet(addr_fmt, account_idx=acct_num)
                    possibles.append(w)
        except ValueError: pass  # if not single sig address format

        if not possibles:
            # can only happen w/ scripts; for single-signer we have things to check
            raise UnknownAddressExplained(
                        "No suitable multisig/miniscript wallets are currently defined.")

        # "quick" check first, before doing any generations

        count = 0
        phase2 = []
        for change_idx in (0, 1):
            files = [AddressCacheFile(w, change_idx) for w in possibles]
            for f in files:
                if dis.has_lcd:
                    dis.fullscreen('Searching wallet(s)...', line2=f.nice_name())
                else:
                    dis.fullscreen('Searching...')

                for maybe in f.fast_search(addr):
                    ok = f.check_match(addr, maybe)
                    if not ok: continue     # false positive - will happen

                    # found winner.
                    return f.wallet, maybe

                if f.count < MAX_ADDRS_STORED:
                    phase2.append(f)

                count += f.count

        # maybe we haven't calculated all the addresses yet, so do that
        # - very slow, but only needed once; any negative (failed) search causes this
        # - could stop when match found, but we go a bit beyond that for next time
        # - we could search all in parallel, rather than serially because
        #   more likely to find a match with low index... but seen as too much memory

        for f in phase2:
            b4 = f.count
            if dis.has_lcd:
                dis.fullscreen("Generating addresses...", line2=f.nice_name())
            else:
                dis.fullscreen("Generating...")

            result = f.build_and_search(addr)
            if result:
                # found it, so report it and stop
                return f.wallet, result

            count += f.count - b4

        # possible phase 3: other seedvault... slow, rare and not implemented

        raise UnknownAddressExplained('Searched %d candidates without finding a match.' % count)

    @classmethod
    async def search_ux(cls, addr):
        # Provide a simple UX. Called functions do fullscreen, progress bar stuff.
        from ux import ux_show_story, show_qr_code
        from charcodes import KEY_QR
        from public_constants import AFC_BECH32, AFC_BECH32M

        try:
            wallet, subpath = OWNERSHIP.search(addr)

            msg = addr
            msg += '\n\nFound in wallet:\n  ' + wallet.name
            if hasattr(wallet, "render_path"):
                msg += '\nDerivation path:\n  ' + wallet.render_path(*subpath)
            if version.has_qwerty:
                esc = KEY_QR
            else:
                msg += '\n\nPress (1) for QR'
                esc = '1'

            while 1:
                ch = await ux_show_story(msg, title="Verified Address",
                                                        escape=esc, hint_icons=KEY_QR)
                if ch != esc: break
                await show_qr_code(addr,
                                   is_alnum=(wallet.addr_fmt & (AFC_BECH32 | AFC_BECH32M)),
                                   msg=addr)

        except UnknownAddressExplained as exc:
            await ux_show_story(addr + '\n\n' + str(exc), title="Unknown Address")

    @classmethod
    def note_subpath_used(cls, subpath):
        # when looking at PSBT, the address format is only implied
        # - but assume BIP-44/48/etc are being respected, and map to addr_fmt
        # - subpath is integers from PSBT contents already
        # - ignore coin_type
        from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

        subpath = subpath[1:]       # ignore xfp
        if len(subpath) < 3 or subpath[0] < 0x80000000 or subpath[2] < 0x80000000:
            # weird path w/o expected hardened levels - ignore
            return

        top = subpath[0] & 0x7fffffff
        acct = subpath[2] & 0x7fffffff
        if top == 44:
            af = AF_CLASSIC
        elif top == 49:
            af = AF_P2WPKH_P2SH
        elif top == 84:
            af = AF_P2WPKH
        else:
            return

        cls.note_wallet_used(af, acct)

    @classmethod
    def note_wallet_used(cls, addr_fmt, subaccount):
        # we track single-sig wallets they seem to use
        # - if they explore it (non-zero subaccount)
        # - if they sign those paths
        # - but ignore testnet vs. not
        from glob import settings

        if subaccount == 0:
            # only interested in non-zero subaccounts
            return

        here = [addr_fmt, subaccount]

        ex = settings.get('accts', [])

        if here in ex:
            # known.
            return

        ex = list(ex)
        ex.append(here)
        settings.set('accts', ex)
                
    @classmethod
    def wipe_all(cls):
        # clear all cached addresses. will affect other seeds in vault
        for fn in os.listdir():
            if fn.endswith('.own'):
                os.remove(fn)

# singleton, but also only created as needed; holds no state.
OWNERSHIP = OwnershipCache()

# EOF
