# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ownership.py - store a cache of hashes related to addresses we might control.
#
import sys, chains, stash, ngu, struct
from uhashlib import sha256
from ubinascii import b2a_base64, a2b_base64
from glob import settings
from ucollections import namedtuple
from wallet import WalletABC
from ubinascii import hexlify as b2a_hex
from exceptions import UnknownAddressExplained

# Track many addresses, but in compressed form
# - map from random Bech32/Base58 payment address to (wallet)/keypath
# - does change and normal (internal, external) addresses, but won't consider
#   any keypath that does not end in 0/* or 1/*
# - store just hints, since we can re-construct any address and want to fully verify
# - try to keep private between different duress wallets, and seed vaults
# - storing bulk data into LFS, not settings
# - okay to wipe, can restore anytime; with CPU cost
# - MAYBE: tracks "high water level" of wallets (highest used addr)
# - MAYBE: enforces a gap limit concept, but would be better if it didn't
# - cannot be used to accelerate address explorer because we don't store full addresses
# - data stored in binary, fixed-length header, then fixed-length records
# - multisig and single sig, and someday taproot, miniscript too
# - searching is interruptable; and leaves behind a cache for next time
# - data building/saves happens when are searching, but might grab some during addr expl export?
#

# length of hashed & truncated address record
HASH_ENC_LEN = const(2)

# File header
OwnershipFileHdr = namedtuple('OwnershipFileHdr', 'file_magic future flags')
OWNERSHIP_FILE_HDR = 'HHI'
OWNERSHIP_FILE_HDR_LEN = 8

OWNERSHIP_MAGIC = 0x10A0            # "Address Ownership" v1.0
# flags: none yet, but 32 bits reserved

# target 3 flash blocks, max file size => 764 addresses
MAX_ADDRS_STORED = ((3*512) - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN
BONUS_GAP_LIMIT = const(20)

def encode_addr(addr, salt):
    # Convert text address to something we can store while preserving privacy.
    return ngu.hash.sha256s(salt + addr)[0:HASH_ENC_LEN]

class AddressCacheFile:

    def __init__(self, wallet):
        self.wallet = wallet
        self.desc = wallet.to_descriptor().serialize()
        h = b2a_hex(ngu.hash.sha256d(self.desc))
        self.fname = h[0:32] + '.own'
        self.salt = h[32:]
        self.count = 0
        self.hdr = None

        self.peek()

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
        except OSError:
            return
        except Exception as exc:
            sys.print_exception(exc)
            self.count = 0
            self.hdr = None
            return

        self.count = (flen - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN

    def setup(self, start_idx):
        if self.count or self.hdr:
            assert start_idx == self.count, 'not an append'

            # Open for append, header should be right already
            self.fd = open(self.fname, 'ab')
        else:
            # Start new file
            self.fd = open(self.fname, 'wb')
            self.hdr = OwnershipFileHdr(OWNERSHIP_MAGIC, 0x0, 0x0)
            hdr = struct.pack(OWNERSHIP_FILE_HDR, *self.hdr)
            self.fd.write(hdr)

    def append(self, addr):
        if addr is None:
            # close file, done
            self.fd.close()
            del self.fd
            return

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
                yield (0, idx)

            dis.progress_sofar(idx, self.count)

    def check_match(self, want_addr, subpath):
        # need to double-check matches, to get rid of false positives.
        chg, idx = subpath
        got = self.wallet.render_address(*subpath)
        return want_addr == got

    def rebuild(self, addr):
        # build more addresses
        # - maybe wipe incomplete stuff from csv export hack
        # - return subpath for a hit or None
        from glob import dis

        bonus = 0
        match = None

        start_idx = self.count
        count = MAX_ADDRS_STORED - start_idx

        if count <= 0:
            return None

        self.setup(start_idx)

        for idx,here,*_ in self.wallet.yield_addresses(
                                    start_idx, count, change_idx=0, censored=False):

            if here == addr:
                # Found it! But keep going a little for next time.
                match = (0, idx)

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
    def saver(cls, wallet, start_idx):
        # when we are generating many addresses for export, capture them
        # as we go with this function
        # - not change -- only main addrs
        file = AddressCacheFile(wallet)

        if file.exists():
            # don't save to existing file, has some already
            return None

        try:
            file.setup(start_idx)
        except Exception as exc:
            # in some cases we don't want to save anything, not an error
            return None

        return file.append

    @classmethod
    def search(cls, addr):
        # Find it!
        # - returns wallet object, and tuple2 of final 2 subpath components
        # - if you start w/ testnet, we'll follow that
        from chains import current_chain
        from multisig import MultisigWallet
        from public_constants import AFC_SCRIPT, AF_P2WPKH_P2SH, AF_P2SH
        from glob import dis

        ch = current_chain()

        addr_fmt = ch.possible_address_fmt(addr)
        if not addr_fmt:
            # might be valid address on testnet vs mainnet
            nm = ch.name if ch.ctype != 'BTC' else 'Bitcoin Mainnet'
            raise UnknownAddressExplained('That address is not valid on ' + nm)

        possibles = []

        if addr_fmt == AF_P2SH and not MultisigWallet.exists():
            # Might be single-sig p2wpkh wrapped in p2sh ... but that was a transition
            # thing that hopefully is going away, so if they have any multisig wallets, 
            # defined, assume that that's the only p2sh address source.
            addr_fmt = AF_P2WPKH_P2SH

        if addr_fmt & AFC_SCRIPT and MultisigWallet.exists():
            # multisig or script at least.. must exist already
            for w in MultisigWallet.iter_wallets(addr_fmt=addr_fmt):
                possibles.append(w)

            # TODO: add tapscript and such fancy stuff here

            if not possibles:
                raise UnknownAddressExplained(
                            "No suitable multisig wallets are currently defined.")
        else:
            # Construct possible single-signer wallets, always at least account=0 case
            from wallet import MasterSingleSigWallet
            w = MasterSingleSigWallet(addr_fmt, account_idx=0)
            possibles.append(w)

            # TODO: add all account idx they have ever looked at

        # "quick" check first, before doing any generations

        count = 0
        phase2 = []
        files = [AddressCacheFile(w) for w in possibles]
        for f in files:
            dis.fullscreen('Searching wallet(s)...', line2=f.wallet.name)

            for maybe in f.fast_search(addr):
                ok = f.check_match(addr, maybe)
                if not ok: continue

                # found winner.
                return f.wallet, maybe

            if f.count < MAX_ADDRS_STORED:
                phase2.append(f)
            count += f.count

        # maybe we haven't rendered all the addresses yet, so do that
        # - very slow, but only needed once
        # - might stop when match found, or maybe go a bit beyond that?
        # - MAYBE NOT: search all in parallel, rather than serially because
        #   more likely to find a match with low index

        for f in phase2:
            b4 = f.count
            dis.fullscreen("Generating addresses...", line2=f.wallet.name)

            result = f.rebuild(addr)
            if result:
                # found it, so report it and stop
                return f.wallet, result

            count += f.count - b4

        raise UnknownAddressExplained('Searched %d candidates without finding a match.' % count)

# singleton, but also only created as needed; holds no state.
OWNERSHIP = OwnershipCache()

# EOF
