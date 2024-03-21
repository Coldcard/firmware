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

MAX_ADDRS_STORED = const(500)
BONUS_GAP_LIMIT = const(20)

OwnershipFileHdr = namedtuple('OwnershipFileHdr', 'file_magic flags offset')
OWNERSHIP_FILE_HDR = 'III'

# length of hashed & truncated address record
HASH_ENC_LEN = const(2)

# We may store only the 0/0 ..0/n paths, or alternating 0/0, 1/0, 0/1, 
FLAG_DUAL = 0x01
OWNERSHIP_MAGIC = 0xA010            # "Address Ownership" v1.0

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
        hdr_len = struct.calcsize(OWNERSHIP_FILE_HDR)

        try:
            with open(self.fname, 'rb') as fd:
                hdr = fd.read(hdr_len)
                assert len(hdr) == hdr_len
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

        each = (2 if (self.hdr.flags & FLAG_DUAL) else 1) * HASH_ENC_LEN
        self.count = (flen - hdr_len) // each

    def setup(self, start_idx, incl_change=False):
        flags = (0x0 if not incl_change else FLAG_DUAL)
        if self.count or self.hdr:
            assert start_idx == self.hdr.offset + self.count, 'not an append'
            assert self.hdr.flags == flags, 'mode wrong'

            # Open for append, header should be right already
            self.fd = open(self.fname, 'ab')
        else:
            # Start new file
            self.fd = open(self.fname, 'wb')
            self.hdr = OwnershipFileHdr(OWNERSHIP_MAGIC, flags, start_idx)
            hdr = struct.pack(OWNERSHIP_FILE_HDR, *self.hdr)
            self.fd.write(hdr)

    def append(self, addr, change_addr=None):
        if addr is None:
            # close file, done
            self.fd.close()
            del self.fd
            return

        self.fd.write(encode_addr(addr, self.salt))
        if change_addr:
            assert self.hdr.flags & FLAG_DUAL
            self.fd.write(encode_addr(change_addr))

    def fast_search(self, addr):
        # Do the easy part of the searching, using the existing file's contents.
        # - generates candidate path subcomponents; might be false positive
        from glob import dis

        if not self.hdr or not self.count:
            return

        chk = encode_addr(addr, self.salt)
        is_dual = (self.hdr.flags & FLAG_DUAL)

        idx = self.hdr.offset
        with open(self.fname, 'rb') as fd:
            fd.seek(struct.calcsize(OWNERSHIP_FILE_HDR))
            buf = bytearray(HASH_ENC_LEN)
            while 1:
                if fd.readinto(buf) != HASH_ENC_LEN:
                    break
                if chk == buf:
                    yield (0, idx)

                if is_dual:
                    if fd.readinto(buf) != HASH_ENC_LEN:
                        break
                    if chk == buf:
                        yield (1, idx)

                idx += 1
                dis.progress_sofar(idx-self.hdr.offset, self.count)

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

        start_idx = self.count + (self.hdr.offset if self.hdr else 0)
        count = MAX_ADDRS_STORED - start_idx

        self.setup(start_idx, incl_change=False)

        for idx,here,*_ in self.wallet.yield_addresses(
                                    start_idx, count, change_idx=0, censored=False):

            if here == addr:
                # Found it! But keep going a little for next time.
                match = (0, idx)

            self.append(addr)
            self.count += 1
            if match:
                bonus += 1

            if match and bonus > BONUS_GAP_LIMIT:
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
            # don't save to existing file, has some
            return None

        try:
            file.setup(start_idx)
        except Exception as exc:
            # in some cases we don't want to save anything, not an error
            sys.print_exception(exc)
            return None

        return file.append

    @classmethod
    def search(cls, addr):
        # find it!
        # - ignoring P2WPKH_P2SH ... for single-sig must be P2WPKH or CLASSIC
        # - anything script-like needs to match an existing multisig wallet
        # - if you start w/ testnet, we'll follow that
        from chains import current_chain
        from multisig import MultisigWallet
        from public_constants import AFC_SCRIPT
        from glob import dis

        ch = current_chain()

        addr_fmt = ch.possible_address_fmt(addr)
        if not addr_fmt:
            # might be valid address on testnet vs mainnet
            nm = ch.name if ch.ctype != 'BTC' else 'Bitcoin Mainnet'
            raise UnknownAddressExplained('That address is not valid on ' + nm)

        possibles = []

        if addr_fmt & AFC_SCRIPT:
            # multisig or script at least.. must exist already
            for w in MultisigWallet.iter_wallets(addr_fmt=addr_fmt):
                possibles.append(w)

            # TODO: add tapscript and such fancy stuff here

            if not possibles:
                raise UnknownAddressExplained(
                            "No suitable multisig wallets are currently defined.")
        else:
            # construct possible single-signer wallets, always at least account=0 case
            from wallet import MasterSingleSigWallet
            w = MasterSingleSigWallet(addr_fmt, account_idx=0)
            possibles.append(w)

            # TODO: add all account idx they have ever looked at

        prompt = 'Searching wallet(s)...'

        # "quick" check first

        # TODO: search all in parallel, rather than serially because
        # more likely to find a match with low index

        count = 0
        phase2 = []
        files = [AddressCacheFile(w) for w in possibles]
        for f in files:
            dis.fullscreen(prompt, line2=f.wallet.name)

            for maybe in f.fast_search(addr):
                ok = f.check_match(addr, maybe)
                if not ok: continue

                # winner.
                return f.wallet, maybe

            if f.count < MAX_ADDRS_STORED:
                phase2.append(f)
            count += f.count

        # maybe we haven't rendered all the addresses yet, so do that
        # - very slow, but only needed once
        # - might stop when match found, or maybe go a bit beyond that?
        for f in phase2:
            b4 = f.count
            dis.fullscreen("Generating addresses...", line2=f.wallet.name)

            result = f.rebuild(addr)
            if result:
                # found it, so report it and stop
                return f.wallet, result

            count += f.count - b4

        raise UnknownAddressExplained('Searched %d candidates without finding a match.' % count)
            

# singleton
OWNERSHIP = OwnershipCache()
    

# EOF
