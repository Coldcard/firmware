# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ownership.py - store a cache of hashes related to addresses we might control.
#
import gc, chains, stash, ngu
from uhashlib import sha256
from ustruct import pack, unpack
from ubinascii import b2a_base64, a2b_base64
from glob import settings
from ucollections import namedtuple
from wallet import WalletABC
from ubinascii import hexlify as b2a_hex

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

REL_GAP_LIMIT = const(1000)

OwnershipFileHdr = namedtuple('OwnershipFileHdr', 'file_magic offset')
OWNERSHIP_FILE_HDR = 'II'
FILE_HDR_LEN = const(8)
OWNERSHIP_MAGIC = 0xA010            # "Address Ownership" v1.0

# length of hashed & truncated address record
HASH_ENC_LEN = const(8)

class OwnershipCache:

    def wallet_to_fname(self, wallet: WalletABC):
        # hash up something about the wallet to form a filename
        desc = wallet.to_descriptor().serialize()
        h = ngu.hash.sha256d(desc)
        return b2a_hex(h)[0:32] + '.own'

    def register(self, wallet:WalletABC):
        # notes the details of a new wallet
        # - won't build anything, so still fast
        fn = self.wallet_to_fname(wallet)

    def note_subkey(self, xfp, path, pubkey):
        # whenever we see an in or out that is ours, note it here
        pass

# singleton
OWNERSHIP = OwnershipCache()
    

# EOF
