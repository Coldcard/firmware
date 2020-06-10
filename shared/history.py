# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# history.py - store some history about past transactions and/or outputs they involved
#
import tcc, gc, chains
from utils import B2A
#from ustruct import unpack_from, unpack, pack
#from ubinascii import hexlify as b2a_hex
from exceptions import IncorrectUTXOAmount
from ubinascii import b2a_base64
from serializations import COutPoint, uint256_from_str
from main import settings

# Very limited space in flash, so we limit how much to store there, and compress
# as much as possible...
HISTORY_DEPTH = const(30)

# length of hashed&encoded key
ENCKEY_LEN = 24

class OutptValueCache:
    # storing a list in settings
    # - maps from hash of txid:n to expected sats there
    # - stored as b64 key concatenated w/ int
    KEY = 'ovc'

    @classmethod
    def clear_cache(cls):
        # user action in danger zone menu
        settings.remove_key(cls.KEY)
        settings.save()

    @classmethod
    def encode_key(cls, prevout):
        # hash up the txid and output number, truncate, and encode as base64
        # - truncating at 18 bytes so no padding on b64 output
        # - expects a COutPoint
        md = tcc.sha256('OutptValueCache')
        md.update(prevout.serialize())
        return b2a_base64(md.digest()[:18])[:-1].decode()

    @classmethod
    def fetch_amount(cls, prevout):
        # read the amount we expect, if we have it, else None
        vals = settings.get(cls.KEY)
        if not vals:
            return None

        key = cls.encode_key(prevout)
        for v in vals:
            if v[0:ENCKEY_LEN] == key:
                return int(v[ENCKEY_LEN:])
        return None

    @classmethod
    def verify_amount(cls, prevout, amount, in_idx):
        # check this input either:
        #   - not been seen before, in which case, record it
        #   - OR: the amount matches exactly, any previously-seend UTXO w/ same outpoint
        # raises IncorrectUTXOAmount with details if it fails, which should abort any signing
        exp = cls.fetch_amount(prevout)

        if exp is None:
            # new entry, add it
            cls.add(prevout, amount)

        elif exp != amount:
            # the error we are looking for!
            ch = chains.current_chain()
            exp, units = ch.render_value(exp, True)
            amount, _ = ch.render_value(amount, True)
            raise IncorrectUTXOAmount(in_idx, "Expected %s but PSBT claims %s %s" % (
                                                exp, amount, units))

    @classmethod
    def add(cls, prevout, amount):
        # protect privacy, compress a little, and save it.
        key = cls.encode_key(prevout)
        vals = settings.get(cls.KEY) or []

        while len(vals) >= HISTORY_DEPTH:
            del vals[0]

        assert len(key) == ENCKEY_LEN
        assert amount > 0
        vals.append(key + str(amount))

        settings.set(cls.KEY, vals)

# As we build new transaction, track what we need to capture
new_outpts = []

def add_segwit_utxos(out_idx, amount):
    # after signing and finalization, we would know all change outpoints
    # (but not the txid yet)
    global new_outpts
    new_outpts.append((out_idx, amount))

def add_segwit_utxos_finalize(txid):
    # now, we know the final txid, so assume this txn will be broadcast, mined,
    # and capture the future UTXO outputs it will represent
    global new_outpts

    # might not have any change, or they may not be segwit
    if not new_outpts: return

    # add it to the cache
    prevout = COutPoint(uint256_from_str(txid), 0) 
    for oi, amount in new_outpts:
        prevout.n = oi
        OutptValueCache.add(prevout, amount)

    new_outpts.clear()

verify_amount = lambda *a: OutptValueCache.verify_amount(*a)
    

# EOF
