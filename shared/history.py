# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# history.py - store some history about past transactions and/or outputs they involved
#
import gc, chains
from uhashlib import sha256
from ustruct import pack, unpack
from exceptions import IncorrectUTXOAmount
from ubinascii import b2a_base64, a2b_base64
from serializations import COutPoint, uint256_from_str
from glob import settings

# Very limited space in flash, so we compress as much as possible:
# - would be very bad for privacy to store these **UTXO amounts** in plaintext
# - result is stored in a JSON serialization, so needs to be text encoded
# - using base64, in two parts, concatenated
#       - 15 bytes are hash over txnhash:out_num => base64 => 20 chars text
#       - 8 bytes exact satoshi value => base64 (pad trimmed) => 11 chars
# - stored satoshi value is XOR'ed with LSB from prevout txn hash, which isn't stored
# - result is a 31 character string for each history entry, plus 4 overhead => 35 each
# - if we store 30 of those it's about 25% of total setting space
#
HISTORY_SAVED = const(30)
HISTORY_MAX_MEM = const(128)

# length of hashed&encoded key only (base64(15 bytes) => 20)
ENCKEY_LEN = const(20)

class OutptValueCache:
    # storing a list in settings
    # - maps from hash of txid:n to expected sats there
    # - stored as b64 key concatenated w/ int
    KEY = 'ovc'

    # we keep extra entries here during the current power-up
    # as defense against using very large txn in the attack
    runtime_cache = []
    _cache_loaded = False

    @classmethod
    def clear(cls):
        # user action in danger zone menu
        cls.runtime_cache.clear()
        cls._cache_loaded = True
        settings.remove_key(cls.KEY)
        settings.save()

    @classmethod
    def load_cache(cls):
        # first time: read saved value, but rest of time; use what's in memory
        if not cls._cache_loaded:
            saved = settings.get(cls.KEY) or []
            cls.runtime_cache.extend(saved)
            cls._cache_loaded = True
    

    @classmethod
    def encode_key(cls, prevout):
        # hash up the txid and output number, truncate, and encode as base64
        # - truncating at (mod3) bytes so no padding on b64 output
        # - expects a COutPoint
        md = sha256('OutptValueCache')
        md.update(prevout.serialize())
        return b2a_base64(md.digest()[:15])[:-1].decode()

    @classmethod
    def encode_value(cls, prevout, amt):
        # XOR stored value with 64 LSB of original txnhash
        xor = pack('<Q', prevout.hash & ((1<<64)-1))
        val = bytes(i^j for i,j in zip(xor, pack('<Q', amt)))
        assert len(val) == 8
        return b2a_base64(val)[:-2].decode()

    @classmethod
    def decode_value(cls, prevout, text):
        # base64 decode, xor w/ hash, decode as uint64
        xor = pack('<Q', prevout.hash & ((1<<64)-1))
        val = a2b_base64(text + '=')
        assert len(val) == 8
        val = bytes(i^j for i,j in zip(xor, val))
        return unpack('<Q', val)[0]

    @classmethod
    def fetch_amount(cls, prevout):
        # Return the amount we expect for this utxo, if we have it, else None
        cls.load_cache()

        if not cls.runtime_cache:
            return None

        key = cls.encode_key(prevout)
        for v in cls.runtime_cache:
            if v[0:ENCKEY_LEN] == key:
                return cls.decode_value(prevout, v[ENCKEY_LEN:])

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
            # Found the hacking we are looking for!
            ch = chains.current_chain()
            exp, units = ch.render_value(exp, True)
            amount, _ = ch.render_value(amount, True)

            raise IncorrectUTXOAmount(in_idx, "Expected %s but PSBT claims %s %s" % (
                                                exp, amount, units))

    @classmethod
    def add(cls, prevout, amount):
        # protect privacy, compress a little, and save it.
        # - we know it's not yet in our lists
        key = cls.encode_key(prevout)

        # memory management: can't store very much, so trim as needed
        depth = HISTORY_SAVED

        # also limit in-memory use
        cls.load_cache()
        if len(cls.runtime_cache) >= HISTORY_MAX_MEM:
            del cls.runtime_cache[0]

        # save new addition
        assert len(key) == ENCKEY_LEN
        assert amount > 0
        entry = key + cls.encode_value(prevout, amount)
        cls.runtime_cache.append(entry)

        # update what we're going to save long-term
        settings.set(cls.KEY, cls.runtime_cache[-depth:])

# As we build new transaction, track what we need to capture
new_outpts = []

def add_segwit_utxos(out_idx, amount):
    # After signing and finalization, we would know all change outpoints
    # (but not the txid yet)
    global new_outpts
    new_outpts.append((out_idx, amount))

def add_segwit_utxos_finalize(txid):
    # Once we know the final txid, assume this txn will be broadcast, mined,
    # and capture the future UTXO outputs it will represent at that point.
    global new_outpts

    # might not have any change, or they may not be segwit
    if not new_outpts: return

    # add it to the cache
    prevout = COutPoint(uint256_from_str(txid), 0) 
    for oi, amount in new_outpts:
        prevout.n = oi
        OutptValueCache.add(prevout, amount)

    new_outpts.clear()

# shortcut
verify_amount = lambda *a: OutptValueCache.verify_amount(*a)
    

# EOF
