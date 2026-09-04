# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# history.py - store some history about past transactions and/or outputs they involved
#
import chains
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
# - 128 entries use about 4.4 KiB, plus the other wallet settings
#
HISTORY_DEPTH = const(128)

# length of hashed&encoded key only (base64(15 bytes) => 20)
ENCKEY_LEN = const(20)

class OutptValueCache:
    # storing a list in settings
    # - maps from hash of txid:n to expected sats there
    # - stored as b64 key concatenated w/ int
    KEY = 'ovc'

    @classmethod
    def clear(cls):
        # user action in danger zone menu
        settings.remove_key(cls.KEY)
        settings.save()

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
    def get_cache(cls):
        return settings.get(cls.KEY) or []

    @classmethod
    def fetch_amount(cls, prevout, cache=None):
        # Return the amount we expect for this utxo, if we have it, else None
        if cache is None:
            cache = cls.get_cache()

        if not cache:
            return None

        key = cls.encode_key(prevout)
        for v in cache:
            if v[0:ENCKEY_LEN] == key:
                return cls.decode_value(prevout, v[ENCKEY_LEN:])

        return None

    @classmethod
    def verify_amount(cls, prevout, amount, in_idx, cache=None):
        # check this input either:
        #   - not been seen before, in which case it may be recorded after signing
        #   - OR: the amount matches exactly, any previously-seen UTXO w/ same outpoint
        # raises IncorrectUTXOAmount with details if it fails, which should abort any signing
        exp = cls.fetch_amount(prevout, cache)

        if exp is None:
            return False

        if exp != amount:
            # Found the hacking we are looking for!
            ch = chains.current_chain()
            exp, units = ch.render_value(exp, True)
            amount, _ = ch.render_value(amount, True)

            raise IncorrectUTXOAmount(in_idx, "Expected %s but PSBT claims %s %s" % (
                                                exp, amount, units))

        return True

    @classmethod
    def commit(cls, psbt):
        # Signing succeeded: record first-seen amounts directly from inputs that
        # received our signature. Parsing/cancelling a PSBT leaves no OVC state.
        # - called only after a signature was actually produced (post-approval)
        # - sp_idxs shows EDGE signing intent; added_sigs is evidence from sign_it()
        # - Proof of Reserves must never read or modify this history
        if psbt.por322:
            return

        # copy so a later verification failure leaves settings unchanged
        cache = list(cls.get_cache())
        changed = False

        for in_idx, txin in psbt.input_iter():
            inp = psbt.inputs[in_idx]
            if inp.added_sigs and inp.sp_idxs and inp.has_utxo() and inp.is_segwit:
                if not cls.verify_amount(txin.prevout, inp.amount, in_idx, cache):
                    # add() serializes prevout immediately, which is important because
                    # PSBTv0 input_iter() reuses and mutates its CTxIn object
                    cls.add(cache, txin.prevout, inp.amount)
                    changed = True

        if changed:
            settings.set(cls.KEY, cache)

    @classmethod
    def add(cls, cache, prevout, amount):
        # protect privacy, compress a little, and append it.
        # - we know it's not yet in our lists
        key = cls.encode_key(prevout)

        # save new addition
        assert len(key) == ENCKEY_LEN
        # assert amount > 0
        entry = key + cls.encode_value(prevout, amount)
        # evict first so append does not grow a full MicroPython list
        if len(cache) >= HISTORY_DEPTH:
            del cache[0]

        cache.append(entry)

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

    # copy and add all change outputs, then update settings once
    cache = list(OutptValueCache.get_cache())
    prevout = COutPoint(uint256_from_str(txid), 0)
    for oi, amount in new_outpts:
        prevout.n = oi
        OutptValueCache.add(cache, prevout, amount)

    settings.set(OutptValueCache.KEY, cache)
    new_outpts.clear()

# shortcut
verify_amount = lambda *a: OutptValueCache.verify_amount(*a)

# EOF
