# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Unified opt-in signature hash, against the cross-implementation vectors from
# the Bitcoin Knots tree (src/test/data/unified_sighash.json).
#
# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/unit_unified_sighash.py')
#
# Kept as flat top-level code: EXEC runs this with its own locals, so a
# function body here cannot see the imports above it.

import ujson, main
from ubinascii import unhexlify as a2b_hex, hexlify as b2a_hex
from psbt import psbtObject
from serializations import CTransaction, CTxIn, CTxOut, ser_compact_size, ser_string
from uhashlib import sha256
from ustruct import pack, unpack
from uio import BytesIO
from sffile import SFFile


class FakeInput:
    # Stands in for psbtInputProxy: make_txn_unified_sighash() reads only the
    # script and the spent output, which is all a vector gives us.
    def __init__(self, is_segwit, script_code, script_sig, utxo):
        self.is_segwit = is_segwit
        # the digest refuses taproot; these vectors are never taproot
        self.addr_fmt = None
        self.scriptCode = script_code
        self.scriptSig = script_sig
        self.utxo = utxo

    def get_utxo(self, idx):
        return self.utxo


# Script types 2 (taproot) and 3 (tapscript) are defined by the rule but out of
# reach here: this firmware refuses to spend taproot at all, so there is no
# input for which it would ever build that form of the message.
SUPPORTED_SCRIPT_TYPES = (0, 1)

fname = getattr(main, 'FILENAME', '../../testing/data/unified_sighash.json')

with open(fname, 'rt') as fd:
    vectors = ujson.load(fd)

assert vectors[0][:2] == ["scriptCode", "rawTx"], "unexpected vector format"

skipped = 0
checked = 0

for vec in vectors[1:]:
    script_code, raw_tx, in_idx, hash_type, script_type, spent, expect = vec

    if script_type not in SUPPORTED_SCRIPT_TYPES:
        skipped += 1
        continue

    raw = a2b_hex(raw_tx)

    # Wrap the raw unsigned txn as the thinnest possible PSBT, so the real
    # psbtObject does the parsing rather than the test. The vectors carry
    # arbitrary transaction versions, which the PSBT parser rejects on sight,
    # so parse under version 2 and hand the real one back before hashing: the
    # message reads self.txn_version, never the bytes in the file.
    txn_version = unpack('<i', raw[:4])[0]
    tx = CTransaction()
    tx.deserialize(BytesIO(raw))
    patched = pack('<i', 2) + raw[4:]
    body = b'psbt\xff\x01\x00' + ser_compact_size(len(patched)) + patched
    body += b'\0' * (1 + len(tx.vin) + len(tx.vout))

    fd = SFFile(0, max_size=65536)
    fd.write(body)
    # PSRAM writes go out in 4-byte blocks; without this the last few bytes of
    # the file are still in the runt buffer and the parser runs off the end.
    fd.flush_out()
    p = psbtObject.read_psbt(SFFile(0, fd.tell()))
    p.txn_version = txn_version
    assert p.lock_time == tx.nLockTime, "locktime parse"

    # Every spent amount and scriptPubKey is committed to, not just this
    # input's. Gathered by consider_inputs() in the real flow.
    ha = sha256()
    hs = sha256()
    utxos = []
    for value, spk in spent:
        utxos.append(CTxOut(value, a2b_hex(spk)))
        ha.update(pack('<q', value))
        hs.update(ser_string(a2b_hex(spk)))

    p.hashAmounts = ha.digest()
    p.hashScriptPubKeys = hs.digest()

    sc = a2b_hex(script_code)
    if script_type == 1:
        # segwit v0 keeps its scriptCode with the length prefix already applied
        inp = FakeInput(True, ser_string(sc), None, utxos[in_idx])
    else:
        inp = FakeInput(False, None, sc, utxos[in_idx])

    replacement = CTxIn()
    replacement.prevout = tx.vin[in_idx].prevout
    replacement.nSequence = tx.vin[in_idx].nSequence

    digest = p.make_txn_unified_sighash(in_idx, replacement, inp, hash_type)
    got = b2a_hex(digest).decode('ascii')

    assert got == expect, "scriptType=%d hashType=0x%x in=%d\nExpected %s\nGot      %s" % (
                                script_type, hash_type, in_idx, expect, got)
    checked += 1

assert checked, "no vectors ran"
print("unified sighash: %d vectors OK, %d taproot skipped" % (checked, skipped))
