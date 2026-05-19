# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Bitcoin transaction signature hash helpers for tests.
#
import copy
import hashlib
import struct

from ctransaction import hash256
from serialize import ser_string
from pysecp256k1 import tagged_sha256


SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1


def legacy_sighash(tx, in_idx, script_code, sighash=SIGHASH_ALL):
    tmp = copy.deepcopy(tx)
    for txin in tmp.vin:
        txin.scriptSig = b''
    tmp.vin[in_idx].scriptSig = script_code
    return hash256(tmp.serialize_without_witness() + struct.pack('<I', sighash))


def segwit_v0_sighash(tx, in_idx, script_code, amount, sighash=SIGHASH_ALL):
    hash_prevouts = hash256(b''.join(i.prevout.serialize() for i in tx.vin))
    hash_sequence = hash256(b''.join(struct.pack('<I', i.nSequence) for i in tx.vin))
    hash_outputs = hash256(b''.join(o.serialize() for o in tx.vout))
    txin = tx.vin[in_idx]
    preimage = struct.pack('<i', tx.nVersion)
    preimage += hash_prevouts + hash_sequence
    preimage += txin.prevout.serialize()
    preimage += ser_string(script_code)
    preimage += struct.pack('<q', amount)
    preimage += struct.pack('<I', txin.nSequence)
    preimage += hash_outputs
    preimage += struct.pack('<I', tx.nLockTime)
    preimage += struct.pack('<I', sighash)
    return hash256(preimage)


def taproot_sighash(tx, in_idx, prevouts, sighash=SIGHASH_DEFAULT):
    assert sighash in (SIGHASH_DEFAULT, SIGHASH_ALL)
    preimage = bytes([sighash])
    preimage += struct.pack('<i', tx.nVersion)
    preimage += struct.pack('<I', tx.nLockTime)
    preimage += hashlib.sha256(b''.join(i.prevout.serialize() for i in tx.vin)).digest()
    preimage += hashlib.sha256(b''.join(struct.pack('<q', amount) for amount, spk in prevouts)).digest()
    preimage += hashlib.sha256(b''.join(ser_string(spk) for amount, spk in prevouts)).digest()
    preimage += hashlib.sha256(b''.join(struct.pack('<I', i.nSequence) for i in tx.vin)).digest()
    preimage += hashlib.sha256(b''.join(o.serialize() for o in tx.vout)).digest()
    preimage += b'\x00'
    preimage += struct.pack('<I', in_idx)
    return tagged_sha256(b"TapSighash", b'\x00' + preimage)
