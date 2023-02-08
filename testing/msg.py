# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import base64, hashlib
from psbt import ser_compact_size
from bech32 import decode
from pycoin.encoding import a2b_hashed_base58, hash160
from pysecp256k1 import ec_pubkey_serialize
from pysecp256k1.recovery import ecdsa_recover, ecdsa_recoverable_signature_parse_compact


def bitcoin_hash_message(msg: bytes):
    s = hashlib.sha256()
    s.update(b'\x18Bitcoin Signed Message:\n')
    msg_len = len(msg)
    s.update(ser_compact_size(msg_len))
    s.update(msg)
    return hashlib.sha256(s.digest()).digest()


def verify_message(address, signature, message):
    script = None
    success = False
    h160 = None
    sig_bytes = base64.b64decode(signature)
    rec_id = (sig_bytes[0] - 27) & 0x03 # least two significant bits
    msg_hash = bitcoin_hash_message(message.encode())
    sig = ecdsa_recoverable_signature_parse_compact(sig_bytes[1:], rec_id)
    pubkey = ecdsa_recover(sig, msg_hash)
    rec_pk = ec_pubkey_serialize(pubkey)
    rec_pk_h160 = hash160(rec_pk)
    if address.startswith(("1", "m", "n")):
        raw = a2b_hashed_base58(address)
        h160 = raw[1:]
    elif address.startswith(("3", "2")):
        raw = a2b_hashed_base58(address)
        script = raw[1:]
    elif address.startswith(("bc1q", "tb1q", "bcrt1q")):
        raw = decode("bcrt" if address[:4] == "bcrt" else address[:2], address)
        if len(raw[1]) != 20:
            raise ValueError("p2wsh")
        h160 = bytes(raw[1])
    else:
        raise ValueError("Unsupported address format")

    if script:
        target = bytes([0, 20]) + rec_pk_h160
        target = hash160(target)
        if target == script:
            success = True
    else:
        if rec_pk_h160 == h160:
            success = True
    return success
