# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import base64, hashlib
from psbt import ser_compact_size
from bech32 import decode
from constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from helpers import hash160
from base58 import decode_base58_checksum
from pysecp256k1 import ec_pubkey_serialize
from pysecp256k1.recovery import ecdsa_recover, ecdsa_recoverable_signature_parse_compact
from pysecp256k1.recovery import ecdsa_sign_recoverable, ecdsa_recoverable_signature_serialize_compact


RFC_SIGNATURE_TEMPLATE = '''\
-----BEGIN BITCOIN SIGNED MESSAGE-----
{msg}
-----BEGIN BITCOIN SIGNATURE-----
{addr}
{sig}
-----END BITCOIN SIGNATURE-----
'''


def parse_signed_message(msg):
    msplit = msg.strip().split("\n")
    assert msplit[0] == "-----BEGIN BITCOIN SIGNED MESSAGE-----"
    assert msplit[2] == "-----BEGIN BITCOIN SIGNATURE-----"
    assert msplit[5] == "-----END BITCOIN SIGNATURE-----"
    return msplit[1], msplit[3], msplit[4]


def sig_hdr_base(addr_fmt):
    if addr_fmt in (AF_CLASSIC, "p2pkh"):
        return 31
    elif addr_fmt in (AF_P2WPKH_P2SH, "p2sh-p2wpkh", "p2wpkh-p2sh"):
        return 35
    elif addr_fmt in (AF_P2WPKH, "p2wpkh"):
        return 39
    else:
        raise ValueError


def bitcoin_hash_message(msg: bytes):
    s = hashlib.sha256()
    s.update(b'\x18Bitcoin Signed Message:\n')
    msg_len = len(msg)
    s.update(ser_compact_size(msg_len))
    s.update(msg)
    return hashlib.sha256(s.digest()).digest()


def sign_message(sk, msg, addr_fmt=AF_CLASSIC, b64=True):
    sig_o = ecdsa_sign_recoverable(sk, bitcoin_hash_message(msg))
    sig_bytes, rec_id = ecdsa_recoverable_signature_serialize_compact(sig_o)
    header_byte = rec_id + sig_hdr_base(addr_fmt=addr_fmt)
    sig = bytes([header_byte]) + sig_bytes
    if b64:
        return base64.b64encode(sig).decode().strip()
    return sig


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
        raw = decode_base58_checksum(address)
        h160 = raw[1:]
    elif address.startswith(("3", "2")):
        raw = decode_base58_checksum(address)
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
