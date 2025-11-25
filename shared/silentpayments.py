# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# silentpayments.py - BIP-352/BIP-375
#
# Consolidates cryptographic primitives and PSBT handling logic for Silent Payments
#
import ngu
from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H

G = ngu.secp256k1.generator()
SECP256K1_ORDER = ngu.secp256k1.curve_order_int()

# -----------------------------------------------------------------------------
# Silent Payments Cryptographic Primitives
# -----------------------------------------------------------------------------


def _combine_pubkeys(pubkeys):
    """
    Combine a list of public keys into a single public key

    Args:
        pubkeys: List of public keys to combine (33-byte compressed)

    Returns:
        bytes: Combined public key (33-byte compressed)
    """
    if len(pubkeys) == 1:
        return pubkeys[0]
    return ngu.secp256k1.ec_pubkey_combine(pubkeys)


def _compute_ecdh_share(a_sum_bytes, B_scan_bytes):
    """
    Compute ECDH share (partial shared secret)

    Formula: ecdh_share = a_sum * B_scan

    Args:
        a_sum_bytes: Combined private key (32-byte scalar)
        B_scan_bytes: Scan public key (33-byte compressed)

    Returns:
        bytes: ECDH share point (33-byte compressed)
    """
    return ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, a_sum_bytes)


def _compute_input_hash(outpoints, A_sum_bytes):
    """
    Compute BIP-352 input hash

    Formula: input_hash = hash_BIP0352/Inputs(smallest_outpoint || A_sum)

    Args:
        outpoints: List of (txid, vout) tuples, where txid is 32-byte and vout is 4-byte little-endian
        A_sum_bytes: Sum of all eligible input public keys (33-byte compressed)

    Returns:
        bytes: Input hash (32-byte scalar)
    """
    smallest = min(outpoints, key=lambda x: x[0] + x[1])
    msg = smallest[0] + smallest[1] + A_sum_bytes
    input_hash_bytes = ngu.hash.sha256t(BIP352_INPUTS_TAG_H, msg, True)
    input_hash_int = int.from_bytes(input_hash_bytes, "big")
    if not (0 < input_hash_int < SECP256K1_ORDER):
        raise ValueError("Invalid input hash: not in valid scalar range")
    return input_hash_int.to_bytes(32, "big")


def _compute_shared_secret_tweak(shared_secret_bytes, k):
    """
    Compute BIP-352 shared secret tweak

    Formula: t_k = hash_BIP0352/SharedSecret(serP(shared_secret) || ser_32(k))

    Args:
        shared_secret_bytes: Shared secret point (33-byte compressed)
        k: Output index per scan key group (int)

    Returns:
        bytes: Shared secret tweak (32-byte scalar)
    """
    msg = shared_secret_bytes + k.to_bytes(4, "big")
    tweak_bytes = ngu.hash.sha256t(BIP352_SHARED_SECRET_TAG_H, msg, True)
    tweak_int = int.from_bytes(tweak_bytes, "big")
    if not (0 < tweak_int < SECP256K1_ORDER):
        raise ValueError("Invalid shared secret tweak: not in valid scalar range")
    return tweak_int.to_bytes(32, "big")


def _compute_silent_payment_output_script(outpoints, A_sum_bytes, ecdh_share_bytes, B_spend_bytes, k):
    """
    Compute the P2TR scriptPubKey for silent payment

    Formula: P_k = B_spend + t_k * G

    Args:
        outpoints: List of (txid, vout) tuples from eligible inputs
        A_sum_bytes: Sum of eligible input public keys (33-byte compressed)
        ecdh_share_bytes: ECDH share point (33-byte compressed)
        B_spend_bytes: Recipient spend public key (33-byte compressed)
        k: Output index per scan key group (int)

    Returns:
        bytes: P2TR scriptPubKey (OP_1 <32-byte x-only pubkey>)
    """
    input_hash_bytes = _compute_input_hash(outpoints, A_sum_bytes)
    shared_secret_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, input_hash_bytes)
    tweak_bytes = _compute_shared_secret_tweak(shared_secret_bytes, k)
    # Derive output pubkey: P_k = B_spend + t_k * G
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G, tweak_bytes)
    output_pubkey = ngu.secp256k1.ec_pubkey_combine([B_spend_bytes, tweak_point])
    x_only = output_pubkey[1:]
    return b"\x51\x20" + x_only


# -----------------------------------------------------------------------------
# Input Eligibility
# -----------------------------------------------------------------------------


def _is_p2pkh(spk):
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 and spk[2] == 0x14 and spk[-2] == 0x88 and spk[-1] == 0xAC
    )


def _is_p2wpkh(spk):
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def _is_p2tr(spk):
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20


def _is_p2sh(spk):
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[-1] == 0x87
