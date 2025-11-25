# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# silentpayments.py - BIP-352/BIP-375 Silent Payment Logic
#
# Consolidates cryptographic primitives and PSBT handling logic for Silent Payments.
#

import ckcc
import ngu
from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H

SECP256K1_ORDER = ngu.secp256k1.curve_order_int()

# -----------------------------------------------------------------------------
# Silent Payments Cryptographic Primitives
# -----------------------------------------------------------------------------

def _compute_ecdh_share(a_sum, B_scan_bytes):
    """
    Compute BIP-375 ECDH share for silent payments 

    Formula: ecdh_share = a_sum * B_scan

    Args:
        a_sum: Combined private key as scalar
        B_scan_bytes: Scan public key (33 bytes compressed)

    Returns:
        bytes: ECDH share as compressed public key (33 bytes)
    """
    privkey_bytes = a_sum.to_bytes(32, "big")
    try:
        ngu.secp256k1.pubkey(B_scan_bytes)
    except Exception as e:
        raise ValueError("Invalid scan public key") from e
    
    return ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, privkey_bytes)

def _compute_shared_secret_tweak(shared_secret_bytes, k):
    """
    Compute BIP-352 shared secret tweak for output index k

    BIP-352 formula: t_k = hash_BIP0352/SharedSecret(shared_secret || ser_32(k))

    Args:
        shared_secret_bytes: Combined shared secret (33 bytes compressed point)
        k: Output index (0-based)

    Returns:
        bytes: Shared secret tweak as 32-byte scalar (reduced mod curve order)
    """
    # Concatenate shared_secret || k
    msg = shared_secret_bytes + k.to_bytes(4, "big")
    tweak_bytes = ngu.hash.sha256t(BIP352_SHARED_SECRET_TAG_H, msg, True)

    # Convert hash to scalar (reduce by curve order)
    return (int.from_bytes(tweak_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")

def _compute_input_hash(outpoints, A_sum_bytes):
    """
    Compute BIP-352 input hash

    BIP-352 formula: input_hash = hash_BIP0352/Inputs(smallest_outpoint || A_sum)

    Args:
        outpoints: List of (txid, vout) tuples, where txid is 32 bytes and vout as (4 bytes little-endian)
        A_sum_bytes: Sum of all eligible input public keys (33 bytes compressed)

    Returns:
        bytes: Input hash as 32-byte scalar (reduced mod curve order)
    """
    # BIP-352: use only the lexicographically smallest outpoint
    smallest = min(outpoints, key=lambda x: (x[0], x[1]))
    msg = smallest[0] + smallest[1] + A_sum_bytes

    input_hash_bytes = ngu.hash.sha256t(BIP352_INPUTS_TAG_H, msg, True)

    return (int.from_bytes(input_hash_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")

def _combine_pubkeys(pubkeys):
    """
    Combine a list of public keys into a single public key

    Args:
        pubkeys: List of public keys (33 bytes compressed)

    Returns:
        bytes: Combined public key (33 bytes compressed)

    Raises:
        ValueError: If list is empty or keys are invalid
    """
    if not pubkeys:
        raise ValueError("No public keys to combine")

    combined_pk = pubkeys[0]
    try:
        for pk in pubkeys[1:]:
            combined_pk = ngu.secp256k1.ec_pubkey_combine(combined_pk, pk)
    except Exception as e:
        raise ValueError("Failed to combine public keys") from e

    return combined_pk

def _compute_silent_payment_output_script(
    outpoints, A_sum_bytes, ecdh_share_bytes, B_spend, k=0
):
    """
    Compute the P2TR scriptPubKey for silent payment with output index k.

    BIP-352 formula: P_k = B_spend + t_k * G
    where input_hash = hash_BIP0352/Inputs(outpoints || A_sum)
          t_k = hash_BIP0352/SharedSecret(ecdh_share * input_hash || ser_32(k))

    Args:
        outpoints: List of (txid, vout) tuples from eligible inputs
        A_sum_bytes: Sum of eligible input public keys (33 bytes compressed)
        ecdh_share_bytes: ECDH share point (33 bytes compressed)
        B_spend: Recipient spend public key (33 bytes compressed)
        k: Output index for this recipient

    Returns:
        bytes: P2TR scriptPubKey (34 bytes: OP_1 <32-byte x-only pubkey>)

    Raises:
        ValueError: If B_spend or output_pubkey is invalid
    """
    try:
        ngu.secp256k1.pubkey(B_spend)
    except Exception:
        raise ValueError("Invalid spend public key")

    # Compute shared secret using input hash and ecdh_share
    input_hash_bytes = _compute_input_hash(outpoints, A_sum_bytes)
    shared_secret_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, input_hash_bytes)

    # Compute shared secret tweak
    tweak_bytes = _compute_shared_secret_tweak(shared_secret_bytes, k)

    # Compute t_k * G using the generator point
    G = ngu.secp256k1.generator()
    tweak_point = ngu.secp256k1.ec_pubkey_tweak_mul(G, tweak_bytes)

    # Derive output pubkey: P_k = B_spend + t_k * G
    output_pubkey = ngu.secp256k1.ec_pubkey_combine(B_spend, tweak_point)

    if len(output_pubkey) != 33:
        raise ValueError("Invalid pubkey length")
    x_only = output_pubkey[1:]

    return b"\x51\x20" + x_only


# -----------------------------------------------------------------------------
# Input Eligibility (BIP-352)
# -----------------------------------------------------------------------------

def _is_p2pkh(spk):
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        len(spk) == 25
        and spk[0] == 0x76
        and spk[1] == 0xA9
        and spk[2] == 0x14
        and spk[-2] == 0x88
        and spk[-1] == 0xAC
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
