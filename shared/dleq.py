# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# dleq.py - DLEQ (Discrete Logarithm Equality) proofs for BIP-374
#
# Implements non-interactive zero-knowledge proofs that prove:
#   log_G(A) = log_B(C)
# where:
#   - G is the secp256k1 generator
#   - A = a*G (sender's public key)
#   - B = (recipient's scan public key)
#   - C = a*B (ECDH share point)
#
# This proves the ECDH computation is correct without revealing the private key
#
import ngu
from precomp_tag_hash import DLEQ_TAG_AUX_H, DLEQ_TAG_NONCE_H, DLEQ_TAG_CHALLENGE_H

G = ngu.secp256k1.generator()
SECP256K1_ORDER = ngu.secp256k1.curve_order_int()


def xor_bytes(a, b):
    """XOR two byte strings of equal length"""
    return bytes(x ^ y for x, y in zip(a, b))


def dleq_challenge(A, B, C, R1, R2, m=None, _G=None):
    """Compute DLEQ challenge using BIP-374 tagged hash"""
    if _G is None:
        _G = ngu.secp256k1.ec_pubkey_serialize(G, compressed=True)

    # BIP-374: e = TaggedHash("BIP0374/challenge", cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m)
    challenge_input = A + B + C + _G + R1 + R2
    if m is not None:
        challenge_input += m

    challenge_hash = ngu.hash.sha256t(DLEQ_TAG_CHALLENGE_H, challenge_input, True)
    return int.from_bytes(challenge_hash, "big")


def generate_dleq_proof(a_sum, B_scan, aux_rand=None, m=None):
    """
    Generate DLEQ proof (BIP-374)

    Args:
        a_sum:     Input private key a    (32-byte scalar)
        B_scan:    Scan public key B      (33-byte compressed)
        aux_rand:  Auxiliary randomness r (32-byte or None)
        m:         Optional message       (32-byte or None)

    Returns:
        bytes: DLEQ proof (64-byte: e || s)

    Raises:
        ValueError: If inputs are invalid
    """
    a_sum_int = int.from_bytes(a_sum, "big")
    if not (0 < a_sum_int < SECP256K1_ORDER):
        raise ValueError("Invalid input private key: not in valid scalar range")

    # Compute public key A = a*G
    A_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G, a_sum)

    # Compute ECDH share C = a*B
    C_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan, a_sum)

    if aux_rand is None:
        aux_rand = ngu.random.bytes(32)
    else:
        if len(aux_rand) != 32:
            raise ValueError("aux_rand must be 32 bytes")

    # t = a XOR TaggedHash("BIP0374/aux", r)
    aux_hash = ngu.hash.sha256t(DLEQ_TAG_AUX_H, aux_rand, True)
    del aux_rand
    t = xor_bytes(a_sum, aux_hash)

    # rand = TaggedHash("BIP0374/nonce", t || A || C || m)
    nonce_input = t + A_bytes + C_bytes
    if m is not None:
        nonce_input += m
    rand = ngu.hash.sha256t(DLEQ_TAG_NONCE_H, nonce_input, True)

    # k = int(rand) mod n
    k = int.from_bytes(rand, "big") % SECP256K1_ORDER
    if k == 0:
        raise ValueError("Generated nonce k is zero")

    # R1 = k*G, R2 = k*B
    k_bytes = k.to_bytes(32, "big")
    R1_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G, k_bytes)
    R2_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan, k_bytes)

    # e = TaggedHash("BIP0374/challenge", A || B || C || G || R1 || R2 || m)
    e = dleq_challenge(A_bytes, B_scan, C_bytes, R1_bytes, R2_bytes, m, _G=G)

    # s = (k + e*a) mod n
    s = (k + e * a_sum_int) % SECP256K1_ORDER

    # proof = e || s
    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")

    # Verify the proof before returning (sanity check)
    if not verify_dleq_proof(A_bytes, B_scan, C_bytes, proof, m):
        raise ValueError("Generated proof failed verification (internal error)")
    return proof


def verify_dleq_proof(A_sum_bytes, B_scan_bytes, ecdh_share_bytes, proof, m=None):
    """
    Verify DLEQ proof (BIP-374)

    Args:
        A_sum_bytes:       Input public key A (33-byte compressed)
        B_scan_bytes:      Scan public key B  (33-byte compressed)
        ecdh_share_bytes:  ECDH share point C (33-byte compressed)
        proof:             DLEQ proof         (64-byte: e || s)
        m:                 Optional message   (32-byte or None)

    Returns:
        bool: True if proof is valid, False otherwise
    """
    if len(proof) != 64:
        return False
    if m is not None and len(m) != 32:
        return False

    e_bytes = proof[:32]
    s_bytes = proof[32:]

    s = int.from_bytes(s_bytes, "big")
    if not (0 < s < SECP256K1_ORDER):
        return False

    # Reconstruct R1 = s*G - e*A
    # We compute this as s*G + (-e)*A using point negation
    sG = ngu.secp256k1.ec_pubkey_tweak_mul(G, s_bytes)
    eA = ngu.secp256k1.ec_pubkey_tweak_mul(A_sum_bytes, e_bytes)

    # Negate eA by flipping the y-coordinate (change 02<->03 prefix)
    eA_neg = bytearray(eA)
    eA_neg[0] = 0x03 if eA[0] == 0x02 else 0x02
    R1_bytes = ngu.secp256k1.ec_pubkey_combine([sG, bytes(eA_neg)])

    # Reconstruct R2 = s*B - e*C
    sB = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, s_bytes)
    eC = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, e_bytes)

    # Negate eC
    eC_neg = bytearray(eC)
    eC_neg[0] = 0x03 if eC[0] == 0x02 else 0x02
    R2_bytes = ngu.secp256k1.ec_pubkey_combine([sB, bytes(eC_neg)])

    # Recompute challenge e'
    e_check = dleq_challenge(A_sum_bytes, B_scan_bytes, ecdh_share_bytes, R1_bytes, R2_bytes, m, _G=G)

    # Verify e == e'
    e = int.from_bytes(e_bytes, "big")
    return e == e_check
