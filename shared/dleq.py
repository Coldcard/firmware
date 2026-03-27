# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# dleq.py - DLEQ (Discrete Logarithm Equality) proofs for BIP-374
#
# Implements non-interactive zero-knowledge proofs that prove:
#   log_G(A) = log_B(C)
# where:
#   - G is the secp256k1 generator
#   - A = a*G (sender's public key)
#   - B = (recipient's scan key)
#   - C = a*B (ECDH share)
#
# This proves the ECDH computation is correct without revealing the private key.
#
import ckcc
import ngu
from precomp_tag_hash import DLEQ_TAG_AUX_H, DLEQ_TAG_NONCE_H, DLEQ_TAG_CHALLENGE_H


def xor_bytes(a, b):
    """XOR two byte strings of equal length"""
    assert len(a) == len(b), "Byte strings must be equal length"
    return bytes(x ^ y for x, y in zip(a, b))


def dleq_challenge(A_bytes, B_bytes, C_bytes, R1_bytes, R2_bytes, m=None, G_bytes=None):
    """
    Compute DLEQ challenge using BIP-374 tagged hash
    
    Args:
        A_bytes: A_sum,      A = a*G (33 bytes compressed)
        B_bytes: B_scan,     B = scan public key (33 bytes compressed)
        C_bytes: C_ecdh,     C = a*B (33 bytes compressed)
        R1_bytes: Commitment R1 = k*G (33 bytes compressed)
        R2_bytes: Commitment R2 = k*B (33 bytes compressed)
        m: Optional message (32 bytes or None)
        G_bytes: Generator point G (33 bytes compressed)
    
    Returns:
        int: Challenge value e
    """
    # BIP-374: e = TaggedHash("BIP0374/challenge", cbytes(A) || cbytes(B) || cbytes(C) || cbytes(G) || cbytes(R1) || cbytes(R2) || m)
    challenge_input = A_bytes + B_bytes + C_bytes + G_bytes + R1_bytes + R2_bytes

    # Append message if provided
    if m is not None:
        challenge_input += m

    challenge_hash = ngu.hash.sha256t(DLEQ_TAG_CHALLENGE_H, challenge_input, True)
    return int.from_bytes(challenge_hash, 'big')


def generate_dleq_proof(a_sum_scalar, B_scan, aux_rand=None, m=None):
    """
    Generate DLEQ proof (BIP-374)
    
    Args:
        a_sum_scalar: Input private key a (scalar)
        B_scan:       Scan public key B (33 bytes compressed)
        aux_rand:     Auxiliary randomness r (32 bytes), if None uses hardware RNG
        m:            Optional message (32 bytes or None)
    
    Returns:
        bytes: DLEQ proof (64 bytes: e || s)
    
    Raises:
        ValueError: If inputs are invalid
    """
    # Validate inputs
    if not isinstance(a_sum_scalar, int) or a_sum_scalar <= 0:
        raise ValueError("Invalid private key")
    
    if len(B_scan) != 33:
        raise ValueError("Invalid scan pubkey length")
    
    if m is not None and len(m) != 32:
        raise ValueError("Message must be 32 bytes")

    # Validate scan_pubkey is a valid point
    try:
        ngu.secp256k1.pubkey(B_scan)
    except Exception:
        raise ValueError("Invalid elliptic curve point")
    
    # Validate privkey is in valid range
    if a_sum_scalar >= ngu.secp256k1.curve_order_int():
        raise ValueError("Private key must be less than curve order")

    # Compute public key A = a*G
    G_bytes = ngu.secp256k1.generator()
    privkey_bytes = a_sum_scalar.to_bytes(32, 'big')
    A_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey_bytes)
    
    # Compute ECDH share C = a*B (this is what we're proving knowledge of)
    C_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan, privkey_bytes)
    
    # Generate aux_rand if not provided
    if aux_rand is None:
        aux_rand = bytearray(32)
        ckcc.rng_bytes(aux_rand)
        aux_rand = bytes(aux_rand)
    else:
        if len(aux_rand) != 32:
            raise ValueError("aux_rand must be 32 bytes")
    
    # t = a XOR TaggedHash("BIP0374/aux", r)
    aux_hash = ngu.hash.sha256t(DLEQ_TAG_AUX_H, aux_rand, True)
    del aux_rand
    t = xor_bytes(privkey_bytes, aux_hash)
    
    # rand = TaggedHash("BIP0374/nonce", t || A || C || m)
    nonce_input = t + A_bytes + C_bytes
    if m is not None:
        nonce_input += m
    rand = ngu.hash.sha256t(DLEQ_TAG_NONCE_H, nonce_input, True)
    
    # k = int(rand) mod n
    k = int.from_bytes(rand, 'big') % ngu.secp256k1.curve_order_int()
    if k == 0:
        raise ValueError("Generated nonce k is zero (extremely unlikely)")
    
    # R1 = k*G, R2 = k*B
    k_bytes = k.to_bytes(32, 'big')
    R1_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, k_bytes)
    R2_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan, k_bytes)
    
    # e = TaggedHash("BIP0374/challenge", A || B || C || G || R1 || R2 || m)
    e = dleq_challenge(A_bytes, B_scan, C_bytes, R1_bytes, R2_bytes, m, G_bytes)
    
    # s = (k + e*a) mod n
    s = (k + e * a_sum_scalar) % ngu.secp256k1.curve_order_int()
    
    # proof = e || s
    proof = e.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    
    # Verify the proof before returning (sanity check)
    if not verify_dleq_proof(A_bytes, B_scan, C_bytes, proof, m=m):
        raise ValueError("Generated proof failed verification (internal error)")
    return proof


def verify_dleq_proof(A_sum_bytes, B_scan_bytes, ecdh_share_bytes, proof, m=None):
    """
    Verify DLEQ proof (BIP-374)
    
    Verifies that the prover knows a value a such that:
    - A = a * G (pubkey)
    - C = a * B (ecdh_share)
    without revealing a (the private key).
    
    Args:
        A_sum_bytes: Input public key A (33 bytes compressed)
        B_scan_bytes: Scan public key B (33 bytes compressed)
        ecdh_share_bytes: ECDH share C (33 bytes compressed)
        proof: DLEQ proof (64 bytes: e || s)
        m: Optional message (32 bytes or None)
    
    Returns:
        bool: True if proof is valid, False otherwise
    """
    # Validate proof length
    if len(proof) != 64:
        return False
    
    if m is not None and len(m) != 32:
        return False
    
    # Parse proof
    e_bytes = proof[:32]
    s_bytes = proof[32:]

    try:
        # Validate scalars are in valid range
        s = int.from_bytes(s_bytes, 'big')
        if s >= ngu.secp256k1.curve_order_int():
            return False
        # Note: e can be >= n since it's a hash output reduced mod n
        
        # Validate points
        ngu.secp256k1.pubkey(A_sum_bytes)
        ngu.secp256k1.pubkey(B_scan_bytes)
        ngu.secp256k1.pubkey(ecdh_share_bytes)
    except Exception:
        # Invalid points
        return False

    # Get generator point
    G_bytes = ngu.secp256k1.generator()

    # Reconstruct R1 = s*G - e*A
    # We compute this as s*G + (-e)*A using point negation
    sG = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, s_bytes)
    eA = ngu.secp256k1.ec_pubkey_tweak_mul(A_sum_bytes, e_bytes)
    # Negate eA by flipping the y-coordinate (change 02<->03 prefix)
    eA_neg = bytearray(eA)
    eA_neg[0] = 0x03 if eA[0] == 0x02 else 0x02
    R1_bytes = ngu.secp256k1.ec_pubkey_combine(sG, bytes(eA_neg))
    
    # Reconstruct R2 = s*B - e*C
    sB = ngu.secp256k1.ec_pubkey_tweak_mul(B_scan_bytes, s_bytes)
    eC = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, e_bytes)
    # Negate eC
    eC_neg = bytearray(eC)
    eC_neg[0] = 0x03 if eC[0] == 0x02 else 0x02
    R2_bytes = ngu.secp256k1.ec_pubkey_combine(sB, bytes(eC_neg))
    
    # Recompute challenge e'
    e_check = dleq_challenge(A_sum_bytes, B_scan_bytes, ecdh_share_bytes, 
                             R1_bytes, R2_bytes, m, G_bytes)
    
    # Verify e == e'
    e = int.from_bytes(e_bytes, 'big')
    return e == e_check