# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# dleq.py - DLEQ (Discrete Logarithm Equality) proofs for BIP-374
#
# Implements non-interactive zero-knowledge proofs that prove:
#   log_G(pubkey) = log_B(C)
# where:
#   - G is the secp256k1 generator
#   - pubkey = privkey * G (sender's public key)
#   - B is the recipient's scan key
#   - C = privkey * B (ECDH share)
#
# This proves the ECDH computation is correct without revealing the private key.
#
# BIP-374 specification: Uses tagged hashes for aux, nonce, and challenge.
#
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
        A_bytes: Public key A = a*G (33 bytes compressed)
        B_bytes: Scan public key B (33 bytes compressed)
        C_bytes: ECDH share C = a*B (33 bytes compressed)
        R1_bytes: Commitment R1 = k*G (33 bytes compressed)
        R2_bytes: Commitment R2 = k*B (33 bytes compressed)
        m: Optional message (32 bytes or None)
        G_bytes: Generator point G (33 bytes compressed)
    
    Returns:
        int: Challenge value e
    """
    # Default G if not provided
    if G_bytes is None:
        G_bytes = ngu.secp256k1.generator()
    
    # BIP-374: challenge = TaggedHash("BIP0374/challenge", A || B || C || G || R1 || R2 || m)
    challenge_input = A_bytes + B_bytes + C_bytes + G_bytes + R1_bytes + R2_bytes
    
    # Append message if provided
    if m is not None:
        challenge_input += m
    
    # Compute tagged hash
    challenge_hash = ngu.hash.sha256t(DLEQ_TAG_CHALLENGE_H, challenge_input, True)

    return int.from_bytes(challenge_hash, 'big')


def generate_dleq_proof(privkey_int, scan_pubkey_bytes, aux_rand=None, m=None):
    """
    Generate DLEQ proof that ecdh_share = privkey * scan_pubkey (BIP-374)
    
    Proves: log_G(A) = log_B(C)
    where A = privkey*G (pubkey) and C = privkey*B (ecdh_share)
    
    BIP-374 Protocol:
    1. t = a XOR TaggedHash("BIP0374/aux", r)  where r is aux_rand
    2. rand = TaggedHash("BIP0374/nonce", t || A || C || m)
    3. k = int(rand) mod n
    4. R1 = k*G, R2 = k*B
    5. e = TaggedHash("BIP0374/challenge", G || B || A || C || R1 || R2 || m)
    6. s = (k + e*a) mod n
    7. proof = e || s
    
    Args:
        privkey_int: Private key a (scalar)
        scan_pubkey_bytes: Scan public key B (33 bytes compressed)
        aux_rand: Auxiliary randomness r (32 bytes), if None uses hardware RNG
        m: Optional message (32 bytes or None)
    
    Returns:
        bytes: DLEQ proof (64 bytes: e || s)
    
    Raises:
        ValueError: If inputs are invalid
    """
    # Validate inputs
    if not isinstance(privkey_int, int) or privkey_int <= 0:
        raise ValueError("Invalid private key")
    
    if len(scan_pubkey_bytes) != 33:
        raise ValueError("Invalid scan pubkey length")
    
    if m is not None and len(m) != 32:
        raise ValueError("Message must be 32 bytes")

    # Validate scan_pubkey is a valid point
    try:
        ngu.secp256k1.pubkey(scan_pubkey_bytes)
    except:
        raise ValueError("Invalid elliptic curve point")
    
    # Validate privkey is in valid range
    if privkey_int >= ngu.secp256k1.curve_order_int():
        raise ValueError("Private key must be less than curve order")

    # Compute public key A = a*G
    G_bytes = ngu.secp256k1.generator()
    privkey_bytes = privkey_int.to_bytes(32, 'big')
    A_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey_bytes)
    
    # Compute ECDH share C = a*B (this is what we're proving knowledge of)
    C_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(scan_pubkey_bytes, privkey_bytes)
    
    # Generate aux_rand if not provided
    if aux_rand is None:
        import ckcc
        aux_rand = bytearray(32)
        ckcc.rng_bytes(aux_rand)
        aux_rand = bytes(aux_rand)
    else:
        if len(aux_rand) != 32:
            raise ValueError("aux_rand must be 32 bytes")
    
    # Step 1: t = a XOR TaggedHash("BIP0374/aux", r)
    aux_hash = ngu.hash.sha256t(DLEQ_TAG_AUX_H, aux_rand, True)
    t = xor_bytes(privkey_bytes, aux_hash)
    
    # Step 2: rand = TaggedHash("BIP0374/nonce", t || A || C || m)
    nonce_input = t + A_bytes + C_bytes
    if m is not None:
        nonce_input += m
    rand = ngu.hash.sha256t(DLEQ_TAG_NONCE_H, nonce_input, True)
    
    # Step 3: k = int(rand) mod n
    k = int.from_bytes(rand, 'big') % ngu.secp256k1.curve_order_int()
    if k == 0:
        raise ValueError("Generated nonce k is zero (extremely unlikely)")
    
    # Step 4: R1 = k*G, R2 = k*B
    k_bytes = k.to_bytes(32, 'big')
    R1_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, k_bytes)
    R2_bytes = ngu.secp256k1.ec_pubkey_tweak_mul(scan_pubkey_bytes, k_bytes)
    
    # Step 5: e = dleq_challenge(A, B, C, R1, R2, m, G)
    e = dleq_challenge(A_bytes, scan_pubkey_bytes, C_bytes, R1_bytes, R2_bytes, m, G_bytes)
    
    # Step 6: s = (k + e*a) mod n  [NOTE: BIP-374 uses + not -]
    s = (k + e * privkey_int) % ngu.secp256k1.curve_order_int()
    
    # Step 7: proof = e || s
    proof = e.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    
    # Verify the proof before returning (sanity check)
    if not verify_dleq_proof(A_bytes, scan_pubkey_bytes, C_bytes, proof, m=m):
        raise ValueError("Generated proof failed verification (internal error)")
    
    return proof


def verify_dleq_proof(pubkey_bytes, scan_pubkey_bytes, ecdh_share_bytes, proof, m=None):
    """
    Verify DLEQ proof (BIP-374)
    
    Verifies that the prover knows a value a such that:
    - A = a * G (pubkey)
    - C = a * B (ecdh_share)
    
    without revealing a (the private key).
    
    BIP-374 Verification:
    1. Parse proof as (e, s)
    2. R1 = s*G - e*A
    3. R2 = s*B - e*C
    4. e' = TaggedHash("BIP0374/challenge", G || B || A || C || R1 || R2 || m)
    5. Verify e == e'
    
    Args:
        pubkey_bytes: Public key A (33 bytes compressed)
        scan_pubkey_bytes: Scan public key B (33 bytes compressed)
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
        ngu.secp256k1.pubkey(pubkey_bytes)
        ngu.secp256k1.pubkey(scan_pubkey_bytes)
        ngu.secp256k1.pubkey(ecdh_share_bytes)
    except:
        # Invalid points
        return False

    # Get generator point
    G_bytes = ngu.secp256k1.generator()

    # Reconstruct R1 = s*G - e*A
    # We compute this as s*G + (-e)*A using point negation
    sG = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, s_bytes)
    eA = ngu.secp256k1.ec_pubkey_tweak_mul(pubkey_bytes, e_bytes)
    # Negate eA by flipping the y-coordinate (change 02<->03 prefix)
    eA_neg = bytearray(eA)
    eA_neg[0] = 0x03 if eA[0] == 0x02 else 0x02
    R1_bytes = ngu.secp256k1.ec_pubkey_combine(sG, bytes(eA_neg))
    
    # Reconstruct R2 = s*B - e*C
    sB = ngu.secp256k1.ec_pubkey_tweak_mul(scan_pubkey_bytes, s_bytes)
    eC = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share_bytes, e_bytes)
    # Negate eC
    eC_neg = bytearray(eC)
    eC_neg[0] = 0x03 if eC[0] == 0x02 else 0x02
    R2_bytes = ngu.secp256k1.ec_pubkey_combine(sB, bytes(eC_neg))
    
    # Recompute challenge e'
    e_check = dleq_challenge(pubkey_bytes, scan_pubkey_bytes, ecdh_share_bytes, 
                             R1_bytes, R2_bytes, m, G_bytes)
    
    # Verify e == e'
    e = int.from_bytes(e_bytes, 'big')
    return e == e_check