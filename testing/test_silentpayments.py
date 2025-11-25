# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_silentpayments.py - Unit tests for BIP-375 Silent Payments implementation
#
# Tests the cryptographic primitives and PSBT field handling for BIP-352/BIP-375
#
from binascii import unhexlify

# Import modules to test
import sys
# Do NOT add shared to path here to avoid shadowing stdlib random
# sys.path.insert(0, '../shared')

# Import ngu wrapper to provide access to the ngu C library
import ngu_wrapper
sys.modules['ngu'] = ngu_wrapper.ngu

# Import micropython compatibility shims
# This imports secrets -> random (stdlib)
import micropython_compat

# Now add shared to path to import firmware modules
sys.path.insert(0, '../shared')

from dleq import generate_dleq_proof, verify_dleq_proof
from silentpayments import (
    compute_ecdh_share,
    compute_shared_secret_tweak,
    derive_silent_payment_output_pubkey,
    apply_label_to_spend_key,
    pubkey_to_p2tr_script,
    combine_pubkeys,
)


class TestBIP352Crypto:
    """Test BIP-352 cryptographic primitives"""
    
    def test_ecdh_share_computation(self):
        """Test ECDH share computation"""
        # Test vector: privkey * scan_pubkey should produce valid ECDH share
        privkey = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        
        # Compressed public key (33 bytes)
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Compute ECDH share
        ecdh_share = compute_ecdh_share(privkey, scan_pubkey)
        
        # Verify it's a valid compressed point (33 bytes, starts with 02 or 03)
        assert len(ecdh_share) == 33
        assert ecdh_share[0] in (0x02, 0x03)
    
    def test_shared_secret_tweak(self):
        """Test shared secret tweak computation"""
        # Test that different output indices produce different tweaks
        ecdh_share = unhexlify('03ccffacf309a1570d01449966bbc0f876d23ee929e88a68968e0a606e31efcc35')
        
        tweak_0 = compute_shared_secret_tweak(ecdh_share, 0)
        tweak_1 = compute_shared_secret_tweak(ecdh_share, 1)
        tweak_2 = compute_shared_secret_tweak(ecdh_share, 2)
        
        # All tweaks should be different
        assert tweak_0 != tweak_1
        assert tweak_1 != tweak_2
        assert tweak_0 != tweak_2
        
        # All should be valid scalars (integers)
        assert isinstance(tweak_0, int)
        assert isinstance(tweak_1, int)
        assert isinstance(tweak_2, int)
    
    def test_output_pubkey_derivation(self):
        """Test silent payment output pubkey derivation"""
        spend_pubkey = unhexlify('03453655039739c41ccb553336f2c0673797f712a754b2032d5f6ad0e2b50bcace')
        ecdh_share = unhexlify('03ccffacf309a1570d01449966bbc0f876d23ee929e88a68968e0a606e31efcc35')
        
        # Derive output pubkeys for different indices
        output_pk_0 = derive_silent_payment_output_pubkey(spend_pubkey, ecdh_share, 0)
        output_pk_1 = derive_silent_payment_output_pubkey(spend_pubkey, ecdh_share, 1)
        
        # Should be valid compressed points
        assert len(output_pk_0) == 33
        assert len(output_pk_1) == 33
        assert output_pk_0[0] in (0x02, 0x03)
        assert output_pk_1[0] in (0x02, 0x03)
        
        # Should be different
        assert output_pk_0 != output_pk_1
    
    def test_p2tr_script_generation(self):
        """Test P2TR scriptPubKey generation"""
        pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        script = pubkey_to_p2tr_script(pubkey)
        
        # P2TR scriptPubKey: OP_1 (0x51) + 0x20 (32 bytes) + x-only pubkey
        assert len(script) == 34
        assert script[0] == 0x51  # OP_1
        assert script[1] == 0x20  # 32 bytes
        # Rest should be x-only pubkey (dropping the 02/03 prefix)
        assert script[2:] == pubkey[1:]


class TestDLEQProofs:
    """Test DLEQ proof generation and verification"""

    def test_proof_generation_and_verification(self):
        """Test that generated proofs verify correctly"""
        import ngu

        privkey = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Generate DLEQ proof (computes C internally)
        proof = generate_dleq_proof(privkey, scan_pubkey)
        
        # Proof should be 64 bytes (e || s)
        assert len(proof) == 64
        
        # Compute public key for verification (pubkey = privkey * G)
        G_bytes = ngu.secp256k1.generator()
        privkey_bytes = privkey.to_bytes(32, 'big')
        pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey_bytes)
        
        # Compute ECDH share (for verification)
        ecdh_share = compute_ecdh_share(privkey, scan_pubkey)

        # Verify proof
        assert verify_dleq_proof(pubkey, scan_pubkey, ecdh_share, proof)
    
    def test_proof_verification_rejects_invalid(self):
        """Test that invalid proofs are rejected"""
        import ngu
        
        privkey = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Generate valid proof (computes C internally)
        proof = generate_dleq_proof(privkey, scan_pubkey)

        G_bytes = ngu.secp256k1.generator()
        privkey_bytes = privkey.to_bytes(32, 'big')
        pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey_bytes)
        
        ecdh_share = compute_ecdh_share(privkey, scan_pubkey)
        
        # Valid proof should verify
        assert verify_dleq_proof(pubkey, scan_pubkey, ecdh_share, proof)
        
        # Tampered proof should fail
        tampered_proof = bytearray(proof)
        tampered_proof[0] ^= 0xFF  # Flip some bits
        assert not verify_dleq_proof(pubkey, scan_pubkey, ecdh_share, bytes(tampered_proof))
        
        # Wrong ECDH share should fail
        wrong_ecdh = unhexlify(
            '02' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        )
        assert not verify_dleq_proof(pubkey, scan_pubkey, wrong_ecdh, proof)
    
    def test_deterministic_proof_with_aux_rand(self):
        """Test that proofs are deterministic when using aux_rand"""
        import ngu
        
        privkey = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        ecdh_share = compute_ecdh_share(privkey, scan_pubkey)
        
        aux_rand = b'\x00' * 32
        
        # Generate proof twice with same aux_rand (computes C internally)
        proof1 = generate_dleq_proof(privkey, scan_pubkey, aux_rand)
        proof2 = generate_dleq_proof(privkey, scan_pubkey, aux_rand)
        
        # Should be identical (deterministic)
        assert proof1 == proof2


class TestPrecomputedTagHashes:
    """Test that precomputed tagged hash values are correct"""

    def test_all_dleq_tags(self):
        """Verify all BIP-374 DLEQ tag hashes at once"""
        from hashlib import sha256
        from precomp_tag_hash import DLEQ_TAG_AUX_H, DLEQ_TAG_NONCE_H, DLEQ_TAG_CHALLENGE_H
        
        # Define expected tags and their precomputed values
        tags = {
            'BIP0374/aux': DLEQ_TAG_AUX_H,
            'BIP0374/nonce': DLEQ_TAG_NONCE_H,
            'BIP0374/challenge': DLEQ_TAG_CHALLENGE_H,
        }
        
        # Verify each tag
        for tag_str, precomputed in tags.items():
            expected = sha256(tag_str.encode()).digest()
            assert precomputed == expected, \
                f"Tag '{tag_str}' mismatch: expected {expected.hex()}, got {precomputed.hex()}"


class TestPSBTFieldConstants:
    """Test that PSBT field constants are correctly imported"""
    
    def test_constants_imported(self):
        """Verify BIP-375 PSBT field constants are available"""
        from public_constants import (
            PSBT_GLOBAL_SP_ECDH_SHARE,
            PSBT_GLOBAL_SP_DLEQ,
            PSBT_IN_SP_ECDH_SHARE,
            PSBT_IN_SP_DLEQ,
            PSBT_OUT_SP_V0_INFO,
            PSBT_OUT_SP_V0_LABEL,
        )
        
        # Verify the values match BIP-375 specification
        assert PSBT_GLOBAL_SP_ECDH_SHARE == 0x07
        assert PSBT_GLOBAL_SP_DLEQ == 0x08
        assert PSBT_IN_SP_ECDH_SHARE == 0x1d
        assert PSBT_IN_SP_DLEQ == 0x1e
        assert PSBT_OUT_SP_V0_INFO == 0x09
        assert PSBT_OUT_SP_V0_LABEL == 0x0a


class TestBIP352Fixes:
    """Test BIP-352 fixes (input hash, tagged hashes, endianness)"""
    
    def test_tagged_hash_constants(self):
        """Verify BIP-352 tagged hash constants"""
        from precomp_tag_hash import BIP352_SHARED_SECRET_TAG_H, BIP352_INPUTS_TAG_H, BIP352_LABEL_TAG_H
        from hashlib import sha256
        
        # Verify SharedSecret tag hash
        expected_shared_secret = sha256(b"BIP0352/SharedSecret").digest()
        assert BIP352_SHARED_SECRET_TAG_H == expected_shared_secret
        
        # Verify Inputs tag hash
        expected_inputs = sha256(b"BIP0352/Inputs").digest()
        assert BIP352_INPUTS_TAG_H == expected_inputs

        # Verify Label tag hash
        expected_label = sha256(b"BIP0352/Label").digest()
        assert BIP352_LABEL_TAG_H == expected_label
    
    def test_input_hash_computation(self):
        """Test input hash computation"""
        from silentpayments import compute_input_hash
        
        # Example outpoints
        outpoints = [
            (unhexlify('0000000000000000000000000000000000000000000000000000000000000001'), b'\x00\x00\x00\x00'),
            (unhexlify('0000000000000000000000000000000000000000000000000000000000000002'), b'\x00\x00\x00\x01'),
        ]
        summed_pubkey = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        
        input_hash = compute_input_hash(outpoints, summed_pubkey)
        
        assert isinstance(input_hash, int)
        assert input_hash > 0
        
        # Verify sorting affects hash (should be sorted internally)
        outpoints_rev = outpoints[::-1]
        input_hash_rev = compute_input_hash(outpoints_rev, summed_pubkey)
        assert input_hash == input_hash_rev
    
    def test_output_derivation_with_input_hash(self):
        """Test output derivation with input hash application"""

        spend_pubkey = unhexlify('03453655039739c41ccb553336f2c0673797f712a754b2032d5f6ad0e2b50bcace')
        ecdh_share = unhexlify('03ccffacf309a1570d01449966bbc0f876d23ee929e88a68968e0a606e31efcc35')
        
        # Compute input hash
        outpoints = [(b'\x00'*32, b'\x00\x00\x00\x00')]
        summed_pubkey = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        from silentpayments import compute_input_hash
        input_hash = compute_input_hash(outpoints, summed_pubkey)
        
        # Derive with and without input hash
        pk_no_hash = derive_silent_payment_output_pubkey(spend_pubkey, ecdh_share, 0)
        pk_with_hash = derive_silent_payment_output_pubkey(spend_pubkey, ecdh_share, 0, input_hash=input_hash)
        
        # Should be different
        assert pk_no_hash != pk_with_hash
        
        # Should be valid pubkeys
        assert len(pk_with_hash) == 33
        assert pk_with_hash[0] in (0x02, 0x03)


class TestMultiSigSilentPayments:
    """Test multi-signature Silent Payment scenarios"""
    
    def test_ecdh_share_combination(self):
        """Test combining ECDH shares from multiple signers"""
        import ngu
        
        # Two signers with different private keys
        privkey1 = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        privkey2 = 0xb6488e56225c1317f7884e342972edf9d15f24951be118e8e833b4a2921222d4
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Each signer computes their ECDH share
        ecdh_share1 = compute_ecdh_share(privkey1, scan_pubkey)
        ecdh_share2 = compute_ecdh_share(privkey2, scan_pubkey)
        
        # Combine shares using point addition
        combined_share = ngu.secp256k1.ec_pubkey_combine(ecdh_share1, ecdh_share2)
        
        # Verify combined share is valid
        assert len(combined_share) == 33
        assert combined_share[0] in (0x02, 0x03)
        
        # Combined share should be different from individual shares
        assert combined_share != ecdh_share1
        assert combined_share != ecdh_share2
        
        # Verify combined share equals (privkey1 + privkey2) * scan_pubkey
        combined_privkey = (privkey1 + privkey2) % ngu.secp256k1.curve_order_int()
        expected_combined = compute_ecdh_share(combined_privkey, scan_pubkey)
        assert combined_share == expected_combined
    
    def test_dleq_verification_multisig(self):
        """Test DLEQ proof verification in multi-sig scenario"""
        import ngu
        
        # Signer 1
        privkey1 = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Signer 1 generates proof
        proof1 = generate_dleq_proof(privkey1, scan_pubkey)
        ecdh_share1 = compute_ecdh_share(privkey1, scan_pubkey)
        
        # Compute pubkey1 for verification
        G_bytes = ngu.secp256k1.generator()
        privkey1_bytes = privkey1.to_bytes(32, 'big')
        pubkey1 = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey1_bytes)
        
        # Signer 2 verifies signer 1's proof
        assert verify_dleq_proof(pubkey1, scan_pubkey, ecdh_share1, proof1)
        
        # Signer 2
        privkey2 = 0xb6488e56225c1317f7884e342972edf9d15f24951be118e8e833b4a2921222d4
        
        # Signer 2 generates proof
        proof2 = generate_dleq_proof(privkey2, scan_pubkey)
        ecdh_share2 = compute_ecdh_share(privkey2, scan_pubkey)
        
        # Compute pubkey2 for verification
        privkey2_bytes = privkey2.to_bytes(32, 'big')
        pubkey2 = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey2_bytes)
        
        # Signer 1 verifies signer 2's proof
        assert verify_dleq_proof(pubkey2, scan_pubkey, ecdh_share2, proof2)
        
        # Both proofs should be valid independently
        assert len(proof1) == 64
        assert len(proof2) == 64
    
    def test_partial_signing_workflow(self):
        """Test the workflow of partial signing in multi-sig"""
        import ngu
        
        # Scenario: 2-of-3 multisig
        privkeys = [
            0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073,
            0xb6488e56225c1317f7884e342972edf9d15f24951be118e8e833b4a2921222d4,
            0xc7599f67336d2428f8995f453a83fefae26f35a62cf229f9f944c5b3a32333e5,
        ]
        
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Step 1: Each signer computes their ECDH share and proof
        shares = []
        proofs = []
        pubkeys = []
        
        G_bytes = ngu.secp256k1.generator()
        
        for privkey in privkeys:
            ecdh_share = compute_ecdh_share(privkey, scan_pubkey)
            proof = generate_dleq_proof(privkey, scan_pubkey)
            
            privkey_bytes = privkey.to_bytes(32, 'big')
            pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey_bytes)
            
            shares.append(ecdh_share)
            proofs.append(proof)
            pubkeys.append(pubkey)
        
        # Step 2: Verify all proofs
        for i in range(len(privkeys)):
            assert verify_dleq_proof(pubkeys[i], scan_pubkey, shares[i], proofs[i])
        
        # Step 3: Combine shares from 2 signers (2-of-3)
        combined_share = ngu.secp256k1.ec_pubkey_combine(shares[0], shares[1])
        
        # Step 4: Use combined share to derive output
        spend_pubkey = unhexlify('03453655039739c41ccb553336f2c0673797f712a754b2032d5f6ad0e2b50bcace')
        output_pubkey = derive_silent_payment_output_pubkey(spend_pubkey, combined_share, 0)
        
        # Verify output is valid
        assert len(output_pubkey) == 33
        assert output_pubkey[0] in (0x02, 0x03)
        
        # Verify that using all 3 signers produces different output
        combined_share_all = ngu.secp256k1.ec_pubkey_combine(
            combined_share, shares[2]
        )
        output_pubkey_all = derive_silent_payment_output_pubkey(spend_pubkey, combined_share_all, 0)
        
        # Different number of signers = different output
        assert output_pubkey != output_pubkey_all
    
    def test_invalid_proof_rejection_multisig(self):
        """Test that invalid proofs are rejected in multi-sig"""
        import ngu
        
        privkey1 = 0xa5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073
        privkey2 = 0xb6488e56225c1317f7884e342972edf9d15f24951be118e8e833b4a2921222d4
        
        scan_pubkey = unhexlify('03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629')
        
        # Signer 1 generates valid proof
        proof1 = generate_dleq_proof(privkey1, scan_pubkey)
        ecdh_share1 = compute_ecdh_share(privkey1, scan_pubkey)
        
        G_bytes = ngu.secp256k1.generator()
        privkey1_bytes = privkey1.to_bytes(32, 'big')
        pubkey1 = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey1_bytes)
        
        # Valid proof verifies
        assert verify_dleq_proof(pubkey1, scan_pubkey, ecdh_share1, proof1)
        
        # Signer 2 tries to use signer 1's proof with their own share (fraud attempt)
        ecdh_share2 = compute_ecdh_share(privkey2, scan_pubkey)
        privkey2_bytes = privkey2.to_bytes(32, 'big')
        pubkey2 = ngu.secp256k1.ec_pubkey_tweak_mul(G_bytes, privkey2_bytes)
        
        # Should fail - proof doesn't match pubkey/share combination
        assert not verify_dleq_proof(pubkey2, scan_pubkey, ecdh_share2, proof1)
        assert not verify_dleq_proof(pubkey1, scan_pubkey, ecdh_share2, proof1)
        assert not verify_dleq_proof(pubkey2, scan_pubkey, ecdh_share1, proof1)


class TestBIP352AddressEncoding:
    """Test BIP-352 Silent Payment address encoding using ngu.codecs.bip352_encode"""
    
    def test_basic_encoding(self):
        """Test basic Silent Payment address encoding"""
        import ngu
        
        # Create test keys (33-byte compressed pubkeys)
        scan_key = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        spend_key = unhexlify('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
        
        # Encode with default version (0) and mainnet HRP
        address = ngu.codecs.bip352_encode('sp', scan_key, spend_key)
        
        # Verify address format
        assert isinstance(address, str)
        assert address.startswith('sp1q')  # sp + 1 + q (version 0 in bech32m)
        # Length: hrp(2) + separator(1) + version+data(107) + checksum(6) = 116
        assert len(address) == 116
    
    def test_testnet_encoding(self):
        """Test testnet Silent Payment address encoding"""
        import ngu
        
        scan_key = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        spend_key = unhexlify('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
        
        # Encode for testnet
        address = ngu.codecs.bip352_encode('tsp', scan_key, spend_key)
        
        assert address.startswith('tsp1q')
        # Length: hrp(3) + separator(1) + version+data(107) + checksum(6) = 117
        assert len(address) == 117
    
    def test_version_parameter(self):
        """Test version parameter encoding and boundaries"""
        import ngu

        scan_key = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        spend_key = unhexlify('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')

        # Default version should match explicit v0
        address_default = ngu.codecs.bip352_encode('sp', scan_key, spend_key)
        address_v0 = ngu.codecs.bip352_encode('sp', scan_key, spend_key, 0)
        assert address_v0 == address_default

        # Version 0 should have 'q' character (0 in bech32 charset)
        assert address_v0[3] == 'q'

        # Test valid version boundaries (0-31 per BIP-352)
        version_addresses = {}
        for version in [0, 1, 15, 30, 31]:
            addr = ngu.codecs.bip352_encode('sp', scan_key, spend_key, version)
            assert isinstance(addr, str)
            assert addr.startswith('sp1')
            version_addresses[version] = addr

        # Different versions should produce different addresses
        assert version_addresses[0] != version_addresses[1]
        assert version_addresses[1] != version_addresses[31]

        # Test invalid versions (boundary violations)
        invalid_versions = [32, 33, 100, -1, -10]
        for invalid_version in invalid_versions:
            try:
                ngu.codecs.bip352_encode('sp', scan_key, spend_key, invalid_version)
                assert False, f"Should have raised ValueError for version {invalid_version}"
            except ValueError as e:
                assert 'version must be 0-31' in str(e)
    
    def test_different_keys_produce_different_addresses(self):
        """Test that different keys produce different addresses"""
        import ngu
        
        scan_key1 = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        scan_key2 = unhexlify('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
        spend_key = unhexlify('021b8c93100d35bd448f4646cc4678f278351b439b52b303ea31ec97b6eda4116f')
        
        address1 = ngu.codecs.bip352_encode('sp', scan_key1, spend_key)
        address2 = ngu.codecs.bip352_encode('sp', scan_key2, spend_key)
        
        assert address1 != address2
        
        # Also test different spend keys
        spend_key2 = unhexlify('03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556')
        address3 = ngu.codecs.bip352_encode('sp', scan_key1, spend_key2)
        
        assert address1 != address3
        assert address2 != address3
    
    def test_invalid_key_sizes(self):
        """Test that invalid key sizes are rejected"""
        import ngu

        scan_key = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

        # Test cases: (key_hex, description)
        invalid_keys = [
            ('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '32-byte key'),  # Missing compression byte
            ('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ff', '34-byte key'),  # Too long
            ('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16', '28-byte key'),  # Too short
            ('', '0-byte key'),  # Empty
        ]

        for key_hex, description in invalid_keys:
            try:
                invalid_key = unhexlify(key_hex) if key_hex else b''
                ngu.codecs.bip352_encode('sp', scan_key, invalid_key)
                assert False, f"Should have raised ValueError for {description}"
            except ValueError as e:
                assert '33 bytes' in str(e), f"Expected '33 bytes' in error for {description}, got: {e}"
    
    def test_uncompressed_key_rejection(self):
        """Test that uncompressed pubkeys are rejected"""
        import ngu

        scan_key = unhexlify('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

        # 65-byte uncompressed key (04 prefix + 64 bytes)
        uncompressed_key = unhexlify(
            '04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
            '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
        )

        try:
            ngu.codecs.bip352_encode('sp', scan_key, uncompressed_key)
            assert False, "Should have raised ValueError for 65-byte uncompressed key"
        except ValueError as e:
            assert '33 bytes' in str(e)


if __name__ == '__main__':
    # Run tests manually
    import sys
    
    test_classes = [
        TestBIP352Crypto(),
        TestDLEQProofs(),
        TestPrecomputedTagHashes(),
        TestPSBTFieldConstants(),
        TestBIP352Fixes(),
        TestMultiSigSilentPayments(),
        TestBIP352AddressEncoding(),
    ]
    
    failed = 0
    passed = 0
    
    for test_class in test_classes:
        class_name = test_class.__class__.__name__
        print(f"\n{'='*60}")
        print(f"Running {class_name}")
        print('='*60)
        
        for method_name in dir(test_class):
            if method_name.startswith('test_'):
                try:
                    print(f"  {method_name}...", end=' ')
                    method = getattr(test_class, method_name)
                    method()
                    print("✓ PASSED")
                    passed += 1
                except Exception as e:
                    print(f"✗ FAILED: {e}")
                    failed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print('='*60)
    
    sys.exit(0 if failed == 0 else 1)
