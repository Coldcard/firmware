# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Unit tests for BIP-352/BIP-375 Silent Payments implementation
# Runs inside the simulator via sim_execfile('devtest/unit_silentpayments.py')
# Success = no output; failure = assertion traceback
#
import ngu
from ubinascii import unhexlify as a2b_hex
from uhashlib import sha256

from dleq import generate_dleq_proof, verify_dleq_proof
from exceptions import FatalPSBTIssue
from silentpayments import (
    _compute_ecdh_share,
    _compute_input_hash,
    _combine_pubkeys,
    _compute_shared_secret_tweak,
    _compute_silent_payment_output_script,
    _is_p2pkh,
    _is_p2wpkh,
    _is_p2tr,
    _is_p2sh,
    NUMS_H,
    SilentPaymentsMixin,
)
from precomp_tag_hash import (
    BIP352_SHARED_SECRET_TAG_H,
    BIP352_INPUTS_TAG_H,
    BIP352_LABEL_TAG_H,
    DLEQ_TAG_AUX_H,
    DLEQ_TAG_NONCE_H,
    DLEQ_TAG_CHALLENGE_H,
)
from public_constants import (
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_PRIVKEY = a2b_hex("a5377d45114b0206f6773e231861ece8c04e13840ab007df6722a3508211c073")
TEST_PRIVKEY2 = a2b_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
TEST_SCAN_KEY = a2b_hex("03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629")
TEST_SPEND_KEY = a2b_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
MY_XFP = 0x12345678
TEST_DERIV_OURS = (MY_XFP, 44, 0, 0, 0)
FOREIGN_XFP = 0xDEADBEEF
G = ngu.secp256k1.generator()
P2WPKH_SPK = b"\x00\x14" + b"\xab" * 20

# ---------------------------------------------------------------------------
# BIP-352 Crypto Primitives
# ---------------------------------------------------------------------------

# ECDH share computation
ecdh_share = _compute_ecdh_share(TEST_PRIVKEY, TEST_SCAN_KEY)
assert len(ecdh_share) == 33
assert ecdh_share[0] in (0x02, 0x03)

# Input hash computation (order-independent)
outpoints = [
    (
        a2b_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        b"\x00\x00\x00\x00",
    ),
    (
        a2b_hex("0000000000000000000000000000000000000000000000000000000000000002"),
        b"\x00\x00\x00\x01",
    ),
]
spk = a2b_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
ih = _compute_input_hash(outpoints, spk)
assert isinstance(ih, bytes) and len(ih) == 32
assert int.from_bytes(ih, "big") > 0
assert _compute_input_hash(outpoints[::-1], spk) == ih

# Shared secret tweak (different k -> different tweak)
es = a2b_hex("03ccffacf309a1570d01449966bbc0f876d23ee929e88a68968e0a606e31efcc35")
t0 = _compute_shared_secret_tweak(es, 0)
t1 = _compute_shared_secret_tweak(es, 1)
t2 = _compute_shared_secret_tweak(es, 2)
assert t0 != t1 and t1 != t2 and t0 != t2
assert isinstance(t0, bytes)

# ---------------------------------------------------------------------------
# Tagged Hash Constants
# ---------------------------------------------------------------------------

assert BIP352_SHARED_SECRET_TAG_H == sha256(b"BIP0352/SharedSecret").digest()
assert BIP352_INPUTS_TAG_H == sha256(b"BIP0352/Inputs").digest()
assert BIP352_LABEL_TAG_H == sha256(b"BIP0352/Label").digest()
assert DLEQ_TAG_AUX_H == sha256(b"BIP0374/aux").digest()
assert DLEQ_TAG_NONCE_H == sha256(b"BIP0374/nonce").digest()
assert DLEQ_TAG_CHALLENGE_H == sha256(b"BIP0374/challenge").digest()

# ---------------------------------------------------------------------------
# PSBT Field Constants (BIP-375)
# ---------------------------------------------------------------------------

assert PSBT_GLOBAL_SP_ECDH_SHARE == 0x07
assert PSBT_GLOBAL_SP_DLEQ == 0x08
assert PSBT_IN_SP_ECDH_SHARE == 0x1D
assert PSBT_IN_SP_DLEQ == 0x1E
assert PSBT_OUT_SP_V0_INFO == 0x09
assert PSBT_OUT_SP_V0_LABEL == 0x0A

# ---------------------------------------------------------------------------
# DLEQ Proofs
# ---------------------------------------------------------------------------

pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY)

proof = generate_dleq_proof(TEST_PRIVKEY, TEST_SCAN_KEY)
assert len(proof) == 64
assert verify_dleq_proof(pubkey, TEST_SCAN_KEY, ecdh_share, proof)

# Tampered proof rejected
tampered = bytearray(proof)
tampered[0] ^= 0xFF
assert not verify_dleq_proof(pubkey, TEST_SCAN_KEY, ecdh_share, bytes(tampered))

# Wrong ECDH share rejected
wrong_ecdh = a2b_hex("02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
try:
    assert not verify_dleq_proof(pubkey, TEST_SCAN_KEY, wrong_ecdh, proof)
except Exception as e:
    assert isinstance(e, ValueError)

# Deterministic with same aux_rand
p1 = generate_dleq_proof(TEST_PRIVKEY, TEST_SCAN_KEY, b"\x00" * 32)
p2 = generate_dleq_proof(TEST_PRIVKEY, TEST_SCAN_KEY, b"\x00" * 32)
assert p1 == p2

# ---------------------------------------------------------------------------
# Address Encoding
# ---------------------------------------------------------------------------

sk = a2b_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
spk2 = a2b_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

addr = ngu.codecs.bip352_encode("sp", sk, spk2)
assert isinstance(addr, str) and addr.startswith("sp1q") and len(addr) == 116

addr_tn = ngu.codecs.bip352_encode("tsp", sk, spk2)
assert addr_tn.startswith("tsp1q") and len(addr_tn) == 117

assert ngu.codecs.bip352_encode("sp", sk, spk2, 0) == addr

for v in [0, 1, 15, 30, 31]:
    a = ngu.codecs.bip352_encode("sp", sk, spk2, v)
    assert isinstance(a, str) and a.startswith("sp1")

for v in [32, 33, 100, -1, -10]:
    try:
        ngu.codecs.bip352_encode("sp", sk, spk2, v)
        assert False, "Should raise for version %d" % v
    except ValueError as e:
        assert "version must be 0-31" in str(e)

# Different keys -> different addresses
sk2 = a2b_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
assert ngu.codecs.bip352_encode("sp", sk2, spk2) != addr

spk3 = a2b_hex("021b8c93100d35bd448f4646cc4678f278351b439b52b303ea31ec97b6eda4116f")
assert ngu.codecs.bip352_encode("sp", sk, spk3) != addr

# Invalid key sizes
for bad_hex in [
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ff",
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16",
    "",
]:
    try:
        bad_key = a2b_hex(bad_hex) if bad_hex else b""
        ngu.codecs.bip352_encode("sp", sk, bad_key)
        assert False, "Should raise for bad key"
    except ValueError as e:
        assert "33 bytes" in str(e)

# Uncompressed key rejected
uncompressed = a2b_hex(
    "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
)
try:
    ngu.codecs.bip352_encode("sp", sk, uncompressed)
    assert False, "Should raise for uncompressed key"
except ValueError as e:
    assert "33 bytes" in str(e)


# ---------------------------------------------------------------------------
# Mock Infrastructure
# ---------------------------------------------------------------------------


class MockInput:
    def __init__(self):
        self.sp_idxs = None
        self.sp_ecdh_shares = None
        self.sp_dleq_proofs = None
        self.subpaths = None
        self.taproot_subpaths = None
        self.previous_txid = None
        self.prevout_idx = None
        self.witness_utxo = None
        self.taproot_internal_key = None
        self.utxo_spk = None
        self.ik_idx = None
        self.sighash = None
        self.redeem_script = None

    @property
    def is_sp_spend(self):
        return bool(self.sp_tweak and self.sp_spend_bip32_derivation)


class MockOutput:
    def __init__(self):
        self.sp_v0_info = None
        self.sp_v0_label = None
        self.script = None


class MockPSBT(SilentPaymentsMixin):
    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.my_xfp = MY_XFP
        self.sp_global_ecdh_shares = {}
        self.sp_global_dleq_proofs = {}

    def get(self, x):
        return x

    def parse_xfp_path(self, coords):
        return coords

    def handle_zero_xfp(self, xfp_path, my_xfp, _):
        return xfp_path

    def _path_to_privkey(self, xfp_path, sv):
        return sv[xfp_path]


def _make_eligible_input(pk, deriv, txid, vout_bytes):
    inp = MockInput()
    inp.utxo_spk = P2WPKH_SPK
    inp.subpaths = [(pk, deriv)]
    inp.previous_txid = txid
    inp.prevout_idx = vout_bytes
    inp.sp_idxs = [0]
    return inp


def _make_test_keypair():
    pk = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY)
    es = _compute_ecdh_share(TEST_PRIVKEY, TEST_SCAN_KEY)
    dp = generate_dleq_proof(TEST_PRIVKEY, TEST_SCAN_KEY, b"\x00" * 32)
    return pk, TEST_SCAN_KEY, es, dp


def _make_mock_psbt_with_global_proofs():
    pk, scan_key, es, dp = _make_test_keypair()
    psbt = MockPSBT()
    inp = _make_eligible_input(pk, (MY_XFP, 44, 0, 0, 0), b"\x01" * 32, b"\x00\x00\x00\x00")
    psbt.inputs = [inp]
    outp = MockOutput()
    outp.sp_v0_info = scan_key + TEST_SPEND_KEY
    psbt.outputs = [outp]
    psbt.sp_global_ecdh_shares = {scan_key: es}
    psbt.sp_global_dleq_proofs = {scan_key: dp}
    return psbt, scan_key, es, dp, pk, TEST_SPEND_KEY


def _make_sp_output(scan_key):
    outp = MockOutput()
    outp.sp_v0_info = scan_key + TEST_SPEND_KEY
    return outp


# ---------------------------------------------------------------------------
# Mixin: ECDH Coverage
# ---------------------------------------------------------------------------

# Global coverage complete
psbt, _, _, _, _, _ = _make_mock_psbt_with_global_proofs()
assert psbt._is_ecdh_coverage_complete() is True

# Global missing
psbt.sp_global_ecdh_shares = {}
assert psbt._is_ecdh_coverage_complete() is False

# Per-input coverage
pk, scan_key, es, _ = _make_test_keypair()
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = {}
inp = _make_eligible_input(pk, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
inp.sp_ecdh_shares = {scan_key: es}
psbt.inputs = [inp]
psbt.outputs = [_make_sp_output(scan_key)]
assert psbt._is_ecdh_coverage_complete() is True

# Per-input missing
inp.sp_ecdh_shares = {}
assert psbt._is_ecdh_coverage_complete() is False

# No SP outputs: vacuously true
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = {}
psbt.inputs = [MockInput()]
assert psbt._is_ecdh_coverage_complete() is True

# ---------------------------------------------------------------------------
# Mixin: DLEQ Validation
# ---------------------------------------------------------------------------

# Global valid proof
psbt, *_ = _make_mock_psbt_with_global_proofs()
psbt._validate_ecdh_coverage()

# Global tampered proof
psbt, scan_key, _, dp, _, _ = _make_mock_psbt_with_global_proofs()
tampered = bytearray(dp)
tampered[0] ^= 0xFF
psbt.sp_global_dleq_proofs = {scan_key: bytes(tampered)}
try:
    psbt._validate_ecdh_coverage()
    assert False, "Should raise FatalPSBTIssue"
except FatalPSBTIssue:
    pass

# Global missing proof
psbt, _, _, _, _, _ = _make_mock_psbt_with_global_proofs()
psbt.sp_global_dleq_proofs = {}
try:
    psbt._validate_ecdh_coverage()
    assert False, "Should raise FatalPSBTIssue"
except FatalPSBTIssue:
    pass

# Per-input valid proof
pk, scan_key, es, dp = _make_test_keypair()
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = {}
inp = _make_eligible_input(pk, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
inp.sp_ecdh_shares = {scan_key: es}
inp.sp_dleq_proofs = {scan_key: dp}
psbt.inputs = [inp]
outp = MockOutput()
outp.sp_v0_info = scan_key + TEST_SPEND_KEY
outp.script = b"\x51\x20" + b"\xcc" * 32
psbt.outputs = [outp]
psbt._validate_ecdh_coverage()

# Per-input tampered proof
pk, scan_key, es, dp = _make_test_keypair()
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = {}
tampered = bytearray(dp)
tampered[0] ^= 0xFF
inp = _make_eligible_input(pk, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
inp.sp_ecdh_shares = {scan_key: es}
inp.sp_dleq_proofs = {scan_key: bytes(tampered)}
psbt.inputs = [inp]
outp = MockOutput()
outp.sp_v0_info = scan_key + TEST_SPEND_KEY
outp.script = b"\x51\x20" + b"\xcc" * 32
psbt.outputs = [outp]
try:
    psbt._validate_ecdh_coverage()
    assert False, "Should raise FatalPSBTIssue"
except FatalPSBTIssue:
    pass

# ---------------------------------------------------------------------------
# Mixin: Compute and Store ECDH
# ---------------------------------------------------------------------------

pk_ours = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY)

# Single signer -> global
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = None
psbt.sp_global_dleq_proofs = None
inp = _make_eligible_input(pk_ours, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
psbt.inputs = [inp]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
sv = {TEST_DERIV_OURS: TEST_PRIVKEY}
assert psbt._compute_and_store_ecdh_shares(sv) is True
assert len(psbt.sp_global_ecdh_shares) == 1
assert TEST_SCAN_KEY in psbt.sp_global_ecdh_shares
assert len(psbt.sp_global_dleq_proofs) == 1

# Idempotent
psbt._compute_and_store_ecdh_shares(sv)
assert len(psbt.sp_global_ecdh_shares) == 1

# Multi-signer -> per-input
psbt = MockPSBT()
inp_ours = _make_eligible_input(pk_ours, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
foreign_deriv = (FOREIGN_XFP, 44, 0, 0, 0)
inp_foreign = _make_eligible_input(b"\x02" + b"\xbb" * 32, foreign_deriv, b"\x02" * 32, b"\x01" * 4)
psbt.inputs = [inp_ours, inp_foreign]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
assert psbt._compute_and_store_ecdh_shares(sv) is True
assert not psbt.sp_global_ecdh_shares
assert len(inp_ours.sp_ecdh_shares) == 1
assert TEST_SCAN_KEY in inp_ours.sp_ecdh_shares

# ---------------------------------------------------------------------------
# Mixin: Ownership
# ---------------------------------------------------------------------------

# All owned
psbt = MockPSBT()
psbt.sp_global_ecdh_shares = None
psbt.sp_global_dleq_proofs = None
inp = _make_eligible_input(pk_ours, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
pub2 = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY2)
inp2 = _make_eligible_input(pub2, (MY_XFP, 44, 0, 0, 1), b"\x02" * 32, b"\x01\x00\x00\x00")
psbt.inputs = [inp, inp2]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
psbt._compute_and_store_ecdh_shares(
    {
        TEST_DERIV_OURS: TEST_PRIVKEY,
        (MY_XFP, 44, 0, 0, 1): TEST_PRIVKEY2,
    }
)
assert psbt.sp_all_inputs_ours is True

# Foreign input
psbt = MockPSBT()
inp_ours = _make_eligible_input(pk_ours, TEST_DERIV_OURS, b"\x01" * 32, b"\x00" * 4)
inp_foreign = _make_eligible_input(b"\x02" + b"\xbb" * 32, (FOREIGN_XFP, 44, 0, 0, 0), b"\x02" * 32, b"\x01" * 4)
psbt.inputs = [inp_ours, inp_foreign]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
psbt._compute_and_store_ecdh_shares({TEST_DERIV_OURS: TEST_PRIVKEY})
assert psbt.sp_all_inputs_ours is False

# No signable inputs
psbt = MockPSBT()
inp = _make_eligible_input(b"\x02" + b"\xbb" * 32, (FOREIGN_XFP, 44, 0, 0, 0), b"\x01" * 32, b"\x00" * 4)
psbt.inputs = [inp]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
assert psbt._compute_and_store_ecdh_shares({}) is False

# ---------------------------------------------------------------------------
# Mixin: Compute Output Scripts
# ---------------------------------------------------------------------------

# Single input, single output
psbt, scan_key, es, _, pk, spend_key = _make_mock_psbt_with_global_proofs()
psbt._compute_silent_payment_output_scripts()
outp = psbt.outputs[0]
assert outp.script is not None and len(outp.script) == 34 and outp.script[0] == 0x51
expected = _compute_silent_payment_output_script([(b"\x01" * 32, b"\x00\x00\x00\x00")], pk, es, spend_key, 0)
assert outp.script == expected

# Missing ECDH share
psbt, _, _, _, _, _ = _make_mock_psbt_with_global_proofs()
other_scan = a2b_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
psbt.outputs[0].sp_v0_info = other_scan + TEST_SPEND_KEY
try:
    psbt._compute_silent_payment_output_scripts()
    assert False, "Should raise"
except Exception as e:
    assert "Missing ECDH share" in str(e)

# Per-input share combining
pub1 = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY)
pub2 = ngu.secp256k1.ec_pubkey_tweak_mul(G, TEST_PRIVKEY2)
share1 = _compute_ecdh_share(TEST_PRIVKEY, TEST_SCAN_KEY)
share2 = _compute_ecdh_share(TEST_PRIVKEY2, TEST_SCAN_KEY)

psbt = MockPSBT()
psbt.sp_global_ecdh_shares = {}
inp1 = _make_eligible_input(pub1, (MY_XFP, 44, 0, 0, 0), b"\x01" * 32, b"\x00\x00\x00\x00")
inp1.sp_ecdh_shares = {TEST_SCAN_KEY: share1}
inp2 = _make_eligible_input(pub2, (MY_XFP, 44, 0, 0, 1), b"\x02" * 32, b"\x01\x00\x00\x00")
inp2.sp_ecdh_shares = {TEST_SCAN_KEY: share2}
psbt.inputs = [inp1, inp2]
outp = MockOutput()
outp.sp_v0_info = TEST_SCAN_KEY + TEST_SPEND_KEY
psbt.outputs = [outp]
psbt._compute_silent_payment_output_scripts()

combined_share = ngu.secp256k1.ec_pubkey_combine([share1, share2])
summed_pk = _combine_pubkeys([pub1, pub2])
outpoints = [(b"\x01" * 32, b"\x00\x00\x00\x00"), (b"\x02" * 32, b"\x01\x00\x00\x00")]
expected = _compute_silent_payment_output_script(outpoints, summed_pk, combined_share, TEST_SPEND_KEY, 0)
assert outp.script == expected

# k counter per scan key (skips non-SP outputs)
psbt, scan_key, es, _, pk, _ = _make_mock_psbt_with_global_proofs()
spend_key_a = a2b_hex("022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")
spend_key_b = a2b_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
spend_key_c = a2b_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

sp0 = MockOutput()
sp0.sp_v0_info = scan_key + spend_key_a
reg1 = MockOutput()
sp2 = MockOutput()
sp2.sp_v0_info = scan_key + spend_key_b
reg3 = MockOutput()
sp4 = MockOutput()
sp4.sp_v0_info = scan_key + spend_key_c
psbt.outputs = [sp0, reg1, sp2, reg3, sp4]
psbt._compute_silent_payment_output_scripts()

ops = [(b"\x01" * 32, b"\x00\x00\x00\x00")]
spk_sum = _combine_pubkeys([pk])
assert sp0.script == _compute_silent_payment_output_script(ops, spk_sum, es, spend_key_a, k=0)
assert sp2.script == _compute_silent_payment_output_script(ops, spk_sum, es, spend_key_b, k=1)
assert sp4.script == _compute_silent_payment_output_script(ops, spk_sum, es, spend_key_c, k=2)
assert reg1.script is None
assert reg3.script is None

# ---------------------------------------------------------------------------
# Mixin: Simple Methods
# ---------------------------------------------------------------------------

psbt = MockPSBT()
outp = MockOutput()
outp.sp_v0_info = b"\x02" + b"\xaa" * 32 + b"\x02" + b"\xbb" * 32
psbt.outputs = [outp]
assert psbt.has_silent_payment_outputs() is True

psbt = MockPSBT()
psbt.outputs = [MockOutput()]
assert psbt.has_silent_payment_outputs() is False

# _get_silent_payment_scan_keys
psbt = MockPSBT()
scan1 = b"\x02" + b"\xaa" * 32
scan2 = b"\x03" + b"\xbb" * 32
o1 = MockOutput()
o1.sp_v0_info = scan1 + b"\x02" + b"\xcc" * 32
o2 = MockOutput()
o2.sp_v0_info = scan2 + b"\x02" + b"\xdd" * 32
o3 = MockOutput()
psbt.outputs = [o1, o2, o3]
keys = psbt._get_silent_payment_scan_keys()
assert len(keys) == 2 and set(keys) == {scan1, scan2}

# Dedup
psbt = MockPSBT()
o1 = MockOutput()
o1.sp_v0_info = scan1 + b"\x02" + b"\xbb" * 32
o2 = MockOutput()
o2.sp_v0_info = scan1 + b"\x02" + b"\xcc" * 32
psbt.outputs = [o1, o2]
assert len(psbt._get_silent_payment_scan_keys()) == 1

# ---------------------------------------------------------------------------
# Script type predicates
# ---------------------------------------------------------------------------

assert _is_p2wpkh(b"\x00\x14" + b"\xab" * 20) is True
assert _is_p2wpkh(b"\x00\x14" + b"\xab" * 19) is False  # wrong length
assert _is_p2tr(b"\x51\x20" + b"\xcd" * 32) is True
assert _is_p2tr(b"\x51\x20" + b"\xcd" * 31) is False  # wrong length
assert _is_p2pkh(b"\x76\xa9\x14" + b"\xab" * 20 + b"\x88\xac") is True
assert _is_p2pkh(b"\x76\xa9\x14" + b"\xab" * 20 + b"\x88\xad") is False  # wrong suffix
assert _is_p2sh(b"\xa9\x14" + b"\xab" * 20 + b"\x87") is True
assert _is_p2sh(b"\xa9\x14" + b"\xab" * 19 + b"\x87") is False  # wrong length

# P2TR with NUMS output key is still valid P2TR shape (ineligibility is checked separately)
assert _is_p2tr(b"\x51\x20" + NUMS_H) is True

# ---------------------------------------------------------------------------
# _combine_pubkeys edge cases
# ---------------------------------------------------------------------------

try:
    _combine_pubkeys([])
    assert False, "Should raise ValueError for empty pubkey list"
except ValueError:
    pass

# Intermediate sums should not fail if final sum is non-zero.
A = ngu.secp256k1.ec_pubkey_tweak_mul(G, (1).to_bytes(32, "big"))
neg_A = bytes([0x03 if A[0] == 0x02 else 0x02]) + A[1:]
assert _combine_pubkeys([A, neg_A, A]) == A

# Final point-at-infinity should still fail in phase 1.
try:
    _combine_pubkeys([A, neg_A])
    assert False, "Should raise ValueError for point-at-infinity"
except ValueError:
    pass
