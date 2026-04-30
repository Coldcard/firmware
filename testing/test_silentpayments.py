# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_silentpayments.py - Simulator-based integration tests for BIP-375 Silent Payments
#
# Tests the full firmware signing path: PSBT construction -> upload to simulator ->
# firmware computes ECDH shares, DLEQ proofs, and set output scripts -> verify
#
# Requires simulator running. Run with: pytest test_silentpayments.py
#

import pytest
import struct
import time
from binascii import unhexlify
from binascii import hexlify
from bip32 import BIP32Node
from ckcc_protocol.protocol import CCProtoError
from psbt import BasicPSBT
from sp_helpers import (
    _sim_sp,
    _sim_get_ecdh_and_pubkey,
    _sim_get_outpoints,
    _sim_verify_dleq,
    _sim_compute_output_script,
    _sim_compute_spend_output_xonly,
    _verify_signatures,
)
from constants import simulator_fixed_tprv


# ---------------------------------------------------------------------------
# Test SP recipient keys (any valid secp256k1 points; these are the recipient's
# keys, not the signer's). Taken from BIP-352 test vectors; sorted lexicographically
# so multi-output tests can use them in correct k-assignment order.
# ---------------------------------------------------------------------------

SCAN_KEY = unhexlify("03af606abaa5e29a89b93bf971c21e46dd2797aee31273c47f979a102eb51c3629")
SCAN_KEY_2 = unhexlify("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

# Sorted: SPEND_KEY_A < SPEND_KEY_B < SPEND_KEY_C (lexicographic)
SPEND_KEY_A = unhexlify("022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")
SPEND_KEY_B = unhexlify("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
SPEND_KEY_C = unhexlify("02fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")

# BIP-376 SP spend constants (BIP-352 path: m/352h/1h/0h/0h/0, testnet)
SP_TWEAK = bytes.fromhex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
SP_SPEND_PATH = "352h/1h/0h/0h/0"
SP_SPEND_PATH_INTS = [
    352 | 0x80000000,
    1 | 0x80000000,
    0 | 0x80000000,
    0 | 0x80000000,
    0,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_sp_outputs(psbt, sp_outputs):
    """Set sp_v0_info on specified outputs and clear script for firmware to compute."""
    for idx, scan_key, spend_key in sp_outputs:
        psbt.outputs[idx].sp_v0_info = scan_key + spend_key
        psbt.outputs[idx].script = None


def _verify_sp_outputs(sim_exec, sim_execfile, tp, scan_key, spend_keys_in_order):
    """Verify SP output scripts match expected derivation for a given scan key."""
    assert scan_key in tp.sp_global_ecdh_shares, "Missing global ECDH share"
    assert scan_key in tp.sp_global_dleq_proofs, "Missing global DLEQ proof"

    ecdh_share = tp.sp_global_ecdh_shares[scan_key]
    dleq_proof = tp.sp_global_dleq_proofs[scan_key]

    assert len(ecdh_share) == 33 and ecdh_share[0] in (0x02, 0x03)
    assert len(dleq_proof) == 64

    _, summed_pubkey = _sim_get_ecdh_and_pubkey(sim_exec, sim_execfile, tp, scan_key)
    _sim_verify_dleq(sim_exec, sim_execfile, summed_pubkey, scan_key, ecdh_share, dleq_proof)

    outpoints = _sim_get_outpoints(sim_exec, sim_execfile, tp)
    sp_outs = [o for o in tp.outputs if o.sp_v0_info and o.sp_v0_info[:33] == scan_key]
    assert len(sp_outs) == len(spend_keys_in_order)

    for k, (outp, sk) in enumerate(zip(sp_outs, spend_keys_in_order)):
        assert outp.script is not None and len(outp.script) == 34
        assert outp.script[0] == 0x51
        expected = _sim_compute_output_script(sim_exec, sim_execfile, outpoints, summed_pubkey, ecdh_share, sk, k)
        assert outp.script == expected


def _compute_foreign_share(sim_exec, sim_execfile, privkey_int, scan_key):
    """Compute ECDH share and DLEQ proof for a foreign input via simulator."""
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_foreign_share",
        {
            "privkey": "%064x" % privkey_int,
            "scan_key": scan_key.hex(),
        },
    )
    parts = rv.split(",")
    return bytes.fromhex(parts[0]), bytes.fromhex(parts[1])


def _setup_sp_spend_input(
    sim_exec,
    sim_execfile,
    inp,
    sp_tweak,
    path,
    path_ints,
    *,
    wrong_tweak=None,
    clear_taproot=True,
):
    """Configure a PSBT input for a BIP-376 SP spend.

    Rewrites inp.witness_utxo to lock to B_spend + utxo_tweak*G, sets
    inp.sp_tweak (to psbt_tweak if given, else utxo_tweak), and sets
    inp.sp_spend_bip32_derivation.  Optionally clears taproot derivation.
    """
    master = BIP32Node.from_wallet_key(simulator_fixed_tprv)
    mfp = master.fingerprint()
    B_spend = master.subkey_for_path(path).sec()
    xfp_and_path = mfp + struct.pack("<" + "I" * len(path_ints), *path_ints)

    xonly = _sim_compute_spend_output_xonly(sim_exec, sim_execfile, B_spend, sp_tweak)
    amount_bytes = inp.witness_utxo[:8]
    inp.witness_utxo = amount_bytes + b"\x22\x51\x20" + xonly

    if clear_taproot:
        inp.taproot_bip32_paths = {}
        inp.taproot_internal_key = None

    inp.sp_tweak = wrong_tweak if wrong_tweak is not None else sp_tweak
    inp.sp_spend_bip32_derivation = {B_spend: xfp_and_path}


def _assert_sp_spend_success(sim_exec, sim_execfile, signed):
    """Assert a signed SP spend PSBT has correct global shares and output scripts."""
    tp = BasicPSBT().parse(signed)
    assert tp.sp_global_ecdh_shares and SCAN_KEY in tp.sp_global_ecdh_shares
    assert tp.sp_global_dleq_proofs and SCAN_KEY in tp.sp_global_dleq_proofs
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])
    _verify_signatures(sim_exec, sim_execfile, tp, signed)


# ---------------------------------------------------------------------------
# Basic Tests
# ---------------------------------------------------------------------------


def test_sp_signing_story(dev, fake_txn, start_sign, end_sign, cap_story):
    """SP output: approval story shows SP address, no unknown-script warning."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)

    time.sleep(0.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "not well understood script" not in story
    assert "sp1" in story

    end_sign(accept=True, finalize=False)


def test_sp_p2wpkh_input(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Single P2WPKH input signing to a single SP output."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])


def test_sp_p2tr_input(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Single P2TR input signing to a single SP output."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])
    _verify_signatures(sim_exec, sim_execfile, tp, signed)


def test_sp_mixed_inputs(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """P2WPKH + P2TR inputs combined produce a single SP output from summed privkey."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn([["p2wpkh"], ["p2tr"]], 1, xp, psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])
    # Schnorr verification skipped: multi-input taproot sighash covers all inputs'
    # sequences, and fake_txn may not write PSBT_IN_SEQUENCE — devtest would
    # reconstruct a wrong hashSequence.


def test_sp_mixed_sp_spend_and_regular_input(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Regular P2TR input + SP-spend input: both private keys summed for ECDH, both signed"""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[1],
            SP_TWEAK,
            SP_SPEND_PATH,
            SP_SPEND_PATH_INTS,
            clear_taproot=True,
        )

    psbt_bytes = fake_txn([["p2tr"], ["p2tr"]], 1, xp, psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)
    _assert_sp_spend_success(sim_exec, sim_execfile, signed)


# ---------------------------------------------------------------------------
# Mixed output tests
# ---------------------------------------------------------------------------


def test_sp_three_outputs_same_scan_key(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Three SP outputs with same scan key: k=0,1,2 all produce distinct scripts."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(
            psbt,
            [
                (0, SCAN_KEY, SPEND_KEY_A),
                (1, SCAN_KEY, SPEND_KEY_B),
                (2, SCAN_KEY, SPEND_KEY_C),
            ],
        )

    psbt_bytes = fake_txn(1, 3, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_A, SPEND_KEY_B, SPEND_KEY_C])

    sp_outs = [o for o in tp.outputs if o.sp_v0_info and o.sp_v0_info[:33] == SCAN_KEY]
    scripts = [o.script for o in sp_outs]
    assert len(set(scripts)) == 3, "All three k-indexed scripts must be distinct"


def test_sp_two_outputs_different_scan_keys(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Two SP outputs with different scan keys each get their own ECDH share."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(
            psbt,
            [
                (0, SCAN_KEY, SPEND_KEY_B),
                (1, SCAN_KEY_2, SPEND_KEY_A),
            ],
        )

    psbt_bytes = fake_txn(1, 2, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY_2, [SPEND_KEY_A])

    assert tp.sp_global_ecdh_shares[SCAN_KEY] != tp.sp_global_ecdh_shares[SCAN_KEY_2], (
        "Different scan keys must produce different ECDH shares"
    )


def test_sp_mixed_output_types(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """SP output alongside a regular output: normal output script is preserved."""
    xp = dev.master_xpub
    original_normal_script = None

    def sp_hacker(psbt):
        nonlocal original_normal_script
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        original_normal_script = psbt.outputs[1].script

    psbt_bytes = fake_txn(1, 2, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)
    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])

    assert tp.outputs[1].script == original_normal_script, "Normal output script must not be modified by SP processing"


# ---------------------------------------------------------------------------
# Multi-signer - complete coverage scenario tests
# ---------------------------------------------------------------------------


def test_sp_all_owned_multi_input(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Scenario (a): all inputs owned -> global ECDH share -> compute scripts -> sign."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn([["p2wpkh"], ["p2wpkh"]], 1, xp, psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)

    assert tp.sp_global_ecdh_shares and SCAN_KEY in tp.sp_global_ecdh_shares
    assert tp.sp_global_dleq_proofs and SCAN_KEY in tp.sp_global_dleq_proofs
    for inp in tp.inputs:
        assert not inp.sp_ecdh_shares, "Per-input shares must not exist in single-signer path"

    _verify_sp_outputs(sim_exec, sim_execfile, tp, SCAN_KEY, [SPEND_KEY_B])

    for i, inp in enumerate(tp.inputs):
        assert inp.part_sigs or inp.taproot_key_sig, f"Input {i} missing signature"


def test_sp_partial_owned_coverage_complete(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Scenario (b): some owned + foreign with pre-existing shares -> coverage complete -> sign."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        foreign_sub = psbt._foreign_mk.subkey_for_path("0/1")
        foreign_privkey_int = int.from_bytes(foreign_sub.privkey(), "big")
        ecdh_share, proof = _compute_foreign_share(sim_exec, sim_execfile, foreign_privkey_int, SCAN_KEY)
        psbt.inputs[1].sp_ecdh_shares = {SCAN_KEY: ecdh_share}
        psbt.inputs[1].sp_dleq_proofs = {SCAN_KEY: proof}

    psbt_bytes = fake_txn(
        [["p2wpkh"], ["p2wpkh", None, None, False]],
        1,
        xp,
        psbt_v2=True,
        psbt_hacker=sp_hacker,
    )
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)

    assert not tp.sp_global_ecdh_shares, "Global ECDH shares must not exist in multi-signer path"

    assert tp.inputs[0].sp_ecdh_shares and SCAN_KEY in tp.inputs[0].sp_ecdh_shares
    assert tp.inputs[1].sp_ecdh_shares and SCAN_KEY in tp.inputs[1].sp_ecdh_shares

    sp_outs = [o for o in tp.outputs if o.sp_v0_info]
    assert len(sp_outs) == 1
    assert sp_outs[0].script is not None and sp_outs[0].script[0] == 0x51

    # Verify output script by combining per-input ECDH shares via firmware
    ecdh_share, summed_pubkey = _sim_get_ecdh_and_pubkey(sim_exec, sim_execfile, tp, SCAN_KEY)
    outpoints = _sim_get_outpoints(sim_exec, sim_execfile, tp)
    expected = _sim_compute_output_script(sim_exec, sim_execfile, outpoints, summed_pubkey, ecdh_share, SPEND_KEY_B, 0)
    assert sp_outs[0].script == expected

    assert tp.inputs[0].part_sigs, "Owned input must have signature"
    assert not tp.inputs[1].part_sigs, "Foreign input must not have signature"


# ---------------------------------------------------------------------------
# Multi-signer - incomplete coverage scenario tests
# ---------------------------------------------------------------------------


def test_sp_partial_owned_coverage_incomplete(dev, fake_txn, start_sign, end_sign, cap_story):
    """Scenario (c): some owned + foreign without shares -> coverage incomplete -> save PSBT."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(
        [["p2wpkh"], ["p2wpkh", None, None, False]],
        1,
        xp,
        psbt_v2=True,
        psbt_hacker=sp_hacker,
    )
    start_sign(psbt_bytes)

    time.sleep(0.1)
    title, story = cap_story()
    assert title == "CONTRIBUTE SHARES?"
    assert "ECDH shares" in story
    assert "Other signers" in story

    signed = end_sign(accept=True, finalize=False)

    tp = BasicPSBT().parse(signed)

    assert not tp.sp_global_ecdh_shares, "Global ECDH shares must not exist in multi-signer path"

    assert tp.inputs[0].sp_ecdh_shares and SCAN_KEY in tp.inputs[0].sp_ecdh_shares
    assert tp.inputs[0].sp_dleq_proofs and SCAN_KEY in tp.inputs[0].sp_dleq_proofs
    assert not tp.inputs[1].sp_ecdh_shares

    sp_outs = [o for o in tp.outputs if o.sp_v0_info]
    assert len(sp_outs) == 1
    assert not sp_outs[0].script, "Output script must NOT be set when coverage is incomplete"

    for i, inp in enumerate(tp.inputs):
        assert not inp.part_sigs, f"Input {i} must not have signature"
        assert not inp.taproot_key_sig, f"Input {i} must not have taproot signature"


def test_sp_partial_owned_coverage_incomplete_refused(dev, fake_txn, start_sign, end_sign, cap_story):
    """Refuse to contribute SP shares -> CCUserRefused."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(
        [["p2wpkh"], ["p2wpkh", None, None, False]],
        1,
        xp,
        psbt_v2=True,
        psbt_hacker=sp_hacker,
    )
    start_sign(psbt_bytes)

    time.sleep(0.1)
    title, _ = cap_story()
    assert title == "CONTRIBUTE SHARES?"

    end_sign(accept=False)


# ---------------------------------------------------------------------------
# BIP-376 Silent Payments spend sp output test
# ---------------------------------------------------------------------------


def test_sp_spend_silent_payment_output(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Spend from SP output with correct proof -> sign.

    Uses the canonical BIP-376 PSBT shape: the input has PSBT_IN_SP_TWEAK and
    PSBT_IN_SP_SPEND_BIP32_DERIVATION (BIP-352-style path), with no
    PSBT_IN_TAP_BIP32_DERIVATION or PSBT_IN_TAP_INTERNAL_KEY.
    """
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[0],
            SP_TWEAK,
            SP_SPEND_PATH,
            SP_SPEND_PATH_INTS,
            clear_taproot=True,
        )

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)
    _assert_sp_spend_success(sim_exec, sim_execfile, signed)


def test_sp_spend_silent_payment_output_with_taproot(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """Spend from SP output with correct proof -> sign (taproot derivation retained)."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[0],
            SP_TWEAK,
            SP_SPEND_PATH,
            SP_SPEND_PATH_INTS,
            clear_taproot=False,
        )

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    signed = end_sign(accept=True, finalize=False)
    _assert_sp_spend_success(sim_exec, sim_execfile, signed)


def test_sp_spend_wrong_tweak_rejected(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """SP_TWEAK that does not match the witness UTXO output key must be rejected."""
    xp = dev.master_xpub
    WRONG_TWEAK = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        # Witness UTXO uses SP_TWEAK; PSBT carries WRONG_TWEAK — firmware must reject this
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[0],
            SP_TWEAK,
            SP_SPEND_PATH,
            SP_SPEND_PATH_INTS,
            wrong_tweak=WRONG_TWEAK,
        )

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="SP_TWEAK does not match UTXO output key"):
        end_sign(accept=True, finalize=False)


def test_sp_spend_wrong_purpose_rejected(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """SP_SPEND_BIP32_DERIVATION with a non-352h purpose must be rejected."""
    xp = dev.master_xpub
    # BIP-84 path instead of BIP-352
    WRONG_PATH = "84h/1h/0h/0/0"
    WRONG_PATH_INTS = [84 | 0x80000000, 1 | 0x80000000, 0 | 0x80000000, 0, 0]

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[0],
            SP_TWEAK,
            WRONG_PATH,
            WRONG_PATH_INTS,
        )

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="SP spend key purpose must use 352h path"):
        end_sign(accept=True, finalize=False)


def test_sp_spend_wrong_coin_type_rejected(dev, fake_txn, start_sign, end_sign, sim_exec, sim_execfile):
    """SP_SPEND_BIP32_DERIVATION with coin type mismatching the network must be rejected."""
    xp = dev.master_xpub
    # Simulator is testnet (coin_type=1); use mainnet coin_type=0 to trigger mismatch
    WRONG_COIN_PATH = "352h/0h/0h/0h/0"
    WRONG_COIN_PATH_INTS = [
        352 | 0x80000000,
        0 | 0x80000000,
        0 | 0x80000000,
        0 | 0x80000000,
        0,
    ]

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        _setup_sp_spend_input(
            sim_exec,
            sim_execfile,
            psbt.inputs[0],
            SP_TWEAK,
            WRONG_COIN_PATH,
            WRONG_COIN_PATH_INTS,
        )

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2tr", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="SP spend path coin type does not match network"):
        end_sign(accept=True, finalize=False)


# ---------------------------------------------------------------------------
# Handle failure test
# ---------------------------------------------------------------------------


def test_exit_gracefully_on_sp_validation_failure(dev, fake_txn, start_sign, end_sign):
    """Invalid SP output info should cause signing to fail with a clear error message."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        # Set sp_v0_info with incorrect length (should be 64 bytes)
        psbt.outputs[0].sp_v0_info = b"\x00" * 10
        psbt.outputs[0].script = None

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="SP_V0_INFO wrong size"):
        end_sign(accept=False, finalize=False)


def test_sp_non_sighash_all_rejected(dev, fake_txn, start_sign, end_sign):
    """Non-SIGHASH_ALL on an input with SP outputs must be rejected (BIP-375)."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])
        psbt.inputs[0].sighash = 3  # SIGHASH_SINGLE

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="Silent payments require SIGHASH_ALL"):
        end_sign(accept=True, finalize=False)


def test_sp_psbt_v0_rejected(dev, fake_txn, start_sign, end_sign):
    """PSBTv0 with SP outputs is rejected: outpoint fields are PSBTv2-only.

    BIP-352 SP computation requires PSBT_IN_PREVIOUS_TXID and PSBT_IN_OUTPUT_INDEX
    (PSBTv2 fields) to derive the input hash. PSBTv0 embeds outpoints only in the
    unsigned transaction, so firmware raises when trying to collect them.
    """
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(psbt, [(0, SCAN_KEY, SPEND_KEY_B)])

    psbt_bytes = fake_txn(1, 1, xp, addr_fmt="p2wpkh", psbt_v2=False, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)
    with pytest.raises(CCProtoError, match="Missing outpoint for silent payment input"):
        end_sign(accept=True, finalize=False)


# ---------------------------------------------------------------------------
# Silent Payments Change Detection Tests
# ---------------------------------------------------------------------------


def test_sp_spend_to_labeled_change_address(dev, fake_txn, start_sign, end_sign, cap_story):
    """Two SP outputs: output 0 is a send (no label), output 1 is change (label=0 per BIP-352 convention)."""
    xp = dev.master_xpub

    def sp_hacker(psbt):
        _add_sp_outputs(
            psbt,
            [
                (0, SCAN_KEY, SPEND_KEY_B),
                (1, SCAN_KEY_2, SPEND_KEY_A),
            ],
        )
        psbt.outputs[1].sp_v0_label = b"\x00\x00\x00\x00"

    psbt_bytes = fake_txn(1, 2, xp, addr_fmt="p2wpkh", psbt_v2=True, psbt_hacker=sp_hacker)
    start_sign(psbt_bytes)

    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "not well understood script" not in story
    assert "sp1" in story
    assert "Change back:" in story

    end_sign(accept=False, finalize=False)
