# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_bip375_vectors.py - Tests for BIP-375 Silent Payments implementation
#
# Unit tests run inside the simulator via devtest/unit_silentpayments.py
# Use simulator to validate BIP-375 test vectors
# 1. Parse psbts and verify validation failure code matches expected mapping in _SIM_INVALID
# 2. For valid vectors, verify ECDH share, DLEQ proof and output script computations match expected values
#
import json
import pytest
from binascii import unhexlify
from psbt import BasicPSBT
from sp_helpers import (
    _sim_validate_sp,
    _sim_get_ecdh_and_pubkey,
    _sim_get_outpoints,
    _sim_pubkey_from_input,
    _sim_verify_dleq,
    _sim_compute_ecdh_share,
    _sim_combine_pubkeys,
    _sim_compute_output_script,
)


# ---------------------------------------------------------------------------
# Unit tests (run inside simulator)
# ---------------------------------------------------------------------------


def test_silentpayments_unit(sim_execfile):
    res = sim_execfile("devtest/unit_silentpayments.py")
    assert res == ""


# ---------------------------------------------------------------------------
# BIP-375 Test Vectors
# ---------------------------------------------------------------------------


def load_test_vectors():
    with open("bip375_test_vectors.json") as f:
        return json.load(f)


def _get_vector(category, description_substr):
    vectors = load_test_vectors()[category]
    matches = [v for v in vectors if description_substr in v["description"]]
    assert len(matches) == 1, "Expected 1 match for %r in %s, got %d" % (
        description_substr,
        category,
        len(matches),
    )
    return matches[0]


class TestBIP375InvalidVectors:
    """Validate that invalid test vectors have detectable structural issues"""

    def _get(self, substr):
        return _get_vector("invalid", substr)

    # Vectors where the firmware raises FatalPSBTIssue
    # Each tuple: (description_substr_from_test_vectors, expected_error_substr_from_FatalPSBTIssue)
    _SIM_INVALID = [
        ("missing PSBT_OUT_SP_V0_INFO field", "SP label but missing SP_V0_INFO"),
        ("incorrect byte length for PSBT_OUT_SP_V0_INFO", "SP_V0_INFO wrong size"),
        ("incorrect byte length for PSBT_IN_SP_ECDH_SHARE", "ECDH share wrong size"),
        ("incorrect byte length for PSBT_IN_SP_DLEQ", "DLEQ proof wrong size"),
        ("PSBT_GLOBAL_TX_MODIFIABLE field is non-zero", "TX_MODIFIABLE not cleared"),
        (
            "missing PSBT_OUT_SCRIPT field when sending",
            "either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
        ),
        ("only one ineligible P2SH multisig input", "no ECDH share for scan key"),
        ("missing PSBT_IN_SP_ECDH_SHARE field for input 0", "missing ECDH share"),
        ("missing PSBT_IN_SP_DLEQ field for input", "ECDH share missing DLEQ proof"),
        ("missing PSBT_GLOBAL_SP_DLEQ field", "Global ECDH share missing DLEQ proof"),
        ("invalid proof in PSBT_IN_SP_DLEQ", "DLEQ proof verification failed"),
        ("invalid proof in PSBT_GLOBAL_SP_DLEQ", "DLEQ proof verification failed"),
        ("missing PSBT_IN_BIP32_DERIVATION field", "missing public key for DLEQ"),
        ("output 1 missing ECDH share for scan key", "no ECDH share for scan key"),
        ("input 1 missing ECDH share for output 1", "missing ECDH share"),
        ("input 1 missing ECDH share for scan key", "missing ECDH share"),
        ("segwit version greater than 1", "Segwit v"),
        ("non-SIGHASH_ALL signature", "SIGHASH_ALL"),
        ("NUMS internal key", "Missing ECDH share for output"),
        ("PSBT_OUT_SCRIPT does not match derived sp output", "output script mismatch"),
        ("not sorted lexicographically by spend key", "output script mismatch"),
        ("k values assigned to wrong output indices", "output script mismatch"),
    ]

    @pytest.mark.parametrize(
        "desc,expected_err", _SIM_INVALID, ids=[d for d, _ in _SIM_INVALID]
    )
    def test_invalid_vectors_sim_validate_sp(
        self, sim_exec, sim_execfile, desc, expected_err
    ):
        p = BasicPSBT().parse(self._get(desc)["psbt"].encode())
        err = _sim_validate_sp(sim_exec, sim_execfile, p)
        assert err, "Expected validation failure for: %s" % desc
        assert expected_err in err, "Expected %r in error for [%s], got: %s" % (
            expected_err,
            desc,
            err,
        )


class TestBIP375ValidVectors:
    """Validate crypto computations against valid test vectors"""

    VALID_VECTORS = load_test_vectors()["valid"]

    def _get(self, substr):
        return _get_vector("valid", substr)

    def test_valid_ecdh_computation(self, sim_exec, sim_execfile):
        for vi in range(len(self.VALID_VECTORS)):
            vec = self.VALID_VECTORS[vi]
            p = BasicPSBT().parse(vec["psbt"].encode())
            eligible_privkeys = [
                unhexlify(inp["private_key"])
                for inp in vec["supplementary"]["inputs"]
                if inp["private_key"]
                and _sim_pubkey_from_input(
                    sim_exec, sim_execfile, p, inp["input_index"]
                )
            ]
            for expected in vec["supplementary"]["sp_proofs"]:
                scan_key = unhexlify(expected["scan_key"])
                expected_ecdh = unhexlify(expected["ecdh_share"])
                if "input_index" in expected:
                    ik = next(
                        k
                        for k in vec["supplementary"]["inputs"]
                        if k["input_index"] == expected["input_index"]
                    )
                    privkey = unhexlify(ik["private_key"])
                    actual = _sim_compute_ecdh_share(
                        sim_exec, sim_execfile, privkey, scan_key
                    )
                else:
                    shares = [
                        _sim_compute_ecdh_share(
                            sim_exec,
                            sim_execfile,
                            privkey,
                            scan_key,
                        )
                        for privkey in eligible_privkeys
                    ]
                    actual = _sim_combine_pubkeys(sim_exec, sim_execfile, shares)
                assert actual == expected_ecdh, (
                    "ECDH mismatch in valid[%d] for scan_key %s"
                    % (vi, expected["scan_key"][:16])
                )

    def test_valid_dleq_verification(self, sim_exec, sim_execfile):
        for vi in range(len(self.VALID_VECTORS)):
            vec = self.VALID_VECTORS[vi]
            p = BasicPSBT().parse(vec["psbt"].encode())

            for scan_key, proof in p.sp_global_dleq_proofs.items():
                ecdh_share = p.sp_global_ecdh_shares.get(scan_key)
                assert ecdh_share is not None, (
                    "valid[%d]: global ECDH share missing for scan key" % vi
                )
                _, summed_pubkey = _sim_get_ecdh_and_pubkey(
                    sim_exec, sim_execfile, p, scan_key
                )
                _sim_verify_dleq(
                    sim_exec,
                    sim_execfile,
                    summed_pubkey,
                    scan_key,
                    ecdh_share,
                    proof,
                )

            for inp_idx, inp in enumerate(p.inputs):
                if not inp.sp_dleq_proofs:
                    continue
                pubkey = _sim_pubkey_from_input(sim_exec, sim_execfile, p, inp_idx)
                if pubkey is None:
                    continue
                for scan_key, proof in inp.sp_dleq_proofs.items():
                    ecdh_share = inp.sp_ecdh_shares.get(scan_key)
                    assert ecdh_share is not None, (
                        "valid[%d] inp[%d]: ECDH share missing" % (vi, inp_idx)
                    )
                    _sim_verify_dleq(
                        sim_exec,
                        sim_execfile,
                        pubkey,
                        scan_key,
                        ecdh_share,
                        proof,
                    )

    def test_valid_output_script_derivation(self, sim_exec, sim_execfile):
        for vi in range(len(self.VALID_VECTORS)):
            vec = self.VALID_VECTORS[vi]
            p = BasicPSBT().parse(vec["psbt"].encode())
            sp_outputs = [
                (o.sp_v0_info[:33], o.sp_v0_info[33:66], o.script)
                for o in p.outputs
                if o.sp_v0_info and len(o.sp_v0_info) == 66
            ]
            if not sp_outputs:
                continue
            outpoints = _sim_get_outpoints(sim_exec, sim_execfile, p)
            scan_key_k = {}
            for scan_key, spend_key, script in sp_outputs:
                ecdh_share, summed_pubkey = _sim_get_ecdh_and_pubkey(
                    sim_exec, sim_execfile, p, scan_key
                )
                if not ecdh_share:
                    continue
                if not script:  # If script is missing, skip vectors test missing script
                    continue

                k = scan_key_k.get(scan_key, 0)
                scan_key_k[scan_key] = k + 1
                expected = _sim_compute_output_script(
                    sim_exec,
                    sim_execfile,
                    outpoints,
                    summed_pubkey,
                    ecdh_share,
                    spend_key,
                    k,
                )
                assert script == expected, (
                    "valid[%d]: output script mismatch at k=%d" % (vi, k)
                )
