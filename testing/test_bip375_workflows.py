# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_bip375_workflows.py - Drive BIP-375 workflow vectors through the simulator's signing flow
#
# Each `workflows` entry is one role transition: `psbt` is the role's input and `expected.psbt` its
# output. The Coldcard is a Signer, so only sign steps run here; the other roles belong to the
# coordinator.
#
# The vector keys come from seeded wallets listed under `wallets`. A sign step discloses the private
# keys of the inputs its party holds, and the PSBT's BIP32 derivation for such an input names the
# wallet by fingerprint. The test loads that wallet's seed into the simulator and signs through the
# normal start_sign/end_sign flow, so the same steps cover every party (signer 1 and signer 2).
#
# Compared: ECDH shares, output scripts, which inputs are signed and the BIP-370 unique id.
# Verified, not compared: DLEQ proofs (fresh randomness) and ECDSA signatures (the firmware grinds
# for low R, the reference does not, so the bytes legitimately differ).
#
import json
import time
import pytest
from base64 import b64decode
from binascii import unhexlify
from helpers import hash160
from bip322 import ecdsa_verify_sig
from sighash import segwit_v0_sighash
from ctransaction import CTransaction, CTxIn, CTxOut, COutPoint, uint256_from_str
from psbt import BasicPSBT
from sp_helpers import _sim_get_ecdh_and_pubkey, _sim_pubkey_from_input, _sim_verify_dleq

SIMULATOR_DELAY = 0.5

with open("bip375_test_vectors.json") as f:
    VECTORS = json.load(f)

WORKFLOWS = VECTORS["workflows"]
MNEMONICS = {w["fingerprint"]: w["mnemonic"] for w in VECTORS["wallets"]}


def _acting_mnemonic(entry):
    """Seed words of the wallet whose keys this sign step discloses."""
    held = [row["input_index"] for row in entry["supplementary"]["inputs"] if row.get("private_key")]
    psbt = BasicPSBT().parse(entry["psbt"].encode())
    # the wallet is named by the origin fingerprint in the PSBT; all held inputs share one wallet
    fingerprints = {next(iter(psbt.inputs[i].bip32_paths.values()))[:4].hex() for i in held}
    assert len(fingerprints) == 1, "one step should act for a single wallet"
    return MNEMONICS[fingerprints.pop()]


def _id(entry):
    return entry["description"].replace("Two-input P2WPKH to silent payment workflow ", "")[:90]


def _params():
    for entry in WORKFLOWS:
        marks = []
        if entry["supplementary"]["task"] != "sign":
            marks.append(pytest.mark.skip(reason="not a Signer step"))
        yield pytest.param(entry, marks=marks, id=_id(entry))


def _unique_id(psbt):
    """BIP-370 unique id, with PSBT_OUT_SP_V0_INFO standing in for unset SP output scripts (BIP-375)."""
    tx = CTransaction()
    tx.nVersion = psbt.txn_version
    tx.nLockTime = 0
    for inp in psbt.inputs:
        tx.vin.append(CTxIn(COutPoint(uint256_from_str(inp.previous_txid), inp.prevout_idx), b"", 0))
    for out in psbt.outputs:
        script = b"\x00" + out.sp_v0_info if out.sp_v0_info else out.script
        tx.vout.append(CTxOut(out.amount, script))
    tx.calc_sha256()
    return tx.sha256.to_bytes(32, "big").hex()


def _sp_fields(psbt):
    return {
        "global_ecdh": dict(psbt.sp_global_ecdh_shares or {}),
        "input_ecdh": [dict(i.sp_ecdh_shares or {}) for i in psbt.inputs],
        "output_scripts": [o.script for o in psbt.outputs],
        "signed_by": [sorted(i.part_sigs or {}) for i in psbt.inputs],
    }


def _verify_p2wpkh_sigs(psbt):
    """Check every partial signature against the BIP-143 sighash of the PSBT's transaction."""
    tx = CTransaction()
    tx.nVersion = psbt.txn_version
    tx.nLockTime = psbt.fallback_locktime or 0
    for inp in psbt.inputs:
        tx.vin.append(CTxIn(COutPoint(uint256_from_str(inp.previous_txid), inp.prevout_idx), b"", inp.sequence))
    for out in psbt.outputs:
        tx.vout.append(CTxOut(out.amount, out.script))
    for idx, inp in enumerate(psbt.inputs):
        for pubkey, sig in (inp.part_sigs or {}).items():
            amount = int.from_bytes(inp.witness_utxo[:8], "little")
            script_code = b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"
            assert ecdsa_verify_sig(pubkey, sig, segwit_v0_sighash(tx, idx, script_code, amount)), (
                "bad signature on input %d" % idx
            )


def _verify_dleq_proofs(sim_exec, sim_execfile, psbt):
    for scan_key, proof in (psbt.sp_global_dleq_proofs or {}).items():
        _, summed_pubkey = _sim_get_ecdh_and_pubkey(sim_exec, sim_execfile, psbt, scan_key)
        _sim_verify_dleq(sim_exec, sim_execfile, summed_pubkey, scan_key, psbt.sp_global_ecdh_shares[scan_key], proof)
    for idx, inp in enumerate(psbt.inputs):
        for scan_key, proof in (inp.sp_dleq_proofs or {}).items():
            pubkey = _sim_pubkey_from_input(sim_exec, sim_execfile, psbt, idx)
            _sim_verify_dleq(sim_exec, sim_execfile, pubkey, scan_key, inp.sp_ecdh_shares[scan_key], proof)


@pytest.mark.parametrize("entry", _params())
def test_workflow_sign_step(set_seed_words, start_sign, end_sign, press_cancel, sim_exec, sim_execfile, entry):
    set_seed_words(_acting_mnemonic(entry))
    start_sign(b64decode(entry["psbt"]))
    time.sleep(SIMULATOR_DELAY)
    # expect_txn=False: end_sign's own check rejects signatures over 71 bytes, but a cosigner's
    # signature already in the PSBT was not ground for low R
    signed = BasicPSBT().parse(end_sign(accept=True, finalize=False, expect_txn=False))
    press_cancel()
    expected = BasicPSBT().parse(entry["expected"]["psbt"].encode())

    got, want = _sp_fields(signed), _sp_fields(expected)
    for field in want:
        assert got[field] == want[field], "%s differs from expected.psbt" % field

    assert _unique_id(signed) == entry["expected"]["transaction_id"]
    _verify_dleq_proofs(sim_exec, sim_execfile, signed)
    _verify_p2wpkh_sigs(signed)
