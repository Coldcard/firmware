# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
# ruff: noqa: F821
#
# Crypto verification for silent payment integration tests
# Runs inside the simulator via sim_execfile('devtest/verify_sp_outputs.py')
#
# Interface: main.SP_VERIFY dict with hex-encoded parameters
# Success = no output; failure = assertion traceback
# RV (uio.BytesIO) is injected into globals by the simulator's exec namespace.
#
import main
import ngu
import struct
import ujson
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from dleq import generate_dleq_proof, verify_dleq_proof
from exceptions import FatalPSBTIssue
from silentpayments import (
    _combine_pubkeys,
    _compute_ecdh_share,
    _compute_input_hash,
    _compute_silent_payment_output_script,
    _compute_silent_payment_spending_privkey,
    _negate_if_odd_y,
    _sum_privkeys,
    SilentPaymentsMixin,
)

if isinstance(main.SP_VERIFY, str):
    with open(main.SP_VERIFY) as f:
        params = ujson.load(f)
else:
    params = main.SP_VERIFY

mode = params.get("mode")


# ---------------------------------------------------------------------------
# MockPSBT infrastructure for firmware method testing
# ---------------------------------------------------------------------------


class MockInput:
    def __init__(self):
        self.utxo_spk = None
        self.taproot_internal_key = None
        self.redeem_script = None
        self.sighash = None
        self.previous_txid = None
        self.prevout_idx = None
        self.sp_ecdh_shares = {}
        self.sp_dleq_proofs = {}
        self.subpaths = []
        self.taproot_subpaths = []
        self.sp_idxs = None
        self.ik_idx = None


class MockOutput:
    def __init__(self):
        self.sp_v0_info = None
        self.sp_v0_label = None
        self.script = None


class MockPSBT(SilentPaymentsMixin):
    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.sp_global_ecdh_shares = {}
        self.sp_global_dleq_proofs = {}
        self.txn_modifiable = None
        self.my_xfp = 0

    def get(self, x):
        return x

    def parse_xfp_path(self, coords):
        return coords


def _build_mock_psbt(params):
    psbt = MockPSBT()
    psbt.txn_modifiable = params.get("txn_modifiable")

    global_ecdh = params.get("global_ecdh") or {}
    global_dleq = params.get("global_dleq") or {}
    psbt.sp_global_ecdh_shares = {a2b_hex(k): a2b_hex(v) for k, v in global_ecdh.items()}
    psbt.sp_global_dleq_proofs = {a2b_hex(k): a2b_hex(v) for k, v in global_dleq.items()}

    for d in params.get("inputs", []):
        inp = MockInput()
        if d.get("utxo_spk"):
            inp.utxo_spk = a2b_hex(d["utxo_spk"])
        elif d.get("witness_utxo"):
            wu = a2b_hex(d["witness_utxo"])
            # Extract scriptPubKey: 8 bytes value + varint length + script
            script_len = wu[8]
            inp.utxo_spk = wu[9 : 9 + script_len]
        if d.get("taproot_internal_key"):
            inp.taproot_internal_key = a2b_hex(d["taproot_internal_key"])
        if d.get("redeem_script"):
            inp.redeem_script = a2b_hex(d["redeem_script"])
        inp.sighash = d.get("sighash")
        if d.get("previous_txid"):
            inp.previous_txid = a2b_hex(d["previous_txid"])
        if d.get("prevout_idx") is not None:
            inp.prevout_idx = struct.pack("<I", d["prevout_idx"])
        inp.sp_ecdh_shares = {a2b_hex(k): a2b_hex(v) for k, v in (d.get("ecdh_shares") or {}).items()}
        inp.sp_dleq_proofs = {a2b_hex(k): a2b_hex(v) for k, v in (d.get("dleq_proofs") or {}).items()}
        # subpaths: list of (pubkey_bytes, ()) for _pubkey_from_input iteration
        inp.subpaths = [(a2b_hex(pk), ()) for pk in (d.get("bip32_paths") or [])]
        psbt.inputs.append(inp)

    for d in params.get("outputs", []):
        outp = MockOutput()
        if d.get("sp_v0_info"):
            outp.sp_v0_info = a2b_hex(d["sp_v0_info"])
        if d.get("sp_v0_label"):
            outp.sp_v0_label = a2b_hex(d["sp_v0_label"])
        if d.get("script"):
            outp.script = a2b_hex(d["script"])
        psbt.outputs.append(outp)

    return psbt


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

if mode == "compute_foreign_share":
    # Compute ECDH share + DLEQ proof for a foreign input's private key
    privkey = a2b_hex(params["privkey"])
    scan_key = a2b_hex(params["scan_key"])
    ecdh_share = _compute_ecdh_share(privkey, scan_key)
    proof = generate_dleq_proof(privkey, scan_key)
    RV.write(b2a_hex(ecdh_share).decode() + "," + b2a_hex(proof).decode())

elif mode == "verify_vector_dleq":
    # Verify a DLEQ proof from a test vector
    pubkey = a2b_hex(params["pubkey"])
    scan_key = a2b_hex(params["scan_key"])
    ecdh_share = a2b_hex(params["ecdh_share"])
    proof = a2b_hex(params["proof"])
    expected = params["expected"]
    result = verify_dleq_proof(pubkey, scan_key, ecdh_share, proof)
    assert result == expected, "DLEQ verify: expected %s got %s" % (expected, result)

elif mode == "compute_ecdh_share":
    # Compute and return ECDH share
    privkey = a2b_hex(params["privkey"])
    scan_key = a2b_hex(params["scan_key"])
    result = _compute_ecdh_share(privkey, scan_key)
    RV.write(b2a_hex(result).decode())

elif mode == "compute_output_script":
    # Compute and return output script
    outpoints = []
    for t, v in params["outpoints"]:
        outpoints.append((a2b_hex(t), a2b_hex(v)))
    summed_pubkey = a2b_hex(params["summed_pubkey"])
    ecdh_share = a2b_hex(params["ecdh_share"])
    spend_key = a2b_hex(params["spend_key"])
    k = params["k"]
    result = _compute_silent_payment_output_script(outpoints, summed_pubkey, ecdh_share, spend_key, k)
    RV.write(b2a_hex(result).decode())

elif mode == "combine_pubkeys":
    # Combine pubkeys and return result
    pubkeys = []
    for h in params["pubkeys"]:
        pubkeys.append(a2b_hex(h))
    result = _combine_pubkeys(pubkeys) if len(pubkeys) > 1 else pubkeys[0]
    RV.write(b2a_hex(result).decode())

elif mode == "validate_sp":
    # Run firmware validation methods; write error string to RV on failure
    psbt = _build_mock_psbt(params)
    try:
        psbt._validate_psbt_structure()
        psbt._validate_input_eligibility()
        psbt._validate_ecdh_coverage()
        psbt._compute_silent_payment_output_scripts()
    except FatalPSBTIssue as e:
        RV.write(str(e))

elif mode == "get_ecdh_and_pubkey":
    # Call _get_ecdh_and_pubkey and return "ecdh_hex,pubkey_hex"
    psbt = _build_mock_psbt(params)
    scan_key = a2b_hex(params["scan_key"])
    ecdh_share, summed_pubkey = psbt._get_ecdh_and_pubkey(scan_key)
    ecdh_hex = b2a_hex(ecdh_share).decode() if ecdh_share else ""
    pubkey_hex = b2a_hex(summed_pubkey).decode() if summed_pubkey else ""
    RV.write(ecdh_hex + "," + pubkey_hex)

elif mode == "get_outpoints":
    # Call _get_outpoints and return "txid:vout,txid:vout,..."
    psbt = _build_mock_psbt(params)
    outpoints = psbt._get_outpoints()
    parts = []
    for txid, vout in outpoints:
        parts.append(b2a_hex(txid).decode() + ":" + b2a_hex(vout).decode())
    RV.write(",".join(parts))

elif mode == "sum_privkeys":
    # Sum a list of normalized privkeys; return as 64-char hex
    privkeys = [a2b_hex(h) for h in params["privkeys"]]
    result = _sum_privkeys(privkeys)
    RV.write(b2a_hex(result).decode())

elif mode == "pubkey_from_input":
    # Call _pubkey_from_input for a specific input; return pubkey hex or ""
    psbt = _build_mock_psbt(params)
    i = params["input_index"]
    pk = psbt._pubkey_from_input(psbt.inputs[i])
    RV.write(b2a_hex(pk).decode() if pk else "")

elif mode == "compute_input_hash":
    outpoints = [(a2b_hex(t), a2b_hex(v)) for t, v in params["outpoints"]]
    A_sum = a2b_hex(params["A_sum"])
    result = _compute_input_hash(outpoints, A_sum)
    RV.write(b2a_hex(result).decode())

elif mode == "compute_shared_secret":
    ecdh_share = a2b_hex(params["ecdh_share"])
    input_hash = a2b_hex(params["input_hash"])
    result = ngu.secp256k1.ec_pubkey_tweak_mul(ecdh_share, input_hash)
    RV.write(b2a_hex(result).decode())

elif mode == "pubkey_from_privkey":
    # Compute pubkey = privkey * G; return 33-byte compressed hex
    privkey = a2b_hex(params["privkey"])
    G = ngu.secp256k1.generator()
    pubkey = ngu.secp256k1.ec_pubkey_tweak_mul(G, privkey)
    RV.write(b2a_hex(pubkey).decode())

elif mode == "compute_spending_privkey":
    b_spend = a2b_hex(params["b_spend"])
    tweak = a2b_hex(params["tweak"])
    result = _compute_silent_payment_spending_privkey(b_spend, tweak)
    RV.write(b2a_hex(result).decode())

elif mode == "negate_if_odd_y":
    privkey = a2b_hex(params["privkey"])
    result = _negate_if_odd_y(privkey)
    RV.write(b2a_hex(result).decode())
