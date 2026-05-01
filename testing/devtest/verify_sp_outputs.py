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
import ujson
from dleq import generate_dleq_proof, verify_dleq_proof
from exceptions import FatalPSBTIssue
from psbt import psbtObject
from serializations import SIGHASH_DEFAULT
from silentpayments import (
    _combine_pubkeys,
    _compute_ecdh_share,
    _compute_input_hash,
    _compute_silent_payment_output_script,
    compute_silent_payment_spending_privkey,
    _compute_silent_payment_spending_xonly,
    _negate_if_odd_y,
    _sum_privkeys,
)
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from uio import BytesIO

if isinstance(main.SP_VERIFY, str):
    with open(main.SP_VERIFY) as f:
        params = ujson.load(f)
else:
    params = main.SP_VERIFY

mode = params.get("mode")


def _load_psbt(params):
    """Parse raw PSBT bytes into a real psbtObject resolve utxo for each input"""
    psbt = psbtObject.read_psbt(BytesIO(a2b_hex(params["psbt"])))
    for inp in psbt.inputs:
        try:
            if inp.witness_utxo:
                # witness path: get_utxo() ignores the vout index
                utxo = inp.get_utxo(0)
            elif inp.prevout_idx is not None:
                # non-witness UTXO: need the actual vout index from PSBT_IN_OUTPUT_INDEX
                prevout_idx = psbt.get(inp.prevout_idx)
                vout_idx = int.from_bytes(prevout_idx, "little")
                utxo = inp.get_utxo(vout_idx)
            else:
                continue
            inp.amount = utxo.nValue
            inp.utxo_spk = utxo.scriptPubKey
        except Exception as e:
            print("Error: failed to resolve utxo for input:", e)
    return psbt


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

if mode == "generate_dleq_proof":
    # Compute DLEQ proof for a private key / scan key
    privkey = a2b_hex(params["privkey"])
    scan_key = a2b_hex(params["scan_key"])
    proof = generate_dleq_proof(privkey, scan_key)
    RV.write(b2a_hex(proof).decode())

elif mode == "verify_vector_dleq":
    # Verify a DLEQ proof from a test vector
    pubkey = a2b_hex(params["pubkey"])
    scan_key = a2b_hex(params["scan_key"])
    ecdh_share = a2b_hex(params["ecdh_share"])
    proof = a2b_hex(params["proof"])
    result = verify_dleq_proof(pubkey, scan_key, ecdh_share, proof)
    assert result, "DLEQ verify failed"

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
    psbt = _load_psbt(params)
    try:
        psbt._validate_psbt_structure()
        psbt._validate_input_eligibility()
        psbt._validate_ecdh_coverage()
        psbt._compute_silent_payment_output_scripts()
    except FatalPSBTIssue as e:
        RV.write(str(e))

elif mode == "get_ecdh_and_pubkey":
    # Call _get_ecdh_and_pubkey and return "ecdh_hex,pubkey_hex"
    psbt = _load_psbt(params)
    scan_key = a2b_hex(params["scan_key"])
    ecdh_share, summed_pubkey = psbt._get_ecdh_and_pubkey(scan_key)
    ecdh_hex = b2a_hex(ecdh_share).decode() if ecdh_share else ""
    pubkey_hex = b2a_hex(summed_pubkey).decode() if summed_pubkey else ""
    RV.write(ecdh_hex + "," + pubkey_hex)

elif mode == "get_outpoints":
    # Call _get_outpoints and return "txid:vout,txid:vout,..."
    psbt = _load_psbt(params)
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
    psbt = _load_psbt(params)
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
    result = compute_silent_payment_spending_privkey(b_spend, tweak)
    RV.write(b2a_hex(result).decode())

elif mode == "compute_spend_output_xonly":
    B_spend = a2b_hex(params["B_spend"])
    sp_tweak = a2b_hex(params["sp_tweak"])
    result = _compute_silent_payment_spending_xonly(B_spend, sp_tweak)
    RV.write(b2a_hex(result).decode())

elif mode == "negate_if_odd_y":
    privkey = a2b_hex(params["privkey"])
    result = _negate_if_odd_y(privkey)
    RV.write(b2a_hex(result).decode())

elif mode == "verify_taproot_key_spend_signature":
    psbt = psbtObject.read_psbt(BytesIO(a2b_hex(params["psbt"])))
    input_index = params["input_index"]

    if psbt.version is None:
        psbt.version = 2 if psbt.txn is None else 0
    psbt.is_v2 = psbt.version >= 2

    for idx, inp in enumerate(psbt.inputs):
        utxo = inp.get_utxo(idx)
        inp.amount = utxo.nValue
        inp.utxo_spk = utxo.scriptPubKey

    inp = psbt.inputs[input_index]
    # P2TR scriptPubKey: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only>
    output_xonly = inp.utxo_spk[2:34]

    sig_coords = inp.taproot_key_sig
    assert sig_coords, "Missing taproot key signature"
    sig = psbt.get(sig_coords)

    hash_type = SIGHASH_DEFAULT if len(sig) == 64 else sig[-1]
    digest = psbt.make_txn_taproot_sighash(input_index, hash_type=hash_type)

    try:
        result = ngu.secp256k1.verify_schnorr(sig[:64], digest, ngu.secp256k1.xonly_pubkey(output_xonly))
    except Exception:
        result = False

    assert result, "Taproot spend signature verify failed"
