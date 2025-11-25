# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sp_helpers.py - Shared simulator helpers for Silent Payment tests
#
# Used by test_silentpayments.py, test_bip352_vectors.py and test_bip375_vectors.py
#
import json
import os
import struct
import tempfile

# Path for large params that exceed the sim_exec message limit
_SP_PARAMS_FILE = os.path.join(tempfile.gettempdir(), "sp_verify_params.json")


def _read_varint(data, offset):
    first = data[offset]
    if first < 0xFD:
        return first, 1
    elif first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], 3
    elif first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], 9


def _extract_spk_from_tx(tx, vout_idx):
    """Return the scriptPubKey bytes at vout_idx from a raw serialized transaction."""
    offset = 4  # skip version
    if tx[offset] == 0x00:  # segwit marker
        offset += 2
    num_in, n = _read_varint(tx, offset)
    offset += n
    for _ in range(num_in):
        offset += 36  # txid + vout
        script_len, n = _read_varint(tx, offset)
        offset += n + script_len + 4  # scriptSig + sequence
    num_out, n = _read_varint(tx, offset)
    offset += n
    for i in range(num_out):
        offset += 8  # value
        script_len, n = _read_varint(tx, offset)
        offset += n
        if i == vout_idx:
            return tx[offset : offset + script_len]
        offset += script_len
    return None


def _sim_sp(sim_exec, sim_execfile, mode, params):
    """Call devtest/verify_sp_outputs.py with given mode and params.

    For modes that write to RV (compute_*), returns the string result.
    For assertion-only modes, returns None (raises on failure).
    """
    params_with_mode = {**params, "mode": mode}
    # Always use the file path to keep the sim_exec command short (~80 bytes).
    # Sending large dict reprs directly over the Unix pipe causes intermittent
    # TimeoutError when the simulator's receive buffer fills up.
    with open(_SP_PARAMS_FILE, "w") as f:
        json.dump(params_with_mode, f)
    sim_exec("import main; main.SP_VERIFY = %r" % _SP_PARAMS_FILE)
    rv = sim_execfile("devtest/verify_sp_outputs.py")
    if rv:
        # Modes that use RV.write return data; assertion-only modes return ''
        # If it contains a traceback, it's an error
        if "Traceback" in rv or "AssertionError" in rv:
            raise AssertionError(rv)
        return rv
    return None


def _serialize_psbt(psbt):
    """Convert a BasicPSBT to a plain dict for transmission to the simulator."""
    inputs = []
    for inp in psbt.inputs:
        d = {
            "sighash": inp.sighash,
            "previous_txid": inp.previous_txid.hex() if inp.previous_txid else None,
            "prevout_idx": inp.prevout_idx,
            "ecdh_shares": {k.hex(): v.hex() for k, v in inp.sp_ecdh_shares.items()},
            "dleq_proofs": {k.hex(): v.hex() for k, v in inp.sp_dleq_proofs.items()},
            "bip32_paths": [pk.hex() for pk in inp.bip32_paths],
        }
        if inp.witness_utxo:
            d["witness_utxo"] = inp.witness_utxo.hex()
        elif inp.utxo and inp.prevout_idx is not None:
            spk = _extract_spk_from_tx(inp.utxo, inp.prevout_idx)
            if spk:
                d["utxo_spk"] = spk.hex()
        if inp.taproot_internal_key:
            d["taproot_internal_key"] = inp.taproot_internal_key.hex()
        if inp.redeem_script:
            d["redeem_script"] = inp.redeem_script.hex()
        inputs.append(d)

    outputs = []
    for outp in psbt.outputs:
        outputs.append(
            {
                "sp_v0_info": outp.sp_v0_info.hex() if outp.sp_v0_info else None,
                "sp_v0_label": outp.sp_v0_label.hex() if outp.sp_v0_label else None,
                "script": outp.script.hex() if outp.script else None,
            }
        )

    return {
        "txn_modifiable": psbt.txn_modifiable,
        "global_ecdh": {
            k.hex(): v.hex() for k, v in psbt.sp_global_ecdh_shares.items()
        },
        "global_dleq": {
            k.hex(): v.hex() for k, v in psbt.sp_global_dleq_proofs.items()
        },
        "inputs": inputs,
        "outputs": outputs,
    }


def _sim_validate_sp(sim_exec, sim_execfile, psbt):
    """Run firmware SP validation on the PSBT. Returns error string or ''."""
    rv = _sim_sp(sim_exec, sim_execfile, "validate_sp", _serialize_psbt(psbt))
    return rv or ""


def _sim_get_ecdh_and_pubkey(sim_exec, sim_execfile, psbt, scan_key):
    """Return (ecdh_share_bytes, summed_pubkey_bytes) or (None, None)."""
    params = {**_serialize_psbt(psbt), "scan_key": scan_key.hex()}
    rv = _sim_sp(sim_exec, sim_execfile, "get_ecdh_and_pubkey", params)
    if not rv:
        return None, None
    ecdh_hex, pubkey_hex = rv.split(",")
    return (
        bytes.fromhex(ecdh_hex) if ecdh_hex else None,
        bytes.fromhex(pubkey_hex) if pubkey_hex else None,
    )


def _sim_get_outpoints(sim_exec, sim_execfile, psbt):
    """Return list of (txid_bytes, vout_bytes) from firmware _get_outpoints()."""
    rv = _sim_sp(sim_exec, sim_execfile, "get_outpoints", _serialize_psbt(psbt))
    outpoints = []
    for pair in rv.split(","):
        txid_hex, vout_hex = pair.split(":")
        outpoints.append((bytes.fromhex(txid_hex), bytes.fromhex(vout_hex)))
    return outpoints


def _sim_pubkey_from_input(sim_exec, sim_execfile, psbt, input_index):
    """Return pubkey bytes from firmware _pubkey_from_input(), or None."""
    params = {**_serialize_psbt(psbt), "input_index": input_index}
    rv = _sim_sp(sim_exec, sim_execfile, "pubkey_from_input", params)
    return bytes.fromhex(rv) if rv else None


def _sim_verify_dleq(
    sim_exec, sim_execfile, pubkey, scan_key, ecdh_share, proof, expected=True
):
    _sim_sp(
        sim_exec,
        sim_execfile,
        "verify_vector_dleq",
        {
            "pubkey": pubkey.hex(),
            "scan_key": scan_key.hex(),
            "ecdh_share": ecdh_share.hex(),
            "proof": proof.hex(),
            "expected": expected,
        },
    )


def _sim_compute_ecdh_share(sim_exec, sim_execfile, privkey, scan_key):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_ecdh_share",
        {
            "privkey": privkey.hex(),
            "scan_key": scan_key.hex(),
        },
    )
    return bytes.fromhex(rv)


def _sim_compute_output_script(
    sim_exec, sim_execfile, outpoints, summed_pubkey, ecdh_share, spend_key, k
):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_output_script",
        {
            "outpoints": [(t.hex(), v.hex()) for t, v in outpoints],
            "summed_pubkey": summed_pubkey.hex(),
            "ecdh_share": ecdh_share.hex(),
            "spend_key": spend_key.hex(),
            "k": k,
        },
    )
    return bytes.fromhex(rv)


def _sim_combine_pubkeys(sim_exec, sim_execfile, pubkeys):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "combine_pubkeys",
        {
            "pubkeys": [pk.hex() for pk in pubkeys],
        },
    )
    return bytes.fromhex(rv)


def _sim_compute_input_hash(sim_exec, sim_execfile, outpoints, A_sum):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_input_hash",
        {
            "outpoints": [(t.hex(), v.hex()) for t, v in outpoints],
            "A_sum": A_sum.hex(),
        },
    )
    return bytes.fromhex(rv)


def _sim_compute_shared_secret(sim_exec, sim_execfile, ecdh_share, input_hash):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_shared_secret",
        {
            "ecdh_share": ecdh_share.hex(),
            "input_hash": input_hash.hex(),
        },
    )
    return bytes.fromhex(rv)


def _sim_compute_spending_privkey(sim_exec, sim_execfile, b_spend, tweak):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "compute_spending_privkey",
        {
            "b_spend": b_spend.hex(),
            "tweak": tweak.hex(),
        },
    )
    return bytes.fromhex(rv) if rv else None


def _sim_pubkey_from_privkey(sim_exec, sim_execfile, privkey):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "pubkey_from_privkey",
        {
            "privkey": privkey.hex(),
        },
    )
    return bytes.fromhex(rv) if rv else None


def _sim_sum_privkeys(sim_exec, sim_execfile, privkeys):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "sum_privkeys",
        {
            "privkeys": [pk.hex() for pk in privkeys],
        },
    )
    return bytes.fromhex(rv)


def _sim_negate_if_odd_y(sim_exec, sim_execfile, privkey):
    rv = _sim_sp(
        sim_exec,
        sim_execfile,
        "negate_if_odd_y",
        {
            "privkey": privkey.hex(),
        },
    )
    return bytes.fromhex(rv)
