# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_bip352_vectors.py - BIP-352 send/receive test vector verification
#
# Verifies that crypto primitives in silentpayments.py match the BIP-352
# reference test vectors. Pubkey extraction from raw scriptSig/witness is
# done CPython-side; all EC math is delegated to the simulator
#
import hashlib
import json
import pytest
import struct
from sp_helpers import (
    _sim_compute_ecdh_share,
    _sim_compute_input_hash,
    _sim_compute_shared_secret,
    _sim_compute_spending_privkey,
    _sim_compute_output_script,
    _sim_pubkey_from_privkey,
    _sim_combine_pubkeys,
    _sim_negate_if_odd_y,
    _sim_sum_privkeys,
)


NUMS_H = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)


def load_bip352_vectors():
    with open("bip352_test_vectors.json") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CPython-side helpers
# ---------------------------------------------------------------------------


def _hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _parse_witness_stack(txinwitness_hex):
    """Parse serialized witness into a list of stack items (bytes)."""
    if not txinwitness_hex:
        return []
    raw = bytes.fromhex(txinwitness_hex)
    pos = 0
    n_items = raw[pos]
    pos += 1
    items = []
    for _ in range(n_items):
        # CompactSize length
        length = raw[pos]
        pos += 1
        if length == 0xFD:
            length = int.from_bytes(raw[pos : pos + 2], "little")
            pos += 2
        elif length == 0xFE:
            length = int.from_bytes(raw[pos : pos + 4], "little")
            pos += 4
        items.append(raw[pos : pos + length])
        pos += length
    return items


def _is_p2pkh(spk):
    return (
        len(spk) == 25
        and spk[0] == 0x76
        and spk[1] == 0xA9
        and spk[-2] == 0x88
        and spk[-1] == 0xAC
    )


def _is_p2wpkh(spk):
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def _is_p2tr(spk):
    return len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20


def _is_p2sh(spk):
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[-1] == 0x87


def _extract_pubkey_from_vin(vin):
    """Extract compressed pubkey from a BIP-352 test vector vin entry.

    Returns (pubkey_bytes, is_taproot) or (None, None) if ineligible.
    Follows BIP-352 reference get_pubkey_from_input() logic.
    """
    spk = bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"])
    script_sig = bytes.fromhex(vin.get("scriptSig", ""))
    witness = _parse_witness_stack(vin.get("txinwitness", ""))

    if _is_p2pkh(spk):
        spk_hash = spk[3:23]
        for i in range(len(script_sig), 32, -1):
            candidate = script_sig[i - 33 : i]
            if candidate[0] in (0x02, 0x03) and _hash160(candidate) == spk_hash:
                return candidate, False
        return None, None

    if _is_p2sh(spk):
        redeem_script = script_sig[1:]
        if _is_p2wpkh(redeem_script) and witness:
            pk = witness[-1]
            if len(pk) == 33 and pk[0] in (0x02, 0x03):
                return pk, False
        return None, None

    if _is_p2wpkh(spk):
        if witness:
            pk = witness[-1]
            if len(pk) == 33 and pk[0] in (0x02, 0x03):
                return pk, False
        return None, None

    if _is_p2tr(spk):
        stack = list(witness)
        if stack:
            if len(stack) > 1 and stack[-1][0] == 0x50:
                stack.pop()
            if len(stack) > 1:
                control_block = stack[-1]
                internal_key = control_block[1:33]
                if internal_key == NUMS_H:
                    return None, None
            x_only = spk[2:34]
            return b"\x02" + x_only, True

    return None, None


def _build_outpoints(vin_list):
    """Build (txid_bytes, vout_bytes) list from vin entries.

    txid is reversed to internal byte order, vout is 4-byte LE.
    """
    outpoints = []
    for vin in vin_list:
        txid = bytes.fromhex(vin["txid"])[::-1]
        vout = struct.pack("<I", vin["vout"])
        outpoints.append((txid, vout))
    return outpoints


def _extract_key_material(vin_list):
    """Extract compressed pubkeys and taproot flags for all eligible vins."""
    results = []
    for vin in vin_list:
        pk, is_taproot = _extract_pubkey_from_vin(vin)
        if pk is not None:
            results.append((pk, is_taproot, vin.get("private_key")))
    return results


def _sum_privkeys(sim_exec, sim_execfile, extracted):
    """Sum private keys with taproot y-parity negation.

    Per-entry normalization is done via the simulator; the sum itself is
    delegated to the firmware _sum_privkeys primitive.

    extracted: list of (pubkey_bytes, is_taproot, private_key_hex) tuples.
    """
    normalized = []
    for _, is_taproot, privkey_hex in extracted:
        privkey_bytes = bytes.fromhex(privkey_hex)
        if is_taproot:
            privkey_bytes = _sim_negate_if_odd_y(sim_exec, sim_execfile, privkey_bytes)
        normalized.append(privkey_bytes)
    return _sim_sum_privkeys(sim_exec, sim_execfile, normalized)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

_VECTORS = load_bip352_vectors()
_VEC_IDS = [v["comment"][:60] for v in _VECTORS]


class TestBIP352Sending:
    @pytest.mark.parametrize("vec_idx", range(len(_VECTORS)), ids=_VEC_IDS)
    def test_sending(self, sim_exec, sim_execfile, vec_idx):
        vec = _VECTORS[vec_idx]
        sending = vec["sending"][0]
        expected = sending["expected"]
        vin_list = sending["given"]["vin"]
        recipients = sending["given"]["recipients"]
        outpoints = _build_outpoints(vin_list)

        # 1. Key material extraction
        extracted = _extract_key_material(vin_list)
        actual_pks = [pk.hex() for pk, _, _ in extracted]
        assert actual_pks == expected.get("input_pub_keys", []), (
            "input_pub_keys mismatch"
        )

        if not extracted:
            for eo in expected["outputs"]:
                assert eo == []
            return

        # Vectors with eligible inputs but no expected sum are expected to
        # fail while summing private keys (point-at-infinity / zero sum)
        expected_sum = expected.get("input_private_key_sum")
        if expected_sum is None:
            with pytest.raises(
                AssertionError, match="Invalid private key sum: result is zero"
            ):
                _sum_privkeys(sim_exec, sim_execfile, extracted)
            for eo in expected["outputs"]:
                assert eo == []
            return

        # 2. Private key sum (with taproot negation)
        a_sum = _sum_privkeys(sim_exec, sim_execfile, extracted)
        assert a_sum.hex() == expected_sum, "input_private_key_sum mismatch"

        pubkeys = [pk for pk, _, _ in extracted]
        A_sum = _sim_combine_pubkeys(sim_exec, sim_execfile, pubkeys)

        # Expand recipients by count and group by scan key
        expanded = []
        for recipient in recipients:
            expanded.extend([recipient] * recipient.get("count", 1))
        groups = {}
        for ri, recipient in enumerate(expanded):
            scan_key = recipient["scan_pub_key"]
            if scan_key not in groups:
                groups[scan_key] = []
            groups[scan_key].append((ri, recipient))

        if any(len(g) > 2323 for g in groups.values()):
            for eo in expected["outputs"]:
                assert eo == []
            return

        # 3. Shared secrets and 4. Output derivation
        actual_outputs = set()
        for scan_key_hex, group in groups.items():
            scan_pub_key = bytes.fromhex(scan_key_hex)
            ecdh_share = _sim_compute_ecdh_share(
                sim_exec, sim_execfile, a_sum, scan_pub_key
            )
            input_hash = _sim_compute_input_hash(
                sim_exec, sim_execfile, outpoints, A_sum
            )
            shared_secret = _sim_compute_shared_secret(
                sim_exec, sim_execfile, ecdh_share, input_hash
            )

            # Check shared_secret against expected (find first recipient index for this scan key)
            for ri, _ in group:
                es = expected["shared_secrets"][ri]
                if es is not None:
                    assert shared_secret.hex() == es, (
                        "shared_secret mismatch for recipient %d" % ri
                    )
                break

            for k, (ri, recipient) in enumerate(group):
                spend_pub_key = bytes.fromhex(recipient["spend_pub_key"])
                script = _sim_compute_output_script(
                    sim_exec,
                    sim_execfile,
                    outpoints,
                    A_sum,
                    ecdh_share,
                    spend_pub_key,
                    k,
                )
                actual_outputs.add(script[2:].hex())

        assert any(set(eo) == actual_outputs for eo in expected["outputs"]), (
            "output mismatch: got %s" % actual_outputs
        )


class TestBIP352Receiving:
    @pytest.mark.parametrize("vec_idx", range(len(_VECTORS)), ids=_VEC_IDS)
    def test_receiving(self, sim_exec, sim_execfile, vec_idx):
        vec = _VECTORS[vec_idx]
        receiving = vec["receiving"][0]
        expected = receiving["expected"]
        vin_list = receiving["given"]["vin"]
        scan_priv_key = bytes.fromhex(
            receiving["given"]["key_material"]["scan_priv_key"]
        )
        spend_priv_key = bytes.fromhex(
            receiving["given"]["key_material"]["spend_priv_key"]
        )
        outpoints = _build_outpoints(vin_list)

        # 1. Extract key material and compute A_sum
        extracted = _extract_key_material(vin_list)

        if not extracted:
            assert expected.get("outputs", []) == []
            return

        expected_pk_sum = expected.get("input_pub_key_sum")
        if expected_pk_sum is None:
            # Point at infinity or no valid inputs
            assert expected.get("outputs", []) == []
            return

        pubkeys = [pk for pk, _, _ in extracted]
        A_sum = _sim_combine_pubkeys(sim_exec, sim_execfile, pubkeys)
        assert A_sum.hex() == expected_pk_sum, "input_pub_key_sum mismatch"

        # 2. Shared secret
        input_hash = _sim_compute_input_hash(sim_exec, sim_execfile, outpoints, A_sum)
        ecdh_share = _sim_compute_ecdh_share(
            sim_exec, sim_execfile, scan_priv_key, A_sum
        )
        shared_secret = _sim_compute_shared_secret(
            sim_exec, sim_execfile, ecdh_share, input_hash
        )
        assert shared_secret.hex() == expected.get("shared_secret"), (
            "shared_secret mismatch"
        )

        # 3. Spending privkey tweaks
        expected_outputs = expected.get("outputs", [])
        if not expected_outputs:
            return

        for expected_out in expected_outputs:
            expected_tweak = bytes.fromhex(expected_out["priv_key_tweak"])
            expected_pubkey = expected_out["pub_key"]
            d = _sim_compute_spending_privkey(
                sim_exec, sim_execfile, spend_priv_key, expected_tweak
            )
            computed_pk = _sim_pubkey_from_privkey(sim_exec, sim_execfile, d)
            assert computed_pk[1:].hex() == expected_pubkey, (
                "spending privkey mismatch for output %s" % expected_pubkey
            )
