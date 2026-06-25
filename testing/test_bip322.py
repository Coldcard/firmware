# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-322 Message Signing and Proof of Reserves
# NOTE: Run this module with and without --psbt2 to cover both PSBT versions.
#
import pytest, time, os
from io import BytesIO
from decimal import Decimal
from constants import SIGHASH_MAP, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH
from bip322 import bip322_txn, bip322_ms_txn, BIP32Node
from ctransaction import CTransaction, CTxIn, COutPoint, CTxOut
from helpers import addr_from_display_format, str_to_path
from txn import render_address


@pytest.fixture
def verify_msg_bip322_por(cap_story, press_select, press_cancel, cap_menu):
    def doit(msg, is_por=True, refuse=False):
        title, story = cap_story()
        assert title == "OK TO SIGN?"
        assert ("Proof of Reserves" if is_por else "BIP-322 Message") in story
        assert msg in story
        if refuse:
            press_cancel()
            time.sleep(.1)
            assert "Ready To Sign" in cap_menu()

    return doit


@pytest.mark.parametrize("msg", [b"POR", b"This is the signed message"])
@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None, None]],
    [["p2sh-p2wpkh", None, None], ["p2wpkh", None, 100000], ["p2pkh", None, 1000000]],
    [["p2wpkh", None, None]] + ([["p2wpkh", None, 1000000]] * 20),
    [["p2pkh", None, None]] + ([["p2wpkh", None, 1000000]] * 5) + ([["p2sh-p2wpkh", None, 10000000]] * 5),
])
def test_bip322_por(msg, ins, bip322_txn, start_sign, end_sign, cap_story, need_keypress,
                    press_select, verify_msg_bip322_por, sim_root_dir, press_cancel,
                    bip322_verify):
    num_ins = len(ins)
    amt = sum([i[2] or 0 for i in ins])
    psbt, msg_challenge = bip322_txn(ins, msg=msg)
    with open(f'{sim_root_dir}/debug/last-b322-por.psbt', 'wb') as f:
        f.write(psbt)

    start_sign(psbt, finalize=True)

    is_por = num_ins > 1
    verify_msg_bip322_por(msg.decode(), is_por=is_por)

    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert ("Proof of Reserves" if is_por else "BIP-322 Message") in story
    assert 'Network fee' not in story  # different story for POR
    assert "explore transaction" in story
    if not is_por:
        assert "Proof of Reserves" not in story
        assert "Amount " not in story
        assert "1 input" not in story
        assert "1 output" not in story
        assert "sign message" in story
    else:
        assert ("Amount %s XTN" % str(Decimal(amt/100000000).quantize(Decimal('.00000001')))) in story
        assert ("%d inputs" % num_ins) in story
        assert "sign proof of reserves" in story

    assert ("Message:\n%s" % msg.decode()) in story
    assert "Message Hash:" not in story
    assert "Challenge Address:" in story
    assert "Message Challenge:" not in story
    assert ("1 output" in story) == is_por
    assert "- OP_RETURN -" not in story
    assert "null-data" not in story
    signed = end_sign(accept=True, exit_export_loop=False)
    bip322_verify(signed)
    title, story = cap_story()
    assert title == "PSBT Signed"
    assert "Signed BIP-322 PSBT shared via USB." in story
    assert "Finalized TX ready for broadcast" not in story
    assert "TXID:" not in story
    press_cancel()


def test_bip322_por_utf8_msg(bip322_txn, start_sign, end_sign, cap_story, press_select,
                             bip322_verify):
    msg = "UTF-8 support: öäüéàè - test text".encode()
    psbt, _ = bip322_txn([["p2wpkh", None, None]], msg=msg)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "BIP-322 Message" in story
    assert "Proof of Reserves" not in story
    assert msg.decode() in story
    assert "WARNING" in story
    assert "non-ASCII characters" in story
    assert "Message Hash:" not in story
    signed = end_sign(accept=True)
    bip322_verify(signed)


def test_bip322_global_msg_hash_mismatch(bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        psbt_in.bip322_msg = b"wrong message"

    psbt, _ = bip322_txn([["p2wpkh", None, None]], msg=b"right message", psbt_hacker=hack)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


def test_bip322_missing_global_msg(bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        psbt_in.bip322_msg = None

    psbt, _ = bip322_txn([["p2wpkh", None, None]], psbt_hacker=hack)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "msg" in story


def test_bip322_missing_input0_utxo(bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        psbt_in.inputs[0].utxo = None
        psbt_in.inputs[0].witness_utxo = None

    psbt, _ = bip322_txn([["p2wpkh", None, None]], psbt_hacker=hack)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "Missing own UTXO" in story


@pytest.mark.parametrize("ins,label", [
    ([["p2wpkh", None, None]], "BIP-322 Message"),
    ([["p2wpkh", None, None], ["p2wpkh", None, 10000000]], "Proof of Reserves"),
])
def test_bip322_psbtv2_accepted(ins, label, bip322_txn, start_sign, end_sign, cap_story,
                                bip322_verify):
    psbt, _ = bip322_txn(ins, psbt_v2=True)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert label in story
    signed = end_sign(accept=True)
    bip322_verify(signed)


@pytest.mark.parametrize("to_sign_nVersion", [1, 3])
def test_bip322_invalid_to_sign_version(to_sign_nVersion, bip322_txn, start_sign, cap_story):
    psbt, _ = bip322_txn([["p2wpkh", None, None], ["p2wpkh", None, 10000000]],
                         to_sign_nVersion=to_sign_nVersion)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "bad txn version" in story


def test_bip322_input0_explorer(bip322_txn, start_sign, cap_story, need_keypress,
                                pick_menu_item, press_cancel):
    psbt, msg_challenge = bip322_txn([["p2wpkh", None, None], ["p2wpkh", None, 10000000]])

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "Press (2) to explore transaction" in story

    need_keypress("2")
    time.sleep(.1)
    pick_menu_item("Inputs")
    time.sleep(.1)

    title, story = cap_story()
    assert title == "Input 0"

    sections = story.split("\n\n")
    txid, n = sections[0].split(":")
    assert len(txid) == 64
    assert n == "0"

    assert "=== UTXO ===" in sections
    utxo_idx = sections.index("=== UTXO ===")
    assert sections[utxo_idx + 1] == "0.00000000 XTN"
    assert sections[utxo_idx + 2] == msg_challenge.hex()
    assert addr_from_display_format(sections[utxo_idx + 3]) == render_address(msg_challenge)
    assert sections[utxo_idx + 4] == "Address Format: p2wpkh"

    assert "=== PSBT ===" in sections
    assert "Our key:" in sections
    assert "- OP_RETURN -" not in story
    assert "null-data" not in story

    press_cancel()


def test_bip322_output_explorer(bip322_txn, start_sign, cap_story, need_keypress,
                                pick_menu_item, press_cancel):
    psbt, _ = bip322_txn([["p2wpkh", None, None], ["p2wpkh", None, 10000000]])

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "Proof of Reserves" in story
    assert "- OP_RETURN -" not in story
    assert "null-data" not in story
    assert "Press (2) to explore transaction" in story

    need_keypress("2")
    time.sleep(.1)
    pick_menu_item("Outputs")
    time.sleep(.1)

    title, story = cap_story()
    assert title == "0-0"
    assert "Output 0:" in story
    assert "0.00000000 XTN" in story
    assert "- OP_RETURN -" in story
    assert "null-data" in story

    press_cancel()
    press_cancel()
    press_cancel()


@pytest.mark.parametrize("sighash", [sh for sh in SIGHASH_MAP if sh != 'ALL'])
def test_bip322_por_invalid_sighash(sighash, bip322_txn, start_sign, cap_story, settings_set):
    settings_set("sighshchk", 1)  # BIP-322 POR still requires SIGHASH_ALL in warn-only mode.
    # all POR txns must have only SIGHASH_ALL
    psbt, _ = bip322_txn([["p2sh-p2wpkh", None, None], ["p2wpkh", None, 100000], ["p2pkh", None, 1000000]],
                         sighash=SIGHASH_MAP[sighash])
    start_sign(psbt, finalize=True)

    title, story = cap_story()
    assert title == "Failure"
    assert "POR not SIGHASH_ALL" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2wpkh", None, None], ["p2wpkh", None, 10000000]],
])
def test_bip322_0th_input_witness_utxo(ins, bip322_txn, start_sign, end_sign, cap_story,
                                       verify_msg_bip322_por, bip322_verify):
    # allowed when the BIP-322 message is provided in the global PSBT field
    psbt, _ = bip322_txn(ins, witness_utxo=[0])
    start_sign(psbt, finalize=True)
    verify_msg_bip322_por("POR", is_por=len(ins) > 1)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    signed = end_sign(accept=True)
    bip322_verify(signed)


def test_bip322_0th_input_witness_utxo_requires_zero_value(bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        txo = CTxOut()
        txo.deserialize(BytesIO(psbt_in.inputs[0].witness_utxo))
        txo.nValue = 1
        psbt_in.inputs[0].witness_utxo = txo.serialize()

    psbt, _ = bip322_txn([["p2wpkh", None, None], ["p2wpkh", None, 10000000]],
                         witness_utxo=[0], psbt_hacker=hack)

    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "input0 value" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None], ["p2wpkh", None, 10000000], ["p2wpkh", None, 10000000]],
    [["p2sh-p2wpkh", None, None], ["p2sh-p2wpkh", None, 10000000], ["p2sh-p2wpkh", None, 10000000]],
    [["p2pkh", None, None], ["p2wpkh", None, 10000000], ["p2sh-p2wpkh", None, 10000000]],
])
def test_bip322_Xth_input_witness_utxo(ins, bip322_txn, start_sign, cap_story, end_sign,
                                       verify_msg_bip322_por, bip322_verify):
    # allowed - input 0 has full utxo here, other inputs can be witness_utxo-only
    msg = b"hellow world"
    psbt, msg_challenge = bip322_txn(ins, witness_utxo=[1, 2], msg=msg)
    start_sign(psbt, finalize=True)
    verify_msg_bip322_por(msg.decode())
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert ("Message:\n%s" % msg.decode()) in story
    assert "Message Hash:" not in story
    assert "Challenge Address:" in story
    assert "Message Challenge:" not in story
    signed = end_sign(accept=True)
    bip322_verify(signed)


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None, None]],
    [["p2pkh", None, None], ["p2wpkh", None, 10000000], ["p2wpkh", None, 10000000]],
    [["p2wpkh", None, None], ["p2pkh", None, 10000000], ["p2pkh", None, 10000000]],
    [["p2sh-p2wpkh", None, None], ["p2sh-p2wpkh", None, 10000000], ["p2sh-p2wpkh", None, 10000000]],
])
def test_bip322_incomplete_psbt_bip32_paths(ins, bip322_txn, start_sign, cap_story,
                                            verify_msg_bip322_por):

    def hack(psbt_in):
        without_paths = 0 if len(psbt_in.inputs) == 1 else 1
        for i, inp in enumerate(psbt_in.inputs):
            if i == without_paths:
                inp.bip32_paths = None

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    if len(ins) == 1:
        assert title == "Failure"
        assert 'PSBT does not contain any key path information.' in story
    else:
        verify_msg_bip322_por("POR")
        time.sleep(.1)
        title, story = cap_story()
        assert "warning" in story
        assert "Limited Signing" in story
        assert "because we do not know the key: 1" in story


def test_bip322_por_input0_bip32_paths_required(bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        psbt_in.inputs[0].bip32_paths = None

    psbt, _ = bip322_txn([["p2wpkh", None, None], ["p2wpkh", None, 10000000]],
                         psbt_hacker=hack)

    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "not our key" in story


@pytest.mark.parametrize("ins", [
    [["p2sh-p2wpkh", None, None]],
    [["p2pkh", None, None], ["p2sh-p2wpkh", None, 10000000], ["p2wpkh", None, 100000000]],
    [["p2sh-p2wpkh", None, None], ["p2sh-p2wpkh", None, 10000000], ["p2pkh", None, 10000000]],
])
def test__bip322_incomplete_psbt_wrapped_redeem(ins, bip322_txn, start_sign, cap_story):

    def hack(psbt_in):
        for i, inp in enumerate(psbt_in.inputs):
            inp.redeem_script = None

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()

    assert title == "Failure"
    assert "Missing redeem/witness script" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None, None]],
])
def test_bip322_invalid_to_spend_scriptSig(ins, bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        to_spend = psbt_in.inputs[0].utxo

        to_sign = psbt_in.txn

        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(to_spend))
        to_sign_tx.deserialize(BytesIO(to_sign))

        for i in to_spend_tx.vin:
            i.scriptSig = b"a" * 34

        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()

        spendable = CTxIn(COutPoint(to_spend_tx.sha256, 0))
        to_sign_tx.vin= [spendable]

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None], ["p2wpkh", None, None]],
    [["p2sh-p2wpkh", None]],
])
def test_bip322_invalid_to_spend_prevout(ins, bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        to_spend = psbt_in.inputs[0].utxo

        to_sign = psbt_in.txn

        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(to_spend))
        to_sign_tx.deserialize(BytesIO(to_sign))

        if len(ins) == 2:
            to_spend_tx.vin[0].prevout.n = 0xfffffffe
        else:
            to_spend_tx.vin[0].prevout.hash = 1

        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()

        to_sign_tx.vin[0] = CTxIn(COutPoint(to_spend_tx.sha256, 0))

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None]],
])
def test_bip322_invalid_to_spend_num_inputs(ins, bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        to_spend = psbt_in.inputs[0].utxo

        to_sign = psbt_in.txn

        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(to_spend))
        to_sign_tx.deserialize(BytesIO(to_sign))

        to_spend_tx.vin.append(to_sign_tx.vin[0])  # two inputs

        assert len(to_spend_tx.vin) == 2

        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()

        spendable = CTxIn(COutPoint(to_spend_tx.sha256, 0))

        to_sign_tx.vin = [spendable]

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None]],
])
def test_bip322_invalid_to_spend_num_outputs(ins, bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        to_spend = psbt_in.inputs[0].utxo

        to_sign = psbt_in.txn

        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(to_spend))
        to_sign_tx.deserialize(BytesIO(to_sign))

        to_spend_tx.vout.append(to_sign_tx.vout[0])  # two inputs

        assert len(to_spend_tx.vout) == 2

        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()

        spendable = CTxIn(COutPoint(to_spend_tx.sha256, 0))

        to_sign_tx.vin = [spendable]

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2pkh", None, None]],
    [["p2sh-p2wpkh", None]],
])
def test_bip322_invalid_to_spend_out_nVal(ins, bip322_txn, start_sign, cap_story):
    def hack(psbt_in):
        to_spend = psbt_in.inputs[0].utxo

        to_sign = psbt_in.txn

        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(to_spend))
        to_sign_tx.deserialize(BytesIO(to_sign))

        to_spend_tx.vout[0].nValue = 1

        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()

        spendable = CTxIn(COutPoint(to_spend_tx.sha256, 0))

        to_sign_tx.vin = [spendable]

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "to_spend hash" in story


@pytest.mark.parametrize("addr_fmt", [AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH])
@pytest.mark.parametrize("M_N", [(2,3), (13,15)])
@pytest.mark.parametrize("signed", [True, False])
@pytest.mark.parametrize("num_ins", [1, 7])
def test_ms_bip322_por(addr_fmt, M_N, signed, bip322_ms_txn, start_sign, end_sign, cap_story,
                       import_ms_wallet, clear_ms, num_ins, verify_msg_bip322_por,
                       bip322_verify):
    clear_ms()

    M, N = M_N
    inp_amount = 10000000

    if addr_fmt == AF_P2SH:
        dd = "m/45h"
    elif addr_fmt == AF_P2WSH:
        dd = "m/48h/1h/0h/2h"
    else:
        dd = "m/48h/1h/0h/1h"

    def path_mapper(idx):
        kk = str_to_path(dd)
        return kk + [0,0]

    keys = import_ms_wallet(M, N, name='bip322_por', accept=True, addr_fmt=addr_fmt, common=dd,
                            do_import=True, descriptor=True)


    psbt, msg_challenge = bip322_ms_txn(num_ins, M, keys, path_mapper=path_mapper, inp_af=addr_fmt,
                                        with_sigs=signed, input_amount=inp_amount)
    start_sign(psbt, finalize=signed)
    is_por = num_ins > 1
    verify_msg_bip322_por("POR", is_por=is_por)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert ("Proof of Reserves" if is_por else "BIP-322 Message") in story
    assert 'Network fee' not in story
    if not is_por:
        assert "Proof of Reserves" not in story
        assert "Amount " not in story
        assert "1 input" not in story
        assert "1 output" not in story
    else:
        amt = (num_ins - 1) * inp_amount
        str_amt = str(Decimal(amt / 100000000).quantize(Decimal('.00000001')))
        assert ("Amount %s XTN" % str_amt) in story
        assert ("%d inputs" % num_ins) in story

    assert "Message:\nPOR" in story
    assert "Message Hash:" not in story
    assert "Challenge Address:" in story
    assert "Message Challenge:" not in story
    assert ("1 output" in story) == is_por
    assert "- OP_RETURN -" not in story
    assert "null-data" not in story

    signed_psbt = end_sign(accept=True)
    if signed:
        # with_sigs=True preloads placeholder cosigner signatures; the device
        # can accept the PSBT shape, but a real signature verifier must reject it.
        with pytest.raises(AssertionError):
            bip322_verify(signed_psbt)


@pytest.mark.parametrize("addr_fmt", [AF_P2WSH, AF_P2SH])
def test_bip322_invalid_ms_psbt(addr_fmt, bip322_ms_txn, start_sign, cap_story, import_ms_wallet):
    def hack(psbt_in):
        if addr_fmt in [AF_P2WSH]:
            psbt_in.inputs[0].witness_script = None
        else:
            psbt_in.inputs[0].redeem_script = None

    if addr_fmt == AF_P2SH:
        dd = "m/45h"
    elif addr_fmt == AF_P2WSH:
        dd = "m/48h/1h/0h/2h"
    else:
        dd = "m/48h/1h/0h/1h"

    def path_mapper(idx):
        kk = str_to_path(dd)
        return kk + [0,0]

    keys = import_ms_wallet(2, 3, name='fail_b322', accept=True, addr_fmt=addr_fmt, common=dd,
                            do_import=True, descriptor=True)

    psbt, msg_challenge = bip322_ms_txn(1, 2, keys, path_mapper=path_mapper, inp_af=addr_fmt,
                                        hack_psbt=hack)

    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "Missing redeem/witness script" in story


@pytest.mark.parametrize("num_ins", [1, 12])
@pytest.mark.parametrize("addr_fmt", ["p2pkh", "p2wpkh", "p2sh-p2wpkh"])
def test_wif_store_sign_bip322_por(num_ins, addr_fmt, bip322_txn, goto_home, pick_menu_item,
                                   need_keypress, start_sign, end_sign, cap_menu, cap_story,
                                   press_cancel, settings_remove, press_select, import_wif_to_store,
                                   bip322_verify):

    settings_remove("wifs")

    node = BIP32Node.from_master_secret(os.urandom(32))

    ins = []
    wifs = []
    for i in range(num_ins):
        n = node.subkey_for_path("0/%d" % i)
        wifs.append(n.node.private_key.wif(testnet=True))
        if i == 0:
            amt = None
        elif i // 2 == 0:
            amt = 10000000
        else:
            amt = 900000000

        ins.append([addr_fmt, None, amt , n.node.private_key.K.sec()])

    msg = b"Coinkite"
    psbt, msg_challenge = bip322_txn(ins, msg=msg)

    import_wif_to_store(wifs)

    menu = cap_menu()
    assert menu[0] == "Import WIF"

    start_sign(psbt, finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert ("Proof of Reserves" if num_ins > 1 else "BIP-322 Message") in story
    if num_ins == 1:
        assert "Proof of Reserves" not in story
        assert "Amount " not in story
        assert "1 input" not in story
        assert "1 output" not in story
    assert msg.decode() in story
    assert "Message Hash:" not in story
    assert "warning" in story
    if num_ins == 1:
        assert "WIF store: 0" in story
    else:
        assert f"WIF store: {', '.join([str(i) for i in range(num_ins)])}" in story
    signed = end_sign()
    bip322_verify(signed)


@pytest.mark.parametrize("bip32_paths", [True, False])
@pytest.mark.parametrize("por", [True, False])
def test_bip322_empty_message_challenge_rejected(bip32_paths, por, bip322_txn,
                                                 start_sign, cap_story):
    def hack(psbt_in):
        to_spend_tx = CTransaction()
        to_sign_tx = CTransaction()
        to_spend_tx.deserialize(BytesIO(psbt_in.inputs[0].utxo))
        to_sign_tx.deserialize(BytesIO(psbt_in.txn))

        if not bip32_paths:
            psbt_in.inputs[0].bip32_paths = None
        to_spend_tx.vout[0].scriptPubKey = b""
        psbt_in.inputs[0].utxo = to_spend_tx.serialize_with_witness()

        to_spend_tx.calc_sha256()
        to_sign_tx.vin[0] = CTxIn(COutPoint(to_spend_tx.sha256, 0),
                                  nSequence=to_sign_tx.vin[0].nSequence)
        psbt_in.txn = to_sign_tx.serialize_with_witness()

    ins = [["p2wpkh", None, None]]
    if por:
        ins.append(["p2wpkh", None, 10000000])

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)

    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"


@pytest.mark.parametrize("msg", [
    b"A"*330,  # allowed
    b"X"*331,  # too long
    b"",       # empty
])
def test_msg_size(msg, bip322_txn, start_sign, end_sign, cap_story, need_keypress,
                  press_select, press_cancel, bip322_verify):

    psbt, msg_challenge = bip322_txn([["p2wpkh", None, None]], msg=msg)

    start_sign(psbt, finalize=True)

    time.sleep(.1)
    title, story = cap_story()

    if 0 < len(msg) <= 330:
        assert title == "OK TO SIGN?"
        assert "BIP-322 Message" in story
        assert "sign message" in story

        assert ("Message:\n%s" % msg.decode()) in story

        signed = end_sign(accept=True, exit_export_loop=False)
        bip322_verify(signed)
        title, story = cap_story()
        assert title == "PSBT Signed"
        assert "Signed BIP-322 PSBT shared via USB." in story
        press_cancel()

    else:
        assert title == "Failure"
        if msg:
            assert "msg len" in story
        else:
            assert "msg" in story


# EOF
