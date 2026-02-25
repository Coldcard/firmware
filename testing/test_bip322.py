# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-322 message signing & Proof of Reserves
#
import pytest, time
from io import BytesIO
from decimal import Decimal
from constants import SIGHASH_MAP, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH
from bip322 import bip322_txn, bip322_ms_txn, bip322_msg_hash
from ctransaction import CTransaction, CTxIn, COutPoint
from helpers import str_to_path
from charcodes import KEY_QR, KEY_NFC
from bbqr import split_qrs


@pytest.fixture
def verify_msg_bip322_por(cap_story, need_keypress, press_select, press_cancel, cap_menu,
                          nfc_write_text, is_q1, press_nfc, scan_a_qr, split_scan_bbqr,
                          enter_complex, pick_menu_item):
    def doit(msg, refuse=False, way="sd", fname=None):
        title, story = cap_story()
        assert title == "BIP-322 MSG"
        # file was already created with bip322_txn fixture above
        if "qr" in way and not is_q1:
            raise pytest.xfail("Mk4 no QR")

        if way == "input":
            enter_complex(msg, b39pass=False)
        elif way == "qr":
            assert f"{KEY_QR} to scan QR code" in story
            need_keypress(KEY_QR)
            scan_a_qr(msg)
            time.sleep(1)

        elif way == "bbqr":
            assert f"{KEY_QR} to scan QR code" in story
            need_keypress(KEY_QR)

            # def split_qrs(raw, type_code, encoding=None,
            #  min_split=1, max_split=1295, min_version=5, max_version=40
            actual_vers, parts = split_qrs(msg, "U", max_version=20)

            for p in parts:
                scan_a_qr(p)
                time.sleep(2.0 / len(parts))  # just so we can watch

            time.sleep(1)

        elif way == "nfc":
            if f"press {KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
                pytest.xfail("NFC disabled")
            else:
                press_nfc()
                time.sleep(0.2)
                nfc_write_text(msg)
                time.sleep(0.3)
        else:
            assert way in ["sd", "vdisk"]
            if way == "vdisk":
                if "(2) to import from Virtual Disk" not in story:
                    pytest.xfail("Vdisk disabled")
                else:
                    need_keypress("2")
            else:
                need_keypress("1")

            if fname:
                pick_menu_item(fname)


        time.sleep(.1)
        title, story = cap_story()
        assert msg in story
        if refuse:
            press_cancel()
            time.sleep(.1)
            assert "Ready To Sign" in cap_menu()
        else:
            press_select()

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
                    press_select, verify_msg_bip322_por):
    num_ins = len(ins)
    amt = sum([i[2] or 0 for i in ins])
    psbt, msg_challenge = bip322_txn(ins, msg=msg)
    start_sign(psbt, finalize=True)

    verify_msg_bip322_por(msg.decode(), way="sd")

    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "Proof of Reserves" in story
    assert 'Network fee' not in story  # different story for POR
    if len(ins) == 1:
        # only the message signed input - amount is zero
        assert "Amount 0.00000000 XTN" in story
        assert "1 input" in story
    else:
        assert ("Amount %s XTN" % str(Decimal(amt/100000000).quantize(Decimal('.00000001')))) in story
        assert ("%d inputs" % num_ins) in story

    assert ("Message Hash:\n%s" % bip322_msg_hash(msg).hex()) in story
    assert ("Message Challenge:\n%s" % msg_challenge.hex()) in story
    assert "1 output" in story
    assert "- OP_RETURN -" in story
    assert "null-data" in story
    end_sign(accept=True, finalize=True)


@pytest.mark.parametrize("sighash", [sh for sh in SIGHASH_MAP if sh != 'ALL'])
def test_bip322_por_invalid_sighash(sighash, bip322_txn, start_sign, cap_story, settings_set,
                                    end_sign, verify_msg_bip322_por):
    settings_set("sighshchk", 0)  # disable checks
    # all POR txns must have only SIGHASH_ALL
    psbt, _ = bip322_txn([["p2sh-p2wpkh", None, None], ["p2wpkh", None, 100000], ["p2pkh", None, 1000000]],
                         sighash=SIGHASH_MAP[sighash])
    start_sign(psbt, finalize=True)
    title, story = cap_story()
    if "NONE" in sighash:
        assert title == "Failure"
        return

    verify_msg_bip322_por("POR", way="sd")

    time.sleep(.1)
    title, story = cap_story()
    assert "warning" in story
    with pytest.raises(Exception):
        end_sign(accept=True, finalize=True)

    title, story = cap_story()
    assert "POR not SIGHASH_ALL" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None]],
    [["p2wpkh", None, None], ["p2wpkh", None, 10000000]],
])
def test_bip322_0th_input_witness_utxo(ins, bip322_txn, start_sign, cap_story):
    # not allowed - 0th input needs to have full pre-segwit utxo
    psbt, _ = bip322_txn(ins, witness_utxo=[0])
    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "utxo" in story


@pytest.mark.parametrize("ins", [
    [["p2wpkh", None, None], ["p2wpkh", None, 10000000], ["p2wpkh", None, 10000000]],
    [["p2wpkh", None, None], ["p2sh-p2wpkh", None, 10000000], ["p2pkh", None, 10000000]],
    [["p2pkh", None, None], ["p2wpkh", None, 10000000], ["p2sh-p2wpkh", None, 10000000]],
])
def test_bip322_Xth_input_witness_utxo(ins, bip322_txn, start_sign, cap_story, end_sign,
                                       verify_msg_bip322_por):
    # allowed - 0th input needs to have full pre-segwit utxo, all other can be just witness_utxo
    msg = b"hellow world"
    psbt, msg_challenge = bip322_txn(ins, witness_utxo=[1, 2], msg=msg)
    start_sign(psbt, finalize=True)
    verify_msg_bip322_por(msg.decode(), way="sd")
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert bip322_msg_hash(msg).hex() in story
    assert msg_challenge.hex() in story
    end_sign(accept=True, finalize=True)


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
        for i, inp in enumerate(psbt_in.inputs):
            if i == 0:
                inp.bip32_paths = None

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    if len(ins) == 1:
        assert title == "Failure"
        assert 'PSBT does not contain any key path information.' in story
    else:
        verify_msg_bip322_por("POR", way="sd")
        time.sleep(.1)
        title, story = cap_story()
        assert "warning" in story
        assert "Limited Signing" in story
        assert "because we do not know the key: 0" in story


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
    assert "scriptSig" in story


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

        spendable = CTxIn(COutPoint(to_spend_tx.sha256, 0))

        to_sign_tx.vin = [spendable]

        psbt_in.txn = to_sign_tx.serialize_with_witness()

    psbt, _ = bip322_txn(ins, psbt_hacker=hack)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert "i0: invalid BIP-322 'to_spend'" in story
    assert "prevout" in story


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
    assert "num ins" in story


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
    assert "num outs" in story


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
    assert "nVal" in story


@pytest.mark.parametrize("addr_fmt", [AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH])
@pytest.mark.parametrize("M_N", [(2,3), (13,15)])
@pytest.mark.parametrize("signed", [True, False])
@pytest.mark.parametrize("num_ins", [1, 7])
def test_ms_bip322_por(addr_fmt, M_N, signed, bip322_ms_txn, start_sign, end_sign, cap_story,
                       import_ms_wallet, clear_ms, num_ins, verify_msg_bip322_por):
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
    verify_msg_bip322_por("POR", way="sd")
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "Proof of Reserves" in story
    assert 'Network fee' not in story
    if num_ins == 1:
        # only the message signed input - amount is zero
        assert "Amount 0.00000000 XTN" in story
        assert "1 input" in story
    else:
        amt = (num_ins - 1) * inp_amount
        str_amt = str(Decimal(amt / 100000000).quantize(Decimal('.00000001')))
        assert ("Amount %s XTN" % str_amt) in story
        assert ("%d inputs" % num_ins) in story

    assert ("Message Hash:\n%s" % bip322_msg_hash(b"POR").hex()) in story
    assert ("Message Challenge:\n%s" % msg_challenge.hex()) in story
    assert "1 output" in story
    assert "- OP_RETURN -" in story
    assert "null-data" in story

    end_sign(accept=True, finalize=signed)


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


@pytest.mark.parametrize("msg", [b"COLDCARD\n\nTHE\n\nBEST\n\nSIGNER", b"X" * 512])
@pytest.mark.parametrize("ins", [
    [["p2sh-p2wpkh", None, None]],
    [["p2pkh", None, None]] + ([["p2wpkh", None, 1000000]] * 5) + ([["p2sh-p2wpkh", None, 10000000]] * 5),
])
@pytest.mark.parametrize("way", ["sd", "qr", "nfc", "vdisk", "bbqr"])
def test_bip322_msg_import(msg, ins, way, bip322_txn, start_sign, end_sign, cap_story, need_keypress,
                           press_select, verify_msg_bip322_por):

    if b"\n" in msg and way == "qr":
        raise pytest.skip("QR code with newlines not supported")

    psbt, msg_challenge = bip322_txn(ins, msg=msg)
    start_sign(psbt, finalize=True)

    verify_msg_bip322_por(msg.decode(), way=way)

    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SIGN?"
    assert "Proof of Reserves" in story


def test_bip322_msg_import_fail(bip322_txn, start_sign, end_sign, cap_story, need_keypress,
                                press_select, OK, press_cancel, cap_menu, microsd_path, enter_complex):

    msg = b"it's me!"
    psbt, msg_challenge = bip322_txn([["p2wpkh", None, None]], msg=msg)
    start_sign(psbt, finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "BIP-322 MSG"

    need_keypress("1")  # SD
    time.sleep(.1)
    title, story = cap_story()
    assert f"Press {OK} to approve message" in story
    press_cancel()  # refuse
    time.sleep(.1)
    assert "Ready To Sign" in cap_menu()

    start_sign(psbt, finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "BIP-322 MSG"

    need_keypress("0")  # manual input
    # leave empty
    press_cancel()
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "need msg" in story
    assert "Msg verification failed" in story
    press_cancel()

    start_sign(psbt, finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "BIP-322 MSG"

    need_keypress("0")  # manual input
    enter_complex("AAA", apply=False, b39pass=False)  # msg wrong
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Msg verification failed" in story
    assert "hash verification failed" in story
    press_cancel()

# EOF