# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# construct Proof of Reserves transaction according to BIP-322
#
import struct, hashlib
from ckcc_protocol.protocol import MAX_TXN_LEN
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from io import BytesIO
from helpers import hash160, str_to_path, taptweak
from bip32 import BIP32Node, PublicKey
from constants import simulator_fixed_tprv, AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut, uint256_from_str
from sighash import legacy_sighash, segwit_v0_sighash, taproot_sighash, SIGHASH_DEFAULT, SIGHASH_ALL
from pysecp256k1 import ec_pubkey_parse, ecdsa_signature_parse_der, ecdsa_verify
from pysecp256k1.extrakeys import xonly_pubkey_parse
from pysecp256k1.schnorrsig import schnorrsig_verify


def bip322_msg_hash(msg):
    tag_hash = hashlib.sha256(b'BIP0322-signed-message').digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def ecdsa_verify_sig(pubkey, sig, digest):
    if not sig or sig[-1] != SIGHASH_ALL:
        return False
    try:
        parsed = ecdsa_signature_parse_der(sig[:-1])
        return bool(ecdsa_verify(parsed, ec_pubkey_parse(pubkey), digest))
    except Exception:
        return False


def bip322_verify(psbt_bytes):
    """Verify BIP-322 PSBT signatures without a full script interpreter.

    Enforces the BIP-322 transaction shape, SIGHASH_ALL for ECDSA,
    SIGHASH_DEFAULT/SIGHASH_ALL for taproot, and direct signature checks for
    p2pkh, p2wpkh, p2sh-p2wpkh, sh, wsh, and p2tr key-path.
    It intentionally omits consensus-level script evaluation rules such as
    CLEANSTACK, MINIMALIF, NULLFAIL beyond empty CHECKMULTISIG dummy,
    CODESEPARATOR/FindAndDelete handling, and NOP-upgrade checks; unsupported
    scripts raise AssertionError.
    """
    psbt = BasicPSBT().parse(psbt_bytes)
    assert psbt.bip322_msg is not None
    msg = psbt.bip322_msg
    tx = CTransaction()
    if psbt.txn:
        tx.deserialize(BytesIO(psbt.txn))
    else:
        tx.nVersion = psbt.txn_version
        tx.nLockTime = psbt.fallback_locktime or 0
        for inp in psbt.inputs:
            tx.vin.append(CTxIn(COutPoint(uint256_from_str(inp.previous_txid), inp.prevout_idx),
                                nSequence=inp.sequence if inp.sequence is not None else 0xffffffff))
        for out in psbt.outputs:
            tx.vout.append(CTxOut(out.amount, out.script))

    inp0 = psbt.inputs[0]
    to_spend = None
    if inp0.utxo:
        to_spend = CTransaction()
        to_spend.deserialize(BytesIO(inp0.utxo))
        assert len(to_spend.vout) == 1
        assert to_spend.vout[0].nValue == 0
        script_pubkey = to_spend.vout[0].scriptPubKey
    else:
        assert inp0.witness_utxo
        witness_utxo = CTxOut()
        witness_utxo.deserialize(BytesIO(inp0.witness_utxo))
        assert witness_utxo.nValue == 0
        script_pubkey = witness_utxo.scriptPubKey

    expected_to_spend = CTransaction()
    expected_to_spend.nVersion = 0
    expected_to_spend.nLockTime = 0
    expected_to_spend.vin = [CTxIn(COutPoint(hash=0, n=0xffffffff),
                                   scriptSig=b'\x00\x20' + bip322_msg_hash(msg),
                                   nSequence=0)]
    expected_to_spend.vout = [CTxOut(0, script_pubkey)]
    expected_to_spend.calc_sha256()
    if to_spend:
        assert to_spend.serialize_without_witness() == expected_to_spend.serialize_without_witness()
    to_spend = expected_to_spend

    assert tx.nVersion in (0, 2)
    assert len(tx.vin) >= 1
    assert tx.vin[0].prevout.hash == to_spend.sha256
    assert tx.vin[0].prevout.n == 0
    assert not (len(tx.vin) == 1 and (tx.vin[0].nSequence != 0 or tx.nLockTime != 0))
    assert len(tx.vout) == 1
    assert tx.vout[0].nValue == 0
    assert tx.vout[0].scriptPubKey == b'\x6a'

    prevouts = []
    for idx, txin in enumerate(tx.vin):
        if idx == 0:
            prevouts.append((0, script_pubkey))
        else:
            assert idx < len(psbt.inputs)
            if psbt.inputs[idx].witness_utxo:
                prev = CTxOut()
                prev.deserialize(BytesIO(psbt.inputs[idx].witness_utxo))
            else:
                prev_tx = CTransaction()
                prev_tx.deserialize(BytesIO(psbt.inputs[idx].utxo))
                prev = prev_tx.vout[txin.prevout.n]
            prevouts.append((prev.nValue, prev.scriptPubKey))

    for idx, txin in enumerate(tx.vin):
        amount, spk = prevouts[idx]

        inp = psbt.inputs[idx]
        if len(spk) == 25 and spk[:3] == b'\x76\xa9\x14' and spk[-2:] == b'\x88\xac':
            assert len(inp.part_sigs) == 1
            pub, sig = next(iter(inp.part_sigs.items()))
            assert hash160(pub) == spk[3:23]
            assert ecdsa_verify_sig(pub, sig, legacy_sighash(tx, idx, spk))
            continue

        if len(spk) == 22 and spk[:2] == b'\x00\x14':
            assert len(inp.part_sigs) == 1
            pub, sig = next(iter(inp.part_sigs.items()))
            assert hash160(pub) == spk[2:22]
            script_code = b'\x76\xa9\x14' + spk[2:22] + b'\x88\xac'
            assert ecdsa_verify_sig(pub, sig, segwit_v0_sighash(tx, idx, script_code, amount))
            continue

        if len(spk) == 34 and spk[:2] == b'\x00\x20':
            assert inp.witness_script
            assert hashlib.sha256(inp.witness_script).digest() == spk[2:34]
            assert inp.part_sigs
            sighash = segwit_v0_sighash(tx, idx, inp.witness_script, amount)
            for pub, sig in inp.part_sigs.items():
                assert ecdsa_verify_sig(pub, sig, sighash)
            continue

        if len(spk) == 34 and spk[:2] == b'\x51\x20':
            assert inp.taproot_key_sig
            if len(inp.taproot_key_sig) == 64:
                sighash = SIGHASH_DEFAULT
                sig = inp.taproot_key_sig
            else:
                assert len(inp.taproot_key_sig) == 65
                sighash = inp.taproot_key_sig[-1]
                sig = inp.taproot_key_sig[:-1]
            digest = taproot_sighash(tx, idx, prevouts, sighash)
            assert schnorrsig_verify(sig, digest, xonly_pubkey_parse(spk[2:34]))
            continue

        if len(spk) == 23 and spk[:2] == b'\xa9\x14' and spk[-1:] == b'\x87':
            assert inp.redeem_script
            assert hash160(inp.redeem_script) == spk[2:22]

            if len(inp.redeem_script) == 22 and inp.redeem_script[:2] == b'\x00\x14':
                assert len(inp.part_sigs) == 1
                pub, sig = next(iter(inp.part_sigs.items()))
                assert hash160(pub) == inp.redeem_script[2:22]
                script_code = b'\x76\xa9\x14' + inp.redeem_script[2:22] + b'\x88\xac'
                assert ecdsa_verify_sig(pub, sig, segwit_v0_sighash(tx, idx, script_code, amount))
                continue

            if len(inp.redeem_script) == 34 and inp.redeem_script[:2] == b'\x00\x20':
                assert inp.witness_script
                assert inp.redeem_script == b'\x00\x20' + hashlib.sha256(inp.witness_script).digest()
                assert inp.part_sigs
                sighash = segwit_v0_sighash(tx, idx, inp.witness_script, amount)
                for pub, sig in inp.part_sigs.items():
                    assert ecdsa_verify_sig(pub, sig, sighash)
                continue

            assert inp.part_sigs
            sighash = legacy_sighash(tx, idx, inp.redeem_script)
            for pub, sig in inp.part_sigs.items():
                assert ecdsa_verify_sig(pub, sig, sighash)
            continue

        assert False, "unsupported script"


def bip322_txn(inputs, msg=b"POR", addr_fmt="p2wpkh", input_amount=1E8, to_sign_lock_time=0,
               sighash=None, psbt_hacker=None, witness_utxo=[], to_sign_nVersion=0,
               psbt_v2=False, master_xpub=None):

    msg_challenge = None

    num_ins = len(inputs)

    psbt = BasicPSBT()
    psbt.bip322_msg = msg

    to_sign = CTransaction()
    to_sign.nLockTime = to_sign_lock_time
    # must be set to 2 if BIP-68 is used (relative tx level lock)
    to_sign.nVersion = to_sign_nVersion
    master_xpub = master_xpub or simulator_fixed_tprv

    # we have a key; use it to provide "plausible" value inputs
    mk = BIP32Node.from_wallet_key(master_xpub)
    mfp = mk.fingerprint()

    psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
    psbt.outputs = []

    for i, inp in enumerate(inputs):
        sp = f"0/{i}"
        af = addr_fmt
        ia = input_amount
        pubkey = None  # public key
        try:
            if inp[0] is not None:
                af = inp[0]
            if inp[1] is not None:
                sp = inp[1]
            if inp[2] is not None:
                ia = inp[2]
            if inp[3] is not None:
                pubkey = inp[3]
        except:
            pass

        if pubkey:
            int_path = [0]
            sec = pubkey
        else:
            int_path = str_to_path(sp)
            sec = mk.subkey_for_path(sp).sec()

        subkey = PublicKey.parse(sec)

        assert len(sec) == 33, "expect compressed"

        if af == "p2tr":
            tweaked_xonly = taptweak(sec[1:])
            psbt.inputs[i].taproot_bip32_paths[sec[1:]] = b"\x00" + mfp + struct.pack(f'<{"I" * len(int_path)}',
                                                                                      *int_path)
            scr = bytes([81, 32]) + tweaked_xonly

        elif af in ("p2wpkh", "p2sh-p2wpkh", "p2wpkh-p2sh"):
            psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack(f'<{"I" * len(int_path)}', *int_path)
            scr = bytes([0x00, 0x14]) + subkey.h160()

            if af != "p2wpkh":
                # use classic p2wpkh (from above) as redeem script
                psbt.inputs[i].redeem_script = scr
                scr = bytes([0xa9, 0x14]) + hash160(scr) + bytes([0x87])

        elif af == "p2pkh":
            psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack(f'<{"I" * len(int_path)}', *int_path)
            scr = bytes([0x76, 0xa9, 0x14]) + subkey.h160() + bytes([0x88, 0xac])

        else:
            raise ValueError("unknown addr_fmt %s" % af)

        if i == 0:
            # first input always spends to_spend
            to_spend = CTransaction()
            to_spend.nVersion = 0
            out_point = COutPoint(hash=0, n=0xffffffff)
            msg_hash = bip322_msg_hash(msg)
            to_spend.vin = [CTxIn(out_point, scriptSig=b'\x00\x20' + msg_hash)]
            to_spend.vout = [CTxOut(0, scr)]  # always zero val
            msg_challenge = scr
        else:
            # other outputs that we want to prove ownership
            to_spend = CTransaction()
            to_spend.nVersion = 0
            out_point = COutPoint(
                uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, i)),
                73
            )
            to_spend.vin = [CTxIn(out_point, nSequence=0xffffffff)]
            to_spend.vout.append(CTxOut(int(ia), scr))


            if sighash is not None:
                psbt.inputs[i].sighash = sighash

        to_spend.calc_sha256()

        if i in witness_utxo:
            psbt.inputs[i].witness_utxo = to_spend.vout[-1].serialize()
        else:
            psbt.inputs[i].utxo = to_spend.serialize_with_witness()

        if len(inputs) == 1:
            # basic msg sign
            seq = 0
        else:
            if to_sign_lock_time and not i:
                seq = 0xfffffffd
            else:
                seq = 0xffffffff

        spendable = CTxIn(COutPoint(to_spend.sha256, 0), nSequence=seq)
        to_sign.vin.append(spendable)

    # just one zero amount output with script null data OP_RETURN
    op_ret_o = BasicPSBTOutput(idx=0)
    op_return_out = CTxOut(0, b'\x6a')
    to_sign.vout.append(op_return_out)

    psbt.outputs.append(op_ret_o)

    psbt.txn = to_sign.serialize_with_witness()

    # last minute chance to mod PSBT object
    if psbt_hacker:
        psbt_hacker(psbt)

    if psbt_v2:
        psbt.parsed_txn = CTransaction()
        psbt.parsed_txn.deserialize(BytesIO(psbt.txn))
        psbt.to_v2()

    rv = BytesIO()
    psbt.serialize(rv)
    assert rv.tell() <= MAX_TXN_LEN, 'too fat'

    return rv.getvalue(), msg_challenge


def bip322_ms_txn(num_ins, M, keys, msg=b"POR", inp_af=AF_P2WSH, input_amount=1E8, path_mapper=None,
                  lock_time=0, with_sigs=False, sighash=None, hack_psbt=None, to_sign_nVersion=0,
                  psbt_v2=False):
    from test_multisig import make_ms_address

    msg_challenge = None

    psbt = BasicPSBT()
    psbt.bip322_msg = msg

    txn = CTransaction()
    txn.nVersion = to_sign_nVersion
    txn.nLockTime = lock_time

    psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
    psbt.outputs = []

    for i in range(num_ins):
        # make a fake txn to supply each of the inputs
        # - each input is 1BTC

        # addr where the fake money will be stored.
        addr, scriptPubKey, script, details = make_ms_address(
            M, keys, idx=i, addr_fmt=inp_af, path_mapper=path_mapper
        )

        if inp_af == AF_P2WSH:
            psbt.inputs[i].witness_script = script
        elif inp_af == AF_P2SH:
            psbt.inputs[i].redeem_script = script
        else:
            assert inp_af == AF_P2WSH_P2SH
            psbt.inputs[i].witness_script = script
            psbt.inputs[i].redeem_script = b'\0\x20' + hashlib.sha256(script).digest()

        for pubkey, xfp_path in details:
            psbt.inputs[i].bip32_paths[pubkey] = b''.join(struct.pack('<I', j) for j in xfp_path)
            if with_sigs and (xfp_path[0] != keys[-1][0]) and len(psbt.inputs[i].part_sigs) < (M-1):  # only cosigner signatures are added
                psbt.inputs[i].part_sigs[pubkey] = b"\x30" + 70*b"a"

        if i == 0:
            to_spend = CTransaction()
            to_spend.nVersion = 0
            out_point = COutPoint(hash=0, n=0xffffffff)
            msg_hash = bip322_msg_hash(msg)
            to_spend.vin = [CTxIn(out_point, scriptSig=b'\x00\x20' + msg_hash)]
            to_spend.vout.append(CTxOut(0, scriptPubKey))
            msg_challenge = scriptPubKey
        else:
            # other outputs that we want to prove ownership
            to_spend = CTransaction()
            to_spend.nVersion = 0
            out_point = COutPoint(
                uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, i)),
                73
            )
            to_spend.vin = [CTxIn(out_point, nSequence=0xffffffff)]
            to_spend.vout.append(CTxOut(int(input_amount), scriptPubKey))

        # always add whole txn as utxo
        psbt.inputs[i].utxo = to_spend.serialize_with_witness()
        if sighash is not None and (i != 0):
            psbt.inputs[i].sighash = sighash

        to_spend.calc_sha256()

        if num_ins == 1:
            # basic msg sign
            seq = 0
        else:
            if lock_time and not i:
                seq = 0xfffffffd
            else:
                seq = 0xffffffff

        spendable = CTxIn(COutPoint(to_spend.sha256, 0), nSequence=seq)
        txn.vin.append(spendable)

    # just one zero amount output with script null data OP_RETURN
    op_ret_o = BasicPSBTOutput(idx=0)
    op_return_out = CTxOut(0, b'\x6a')
    txn.vout.append(op_return_out)

    psbt.outputs.append(op_ret_o)

    if hack_psbt:
        hack_psbt(psbt)

    psbt.txn = txn.serialize_with_witness()
    if psbt_v2:
        psbt.parsed_txn = CTransaction()
        psbt.parsed_txn.deserialize(BytesIO(psbt.txn))
        psbt.to_v2()

    rv = BytesIO()
    psbt.serialize(rv)
    assert rv.tell() <= MAX_TXN_LEN, 'too fat'

    return rv.getvalue(), msg_challenge
