# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# construct Proof of Reserves transaction according to BIP-322
#
import pytest, struct, hashlib
from ckcc_protocol.protocol import MAX_TXN_LEN
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from io import BytesIO
from helpers import hash160, taptweak, str_to_path
from bip32 import BIP32Node
from constants import simulator_fixed_tprv, AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut, uint256_from_str


def bip322_msg_hash(msg):
    tag_hash = hashlib.sha256(b'BIP0322-signed-message').digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


@pytest.fixture
def bip322_txn(dev, pytestconfig):

    def doit(inputs, msg=b"POR", addr_fmt="p2wpkh", input_amount=1E8, to_sign_lock_time=0,
             sighash=None, psbt_hacker=None, witness_utxo=[], to_sign_nVersion=0):

        msg_challenge = None

        num_ins = len(inputs)

        psbt = BasicPSBT()

        to_sign = CTransaction()
        to_sign.nLockTime = to_sign_lock_time
        # must be set to 2 if BIP-68 is used (relative tx level lock)
        to_sign.nVersion = to_sign_nVersion
        master_xpub = dev.master_xpub or simulator_fixed_tprv

        # we have a key; use it to provide "plausible" value inputs
        mk = BIP32Node.from_wallet_key(master_xpub)
        mfp = mk.fingerprint()

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = []

        for i, inp in enumerate(inputs):
            sp = f"0/{i}"
            af = addr_fmt
            ia = input_amount
            try:
                if inp[0] is not None:
                    af = inp[0]
                if inp[1] is not None:
                    sp = inp[1]
                if inp[2] is not None:
                    ia = inp[2]
            except:
                pass

            int_path = str_to_path(sp)
            subkey = mk.subkey_for_path(sp)
            sec = subkey.sec()
            assert len(sec) == 33, "expect compressed"

            if af == "p2tr":
                tweaked_xonly = taptweak(sec[1:])
                psbt.inputs[i].taproot_bip32_paths[sec[1:]] = b"\x00" + mfp + struct.pack(f'<{"I" * len(int_path)}',
                                                                                          *int_path)
                scr = bytes([81, 32]) + tweaked_xonly

            elif af in ("p2wpkh", "p2sh-p2wpkh", "p2wpkh-p2sh"):
                psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack(f'<{"I" * len(int_path)}', *int_path)
                scr = bytes([0x00, 0x14]) + subkey.hash160()

                if af != "p2wpkh":
                    # use classic p2wpkh (from above) as redeem script
                    psbt.inputs[i].redeem_script = scr
                    scr = bytes([0xa9, 0x14]) + hash160(scr) + bytes([0x87])

            elif af == "p2pkh":
                psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack('<II', 0, i)
                scr = bytes([0x76, 0xa9, 0x14]) + subkey.hash160() + bytes([0x88, 0xac])

            else:
                raise ValueError("unknown addr_fmt %s" % af)

            if i == 0:
                # first input always spends to_spend
                to_spend = CTransaction()
                to_spend.nVersion = 0
                out_point = COutPoint(hash=0, n=0xffffffff)
                to_spend.vin = [CTxIn(out_point, scriptSig=b'\x00\x20' + bip322_msg_hash(msg))]
                to_spend.vout = [CTxOut(0, scr)]  # always zero val
                msg_challenge = scr
            else:
                # other outputs that we want to prove ownership
                to_spend = CTransaction()
                to_spend.nVersion = 0
                out_point = COutPoint(
                    uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, 0)),
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

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue(), msg_challenge

    return doit


@pytest.fixture
def bip322_ms_txn(pytestconfig):
    from test_multisig import make_ms_address

    def doit(num_ins, M, keys, msg=b"POR", inp_af=AF_P2WSH, input_amount=1E8, path_mapper=None,
             lock_time=0, with_sigs=False, sighash=None, hack_psbt=None, to_sign_nVersion=0):

        msg_challenge = None

        psbt = BasicPSBT()

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
                if with_sigs and (xfp_path[0] != keys[-1][0]):  # only cosigner signatures are added
                    psbt.inputs[i].part_sigs[pubkey] = b"\x30" + 70*b"a"

            if i == 0:
                to_spend = CTransaction()
                to_spend.nVersion = 0
                out_point = COutPoint(hash=0, n=0xffffffff)
                to_spend.vin = [CTxIn(out_point, scriptSig=b'\x00\x20' + bip322_msg_hash(msg))]
                to_spend.vout.append(CTxOut(0, scriptPubKey))
                msg_challenge = scriptPubKey
            else:
                # other outputs that we want to prove ownership
                to_spend = CTransaction()
                to_spend.nVersion = 0
                out_point = COutPoint(
                    uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, 0)),
                    73
                )
                to_spend.vin = [CTxIn(out_point, nSequence=0xffffffff)]
                to_spend.vout.append(CTxOut(int(input_amount), scriptPubKey))

            # always add whole txn as utxo
            psbt.inputs[i].utxo = to_spend.serialize_with_witness()
            if sighash is not None and (i != 0):
                psbt.inputs[i].sighash = sighash

            to_spend.calc_sha256()

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

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue(), msg_challenge

    return doit