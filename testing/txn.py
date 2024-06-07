# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Creating fake transactions. Not simple.
#
import pytest, struct
from ckcc_protocol.protocol import MAX_TXN_LEN
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from io import BytesIO
from helpers import fake_dest_addr, make_change_addr, hash160, taptweak
from base58 import decode_base58
from bip32 import BIP32Node
from constants import ADDR_STYLES, simulator_fixed_tprv
from serialize import uint256_from_str
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut


@pytest.fixture()
def fake_txn(dev, pytestconfig):
    # make various size txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    # - input total = num_inputs * 1BTC

    def doit(num_ins, num_outs, master_xpub=None, subpath="0/%d", fee=10000,
             invals=None, outvals=None, segwit_in=False, wrapped=False,
             outstyles=['p2pkh'],  psbt_hacker=None, change_outputs=[],
             capture_scripts=None, add_xpub=None, op_return=None,
             psbt_v2=None, input_amount=1E8, taproot_in=False):

        psbt = BasicPSBT()

        if psbt_v2 is None:
            # anything passed directly to this function overrides
            # pytest flag --psbt2 - only care about pytest flag
            # if psbt_v2 is not specified (None)
            psbt_v2 = pytestconfig.getoption('psbt2')

        if psbt_v2:
            psbt.version = 2
            psbt.txn_version = 2
            psbt.input_count = num_ins
            psbt.output_count = num_outs

        txn = CTransaction()
        txn.nVersion = 2
        master_xpub = master_xpub or dev.master_xpub or simulator_fixed_tprv
        
        # we have a key; use it to provide "plausible" value inputs
        mk = BIP32Node.from_wallet_key(master_xpub)
        xfp = mk.fingerprint()

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        for i in range(num_ins):
            # make a fake txn to supply each of the inputs
            # - each input is 1BTC

            # addr where the fake money will be stored.
            subkey = mk.subkey_for_path(subpath % i)
            sec = subkey.sec()
            assert len(sec) == 33, "expect compressed"
            assert subpath[0:2] == '0/'

            if taproot_in:
                tweaked_xonly = taptweak(sec[1:])

            if segwit_in and taproot_in:
                # if both specified:
                # even is segwit v0
                # odd is segvit v1 (taproot)
                if i % 2 == 0:
                    psbt.inputs[i].bip32_paths[sec] = xfp + struct.pack('<II', 0, i)
                    scr = bytes([0x00, 0x14]) + subkey.hash160()
                    if wrapped:
                        # p2sh-p2wpkh
                        psbt.inputs[i].redeem_script = scr
                        scr = bytes([0xa9, 0x14]) + hash160(scr) + bytes([0x87])
                else:
                    psbt.inputs[i].taproot_bip32_paths[sec[1:]] = b"\x00" + xfp + struct.pack('<II', 0, i)
                    scr = bytes([81, 32]) + tweaked_xonly

                # UTXO that provides the funding for to-be-signed txn
            elif taproot_in:
                psbt.inputs[i].taproot_bip32_paths[sec[1:]] = b"\x00" + xfp + struct.pack('<II', 0, i)
                scr = bytes([81, 32]) + tweaked_xonly
            else:
                psbt.inputs[i].bip32_paths[sec] = xfp + struct.pack('<II', 0, i)
                if segwit_in:
                    # p2wpkh
                    scr = bytes([0x00, 0x14]) + subkey.hash160()
                    if wrapped:
                        # p2sh-p2wpkh
                        psbt.inputs[i].redeem_script = scr
                        scr = bytes([0xa9, 0x14]) + hash160(scr) + bytes([0x87])
                else:
                    # p2pkh
                    scr = bytes([0x76, 0xa9, 0x14]) + subkey.hash160() + bytes([0x88, 0xac])

            # UTXO that provides the funding for to-be-signed txn
            supply = CTransaction()
            supply.nVersion = 2
            out_point = COutPoint(
                uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, 0)),
                73
            )
            supply.vin = [CTxIn(out_point, nSequence=0xffffffff)]

            supply.vout.append(CTxOut(int(input_amount if not invals else invals[i]), scr))

            if segwit_in:
                # just utxo for segwit
                psbt.inputs[i].witness_utxo = supply.vout[-1].serialize()
            else:
                # whole tx for pre-segwit
                psbt.inputs[i].utxo = supply.serialize_with_witness()

            supply.calc_sha256()

            if psbt_v2:
                psbt.inputs[i].previous_txid = supply.hash
                psbt.inputs[i].prevout_idx = 0
                # TODO sequence
                # TODO height timelock
                # TODO time timelock

            spendable = CTxIn(COutPoint(supply.sha256, 0), nSequence=0xffffffff)
            txn.vin.append(spendable)

        for i in range(num_outs):
            # random P2PKH
            if not outstyles:
                style = ADDR_STYLES[i % len(ADDR_STYLES)]
            elif len(outstyles) == num_outs:
                style = outstyles[i]
            else:
                style = outstyles[i % len(outstyles)]

            if i in change_outputs:
                scr, act_scr, isw, pubkey, sp = make_change_addr(mk, style)

                if len(pubkey) == 32:  # xonly
                    psbt.outputs[i].taproot_bip32_paths[pubkey] = sp
                else:
                    psbt.outputs[i].bip32_paths[pubkey] = sp
            else:
                scr = act_scr = fake_dest_addr(style)
                isw = ('w' in style)

            assert scr
            act_scr = act_scr or scr

            # one of these is not needed anymore in v2 as you have scriptPubkey provided by self.script
            if "p2sh" in style:# in ('p2sh-p2wpkh', 'p2wpkh-p2sh'):
                psbt.outputs[i].redeem_script = scr
            elif isw:
                psbt.outputs[i].witness_script = scr

            if psbt_v2:
                psbt.outputs[i].script = act_scr
                psbt.outputs[i].amount = int(outvals[i] if outvals else round(((input_amount*num_ins)-fee) / num_outs, 4))

            if not outvals:
                h = CTxOut(int(round(((input_amount*num_ins)-fee) / num_outs, 4)), act_scr)
            else:
                h = CTxOut(int(outvals[i]), act_scr)

            if capture_scripts is not None:
                capture_scripts.append( act_scr )

            txn.vout.append(h)

        # op_return is a tuple of (amount, data)
        if op_return:
            for op_ret in op_return:
                amount, data = op_ret
                op_return_size = len(data)
                if op_return_size < 76:
                    script = bytes([106, op_return_size]) + data
                else:
                    script = bytes([106, 76, op_return_size]) + data

                op_ret_o = BasicPSBTOutput(idx=len(psbt.outputs))
                if psbt_v2:
                    op_ret_o.script = script
                    op_ret_o.amount = amount
                    psbt.output_count += 1
                else:
                    op_return_out = CTxOut(amount, script)
                    txn.vout.append(op_return_out)

                psbt.outputs.append(op_ret_o)

                if capture_scripts is not None:
                    capture_scripts.append(script)

        if not psbt_v2:
            psbt.txn = txn.serialize_with_witness()

        if add_xpub:
            # some people want extra xpub data in their PSBTs
            psbt.xpubs = [(decode_base58(master_xpub),  xfp)]

        # last minute chance to mod PSBT object
        if psbt_hacker:
            psbt_hacker(psbt)

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

def render_address(script, testnet=True):
    # take a scriptPubKey (part of the CTxOut) and convert into conventional human-readable
    # string... aka: the "payment address"
    from base58 import encode_base58_checksum
    from bech32 import encode as bech32_encode
    from binascii import hexlify as b2a_hex

    ll = len(script)

    if not testnet:
        bech32_hrp = 'bc'
        b58_addr    = bytes([0])
        b58_script  = bytes([5])
        b58_privkey = bytes([128])
    else:
        bech32_hrp = 'tb'
        b58_addr    = bytes([111])
        b58_script  = bytes([196])
        b58_privkey = bytes([239])

    # P2PKH
    if ll == 25 and script[0:3] == b'\x76\xA9\x14' and script[23:26] == b'\x88\xAC':
        return encode_base58_checksum(b58_addr + script[3:3+20])

    # P2SH
    if ll == 23 and script[0:2] == b'\xA9\x14' and script[22] == 0x87:
        return encode_base58_checksum(b58_script + script[2:2+20])

    # segwit v0 (P2WPKH, P2WSH)
    if script[0] == 0 and script[1] in (0x14, 0x20) and (ll - 2) == script[1]:
        return bech32_encode(bech32_hrp, script[0], script[2:])

    # segwit v1 (P2TR) and later segwit version
    if ll == 34 and (0x51 <= script[0] <= 0x60) and script[1] == 0x20:
        return bech32_encode(bech32_hrp, script[0] - 80, script[2:])

    # OP_RETURN
    if script[0:1] == b'\x6a':
        return b2a_hex(script)

    raise ValueError('Unknown payment script', repr(script))

def fake_address(addr_fmt, testnet=False):
    # Make fake addresses of any type. Contents are noise... don't ever send to them!!
    # TODO add regtest option
    # LATER: dup of helper.py fake_dest_addr
    from constants import AFC_WRAPPED, AFC_PUBKEY, AFC_SEGWIT, AFC_BECH32M, AFC_SCRIPT
    from helpers import prandom
    from base58 import encode_base58_checksum
    from bech32 import encode as bech32_encode

    is_script = bool(addr_fmt & (AFC_SCRIPT | AFC_WRAPPED))
    body = prandom(32 if is_script else 20)

    if not testnet:
        bech32_hrp = 'bc'
        b58_addr    = bytes([0])
        b58_script  = bytes([5])
    else:
        bech32_hrp = 'tb'
        b58_addr    = bytes([111])
        b58_script  = bytes([196])

    if (addr_fmt & AFC_SEGWIT) and not (addr_fmt & AFC_WRAPPED):
        # bech32
        vers = 1 if (addr_fmt & AFC_BECH32M) == AFC_BECH32M else 0
        return bech32_encode(bech32_hrp, vers, body)
    else:
        # base58
        return encode_base58_checksum((b58_script if is_script else b58_addr) + body[0:20])

# EOF
