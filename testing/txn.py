# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Creating fake transactions. Not simple.
#
import pytest, os
from ckcc_protocol.protocol import MAX_TXN_LEN
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from io import BytesIO
from helpers import fake_dest_addr, make_change_addr
from pycoin.key.BIP32Node import BIP32Node
from constants import ADDR_STYLES, simulator_fixed_tprv

@pytest.fixture()
def simple_fake_txn():
    # make various size txn's ... completely fake and pointless values
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxIn import TxIn
    from pycoin.tx.TxOut import TxOut
    from struct import pack

    def doit(num_ins, num_outs, fat=0):
        psbt = BasicPSBT()
        txn = Tx(2,[],[])
        
        for i in range(num_ins):
            h = TxIn(pack('4Q', 0, 0, 0, i), i)
            txn.txs_in.append(h)

        for i in range(num_outs):
            # random P2PKH
            scr = bytes([0x76, 0xa9, 0x14]) + pack('I', i+1) + bytes(16) + bytes([0x88, 0xac])
            h = TxOut((1E6*i) if i else 1E8, scr)
            txn.txs_out.append(h)

        with BytesIO() as b:
            txn.stream(b)
            psbt.txn = b.getvalue()

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        if fat:
            for i in range(num_ins):
                psbt.inputs[i].utxo = os.urandom(fat)

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

@pytest.fixture()
def fake_txn(dev, pytestconfig):
    # make various size txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    # - input total = num_inputs * 1BTC
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxIn import TxIn
    from pycoin.tx.TxOut import TxOut
    from pycoin.encoding import hash160
    from struct import pack

    def doit(num_ins, num_outs, master_xpub=None, subpath="0/%d", fee=10000,
             invals=None, outvals=None, segwit_in=False, wrapped=False,
             outstyles=['p2pkh'],  psbt_hacker=None, change_outputs=[],
             capture_scripts=None, add_xpub=None, op_return=None,
             psbt_v2=None):

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

        txn = Tx(2,[],[])
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

            psbt.inputs[i].bip32_paths[sec] = xfp + pack('<II', 0, i)

            # UTXO that provides the funding for to-be-signed txn
            supply = Tx(2,[TxIn(pack('4Q', 0xdead, 0xbeef, 0, 0), 73)],[])

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

            supply.txs_out.append(TxOut(1E8 if not invals else invals[i], scr))

            with BytesIO() as fd:
                if not segwit_in:
                    supply.stream(fd)
                    psbt.inputs[i].utxo = fd.getvalue()
                else:
                    supply.txs_out[-1].stream(fd)
                    psbt.inputs[i].witness_utxo = fd.getvalue()

            if psbt_v2:
                psbt.inputs[i].previous_txid = supply.hash()
                psbt.inputs[i].prevout_idx = 0
                # TODO sequence
                # TODO height timelock
                # TODO time timelock

            spendable = TxIn(supply.hash(), 0)
            txn.txs_in.append(spendable)

        from binascii import hexlify as b2a_hex
        for i in range(num_outs):
            # random P2PKH
            if not outstyles:
                style = ADDR_STYLES[i % len(ADDR_STYLES)]
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
                psbt.outputs[i].amount = outvals[i] if outvals else int(round(((1E8*num_ins)-fee) / num_outs, 4))

            if not outvals:
                h = TxOut(round(((1E8*num_ins)-fee) / num_outs, 4), act_scr)
            else:
                h = TxOut(outvals[i], act_scr)

            if capture_scripts is not None:
                capture_scripts.append( act_scr )

            txn.txs_out.append(h)

        # op_return is a tuple of (amount, data)
        if op_return:
            amount, data = op_return
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
                op_return_out = TxOut(amount, script)
                txn.txs_out.append(op_return_out)

            psbt.outputs.append(op_ret_o)

            if capture_scripts is not None:
                capture_scripts.append(script)

        if not psbt_v2:
            with BytesIO() as b:
                txn.stream(b)
                psbt.txn = b.getvalue()

        if add_xpub:
            # some people want extra xpub data in their PSBTs
            from pycoin.encoding import a2b_base58
            psbt.xpubs = [ (a2b_base58(master_xpub),  xfp) ]

        # last minute chance to mod PSBT object
        if psbt_hacker:
            psbt_hacker(psbt)

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

def render_address(script, testnet=True):
    # take a scriptPubKey (part of the TxOut) and convert into conventional human-readable
    # string... aka: the "payment address"
    from pycoin.encoding import b2a_hashed_base58
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
        return b2a_hashed_base58(b58_addr + script[3:3+20])

    # P2SH
    if ll == 23 and script[0:2] == b'\xA9\x14' and script[22] == 0x87:
        return b2a_hashed_base58(b58_script + script[2:2+20])

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
    from pycoin.encoding import b2a_hashed_base58
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
        return b2a_hashed_base58((b58_script if is_script else b58_addr) + body[0:20])

# EOF
