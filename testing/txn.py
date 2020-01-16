# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Creating fake transactions. Not simple.
#
import time, pytest, os
from ckcc_protocol.protocol import MAX_TXN_LEN
from binascii import b2a_hex, a2b_hex
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from io import BytesIO
from pprint import pprint, pformat
from decimal import Decimal
from helpers import B2A, U2SAT, prandom, fake_dest_addr, make_change_addr, parse_change_back
from pycoin.key.BIP32Node import BIP32Node
from constants import ADDR_STYLES, ADDR_STYLES_SINGLE

@pytest.fixture()
def simple_fake_txn():
    # make various size txn's ... completely fake and pointless values
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxIn import TxIn
    from pycoin.tx.TxOut import TxOut
    from pycoin.serialize import h2b_rev
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
def fake_txn():
    # make various size txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    # - input total = num_inputs * 1BTC
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxIn import TxIn
    from pycoin.tx.TxOut import TxOut
    from pycoin.serialize import h2b_rev
    from struct import pack

    def doit(num_ins, num_outs, master_xpub, subpath="0/%d", fee=10000,
                outvals=None, segwit_in=False, outstyles=['p2pkh'],
                change_outputs=[], capture_scripts=None):
        psbt = BasicPSBT()
        txn = Tx(2,[],[])
        
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

            scr = bytes([0x76, 0xa9, 0x14]) + subkey.hash160() + bytes([0x88, 0xac])

            supply.txs_out.append(TxOut(1E8, scr))

            with BytesIO() as fd:
                if not segwit_in:
                    supply.stream(fd)
                    psbt.inputs[i].utxo = fd.getvalue()
                else:
                    supply.txs_out[-1].stream(fd)
                    psbt.inputs[i].witness_utxo = fd.getvalue()

            spendable = TxIn(supply.hash(), 0)
            txn.txs_in.append(spendable)


        for i in range(num_outs):
            # random P2PKH
            if not outstyles:
                style = ADDR_STYLES[i % len(ADDR_STYLES)]
            else:
                style = outstyles[i % len(outstyles)]

            if i in change_outputs:
                scr, act_scr, isw, pubkey, sp = make_change_addr(mk, style)
                psbt.outputs[i].bip32_paths[pubkey] = sp
            else:
                scr = act_scr = fake_dest_addr(style)
                isw = ('w' in style)

            assert scr
            act_scr = act_scr or scr

            if isw:
                psbt.outputs[i].witness_script = scr
            elif style.endswith('sh'):
                psbt.outputs[i].redeem_script = scr

            if not outvals:
                h = TxOut(round(((1E8*num_ins)-fee) / num_outs, 4), act_scr)
            else:
                h = TxOut(outvals[i], act_scr)

            if capture_scripts is not None:
                capture_scripts.append( (style, act_scr) )

            txn.txs_out.append(h)

        with BytesIO() as b:
            txn.stream(b)
            psbt.txn = b.getvalue()

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

def render_address(script, testnet=True):
    # take a scriptPubKey (part of the TxOut) and convert into conventional human-readable
    # string... aka: the "payment address"
    from pycoin.encoding import b2a_hashed_base58
    from pycoin.contrib.segwit_addr import encode as bech32_encode

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

    # P2WPKH
    if ll == 22 and script[0:2] == b'\x00\x14':
        return bech32_encode(bech32_hrp, 0, script[2:])

    # P2WSH
    if ll == 34 and script[0:2] == b'\x00\x20':
        return bech32_encode(bech32_hrp, 0, script[2:])

    raise ValueError('Unknown payment script', repr(script))

# EOF
