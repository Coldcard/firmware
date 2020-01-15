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
                outvals=None, segwit_in=False, outstyles=['p2pkh'], change_outputs=[]):
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
                #if style.endswith('sh'):

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

            txn.txs_out.append(h)

        with BytesIO() as b:
            txn.stream(b)
            psbt.txn = b.getvalue()

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit
