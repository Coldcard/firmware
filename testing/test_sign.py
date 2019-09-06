# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Transaction Signing. Important.
#
import time, pytest, os
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from binascii import b2a_hex, a2b_hex
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from io import BytesIO
from pprint import pprint, pformat
from decimal import Decimal
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom, fake_dest_addr, make_change_addr
from pycoin.key.BIP32Node import BIP32Node
from constants import ADDR_STYLES, ADDR_STYLES_SINGLE

@pytest.mark.parametrize('finalize', [ False, True ])
def test_sign1(dev, need_keypress, finalize):
    in_psbt = a2b_hex(open('data/p2pkh-in-scriptsig.psbt', 'rb').read())

    ll, sha = dev.upload_file(in_psbt)

    dev.send_recv(CCProtocolPacker.sign_transaction(ll, sha, finalize))


    #need_keypress('y')

    with pytest.raises(CCProtoError) as ee:
        while dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None) == None:
            pass

    #assert 'None of the keys' in str(ee)
    assert 'require subpaths' in str(ee)


@pytest.mark.parametrize('fn', [
	'data/missing_ins.psbt',
	'data/missing_txn.psbt',
	'data/truncated.psbt',
	'data/unknowns-ins.psbt',
	'data/unknowns-ins.psbt',
])
def test_psbt_parse_fails(try_sign, fn):

    # just parse them
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(fn, accept=False)

    msg = ee.value.args[0]
    assert ('PSBT parse failed' in msg) or ('Invalid PSBT' in msg)

@pytest.mark.parametrize('fn', [
	'data/2-of-2.psbt',
	'data/dup_keys.psbt',
	'data/filled_scriptsig.psbt',
	'data/one-p2pkh-in.psbt',
	'data/p2pkh+p2sh+outs.psbt',
	'data/p2pkh-in-scriptsig.psbt',
	'data/p2pkh-p2sh-p2wpkh.psbt',
	'data/worked-1.psbt',
	'data/worked-2.psbt',
	'data/worked-unsigned.psbt',
	'data/worked-4.psbt',
	'data/worked-5.psbt',
	'data/worked-combined.psbt',
	'data/worked-7.psbt',
])
@pytest.mark.parametrize('accept', [True, False])
def test_psbt_parse_good(try_sign, fn, accept):
    # successful parses, but not signable

    # just parse them
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(fn, accept=accept)

    msg = ee.value.args[0]
    assert ('Missing UTXO' in msg) \
                or ('None of the keys' in msg) \
                or ('completely signed already' in msg) \
                or ('require subpaths' in msg), msg


# works, but annoying output
def xxx_test_sign_truncated(dev):
    ll, sha = dev.upload_file(open('data/truncated.psbt', 'rb').read())

    dev.send_recv(CCProtocolPacker.sign_transaction(ll, sha))

    with pytest.raises(CCProtoError):
        done = None
        while done == None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)


@pytest.mark.parametrize('fn', [
	'data/2-of-2.psbt',
	'data/dup_keys.psbt',
	'data/filled_scriptsig.psbt',
	'data/one-p2pkh-in.psbt',
	'data/p2pkh+p2sh+outs.psbt',
	'data/p2pkh-in-scriptsig.psbt',
	'data/p2pkh-p2sh-p2wpkh.psbt',
	'data/worked-1.psbt',
	'data/worked-2.psbt',
	'data/worked-unsigned.psbt',
	'data/worked-4.psbt',
	'data/worked-5.psbt',
	'data/worked-combined.psbt',
	'data/worked-7.psbt',
])
def test_psbt_proxy_parsing(fn, sim_execfile, sim_exec):
    # unit test: parsing by the psbt proxy object

    sim_exec('import main; main.FILENAME = %r; ' % ('../../testing/'+fn))
    rv = sim_execfile('devtest/unit_psbt.py')
    assert not rv, rv

    rb = '../unix/work/readback.psbt'

    oo = BasicPSBT().parse(open(fn, 'rb').read())
    rb = BasicPSBT().parse(open(rb, 'rb').read())
    assert oo == rb

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

            if style.endswith('sh'):
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

@pytest.mark.parametrize('num_out', [1, 10,11, 250])
@pytest.mark.parametrize('num_in', [1, 10, 20])
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('out_style', ADDR_STYLES)
def test_io_size(request, decode_with_bitcoind, fake_txn,
                    start_sign, end_sign, dev, segwit, out_style, 
                    num_out, num_in, accept=True):

    # try a bunch of different bigger sized txns
    # - important to test on real device, due to it's limited memory
    # - cmdline: "pytest test_sign.py -k test_io_size --dev --manual -s --durations=50"
    # - simulator can do 400/400 but takes long time
    # - offical target: 20 inputs, 250 outputs (see docs/limitations.md)
    # - complete run on real hardware takes 1800.94 seconds = 30 minutes

    psbt = fake_txn(num_in, num_out, dev.master_xpub, segwit_in=segwit, outstyles=[out_style])

    open('debug/last.psbt', 'wb').write(psbt)

    start_sign(psbt, finalize=True)

    # on simulator, read screen
    try:
        cap_story = request.getfixturevalue('cap_story')
        time.sleep(.01)
        title, story = cap_story()
        assert 'OK TO SEND' in title
    except:
        cap_story = None

    signed = end_sign(accept, finalize=True)

    decoded = decode_with_bitcoind(signed)

    #print("Bitcoin code says:", end=''); pprint(decoded)

    if cap_story:
        # check we are showing right addresses
        shown = set()
        hidden = set()
        for i in decoded['vout']:
            dest = i['scriptPubKey']['addresses'][0]
            val = i['value']
            if dest in story:
                shown.add((val, dest))
                assert str(val) in story
            else:
                hidden.add((val, dest))

        # UI only shows 10 largest outputs if there are too many
        # - assuming no change outputs here
        MAX_VIZ = 10
        if num_out <= MAX_VIZ:
            assert len(shown) == num_out
            assert not hidden
        else:
            assert 'which total' in story
            assert len(shown) == MAX_VIZ
            assert len(hidden) >= 1
            assert len(shown) + len(hidden) == len(decoded['vout'])
            assert max(v for v,d in hidden) >= min(v for v,d in shown)
    
    
@pytest.mark.parametrize('num_ins', [ 2, 7, 15 ])
@pytest.mark.parametrize('segwit', [True, False])
def test_real_signing(fake_txn, try_sign, dev, num_ins, segwit, decode_with_bitcoind):
    # create a TXN using actual addresses that are correct for DUT
    xp = dev.master_xpub

    psbt = fake_txn(num_ins, 1, xp, segwit_in=segwit)
    open('debug/real-%d.psbt' % num_ins, 'wb').write(psbt)

    _, txn = try_sign(psbt, accept=True, finalize=True)

    #print('Signed; ' + B2A(txn))

    decoded = decode_with_bitcoind(txn)

    #pprint(decoded)

    assert len(decoded['vin']) == num_ins
    if segwit:
        assert all(x['txinwitness'] for x in decoded['vin'])

@pytest.mark.parametrize('we_finalize', [ False, True ])
@pytest.mark.parametrize('num_dests', [ 1, 10, 25 ])
@pytest.mark.bitcoind
def test_vs_bitcoind(match_key, check_against_bitcoind, bitcoind, start_sign, end_sign, we_finalize, num_dests):

    wallet_xfp = match_key()

    bal = bitcoind.getbalance()
    assert bal > 0, "need some play money; drink from a faucet"

    amt = round((bal/4)/num_dests, 6)

    args = {}

    for no in range(num_dests):
        dest = bitcoind.getrawchangeaddress()
        assert dest[0] in '2mn' or dest.startswith('tb1'), dest

        args[dest] = amt

    if 0:
        # old approach: fundraw + convert to psbt

        # working with hex strings here
        txn = bitcoind.createrawtransaction([], args)
        assert txn[0:2] == '02'
        #print(txn)

        resp = bitcoind.fundrawtransaction(txn)
        txn2 = resp['hex']
        fee = resp['fee']
        chg_pos = resp['changepos']
        #print(txn2)

        print("Sending %.8f XTN to %s (Change back in position: %d)" % (amt, dest, chg_pos))

        psbt = b64decode(bitcoind.converttopsbt(txn2, True))

    # use walletcreatefundedpsbt
    # - updated/validated against 0.17.1
    resp = bitcoind.walletcreatefundedpsbt([], args, 0, {
                'subtractFeeFromOutputs': list(range(num_dests)),
                'feeRate': 0.00001500}, True)

    if 0:
        # OMFG all this to reconstruct the rpc command!
        import json, decimal
        def EncodeDecimal(o):
            if isinstance(o, decimal.Decimal):
                return float(round(o, 8))
            raise TypeError

        print('walletcreatefundedpsbt "[]" "[%s]" 0 {} true' % json.dumps(args,
                    default=EncodeDecimal).replace('"', '\\"'))

    psbt = b64decode(resp['psbt'])
    fee = resp['fee']
    chg_pos = resp['changepos']

    open('debug/vs.psbt', 'wb').write(psbt)

    # check some basics
    mine = BasicPSBT().parse(psbt)
    from struct import unpack_from
    for i in mine.inputs:
        got_xfp, = unpack_from('I', list(i.bip32_paths.values())[0])
        #assert hex(got_xfp) == hex(wallet_xfp), "wrong HD master key fingerprint"

        # see <https://github.com/bitcoin/bitcoin/issues/15884>
        if hex(got_xfp) != hex(wallet_xfp):
            raise pytest.xfail("wrong HD master key fingerprint")

    # pull out included txn
    txn2 = B2A(mine.txn)

    start_sign(psbt, finalize=we_finalize)

    # verify against how bitcoind reads it
    check_against_bitcoind(txn2, fee)

    signed = end_sign(accept=True)
    open('debug/vs-signed.psbt', 'wb').write(signed)

    if not we_finalize:
        b4 = BasicPSBT().parse(psbt)
        aft = BasicPSBT().parse(signed)
        assert b4 != aft, "signing didn't change anything?"

        open('debug/signed.psbt', 'wb').write(signed)
        resp = bitcoind.finalizepsbt(str(b64encode(signed), 'ascii'), True)

        #combined_psbt = b64decode(resp['psbt'])
        #open('debug/combined.psbt', 'wb').write(combined_psbt)

        assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

        network = a2b_hex(resp['hex'])

        # assert resp['complete']
        #print("Final txn: %r" % network)
        open('debug/finalized-by-btcd.txn', 'wb').write(network)

        # try to send it
        txed = bitcoind.sendrawtransaction(B2A(network))
        print("Final txn hash: %r" % txed)

    else:
        assert signed[0:4] != b'psbt', "expecting raw bitcoin txn"
        #print("Final txn: %s" % B2A(signed))
        open('debug/finalized-by-cc.txn', 'wb').write(signed)

        txed = bitcoind.sendrawtransaction(B2A(signed))
        print("Final txn hash: %r" % txed)

def test_sign_example(set_master_key, sim_execfile, start_sign, end_sign):
    # use the private key given in BIP 174 and do similar signing
    # as the examples.
    
    exk = 'tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF'
    set_master_key(exk)

    mk = BIP32Node.from_wallet_key(exk)

    psbt = a2b_hex(open('data/worked-unsigned.psbt', 'rb').read())

    start_sign(psbt)
    signed = end_sign(True)

    aft = BasicPSBT().parse(signed)
    expect = BasicPSBT().parse(open('data/worked-combined.psbt', 'rb').read())

    assert aft == expect

    #assert 'require subpaths to be spec' in str(ee)

def test_sign_p2sh_p2wpkh(match_key, start_sign, end_sign, bitcoind):
    # Check we can finalize p2sh_p2wpkh inputs right.

    #raise pytest.skip('not ready/junk test')

    wallet_xfp = match_key()

    fn = 'data/p2sh_p2wpkh.psbt'

    psbt = open(fn, 'rb').read()

    start_sign(psbt, finalize=True)
    signed = end_sign(accept=True)
    #signed = end_sign(None)
    open('debug/p2sh-signed.psbt', 'wb').write(signed)

    #print('my finalization: ' + B2A(signed))

    start_sign(psbt, finalize=False)
    signed_psbt = end_sign(accept=True)

    # use bitcoind to combine
    open('debug/signed.psbt', 'wb').write(signed_psbt)
    resp = bitcoind.finalizepsbt(str(b64encode(signed_psbt), 'ascii'), True)

    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"
    network = a2b_hex(resp['hex'])

    #print('his finalization: ' + B2A(network))

    assert network == signed

def test_sign_p2sh_example(set_master_key, sim_execfile, start_sign, end_sign, decode_psbt_with_bitcoind, offer_ms_import, need_keypress, clear_ms):
    # Use the private key given in BIP 174 and do similar signing
    # as the examples.

    # PROBLEM: we can't handle this, since we don't allow same cosigner key to be used
    # more than once and that check happens after we decide we can sign an input, and yet
    # no way to provide the right set of keys needed since 4 in total, etc, etc.
    # - code below nearly works tho
    raise pytest.skip('difficult example')
    
    # expect xfp=4F6A0CD9
    exk = 'tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF'
    set_master_key(exk)

    # Peeked at PSBT to know the full, deep hardened path we'll need.
    # in1: 0'/0'/0' and 0'/0'/1'
    # in2: 0'/0'/3' and 0'/0'/2'

    config = "name: p2sh-example\npolicy: 2 of 2\n\n"
    n1 = BIP32Node.from_hwif(exk).subkey_for_path("0'/0'").hwif()
    n2 = BIP32Node.from_hwif(exk).subkey_for_path("0'/0'").hwif()
    xfp = '4F6A0CD9'
    config += f'{xfp}: {n1}\n{xfp}: {n2}\n'

    clear_ms()
    offer_ms_import(config)
    time.sleep(.1)
    need_keypress('y')

    psbt = a2b_hex(open('data/worked-unsigned.psbt', 'rb').read())

    # PROBLEM: revised BIP174 has p2sh multisig cases which we don't support yet.
    # - it has two signatures from same key on same input
    # - that's a rare case and not worth supporting in the firmware
    # - but we can do it in two passes
    # - the MS wallet is also hard, since dup xfp (same actual key) ... altho can
    #   provide different subkeys

    start_sign(psbt)
    part_signed = end_sign(True)

    open('debug/ex-signed-part.psbt', 'wb').write(part_signed)

    b4 = BasicPSBT().parse(psbt)
    aft = BasicPSBT().parse(part_signed)
    assert b4 != aft, "(partial) signing didn't change anything?"

    # NOTE: cannot handle combining multisig txn yet, so cannot finalize on-device
    start_sign(part_signed, finalize=False)
    signed = end_sign(True, finalize=False)

    open('debug/ex-signed.psbt', 'wb').write(signed)
    aft2 = BasicPSBT().parse(signed)

    decode = decode_psbt_with_bitcoind(signed)
    pprint(decode)

    mx_expect = BasicPSBT().parse(a2b_hex(open('data/worked-combined.psbt', 'rb').read()))
    assert aft2 == mx_expect

    expect = a2b_hex(open('data/worked-combined.psbt', 'rb').read())
    decode_ex = decode_psbt_with_bitcoind(expect)

    # NOTE: because we are using RFC6979, the exact bytes of the signatures should match

    for i in range(2):
        assert decode['inputs'][i]['partial_signatures'] == \
                    decode_ex['inputs'][i]['partial_signatures']

    if 0:
        import json, decimal
        def EncodeDecimal(o):
            if isinstance(o, decimal.Decimal):
                return float(round(o, 8))
            raise TypeError
        json.dump(decode, open('debug/core-decode.json', 'wt'), indent=2, default=EncodeDecimal)

@pytest.mark.bitcoind
def test_change_case(start_sign, end_sign, check_against_bitcoind, cap_story):
    # is change shown/hidden at right times. no fraud checks 

    # NOTE: out#1 is change:
    chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()

    start_sign(psbt)

    time.sleep(.1)
    _, story = cap_story()
    assert chg_addr not in story

    b4 = BasicPSBT().parse(psbt)
    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[1,])

    signed = end_sign(True)
    open('debug/chg-signed.psbt', 'wb').write(signed)

    # modify it: remove bip32 path
    b4.outputs[1].bip32_paths = {}
    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    start_sign(mod_psbt)

    time.sleep(.1)
    _, story = cap_story()
    assert chg_addr in story

    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[])

    signed2 = end_sign(True)
    open('debug/chg-signed2.psbt', 'wb').write(signed)
    aft = BasicPSBT().parse(signed)
    aft2 = BasicPSBT().parse(signed2)
    assert aft.txn == aft2.txn

@pytest.mark.parametrize('case', [ 1, 2])
@pytest.mark.bitcoind
def test_change_fraud_path(start_sign, end_sign, case, check_against_bitcoind, cap_story):
    # fraud: BIP32 path of output doesn't lead to pubkey indicated

    # NOTE: out#1 is change:
    chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    (pubkey, path), = b4.outputs[1].bip32_paths.items()
    skp = bytearray(b4.outputs[1].bip32_paths[pubkey])
    if case == 1:
        # change subkey
        skp[-2] ^= 0x01
    elif case == 2:
        # change xfp
        skp[0] ^= 0x01

    b4.outputs[1].bip32_paths[pubkey] = bytes(skp)

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    open('debug/mod-%d.psbt' % case, 'wb').write(mod_psbt)

    if case == 1:
        start_sign(mod_psbt)
        with pytest.raises(CCProtoError) as ee:
            signed = end_sign(True)
        assert 'BIP32 path' in str(ee)
    elif case == 2:
        # will not consider it a change output, but not an error either
        start_sign(mod_psbt)
        check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[])

        time.sleep(.1)
        _, story = cap_story()
        assert chg_addr in story

        signed = end_sign(True)

@pytest.mark.bitcoind
def test_change_fraud_addr(start_sign, end_sign, check_against_bitcoind, cap_story):
    # fraud: BIP32 path of output doesn't match TXO address
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxOut import TxOut

    # NOTE: out#1 is change:
    #chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    # tweak output addr to garbage
    t = Tx.parse(BytesIO(b4.txn))
    chg = t.txs_out[1]          # pycoin.tx.TxOut.TxOut
    b = bytearray(chg.script)
    b[-5] ^= 0x55
    chg.script = bytes(b)

    b4.txn = t.as_bin()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    open('debug/mod-addr.psbt', 'wb').write(mod_psbt)

    start_sign(mod_psbt)
    with pytest.raises(CCProtoError) as ee:
        signed = end_sign(True)
    assert 'Change output is fraud' in str(ee)


@pytest.mark.parametrize('case', [ 'p2wpkh', 'p2sh'])
@pytest.mark.bitcoind
def test_change_p2sh_p2wpkh(start_sign, end_sign, check_against_bitcoind, cap_story, case):
    # not fraud: output address encoded in various equiv forms
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxOut import TxOut

    # NOTE: out#1 is change:
    #chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    t = Tx.parse(BytesIO(b4.txn))

    pkh = t.txs_out[1].hash160()

    if case == 'p2wpkh':
        t.txs_out[1].script = bytes([0, 20]) + bytes(pkh)

        from bech32 import encode
        expect_addr = encode('tb', 1, pkh)

    elif case == 'p2sh':
        b4.outputs[1].redeem_script = bytes([0, 20]) + bytes(pkh)

        spk = bytes([0xa9, 0x14]) + pkh + bytes([0x87])

        t.txs_out[1].script = spk

        expect_addr = t.txs_out[1].address()

    b4.txn = t.as_bin()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    open('debug/mod-%s.psbt' % case, 'wb').write(mod_psbt)

    start_sign(mod_psbt)

    _, story = cap_story()

    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[1,])

    #print(story)

    signed = end_sign(True)

def test_sign_multisig_partial_fail(start_sign, end_sign):

    # file from AChow, via slack: a partially signed multisig setup (which we can't handle)
    #fn = 'data/multisig-single.psbt'
    fn = 'data/multisig-single-unsigned.psbt'
    from base64 import b64decode

    psbt = b64decode(open(fn, 'rb').read())

    with pytest.raises(CCProtoError) as ee:
        start_sign(psbt, finalize=True)
        signed = end_sign(accept=True)

    assert 'None of the keys involved' in str(ee)

def test_sign_wutxo(start_sign, set_seed_words, end_sign, cap_story, sim_exec, sim_execfile):

    # Example from SomberNight: we can sign it, but signature won't be accepted by
    # network because the PSBT lies about the UTXO amount and tries to give away to miners,
    # as overly-large fee.

    set_seed_words('fault lava rice chest uncle exclude power tornado catalog stool'
                    ' swear rival sun aspect oyster deer pepper exchange scrap toward'
                    ' mix second world shaft')

    in_psbt = a2b_hex(open('data/snight-example.psbt', 'rb').read()[:-1])

    for fin in (False, True):
        start_sign(in_psbt, finalize=fin)

        time.sleep(.1)
        _, story = cap_story()

        #print(story)

        assert 'Network fee:\n0.00000500 XTN' in story

        # check we understood it right
        ex = dict(  had_witness=False, num_inputs=1, num_outputs=1, sw_inputs=[True], 
                    miner_fee=500, warnings_expected=0,
                    lock_time=1442308, total_value_out=99500,
                    total_value_in=100000)

        rv= sim_exec('import main; main.EXPECT = %r; ' % ex)
        if rv: pytest.fail(rv)
        rv = sim_execfile('devtest/check_decode.py')
        if rv: pytest.fail(rv)

        signed = end_sign(True, finalize=fin)

        open('debug/sn-signed.'+ ('txn' if fin else 'psbt'), 'wb').write(signed)

@pytest.mark.parametrize('fee_max', [ 10, 25, 50])
@pytest.mark.parametrize('under', [ False, True])
def test_network_fee_amts(fee_max, under, fake_txn, try_sign, start_sign, dev, settings_set, sim_exec, cap_story):

    settings_set('fee_limit', fee_max)

    # creat a txn with single 1BTC input, and one output, equal to 1BTC-fee
    target = (fee_max - 2) if under else fee_max
    outval = int(1E8 / ((target/100.) + 1.))

    psbt = fake_txn(1, 1, dev.master_xpub, fee=None, outvals=[outval])

    open('debug/fee.psbt', 'wb').write(psbt)

    if not under:
        with pytest.raises(CCProtoError) as ee:
            try_sign(psbt, False)
        msg = ee.value.args[0]
        assert 'Network fee bigger than' in msg
        assert ('than %d%% of total' % target) in msg
    else:
        start_sign(psbt, False)
        time.sleep(.1)
        _, story = cap_story()

        assert 'warning below' in story
        assert 'Big Fee' in story
        assert 'more than 5% of total' in story

    settings_set('fee_limit', 10)

def test_network_fee_unlimited(fake_txn, start_sign, end_sign, dev, settings_set, cap_story):

    settings_set('fee_limit', -1)

    # creat a txn with single 1BTC input, and tiny one output; the rest is fee
    outval = 100

    psbt = fake_txn(1, 1, dev.master_xpub, fee=None, outvals=[outval])

    open('debug/fee-un.psbt', 'wb').write(psbt)

    # should be able to sign, but get warning
    start_sign(psbt, False)

    time.sleep(.1)
    _, story = cap_story()

    #print(story)

    assert 'warning below' in story
    assert 'Big Fee' in story
    assert 'more than 5% of total' in story

    settings_set('fee_limit', 10)

@pytest.mark.parametrize('num_outs', [ 2, 7, 15 ])
@pytest.mark.parametrize('act_outs', [ 2, 1, -1])
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('out_style', ADDR_STYLES_SINGLE)
def test_change_outs(fake_txn, start_sign, end_sign, cap_story, dev, num_outs,
                        act_outs, segwit, out_style, num_ins=3):
    # create a TXN which has change outputs, which shouldn't be shown to user, and also not fail.
    xp = dev.master_xpub

    couts = num_outs if act_outs == -1 else num_ins-act_outs
    psbt = fake_txn(num_ins, num_outs, xp, segwit_in=segwit,
                        outstyles=[out_style], change_outputs=range(couts))

    open('debug/change.psbt', 'wb').write(psbt)

    # should be able to sign, but get warning
    start_sign(psbt, False)

    time.sleep(.1)
    title, story = cap_story()
    print(repr(story))

    assert title == "OK TO SEND?"
    assert 'Network fee' in story

    if couts < num_outs:
        assert '- to address -' in story
    else:
        assert 'Consolidating' in story

    #signed = end_sign(True, finalize=True)

def KEEP_test_random_psbt(try_sign, sim_exec, fname="data/   .psbt"):
    # allow almost any PSBT to run on simulator, at least up until wrong pubkeys detected
    # - detects expected XFP and changes to match
    # - good for debug of random psbt
    oo = BasicPSBT().parse(open(fname, 'rb').read())
    paths = []
    for i in oo.inputs:
         paths.extend(i.bip32_paths.values())

    used = set(i[0:4] for i in paths)
    assert len(used) == 1, "multiple key fingerprints in inputs, can only handle 1"
    import struct
    need_xfp, = struct.unpack("<I", used.pop())

    sim_exec('from main import settings; settings.set("xfp", 0x%x);' % need_xfp)


    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign('data/tick11088.psbt', accept=True)

    msg = ee.value.args[0]
    assert 'Signing failed late' in msg
    assert 'led to wrong pubkey for input' in msg


@pytest.mark.parametrize('num_dests', [ 1, 10, 25 ])
@pytest.mark.bitcoind
def test_finalization_vs_bitcoind(match_key, check_against_bitcoind, bitcoind, start_sign, end_sign, num_dests):
    # Compare how we finalize vs bitcoind ... should be exactly the same txn

    wallet_xfp = match_key()

    bal = bitcoind.getbalance()
    assert bal > 0, "need some play money; drink from a faucet"

    amt = round((bal/4)/num_dests, 6)

    args = {}

    for no in range(num_dests):
        dest = bitcoind.getrawchangeaddress()
        assert dest[0] in '2mn' or dest.startswith('tb1'), dest

        args[dest] = amt

    # use walletcreatefundedpsbt
    # - updated/validated against 0.17.1
    resp = bitcoind.walletcreatefundedpsbt([], args, 0, {
                'subtractFeeFromOutputs': list(range(num_dests)),
                'feeRate': 0.00001500}, True)

    psbt = b64decode(resp['psbt'])
    fee = resp['fee']
    chg_pos = resp['changepos']

    open('debug/vs.psbt', 'wb').write(psbt)

    # check some basics
    mine = BasicPSBT().parse(psbt)
    from struct import unpack_from
    for i in mine.inputs:
        got_xfp, = unpack_from('I', list(i.bip32_paths.values())[0])
        #assert hex(got_xfp) == hex(wallet_xfp), "wrong HD master key fingerprint"

        # see <https://github.com/bitcoin/bitcoin/issues/15884>
        if hex(got_xfp) != hex(wallet_xfp):
            raise pytest.xfail("wrong HD master key fingerprint")

    # pull out included txn
    txn2 = B2A(mine.txn)

    start_sign(psbt, finalize=True)

    # verify against how bitcoind reads it
    check_against_bitcoind(txn2, fee)

    signed_final = end_sign(accept=True)
    assert signed_final[0:4] != b'psbt', "expecting raw bitcoin txn"
    open('debug/finalized-by-ckcc.txn', 'wt').write(B2A(signed_final))

    # Sign again, but don't finalize it.
    start_sign(psbt, finalize=False)
    signed = end_sign(accept=True)

    open('debug/vs-signed-unfin.psbt', 'wb').write(signed)

    # Use bitcoind to finalize it this time.
    resp = bitcoind.finalizepsbt(str(b64encode(signed), 'ascii'), True)
    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

    network = a2b_hex(resp['hex'])

    # assert resp['complete']
    #print("Final txn: %r" % network)
    open('debug/finalized-by-btcd.txn', 'wt').write(B2A(network))

    assert network == signed_final, "Finalized differently"

    # try to send it
    txed = bitcoind.sendrawtransaction(B2A(network))
    print("Final txn hash: %r" % txed)


# EOF
