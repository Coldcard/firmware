# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Transaction Signing. Important.
#

import time, pytest, os, random, pdb, struct, base64, binascii, itertools
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from binascii import b2a_hex, a2b_hex
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from io import BytesIO
from pprint import pprint, pformat
from decimal import Decimal
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom, fake_dest_addr, make_change_addr, parse_change_back
from helpers import xfp2str
from pycoin.key.BIP32Node import BIP32Node
from constants import ADDR_STYLES, ADDR_STYLES_SINGLE, SIGHASH_MAP
from txn import *
from ckcc_protocol.constants import STXN_FINALIZE, STXN_VISUALIZE, STXN_SIGNED


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
    #assert 'require subpaths' in str(ee)
    assert 'PSBT does not contain any key path information' in str(ee)


@pytest.mark.parametrize('fn', [
	'data/missing_ins.psbt',
	'data/missing_txn.psbt',
	'data/truncated.psbt',
	'data/unknowns-ins.psbt',
	'data/unknowns-ins.psbt',
	'data/dup_keys.psbt',
])
def test_psbt_parse_fails(try_sign, fn):

    # just parse them
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(fn, accept=False)

    msg = ee.value.args[0]
    assert ('PSBT parse failed' in msg) or ('Invalid PSBT' in msg)

@pytest.mark.parametrize('fn', [
	'data/2-of-2.psbt',
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
                or ('PSBT does not contain any key path information' in msg) \
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

    raise pytest.xfail('issues on mk4 sim?')        # XXX fix me

    sim_exec('import main; main.FILENAME = %r; ' % ('../../testing/'+fn))
    rv = sim_execfile('devtest/unit_psbt.py')
    assert not rv, rv

    rb = '../unix/work/readback.psbt'

    oo = BasicPSBT().parse(open(fn, 'rb').read())
    rb = BasicPSBT().parse(open(rb, 'rb').read())
    assert oo == rb

@pytest.mark.unfinalized
def test_speed_test(dev, fake_txn, is_mark3, is_mark4, start_sign, end_sign, need_keypress):
    import time
    # measure time to sign a larger txn
    if is_mark4:
        # Mk4: expect 
        #       20/250 => 15.5s (or 10.0 if seed is cached)
        #       200/500 => 96.3s 
        num_in = 20
        num_out = 250
    elif is_mark3:
        num_in = 20
        num_out = 250
    else:
        num_in = 9
        num_out = 100

    psbt = fake_txn(num_in, num_out, dev.master_xpub, segwit_in=True)

    open('debug/speed.psbt', 'wb').write(psbt)
    dt = time.time()
    start_sign(psbt, finalize=False)

    tx_time = time.time() - dt

    need_keypress('y', timeout=None)

    dt = time.time()
    done = None
    while done == None:
        time.sleep(0.05)
        done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

    ready_time = time.time() - dt

    print("  Tx time: %.1f" % tx_time)
    print("Sign time: %.1f" % ready_time)

if 0:
    # TODO: attempt to re-create the mega transaction: 5,569 inputs, one out
    # see <https://bitcoin.stackexchange.com/questions/11542>
    # - how big woudl PSBT be?
    # - not a great test case because so slow.
    def test_mega_txn(fake_txn, is_mark4, start_sign, end_sign, dev):
        if not is_mark4:
            raise pytest.xfail('no way')

        psbt = fake_txn(5569, 1, dev.master_xpub)

        open('debug/mega.psbt', 'wb').write(psbt)

        _, txn = try_sign(psbt, accept=True, finalize=True)

        open('debug/mega.txn', 'wb').write(txn)


@pytest.mark.bitcoind
@pytest.mark.veryslow
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('out_style', ADDR_STYLES)
def test_io_size(request, use_regtest, decode_with_bitcoind, fake_txn, is_mark3, is_mark4,
                    start_sign, end_sign, dev, segwit, out_style, accept = True):

    # try a bunch of different bigger sized txns
    # - important to test on real device, due to it's limited memory
    # - cmdline: "pytest test_sign.py -k test_io_size --dev --manual -s --durations=50"
    # - simulator can do 400/400 but takes long time
    # - offical target: 20 inputs, 250 outputs (see docs/limitations.md)
    # - complete run on real hardware takes 1800.94 seconds = 30 minutes
    # - only mk3 can do full amounts
    # - time on mk3, v4.0.0 firmware: 13 minutes

    # for this test you need to configure core `repcservertimeout` to something big
    # in bitcoin.conf `rpcservertimeout=2000` should do the trick
    use_regtest()
    num_in = 10
    num_out = 10

    if is_mark3:
        num_in = 20
        num_out = 250
    elif is_mark4:
        num_in = 250
        num_out = 2000

    psbt = fake_txn(num_in, num_out, dev.master_xpub, segwit_in=segwit, outstyles=[out_style])

    open('debug/last.psbt', 'wb').write(psbt)

    start_sign(psbt, finalize=True)

    # on simulator, read screen
    try:
        cap_story = request.getfixturevalue('cap_story')
        time.sleep(.1)
        title, story = cap_story()
        assert 'OK TO SEND' in title
    except:
        cap_story = None

    signed = end_sign(accept, finalize=True)

    open('debug/signed.txn', 'wb').write(signed)

    decoded = decode_with_bitcoind(signed)

    #print("Bitcoin code says:", end=''); pprint(decoded)

    if cap_story:
        # check we are showing right addresses
        shown = set()
        hidden = set()
        for i in decoded['vout']:
            dest = i['scriptPubKey']['address']
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
    

@pytest.mark.bitcoind
@pytest.mark.parametrize('num_ins', [ 2, 7, 15 ])
@pytest.mark.parametrize('segwit', [True, False])
def test_real_signing(fake_txn, use_regtest, try_sign, dev, num_ins, segwit, decode_with_bitcoind):
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


@pytest.mark.unfinalized        # iff we_finalize=F
@pytest.mark.parametrize('we_finalize', [ False, True ])
@pytest.mark.parametrize('num_dests', [ 1, 10, 25 ])
@pytest.mark.bitcoind
def test_vs_bitcoind(match_key, use_regtest, check_against_bitcoind, bitcoind, start_sign, end_sign, we_finalize, num_dests):

    wallet_xfp = match_key
    use_regtest()
    bal = bitcoind.supply_wallet.getbalance()
    assert bal > 0, "need some play money; drink from a faucet"

    amt = round((bal/4)/num_dests, 6)

    args = {}

    for no in range(num_dests):
        dest = bitcoind.supply_wallet.getrawchangeaddress()
        assert dest.startswith('bcrt1'), dest

        args[dest] = amt

    if 0:
        # old approach: fundraw + convert to psbt

        # working with hex strings here
        txn = bitcoind.supply_wallet.createrawtransaction([], args)
        assert txn[0:2] == '02'
        #print(txn)

        resp = bitcoind.supply_wallet.fundrawtransaction(txn)
        txn2 = resp['hex']
        fee = resp['fee']
        chg_pos = resp['changepos']
        #print(txn2)

        print("Sending %.8f XTN to %s (Change back in position: %d)" % (amt, dest, chg_pos))

        psbt = b64decode(bitcoind.supply_wallet.converttopsbt(txn2, True))

    # use walletcreatefundedpsbt
    # - updated/validated against 0.17.1
    resp = bitcoind.supply_wallet.walletcreatefundedpsbt([], args, 0, {
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
    for i in mine.inputs:
        got_xfp, = struct.unpack_from('I', list(i.bip32_paths.values())[0])
        #assert hex(got_xfp) == hex(wallet_xfp), "wrong HD master key fingerprint"

        # see <https://github.com/bitcoin/bitcoin/issues/15884>
        if hex(got_xfp) != hex(wallet_xfp):
            raise pytest.xfail("wrong HD master key fingerprint")

    start_sign(psbt, finalize=we_finalize)
    if mine.txn:
        # pull out included txn
        txn2 = B2A(mine.txn)
        # verify against how bitcoind reads it
        check_against_bitcoind(txn2, fee)
    else:
        assert mine.version == 2

    signed = end_sign(accept=True, finalize=we_finalize)
    open('debug/vs-signed.psbt', 'wb').write(signed)

    if not we_finalize:
        b4 = BasicPSBT().parse(psbt)
        aft = BasicPSBT().parse(signed)
        assert b4 != aft, "signing didn't change anything?"

        open('debug/signed.psbt', 'wb').write(signed)
        resp = bitcoind.supply_wallet.finalizepsbt(str(b64encode(signed), 'ascii'), True)

        #combined_psbt = b64decode(resp['psbt'])
        #open('debug/combined.psbt', 'wb').write(combined_psbt)

        assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

        network = a2b_hex(resp['hex'])

        # assert resp['complete']
        print("Final txn: %r" % network)
        open('debug/finalized-by-btcd.txn', 'wb').write(network)

        # try to send it
        txed = bitcoind.supply_wallet.sendrawtransaction(B2A(network))
        print("Final txn hash: %r" % txed)

    else:
        assert signed[0:4] != b'psbt', "expecting raw bitcoin txn"
        #print("Final txn: %s" % B2A(signed))
        open('debug/finalized-by-cc.txn', 'wb').write(signed)

        txed = bitcoind.supply_wallet.sendrawtransaction(B2A(signed))
        print("Final txn hash: %r" % txed)

def test_sign_example(set_master_key, sim_execfile, start_sign, end_sign):
    # use the private key given in BIP 174 and do similar signing
    # as the examples.

    # TODO fix this
    # - doesn't work anymore, because we won't sign a multisig we don't know the wallet details for
    raise pytest.skip('needs rework')
    
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

@pytest.mark.bitcoind
@pytest.mark.unfinalized
def test_sign_p2sh_p2wpkh(match_key, use_regtest, start_sign, end_sign, bitcoind):
    # Check we can finalize p2sh_p2wpkh inputs right.

    # TODO fix this
    # - doesn't work anymore, because we won't sign a multisig we don't know the wallet details for
    raise pytest.skip('needs rework')

    wallet_xfp = match_key

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
    resp = bitcoind.rpc.finalizepsbt(str(b64encode(signed_psbt), 'ascii'), True)

    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"
    network = a2b_hex(resp['hex'])

    #print('his finalization: ' + B2A(network))

    assert network == signed

@pytest.mark.bitcoind
@pytest.mark.unfinalized
def test_sign_p2sh_example(set_master_key, use_regtest, sim_execfile, start_sign, end_sign, decode_psbt_with_bitcoind, offer_ms_import, need_keypress, clear_ms):
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

    # PROBLEM: revised BIP-174 has p2sh multisig cases which we don't support yet.
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
def test_change_case(start_sign, use_regtest, end_sign, check_against_bitcoind, cap_story):
    # is change shown/hidden at right times. no fraud checks 

    # NOTE: out#1 is change:
    chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()

    start_sign(psbt)

    time.sleep(.1)
    _, story = cap_story()
    assert chg_addr in story

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

    # no change expected (they are outputs)
    assert 'Change back' not in story

    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[])

    signed2 = end_sign(True)
    open('debug/chg-signed2.psbt', 'wb').write(signed)
    aft = BasicPSBT().parse(signed)
    aft2 = BasicPSBT().parse(signed2)
    assert aft.txn == aft2.txn

@pytest.mark.parametrize('case', [ 1, 2])
@pytest.mark.bitcoind
def test_change_fraud_path(start_sign, use_regtest, end_sign, case, check_against_bitcoind, cap_story):
    # fraud: BIP-32 path of output doesn't lead to pubkey indicated

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
        assert 'BIP-32 path' in str(ee)
    elif case == 2:
        # will not consider it a change output, but not an error either
        start_sign(mod_psbt)
        check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[])

        time.sleep(.1)
        _, story = cap_story()
        assert chg_addr in story
        assert 'Change back:' not in story

        signed = end_sign(True)

@pytest.mark.bitcoind
def test_change_fraud_addr(start_sign, end_sign, use_regtest, check_against_bitcoind, cap_story):
    # fraud: BIP-32 path of output doesn't match TXO address
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
def test_change_p2sh_p2wpkh(start_sign, end_sign, check_against_bitcoind, use_regtest, cap_story, case):
    # not fraud: output address encoded in various equiv forms
    from pycoin.tx.Tx import Tx
    use_regtest()
    # NOTE: out#1 is change:
    #chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    t = Tx.parse(BytesIO(b4.txn))

    pkh = t.txs_out[1].hash160()

    if case == 'p2wpkh':
        t.txs_out[1].script = bytes([0, 20]) + bytes(pkh)

        from bech32 import encode
        expect_addr = encode('bcrt', 0, pkh)

    elif case == 'p2sh':

        spk = bytes([0xa9, 0x14]) + pkh + bytes([0x87])

        b4.outputs[1].redeem_script = bytes([0, 20]) + bytes(pkh)
        t.txs_out[1].script = spk

        expect_addr = t.txs_out[1].address('XTN')

    b4.txn = t.as_bin()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    open('debug/mod-%s.psbt' % case, 'wb').write(mod_psbt)

    start_sign(mod_psbt)

    time.sleep(.1)
    _, story = cap_story()

    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[1,],
            dests=[(1, expect_addr)])

    #print(story)
    assert expect_addr in story
    assert parse_change_back(story) == (Decimal('1.09997082'), [expect_addr])

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

@pytest.mark.unfinalized
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
        ex = dict(  had_witness=False, num_inputs=1, num_outputs=1, sw_inputs=[None],
                    miner_fee=500, warnings_expected=0,
                    lock_time=1442308, total_value_out=99500,
                    total_value_in=100000)

        rv= sim_exec('import main; main.EXPECT = %r; ' % ex)
        if rv: pytest.fail(rv)
        rv = sim_execfile('devtest/check_decode.py')
        if rv: pytest.fail(rv)

        signed = end_sign(True, finalize=fin)

        open('debug/sn-signed.'+ ('txn' if fin else 'psbt'), 'wt').write(B2A(signed))

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
@pytest.mark.parametrize('add_xpub', [True, False])
@pytest.mark.parametrize('out_style', ADDR_STYLES_SINGLE)
@pytest.mark.parametrize('visualized', [0, STXN_VISUALIZE, STXN_VISUALIZE|STXN_SIGNED])
def test_change_outs(fake_txn, start_sign, end_sign, cap_story, dev, num_outs, master_xpub,
                        act_outs, segwit, out_style, visualized, add_xpub, num_ins=3):
    # create a TXN which has change outputs, which shouldn't be shown to user, and also not fail.
    xp = dev.master_xpub

    couts = num_outs if act_outs == -1 else num_ins-act_outs
    psbt = fake_txn(num_ins, num_outs, xp, segwit_in=segwit,
                        outstyles=[out_style], change_outputs=range(couts), add_xpub=add_xpub)

    open('debug/change.psbt', 'wb').write(psbt)

    # should be able to sign, but get warning
    if not visualized:
        start_sign(psbt, False)

        time.sleep(.1)
        title, story = cap_story()
        print(repr(story))

        assert title == "OK TO SEND?"
    else:
        # use new feature to have Coldcard return the 'visualization' of transaction
        start_sign(psbt, False, stxn_flags=visualized)
        story = end_sign(accept=None, expect_txn=False)

        story = story.decode('ascii')

        if (visualized & STXN_SIGNED):
            # last line should be signature, using 'm' over the rest
            from pycoin.contrib.msg_signing import verify_message
            from pycoin.key.BIP32Node import BIP32Node

            #def verify_message(key_or_address, signature, message=None, msg_hash=None, netcode=None):

            assert story[-1] == '\n'
            last_nl = story[:-1].rindex('\n')
            msg, sig = story[0:last_nl+1], story[last_nl:]
            wallet = BIP32Node.from_wallet_key(master_xpub)
            assert verify_message(wallet, sig, message=msg) == True
            story = msg

    assert 'Network fee' in story

    if couts < num_outs:
        assert '- to address -' in story
    else:
        assert 'Consolidating' in story

    if couts == 1:
        assert "- to address -" in story
    else:
        assert "- to addresses -" in story

    val, addrs = parse_change_back(story)
    assert val > 0          # hard to calc here
    assert len(addrs) == couts
    if out_style == 'p2pkh':
        assert all((i[0] in 'mn') for i in addrs)
    elif out_style == 'p2wpkh':
        assert set(i[0:4] for i in addrs) == {'tb1q'}
    elif out_style == 'p2wpkh-p2sh':
        assert set(i[0] for i in addrs) == {'2'}

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
    need_xfp, = struct.unpack("<I", used.pop())

    sim_exec('from main import settings; settings.set("xfp", 0x%x);' % need_xfp)


    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(fname, accept=True)

    msg = ee.value.args[0]
    assert 'Signing failed late' in msg
    assert 'led to wrong pubkey for input' in msg


@pytest.mark.bitcoind
@pytest.mark.unfinalized
@pytest.mark.parametrize('num_dests', [ 1, 10, 25 ])
def test_finalization_vs_bitcoind(match_key, use_regtest, check_against_bitcoind, bitcoind, start_sign, end_sign, num_dests):
    # Compare how we finalize vs bitcoind ... should be exactly the same txn
    wallet_xfp = match_key
    # has to be after match key
    use_regtest()

    bal = bitcoind.supply_wallet.getbalance()
    assert bal > 0, "need some play money; drink from a faucet"

    amt = round((bal/4)/num_dests, 6)

    args = {}

    for no in range(num_dests):
        dest = bitcoind.supply_wallet.getrawchangeaddress()
        assert dest.startswith('bcrt1q'), dest

        args[dest] = amt

    # use walletcreatefundedpsbt
    # - updated/validated against 0.17.1
    resp = bitcoind.supply_wallet.walletcreatefundedpsbt([], args, 0, {
                'subtractFeeFromOutputs': list(range(num_dests)),
                'feeRate': 0.00001500}, True)

    psbt = b64decode(resp['psbt'])
    fee = resp['fee']
    chg_pos = resp['changepos']

    open('debug/vs.psbt', 'wb').write(psbt)

    # check some basics
    mine = BasicPSBT().parse(psbt)
    for i in mine.inputs:
        got_xfp, = struct.unpack_from('I', list(i.bip32_paths.values())[0])
        #assert hex(got_xfp) == hex(wallet_xfp), "wrong HD master key fingerprint"

        # see <https://github.com/bitcoin/bitcoin/issues/15884>
        if hex(got_xfp) != hex(wallet_xfp):
            raise pytest.xfail("wrong HD master key fingerprint")

    start_sign(psbt, finalize=True)
    if mine.txn:
        # pull out included txn (only available in PSBTv0)
        txn2 = B2A(mine.txn)
        # verify against how bitcoind reads it
        check_against_bitcoind(txn2, fee)
    else:
        assert mine.version == 2

    signed_final = end_sign(accept=True, finalize=True)
    assert signed_final[0:4] != b'psbt', "expecting raw bitcoin txn"
    open('debug/finalized-by-ckcc.txn', 'wt').write(B2A(signed_final))

    # Sign again, but don't finalize it.
    start_sign(psbt, finalize=False)
    signed = end_sign(accept=True)

    open('debug/vs-signed-unfin.psbt', 'wb').write(signed)

    # Use bitcoind to finalize it this time.
    resp = bitcoind.supply_wallet.finalizepsbt(str(b64encode(signed), 'ascii'), True)
    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

    network = a2b_hex(resp['hex'])

    # assert resp['complete']
    #print("Final txn: %r" % network)
    open('debug/finalized-by-btcd.txn', 'wt').write(B2A(network))

    assert network == signed_final, "Finalized differently"

    # try to send it
    txed = bitcoind.supply_wallet.sendrawtransaction(B2A(network))
    print("Final txn hash: %r" % txed)


# Correct change path is: (m=4369050F)/44'/1'/0'/1/5
@pytest.mark.parametrize('try_path,expect', [
    ("44'/1'/0'/1/40000", 'last component beyond'),
    ("44'/1'/0'/1/405", 'last component beyond'),
    ("44'/1'/0'/1'/5", 'hardening'),
    ("44'/1'/0'/1/5'", 'hardening'),
    ("44'/1/0'/1/5'", 'hardening'),
    ("45'/1'/0'/1/5", 'diff path prefix'),
    ("44'/2'/0'/1/5", 'diff path prefix'),
    ("44'/1'/1'/1/5", 'diff path prefix'),
    ("44'/1'/0'/3000/5", '2nd last component'),
    ("44'/1'/0'/3/5", '2nd last component'),
])
def test_change_troublesome(dev, start_sign, cap_story, try_path, expect):
    # NOTE: out#1 is change:
    # addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'
    # path = (m=4369050F)/44'/1'/0'/1/5
    # pubkey = 03c80814536f8e801859fc7c2e5129895b261153f519d4f3418ffb322884a7d7e1

    if dev.master_fingerprint != 0x4369050f:
        # file relies on XFP=0F056943 value
        raise pytest.skip('simulator only')

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    if 0:
        #from pycoin.tx.Tx import Tx
        #from pycoin.tx.TxOut import TxOut
        # tweak output addr to garbage
        t = Tx.parse(BytesIO(b4.txn))
        chg = t.txs_out[1]          # pycoin.tx.TxOut.TxOut
        b = bytearray(chg.script)
        b[-5] ^= 0x55
        chg.script = bytes(b)

        b4.txn = t.as_bin()

    pubkey = a2b_hex('03c80814536f8e801859fc7c2e5129895b261153f519d4f3418ffb322884a7d7e1')
    path = [int(p) if ("'" not in p) else 0x80000000+int(p[:-1]) 
                        for p in try_path.split('/')]
    bin_path = b4.outputs[1].bip32_paths[pubkey][0:4] \
                + b''.join(struct.pack('<I', i) for i in path)
    b4.outputs[1].bip32_paths[pubkey] = bin_path

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    open('debug/troublesome.psbt', 'wb').write(mod_psbt)

    start_sign(mod_psbt)
    time.sleep(0.1)
    title, story = cap_story()
    assert 'OK TO SEND' in title
    assert '(1 warning below)' in story, "no warning shown"

    assert expect in story, story

    assert parse_change_back(story) == (Decimal('1.09997082'), ['mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'])

def test_bip143_attack(try_sign, sim_exec, set_xfp, settings_set, settings_get):
    # cleanup prev runs
    sim_exec('import history; history.OutptValueCache.clear()')

    # hand-modified transactions from Andrew Chow
    set_xfp('D1A226A9')
    mod1 = b64decode(open('data/b143a_mod1.psbt').read())
    mod2 = b64decode(open('data/b143a_mod2.psbt').read())

    orig, result = try_sign(mod1, accept=False)

    # after seeing first one, should raise an error on second one
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(mod2, accept=False)

    assert 'but PSBT claims 15 XTN' in str(ee), ee

    assert len(settings_get('ovc')) == 2
    sim_exec('import history; history.OutptValueCache.clear()')

    # try in opposite order, should also trigger
    orig, result = try_sign(mod2, accept=False)
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(mod1, accept=False)

    assert 'but PSBT claims' in str(ee), ee
    assert 'Expected 15 but' in str(ee)

def spend_outputs(funding_psbt, finalized_txn, tweaker=None):
    # take details from PSBT that created a finalized txn (also provided)
    # and build a new PSBT that spends those change outputs.
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxOut import TxOut
    from pycoin.tx.TxIn import TxIn
    funding = Tx.from_bin(finalized_txn)
    b4 = BasicPSBT().parse(funding_psbt)

    # segwit change outputs only
    spendables = [(n,i) for n,i in enumerate(funding.tx_outs_as_spendable()) 
                        if i.script[0:2] == b'\x00\x14' and b4.outputs[n].bip32_paths]

    #spendables = list(reversed(spendables))
    random.shuffle(spendables)

    if tweaker:
        tweaker(spendables)

    nn = BasicPSBT()
    nn.inputs = [BasicPSBTInput(idx=i) for i in range(len(spendables))]
    nn.outputs = [BasicPSBTOutput(idx=0)]

    # copy input values from funding PSBT's output side
    for p_in, (f_out, sp) in zip(nn.inputs, [(b4.outputs[x], s) for x,s in spendables]):
        p_in.bip32_paths = f_out.bip32_paths
        p_in.witness_script = f_out.redeem_script
        with BytesIO() as fd:
            sp.stream(fd)
            p_in.witness_utxo = fd.getvalue()

    # build new txn: single output, no change, no miner fee
    act_scr = fake_dest_addr('p2wpkh')
    dest_out = TxOut(sum(s.coin_value for n,s in spendables), act_scr)

    txn = Tx(2, [s.tx_in() for _,s in spendables], [dest_out])

    # put unsigned TXN into PSBT
    with BytesIO() as b:
        txn.stream(b)
        nn.txn = b.getvalue()

    with BytesIO() as rv:
        nn.serialize(rv)
        raw = rv.getvalue()
    
    open('debug/spend_outs.psbt', 'wb').write(raw)

    return nn, raw

@pytest.fixture
def hist_count(sim_exec):
    def doit():
        return int(sim_exec(
            'import history; RV.write(str(len(history.OutptValueCache.runtime_cache)));'))
    return doit

@pytest.mark.parametrize('num_utxo', [9, 100])
@pytest.mark.parametrize('segwit_in', [False, True])
def test_bip143_attack_data_capture(num_utxo, segwit_in, try_sign, fake_txn, settings_set,
                                    settings_get, cap_story, sim_exec, hist_count):

    # cleanup prev runs, if very first time thru
    sim_exec('import history; history.OutptValueCache.clear()')
    hist_b4 = hist_count()
    assert hist_b4 == 0

    # make a txn, capture the outputs of that as inputs for another txn
    psbt = fake_txn(1, num_utxo+3, segwit_in=segwit_in, change_outputs=range(num_utxo+2),
                        outstyles=(['p2wpkh']*num_utxo) + ['p2wpkh-p2sh', 'p2pkh'])
    _, txn = try_sign(psbt, accept=True, finalize=True)

    open('debug/funding.psbt', 'wb').write(psbt)

    num_inp_utxo = (1 if segwit_in else 0)

    time.sleep(.1)
    title, story = cap_story()
    assert 'TXID' in title, story
    txid = story.strip().split()[0]

    assert hist_count() in {128, hist_b4+num_utxo+num_inp_utxo}

    # compare to PyCoin
    from pycoin.tx.Tx import Tx
    t = Tx.from_bin(txn)
    assert t.id() == txid

    # expect all of new "change outputs" to be recorded (none of the non-segwit change tho)
    # plus the one input we "revealed"
    after1 = settings_get('ovc')
    assert len(after1) == min(30, num_utxo + num_inp_utxo)

    all_utxo = hist_count()
    assert all_utxo == hist_b4+num_utxo+num_inp_utxo

    # build a new PSBT based on those change outputs
    psbt2, raw = spend_outputs(psbt, txn)

    # try to sign that ... should work fine
    try_sign(raw, accept=True, finalize=True)
    time.sleep(.1)

    # should not affect stored data, because those values already cached
    assert settings_get('ovc') == after1

    # any tweaks to input side's values should fail.
    for amt in [int(1E6), 1]:
        def value_tweak(spendables):
            assert len(spendables) > 2
            spendables[0][1].coin_value += amt

        psbt3, raw = spend_outputs(psbt, txn, tweaker=value_tweak)
        with pytest.raises(CCProtoError) as ee:
            orig, result = try_sign(raw, accept=True, finalize=True)

        assert 'but PSBT claims' in str(ee), ee


@pytest.mark.parametrize('segwit', [False, True])
@pytest.mark.parametrize('num_ins', [1, 17])
def test_txid_calc(num_ins, fake_txn, try_sign, dev, segwit, decode_with_bitcoind, cap_story):
    # verify correct txid for transactions is being calculated
    xp = dev.master_xpub

    psbt = fake_txn(num_ins, 1, xp, segwit_in=segwit)

    _, txn = try_sign(psbt, accept=True, finalize=True)

    #print('Signed; ' + B2A(txn))

    time.sleep(.1)
    title, story = cap_story()
    assert '0' in story
    assert 'TXID' in title, story
    txid = story.strip().split()[0]

    if 1:
        # compare to PyCoin
        from pycoin.tx.Tx import Tx
        t = Tx.from_bin(txn)
        assert t.id() == txid

    if 1:
        # compare to bitcoin core
        decoded = decode_with_bitcoind(txn)
        pprint(decoded)

        assert len(decoded['vin']) == num_ins
        if segwit:
            assert all(x['txinwitness'] for x in decoded['vin'])

        assert decoded['txid'] == txid

@pytest.mark.unfinalized            # iff partial=1
@pytest.mark.parametrize('encoding', ['binary', 'hex', 'base64'])
#@pytest.mark.parametrize('num_outs', [1,2,3,4,5,6,7,8])
@pytest.mark.parametrize('num_outs', [1,2])
@pytest.mark.parametrize('del_after', [1, 0])
@pytest.mark.parametrize('partial', [1, 0])
def test_sdcard_signing(encoding, num_outs, del_after, partial, try_sign_microsd, fake_txn, try_sign, dev, settings_set):
    # exercise the txn encode/decode from sdcard
    xp = dev.master_xpub

    settings_set('del', del_after)

    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    psbt = fake_txn(2, num_outs, xp, segwit_in=True, psbt_hacker=hack)

    _, txn, txid = try_sign_microsd(psbt, finalize=not partial,
                                        encoding=encoding, del_after=del_after)

@pytest.mark.unfinalized
@pytest.mark.parametrize('num_ins', [2,3,8])
@pytest.mark.parametrize('num_outs', [1,2,8])
def test_payjoin_signing(num_ins, num_outs, fake_txn, try_sign, start_sign, end_sign, cap_story):

    # Try to simulate a PSBT that might be involved in a Payjoin (BIP-78 txn)

    def hack(psbt):
        # change an input to be "not ours" ... but with utxo details
        psbt.inputs[num_ins-1].bip32_paths.clear()

    psbt = fake_txn(num_ins, num_outs, segwit_in=True, psbt_hacker=hack)

    open('debug/payjoin.psbt', 'wb').write(psbt)

    ip = start_sign(psbt, finalize=False)
    time.sleep(.1)
    _, story = cap_story()

    assert 'warning below' in story
    assert 'Limited Signing' in story
    assert 'because we do not know the key' in story
    assert ': %s' % (num_ins-1) in story

    txn = end_sign(True, finalize=False)

@pytest.mark.parametrize('segwit', [False, True])
def test_fully_unsigned(fake_txn, try_sign, segwit):

    # A PSBT which is unsigned but all inputs lack keypaths

    def hack(psbt):
        # change all inputs to be "not ours" ... but with utxo details
        for i in psbt.inputs:
            i.bip32_paths.clear()

    psbt = fake_txn(7, 2, segwit_in=segwit, psbt_hacker=hack)

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    assert 'does not contain any key path information' in str(ee)

@pytest.mark.parametrize('segwit', [False, True])
def test_wrong_xfp(fake_txn, try_sign, segwit):

    # A PSBT which is unsigned and doesn't involve our XFP value

    wrong_xfp = b'\x12\x34\x56\x78'

    def hack(psbt):
        # change all inputs to be "not ours" ... but with utxo details
        for i in psbt.inputs:
            for pubkey in i.bip32_paths:
                i.bip32_paths[pubkey] = wrong_xfp + i.bip32_paths[pubkey][4:]

    psbt = fake_txn(7, 2, segwit_in=segwit, psbt_hacker=hack)

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    assert 'None of the keys' in str(ee)
    assert 'found 12345678' in str(ee)

@pytest.mark.parametrize('segwit', [False, True])
def test_wrong_xfp_multi(fake_txn, try_sign, segwit):

    # A PSBT which is unsigned and doesn't involve our XFP value
    # - but multiple wrong XFP values

    wrongs = set()

    def hack(psbt):
        # change all inputs to be "not ours" ... but with utxo details
        for idx, i in enumerate(psbt.inputs):
            for pubkey in i.bip32_paths:
                here = struct.pack('<I', idx+73)
                i.bip32_paths[pubkey] = here + i.bip32_paths[pubkey][4:]
                wrongs.add(xfp2str(idx+73))

    psbt = fake_txn(7, 2, segwit_in=segwit, psbt_hacker=hack)

    open('debug/wrong-xfp.psbt', 'wb').write(psbt)
    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    if 'Signing failed late' in str(ee):
        pass
    else:
        assert 'None of the keys' in str(ee)
        # WEAK: device keeps them in order, but that's chance/impl defined...
        assert 'found '+', '.join(sorted(wrongs)) in str(ee)

@pytest.mark.parametrize('out_style', ADDR_STYLES_SINGLE)
@pytest.mark.parametrize('segwit', [False, True])
@pytest.mark.parametrize('outval', ['.5', '.788888', '0.92640866'])
def test_render_outs(out_style, segwit, outval, fake_txn, start_sign, end_sign, dev):
    # check how we render the value of outputs
    # - works on simulator and connected USB real-device
    xp = dev.master_xpub
    oi = int(Decimal(outval) * int(1E8))

    psbt = fake_txn(1, 2, dev.master_xpub, segwit_in=segwit, outvals=[oi, 1E8-oi],
                        outstyles=[out_style], change_outputs=[1])

    open('debug/render.psbt', 'wb').write(psbt)

    # should be able to sign, but get warning

    # use new feature to have Coldcard return the 'visualization' of transaction
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    story = end_sign(accept=None, expect_txn=False)

    story = story.decode('ascii')

    assert 'Network fee' in story
    assert '- to address -' in story

    # check rendered right
    lines = story.split('\n')
    amt = Decimal(lines[lines.index(' - to address -')-1].split(' ')[0])
    assert amt == Decimal(outval)

    val, addrs = parse_change_back(story)
    assert val  == (1-Decimal(outval))
    assert len(addrs) == 1

    if out_style == 'p2pkh':
        assert all((i[0] in 'mn1') for i in addrs)
    elif out_style == 'p2wpkh':
        pr = set(i[0:4] for i in addrs)
        assert len(pr) == 1
        assert pr.pop() in {'tb1q', 'bc1q'}
    elif out_style == 'p2wpkh-p2sh':
        assert len(set(i[0] for i in addrs)) == 1
        assert addrs[0][0] in {'2', '3'}


def test_negative_fee(dev, fake_txn, try_sign):
    # Silly to sign a psbt the network won't accept, but anyway...
    with pytest.raises(CCProtoError) as ee:
        psbt = fake_txn(1, 1, dev.master_xpub, outvals=[int(2E8)])
        orig, result = try_sign(psbt, accept=False)

    msg = ee.value.args[0]
    assert 'Outputs worth more than inputs' in msg

@pytest.mark.parametrize('units', [
    ( 8, 'XTN'), 
    ( 5, 'mXTN'), 
    ( 2, 'bits'), 
    ( 0, 'sats')])
def test_value_render(dev, units, fake_txn, start_sign, cap_story, settings_set, settings_remove):

    # Check we are rendering values in right units.
    decimal, units = units
    settings_set('rz', decimal)

    outputs = [int(i) for i in [
                    10E8, 3E8, 
                    1.2345678E8, 
                    1, 12, 123, 123456, 1234567, 12345678,
                    123456789012,
                ]]

    need = sum(outputs)
    psbt = fake_txn(1, len(outputs), dev.master_xpub, segwit_in=True, outvals=outputs, invals=[need])

    open('debug/values.psbt', 'wb').write(psbt)

    ip = start_sign(psbt, finalize=False)
    time.sleep(.1)
    _, story = cap_story()

    lines = story.split('\n')
    for v in outputs:
        div = int(10**decimal)
        #expect = '%d %s' % ((v//div), units)
        if decimal == 0:
            expect = '%d %s' % (v, units)
        else:
            expect = f'%d.%0{decimal}d %s' % ((v//div), (v % div), units)

        assert expect in lines

    settings_remove('rz')


@pytest.mark.qrcode
@pytest.mark.parametrize('num_in', [1,2,3])
@pytest.mark.parametrize('num_out', [1,2,3])
def test_qr_txn(num_in, num_out, request, fake_txn, try_sign, dev, cap_screen_qr, qr_quality_check, cap_story, need_keypress):
    segwit=True

    psbt = fake_txn(num_in, num_out, dev.master_xpub, segwit_in=False)


    _, txn = try_sign(psbt, accept=True, finalize=True)
    open('debug/last.txn', 'wb').write(txn)

    print("txn len = %d bytes" % len(txn))

    title, story = cap_story()

    assert 'QR Code' in story

    if 1:
        # check TXID qr code
        need_keypress('1')

        qr = cap_screen_qr().decode()

        from pycoin.tx.Tx import Tx
        t = Tx.from_bin(txn)
        assert t.id() == qr.lower()

    else:
        # TODO: QR for txn itself yet
        need_keypress('2')
        qr = cap_screen_qr().decode()
        assert qr.lower() == txn.hex()

def test_missing_keypaths(dev, try_sign, fake_txn):

    # make valid psbt
    psbt = fake_txn(3, 1, dev.master_xpub, segwit_in=False)

    # strip keypaths
    oo = BasicPSBT().parse(psbt)
    for inp in oo.inputs:
        inp.bip32_paths.clear()

    with BytesIO() as fd:
        oo.serialize(fd)
        mod_psbt = fd.getvalue()

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(mod_psbt, accept=False)

    msg = ee.value.args[0]
    assert ('does not contain any key path information' in msg)

def test_wrong_pubkey(dev, try_sign, fake_txn):
    # psbt input gives a pubkey+subkey path, but that pubkey doesn't map to utxo pubkey

    psbt = fake_txn(1, 1, dev.master_xpub, segwit_in=False)

    # tweak the pubkey of first input
    oo = BasicPSBT().parse(psbt)

    pubkey = list(oo.inputs[0].bip32_paths.keys())[0]
    xpk = bytearray(pubkey)

    for i in range(5, 20):
        xpk[i] = 0xff

    oo.inputs[0].bip32_paths[bytes(xpk)] = oo.inputs[0].bip32_paths[pubkey]
    del  oo.inputs[0].bip32_paths[pubkey]

    with BytesIO() as fd:
        oo.serialize(fd)
        mod_psbt = fd.getvalue()

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(mod_psbt, accept=False)

    msg = ee.value.args[0]
    assert ('pubkey vs. address wrong' in msg)

def test_incomplete_signing(dev, try_sign, fake_txn, cap_story):
    # psbt where we only sign one input
    # - must not allow finalization
    psbt = fake_txn(3, 1, dev.master_xpub, segwit_in=False)

    oo = BasicPSBT().parse(psbt)
    oo.inputs[1].bip32_paths = { k: b'\x01\x02\x03\x04'+v[4:] 
                                        for k,v in oo.inputs[1].bip32_paths.items() }
    with BytesIO() as fd:
        oo.serialize(fd)
        mod_psbt = fd.getvalue()

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(mod_psbt, accept=True, finalize=True)

    msg = ee.value.args[0]
    assert ('PSBT output failed' in msg)

    title, story = cap_story()
    assert 'No signature on input' in story

def test_zero_xfp(dev, start_sign, end_sign, fake_txn, cap_story):
    # will sign PSBT with zero values for XFP in ins and outs
    psbt = fake_txn(2, 3, dev.master_xpub, segwit_in=False, change_outputs=[1,2])

    oo = BasicPSBT().parse(psbt)
    for i in oo.inputs:
        i.bip32_paths = { k: b'\x00\x00\x00\x00'+v[4:] for k,v in i.bip32_paths.items() }
    for o in oo.outputs:
        o.bip32_paths = { k: b'\x00\x00\x00\x00'+v[4:] for k,v in o.bip32_paths.items() }

    with BytesIO() as fd:
        oo.serialize(fd)
        mod_psbt = fd.getvalue()

    # should work, with a warning
    start_sign(mod_psbt, finalize=True)
    time.sleep(.1)
    _, story = cap_story()

    assert '(1 warning below)' in story
    assert 'Zero XFP' in story

    # and then signing should work.
    signed = end_sign(True, finalize=True)


@pytest.mark.parametrize("segwit_in", [True, False])
@pytest.mark.parametrize('num_not_ours', [1, 3, 4])
def test_foreign_utxo_missing(segwit_in, num_not_ours, dev, fake_txn, start_sign, cap_story, end_sign):
    def hack(psbt):
        # change first input to not be ours
        for i in range(num_not_ours):
            pk = list(psbt.inputs[i].bip32_paths.keys())[0]
            pp = psbt.inputs[i].bip32_paths[pk]
            psbt.inputs[i].bip32_paths[pk] = b'what' + pp[4:]
            # no utxo provided for foreign inputs
            psbt.inputs[i].utxo = None
            psbt.inputs[i].witness_utxo = None

    psbt = fake_txn(5, 2, dev.master_xpub, segwit_in=segwit_in, psbt_hacker=hack)
    start_sign(psbt)
    time.sleep(.1)
    _, story = cap_story()
    no = ", ".join(str(i) for i in list(range(num_not_ours)))
    assert "warnings" in story
    assert f"Limited Signing: We are not signing these inputs, because we do not know the key: {no}" in story
    assert f"Unable to calculate fee: Some input(s) haven't provided UTXO(s): {no}" in story
    signed = end_sign(accept=True)
    assert signed != psbt

@pytest.mark.parametrize("segwit_in", [True, False])
@pytest.mark.parametrize("num_missing", [1, 3, 4])
def test_own_utxo_missing(segwit_in, num_missing, dev, fake_txn, start_sign, cap_story, end_sign, need_keypress):
    def hack(psbt):
        for i in range(num_missing):
            # no utxo provided for our input
            psbt.inputs[i].utxo = None
            psbt.inputs[i].witness_utxo = None

    psbt = fake_txn(5, 2, dev.master_xpub, segwit_in=segwit_in, psbt_hacker=hack)
    start_sign(psbt)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Missing own UTXO(s)" in story
    need_keypress("x")

@pytest.mark.bitcoind
def test_bitcoind_missing_foreign_utxo(bitcoind, bitcoind_d_sim_watch, microsd_path, try_sign):
    # batch tx created from three different psbts (using joinpsbts)
    # they all pay one destination address...
    # good thing is that if bitcoin core one day decides that they no longer support missing UTXO for foreign inputs
    # we will know about it
    dest_address = bitcoind.supply_wallet.getnewaddress()
    alice = bitcoind.create_wallet(wallet_name="alice")
    bob = bitcoind.create_wallet(wallet_name="bob")
    cc = bitcoind_d_sim_watch
    alice_addr = alice.getnewaddress()
    alice_pubkey = alice.getaddressinfo(alice_addr)["pubkey"]
    bob_addr = bob.getnewaddress()
    bob_pubkey = bob.getaddressinfo(bob_addr)["pubkey"]
    cc_addr = cc.getnewaddress()
    cc_pubkey = cc.getaddressinfo(cc_addr)["pubkey"]
    # fund all addresses
    for addr in (alice_addr, bob_addr, cc_addr):
        bitcoind.supply_wallet.generatetoaddress(101, addr)
    psbt_list = []
    for w in (alice, bob, cc):
        assert w.listunspent()
        psbt = w.walletcreatefundedpsbt([], [{dest_address: 1.0}], 0, {"fee_rate": 20})["psbt"]
        psbt_list.append(psbt)
    # join PSBTs to one
    the_psbt = bitcoind.supply_wallet.joinpsbts(psbt_list)
    the_psbt_obj = BasicPSBT().parse(the_psbt.encode())
    # remove utxos for bob and alice and let coldcard sign
    for inp in the_psbt_obj.inputs:
        for pk, _ in inp.bip32_paths.items():
            if pk.hex() == cc_pubkey:
                continue
            assert pk.hex() in (alice_pubkey, bob_pubkey)
            inp.utxo = None
            inp.witness_utxo = None

    psbt0 = the_psbt_obj.as_bytes()
    orig, res = try_sign(psbt0, accept=True)
    assert orig != res  # coldcard signs no problem - only our UTXO matters for signing
    # now alice and bob UTXOs are still missing but bitcoind does not care either
    # lets sign with bob first - bobs wallet will ignore missing alice UTXO but will supply his UTXO
    psbt1 = bob.walletprocesspsbt(base64.b64encode(res).decode(), True, "ALL")["psbt"]
    # finally sign with alice
    res = alice.walletprocesspsbt(psbt1, True, "ALL")
    psbt2 = res["psbt"]
    assert res["complete"] is True
    tx = alice.finalizepsbt(psbt2)["hex"]
    assert alice.testmempoolaccept([tx])[0]["allowed"] is True
    tx_id = alice.sendrawtransaction(tx)
    assert isinstance(tx_id, str) and len(tx_id) == 64

@pytest.mark.bitcoind
@pytest.mark.parametrize("op_return_data", [
    b"Coldcard is the best signing device",  # to test with both pushdata opcodes
    b"Coldcard, the best signing deviceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # len 80 max
    b"\x80" * 80,
    "££££££££££".encode("utf-8"),
    bytes.fromhex("aa21a9ed68512d3c6b0514b18fbc9f0c540d5bec8f4ae62da4bf6c9b16f90b655f9f4210"),
    b"$$$$$$$$$$$$$$ Bitcoin",
    b"\xeb\x97\xf7\xb7\xf78\x9a';\x90F_\xfc\xe2b\xa4\x93)\xea\xac\xacR\xff\x9c\xbe\x1c\xf1\xad\xe9!\xee\xd9t1\x1f\x92\x83\x97\xb3\x98/\xff\xc8\xff\xc1\xc0\xdd\x1et\x00L\x13\xe0\xe3\x90\xe4\xd4\xf2x:\xf7Ab\x04\x91\x1e\xa8R\x92\xd3\x96OK\xc6I\x06\x9e\xce=\xb3",
])
def test_op_return_signing(op_return_data, dev, fake_txn, bitcoind_d_sim_watch, bitcoind, start_sign, end_sign, cap_story):
    cc = bitcoind_d_sim_watch
    dest_address = cc.getnewaddress()
    bitcoind.supply_wallet.generatetoaddress(101, dest_address)
    psbt = cc.walletcreatefundedpsbt([], [{dest_address: 1.0}, {"data": op_return_data.hex()}], 0, {"fee_rate": 20})["psbt"]
    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    # in older implementations, one would see a warning for OP_RETURN --> not now
    assert "warning" not in story
    assert "OP_RETURN" in story
    try:
        expect = op_return_data.decode("ascii")
    except:
        expect = binascii.hexlify(op_return_data).decode()
    assert expect in story
    signed = end_sign(accept=True)
    tx = cc.finalizepsbt(base64.b64encode(signed).decode())["hex"]
    assert cc.testmempoolaccept([tx])[0]["allowed"] is True
    tx_id = cc.sendrawtransaction(tx)
    assert isinstance(tx_id, str) and len(tx_id) == 64

@pytest.mark.parametrize("unknowns", [
    # tuples (unknown_global, unknown_ins, unknown_outs)
    ({b"x" * 16: b"y" * 16}, {b"q": b"p"}, {b"w" * 5: b"z" * 22}),
    ({b"x": b"y", b"cccccc": b"oooooooooooooooooooooooooo", b"a": b"a"}, {b"q" * 2: b"p" * 16}, {b"w" * 64: b"z"}),
    ({b"x" * 64: b"y"}, {b"q" * 45: b"p"}, {b"w": b"z" * 64}),
    ({b"x": b"y" * 64}, {b"q": b"p" * 64}, {b"w" * 16: b"z" * 64}),
    ({b"x" * 64: b"y" * 64}, {b"q" * 71: b"p" * 22}, {b"w" * 71: b"z" * 128, b"keyp": 32 * b"\x00"}),
    ({b"x" * 64: b"y" * 128}, {b"q" * 64: b"p" * 128}, {b"w" * 90: b"z" * 256}),
    ({b"x" * 32: b"y" * 256}, {b"q" * 32: b"p" * 256, b"f" * 15: 32 * b"\x01"}, {b"w": b"z"}),
])
def test_unknow_values_in_psbt(unknowns, dev, start_sign, end_sign, fake_txn):
    unknown_global, unknown_ins, unknown_outs = unknowns
    def hack(psbt):
        psbt.unknown = unknown_global
        for i in psbt.inputs:
            i.unknown = unknown_ins
        for o in psbt.outputs:
            o.unknown = unknown_outs

    psbt = fake_txn(5, 5, dev.master_xpub, segwit_in=True, psbt_hacker=hack)
    open('debug/last.psbt', 'wb').write(psbt)
    psbt_o = BasicPSBT().parse(psbt)
    assert psbt_o.unknown == unknown_global
    for inp in psbt_o.inputs:
        assert inp.unknown == unknown_ins
    for out in psbt_o.outputs:
        assert out.unknown == unknown_outs
    start_sign(psbt)
    signed = end_sign()
    assert signed != psbt
    res = BasicPSBT().parse(signed)
    assert res.unknown == unknown_global
    for inp in res.inputs:
        assert inp.unknown == unknown_ins
    for out in res.outputs:
        assert out.unknown == unknown_outs

def test_read_write_prop_attestation_keys(try_sign, fake_txn):
    from psbt import ser_prop_key, PSBT_PROP_CK_ID
    def attach_attest_to_outs(psbt):
        for idx, o in enumerate(psbt.outputs):
            key = ser_prop_key(PSBT_PROP_CK_ID, 0)
            value = b"fake attestation"
            o.proprietary[key] = value

    psbt = fake_txn(2, 2, psbt_hacker=attach_attest_to_outs)
    open('debug/propkeys.psbt', 'wb').write(psbt)
    orig, signed = try_sign(psbt)
    res = BasicPSBT().parse(signed)

    for o in res.outputs:
        assert len(o.proprietary) == 1
        for key, val in o.proprietary.items():
            assert key == b'\x08COINKITE\x00' # generated using external lib just to be safe
            assert val == b"fake attestation"

def test_duplicate_unknow_values_in_psbt(dev, start_sign, end_sign, fake_txn):
    # duplicate keys for global unknowns
    def hack(psbt):
        psbt.unknown = [(b"xxx", 32 * b"\x00"), (b"xxx", 32 * b"\x01")]
    psbt = fake_txn(5, 5, dev.master_xpub, segwit_in=True, psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()

    # duplicate keys for input unknowns
    def hack(psbt):
        for i in psbt.inputs:
            i.unknown = [(b"xxx", 32 * b"\x00"), (b"xxx", 32 * b"\x01")]
    psbt = fake_txn(5, 5, dev.master_xpub, segwit_in=True, psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()

    # duplicate keys for output unknown
    def hack(psbt):
        for o in psbt.outputs:
            o.unknown = [(b"xxx", 32 * b"\x00"), (b"xxx", 32 * b"\x01")]
    psbt = fake_txn(5, 5, dev.master_xpub, segwit_in=True, psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()


@pytest.fixture
def _test_single_sig_sighash(microsd_wipe, microsd_path, goto_home, cap_story, need_keypress,
                             bitcoind, bitcoind_d_sim_watch, settings_set, finalize_v2_v0_convert):
    def doit(addr_fmt, sighash, num_inputs=2, num_outputs=2, consolidation=False, sh_checks=False,
             psbt_v2=False):
        from decimal import Decimal, ROUND_DOWN

        settings_set("sighshchk", int(not sh_checks))
        microsd_wipe()
        time.sleep(0.1)
        goto_home()

        not_all_ALL = any(sh != "ALL" for sh in sighash)

        bitcoind_d_sim_watch.keypoolrefill(num_inputs + num_outputs)
        input_val = bitcoind.supply_wallet.getbalance() / num_inputs
        cc_dest = [
            {bitcoind_d_sim_watch.getnewaddress("", addr_fmt): Decimal(input_val).quantize(Decimal('.0000001'), rounding=ROUND_DOWN)}
            for _ in range(num_inputs)
        ]
        psbt = bitcoind.supply_wallet.walletcreatefundedpsbt(
            [], cc_dest, 0, {"fee_rate": 20, "subtractFeeFromOutputs": [0]}
        )["psbt"]
        psbt = bitcoind.supply_wallet.walletprocesspsbt(psbt, True, "ALL")["psbt"]
        resp = bitcoind.supply_wallet.finalizepsbt(psbt)
        assert resp["complete"] is True
        assert len(bitcoind.supply_wallet.sendrawtransaction(resp["hex"])) == 64
        # mine above txs
        bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
        unspent = bitcoind_d_sim_watch.listunspent()
        output_val = bitcoind_d_sim_watch.getbalance() / num_outputs
        # consolidation or not?
        dest_wal = bitcoind_d_sim_watch if consolidation else bitcoind.supply_wallet
        destinations = [
            {dest_wal.getnewaddress("", addr_fmt): Decimal(output_val).quantize(Decimal('.0000001'), rounding=ROUND_DOWN)}
            for _ in range(num_outputs)
        ]
        assert len(unspent) >= num_inputs
        psbt = bitcoind_d_sim_watch.walletcreatefundedpsbt(
            unspent[:num_inputs], destinations, 0,
            {"fee_rate": 20, "subtractFeeFromOutputs": list(range(num_outputs))}
        )["psbt"]
        x = BasicPSBT().parse(base64.b64decode(psbt))
        assert len(x.inputs) == num_inputs
        assert len(x.outputs) == num_outputs
        for idx, i in enumerate(x.inputs):
            if len(sighash) == 1:
                i.sighash = SIGHASH_MAP.get(sighash[0], sighash[0])
            else:
                i.sighash = SIGHASH_MAP.get(sighash[idx], sighash[idx])

        if psbt_v2:
            # below is noop is psbt is already v2
            psbt_sh = base64.b64encode(x.to_v2()).decode()
        else:
            psbt_sh = x.as_b64_str()

        # make useful reference psbt along the way
        open(f'debug/sighash-{sighash[0] if len(sighash) == 1 else "MIX"}.psbt'\
                .replace('|', '-'), 'wt').write(psbt_sh)

        with open(microsd_path("sighash.psbt"), "w") as f:
            f.write(psbt_sh)
        need_keypress("y")
        time.sleep(0.2)
        title, story = cap_story()

        if sh_checks is True:
            # checks enabled
            if consolidation and not_all_ALL:
                assert title == "Failure"
                assert "Only sighash ALL is allowed for pure consolidation transaction" in story
                return

            elif not consolidation and any("NONE" in sh for sh in sighash if isinstance(sh, str)):
                assert title == "Failure"
                assert "Sighash NONE is not allowed as funds could be going anywhere" in story
                return

        assert title == "OK TO SEND?"
        if any("NONE" in sh for sh in sighash):
            assert "(1 warning below)" in story
            assert "---WARNING---" in story
            assert "Danger" in story
            assert "Destination address can be changed after signing (sighash NONE)." in story
        elif any(sh != "ALL" for sh in sighash):
            assert "(1 warning below)" in story
            assert "---WARNING---" in story
            assert "Caution" in story
            assert "Some inputs have unusual SIGHASH values not used in typical cases." in story

        need_keypress("y")
        time.sleep(0.5)
        title, story = cap_story()
        time.sleep(0.1)
        need_keypress("y")  # confirm success or failure
        # now not just legacy but also segwit prohibits SINGLE out of bounds
        # consensus allows it but it really is just bad usage - restricted
        if (num_outputs < num_inputs) and any("SINGLE" in sh for sh in sighash):
            assert "SINGLE corresponding output" in story
            assert "missing" in story
            return

        split_story = story.split("\n\n")
        signed_fname = split_story[1]
        txn_fname = split_story[3]
        tx_id = split_story[4].split("\n")[-1]

        with open(microsd_path(signed_fname), "r") as f:
            cc_psbt = f.read().strip()
        with open(microsd_path(txn_fname), "r") as f:
            cc_tx_hex = f.read().strip()

        y = BasicPSBT().parse(base64.b64decode(cc_psbt))

        for idx, i in enumerate(y.inputs):
            if len(sighash) == 1:
                assert i.sighash == SIGHASH_MAP[sighash[0]]
            else:
                assert i.sighash == SIGHASH_MAP[sighash[idx]]
            # check signature hash correct checkusm appended
            for _, sig in i.part_sigs.items():
                assert sig[-1] == i.sighash

        resp = finalize_v2_v0_convert(y)

        assert resp["complete"] is True
        tx_hex = resp["hex"]
        assert tx_hex == cc_tx_hex

        if psbt_v2:
            # check txn_modifiable properly set
            po = BasicPSBT().parse(base64.b64decode(cc_psbt))
            mod = po.txn_modifiable
            used_sh = [SIGHASH_MAP[sh] for sh in sighash]
            if all(sh > 128 for sh in used_sh):
                # all sighash flags are ANYONECANPAY
                assert mod & 1  # allow inputs modification
            else:
                assert mod & 1 == 0  # inputs modification not allowed

            if all(sh in (2, 130) for sh in used_sh):
                # all sighash flags are NONE
                assert mod & 2  # allow outputs modification
            else:
                assert mod & 2 == 0

            if any(sh in (3, 131) for sh in used_sh):
                # some sighash flag/s are SINGLE
                assert mod & 4  # allow outputs modification
            else:
                assert mod & 4 == 0

        # for PSBTv2 here we check if we correctly finalize
        res = bitcoind.supply_wallet.testmempoolaccept([cc_tx_hex])
        assert res[0]["allowed"]
        txn_id = bitcoind.supply_wallet.sendrawtransaction(cc_tx_hex)
        assert tx_id == txn_id

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.parametrize("sighash", [sh for sh in SIGHASH_MAP if sh != 'ALL'])
@pytest.mark.parametrize("num_outs", [1, 3, 5])
@pytest.mark.parametrize("num_ins", [2, 5])
@pytest.mark.parametrize("psbt_v2", [True, False])
def test_sighash_same(addr_fmt, sighash, num_ins, num_outs, psbt_v2, _test_single_sig_sighash):
    # sighash is the same among all inputs
    _test_single_sig_sighash(addr_fmt, [sighash], num_inputs=num_ins, num_outputs=num_outs,
                             psbt_v2=psbt_v2)


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.parametrize("sighash", list(itertools.combinations(SIGHASH_MAP.keys(), 2)))
@pytest.mark.parametrize("num_outs", [2, 3, 5])
@pytest.mark.parametrize("psbt_v2", [True, False])
def test_sighash_different(addr_fmt, sighash, num_outs, psbt_v2, _test_single_sig_sighash):
    # sighash differ among all inputs
    _test_single_sig_sighash(addr_fmt, sighash, num_inputs=2, num_outputs=num_outs,
                             psbt_v2=psbt_v2)


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.parametrize("num_outs", [5, 8])
@pytest.mark.parametrize("psbt_v2", [True, False])
def test_sighash_fullmix(addr_fmt, num_outs, psbt_v2, _test_single_sig_sighash):
    # tx with 6 inputs representing all possible sighashes
    _test_single_sig_sighash(addr_fmt, tuple(SIGHASH_MAP.keys()), num_inputs=6,
                             num_outputs=num_outs, psbt_v2=psbt_v2)


@pytest.mark.bitcoind
@pytest.mark.parametrize("sighash", [sh for sh in SIGHASH_MAP if sh != 'ALL'])
def test_sighash_disallowed_consolidation(sighash, _test_single_sig_sighash):
    # sighash != ALL blocked for pure consolidations
    _test_single_sig_sighash("bech32", [sighash], num_inputs=2, num_outputs=2,
                             sh_checks=True, consolidation=True)


@pytest.mark.bitcoind
@pytest.mark.parametrize("sighash", ["NONE", "NONE|ANYONECANPAY"])
def test_sighash_disallowed_NONE(sighash, _test_single_sig_sighash):
    # sighash is the same among all inputs
    _test_single_sig_sighash("bech32", [sighash], num_inputs=2, num_outputs=2,
                             consolidation=False, sh_checks=True)


@pytest.mark.bitcoind
def test_sighash_nonexistent(_test_single_sig_sighash):
    # invalid sighash value
    with pytest.raises(AssertionError) as exc:
        _test_single_sig_sighash("legacy", [0xe2], num_inputs=2, num_outputs=2,
                                 consolidation=True, sh_checks=False)
    assert "'Failure' == 'OK TO SEND?'" in exc.value.args[0]


def test_no_outputs_tx(fake_txn, microsd_path, goto_home, need_keypress, pick_menu_item, cap_story):
    goto_home()
    psbt = fake_txn(3, 0)  # no outputs
    fname = "zero_outputs.psbt"
    fpath = microsd_path(fname)

    with open(fpath, "wb") as f:
        f.write(psbt)

    pick_menu_item("Ready To Sign")
    time.sleep(0.1)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()

    assert title == "Failure"
    assert "Invalid PSBT" in story
    assert "need outputs" in story

    try: os.remove(fpath)
    except: pass


def test_send2taproot_addresss(fake_txn , start_sign, end_sign, cap_story):
    psbt = fake_txn(2, 2, segwit_in=True, change_outputs=[0], outstyles=["p2tr"])
    start_sign(psbt)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    # we do not understand change in taproot (taproot not supported)
    assert "Consolidating" not in story
    assert "Change back" not in story
    # but we should show address
    assert "to script" not in story
    assert "tb1p" in story
    signed = end_sign(accept=True, finalize=False)
    assert signed


@pytest.mark.parametrize("num_tx", [1, 2, 10])
@pytest.mark.parametrize("ui_path", [True, False])
@pytest.mark.parametrize("action", ["sign", "skip", "refuse"])
def test_batch_sign(num_tx, ui_path, action, fake_txn, need_keypress,
                    pick_menu_item, cap_story, microsd_path,
                    microsd_wipe, goto_home):

    goto_home()
    microsd_wipe()

    for i in range(num_tx):
        psbt = fake_txn(2, 2, segwit_in=random.getrandbits(1))
        with open(microsd_path(f"{i}.psbt"), "wb") as f:
            f.write(psbt)

    if ui_path:
        pick_menu_item("Advanced/Tools")
        pick_menu_item("File Management")
        pick_menu_item("Batch Sign PSBT")
    else:
        # shortcut via Ready To Sign
        pick_menu_item("Ready To Sign")
        time.sleep(.1)
        if num_tx == 1:
            need_keypress("x")
            pytest.skip("classic sign")

        _, story = cap_story()
        assert "Press (9) to select all files for potential signing" in story
        need_keypress("9")

    time.sleep(.1)
    title, story = cap_story()
    if "Press (1)" in story:
        need_keypress("1")
        time.sleep(.1)
        title, story = cap_story()

    for i in range(num_tx):
        assert "Sign" in story
        assert "(1) to skip" in story
        assert "X to quit and exit" in story
        if action == "skip":
            need_keypress("1")  # skip this PSBT
            time.sleep(.5)
            title, story = cap_story()
            continue

        need_keypress("y")  # sign this PSBT
        time.sleep(.5)
        title, story = cap_story()
        assert title == "OK TO SEND?"
        if action == "refuse":
            need_keypress("x")  # refuse
            time.sleep(.5)
            title, story = cap_story()
            continue

        need_keypress("y")  # confirm send
        time.sleep(.5)
        title, story = cap_story()
        assert "-signed.psbt" in story
        need_keypress("y")
        time.sleep(.5)
        title, story = cap_story()


@pytest.mark.parametrize("desc_psbt_hex", [
    ("PSBTv0 but with PSBT_GLOBAL_VERSION set to 2.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_GLOBAL_TX_VERSION.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001020402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_GLOBAL_FALLBACK_LOCKTIME.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001030402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_GLOBAL_INPUT_COUNT.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001040102000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_GLOBAL_OUTPUT_COUNT.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001050102000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_GLOBAL_TX_MODIFIABLE.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001060100000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_IN_PREVIOUS_TXID.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc800220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_IN_OUTPUT_INDEX.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_IN_SEQUENCE.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27011004ffffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_IN_REQUIRED_TIME_LOCKTIME.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a270111048c8dc46200220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a270112041027000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_OUT_AMOUNT.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f00000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv0 but with PSBT_OUT_SCRIPT.", "70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000104160014a07dac8ab6ca942d379ed795f835ba71c9cc6885002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000"),
    ("PSBTv2 missing PSBT_GLOBAL_INPUT_COUNT.", "70736274ff01020402000000010304000000000105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 missing PSBT_GLOBAL_OUTPUT_COUNT.", "70736274ff01020402000000010304000000000104010101fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 missing PSBT_IN_PREVIOUS_TXID.", "70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 missing PSBT_IN_OUTPUT_INDEX.", "70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 missing PSBT_OUT_AMOUNT.", "70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 missing PSBT_OUT_SCRIPT.", "70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f0000000000220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 with PSBT_IN_REQUIRED_TIME_LOCKTIME less than 500000000.", "70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011104ff64cd1d00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
    ("PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME greater than or equal to 500000000.", "70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f04000000000112040065cd1d00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300"),
])
def test_v2_psbt_bip370_invalid(desc_psbt_hex, start_sign, cap_story):
    desc, psbt_hex = desc_psbt_hex
    psbt = bytes.fromhex(psbt_hex)
    print(desc)
    start_sign(psbt)
    title, story = cap_story()
    assert title == "Failure"
    assert ".py:" in story  # problem file line


@pytest.mark.bitcoind
@pytest.mark.parametrize("outstyle", ADDR_STYLES_SINGLE)
@pytest.mark.parametrize("segwit_in", [True, False])
@pytest.mark.parametrize("wrapped_segwit_in", [True, False])
def test_psbt_v2(outstyle, segwit_in, wrapped_segwit_in, fake_txn , start_sign, end_sign, cap_story,
                 microsd_path, bitcoind, finalize_v2_v0_convert):
    psbt = fake_txn(2, 2, segwit_in=segwit_in, wrapped=wrapped_segwit_in, change_outputs=[0],
                    outstyles=[outstyle], psbt_v2=True)

    start_sign(psbt)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    # we do not understand change in taproot (taproot not supported)
    assert "Consolidating" not in story
    assert "Change back" in story
    # but we should show address
    assert "to script" not in story
    signed = end_sign(accept=True, finalize=False)
    assert signed
    po = BasicPSBT().parse(signed)
    assert po.version == 2
    assert po.txn_version == 2
    assert po.input_count is not None
    assert po.output_count is not None
    for inp in po.inputs:
        assert inp.previous_txid
        assert inp.prevout_idx is not None
    for out in po.outputs:
        assert out.amount
        assert out.script

    resp = finalize_v2_v0_convert(po)

    assert resp["complete"] is True


@pytest.mark.bitcoind
@pytest.mark.parametrize("way", ["i+", "i-", "o+", "o-"])
def test_psbt_v2_global_quantities(way, fake_txn, start_sign, end_sign, cap_story,
                                   microsd_path, bitcoind, finalize_v2_v0_convert):

    def hacker(psbt, way):
        actual_len_i = len(psbt.inputs)
        actual_len_o = len(psbt.outputs)
        if way == "i-":
            psbt.input_count = actual_len_i - 1
        elif way == "i+":
            psbt.input_count = actual_len_i - 1
        elif way == "o-":
            psbt.output_count = actual_len_o - 1
        elif way == "o+":
            psbt.output_count = actual_len_o + 1


    psbt = fake_txn(2, 2, segwit_in=True, wrapped=True, change_outputs=[0],
                    outstyles=["p2pkh", "p2wpkh"], psbt_v2=True,
                    psbt_hacker=lambda psbt: hacker(psbt, way))

    with open(f"/home/scg/PycharmProjects/afirmware/unix/work/MicroSD/{way}.psbt", "wb") as f:
        f.write(psbt)

    start_sign(psbt)
    title, story = cap_story()
    assert "failed" in story or "Invalid PSBT" in story or "Network fee bigger" in story

# EOF
