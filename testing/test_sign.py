# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Transaction Signing. Important.
#

import time, pytest, os, random, pdb, struct, base64, binascii, itertools, datetime
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError
from binascii import b2a_hex, a2b_hex
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from io import BytesIO
from pprint import pprint
from decimal import Decimal
from base64 import b64encode, b64decode
from base58 import encode_base58_checksum
from helpers import B2A, fake_dest_addr, parse_change_back, addr_from_display_format
from helpers import xfp2str, seconds2human_readable, hash160
from msg import verify_message
from bip32 import BIP32Node
from constants import ADDR_STYLES, ADDR_STYLES_SINGLE, SIGHASH_MAP, simulator_fixed_xfp
from txn import *
from ctransaction import CTransaction, CTxOut, CTxIn, COutPoint
from ckcc_protocol.constants import STXN_VISUALIZE, STXN_SIGNED
from charcodes import KEY_QR, KEY_RIGHT


SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)


@pytest.mark.parametrize('finalize', [ False, True ])
def test_sign1(dev, finalize):
    in_psbt = a2b_hex(open('data/p2pkh-in-scriptsig.psbt', 'rb').read())

    ll, sha = dev.upload_file(in_psbt)

    dev.send_recv(CCProtocolPacker.sign_transaction(ll, sha, finalize))

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
def test_psbt_proxy_parsing(fn, sim_execfile, sim_exec, src_root_dir, sim_root_dir):
    # unit test: parsing by the psbt proxy object

    sim_exec('import main; main.FILENAME = %r; ' % (f'{src_root_dir}/testing/'+fn))
    rv = sim_execfile('devtest/unit_psbt.py')
    assert not rv, rv

    rb = f'{sim_root_dir}/readback.psbt'

    oo = BasicPSBT().parse(open(fn, 'rb').read())
    rb = BasicPSBT().parse(open(rb, 'rb').read())
    assert oo == rb

@pytest.mark.unfinalized
@pytest.mark.parametrize("addr_fmt", ["p2tr", "p2wpkh"])
def test_speed_test(dev, addr_fmt, fake_txn, is_mark3, is_mark4, start_sign, end_sign,
                    press_select, press_cancel, sim_root_dir):
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

    psbt = fake_txn(num_in, num_out, dev.master_xpub, addr_fmt=addr_fmt)

    with open(f'{sim_root_dir}/debug/speed.psbt', 'wb') as f:
        f.write(psbt)

    dt = time.time()
    start_sign(psbt, finalize=False)

    tx_time = time.time() - dt

    press_select(timeout=None)

    dt = time.time()
    done = None
    while done == None:
        time.sleep(0.05)
        done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

    ready_time = time.time() - dt

    print("  Tx time: %.1f" % tx_time)
    print("Sign time: %.1f" % ready_time)
    press_cancel()

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
@pytest.mark.parametrize('addr_fmt', ["p2wpkh", "p2tr", "p2pkh"])
def test_io_size(request, use_regtest, decode_with_bitcoind, fake_txn,
                 start_sign, end_sign, dev, addr_fmt, sim_root_dir):

    # try a bunch of different bigger sized txns
    # - important to test on real device, due to it's limited memory
    # - cmdline: "pytest test_sign.py -k test_io_size --dev --manual -s --durations=50"
    # - simulator can do 400/400 but takes long time
    # - offical target: 20 inputs, 250 outputs (see docs/limitations.md)
    # - Mk4: complete run on real hardware takes 1800.94 seconds = 30 minutes
    # - Historical: time on Mk3, v4.0.0 firmware: 13 minutes for ins/outs=20/250

    # for this test you need to configure core `repcservertimeout` to something big
    # in bitcoin.conf `rpcservertimeout=2000` should do the trick
    use_regtest()

    num_in = 250
    num_out = 2000

    psbt = fake_txn(num_in, num_out, dev.master_xpub, addr_fmt=addr_fmt)

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    start_sign(psbt, finalize=True)

    # on simulator, read screen
    try:
        cap_story = request.getfixturevalue('cap_story')
        time.sleep(.1)
        title, story = cap_story()
        assert 'OK TO SEND' in title
    except:
        cap_story = None

    signed = end_sign(True, finalize=True)

    with open(f'{sim_root_dir}/debug/signed.txn', 'wb') as f:
        f.write(signed)

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
def test_real_signing(fake_txn, use_regtest, try_sign, dev, num_ins,
                      decode_with_bitcoind, sim_root_dir):
    # create a TXN using actual addresses that are correct for DUT
    xp = dev.master_xpub

    inputs = [["p2tr"] if i % 2 == 0 else ["p2wpkh"] for i in range(num_ins)]

    psbt = fake_txn(inputs, 1, xp)
    with open(f'{sim_root_dir}/debug/real-%d.psbt' % num_ins, 'wb') as f:
        f.write(psbt)

    _, txn = try_sign(psbt, accept=True, finalize=True)

    #print('Signed; ' + B2A(txn))

    decoded = decode_with_bitcoind(txn)

    #pprint(decoded)

    assert len(decoded['vin']) == num_ins
    assert all(x['txinwitness'] for x in decoded['vin'])


@pytest.mark.unfinalized        # iff we_finalize=F
@pytest.mark.parametrize('we_finalize', [ False, True ])
@pytest.mark.parametrize('num_dests', [ 1, 10, 25 ])
@pytest.mark.bitcoind
def test_vs_bitcoind(match_key, use_regtest, check_against_bitcoind, bitcoind,
                     start_sign, end_sign, we_finalize, num_dests, sim_root_dir):

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

    with open(f'{sim_root_dir}/debug/vs.psbt', 'wb') as f:
        f.write(psbt)

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
    with open(f'{sim_root_dir}/debug/vs-signed.psbt', 'wb') as f:
        f.write(signed)

    if not we_finalize:
        b4 = BasicPSBT().parse(psbt)
        aft = BasicPSBT().parse(signed)
        assert b4 != aft, "signing didn't change anything?"

        with open(f'{sim_root_dir}/debug/signed.psbt', 'wb') as f:
            f.write(signed)

        resp = bitcoind.supply_wallet.finalizepsbt(str(b64encode(signed), 'ascii'), True)

        #combined_psbt = b64decode(resp['psbt'])
        #open('debug/combined.psbt', 'wb').write(combined_psbt)

        assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

        network = a2b_hex(resp['hex'])

        # assert resp['complete']
        print("Final txn: %r" % network)
        with open(f'{sim_root_dir}/debug/finalized-by-btcd.txn', 'wb') as f:
            f.write(network)

        # try to send it
        txed = bitcoind.supply_wallet.sendrawtransaction(B2A(network))
        print("Final txn hash: %r" % txed)

    else:
        assert signed[0:4] != b'psbt', "expecting raw bitcoin txn"
        #print("Final txn: %s" % B2A(signed))
        with open(f'{sim_root_dir}/debug/finalized-by-cc.txn', 'wb') as f:
            f.write(signed)

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
def test_sign_p2sh_p2wpkh(match_key, use_regtest, start_sign, end_sign, bitcoind, sim_root_dir):
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
    with open(f'{sim_root_dir}/debug/p2sh-signed.psbt', 'wb') as f:
        f.write(signed)

    #print('my finalization: ' + B2A(signed))

    start_sign(psbt, finalize=False)
    signed_psbt = end_sign(accept=True)

    # use bitcoind to combine
    with open(f'{sim_root_dir}/debug/signed.psbt', 'wb') as f:
        f.write(signed_psbt)

    resp = bitcoind.rpc.finalizepsbt(str(b64encode(signed_psbt), 'ascii'), True)

    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"
    network = a2b_hex(resp['hex'])

    #print('his finalization: ' + B2A(network))

    assert network == signed

@pytest.mark.bitcoind
@pytest.mark.unfinalized
def test_sign_p2sh_example(set_master_key, use_regtest, sim_execfile, start_sign, end_sign,
                           decode_psbt_with_bitcoind, offer_minsc_import, press_select, clear_miniscript,
                           sim_root_dir):
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

    clear_miniscript()
    offer_minsc_import(config)
    time.sleep(.1)
    press_select()

    psbt = a2b_hex(open('data/worked-unsigned.psbt', 'rb').read())

    # PROBLEM: revised BIP-174 has p2sh multisig cases which we don't support yet.
    # - it has two signatures from same key on same input
    # - that's a rare case and not worth supporting in the firmware
    # - but we can do it in two passes
    # - the MS wallet is also hard, since dup xfp (same actual key) ... altho can
    #   provide different subkeys

    start_sign(psbt)
    part_signed = end_sign(True)

    with open(f'{sim_root_dir}/debug/ex-signed-part.psbt', 'wb') as f:
        f.write(part_signed)

    b4 = BasicPSBT().parse(psbt)
    aft = BasicPSBT().parse(part_signed)
    assert b4 != aft, "(partial) signing didn't change anything?"

    # NOTE: cannot handle combining multisig txn yet, so cannot finalize on-device
    start_sign(part_signed, finalize=False)
    signed = end_sign(True, finalize=False)

    with open(f'{sim_root_dir}/debug/ex-signed.psbt', 'wb') as f:
        f.write(signed)

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
def test_change_case(start_sign, use_regtest, end_sign, check_against_bitcoind, cap_story,
                     sim_root_dir):
    # is change shown/hidden at right times. no fraud checks 

    # NOTE: out#1 is change:
    chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()

    start_sign(psbt)

    time.sleep(.1)
    _, story = cap_story()
    split_sory = story.split("\n\n")[3].split("\n")
    assert split_sory[0] == "Change back:"
    assert chg_addr == addr_from_display_format(split_sory[-1])

    b4 = BasicPSBT().parse(psbt)
    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[1,])

    signed = end_sign(True)
    with open(f'{sim_root_dir}/debug/chg-signed.psbt', 'wb') as f:
        f.write(signed)

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
    with open(f'{sim_root_dir}/debug/chg-signed2.psbt', 'wb') as f:
        f.write(signed)

    aft = BasicPSBT().parse(signed)
    aft2 = BasicPSBT().parse(signed2)
    assert aft.txn == aft2.txn

@pytest.mark.parametrize('case', [ 1, 2])
@pytest.mark.bitcoind
def test_change_fraud_path(start_sign, use_regtest, end_sign, case, check_against_bitcoind,
                           cap_story, sim_root_dir):
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

    with open(f'{sim_root_dir}/debug/mod-%d.psbt' % case, 'wb') as f:
        f.write(mod_psbt)

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
        assert chg_addr == addr_from_display_format(story.split("\n\n")[3].split("\n")[-1])
        assert 'Change back:' not in story
        end_sign(True)

@pytest.mark.bitcoind
def test_change_fraud_addr(start_sign, end_sign, use_regtest, check_against_bitcoind, cap_story,
                           sim_root_dir):
    # fraud: BIP-32 path of output doesn't match TXO address
    # NOTE: out#1 is change:
    #chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    # tweak output addr to garbage
    t = CTransaction()
    t.deserialize(BytesIO(b4.txn))
    chg = t.vout[1]          # tx.CTxOut
    b = bytearray(chg.scriptPubKey)
    b[-5] ^= 0x55
    chg.scriptPubKey = bytes(b)

    b4.txn = t.serialize_with_witness()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    with open(f'{sim_root_dir}/debug/mod-addr.psbt', 'wb') as f:
        f.write(mod_psbt)

    start_sign(mod_psbt)
    with pytest.raises(CCProtoError) as ee:
        signed = end_sign(True)
    assert 'Change output is fraud' in str(ee)


@pytest.mark.parametrize('case', ['p2sh-p2wpkh', 'p2wpkh', 'p2sh', 'p2sh-p2pkh'])
@pytest.mark.bitcoind
def test_change_p2sh_p2wpkh(start_sign, end_sign, check_against_bitcoind, use_regtest,
                            cap_story, case, sim_root_dir):
    # not fraud: output address encoded in various equiv forms
    use_regtest()
    # NOTE: out#1 is change:
    #chg_addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'

    with open('data/example-change.psbt', 'rb') as f:
        psbt = f.read()

    b4 = BasicPSBT().parse(psbt)

    t = CTransaction()
    t.deserialize(BytesIO(b4.txn))

    scpk = t.vout[1].scriptPubKey
    assert scpk[:3] == bytes.fromhex("76a914")  # OP_DUP OP_HASH160 OP_PUSH20
    assert scpk[-2:] == bytes.fromhex("88ac")  # OP_EQUALVERIFY OP_CHECKSIG
    pkh = scpk[3:-2]

    if case == 'p2wpkh':
        t.vout[1].scriptPubKey = bytes([0, 20]) + pkh

        from bech32 import encode
        expect_addr = encode('bcrt', 0, pkh)

    elif case == 'p2sh-p2wpkh':
        redeem_scr = bytes([0, 20]) + pkh
        h160_redeem_scr = hash160(redeem_scr)
        spk = bytes([0xa9, 0x14]) + h160_redeem_scr + bytes([0x87])

        b4.outputs[1].redeem_script = redeem_scr
        t.vout[1].scriptPubKey = spk
        expect_addr = encode_base58_checksum(b"\xc4" + h160_redeem_scr)

    elif case == 'p2sh-p2pkh':
        # not supported
        redeem_scr = scpk
        h160_redeem_scr = hash160(redeem_scr)
        spk = bytes([0xa9, 0x14]) + h160_redeem_scr + bytes([0x87])
        b4.outputs[1].redeem_script = redeem_scr
        t.vout[1].scriptPubKey = spk
        expect_addr = encode_base58_checksum(b"\xc4" + h160_redeem_scr)

    elif case == 'p2sh':
        # plain wrong for p2sh-p2wpkh (check for case == 'p2sh-p2wpkh' for correct)
        # scriptPubKey for p2sh-p2wpkh uses hash of the script not hash of pubkey
        # also check 'test_wrong_p2sh_p2wpkh' below
        spk = bytes([0xa9, 0x14]) + pkh + bytes([0x87])
        b4.outputs[1].redeem_script = bytes([0, 20]) + pkh
        t.vout[1].scriptPubKey = spk
        expect_addr = encode_base58_checksum(b"\xc4" + scpk)

    b4.txn = t.serialize_with_witness()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    with open(f'{sim_root_dir}/debug/mod-%s.psbt' % case, 'wb') as f:
        f.write(mod_psbt)

    start_sign(mod_psbt)

    time.sleep(.1)
    _, story = cap_story()

    if case in ["p2sh", "p2sh-p2pkh"]:
        assert "Output#1: Change output is fraudulent" == story
        return

    check_against_bitcoind(B2A(b4.txn), Decimal('0.00000294'), change_outs=[1,],
            dests=[(1, expect_addr)])

    split_sory = story.split("\n\n")[3].split("\n")
    assert split_sory[0] == "Change back:"
    assert expect_addr == addr_from_display_format(split_sory[-1])
    assert parse_change_back(story) == (Decimal('1.09997082'), [expect_addr])

    end_sign(True)


def test_wrong_p2sh_p2wpkh(bitcoind, start_sign, end_sign, bitcoind_d_sim_watch, cap_story):
    sim = bitcoind_d_sim_watch
    sim_addr = sim.getnewaddress("", "bech32")
    bitcoind.supply_wallet.sendtoaddress(sim_addr, 2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    utxos = sim.listunspent()
    assert len(utxos) == 1
    conso_addr = sim.getnewaddress("", "legacy")
    psbt_resp = sim.walletcreatefundedpsbt([], [{conso_addr: 1}], 0, {"fee_rate": 2, "change_type": "bech32"})
    psbt = psbt_resp.get("psbt")
    b4 = BasicPSBT().parse(base64.b64decode(psbt))
    t = CTransaction()
    t.deserialize(BytesIO(b4.txn))

    if t.vout[0].scriptPubKey[:2] == b"\x00\x14":
        target_out_idx = 1
    else:
        target_out_idx = 0

    # looking for p2pkh output
    scpk = t.vout[target_out_idx].scriptPubKey
    assert scpk[:3] == bytes.fromhex("76a914")  # OP_DUP OP_HASH160 OP_PUSH20
    assert scpk[-2:] == bytes.fromhex("88ac")  # OP_EQUALVERIFY OP_CHECKSIG
    pkh = scpk[3:-2]

    # below is wrong - but that is the point of this test
    spk = bytes([0xa9, 0x14]) + pkh + bytes([0x87])
    b4.outputs[target_out_idx].redeem_script = bytes([0, 20]) + bytes(pkh)
    t.vout[target_out_idx].scriptPubKey = spk

    b4.txn = t.serialize_with_witness()

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    start_sign(mod_psbt)
    try:
        fin = end_sign(True)
    except Exception as e:
        assert "Change output is fraudulent" in e.args[0]
        # this is the correct ending
        return

    # for people with un-patched psbt.py (proof)
    res = sim.finalizepsbt(base64.b64encode(fin).decode())
    # sure core allows you to send your money wherever you please
    assert res["complete"]
    assert sim.testmempoolaccept([res['hex']])[0]["allowed"] is True
    tx_id = sim.sendrawtransaction(res['hex'])
    assert isinstance(tx_id, str) and len(tx_id) == 64

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    utxos = sim.listunspent()
    # but now not even core can spot the utxo as ours, so money send to limbo
    # would need to find a script that hash160 == hash160(pubkey)
    assert len(utxos) == 2


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
def test_sign_wutxo(start_sign, set_seed_words, end_sign, cap_story, sim_exec, sim_execfile,
                    sim_root_dir):

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

        assert 'Network fee 0.00000500 XTN' in story

        # check we understood it right
        ex = dict(  had_witness=False, num_inputs=1, num_outputs=1, sw_inputs=[False],
                    miner_fee=500, warnings_expected=0,
                    lock_time=1442308, total_value_out=99500,
                    total_value_in=100000)

        rv= sim_exec('import main; main.EXPECT = %r; ' % ex)
        if rv: pytest.fail(rv)
        rv = sim_execfile('devtest/check_decode.py')
        if rv: pytest.fail(rv)

        signed = end_sign(True, finalize=fin)

        with open(f'{sim_root_dir}/debug/sn-signed.'+ ('txn' if fin else 'psbt'), 'wt') as f:
            f.write(B2A(signed))

@pytest.mark.parametrize('fee_max', [ 10, 25, 50])
@pytest.mark.parametrize('under', [ False, True])
def test_network_fee_amts(fee_max, under, fake_txn, try_sign, start_sign, dev, settings_set,
                          sim_exec, cap_story, sim_root_dir):

    settings_set('fee_limit', fee_max)

    # creat a txn with single 1BTC input, and one output, equal to 1BTC-fee
    target = (fee_max - 2) if under else fee_max
    outval = int(1E8 / ((target/100.) + 1.))

    psbt = fake_txn(1, [["p2pkh", outval]], dev.master_xpub, fee=0)

    with open(f'{sim_root_dir}/debug/fee.psbt', 'wb') as f:
        f.write(psbt)

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

def test_network_fee_unlimited(fake_txn, start_sign, end_sign, dev, settings_set, cap_story,
                               sim_root_dir):

    settings_set('fee_limit', -1)

    # creat a txn with single 1BTC input, and tiny one output; the rest is fee
    psbt = fake_txn(1, [["p2wpkh", 100]], dev.master_xpub)

    with open(f'{sim_root_dir}/debug/fee-un.psbt', 'wb') as f:
        f.write(psbt)

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
# @pytest.mark.parametrize('add_xpub', [True, False])  # TODO create test and verify
@pytest.mark.parametrize('out_style', ADDR_STYLES_SINGLE)
@pytest.mark.parametrize('visualized', [0, STXN_VISUALIZE, STXN_VISUALIZE|STXN_SIGNED])
def test_change_outs(fake_txn, start_sign, end_sign, cap_story, dev, num_outs, master_xpub,
                     act_outs, out_style, visualized, sim_root_dir):
    # create a TXN which has change outputs, which shouldn't be shown to user, and also not fail.
    num_ins = 3
    xp = dev.master_xpub

    couts = num_outs if act_outs == -1 else num_ins-act_outs
    outs = [[out_style, None, True] for _ in range(couts)] + [[out_style] for _ in range(num_outs-couts)]
    psbt = fake_txn(num_ins, outs, xp, addr_fmt=out_style)

    with open(f'{sim_root_dir}/debug/change.psbt', 'wb') as f:
        f.write(psbt)

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
            assert story[-1] == '\n'
            last_nl = story[:-1].rindex('\n')
            msg, sig = story[0:last_nl+1], story[last_nl:]
            wallet = BIP32Node.from_wallet_key(master_xpub)
            assert verify_message(wallet.address(), sig, message=msg) is True
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
    elif out_style in ('p2wpkh-p2sh', 'p2sh-p2wpkh'):
        assert set(i[0] for i in addrs) == {'2'}
    else:
        assert out_style == "p2tr"
        assert set(i[0:4] for i in addrs) == {'tb1p'}


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
def test_finalization_vs_bitcoind(match_key, use_regtest, check_against_bitcoind, bitcoind,
                                  start_sign, end_sign, num_dests, sim_root_dir):
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

    with open(f'{sim_root_dir}/debug/vs.psbt', 'wb') as f:
        f.write(psbt)

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
    with open(f'{sim_root_dir}/debug/finalized-by-ckcc.txn', 'wt') as f:
        f.write(B2A(signed_final))

    # Sign again, but don't finalize it.
    start_sign(psbt, finalize=False)
    signed = end_sign(accept=True)

    with open(f'{sim_root_dir}/debug/vs-signed-unfin.psbt', 'wb') as f:
        f.write(signed)

    # Use bitcoind to finalize it this time.
    resp = bitcoind.supply_wallet.finalizepsbt(str(b64encode(signed), 'ascii'), True)
    assert resp['complete'] == True, "bitcoind wasn't able to finalize it"

    network = a2b_hex(resp['hex'])

    # assert resp['complete']
    #print("Final txn: %r" % network)
    with open(f'{sim_root_dir}/debug/finalized-by-btcd.txn', 'wt') as f:
        f.write(B2A(network))

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
    # ("44'/1'/0'/3000/5", '2nd last component'),
    # ("44'/1'/0'/3/5", '2nd last component'),
])
def test_change_troublesome(dev, start_sign, cap_story, try_path, expect, sim_root_dir):
    # NOTE: out#1 is change:
    # addr = 'mvBGHpVtTyjmcfSsy6f715nbTGvwgbgbwo'
    # path = (m=4369050F)/44'/1'/0'/1/5
    # pubkey = 03c80814536f8e801859fc7c2e5129895b261153f519d4f3418ffb322884a7d7e1

    if dev.master_fingerprint != 0x4369050f:
        # file relies on XFP=0F056943 value
        raise pytest.skip('simulator only')

    psbt = open('data/example-change.psbt', 'rb').read()
    b4 = BasicPSBT().parse(psbt)

    pubkey = a2b_hex('03c80814536f8e801859fc7c2e5129895b261153f519d4f3418ffb322884a7d7e1')
    path = [int(p) if ("'" not in p) else 0x80000000+int(p[:-1]) 
                        for p in try_path.split('/')]
    bin_path = b4.outputs[1].bip32_paths[pubkey][0:4] \
                + b''.join(struct.pack('<I', i) for i in path)
    b4.outputs[1].bip32_paths[pubkey] = bin_path

    with BytesIO() as fd:
        b4.serialize(fd)
        mod_psbt = fd.getvalue()

    with open(f'{sim_root_dir}/debug/troublesome.psbt', 'wb') as f:
        f.write(mod_psbt)

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
    funding = CTransaction()
    funding.deserialize(BytesIO(finalized_txn))
    funding.calc_sha256()
    b4 = BasicPSBT().parse(funding_psbt)

    # segwit change outputs only
    spendables = [(n,o)
                   for n, o in enumerate(funding.vout)
                   if o.scriptPubKey[:2] == b"\x00\x14" and b4.outputs[n].bip32_paths]

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
        p_in.witness_utxo = sp.serialize()

    # build new txn: single output, no change, no miner fee
    act_scr = fake_dest_addr('p2wpkh')
    dest_out = CTxOut(sum(s.nValue for _,s in spendables), act_scr)

    txn = CTransaction()
    txn.nVersion = 2
    txn.vin = [CTxIn(COutPoint(funding.sha256, i), nSequence=0xffffffff)
               for i,s in spendables]
    txn.vout = [dest_out]

    # put unsigned TXN into PSBT
    nn.txn = txn.serialize_with_witness()

    with BytesIO() as rv:
        nn.serialize(rv)
        raw = rv.getvalue()

    return nn, raw

@pytest.fixture
def history_data(sim_exec):
    def doit():
        return eval(sim_exec(
            'import history; RV.write(str(history.OutptValueCache.runtime_cache));'))
    return doit

@pytest.fixture
def txid_from_export_prompt(cap_story, cap_screen_qr, cap_screen, need_keypress):
    def doit():
        time.sleep(.1)
        title, story = cap_story()
        assert "(6) for QR Code of TXID" in story
        need_keypress("6")
        time.sleep(.1)
        screen_txid = cap_screen().strip().replace("\n", "").replace("~", "")
        qr_txid = cap_screen_qr().decode().strip().lower()
        assert qr_txid == screen_txid
        return qr_txid

    return doit

@pytest.mark.parametrize('num_utxo', [9, 100])
def test_bip143_attack_data_capture(num_utxo, try_sign, fake_txn, press_cancel,
                                    settings_set, settings_get, cap_story, sim_exec,
                                    history_data, txid_from_export_prompt, sim_root_dir):

    # cleanup prev runs, if very first time thru
    sim_exec('import history; history.OutptValueCache.clear()')
    assert len(history_data()) == 0

    # make a txn, capture the outputs of that as inputs for another txn
    outputs = []
    for i in range(num_utxo):
        if i:
            # change
            outputs.append(["p2wpkh", None, True])
        else:
            outputs.append(["p2pkh", None, True])

    psbt = fake_txn(1, outputs, addr_fmt="p2wpkh")
    _, txn = try_sign(psbt, accept=True, finalize=True, exit_export_loop=False)

    with open(f'{sim_root_dir}/debug/funding.psbt', 'wb') as f:
        f.write(psbt)

    txid = txid_from_export_prompt()
    press_cancel()
    press_cancel()

    curr = history_data()
    assert len(curr) in {128, num_utxo}

    t = CTransaction()
    t.deserialize(BytesIO(txn))
    assert t.txid().hex() == txid

    # expect all of new "change outputs" to be recorded (none of the non-segwit change tho)
    # plus the one input we "revealed"
    after1 = settings_get('ovc')
    assert len(after1) == min(30, num_utxo)

    all_utxo = history_data()
    assert len(all_utxo) == num_utxo
    # build a new PSBT based on those change outputs
    psbt2, raw = spend_outputs(psbt, txn)
    with open(f'{sim_root_dir}/debug/spend_outs.psbt', 'wb') as f:
        f.write(raw)

    # try to sign that ... should work fine
    try_sign(raw, accept=True, finalize=True)
    time.sleep(.1)

    # should not affect stored data, because those values already cached
    assert settings_get('ovc') == after1

    # any tweaks to input side's values should fail.
    for amt in [int(1E6), 1]:
        def value_tweak(spendables):
            assert len(spendables) > 2
            spendables[0][1].nValue += amt

        psbt3, raw = spend_outputs(psbt, txn, tweaker=value_tweak)
        with open(f'{sim_root_dir}/debug/spend_outs.psbt', 'wb') as f:
            f.write(raw)
        with pytest.raises(CCProtoError) as ee:
            orig, result = try_sign(raw, accept=True, finalize=True)

        assert 'but PSBT claims' in str(ee), ee


@pytest.mark.parametrize('addr_fmt', ADDR_STYLES_SINGLE)
@pytest.mark.parametrize('num_ins', [1, 17])
@pytest.mark.parametrize('num_outs', [1, 17])
def test_txid_calc(num_ins, fake_txn, try_sign, dev, decode_with_bitcoind, cap_story,
                   txid_from_export_prompt, press_cancel, num_outs, addr_fmt):
    # verify correct txid for transactions is being calculated
    xp = dev.master_xpub

    psbt = fake_txn(num_ins, num_outs, xp, addr_fmt=addr_fmt)

    _, txn = try_sign(psbt, accept=True, finalize=True, exit_export_loop=False)
    txid = txid_from_export_prompt()
    press_cancel()  # exit QR
    press_cancel()  # exit re-export loop

    t = CTransaction()
    t.deserialize(BytesIO(txn))
    assert t.txid().hex() == txid

    # compare to bitcoin core
    decoded = decode_with_bitcoind(txn)
    pprint(decoded)

    assert len(decoded['vin']) == num_ins
    if "w" in addr_fmt:
        assert all(x['txinwitness'] for x in decoded['vin'])
    assert decoded['txid'] == txid


@pytest.mark.unfinalized            # iff partial=1
@pytest.mark.reexport
@pytest.mark.parametrize('encoding', ['binary', 'hex', 'base64'])
@pytest.mark.parametrize('num_outs', [1,15])
@pytest.mark.parametrize('del_after', [1, 0])
@pytest.mark.parametrize('partial', [1, 0])
def test_sdcard_signing(encoding, num_outs, del_after, partial, try_sign_microsd, fake_txn,
                        dev, settings_set, signing_artifacts_reexport):
    # exercise the txn encode/decode from sdcard
    xp = dev.master_xpub

    settings_set('del', del_after)

    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    psbt = fake_txn([["p2pkh"], ["p2wpkh"], ["p2tr"]], num_outs, xp, psbt_hacker=hack)

    _, txn, txid = try_sign_microsd(psbt, finalize=not partial,
                                    encoding=encoding, del_after=del_after)
    _psbt, _txn = signing_artifacts_reexport("sd", tx_final=not partial, txid=txid,
                                             encoding=encoding, del_after=del_after)
    if partial:
        assert _psbt == txn
    else:
        assert _txn == txn

@pytest.mark.unfinalized
@pytest.mark.parametrize('num_ins', [2,3,8])
@pytest.mark.parametrize('num_outs', [1,2,8])
def test_payjoin_signing(num_ins, num_outs, fake_txn, try_sign, start_sign, end_sign,
                         cap_story, sim_root_dir):

    # Try to simulate a PSBT that might be involved in a Payjoin (BIP-78 txn)

    def hack(psbt):
        # change an input to be "not ours" ... but with utxo details
        psbt.inputs[num_ins-1].bip32_paths.clear()

    psbt = fake_txn(num_ins, num_outs, addr_fmt="p2wpkh", psbt_hacker=hack)

    with open(f'{sim_root_dir}/debug/payjoin.psbt', 'wb') as f:
        f.write(psbt)

    ip = start_sign(psbt, finalize=False)
    time.sleep(.1)
    _, story = cap_story()

    assert 'warning below' in story
    assert 'Limited Signing' in story
    assert 'because we do not know the key' in story
    assert ': %s' % (num_ins-1) in story

    txn = end_sign(True, finalize=False)

@pytest.mark.parametrize('addr_fmt', ["p2wpkh", "p2tr"])
def test_fully_unsigned(fake_txn, try_sign, addr_fmt):

    # A PSBT which is unsigned but all inputs lack keypaths

    def hack(psbt):
        # change all inputs to be "not ours" ... but with utxo details
        for i in psbt.inputs:
            i.bip32_paths.clear()
            i.taproot_bip32_paths.clear()

    psbt = fake_txn(7, 2, addr_fmt=addr_fmt, psbt_hacker=hack)

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    assert 'does not contain any key path information' in str(ee)

@pytest.mark.parametrize('addr_fmt', ["p2wpkh", "p2tr"])
def test_wrong_xfp(fake_txn, try_sign, addr_fmt):

    # A PSBT which is unsigned and doesn't involve our XFP value

    wrong_xfp = b'\x12\x34\x56\x78'

    def hack(psbt):
        # change all inputs to be "not ours" ... but with utxo details
        for i in psbt.inputs:
            for pubkey in i.bip32_paths:
                i.bip32_paths[pubkey] = wrong_xfp + i.bip32_paths[pubkey][4:]
            for xonly_pubkey in i.taproot_bip32_paths:
                i.taproot_bip32_paths[xonly_pubkey] = b"\x00" + wrong_xfp + i.taproot_bip32_paths[xonly_pubkey][5:]

    psbt = fake_txn(7, 2, addr_fmt=addr_fmt, psbt_hacker=hack)

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    assert 'None of the keys' in str(ee)
    assert 'found 12345678' in str(ee)

@pytest.mark.parametrize('addr_fmt', ["p2wpkh", "p2tr"])
def test_wrong_xfp_multi(fake_txn, try_sign, addr_fmt, sim_root_dir):

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
            for xonly_pubkey in i.taproot_bip32_paths:
                here = struct.pack('<I', idx + 73)
                i.taproot_bip32_paths[xonly_pubkey] = b"\x00" + here + i.taproot_bip32_paths[xonly_pubkey][5:]
                wrongs.add(xfp2str(idx + 73))

    psbt = fake_txn(7, 2, addr_fmt=addr_fmt, psbt_hacker=hack)

    with open(f'{sim_root_dir}/debug/wrong-xfp.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(CCProtoError) as ee:
        orig, result = try_sign(psbt, accept=True)

    if 'Signing failed late' in str(ee):
        pass
    else:
        assert 'None of the keys' in str(ee)
        # WEAK: device keeps them in order, but that's chance/impl defined...
        assert 'found '+', '.join(sorted(wrongs)) in str(ee)


@pytest.mark.parametrize('out_style', ADDR_STYLES_SINGLE)
@pytest.mark.parametrize('outval', ['.5', '.788888', '0.92640866'])
def test_render_outs(out_style, outval, fake_txn, start_sign, end_sign, dev, sim_root_dir):
    # check how we render the value of outputs
    # - works on simulator and connected USB real-device
    oi = int(Decimal(outval) * int(1E8))

    psbt = fake_txn(1, [[out_style, oi],[out_style, int(1E8 -oi), True]], dev.master_xpub,
                    addr_fmt="p2wpkh")

    with open(f'{sim_root_dir}/debug/render.psbt', 'wb') as f:
        f.write(psbt)

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
    elif out_style == 'p2tr':
        assert all(i.startswith(("bc1p", "tb1p", "bcrt1p")) for i in addrs)


def test_negative_fee(dev, fake_txn, try_sign):
    # Silly to sign a psbt the network won't accept, but anyway...
    with pytest.raises(CCProtoError) as ee:
        psbt = fake_txn(1, [["p2pkh", int(2E8)]], dev.master_xpub)
        orig, result = try_sign(psbt, accept=False)

    msg = ee.value.args[0]
    assert 'Outputs worth more than inputs' in msg

@pytest.mark.parametrize('units', [
    ( 8, 'XTN'), 
    ( 5, 'mXTN'), 
    ( 2, 'bits'), 
    ( 0, 'sats')])
def test_value_render(dev, units, fake_txn, start_sign, cap_story, settings_set,
                      settings_remove, sim_root_dir):

    # Check we are rendering values in right units.
    decimal, units = units
    settings_set('rz', decimal)

    outputs = [[random.choice(ADDR_STYLES_SINGLE), int(i)] for i in [
                    10E8, 3E8, 
                    1.2345678E8, 
                    1, 12, 123, 123456, 1234567, 12345678,
                    123456789012,
                ]]

    need = sum([r[1] for r in outputs])
    psbt = fake_txn(1, outputs, dev.master_xpub,
                    input_amount=need)

    with open(f'{sim_root_dir}/debug/values.psbt', 'wb') as f:
        f.write(psbt)

    ip = start_sign(psbt, finalize=False)
    time.sleep(.1)
    _, story = cap_story()

    lines = story.split('\n')
    for af, v in outputs:
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
@pytest.mark.parametrize('addr_fmt', ["p2wpkh", "p2tr"])
def test_qr_txn(num_in, num_out, addr_fmt, fake_txn, try_sign, dev, cap_screen_qr,
                qr_quality_check, cap_story, need_keypress, is_q1, press_cancel, sim_root_dir):

    psbt = fake_txn(num_in, num_out, dev.master_xpub, addr_fmt=addr_fmt)

    _, txn = try_sign(psbt, accept=True, finalize=True, exit_export_loop=False)
    with open(f'{sim_root_dir}/debug/last.txn', 'wb') as f:
        f.write(txn)

    title, story = cap_story()

    assert '(6) for QR Code of TXID' in story

    # check TXID qr code
    need_keypress('6')
    qr = cap_screen_qr().decode()
    press_cancel()

    t = CTransaction()
    t.deserialize(BytesIO(txn))
    assert t.txid().hex() == qr.lower()

    if is_q1:
        need_keypress(KEY_QR)
        qr = cap_screen_qr().decode()
        assert qr.lower() == txn.hex()
        press_cancel()

    press_cancel()

def test_missing_keypaths(dev, try_sign, fake_txn):

    # make valid psbt
    psbt = fake_txn(3, 1, dev.master_xpub, addr_fmt="p2pkh")

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

    psbt = fake_txn(1, 1, dev.master_xpub, addr_fmt="p2pkh")

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
    psbt = fake_txn(3, 1, dev.master_xpub, addr_fmt="p2pkh")

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
    psbt = fake_txn(2, [["p2pkh", None],["p2pkh", None, True],["p2pkh", None, True]],
                    dev.master_xpub, addr_fmt="p2pkh")

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


@pytest.mark.parametrize("addr_fmt", ["p2pkh", "p2wpkh"])
@pytest.mark.parametrize('num_not_ours', [1, 3, 4])
def test_foreign_utxo_missing(addr_fmt, num_not_ours, dev, fake_txn, start_sign,
                              cap_story, end_sign):
    def hack(psbt):
        # change first input to not be ours
        for i in range(num_not_ours):
            pk = list(psbt.inputs[i].bip32_paths.keys())[0]
            pp = psbt.inputs[i].bip32_paths[pk]
            psbt.inputs[i].bip32_paths[pk] = b'what' + pp[4:]
            # no utxo provided for foreign inputs
            psbt.inputs[i].utxo = None
            psbt.inputs[i].witness_utxo = None

    psbt = fake_txn(5, 2, dev.master_xpub, addr_fmt=addr_fmt, psbt_hacker=hack)
    start_sign(psbt)
    time.sleep(.1)
    _, story = cap_story()
    no = ", ".join(str(i) for i in list(range(num_not_ours)))
    assert "warnings" in story
    assert f"Limited Signing: We are not signing these inputs, because we do not know the key: {no}" in story
    assert f"Unable to calculate fee: Some input(s) haven't provided UTXO(s): {no}" in story
    signed = end_sign(accept=True)
    assert signed != psbt

@pytest.mark.parametrize("addr_fmt", ["p2pkh", "p2wpkh", "p2tr"])
@pytest.mark.parametrize("num_missing", [1, 3, 4])
def test_own_utxo_missing(num_missing, dev, fake_txn, start_sign, cap_story, end_sign,
                          press_cancel, addr_fmt):
    def hack(psbt):
        for i in range(num_missing):
            # no utxo provided for our input
            psbt.inputs[i].utxo = None
            psbt.inputs[i].witness_utxo = None

    psbt = fake_txn(5, 2, dev.master_xpub, addr_fmt=addr_fmt, psbt_hacker=hack)
    start_sign(psbt)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Missing own UTXO(s)" in story
    press_cancel()

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
    tap_dave = bitcoind.create_wallet(wallet_name="tap_dave")
    alice_addr = alice.getnewaddress()
    alice_pubkey = alice.getaddressinfo(alice_addr)["pubkey"]
    bob_addr = bob.getnewaddress()
    bob_pubkey = bob.getaddressinfo(bob_addr)["pubkey"]
    cc_addr = cc.getnewaddress()
    cc_pubkey = cc.getaddressinfo(cc_addr)["pubkey"]
    tap_dave_addr = tap_dave.getnewaddress("", "bech32m")
    # fund all addresses
    for addr in (alice_addr, bob_addr, cc_addr, tap_dave_addr):
        bitcoind.supply_wallet.sendtoaddress(addr, 2.0)

    # mine above sends
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    psbt_list = []
    for w in (alice, bob, cc, tap_dave):
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
        for xo_pk, _ in inp.taproot_bip32_paths.items():
            inp.utxo = None
            inp.witness_utxo = None

    psbt0 = the_psbt_obj.as_bytes()
    orig, res = try_sign(psbt0, accept=True)
    assert orig != res  # coldcard signs no problem - only our UTXO matters for signing
    # now alice and bob UTXOs are still missing but bitcoind does not care either
    # lets sign with bob first - bobs wallet will ignore missing alice UTXO but will supply his UTXO
    psbt1 = bob.walletprocesspsbt(base64.b64encode(res).decode(), True, "ALL")["psbt"]
    # finally sign with alice
    res = alice.walletprocesspsbt(psbt1, True)
    psbt2 = res["psbt"]
    res = tap_dave.walletprocesspsbt(psbt2, True)
    psbt3 = res["psbt"]
    assert res["complete"] is True
    tx = alice.finalizepsbt(psbt3)["hex"]
    assert alice.testmempoolaccept([tx])[0]["allowed"] is True
    tx_id = alice.sendrawtransaction(tx)
    assert isinstance(tx_id, str) and len(tx_id) == 64

@pytest.mark.bitcoind
@pytest.mark.parametrize("op_return_data", [
    81 * b"a",
    255 * b"b",  # biggest possible with PUSHDATA1
    256 * b"c",  # PUSHDATA2
    4000 * b"d",  # PUSHDATA2
    b"Coldcard is the best signing device",  # to test with both pushdata opcodes
    b"Coldcard, the best signing deviceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # len 80 max
    b"\x80" * 80,
    "££££££££££".encode("utf-8"),
    bytes.fromhex("aa21a9ed68512d3c6b0514b18fbc9f0c540d5bec8f4ae62da4bf6c9b16f90b655f9f4210"),
    b"$$$$$$$$$$$$$$ Bitcoin",
    b"\xeb\x97\xf7\xb7\xf78\x9a';\x90F_\xfc\xe2b\xa4\x93)\xea\xac\xacR\xff\x9c\xbe\x1c\xf1\xad\xe9!\xee\xd9t1\x1f\x92\x83\x97\xb3\x98/\xff\xc8\xff\xc1\xc0\xdd\x1et\x00L\x13\xe0\xe3\x90\xe4\xd4\xf2x:\xf7Ab\x04\x91\x1e\xa8R\x92\xd3\x96OK\xc6I\x06\x9e\xce=\xb3",
])
def test_op_return_signing(op_return_data, dev, fake_txn, bitcoind_d_sim_watch, bitcoind,
                           start_sign, end_sign, cap_story):
    cc = bitcoind_d_sim_watch
    dest_address = cc.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(dest_address, 2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    psbt = cc.walletcreatefundedpsbt([], [{dest_address: 1.0}, {"data": op_return_data.hex()}], 0, {"fee_rate": 20})["psbt"]
    start_sign(base64.b64decode(psbt), finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    # in older implementations, one would see a warning for OP_RETURN --> not now
    if len(op_return_data) > 80:
        assert "(1 warning below)" in story  # looking for warning at the top
        assert "OP_RETURN > 80 bytes" in story
    else:
        assert "warning" not in story

    assert "OP_RETURN" in story
    assert "Multiple OP_RETURN outputs:" not in story  # always just one - core restriction

    try:
        assert len(op_return_data) <= 200
        expect = op_return_data.decode("ascii")
    except:
        expect = binascii.hexlify(op_return_data).decode()
        if len(op_return_data) > 200:
            expect = expect[:200] + "\n ⋯\n" + expect[-200:]

    assert expect in story
    tx = end_sign(accept=True, finalize=True).hex()

    # tx is final at this point and consensus valid
    # tx = cc.finalizepsbt(base64.b64encode(signed).decode())["hex"]
    res = cc.testmempoolaccept([tx])[0]

    if len(op_return_data) > 80:
        # policy
        assert res["allowed"] is False
        assert res["reject-reason"] == "scriptpubkey"
    else:
        assert res["allowed"] is True
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
def test_unknow_values_in_psbt(unknowns, dev, start_sign, end_sign, fake_txn, sim_root_dir):
    unknown_global, unknown_ins, unknown_outs = unknowns
    def hack(psbt):
        psbt.unknown = unknown_global
        for i in psbt.inputs:
            i.unknown = unknown_ins
        for o in psbt.outputs:
            o.unknown = unknown_outs

    psbt = fake_txn(5, 5, dev.master_xpub, addr_fmt="p2wpkh", psbt_hacker=hack)
    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)
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

def test_read_write_prop_attestation_keys(try_sign, fake_txn, sim_root_dir):
    from psbt import ser_prop_key, PSBT_PROP_CK_ID
    def attach_attest_to_outs(psbt):
        for idx, o in enumerate(psbt.outputs):
            key = ser_prop_key(PSBT_PROP_CK_ID, 0)
            value = b"fake attestation"
            o.proprietary[key] = value

    psbt = fake_txn(2, 2, psbt_hacker=attach_attest_to_outs)
    with open(f'{sim_root_dir}/debug/propkeys.psbt', 'wb') as f:
        f.write(psbt)
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
    psbt = fake_txn(5, 5, dev.master_xpub, addr_fmt="p2wpkh", psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()

    # duplicate keys for input unknowns
    def hack(psbt):
        for i in psbt.inputs:
            i.unknown = [(b"xxx", 32 * b"\x00"), (b"xxx", 32 * b"\x01")]
    psbt = fake_txn(5, 5, dev.master_xpub, addr_fmt="p2pkh", psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()

    # duplicate keys for output unknown
    def hack(psbt):
        for o in psbt.outputs:
            o.unknown = [(b"xxx", 32 * b"\x00"), (b"xxx", 32 * b"\x01")]
    psbt = fake_txn(5, 5, dev.master_xpub, addr_fmt="p2tr", psbt_hacker=hack)
    start_sign(psbt)
    with pytest.raises(Exception):
        end_sign()


@pytest.fixture
def _test_single_sig_sighash(cap_story, press_select, start_sign, end_sign, dev,
                             bitcoind, bitcoind_d_dev_watch, settings_set,
                             finalize_v2_v0_convert, pytestconfig, sim_root_dir):
    def doit(addr_fmt, sighash, num_inputs=2, num_outputs=2, consolidation=False, sh_checks=False,
             psbt_v2=None, tx_check=True):

        from decimal import Decimal, ROUND_DOWN

        if psbt_v2 is None:
            # anything passed directly to this function overrides
            # pytest flag --psbt2 - only care about pytest flag
            # if psbt_v2 is not specified (None)
            psbt_v2 = pytestconfig.getoption('psbt2')

        if dev.is_simulator:
            # if running against real HW you need to set CC to correct sighshchk mode
            # Below test need to run with sighshchk disabled:
            #     * test_sighash_same
            #     * test_sighash_different
            #     * test_sighash_fullmix
            #
            # With sighshchk enabled (CC default):
            #     * test_sighash_disallowed_consolidation
            #     * test_sighash_disallowed_NONE

            settings_set("sighshchk", int(not sh_checks))

        not_all_ALL = any(sh != "ALL" for sh in sighash)

        # this is needed as supply wallet is still legacy bitcoind wallet (no tr support)
        dest_wal = bitcoind.create_wallet("dest_wal")

        bitcoind_d_dev_watch.keypoolrefill(num_inputs + num_outputs)
        input_val = bitcoind.supply_wallet.getbalance() / num_inputs
        cc_dest = [
            {bitcoind_d_dev_watch.getnewaddress("", addr_fmt): Decimal(input_val).quantize(Decimal('.0000001'), rounding=ROUND_DOWN)}
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
        unspent = bitcoind_d_dev_watch.listunspent()
        output_val = bitcoind_d_dev_watch.getbalance() / num_outputs
        # consolidation or not?
        dest_wal = bitcoind_d_dev_watch if consolidation else dest_wal
        destinations = [
            {dest_wal.getnewaddress("", addr_fmt): Decimal(output_val).quantize(Decimal('.0000001'), rounding=ROUND_DOWN)}
            for _ in range(num_outputs)
        ]
        assert len(unspent) >= num_inputs
        psbt = bitcoind_d_dev_watch.walletcreatefundedpsbt(
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
            # below is noop if psbt is already v2
            psbt_sh_bytes = x.to_v2()
            psbt_sh = base64.b64encode(psbt_sh_bytes).decode()

        else:
            psbt_sh_bytes = x.as_bytes()
            psbt_sh = x.as_b64_str()

        # make useful reference psbt along the way
        with open(f'{sim_root_dir}/debug/sighash-{sighash[0] if len(sighash) == 1 else "MIX"}.psbt'\
                .replace('|', '-'), 'wt') as f:
            f.write(psbt_sh)

        # get story out of CC via visualize feature
        start_sign(psbt_sh_bytes, False, stxn_flags=STXN_VISUALIZE)
        if sh_checks is True:
            # checks enabled
            if consolidation and not_all_ALL:
                with pytest.raises(Exception) as e:
                    end_sign(accept=None, expect_txn=False).decode()
                # assert title == "Failure"
                assert "Only sighash ALL is allowed for pure consolidation transaction" in e.value.args[0]
                return

            elif not consolidation and any("NONE" in sh for sh in sighash if isinstance(sh, str)):
                with pytest.raises(Exception) as e:
                    end_sign(accept=None, expect_txn=False).decode()
                # assert title == "Failure"
                assert "Sighash NONE is not allowed as funds could be going anywhere" in e.value.args[0]
                return

        story = end_sign(accept=None, expect_txn=False).decode()

        # assert title == "OK TO SEND?"
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

        # sign and get PSBT out
        start_sign(psbt_sh_bytes)
        # now not just legacy but also segwit prohibits SINGLE out of bounds
        # consensus allows it but it really is just bad usage - restricted
        if (num_outputs < num_inputs) and any("SINGLE" in sh for sh in sighash):
            with pytest.raises(Exception) as e:
                end_sign(accept=True)
            assert "Signing failed late" in e.value.args[0]
            # assert "SINGLE corresponding output" in story
            # assert "missing" in story
            return

        psbt_out = end_sign(accept=True)
        y = BasicPSBT().parse(psbt_out)

        for idx, i in enumerate(y.inputs):
            if len(sighash) == 1:
                target = sighash[0]
                sh_num = SIGHASH_MAP[target]
                if target == "ALL":
                    assert i.sighash is None
                else:
                    assert i.sighash == sh_num
            else:
                target = sighash[idx]
                sh_num = SIGHASH_MAP[target]
                if target == "ALL":
                    assert i.sighash is None
                else:
                    assert i.sighash == sh_num
            # check signature hash correct checksum appended
            for _, sig in i.part_sigs.items():
                assert sig[-1] == sh_num

        resp = finalize_v2_v0_convert(y)

        assert resp["complete"] is True
        tx_hex = resp["hex"]

        if tx_check:
            # sign and get finalized tx ready for broadcast out
            start_sign(psbt_sh_bytes, finalize=True)
            cc_tx_hex = end_sign(accept=True, finalize=True)
            cc_tx_hex = cc_tx_hex.hex()
            if addr_fmt != "bech32m":
                # schnorr signatures are not deterministic
                # any subsequent sign will produce different witness
                assert tx_hex == cc_tx_hex

        if psbt_v2:
            # check txn_modifiable properly set
            po = BasicPSBT().parse(psbt_out)
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
        assert txn_id

    return doit

# TODO Sighash test MUST be run with --psbt2 flag on and off
# pytest test_sign.py -k sighash {--psbt2,}

@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32", "bech32m"])
@pytest.mark.parametrize("sighash", [sh for sh in SIGHASH_MAP if sh != 'ALL'])
@pytest.mark.parametrize("num_outs", [1, 3, 5])
@pytest.mark.parametrize("num_ins", [2, 5])
def test_sighash_same(addr_fmt, sighash, num_ins, num_outs, _test_single_sig_sighash):
    # sighash is the same among all inputs
    _test_single_sig_sighash(addr_fmt, [sighash], num_inputs=num_ins, num_outputs=num_outs)


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32", "bech32m"])
@pytest.mark.parametrize("sighash", list(itertools.combinations(SIGHASH_MAP.keys(), 2)))
@pytest.mark.parametrize("num_outs", [2, 3, 5])
def test_sighash_different(addr_fmt, sighash, num_outs, _test_single_sig_sighash):
    # sighash differ among all inputs
    _test_single_sig_sighash(addr_fmt, sighash, num_inputs=2, num_outputs=num_outs)


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["legacy", "p2sh-segwit", "bech32", "bech32m"])
@pytest.mark.parametrize("num_outs", [5, 8])
def test_sighash_fullmix(addr_fmt, num_outs, _test_single_sig_sighash):
    # tx with 6 inputs representing all possible sighashes
    _test_single_sig_sighash(addr_fmt, tuple(SIGHASH_MAP.keys()), num_inputs=6, num_outputs=num_outs)


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
    with pytest.raises(Exception) as exc:
        _test_single_sig_sighash("legacy", [0xe2], num_inputs=2, num_outputs=2,
                                 consolidation=True, sh_checks=False)
    assert "Unsupported sighash flag 0xe2" in exc.value.args[0]


def test_no_outputs_tx(fake_txn, microsd_path, goto_home, press_select, pick_menu_item, cap_story):
    goto_home()
    psbt = fake_txn(3, 0)  # no outputs
    fname = "zero_outputs.psbt"
    fpath = microsd_path(fname)

    with open(fpath, "wb") as f:
        f.write(psbt)

    pick_menu_item('Ready To Sign')
    time.sleep(0.1)
    try:
        pick_menu_item(fname)
    except KeyError: pass
    time.sleep(0.1)
    title, story = cap_story()

    assert title == "Failure"
    assert "Invalid PSBT" in story
    assert "need outputs" in story

    try: os.remove(fpath)
    except: pass

@pytest.mark.parametrize("num_unknown", [1,3])
def test_send2unknown_script(fake_txn , start_sign, end_sign, cap_story, use_testnet, num_unknown):
    use_testnet()
    unknowns = ["unknown"] * num_unknown
    num_out = 2 if num_unknown == 1 else 4

    # <same date> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    hex_str = "049f7b2a5cb17576a914371c20fb2e9899338ce5e99908e64fd30b78931388ac"

    outs = [["p2tr", None, True] if not i else ["unknown", None, False, hex_str] for i in range(num_out)]
    psbt = fake_txn(2, outs, addr_fmt="p2tr")
    start_sign(psbt)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    # we do not understand change in taproot (taproot not supported)
    assert "(1 warning below)" in story  # unknown script
    assert ("Sending to %d not well understood script(s)" % num_unknown) in story
    assert "Consolidating" not in story
    assert "to script" in story
    signed = end_sign(accept=True, finalize=False)
    assert signed


@pytest.mark.parametrize("num_tx", [1, 2, 10])
@pytest.mark.parametrize("ui_path", [True, False])
@pytest.mark.parametrize("action", ["sign", "skip", "refuse"])
def test_batch_sign(num_tx, ui_path, action, fake_txn, need_keypress,
                    pick_menu_item, cap_story, microsd_path, cap_menu,
                    microsd_wipe, goto_home, press_select, press_cancel, X):

    goto_home()
    microsd_wipe()

    for i in range(num_tx):
        psbt = fake_txn(2, 2, addr_fmt=random.choice(["p2tr", "p2wpkh", "p2pkh"]))
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
            press_cancel()
            pytest.skip("classic sign")

        m = cap_menu()
        mi = "[Sign All]"
        assert mi in m
        pick_menu_item(mi)

    time.sleep(.1)
    title, story = cap_story()
    if "Press (1)" in story:
        need_keypress("1")
        time.sleep(.1)
        title, story = cap_story()

    for i in range(num_tx):
        assert "Sign" in story
        assert "(1) to skip" in story
        assert f"{X} to quit and exit" in story
        if action == "skip":
            need_keypress("1")  # skip this PSBT
            time.sleep(.5)
            title, story = cap_story()
            continue

        press_select()  # sign this PSBT
        time.sleep(.5)
        title, story = cap_story()
        assert title == "OK TO SEND?"
        if action == "refuse":
            press_cancel()  # refuse
            time.sleep(.5)
            title, story = cap_story()
            continue

        press_select()  # confirm send
        time.sleep(.5)
        title, story = cap_story()
        assert "-signed.psbt" in story
        press_cancel()
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
def test_psbt_v2(outstyle, fake_txn , start_sign, end_sign, cap_story,
                 microsd_path, bitcoind, finalize_v2_v0_convert):
    psbt = fake_txn(2, [[outstyle, None, True], [outstyle]], addr_fmt=outstyle, psbt_v2=True)

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

def test_psbt_v2_tx_modifiable_parse(fake_txn, start_sign, end_sign):
    psbt = fake_txn(2, [["p2tr", None, True],["p2wpkh"]], addr_fmt="p2tr", psbt_v2=True)
    p = BasicPSBT().parse(psbt)
    # 3 = both inputs and outputs are modifiable
    # need just some value instead of None, in that case flag is ommited
    p.txn_modifiable = 3
    with BytesIO() as fd:
        p.serialize(fd)
        mod_psbt = fd.getvalue()

    start_sign(mod_psbt)
    signed = end_sign(accept=True, finalize=False)
    assert signed
    po = BasicPSBT().parse(signed)
    # signed with sighash ALL - meaning nothing is modifiable now
    assert po.txn_modifiable == 0

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


    psbt = fake_txn(2, [["p2pkh", None, True],["p2wpkh"]], addr_fmt="p2sh-p2wpkh",
                    psbt_v2=True, psbt_hacker=lambda psbt: hacker(psbt, way))

    start_sign(psbt)
    title, story = cap_story()
    assert "failed" in story or "Invalid PSBT" in story or "Network fee bigger" in story


@pytest.mark.bitcoind
@pytest.mark.parametrize("locktime", [
    0,  # zero default
    False,  # current block height
    800000,
    1513209600,  # 2017-12-14 00:00:00
    1387324800,  # 2013-12-18 00:00:00
    1294790399,  # 2011-11-01 23:59:59
    1748671747,  # 2025-05-31 07:09:07
])
def test_locktime_ux(use_regtest, bitcoind_d_sim_watch, start_sign, end_sign,
                     microsd_path, cap_story, goto_home, press_select,
                     pick_menu_item, bitcoind, locktime, file_tx_signing_done):
    use_regtest()
    sim = bitcoind_d_sim_watch
    addr = sim.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(addr, 2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    bi = sim.getblockchaininfo()
    blocks = bi["blocks"]

    success = True
    if locktime is False:
        # current height - allowed
        locktime = blocks

    if locktime < 500000000:
        # blocks
        if locktime > blocks:
            success = False
    else:
        # MTP
        if locktime > datetime.datetime.utcnow().timestamp():
            success = False

    dest_addr = sim.getnewaddress()  # self-spend
    psbt_resp = sim.walletcreatefundedpsbt([], [{dest_addr: 1.0}], locktime, {"fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "locktime.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(0.1)
    title, story = cap_story()
    if 'OK TO SEND' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()

    assert "WARNING" not in story
    if locktime != 0:
        assert "LOCKTIMES" in story
        assert "Abs Locktime" in story
        if locktime < 500000000:
            assert f"This tx can only be spent after block height of {locktime}" in story
        else:
            dt = datetime.datetime.utcfromtimestamp(locktime)
            ux_dt = dt.strftime("%Y-%m-%d %H:%M:%S")
            assert f"This tx can only be spent after {ux_dt} UTC (MTP)" in story
            # assert f"This tx can only be spent after {locktime} (unix timestamp)" in story
    else:
        assert "LOCKTIMES" not in story

    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    signed_psbt, signed_txn, story_txid = file_tx_signing_done(story)
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is success
    assert signed_txn == bitcoind_signed_txn
    if success:
        txid = sim.sendrawtransaction(signed_txn)
    else:
        with pytest.raises(Exception):
            sim.sendrawtransaction(signed_txn)
        txid = accept_res["txid"]
    assert len(txid) == 64
    assert txid == story_txid


@pytest.mark.bitcoind
@pytest.mark.parametrize("num_ins", [1, 4, 11])
@pytest.mark.parametrize("differ", [True, False])
@pytest.mark.parametrize("sequence", [0, 1, 50, 65534])
def test_nsequence_blockheight_relative_locktime_ux(sequence, use_regtest, bitcoind_d_sim_watch,
                                                    start_sign, end_sign, microsd_path, cap_story,
                                                    goto_home, press_select, pick_menu_item,
                                                    bitcoind, num_ins, differ, file_tx_signing_done):
    if differ and (sequence == 0):
        # this case makes no sense
        return

    use_regtest()
    sim = bitcoind_d_sim_watch
    sim.keypoolrefill(20)
    for i in range(num_ins):
        addr = sim.getnewaddress()
        bitcoind.supply_wallet.sendtoaddress(addr, 1)

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    dest_addr = sim.getnewaddress()  # self-spend
    utxos = sim.listunspent()
    assert len(utxos) == num_ins

    ins = []
    num_ins_locked = 0
    locks = []
    for i, utxo in enumerate(utxos):
        confirmations = utxo["confirmations"]
        lock = (confirmations + sequence) if sequence else 0
        if i and differ:
            # not first one (0th) as it should have sequence provided via parametrize
            # all others decremented by iteration count
            nSeq = lock - i
            if nSeq < 0:
                nSeq = 0
        else:
            nSeq = lock

        if nSeq > 0:
            num_ins_locked += 1
            locks.append(nSeq)

        # block height based RTL
        inp = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "sequence": nSeq,
        }
        ins.append(inp)

    psbt_resp = sim.walletcreatefundedpsbt(ins, [{dest_addr: (num_ins - 0.1)}], 0, {"fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "rtl-blockheight.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(0.1)
    title, story = cap_story()
    if 'OK TO SEND' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()

    assert "WARNING" not in story
    if sequence:
        assert "TX LOCKTIMES" in story
        assert "Block height RTL" in story
        if num_ins_locked == 1:
            assert ("has relative block height timelock of %d" % lock) in story
        else:
            if differ:
                assert ("%d inputs have relative block height timelock." % num_ins_locked) in story
                for i in range(num_ins_locked):
                    if not (("%d.  " % i) in story):
                        assert "only 10 with highest values" in story
            else:
                assert ("%d inputs have relative block height timelock of %d" % (num_ins_locked, lock)) in story
    else:
        assert "TX LOCKTIMES" not in story

    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    press_select()  # exit saved story
    signed_psbt, signed_txn, story_txid = file_tx_signing_done(story)
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    if sequence == 0:
        assert accept_res["allowed"]
        return

    assert accept_res["allowed"] is False
    assert accept_res["reject-reason"] == 'non-BIP68-final'
    if sequence > 50:
        # not gonna mine 65k blocks
        return
    sim.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())  # mine N blocks
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid


@pytest.mark.bitcoind
@pytest.mark.parametrize("num_ins", [1, 4, 11])
@pytest.mark.parametrize("differ", [True, False])
@pytest.mark.parametrize("seconds", [512, 10240, 1024000, 33554431])
def test_nsequence_timebased_relative_locktime_ux(seconds, use_regtest, bitcoind_d_sim_watch, start_sign,
                                                  microsd_path, cap_story, goto_home, press_select,
                                                  pick_menu_item, bitcoind, end_sign, num_ins, differ,
                                                  file_tx_signing_done):
    sequence = SEQUENCE_LOCKTIME_TYPE_FLAG | (seconds >> 9)
    use_regtest()
    sim = bitcoind_d_sim_watch
    sim.keypoolrefill(20)
    for i in range(num_ins):
        addr = sim.getnewaddress()
        bitcoind.supply_wallet.sendtoaddress(addr, 1)

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    dest_addr = sim.getnewaddress()  # self-spend
    utxos = sim.listunspent()
    assert len(utxos) == num_ins

    bi = sim.getblockchaininfo()

    ins = []
    num_ins_locked = 0
    locked_indexes = []
    for i, utxo in enumerate(utxos):
        # time-based RTL
        if i and differ and (seconds > 512):
            secs = seconds // i
            nSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | (secs >> 9)
            if nSeq < 0:
                nSeq = 0

        else:
            secs = seconds
            nSeq = sequence

        if nSeq > 0:
            num_ins_locked += 1
            locked_indexes.append((i, secs))

        inp = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "sequence": nSeq,
        }
        ins.append(inp)

    psbt_resp = sim.walletcreatefundedpsbt(ins, [{dest_addr: (num_ins - 0.1)}], 0, {"fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "rtl-time.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.1)
    title, story = cap_story()
    if 'OK TO SEND' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()

    assert "WARNING" not in story
    assert "TX LOCKTIMES" in story
    assert "Time-based RTL" in story
    t_from_seq = (sequence & 0x0000ffff) << 9
    base_msg = "relative time-based timelock of:\n %s" % seconds2human_readable(t_from_seq)
    if num_ins_locked == 1:
        assert ("has " + base_msg) in story
    else:
        if differ and (seconds > 512):
            assert ("%d inputs have relative time-based timelock." % num_ins_locked) in story
            for i, _ in sorted(locked_indexes, key=lambda i: i[1], reverse=True)[:10]:
                assert ("%d.  " % i) in story
        else:
            msg1 = "%d inputs have " % num_ins_locked
            assert (msg1 + base_msg) in story

    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    signed_psbt, signed_txn, story_txid = file_tx_signing_done(story)
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is False
    assert accept_res["reject-reason"] == 'non-BIP68-final'
    if seconds > 512:
        # not gonna wait for it
        return
    # mine blocks - mining increases the timestamp but somehow randomly
    while True:
        sim.generatetoaddress(5, bitcoind.supply_wallet.getnewaddress())
        t = sim.getblockchaininfo()["time"]
        if (t - bi["time"]) > 600:
            break
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid


@pytest.mark.bitcoind
@pytest.mark.parametrize("abs_lock", [True, False])
@pytest.mark.parametrize("num_rtl", [(2,3),(4,7),(8,3),(6,7)])
def test_mixed_locktimes(num_rtl, use_regtest, bitcoind_d_sim_watch, start_sign, microsd_path,
                         cap_story, goto_home, press_select, pick_menu_item, bitcoind, end_sign,
                         abs_lock, file_tx_signing_done):
    tb, bb = num_rtl
    num_ins = tb + bb
    sequence = SEQUENCE_LOCKTIME_TYPE_FLAG | (512 >> 9)
    use_regtest()
    sim = bitcoind_d_sim_watch
    sim.keypoolrefill(20)
    for i in range(num_ins):
        addr = sim.getnewaddress()
        bitcoind.supply_wallet.sendtoaddress(addr, 1)

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    dest_addr = sim.getnewaddress()  # self-spend
    utxos = sim.listunspent()
    assert len(utxos) == num_ins

    bi = sim.getblockchaininfo()
    blocks = bi["blocks"]
    if abs_lock:
        # absolute locktime smaller then relative
        locktime = blocks + 10
    else:
        locktime = 0

    ins = []
    for i, utxo in enumerate(utxos):
        # time-based RTL
        if i < tb:
            nSeq = sequence
        else:
            confirmations = utxo["confirmations"]
            nSeq = confirmations + 20  # blocks

        inp = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "sequence": nSeq,
        }
        ins.append(inp)

    psbt_resp = sim.walletcreatefundedpsbt(ins, [{dest_addr: (num_ins - 0.1)}], locktime, {"fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "mixed-locktimes.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(0.1)
    title, story = cap_story()
    if 'OK TO SEND' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()

    assert "WARNING" not in story
    assert "TX LOCKTIMES" in story
    assert "Time-based RTL" in story
    t_from_seq = (sequence & 0x0000ffff) << 9
    base_msg = "relative time-based timelock of:\n %s" % seconds2human_readable(t_from_seq)
    msg1 = "%d inputs have " % tb
    assert (msg1 + base_msg) in story
    assert "Block height RTL" in story
    assert ("%d inputs have relative block height timelock of %d" % (bb, 21)) in story

    if abs_lock:
        assert "Abs Locktime" in story
        assert f"This tx can only be spent after block height of {locktime}" in story
    else:
        assert "Abs Locktime" not in story

    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    signed_psbt, signed_txn, story_txid = file_tx_signing_done(story)
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is False

    if abs_lock:
        assert accept_res["reject-reason"] == 'non-final'
    else:
        assert accept_res["reject-reason"] == 'non-BIP68-final'

    # try to mine 21 blocks - which should unlock height based inpputs
    # and also absolute timelock which is smaller than relative
    # but tx must be still unspendable as time based are still locked
    sim.generatetoaddress(21, bitcoind.supply_wallet.getnewaddress())
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is False
    assert accept_res["reject-reason"] == 'non-BIP68-final'

    # mine blocks - mining increases the timestamp but somehow randomly
    while True:
        sim.generatetoaddress(5, bitcoind.supply_wallet.getnewaddress())
        t = sim.getblockchaininfo()["time"]
        if (t - bi["time"]) > 600:
            break
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid

def random_nLockTime_test_cases(num=10):
    res = []
    now = datetime.datetime.utcnow()
    for i in range(num):
        td = datetime.timedelta(days=i, hours=i+i, seconds=7**i)
        var = now + td
        var = var.replace(tzinfo=datetime.timezone.utc)
        res.append((int(var.timestamp()), var.strftime("%Y-%m-%d %H:%M:%S")))
    return res


@pytest.mark.parametrize("nLockTime", [
    (1513209600, "2017-12-14 00:00:00"),
    (1387324800, "2013-12-18 00:00:00"),
    (1294790399, "2011-01-11 23:59:59"),
    (1748671747, "2025-05-31 06:09:07"),
    *random_nLockTime_test_cases()
])
def test_timelocks_visualize(start_sign, end_sign, dev, bitcoind, use_regtest,
                             bitcoind_d_sim_watch, nLockTime, sim_root_dir):
    # - works on simulator and connected USB real-device
    nLockTime, expect_ux = nLockTime
    num_ins = 10
    use_regtest()
    bitcoind_d_sim_watch.keypoolrefill(20)
    for i in range(num_ins):
        addr = bitcoind_d_sim_watch.getnewaddress()
        bitcoind.supply_wallet.sendtoaddress(addr, 1)

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    dest_addr = bitcoind_d_sim_watch.getnewaddress()  # self-spend
    utxos = bitcoind_d_sim_watch.listunspent()
    assert len(utxos) == num_ins

    ins = []
    for i, utxo in enumerate(utxos):
        if i % 2 == 0:
            nSeq = (SEQUENCE_LOCKTIME_TYPE_FLAG | i)
        else:
            confirmations = utxo["confirmations"]
            nSeq = confirmations + (20*i)

        inp = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "sequence": nSeq,
        }
        ins.append(inp)

    psbt_resp = bitcoind_d_sim_watch.walletcreatefundedpsbt(
        ins, [{dest_addr: (num_ins - 0.1)}],
        nLockTime, {"fee_rate": 20}
    )
    psbt = base64.b64decode(psbt_resp.get("psbt"))

    with open(f'{sim_root_dir}/debug/locktimes.psbt', 'wb') as f:
        f.write(psbt)

    # should be able to sign, but get warning

    # use new feature to have Coldcard return the 'visualization' of transaction
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    story = end_sign(accept=None, expect_txn=False)

    story = story.decode('ascii')
    assert datetime.datetime.utcfromtimestamp(nLockTime).strftime("%Y-%m-%d %H:%M:%S") == expect_ux
    assert f"Abs Locktime: This tx can only be spent after {expect_ux} UTC (MTP)" in story
    assert "Block height RTL: 5 inputs have relative block height timelock" in story
    # when i=0 in loop time based RTL is zero
    assert "Time-based RTL: 4 inputs have relative time-based timelock" in story


@pytest.mark.parametrize('in_out', [(4,1),(2,2),(2,1)])
@pytest.mark.parametrize('partial', [False, True])
def test_base64_psbt_qr(in_out, partial, scan_a_qr, readback_bbqr,
                        goto_home, use_regtest, cap_story, fake_txn, dev,
                        decode_psbt_with_bitcoind, decode_with_bitcoind,
                        press_cancel, press_select, need_keypress, sim_root_dir):
    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    num_in, num_out = in_out

    psbt = fake_txn(num_in, num_out, dev.master_xpub, addr_fmt="p2wpkh", psbt_hacker=hack)

    psbt = base64.b64encode(psbt).decode()

    with open(f'{sim_root_dir}/debug/last.psbt', 'w') as f:
        f.write(psbt)

    goto_home()
    need_keypress(KEY_QR)

    scan_a_qr(psbt)

    for r in range(20):
        title, story = cap_story()
        if 'OK TO SEND' in title:
            break
        time.sleep(.1)
    else:
        raise pytest.fail('never saw it?')

    # approve it
    press_select()

    time.sleep(.2)

    file_type, rb = readback_bbqr()
    assert file_type in 'TP'

    if file_type == 'T':
        assert not partial
        decoded = decode_with_bitcoind(rb)
        ic, oc = len(decoded['vin']), len(decoded['vout'])
    else:
        assert file_type == 'P'
        assert partial
        assert rb[0:4] == b'psbt'
        decoded = decode_psbt_with_bitcoind(rb)
        assert not decoded['unknown']
        if 'tx' in decoded:
            # psbt v0
            decoded = decoded['tx']
            ic, oc = len(decoded['vin']), len(decoded['vout'])
        else:
            # expect psbt v2
            ic = decoded["input_count"]
            oc = decoded["output_count"]

    # just smoke test; syntax not content
    assert ic == num_in
    assert oc == num_out

    press_cancel()      # back to menu


def test_sorting_outputs_by_size(fake_txn, start_sign, cap_story, use_testnet,
                                 press_cancel):
    use_testnet()
    out_vals = [1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000,
                9000000, 179989995, 11000000, 12000000, 13000000, 14000000, 15000000]
    max_display_num = 10
    rest_num = len(out_vals) - max_display_num
    psbt = fake_txn(3, [[random.choice(ADDR_STYLES_SINGLE), i] for i in out_vals], addr_fmt="p2wpkh")
    start_sign(psbt)
    time.sleep(.1)
    title, story = cap_story()
    assert title == 'OK TO SEND?'
    rest_sum = 0
    for i, ov in enumerate(sorted(out_vals, reverse=True)):
        str_ov = f'{ov / 100000000:.8f} XTN'
        if i < 10:
            # these must be in story
            assert str_ov in story
        else:
            # these are not covered in story, instead their vals are summed and
            # provided just as rest sum
            assert str_ov not in story
            rest_sum += ov

    # check rest sum is correct
    rest_story = f"plus {rest_num} smaller output(s), not shown here, which total: "
    rest_story += f'{rest_sum / 100000000:.8f} XTN'
    assert rest_story in story
    press_cancel()


@pytest.mark.parametrize("chain", ["BTC", "XTN"])
@pytest.mark.parametrize("data", [
    # (out_style, amount, is_change)
    [("p2tr", 999999, 1)] + [("p2tr", 888888, 0)] * 12,
    [("p2pkh", 1000000, 0)] * 99,
    [("p2wpkh", 1000000, 1),("p2wpkh-p2sh", 800000, 1), ("p2tr", 600000, 1)] * 27,
    [("p2pkh", 1000000, 1)] * 11 + [("p2wpkh", 50000000, 0)] * 16,
    [("p2pkh", 1000000, 1), ("p2wpkh", 50000000, 0), ("p2wpkh-p2sh", 800000, 1), ("p2tr", 100000, 0)] * 11,
])
def test_txout_explorer(chain, data, fake_txn, start_sign, settings_set, txout_explorer,
                        cap_story, pytestconfig):
    # TODO This test MUST be run with --psbt2 flag on and off
    settings_set("chain", chain)

    out_val = sum(d[1] for d in data)  # zero fee
    psbt = fake_txn(1, data, addr_fmt="p2tr", input_amount=out_val,
                    psbt_v2=pytestconfig.getoption('psbt2'))

    start_sign(psbt)
    txout_explorer(data, chain)

@pytest.mark.parametrize("finalize", [True, False])
@pytest.mark.parametrize("data", [
    [(1, b"Coinkite"), (0, b"Mk1 Mk2 Mk3 Mk4 Q"), (100, b"binarywatch.org"), (100, b"a" * 75)],
    [(0, b"a" * 300), (10, b"x" * 1000), (0, b"anchor output")],
    [(0, b""), (10, b"")],
])
def test_txout_explorer_op_return(finalize, data, fake_txn, start_sign, cap_story, is_q1,
                                  need_keypress, press_cancel, press_select, end_sign,
                                  cap_screen_qr):
    outputs = [["p2tr", 50000, not i] for i in range(20)]
    outputs += [["op_return", am, None, d] for am, d in data]
    out_val = sum(o[1] for o in outputs)
    psbt = fake_txn(1, outputs, addr_fmt="p2tr", input_amount=out_val)
    start_sign(psbt, finalize=finalize)
    time.sleep(.1)
    title, story = cap_story()
    assert title == 'OK TO SEND?'
    assert "(1 warning below)" in story
    if len(data) > 1:
        assert ("Multiple OP_RETURN outputs: %d" % len(data)) in story
    else:
        assert "Multiple OP_RETURN outputs" not in story

    if sum(int(len(x[1]) > 80) for x in data):
        assert "OP_RETURN > 80 bytes" in story
    else:
        assert "OP_RETURN > 80 bytes" not in story

    assert "Press (2) to explore txn" in story
    need_keypress("2")
    time.sleep(.1)
    # OP_RETURN is put at the end of output list (fake_txn)
    # 20 normal outputs, all OP_RETURN on last page
    for _ in range(2):
        need_keypress(KEY_RIGHT if is_q1 else "9")

    time.sleep(.1)
    _, story = cap_story()
    ss = story.split("\n\n")

    # collect QR codes first
    need_keypress(KEY_QR if is_q1 else "4")
    qr_list = []
    for _ in range(len(data)):
        qr = cap_screen_qr().decode()
        qr_list.append(qr)
        need_keypress(KEY_RIGHT if is_q1 else "9")
        time.sleep(.5)

    press_cancel()  # QR code on screen - exit

    for i, (sa, sb, (amount, data)) in enumerate(zip(ss[:-1:2], ss[1::2], data), start=20):
        assert f"Output {i}:" == sa
        try:
            val, name, dd = sb.split("\n")
        except:
            dd = None
            val, name, dd0, _, dd1 = sb.split("\n")
        assert "OP_RETURN" in name
        assert f'{amount / 100000000:.8f} XTN' == val
        if dd == "null-data":
            assert qr_list[i - 20] == ""
        elif dd:
            hex_str, ascii_str = dd.split(" ", 1)
            assert hex_str == qr_list[i-20]
            assert f"(ascii: {data.decode()})" == ascii_str
            assert data.hex() == hex_str
        else:
            s = data[:100].hex()
            e = data[-100:].hex()
            assert s == dd0
            assert e == dd1
            qr = qr_list[i - 20]
            assert qr == ""

    press_cancel()  # exit txn out explorer
    end_sign(finalize=finalize)


def test_low_R_grinding(dev, goto_home, microsd_path, press_select, offer_minsc_import,
                        cap_story, try_sign, reset_seed_words, clear_miniscript):
    reset_seed_words()
    clear_miniscript()
    desc = "sh(sortedmulti(2,[6ba6cfd0/45h]tpubD9429UXFGCTKJ9NdiNK4rC5ygqSUkginycYHccqSg5gkmyQ7PZRHNjk99M6a6Y3NY8ctEUUJvCu6iCCui8Ju3xrHRu3Ez1CKB4ZFoRZDdP9/0/*,[747b698e/45h]tpubD97nVL37v5tWyMf9ofh5rznwhh1593WMRg6FT4o6MRJkKWANtwAMHYLrcJFsFmPfYbY1TE1LLQ4KBb84LBPt1ubvFwoosvMkcWJtMwvXgSc/0/*,[7bb026be/45h]tpubD9ArfXowvGHnuECKdGXVKDMfZVGdephVWg8fWGWStH3VKHzT4ph3A4ZcgXWqFu1F5xGTfxncmrnf3sLC86dup2a8Kx7z3xQ3AgeNTQeFxPa/0/*,[0f056943/45h]tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n/0/*))#up0sw2xp"
    # PSBT created via fake_ms_txn, grinded in test_ms_sign_myself
    psbt_fname = "myself-72sig.psbt"
    with open(f"data/{psbt_fname}", "r") as f:
        b64psbt = f.read()

    goto_home()
    passphrase = "Myself"
    dev.send_recv(CCProtocolPacker.bip39_passphrase(passphrase), timeout=None)
    press_select()
    time.sleep(.1)
    title, story = cap_story()

    if 'Seed Vault' in story:
        press_select()
        time.sleep(.1)
        title, story = cap_story()

    assert "[747B698E]" in title
    press_select()

    time.sleep(.1)
    _, story = offer_minsc_import(desc)
    assert "Create new miniscript wallet?" in story \
                or 'Update NAME only of existing multisig' in story
    time.sleep(.1)
    press_select()

    # below raises for 72 bytes long signature
    # only on firmware versions that do only 10 grinding iterations
    try_sign(base64.b64decode(b64psbt), accept=True)

    reset_seed_words()

def test_null_data_op_return(fake_txn, start_sign, end_sign, reset_seed_words):
    reset_seed_words()
    psbt = fake_txn(1, [["p2pkh", 99_999_800], ["op_return", 50, None, b""]])
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    story = end_sign(accept=None, expect_txn=False).decode()
    assert "null-data" in story
    assert "OP_RETURN" in story

def test_smallest_txn(fake_txn, start_sign, end_sign, reset_seed_words, settings_set):
    # serialized txn has just 62 bytes and is the smallest that we support
    # 1 input (iregardless of script type) and 1 zero value null OP_RETURN
    reset_seed_words()
    settings_set("fee_limit", -1)
    psbt = fake_txn(1, [["op_return", 10, None, b""]], addr_fmt="p2tr", input_amount=10)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    story = end_sign(accept=None, expect_txn=False).decode()
    assert "null-data" in story
    assert "OP_RETURN" in story


@pytest.mark.parametrize("num_outs", [1, 12])
@pytest.mark.parametrize("change", [True, False])
def test_zero_value_outputs(num_outs, change, fake_txn, start_sign, end_sign, reset_seed_words,
                            settings_set):
    reset_seed_words()
    # user needs to disable fee limit checks to be able to do this
    settings_set("fee_limit", -1)
    psbt = fake_txn(1, num_outs * [[random.choice(ADDR_STYLES_SINGLE), 0, change]], input_amount=1)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    story = end_sign(accept=None, expect_txn=False).decode()
    assert "Zero Value: Non-standard zero value output(s)." in story
    assert "1 input" in story
    assert f"{num_outs} output{'' if num_outs == 1 else 's'}" in story
    assert 'Network fee 0.00000001 XTN' in story

    if change:
        assert "0.00000000 XTN" in story.split("\n\n")[4]  # change back is zero
        assert "Consolidating 0.00000000 XTN" in story
        assert "Change back" in story
        if num_outs > 1:
            assert "to addresses" in story
        else:
            assert "to address" in story
    else:
        # even
        if num_outs == 12:
            # even tho we do not see 2 outputs, fee is also 0 and 2 smaller not shown here have also value o 0
            assert story.count('0.00000000 XTN') == 12
        else:
            assert story.count('0.00000000 XTN') == 2
        assert "Change back" not in story


@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize("num_ins", [True, False])
def test_zero_value_input(change, num_ins, fake_txn, start_sign, end_sign, reset_seed_words,
                          cap_story):
    # 0 value inputs - not allowed
    reset_seed_words()
    af = random.choice(ADDR_STYLES_SINGLE)
    psbt = fake_txn([[af, None, 0]], [[af, 0, change]], addr_fmt=af, fee=0)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    with pytest.raises(Exception):
        end_sign(accept=None, expect_txn=False).decode()

    _, story = cap_story()
    assert "zero value txn" in story


@pytest.mark.parametrize("num_ins", [1, 12])
@pytest.mark.parametrize("foreign", [True, False])
@pytest.mark.parametrize("change", [True, False])
def test_zero_value_inputs(num_ins, foreign, change, fake_txn, start_sign, end_sign,
                           reset_seed_words):
    # one input is-non zero
    # others are zero  --> allowed
    reset_seed_words()
    af = random.choice(ADDR_STYLES_SINGLE)

    inputs = (num_ins - 1 -int(foreign)) * [[af, None, 0]]
    if foreign:
        inputs += [[af, None, 0, False]]

    inputs += [[af, None, 10000]]  # always one input mine

    psbt = fake_txn(inputs, [[af, 9980, change]], addr_fmt=af, fee=20)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    end_sign(accept=None, expect_txn=False).decode()


def test_negative_amount_inputs(reset_seed_words, fake_txn, start_sign, end_sign, cap_story):
    reset_seed_words()
    af = random.choice(ADDR_STYLES_SINGLE)
    psbt = fake_txn([[af, None, -1000]], [[af, 200]], addr_fmt=af, fee=0)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    with pytest.raises(Exception):
        end_sign(accept=None, expect_txn=False).decode()

    _, story = cap_story()
    assert "negative input value: i0" in story

def test_negative_amount_outputs(reset_seed_words, fake_txn, start_sign, end_sign, cap_story):
    reset_seed_words()
    af = random.choice(ADDR_STYLES_SINGLE)
    psbt = fake_txn([[af, None, 1000]], [[af, -200]], addr_fmt=af, fee=0)
    start_sign(psbt, False, stxn_flags=STXN_VISUALIZE)
    with pytest.raises(Exception):
        end_sign(accept=None, expect_txn=False).decode()

    _, story = cap_story()
    assert "negative output value: o0" in story

def test_mk4_done_signing_infinite_loop(goto_home, try_sign, fake_txn, enable_hw_ux,
                                        settings_get, is_q1):
    if is_q1:
        raise pytest.skip("Irrelevant on Q as it always provides QR option")

    goto_home()
    had_nfc = settings_get("nfc", None)
    had_vdisk = settings_get("vidsk", None)
    enable_hw_ux("nfc", disable=True)
    enable_hw_ux("vdisk", disable=True)
    psbt = fake_txn(1, [["p2wpkh", None, True], []], addr_fmt="p2wpkh")
    try_sign(psbt, accept=True)
    # above never returns in unpatched version and fills up the disk
    if had_nfc:
        enable_hw_ux("nfc")
    if had_vdisk:
        enable_hw_ux("vdisk")


@pytest.mark.bitcoind
def test_finalize_with_foreign_inputs(bitcoind, bitcoind_d_sim_watch, start_sign, end_sign,
                                      cap_story, try_sign_microsd):
    # foreign inputs that have partial sigs filled
    # we still do not care about final_scriptsig & final_scriptwitness PSBT fields
    dest_address = bitcoind.supply_wallet.getnewaddress()
    alice = bitcoind.create_wallet(wallet_name="alice")
    bob = bitcoind.create_wallet(wallet_name="bob")
    cc = bitcoind_d_sim_watch
    alice_addr = alice.getnewaddress()
    bob_addr = bob.getnewaddress()
    cc_addr = cc.getnewaddress()
    # fund all addresses
    for addr in (alice_addr, bob_addr, cc_addr):
        bitcoind.supply_wallet.sendtoaddress(addr, 2.0)

        # mine above sends
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    psbt_list = []
    for w in (alice, bob, cc):
        assert w.listunspent()
        psbt = w.walletcreatefundedpsbt([], [{dest_address: 1.0}], 0, {"fee_rate": 20})["psbt"]
        psbt_list.append(psbt)

    # join PSBTs to one
    the_psbt = bitcoind.supply_wallet.joinpsbts(psbt_list)

    # bitcoin core would just fill finalscriptwitness, we need partial signatures
    # just add dummy signatures and remove
    pp = BasicPSBT().parse(base64.b64decode(the_psbt))
    for i in pp.inputs:
        assert len(i.bip32_paths) == 1  # single sigs
        der = list(i.bip32_paths.values())[0]
        if der[:4].hex().upper() == xfp2str(simulator_fixed_xfp):
            # our key
            continue
        pubkey = list(i.bip32_paths.keys())[0]
        assert not i.part_sigs  # empty
        i.part_sigs[pubkey] = os.urandom(71)  # dummy sig

    # USB works and our signature is added (but only if we do not finalize)
    psbt = pp.as_bytes()
    start_sign(psbt)
    signed = end_sign(accept=True)
    assert signed != psbt
    for i in BasicPSBT().parse(signed).inputs:
        assert i.part_sigs

    try_sign_microsd(psbt, finalize=True, accept=True)
    title, story = cap_story()
    assert title == "PSBT Signed"
    assert "Finalized transaction (ready for broadcast)" in story

# EOF

@pytest.mark.bitcoind
def test_taproot_keyspend(use_regtest, bitcoind_d_sim_watch, start_sign, end_sign, microsd_path, cap_story, goto_home,
                          press_select, pick_menu_item, bitcoind):
    use_regtest()
    sim = bitcoind_d_sim_watch
    sim.keypoolrefill(10)
    addr = sim.getnewaddress("", "bech32m")
    bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    dest_addr = sim.getnewaddress("", "bech32m")  # self-spend
    psbt_resp = sim.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "tr.psbt"
    open('debug/last.psbt', 'w').write(psbt)
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(.1)
    title, story = cap_story()
    if 'OK TO SEND?' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == 'OK TO SEND?'
    assert "Consolidating" in story  # self-spend
    assert " 1 input\n 2 outputs" in story
    addrs = [addr_from_display_format(l) for l in story.split("\n") if l and (l[0] == '\x02')]
    assert len(addrs) == 2
    for addr in addrs:
        assert addr.startswith("bcrt1p")
    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert title == 'PSBT Signed'
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    split_story = story.split("\n\n")
    story_txid = split_story[4].split("\n")[-1]
    signed_psbt_fname = split_story[1]
    with open(microsd_path(signed_psbt_fname), "r") as f:
        signed_psbt = f.read().strip()
    open('debug/last.psbt', 'w').write(psbt)
    signed_txn_fname = split_story[3]
    with open(microsd_path(signed_txn_fname), "r") as f:
        signed_txn = f.read().strip()
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid

    addr_segwit = sim.getnewaddress("", "bech32")
    sim.generatetoaddress(1, addr_segwit)  # mine transaction sent and also new coins to p2wpkh
    addr_nested_segwit = sim.getnewaddress("", "p2sh-segwit")
    sim.generatetoaddress(1, addr_nested_segwit)
    addr_legacy = sim.getnewaddress("", "legacy")
    sim.generatetoaddress(1, addr_legacy)
    # try to sign tx with all input types (legacy, nested segwit, native segwit, taproot)
    all_of_it = sim.getbalance()
    dest_addr0 = sim.getnewaddress("", "bech32m")  # self-spend
    dest_addr1 = sim.getnewaddress("", "bech32m")  # self-spend
    dest_addr2 = sim.getnewaddress("", "bech32m")  # self-spend
    chunk = round(all_of_it / 3, 6)
    psbt_resp = sim.walletcreatefundedpsbt([], [{dest_addr0: chunk}, {dest_addr1: chunk}, {dest_addr2: chunk}],
                                           0, {'subtractFeeFromOutputs': [0], "fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "tr-all.psbt"
    open('debug/last.psbt', 'w').write(psbt)
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(.1)
    title, story = cap_story()
    if 'OK TO SEND?' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == 'OK TO SEND?'
    assert "Consolidating" in story  # self-spend
    assert " 2 inputs\n 3 outputs" in story
    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert title == 'PSBT Signed'
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    split_story = story.split("\n\n")
    story_txid = split_story[4].split("\n")[-1]
    signed_psbt_fname = split_story[1]
    with open(microsd_path(signed_psbt_fname), "r") as f:
        signed_psbt = f.read().strip()
    open('debug/last.psbt', 'w').write(psbt)
    signed_txn_fname = split_story[3]
    with open(microsd_path(signed_txn_fname), "r") as f:
        signed_txn = f.read().strip()
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid

    # multi p2tr output consolidation
    addr_segwit = sim.getnewaddress("", "bech32")
    sim.generatetoaddress(1, addr_segwit)  # mine transaction sent and also new coins to p2wpkh
    all_of_it = sim.getbalance()
    dest_addr = sim.getnewaddress("", "bech32m")
    psbt_resp = sim.walletcreatefundedpsbt([], [{dest_addr: all_of_it}],
                                           0, {'subtractFeeFromOutputs': [0], "fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "tr-multi-out-consolidation.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(.1)
    title, story = cap_story()
    if 'OK TO SEND?' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == 'OK TO SEND?'
    assert "Consolidating" in story  # self-spend
    assert " 3 inputs\n 1 output" in story
    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert title == 'PSBT Signed'
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    split_story = story.split("\n\n")
    story_txid = split_story[4].split("\n")[-1]
    signed_psbt_fname = split_story[1]
    with open(microsd_path(signed_psbt_fname), "r") as f:
        signed_psbt = f.read().strip()
    open('debug/last.psbt', 'w').write(psbt)
    signed_txn_fname = split_story[3]
    with open(microsd_path(signed_txn_fname), "r") as f:
        signed_txn = f.read().strip()
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid

    # send it all to bob, he's a good guy
    bob_w = bitcoind.create_wallet("bob")
    dst = bob_w.getnewaddress("", "bech32m")
    all_of_it = sim.getbalance()
    psbt_resp = sim.walletcreatefundedpsbt([], [{dst: all_of_it}],
                                           0, {'subtractFeeFromOutputs': [0], "fee_rate": 20})
    psbt = psbt_resp.get("psbt")
    psbt_fname = "tr2bob.psbt"
    with open(microsd_path(psbt_fname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item('Ready To Sign')
    time.sleep(.1)
    title, story = cap_story()
    if 'OK TO SEND?' not in title:
        pick_menu_item(psbt_fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == 'OK TO SEND?'
    assert "Consolidating" not in story  # NOT a self-spend
    assert "to address" in story
    assert dst in story
    press_select()  # confirm signing
    time.sleep(0.1)
    title, story = cap_story()
    assert title == 'PSBT Signed'
    assert "Updated PSBT is:" in story
    assert "Finalized transaction (ready for broadcast)" in story
    assert "TXID" in story
    split_story = story.split("\n\n")
    story_txid = split_story[4].split("\n")[-1]
    signed_psbt_fname = split_story[1]
    with open(microsd_path(signed_psbt_fname), "r") as f:
        signed_psbt = f.read().strip()
    signed_txn_fname = split_story[3]
    with open(microsd_path(signed_txn_fname), "r") as f:
        signed_txn = f.read().strip()
    assert signed_psbt != psbt
    finalize_res = sim.finalizepsbt(signed_psbt)
    bitcoind_signed_txn = finalize_res["hex"]
    assert finalize_res["complete"] is True
    accept_res = sim.testmempoolaccept([bitcoind_signed_txn])[0]
    assert accept_res["allowed"] is True
    assert signed_txn == bitcoind_signed_txn
    txid = sim.sendrawtransaction(signed_txn)
    assert len(txid) == 64
    assert txid == story_txid


@pytest.mark.parametrize('fn_err_msg', [
    ('data/taproot/in_internal_key_len.psbt', 'PSBT_IN_TAP_INTERNAL_KEY length != 32'),
    ('data/taproot/in_key_pth_sig_len.psbt', 'PSBT_IN_TAP_KEY_SIG length != 64 or 65'),
    ('data/taproot/in_key_pth_sig_len1.psbt', 'PSBT_IN_TAP_KEY_SIG length != 64 or 65'),
    ('data/taproot/in_tr_deriv_key_len.psbt', 'PSBT_IN_TAP_BIP32_DERIVATION xonly-pubkey length != 32'),
    ('data/taproot/in_script_sig_key_len.psbt', 'PSBT_IN_TAP_SCRIPT_SIG key length != 64'),
    ('data/taproot/in_script_sig_sig_len.psbt', 'PSBT_IN_TAP_SCRIPT_SIG signature length != 64 or 65'),
    ('data/taproot/in_script_sig_sig_len1.psbt', 'PSBT_IN_TAP_SCRIPT_SIG signature length != 64 or 65'),
    ('data/taproot/in_leaf_script_cb_len.psbt', 'PSBT_IN_TAP_LEAF_SCRIPT control block is not valid'),
    ('data/taproot/in_leaf_script_cb_len1.psbt', 'PSBT_IN_TAP_LEAF_SCRIPT control block is not valid'),
])
def test_invalid_input_taproot_psbt(start_sign, fn_err_msg, cap_story):
    fn, err_msg = fn_err_msg
    start_sign(fn)

    title, story = cap_story()
    assert title == "Failure"
    assert 'Invalid PSBT' in story
    # error messages are disabled to save some space - problem file line is still included
    # assert err_msg in story


def test_invalid_output_taproot_psbt(fake_txn, start_sign, cap_story, dev):
    psbt = fake_txn(3, [[],["p2tr", None, True]], master_xpub=dev.master_xpub, addr_fmt="p2tr")
    # invalid internal key length
    psbt_obj = BasicPSBT().parse(psbt)
    for o in psbt_obj.outputs:
        o.taproot_internal_key = b"\x03" + b"a" * 32
    psbt0 = BytesIO()
    psbt_obj.serialize(psbt0)
    start_sign(psbt0.getvalue())
    title, story = cap_story()
    assert title == "Failure"
    assert 'Invalid PSBT' in story
    # error messages are disabled to save some space - problem file line is still included
    # assert "PSBT_OUT_TAP_INTERNAL_KEY length != 32" in story

    # invalid internal key length in bip32 taproot paths
    psbt_obj = BasicPSBT().parse(psbt)
    for o in psbt_obj.outputs:
        o.taproot_bip32_paths = {b"\x03" + b"a" * 32: 12 * b"1"}
    psbt0 = BytesIO()
    psbt_obj.serialize(psbt0)
    start_sign(psbt0.getvalue())
    title, story = cap_story()
    assert title == "Failure"
    assert 'Invalid PSBT' in story
    # error messages are disabled to save some space - problem file line is still included
    # assert "PSBT_IN_TAP_BIP32_DERIVATION xonly-pubkey length != 32" in story
