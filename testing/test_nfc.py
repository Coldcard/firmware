# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Mk4 NFC feature related tests.
#
# - many test "sync" issues here; case is right but gets outs of sync with DUT
# - use `./simulator.py --eff --set nfc=1`
#
import pytest, time, io, shutil, json, os, random
from binascii import b2a_hex, a2b_hex
from struct import pack, unpack
import ndef
from hashlib import sha256
from txn import *
from charcodes import KEY_NFC, KEY_QR

    
@pytest.mark.parametrize('case', range(6))
def test_ndef(case, load_shared_mod):
    # NDEF unit tests -- runs in cpython

    def get_body(efile):
        # unwrap CC_FILE and cruft
        assert efile[-1] == 0xfe
        assert efile[0] == 0xE2
        st = len(cc_ndef.CC_FILE)
        if efile[st] == 0xff:
            xl = unpack('>H', efile[st+1:st+3])[0]
            st += 3
        else:
            xl = efile[st]
            st += 1
        body = efile[st:-1]
        assert len(body) == xl
        return body

    def decode(msg):
        return list(ndef.message_decoder(get_body(msg)))

    cc_ndef = load_shared_mod('cc_ndef', '../shared/ndef.py')
    n = cc_ndef.ndefMaker()

    if case == 0:
        n.add_text("Hello world")

        got, = decode(n.bytes())
        assert got.type == 'urn:nfc:wkt:T'
        assert got.text == 'Hello world'
        assert got.language == 'en'
        assert got.encoding == 'UTF-8'

    elif case == 1:
        n.add_text("Hello world")
        n.add_url("store.coinkite.com/store/coldcard")
        
        txt,url = decode(n.bytes())
        assert txt.text == 'Hello world'

        assert url.type == 'urn:nfc:wkt:U'
        assert url.uri == 'https://store.coinkite.com/store/coldcard' == url.iri

    elif case == 2:
        hx = b2a_hex(bytes(range(32)))
        n.add_text("Title")
        n.add_custom('bitcoin.org:sha256', hx)

        txt,sha = decode(n.bytes())
        assert txt.text == 'Title'
        assert sha.data == hx

    elif case == 3:
        psbt = b'psbt\xff' + bytes(5000)
        n.add_text("Title")
        n.add_custom('bitcoin.org:psbt', psbt)
        n.add_text("Footer")

        txt,p,ft = decode(n.bytes())
        assert txt.text == 'Title'
        assert ft.text == 'Footer'
        assert p.data == psbt
        assert p.type == 'urn:nfc:ext:bitcoin.org:psbt'

    elif case == 4:
        hx = b2a_hex(bytes(range(32)))
        n.add_custom('bitcoin.org:txid', hx)
        got, = decode(n.bytes())
        assert got.type == 'urn:nfc:ext:bitcoin.org:txid'
        assert got.data == hx

    elif case == 5:
        hx = bytes(2000)
        n.add_custom('bitcoin.org:txn', hx)
        got, = decode(n.bytes())
        assert got.type == 'urn:nfc:ext:bitcoin.org:txn'
        assert got.data == hx

@pytest.mark.parametrize('ccfile', [
    'E1 40 80 09  03 10  D1 01 0C 55 01 6E 78 70 2E 63 6F 6D 2F 6E 66 63 FE 00', 
    'E1 40 40 00  03 2A   D1012655016578616D706C652E636F6D2F74656D703D303030302F746170636F756E7465723D30303030FE000000',
    b'\xe1@@\x00\x03*\xd1\x01&U\x01example.com/temp=0000/tapcounter=0000\xfe\x00\x00\x00',
    'rx',
    'short',
    'long',
])
def test_ndef_ccfile(ccfile, load_shared_mod):
    # NDEF unit tests

    def decode(body):
        return list(ndef.message_decoder(body))

    cc_ndef = load_shared_mod('cc_ndef', '../shared/ndef.py')

    txt_msg = None
    if ccfile == 'rx':
        ccfile = cc_ndef.CC_WR_FILE
    elif ccfile == 'short':
        n = cc_ndef.ndefMaker()
        txt_msg = "this is a test"
        n.add_text(txt_msg)
        ccfile = n.bytes()
    elif ccfile == 'long':
        n = cc_ndef.ndefMaker()
        txt_msg = "t" * 600
        n.add_text(txt_msg)
        ccfile = n.bytes()
    elif isinstance(ccfile, str):
        ccfile = a2b_hex(ccfile.replace(' ', ''))
    
    st, ll, is_wr, mlen = cc_ndef.ccfile_decode(ccfile[0:16])
    assert ccfile[st+ll] == 0xfe
    body = ccfile[st:st+ll]
    ref = decode(body)

    if ll == 0: return      # empty we can't parse

    got = list(cc_ndef.record_parser(body))

    for r,g in zip(ref, got):
        assert r.type == g[0]
        urn, data, meta = g
        if r.type == 'urn:nfc:wkt:U':
            assert r.data == bytes([meta['prefix']]) + bytes(data)
        if r.type == 'urn:nfc:wkt:T':
            assert data == r.text.encode('utf-8')
            assert meta['lang'] == 'en'
            if txt_msg:
                assert data == txt_msg.encode('utf-8')


@pytest.fixture
def try_sign_nfc(cap_story, pick_menu_item, goto_home, need_keypress,
                 sim_exec, nfc_read, nfc_write, nfc_block4rf, press_select,
                 press_cancel, press_nfc):

    # like "try_sign" but use NFC to send/receive PSBT/results

    sim_exec('from pyb import SDCard; SDCard.ejected = True; import nfc; nfc.NFCHandler.startup()')

    def doit(f_or_data, accept=True, expect_finalize=False, accept_ms_import=False,
             complete=False, encoding='binary', over_nfc=True, nfc_tools=False, nfc_push_tx=False):

        if f_or_data[0:5] == b'psbt\xff':
            ip = f_or_data
            filename = 'memory'
        else:
            filename = f_or_data
            ip = open(f_or_data, 'rb').read()
            if ip[0:10] == b'70736274ff':
                ip = a2b_hex(ip.strip())
            assert ip[0:5] == b'psbt\xff'

        if encoding == 'hex':
            ip = b2a_hex(ip)
            recs = [ndef.TextRecord(ip)]
        elif encoding == 'base64':
            from base64 import b64encode
            ip = b64encode(ip)
            recs = [ndef.TextRecord(ip)]
        else:
            assert encoding == 'binary'
            recs = [ndef.Record(type='urn:nfc:ext:bitcoin.org:psbt', data=ip),
                    ndef.Record(type='urn:nfc:ext:bitcoin.org:sha256', data=sha256(ip).digest()),
                    ndef.TextRecord('some text'),
            ]

        with open('debug/nfc-sent.psbt', 'wb') as f:
            f.write(ip)

        # wrap in a CCFile 
        serialized = b''.join(ndef.message_encoder(recs))
        ccfile = bytearray([0xE2, 0x43, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00,   0x03])
        if len(serialized) > 250:
            ccfile.extend(b'\xff' + pack('>H', len(serialized)))
        else:
            ccfile.append(len(serialized))
        ccfile.extend(serialized)
        ccfile.append(0xfe)

        time.sleep(.2)      # required
        goto_home()
        if nfc_tools:
            pick_menu_item("Advanced/Tools")
            pick_menu_item("NFC Tools")
            pick_menu_item("Sign PSBT")
        else:
            pick_menu_item('Ready To Sign')

            time.sleep(.1)
            _, story = cap_story()
            assert 'NFC' in story

            press_nfc()
            time.sleep(.1)

        nfc_write(ccfile)
            
        time.sleep(.5)
        
        if accept_ms_import:
            # would be better to do cap_story here
            press_select()
            time.sleep(0.050)

        title, story = cap_story()
        assert title == 'OK TO SEND?'

        if accept is not None:
            if accept:
                press_select()
            else:
                press_cancel()

        if not accept:
            time.sleep(0.050)

            # look for "Aborting..." ??
            return ip, None, None

        time.sleep(.1)
        if nfc_push_tx:
            return ip, None, None

        if not over_nfc:
            # wait for it to finish
            for r in range(10):
                time.sleep(0.1)
                title, story = cap_story()
                if title == 'PSBT Signed': break
            else:
                assert False, 'timed out'

            txid = None
            lines = story.split('\n')
            if 'Final TXID:' in lines:
                txid = lines[-1]

            press_nfc()
            time.sleep(.1)
            contents = nfc_read()
            press_select()
        else:
            nfc_block4rf()
            contents = nfc_read()
            press_select()
            txid = None

        got_txid = None
        got_txn = None
        got_psbt = None
        got_hash = None
        for got in ndef.message_decoder(contents):
            if got.type == 'urn:nfc:wkt:T':
                assert 'Transaction' in got.text or 'PSBT' in got.text
                if 'Transaction' in got.text and txid:
                    assert b2a_hex(txid).decode() in got.text
            elif got.type == 'urn:nfc:ext:bitcoin.org:txid':
                got_txid = b2a_hex(got.data).decode('ascii')
            elif got.type == 'urn:nfc:ext:bitcoin.org:txn':
                got_txn = got.data
            elif got.type == 'urn:nfc:ext:bitcoin.org:psbt':
                got_psbt = got.data
            elif got.type == 'urn:nfc:ext:bitcoin.org:sha256':
                got_hash = got.data
            else:
                raise ValueError(got.type)

        assert got_psbt or got_txn, 'no data?'
        assert got_hash
        assert got_hash == sha256(got_psbt or got_txn).digest()

        if got_txid and not txid:
            # Txid not shown in pure NFC case
            txid = got_txid

        if got_txid:
            assert got_txn
            assert got_txid == txid
            assert expect_finalize
            result = got_txn
            open("debug/nfc-result.txn", 'wb').write(result)
        else:
            assert not expect_finalize
            result = got_psbt

            open("debug/nfc-result.psbt", 'wb').write(result)

        if 0:
            # check output encoding matches input
            if encoding == 'hex' or finalize:
                result = a2b_hex(result.strip())
            elif encoding == 'base64':
                result = b64decode(result)
            else:
                assert encoding == 'binary'

        # read back final product
        if got_txn:
            from ctransaction import CTransaction
            # parse it a little
            assert result[0:4] != b'psbt'
            t = CTransaction()
            t.deserialize(io.BytesIO(got_txn))
            assert t.nVersion in [1, 2]
            assert t.txid().hex() == txid

        if got_psbt:
            assert got_psbt[0:5] == b'psbt\xff'

            from psbt import BasicPSBT
            was = BasicPSBT().parse(ip) 
            now = BasicPSBT().parse(got_psbt)
            assert was.txn == now.txn
            assert was != now

        return ip, (got_psbt or got_txn), txid

    yield doit

    # cleanup / restore
    sim_exec('from pyb import SDCard; SDCard.ejected = False')

@pytest.mark.parametrize('num_outs', [ 1, 20, 250])
def test_nfc_after(num_outs, fake_txn, try_sign, nfc_read, need_keypress,
                   cap_story, is_q1, press_nfc, press_cancel):
    # Read signing result (transaction) over NFC, decode it.
    psbt = fake_txn(1, num_outs)
    orig, result = try_sign(psbt, accept=True, finalize=True)

    too_big = len(result) > 8000

    if too_big: assert num_outs > 100
    if num_outs > 100: assert too_big

    time.sleep(.1)
    title, story = cap_story()
    assert 'TXID' in title, story
    txid = a2b_hex(story.split()[0])
    assert f'Press {KEY_NFC if is_q1 else "(3)"}' in story
    press_nfc()
    time.sleep(.2)

    if too_big:
        title, story = cap_story()
        assert 'is too large' in story
        return

    contents = nfc_read()
    press_cancel()

    #print("contents = " + B2A(contents))
    for got in ndef.message_decoder(contents):
        if got.type == 'urn:nfc:wkt:T':
            assert 'Transaction' in got.text
            assert txid.hex() in got.text
        elif got.type == 'urn:nfc:ext:bitcoin.org:txid':
            assert got.data == txid
        elif got.type == 'urn:nfc:ext:bitcoin.org:txn':
            assert got.data == result
        elif got.type == 'urn:nfc:ext:bitcoin.org:sha256':
            assert got.data == sha256(result).digest()
        else:
            raise ValueError(got.type)

@pytest.mark.unfinalized            # iff partial=1
@pytest.mark.parametrize('encoding', ['binary', 'hex', 'base64'])
@pytest.mark.parametrize('num_outs', [1,2])
@pytest.mark.parametrize('partial', [1, 0])
def test_nfc_signing(encoding, num_outs, partial, try_sign_nfc, fake_txn, dev):
    xp = dev.master_xpub

    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    psbt = fake_txn(2, num_outs, xp, segwit_in=True, psbt_hacker=hack)

    _, txn, txid = try_sign_nfc(psbt, expect_finalize=not partial, encoding=encoding)

def test_rf_uid(rf_interface, cap_story, goto_home, pick_menu_item):
    # read UID of NFC chip over the air
    sw, ident = rf_interface.apdu(0xff, 0xca)       # PAPDU_GET_UID
    assert sw == '0x9000'
    assert ident[-2:] == b'\x02\xe0'        # ST vendor
    assert len(ident) == 8
    uid = ''.join('%02x'%i for i in reversed(ident))

    # check UI is reporting same value
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Upgrade')
    pick_menu_item('Show Version')
    _, story = cap_story()

    assert uid in story
    print(uid)


def test_ndef_roundtrip(load_shared_mod):
    # specific failing case
    cc_ndef = load_shared_mod('cc_ndef', '../shared/ndef.py')

    r = open('data/ms-import.ndef', 'rb').read()

    assert cc_ndef.ccfile_decode(r) == (12, 399, False, 4096)


@pytest.mark.parametrize('multisig', [True, False])
@pytest.mark.parametrize('num_outs', [2, 5, 100, 250])
@pytest.mark.parametrize('chain', ['BTC', 'XTN'])
@pytest.mark.parametrize('way', ['sd', 'nfc', 'usb', 'qr'])
def test_nfc_pushtx(num_outs, chain, enable_nfc, settings_set, settings_remove,
                    try_sign, fake_txn, nfc_block4rf, nfc_read, press_cancel,
                    cap_story, cap_screen, has_qwerty, way, try_sign_microsd,
                    try_sign_nfc, scan_a_qr, need_keypress, press_select,
                    goto_home, multisig, fake_ms_txn, import_ms_wallet,
                    clear_ms, try_sign_bbqr):
    # check the NFC push Tx feature, validating the URL's it makes
    # - not the UX
    # - 100 outs => 5000 or so
    # - 250 outs => 8800
    # - not too many inputs so faster to sign
    from base64 import urlsafe_b64decode
    from urllib.parse import urlsplit, parse_qsl, unquote

    clear_ms()
    settings_set('chain', chain)

    enable_nfc()

    if way in ("nfc", "qr") and num_outs >= 100:
        raise pytest.skip("too big")

    prefix = 'http://10.0.0.10/pushtx#'
    settings_set('ptxurl', prefix)

    if multisig:
        goto_home()
        # create 1 of 3 multiig wallet - no need for another signers to make tx final
        M, N = 1, 3
        keys = import_ms_wallet(M, N, random.choice(["p2wsh", "p2sh-p2wsh", "p2sh"]),
                                name="ms_pushtx", accept=True, way=way, netcode=chain,
                                force_unsort_ms=random.getrandbits(1))
        psbt = fake_ms_txn(2, num_outs, M, keys)
    else:
        psbt = fake_txn(2, num_outs)

    if way == "usb":
        _, result = try_sign(psbt, finalize=True)
    elif way == "sd":
        ip, result, txid = try_sign_microsd(psbt, finalize=True, nfc_push_tx=True)
    elif way == "nfc":
        if len(psbt) > 1000:
            pytest.skip("too big")

        ip, result, txid = try_sign_nfc(psbt, expect_finalize=True, nfc_tools=True,
                                        nfc_push_tx=True, encoding="hex")
    elif way == "qr":
        try_sign_bbqr(psbt, nfc_push_tx=True)

    # print(f'len = {len(result)}')
    #
    if num_outs >= 250:
        # NFC will not be offered (too big)
        time.sleep(.1)
        title, story = cap_story()
        if way == "usb":
            assert title == 'Final TXID'
            assert 'to share signed txn' in story
        elif way == "sd":
            assert title == "PSBT Signed"
        else:
            assert False
        return

    # expect NFC animation
    nfc_block4rf()

    if has_qwerty:
        scr = cap_screen()
        assert 'TXID:' in scr

    contents = nfc_read()

    print(f'nfc contents = {len(contents)}')

    press_cancel()  # exit NFC animation

    # expect a single record, a URL
    got, = ndef.message_decoder(contents)

    assert got.type == 'urn:nfc:wkt:U'
    assert got.uri.startswith(prefix)
    assert got.uri.startswith(prefix + 't')

    parts = urlsplit(got.uri)
    args = parse_qsl(unquote(parts.fragment))

    assert args[0][0] == 't', 'txn must be first'
    assert args[1][0] == 'c', 'checksum next'

    if len(args) == 3:
        assert args[2][0] == 'n', 'block chain'
        assert chain == args[2][1]
    else:
        assert len(args) == 2
        assert chain == 'BTC'

    args = dict(args)
    assert len(args['c']) == 11
    decoded_txn = urlsafe_b64decode(args['t'] + '=====')
    decoded_chk = urlsafe_b64decode(args['c'] + '=====')
    assert len(decoded_chk) == 8

    expect = sha256(decoded_txn).digest()[-8:]
    assert expect == decoded_chk

    settings_remove('ptxurl')
    settings_set('chain', 'XTN')


@pytest.mark.parametrize("is_hex", [True, False])
def test_share_by_pushtx(goto_home, cap_story, pick_menu_item, settings_set,
                         settings_remove, microsd_path, cap_menu, has_qwerty,
                         cap_screen, press_cancel, enable_nfc, nfc_block4rf,
                         nfc_read, is_hex):

    enable_nfc()

    fake_txn = b'\x02\0\0\0\0\0\0' + (b'Ab'*500)

    prefix = 'http://10.0.0.10/pushtx#'
    settings_set('ptxurl', prefix)

    fname = "fake-nfc.txn"
    with open(microsd_path(fname), "wb") as f:
        f.write(b2a_hex(fake_txn) if is_hex else fake_txn)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item('NFC Tools')
    pick_menu_item('Push Transaction')
    time.sleep(0.1)
    pick_menu_item(fname)
    time.sleep(0.1)

    # expect NFC animation
    nfc_block4rf()

    if has_qwerty:
        scr = cap_screen()
        assert 'File:' in scr
        assert fname in scr

    contents = nfc_read()

    press_cancel()

    # hacky quick check
    from base64 import urlsafe_b64encode

    assert b't='+urlsafe_b64encode(fake_txn).rstrip(b'=')+b'&c=' in contents

    settings_remove('ptxurl')

@pytest.mark.parametrize("fname,mode,ftype", [
    ("ccbk-start.json", "r", "J"),
    ("ckcc-backup.txt", "r", "U"),
    ("devils-txn.txn", "rb", "T"),
    ("example-change.psbt", "rb", "P"),
    ("sim_conso5.psbt", "rb", "P"),  # binary psbt
    ("payjoin.psbt", "rb", "P"),  # base64 string in file
    ("worked-unsigned.psbt", "rb", "P"),  # hex string psbt
    ("coldcard-export.json", "rb", "J"),
    ("coldcard-export.sig", "r", "U"),
])
def test_nfc_share_files(fname, mode, ftype, nfc_read_json, nfc_read_text,
                         need_keypress, goto_home, pick_menu_item, is_q1,
                         cap_menu, nfc_read, nfc_block4rf, press_select):
    goto_home()
    fpath = "data/" + fname
    shutil.copy2(fpath, '../unix/work/MicroSD')
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("NFC File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    time.sleep(.1)
    if ftype == "J":
        contents = nfc_read_json()
    elif ftype == "U":
        contents = nfc_read_text()
    else:
        nfc_block4rf()
        res = nfc_read()

        got_txid = None
        got_txn = None
        got_psbt = None
        got_hash = None
        for got in ndef.message_decoder(res):
            if got.type == 'urn:nfc:wkt:T':
                assert 'Transaction' in got.text or 'PSBT' in got.text
            elif got.type == 'urn:nfc:ext:bitcoin.org:txid':
                got_txid = b2a_hex(got.data).decode('ascii')
            elif got.type == 'urn:nfc:ext:bitcoin.org:txn':
                got_txn = got.data
            elif got.type == 'urn:nfc:ext:bitcoin.org:psbt':
                got_psbt = got.data
            elif got.type == 'urn:nfc:ext:bitcoin.org:sha256':
                got_hash = got.data
            else:
                raise ValueError(got.type)

        if fname.endswith(".psbt"):
            contents = bytes(got_psbt)
            assert got_hash
        else:
            contents = bytes(got_txn)

    time.sleep(.1)
    press_select()

    with open(fpath, mode) as f:
        res = f.read()

    if fname.endswith(".txn"):
        res = bytes.fromhex(res.decode())
    if fname.endswith(".json"):
        res = json.loads(res)

    assert res == contents
    os.remove('../unix/work/MicroSD/' + fname)

# EOF
