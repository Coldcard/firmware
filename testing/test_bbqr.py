# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BBQr and secure notes.
#
import pytest, time, random, base64
from helpers import prandom
from binascii import a2b_hex
from bbqr import split_qrs, join_qrs
from charcodes import KEY_QR
from base64 import b32decode, b32encode

# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1, is_headless):
    if not is_q1 or is_headless:
        raise pytest.skip('Q1 only (not headless)')

@pytest.fixture
def readback_bbqr_ll(cap_screen_qr, sim_exec, cap_screen):
    # low level version
    def doit():
        num_parts = None
        encoding, file_type = None, None
        parts = {}

        for retries in range(1000):
            #time.sleep(0.05)       # not really sync'ed
            try:
                rb = cap_screen_qr(no_history=True).decode('ascii')
            except RuntimeError:
                time.sleep(0.1)
                x = cap_screen()
                assert 'Yikes' not in x, x
                continue

            #print(rb[0:20]+'...')

            if len(rb) > 2 and rb[0:2] != 'B$':
                # it sent a non-BBQr QR which isn't wrong.. but let caller decode
                return 0, None, None, rb

            assert rb[0:2] == 'B$'
            if not encoding:
                encoding = rb[2]
            else:
                assert encoding == rb[2]

            if not file_type:
                file_type = rb[3]
            else:
                assert file_type == rb[3]

            if num_parts is None:
                num_parts = int(rb[4:6], 36)
                assert num_parts >= 1
            else:
                assert num_parts == int(rb[4:6], 36)

            part = int(rb[6:8], 36)
            assert part < num_parts

            if part in parts:
                if parts[part] != rb:
                    print(f"Wrong-read on part {part}")
                    continue
            else:
                parts[part] = rb

            if len(parts) >= num_parts:
                break

        if len(parts) != num_parts:
            # timed out
            raise pytest.fail(f'Could not read all parts of BBQr: '\
                                f'got {[parts.keys()]} of {num_parts}')

        return num_parts, encoding, file_type, parts

    return doit

@pytest.fixture
def readback_bbqr(readback_bbqr_ll):
    # give back just the decoded data and file_type
    def doit():
        import json

        num_parts, encoding, file_type, parts = readback_bbqr_ll()

        if num_parts == 0:
            # not sent as BBQr .. assume Hex, else base32 but PSBT would be BBQr
            # - but might be text too
            try:
                rb = a2b_hex(parts)
                if rb[0:5] == b'psbt\xff':
                    file_type = 'P'
                else:
                    file_type = 'T'
            except:
                if parts[0] == '{' and parts[-1] == '}':
                    file_type = 'J'
                else:
                    file_type = 'U'
                rb = parts      # already a string
        else:
            _, rb = join_qrs(parts.values())

        assert rb[0:2] != 'B$'

        return file_type, rb

    return doit
    
@pytest.fixture
def render_bbqr(need_keypress, cap_screen_qr, sim_exec, readback_bbqr_ll):
    def doit(data=None, str_expr=None, file_type='B', msg=None, setup=''):
        assert data or str_expr

        if data:
            data = repr(data)
        else:
            assert str_expr
            data = str_expr

        num_parts = None
        cmd = f'{setup};' if setup else ''
        cmd += f'import ux_q1,main; main.TT = asyncio.create_task(ux_q1.show_bbqr_codes'\
                        f'("{file_type}", {data}, {msg!r}));'
        print(f"CMD: {cmd}")
        try:
            resp = sim_exec(cmd)
            print(f"RESP: {resp}")
            assert 'error' not in resp.lower()

            num_parts, encoding, rb_ft, parts = readback_bbqr_ll()
            assert rb_ft == file_type

        finally:
            print(sim_exec(f'import main; main.TT.cancel()'))
            need_keypress('0')      # for menu to redraw

        # we only can decode simple BBQr here
        assert encoding in 'HZ2'
        _, body = join_qrs(parts.values())

        if file_type == 'U':
            body = body.decode('utf-8')

        return body, parts

    return doit


@pytest.fixture
def split_scan_bbqr(scan_a_qr, goto_home, need_keypress):

    # take big data and send it via series of BBQr thru emulated scanner
    def doit(raw_data, type_code, **kws):
        goto_home()
        need_keypress(KEY_QR)

        # def split_qrs(raw, type_code, encoding=None,
        #  min_split=1, max_split=1295, min_version=5, max_version=40
        actual_vers, parts = split_qrs(raw_data, type_code, **kws)
        random.shuffle(parts)

        for p in parts:
            scan_a_qr(p)
            time.sleep(2.0 / len(parts))  # just so we can watch

    return doit

@pytest.fixture
def try_sign_bbqr(cap_story, scan_a_qr, press_select, press_cancel, need_keypress,
                  readback_bbqr, split_scan_bbqr):
    def doit(psbt, type_code="P", approve=True, nfc_push_tx=False, **kws):

        split_scan_bbqr(psbt, type_code, **kws)

        for r in range(20):
            title, story = cap_story()
            if 'OK TO SEND' in title:
                break
            time.sleep(.1)
        else:
            raise pytest.fail('never saw it?')

        if not approve:
            press_cancel()
            return

        # approve it
        press_select()

        if nfc_push_tx:
            return psbt, None, None

        time.sleep(.2)

        # expect signed txn back
        file_type, rb = readback_bbqr()
        assert file_type in 'TP'
        return psbt, file_type, rb

    return doit

@pytest.mark.parametrize('size', [ 1, 20, 990, 2060*2,  5000, 65537] )
def test_show_bbqr_sizes(size, cap_screen_qr, sim_exec, render_bbqr):
    # test lengths
    data, parts = render_bbqr(str_expr=f"'a'*{size}", msg=f'Size {size}', file_type='U')

    if size < 330:
        assert len(parts) == 1 
    assert len(data) == size
    assert data == 'a' * size

    ft, data2 = join_qrs(parts.values())
    assert data2.decode('utf-8') == data
    assert ft == 'U'

@pytest.mark.parametrize('src', [ 'rng', 'gpu', 'bigger'] )
def test_show_bbqr_contents(src, cap_screen_qr, sim_exec, render_bbqr, load_shared_mod, src_root_dir):

    args = dict(msg=f'Test {src}', file_type='B')
    if src == 'rng':
        args['data'] = expect = prandom(500)        # limited by simulated USB path
    elif src in { 'gpu', 'bigger' }:
        args['setup'] = 'from gpu_binary import BINARY'
        cc_gpu_bin = load_shared_mod('cc_gpu_bin', f'{src_root_dir}/shared/gpu_binary.py')
        if src == 'gpu':
            args['str_expr'] = 'BINARY'
            expect = cc_gpu_bin.BINARY
        elif src == 'bigger':
            args['str_expr'] = 'BINARY*10'
            expect = cc_gpu_bin.BINARY*10

    data, parts = render_bbqr(**args)

    assert len(data) == len(expect)
    assert data == expect
    ft, data2 = join_qrs(parts.values())
    assert data2 == data
    assert ft == 'B'

@pytest.mark.bitcoind
@pytest.mark.reexport
@pytest.mark.parametrize('size', [ 2, 10 ] )
@pytest.mark.parametrize('max_ver', [ 20 ] )        # 20 max due to 4k USB buffer limit
@pytest.mark.parametrize('encoding', '2HZ' )
@pytest.mark.parametrize('partial', [False, True])
@pytest.mark.parametrize('base64str', [False, True])
@pytest.mark.parametrize('segwit', [True, False])
def test_bbqr_psbt(size, encoding, max_ver, partial, segwit, scan_a_qr, readback_bbqr,
                   cap_screen_qr, render_bbqr, goto_home, use_regtest, cap_story,
                   decode_psbt_with_bitcoind, decode_with_bitcoind, fake_txn, dev,
                   start_sign, end_sign, press_cancel, press_select, need_keypress,
                   base64str, try_sign_bbqr, signing_artifacts_reexport, sim_root_dir):

    num_in = size
    num_out = size*10

    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    if not segwit:
        psbt = fake_txn(num_in, num_out, dev.master_xpub, psbt_hacker=hack)
    else:
        psbt = fake_txn(num_in, num_out, dev.master_xpub, psbt_hacker=hack,
                            segwit_in=True, outstyles=['p2wpkh'])
    if base64str:
        psbt = base64.b64encode(psbt).decode()

    with open(f'{sim_root_dir}/debug/last.psbt', 'w' if base64str else 'wb') as f:
        f.write(psbt)

    _, file_type, rb = try_sign_bbqr(psbt, type_code="U" if base64str else "P",
                                  max_version=max_ver, encoding=encoding)

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
    _psbt, _txn = signing_artifacts_reexport("qr", tx_final=not partial,
                                             encoding="binary")
    if partial:
        assert _psbt == rb
    else:
        assert _txn == rb

@pytest.mark.parametrize('test_size', [7854, 4592,
    758, 375, 465,       # v15 capacity
    1853, 922, 1150,      # v25
    2520, 1256, 1570,     # v30 (unlikely)
    4296, 2144, 2680,     # v40
])
@pytest.mark.parametrize('encoding', '2H')
def test_split_unit(test_size, encoding, sim_exec, sim_eval):
    # unit test for: bbqr.test_split_unit()

    for multi in [1, 2, 5]:
        for fuzz in range(-10, 11):
            size = (test_size * multi) + fuzz
            if size < 1: continue

            cmd = f'import bbqr; RV.write(repr(bbqr.num_qr_needed( {encoding!r}, {size} )))'
            print(f"CMD: {cmd}")
            resp = sim_exec(cmd)
            print(f"RESP: {resp}")
            assert 'error' not in resp.lower()

            target_ver, num_parts, part_size = eval(resp)

            assert num_parts * part_size >= size
            assert (num_parts-1) * part_size < size

            if size == 7854 and encoding == '2':
                assert target_ver == 25
                assert num_parts == 7

            if size == 4592 and encoding == '2':
                assert target_ver == 15
                assert num_parts == 10

            if encoding == 'H':
                assert 1 <= part_size <= 2144
            elif encoding == '2':
                assert 1 <= part_size <= 2680 

            assert 15 <= target_ver <= 40
            if num_parts > 12:
                assert target_ver == 40


@pytest.mark.bitcoind
@pytest.mark.parametrize("file", [
    "data/sim_conso.psbt",
    "data/sim_conso1.psbt",
    "data/sim_conso2.psbt",
    "data/sim_conso3.psbt",
    "data/sim_conso4.psbt",
    "data/sim_conso5.psbt",
])
def test_psbt_static(file, goto_home, cap_story, scan_a_qr, press_select,
                     readback_bbqr, need_keypress, press_cancel, start_sign,
                     end_sign, bitcoind, try_sign_bbqr):
    # final tx qrs are versions 23,24,25

    with open(file, "rb") as f:
        psbt = f.read()

    _, file_type, rb = try_sign_bbqr(psbt, type_code="P", max_version=20, encoding="2")

    press_cancel()      # back to menu

    # now verify signed tx are correct with bitcoind
    # sign it first
    start_sign(psbt)
    signed_psbt = end_sign(True)
    res = bitcoind.supply_wallet.finalizepsbt(base64.b64encode(signed_psbt).decode())
    assert res["complete"] is True
    assert rb.hex() == res["hex"]


def test_verify_signed_msg(goto_home, need_keypress, scan_a_qr, cap_story):
    goto_home()
    need_keypress(KEY_QR)

    data = """\n\n\n  \t  \n-----BEGIN BITCOIN SIGNED MESSAGE-----
5b9e372262952ed399dcdd4f5f08458a6d2811f120cddcb4267099f68f60207c  addresses.csv
-----BEGIN BITCOIN SIGNATURE-----
tb1qupyd58ndsh7lut0et0vtrq432jvu9jtdyws9n9
KDOloGMDU3fv+Y3NRSe17SoO4uSKo9IUU2+baJ/pqaHZBuvmW6j5nnv/N4M5BCVawiUig/qzExZpFsA7ZKzlUmU=
-----END BITCOIN SIGNATURE-----\n\n\n\n"""

    actual_vers, parts = split_qrs(data, 'U', max_version=20)

    for p in parts:
        scan_a_qr(p)
        time.sleep(4.0 / len(parts))       # just so we can watch

    title, story = cap_story()
    assert "Good signature by address" in story

@pytest.mark.qrcode
@pytest.mark.manual
@pytest.mark.parametrize("i", range(1,25))
def test_qr_sizes(i, dev, fake_txn, press_cancel, cap_screen_qr, try_sign_bbqr):

    # QRs from version 10 to version 25, everything from v26(included) and above is BBQR
    # only v17 contains 2 lines of txid
    psbt = fake_txn(1, i, dev.master_xpub, segwit_in=True, outstyles=['p2wpkh'])

    try_sign_bbqr(psbt, type_code="P")
    cap_screen_qr()
    press_cancel()

# EOF
