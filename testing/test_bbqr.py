# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BBQr and secure notes.
#

import pytest, time, random
from helpers import prandom
from binascii import a2b_hex
from bbqr import split_qrs, join_qrs
from charcodes import KEY_QR

# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1):
    if not is_q1:
        raise pytest.skip('Q1 only')

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
                assert parts[part] == rb
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
        num_parts, encoding, file_type, parts = readback_bbqr_ll()

        if num_parts == 0:
            # not sent as BBQr .. assume Hex
            rb = a2b_hex(parts)
            file_type = 'P' if rb[0:4] == b'psbt' else 'T'
        else:
            _, rb = join_qrs(parts.values())

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
def test_show_bbqr_contents(src, cap_screen_qr, sim_exec, render_bbqr, load_shared_mod):

    args = dict(msg=f'Test {src}', file_type='B')
    if src == 'rng':
        args['data'] = expect = prandom(500)        # limited by simulated USB path
    elif src in { 'gpu', 'bigger' }:
        args['setup'] = 'from gpu_binary import BINARY'
        cc_gpu_bin = load_shared_mod('cc_gpu_bin', '../shared/gpu_binary.py')
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

@pytest.mark.parametrize('size', [ 2, 10 ] )
@pytest.mark.parametrize('max_ver', [ 20 ] )        # 20 max due to 4k USB buffer limit
@pytest.mark.parametrize('encoding', '2HZ' )
@pytest.mark.parametrize('partial', [False, True])
@pytest.mark.parametrize('segwit', [True, False])
def test_bbqr_psbt(size, encoding, max_ver, partial, segwit, scan_a_qr, readback_bbqr,
                   cap_screen_qr, render_bbqr, goto_home, use_regtest, cap_story,
                   decode_psbt_with_bitcoind, decode_with_bitcoind, fake_txn, dev,
                   start_sign, end_sign, press_cancel, press_select, need_keypress):

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
    open('debug/last.psbt', 'wb').write(psbt)

    goto_home()
    need_keypress(KEY_QR)

    # def split_qrs(raw, type_code, encoding=None, 
    #  min_split=1, max_split=1295, min_version=5, max_version=40
    actual_vers, parts = split_qrs(psbt, 'P',  max_version=max_ver, encoding=encoding)
    random.shuffle(parts)

    for p in parts:
        scan_a_qr(p)
        time.sleep(4.0 / len(parts))       # just so we can watch

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

    # expect signed txn back
    file_type, rb = readback_bbqr()
    assert file_type in 'TP'

    if file_type == 'T':
        assert not partial
        decoded = decode_with_bitcoind(rb)
    elif file_type == 'P':
        assert partial
        assert rb[0:4] == b'psbt'
        decoded = decode_psbt_with_bitcoind(rb)
        assert not decoded['unknown']
        decoded = decoded['tx']

    # just smoke test; syntax not content
    assert len(decoded['vin']) == num_in
    assert len(decoded['vout']) == num_out

    press_cancel()      # back to menu

@pytest.mark.parametrize('size', [7854, 4592, 375,465, 922,1150 ] + list(range(1, (12*2680), 197)))
@pytest.mark.parametrize('encoding', '2H')
def test_split_unit(size, encoding, sim_exec, sim_eval):
    # unit test for: bbqr.test_split_unit()

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

# EOF
