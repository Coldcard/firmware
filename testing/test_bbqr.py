# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BBQr and secure notes.
#

import pytest, os, time
from helpers import B2A
from binascii import b2a_hex, a2b_hex

@pytest.mark.parametrize('size', [ 20, 990] )
def XXX_test_show_bbqr_codes(size, sim_execfile, need_keypress, cap_screen_qr, sim_exec):
    sim_exec('import main; main.BBQR_SIZE = %r; ' % size)
    rv = sim_execfile('devtest/bbqr.py')
    assert 'Error' not in rv
    readback = cap_screen_qr()
    assert readback == 'sdf'
    
@pytest.fixture
def render_bbqr(need_keypress, cap_screen_qr, sim_exec):
    def doit(data=None, str_expr=None, file_type='B', msg=None):
        assert data or str_expr

        if data:
            data = repr(data)
        else:
            assert str_expr
            data = str_expr

        num_parts = None
        sim_exec(f'import ux_q1, main; main.TT = asyncio.create_task(ux_q1.show_bbqr_codes'\
                    f'("{file_type}", {data}, {msg!r}));')

        num_parts = None
        encoding = None
        parts = {}
        for retries in range(200):
            time.sleep(0.005)       # not really sync'ed
            try:
                rb = cap_screen_qr().decode('ascii')
            except RuntimeError:
                time.sleep(0.1)
                continue

            print(rb[0:20])
            assert rb[0:2] == 'B$'
            if not encoding:
                encoding = rb[2]
            else:
                assert encoding == rb[2]
            assert rb[3] == file_type

            if num_parts is None:
                num_parts = int(rb[4:6], 36)
                assert num_parts >= 1
            else:
                assert num_parts == int(rb[4:6], 36)
            part = int(rb[6:8], 36)
            assert part < num_parts

            parts[part] = rb

            if len(parts) >= num_parts:
                break

        print(sim_exec(f'import main; main.TT.cancel()'))

        need_keypress('\r')
        need_keypress('0')      # for menu to redraw

        if len(parts) != num_parts:
            # timed out
            raise pytest.fail(f'Could not read all parts of BBQr: got {[parts.keys()]} of {num_parts}')

        # we only can decode simple BBQr here
        assert encoding == 'H'
        body = a2b_hex(''.join(p[8:] for p in [parts[i] for i in range(num_parts)]))

        if file_type == 'U':
            body = body.decode('utf-8')

        return body, parts

    return doit

@pytest.mark.parametrize('size', [ 20, 990, 5000] )
def test_show_bbqr_codes(size, need_keypress, cap_screen_qr, sim_exec, render_bbqr):
    data, parts = render_bbqr(str_expr=f"'a'*{size}", msg=f'Size {size}', file_type='U')
    if size < 2000:
        assert len(parts) == 1 
    assert data == 'a' * size

# EOF
