# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test decoders.py code (unit test)
#
#
import pytest
from binascii import a2b_hex, b2a_hex
from base64 import b64encode
from urllib.parse import urlparse, parse_qs
from helpers import prandom

from mnemonic import Mnemonic
wordlist = Mnemonic('english').wordlist

@pytest.fixture
def try_decode(sim_exec):
    def doit(arg):
        cmd = "from decoders import decode_qr_result;  " + \
                    f"RV.write(repr(decode_qr_result({arg!r})))"

        result = sim_exec(cmd)

        if 'Traceback' in result:
            raise RuntimeError(result)

        if '<' in result:
            # objects, like "<HexStreamer..."
            result = result.replace('<', "'").replace('>', "'")

        return eval(result)
    return doit

@pytest.mark.parametrize('fname,expect', [
    ( 'data/p2pkh+p2sh+outs.psbt', 'psbt'),
    ( 'data/snight-example.psbt', 'psbt'),
    ( 'data/devils-txn.txn', 'txn'),
])
@pytest.mark.parametrize('encoding', ['hex', 'b64'])
def test_detector_bin(fname, expect, encoding, try_decode):

    # NOTE: input files must be hex to start
    arg = a2b_hex(open(fname, 'rt').read().strip())
    
    if encoding == 'hex':
        arg = b2a_hex(arg).decode()
    elif encoding == 'b64':
        arg = b64encode(arg).decode()
    else:
        raise ValueError

    ft, vals = try_decode(arg)
    assert ft == expect
    

@pytest.mark.parametrize('url', [
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R',
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?label=Luke-Jr',
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?amount=20.3&label=Luke-Jr',
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz',
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999',
'bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?somethingyoudontunderstand=50&somethingelseyoudontget=999',
])
@pytest.mark.parametrize('bip21', range(2))
@pytest.mark.parametrize('addr_fmt', range(2))
def test_detector_url(url, bip21, addr_fmt, try_decode):
    a1, a2 = ('mtHSVByP9EYZmB26jASDdPVm19gvpecb5R',
                            'BCRT1QUPYD58NDSH7LUT0ET0VTRQ432JVU9JTDX8FGYV')

    if not bip21:
        _, url = url.split(':', 1)
    if addr_fmt:
        url = url.replace(a1, a2)
        expect_addr = a2
    else:
        expect_addr = a1

    ft, vals = try_decode(url)
    assert ft == 'addr'
    proto, addr, args =  vals
    assert addr == expect_addr
    assert proto == ('bitcoin' if bip21 else None)

    p = urlparse(url)
    assert p.path == addr

    xargs = parse_qs(p.query)
    if args:
        assert xargs.keys() == args.keys()
    else:
        assert not xargs


@pytest.mark.parametrize('num_words', [12, 18, 24])
@pytest.mark.parametrize('encoding', ['short', 'long', 'seed_qr'])
@pytest.mark.parametrize('case', range(2))
def test_detector_secrets(num_words, encoding, case, try_decode):

    n = [(i*179)% 2048 for i in range(num_words)]

    words = [wordlist[i] for i in n]
    expect = list(words)

    if encoding == 'seed_qr':
        if case: return
        qr = ''.join('%04d'%i for i in n)
    else:
        
        if encoding == 'short':
            words = [w[0:4] for w in words]
        if case:
            words = [w.upper() for w in words]

        qr = ' '.join(words)
        
    ft, vals = try_decode(qr)
    assert ft == 'words'
    got_words, = vals
    assert got_words == expect
    
@pytest.mark.parametrize('code', [
    'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb',
    'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
])
def test_detector_xp(code, try_decode):

    ft, vals = try_decode(code)

    assert ft == code[0:4]
    assert vals[0] == code


@pytest.mark.parametrize('url', [
    'sldkfjslk%20d%40fj',
    'to+sp%65ce+ed',
    # add some more cases?
])
def test_urldecode(url, sim_exec):
    from urllib.parse import unquote_plus

    cmd = "from decoders import url_decode;  " + \
                f"RV.write(url_decode({url!r}))"
    result = sim_exec(cmd)

    assert result == unquote_plus(url)
    

# EOF
