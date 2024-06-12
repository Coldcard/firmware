# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test decoders.py code (unit test)
#
#
import pytest
from binascii import a2b_hex, b2a_hex
from base64 import b64encode
from urllib.parse import urlparse, parse_qs


from mnemonic import Mnemonic
wordlist = Mnemonic('english').wordlist

@pytest.fixture
def try_decode(sim_exec):
    def doit(arg, ):
        cmd = "from decoders import decode_qr_result;  " + \
                    f"RV.write(repr(decode_qr_result({arg!r})))"

        result = sim_exec(cmd)
        if 'Traceback' in result:
            raise RuntimeError(result)

        try:
            return eval(result)
        except SyntaxError:
            if '<' in result:
                # objects, like "<HexStreamer..."
                result = result.replace('<', "'").replace('>', "'")
                return eval(result)

            raise

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
        expect_addr = a2.lower()
    else:
        expect_addr = a1

    ft, vals = try_decode(url)
    assert ft == 'addr'
    proto, addr, args =  vals
    assert addr == expect_addr
    assert proto == ('bitcoin' if bip21 else None)

    p = urlparse(url)
    assert (p.path == addr) or (p.path.lower() == addr.lower())

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

    cmd = "from utils import url_decode;  " + \
                f"RV.write(url_decode({url!r}))"
    result = sim_exec(cmd)

    assert result == unquote_plus(url)


@pytest.mark.parametrize('config', [
    '0f056943: tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP\n6ba6cfd0: tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm',
    '0f056943: xpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP\n6ba6cfd0: tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm',
    '   0F056943   : tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP\n   6BA6CFD0  : tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm',
    ' 0AA5684E:ypub6URBiWBdvF4h7SSjejyy1Wmabo2RvKvoqHzD3sJXqbX8gGcdGvkofMSCuwThopEPZzaczYwSLVg2AMoS6hW8YNuwxYMtLhYokuqA2LHeiD7\n00000000:zpub6oFT2ArZ4vcAxjdrV6mbDbs5mmAsrwvJkQWRqGCRDbu1jNRrXavNHR6Lw9RHoitJydhRk2XzoA2a3eQzpPv9LcbYpt4JvcNJ2dtoQxConEW',
    '00000000:zpub6oFT2ArZ4vcAxjdrV6mbDbs5mmAsrwvJkQWRqGCRDbu1jNRrXavNHR6Lw9RHoitJydhRk2XzoA2a3eQzpPv9LcbYpt4JvcNJ2dtoQxConEW\n\nafafafaf: Zpub6z9Y9QazdtAYPJoERmEa3gCtVZD95Jbu4gA6kXTxbNjRMYzmHzJeNXxGjrNmNA7DD6mQccY7gNR5Ap2m7d56V6iDfMAiL1qHvNAfzo3Qaun',
    ' afafafaf: Zpub6z9Y9QazdtAYPJoERmEa3gCtVZD95Jbu4gA6kXTxbNjRMYzmHzJeNXxGjrNmNA7DD6mQccY7gNR5Ap2m7d56V6iDfMAiL1qHvNAfzo3Qaun\n\n\n11111111:Ypub6fKGqjv5VCd4Y1c7bQSwqb7PKb4h8gcQ9Zdsy8a5DNMYJTBY3L95kUJ8ieRBNFTHoTebs8wZDi4XHXRCPvf5gs2co1UHk71oee72cFcNrrt',
    '11111111:Ypub6fKGqjv5VCd4Y1c7bQSwqb7PKb4h8gcQ9Zdsy8a5DNMYJTBY3L95kUJ8ieRBNFTHoTebs8wZDi4XHXRCPvf5gs2co1UHk71oee72cFcNrrt\na0a0a0a0:  Upub5MzDd5EQtUT98pqeFyJT1EjNdiUuNCeQV7YzqYzXhLr263vd2hUqGDfadpaqNcqcAuBNsEZKP4eKkNxwX912VvJDKegbQTjrZjrT3zJRqB4',
    'a0a0a0a0:  Upub5MzDd5EQtUT98pqeFyJT1EjNdiUuNCeQV7YzqYzXhLr263vd2hUqGDfadpaqNcqcAuBNsEZKP4eKkNxwX912VvJDKegbQTjrZjrT3zJRqB4\n7BB026BE:  Vpub5gpUvjuL39zcz82m6L65DKpsogdMJpduQE5DcwtR5MDu99jrHMePtHKif2YRNXVXaYJBci9sqizsdfaWEqR3J9ypBzP1zNZLqTv6SXYWTR8',
    '7BB026BE:  Vpub5gpUvjuL39zcz82m6L65DKpsogdMJpduQE5DcwtR5MDu99jrHMePtHKif2YRNXVXaYJBci9sqizsdfaWEqR3J9ypBzP1zNZLqTv6SXYWTR8\n0AA5684E:ypub6URBiWBdvF4h7SSjejyy1Wmabo2RvKvoqHzD3sJXqbX8gGcdGvkofMSCuwThopEPZzaczYwSLVg2AMoS6hW8YNuwxYMtLhYokuqA2LHeiD7',
])
def test_multisig(config, try_decode):

    ft, vals = try_decode(config)

    assert ft == "multi"
    assert vals[0] == config

@pytest.mark.parametrize('desc', [
    'wsh(sortedmulti(2,[0f056943/48h/1h/0h/2h]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[6ba6cfd0/48h/1h/0h/2h]tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm/0/*,[747b698e/48h/1h/0h/2h]tpubDExj5FnaUnPAn7sHGUeBqD3buoNH5dqmjAT6884vbDpH1iDYWigb7kFo2cA97dc8EHb54u13TRcZxC4kgRS9gc3Ey2xc8c5urytEzTcp3ac/0/*,[7bb026be/48h/1h/0h/2h]tpubDFiuHYSJhNbHcbLJoxWdbjtUcbKR6PvLq53qC1Xq6t93CrRx78W3wcng8vJyQnY3giMJZEgNCRVzTojLb8RqPFpW5Ms2dYpjcJYofN1joyu/0/*))#al5z7mcj',
    'wsh(or_d(pk([5155f1fa/44h/1h/0h]tpubDCtts5PqRUpJZaRegaWEGTULHp9XbFVsmrxQ38bAXf291HfmnTuDdeeXgyi59ywvRzaAmE8hiFZMVEv7KyGnH5YVBK3SDK625Huv4uoTsWZ/<0;1>/*),and_v(v:pkh([0f056943/84h/0h/0h]tpubDCx8y86cKonoPyTtj3f9NZLpBYoBNkbAzUdafMHhggjxkhF8Dny2aekWfDafywEMZEQaQjkK9Gxn7aN7usLRUQdYbvDgcnmYRf72khPEouL/<0;1>/*),older(5))))#sraf9nwn',
    'wsh(or_d(pk([d7beb757/44h/1h/0h]tpubDCKMUppLh1DJkSgbp9dmKaMwHyBQwrmLzxgwz8J7obXnFEaWneGyMZymyLra1PBjDyqBUE9JmPVyn33QCgXwkeAniz3LCXXTpw8YFe6edjk/0/*),and_v(v:pkh([0f056943/84h/0h/0h]tpubDCx8y86cKonoPyTtj3f9NZLpBYoBNkbAzUdafMHhggjxkhF8Dny2aekWfDafywEMZEQaQjkK9Gxn7aN7usLRUQdYbvDgcnmYRf72khPEouL/<0;1>/*),older(5))))',
    '{"name":"a","desc":"wsh(or_d(pk([d7beb757/44h/1h/0h]tpubDCKMUppLh1DJkSgbp9dmKaMwHyBQwrmLzxgwz8J7obXnFEaWneGyMZymyLra1PBjDyqBUE9JmPVyn33QCgXwkeAniz3LCXXTpw8YFe6edjk/0/*),and_v(v:pkh([0f056943/84h/0h/0h]tpubDCx8y86cKonoPyTtj3f9NZLpBYoBNkbAzUdafMHhggjxkhF8Dny2aekWfDafywEMZEQaQjkK9Gxn7aN7usLRUQdYbvDgcnmYRf72khPEouL/<0;1>/*),older(5))))"}',
])
def test_miniscript_descriptors(desc, try_decode):
    # includes multisig
    ft, vals = try_decode(desc)
    assert ft == "minisc"
    assert vals[0] == desc

@pytest.mark.parametrize('data', [
    ('5J9Gfy2FNTw2EpkkQu41S9CTBBVij123kYPkbYAnaQkUHtMuv2Q', False, False),
    ('L2TgtddYM9ueK2auJVkNaNEF3egMMK1MTMkng5RBAcBWXnCMnxcb', True, False),
    ('cUfNdkyMXhggsqB1FvijAQ9ETcZrGdLEtzbdsWdSRUtVLHPGPpak', True, True),
    ('92DhqVmmSAhyhW8HzgL8DDGFn2ZH6fk1wh9mEK4fjNn8f7mJyAC', False, True),
])
def test_wif(data, try_decode):
    wif, compressed, testnet = data
    ft, vals = try_decode(wif)

    assert ft == "wif"
    twif, _, tcompressed, ttestnet = vals[0]
    assert wif == twif
    assert compressed == tcompressed
    assert testnet == ttestnet

# EOF
