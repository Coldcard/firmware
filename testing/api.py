# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Access a local bitcoin-Qt/bitcoind on testnet
#
# Must have these lines in the bitcoin.conf file:
#
#   testnet=1
#   server=1
#
import pytest, os
from bitcoinrpc.authproxy import AuthServiceProxy
from base64 import b64encode, b64decode

URL = '127.0.0.1:18332'

def get_cookie():
    # read local bitcoind cookie .. highly mac-only
    AUTHFILE = '~/Library/Application Support/Bitcoin/testnet3/.cookie'

    try:
        cookie = open(os.path.expanduser(AUTHFILE), 'rt').read().strip()
    except FileNotFoundError:
        raise pytest.skip('no local bitcoind')

    return cookie

@pytest.fixture(scope='function')
def bitcoind():
    # JSON-RPC connection to a bitcoind instance

    # see <https://github.com/jgarzik/python-bitcoinrpc>
    cookie = get_cookie()

    conn = AuthServiceProxy('http://' + cookie + '@' + URL)

    assert conn.getblockchaininfo()['chain'] == 'test'

    return conn

@pytest.fixture
def match_key(bitcoind, set_master_key, reset_seed_words):
    # load simulator w/ existing bip32 master key of testnet instance

    # bummer: dumpmasterprivkey RPC call was removed!
    #prv = bitcoind.dumpmasterprivkey()

    def doit():
        print("match_key: doit()")
        from tempfile import mktemp
        fn = mktemp()
        bitcoind.dumpwallet(fn)
        prv = None

        for ln in open(fn, 'rt').readlines():
            if 'extended private masterkey' in ln:
                assert not prv
                prv = ln.split(": ", 1)[1].strip()

        os.unlink(fn)

        assert prv.startswith('tprv')

        xfp = set_master_key(prv)

        return xfp

    # NOTE: set_master_key does teardown/reset
    return doit

@pytest.fixture()
def bitcoind_finalizer(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt, extract=True):

        rv = bitcoind.finalizepsbt(b64encode(psbt).decode('ascii'), extract)

        return b64decode(rv.get('psbt', '')), rv.get('hex'), rv['complete']

    return doit

@pytest.fixture()
def bitcoind_analyze(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt):
        return bitcoind.analyzepsbt(b64encode(psbt).decode('ascii'))

    return doit

@pytest.fixture()
def bitcoind_decode(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt):
        return bitcoind.decodepsbt(b64encode(psbt).decode('ascii'))

    return doit

@pytest.fixture()
def explora():
    def doit(*parts):
        import urllib.request
        import json
        url = 'https://blockstream.info/testnet/api/' + '/'.join(parts)
        with urllib.request.urlopen(url) as response:
           return json.load(response)

    return doit


@pytest.fixture(scope='function')
def bitcoind_wallet(bitcoind):
    # Use bitcoind to create a temporary wallet file, and then do cleanup after
    # - wallet will not have any keys, and is watch only
    import os, shutil

    fname = '/tmp/ckcc-test-wallet-%d' % os.getpid()

    disable_private_keys = True
    blank = True
    w = bitcoind.createwallet(fname, disable_private_keys, blank)

    assert w['name'] == fname

    # give them an object they can do API calls w/ rpcwallet filled-in
    cookie = get_cookie()
    url = 'http://' + cookie + '@' + URL + '/wallet/' + fname.replace('/', '%2f')
    #print(url)
    conn = AuthServiceProxy(url)
    assert conn.getblockchaininfo()['chain'] == 'test'

    yield conn

    # cleanup
    bitcoind.unloadwallet(fname)
    assert fname.startswith('/tmp/ckcc-test-wallet')
    shutil.rmtree(fname)


# EOF
