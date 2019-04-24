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

URL = '127.0.0.1:18332'
AUTHFILE = '~/Library/Application Support/Bitcoin/testnet3/.cookie'

@pytest.fixture(scope='session')
def bitcoind():
    # JSON-RPC connection to a bitcoind instance

    try:
        cookie = open(os.path.expanduser(AUTHFILE), 'rt').read().strip()
    except FileNotFoundError:
        raise pytest.skip('no local bitcoind')

    # see <https://github.com/jgarzik/python-bitcoinrpc>

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

# EOF
