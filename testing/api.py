# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# needs local bitcoind in PATH

import os, time, uuid, atexit, socket, shutil, pytest, tempfile, subprocess
from authproxy import AuthServiceProxy, JSONRPCException
from base64 import b64encode, b64decode


def find_bitcoind():
    # search for the binary we need
    # - should be in the path really
    easy = shutil.which('bitcoind')
    if easy:
        return easy
    
    # - default landing spot for MacOS .dmg from bitcoin.org
    mac_default = '/Applications/Bitcoin-Qt.app/Contents/MacOS/Bitcoin-Qt'
    if os.path.exists(mac_default):
        return mac_default

    raise RuntimeError("Need a binary for bitcoin core. Check path?")

# stolen from HWI test suite and slightly modified
class Bitcoind:
    def __init__(self):
        self.bitcoind_path = find_bitcoind()
        self.datadir = tempfile.mkdtemp()
        self.rpc = None
        self.bitcoind_proc = None
        self.userpass = None
        self.supply_wallet = None

    def start(self):

        def get_free_port():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", 0))
            s.listen(1)
            port = s.getsockname()[1]
            s.close()
            return port

        self.p2p_port = get_free_port()
        self.rpc_port = get_free_port()

        self.bitcoind_proc = subprocess.Popen(
            [
                self.bitcoind_path,
                "-regtest",
                f"-datadir={self.datadir}",
                "-noprinttoconsole",
                "-fallbackfee=0.0002",
                "-server=1",
                "-keypool=1",
                f"-port={self.p2p_port}",
                f"-rpcport={self.rpc_port}"
            ]
        )

        atexit.register(self.cleanup)

        # Wait for cookie file to be created
        cookie_path = os.path.join(self.datadir, "regtest", ".cookie")
        for i in range(20):
            if not os.path.exists(cookie_path):
                time.sleep(0.5)
        else:
            RuntimeError("'.cookie' not found. Is bitcoind running?")
        # Read .cookie file to get user and pass
        with open(cookie_path) as f:
            self.userpass = f.readline().lstrip().rstrip()
        self.rpc_url = f"http://{self.userpass}@127.0.0.1:{self.rpc_port}"
        self.rpc = AuthServiceProxy(self.rpc_url)

        # Wait for bitcoind to be ready
        ready = False
        while not ready:
            try:
                self.rpc.getblockchaininfo()
                ready = True
            except JSONRPCException:
                time.sleep(0.5)
                pass

        assert self.rpc.getblockchaininfo()['chain'] == 'regtest'
        assert self.rpc.getnetworkinfo()['version'] >= 220000, "we require >= 22.0 of Core"
        # not descriptors so that we can do dumpwallet
        self.supply_wallet = self.create_wallet(wallet_name="supply", descriptors=False)
        # Make sure there are blocks and coins available
        self.supply_wallet.generatetoaddress(101, self.supply_wallet.getnewaddress())

    def get_wallet_rpc(self, wallet):
        url = self.rpc_url + f"/wallet/{wallet}"
        return AuthServiceProxy(url)

    def create_wallet(self, wallet_name: str, disable_private_keys: bool = False, blank: bool = False,
                      passphrase: str = None, avoid_reuse: bool = False, descriptors: bool = True,
                      load_on_startup: bool = False, external_signer: bool = False) -> AuthServiceProxy:
        """Create wallet and return AuthServiceProxy object to that wallet"""
        self.rpc.createwallet(wallet_name=wallet_name, disable_private_keys=disable_private_keys,
                              blank=blank, passphrase=passphrase, avoid_reuse=avoid_reuse,
                              descriptors=descriptors, load_on_startup=load_on_startup,
                              external_signer=external_signer)
        return self.get_wallet_rpc(wallet_name)

    def cleanup(self):
        if self.bitcoind_proc is not None and self.bitcoind_proc.poll() is None:
            self.bitcoind_proc.kill()
        shutil.rmtree(self.datadir)

    def delete_wallet_files(self, pattern=None):
        wallets_dir = os.path.join(self.datadir, "regtest/wallets")
        wallet_files = os.listdir(wallets_dir)
        for wf in wallet_files:
            abs_path = os.path.join(wallets_dir, wf)
            if pattern is None:
                # remove all
                shutil.rmtree(abs_path)
            else:
                if pattern in wf:
                    shutil.rmtree(abs_path)

    @staticmethod
    def create(*args, **kwargs):
        c = Bitcoind(*args, **kwargs)
        c.start()
        return c


@pytest.fixture(scope='session')
def bitcoind():
    # JSON-RPC connection to a bitcoind instance
    # this assumes that you have bitcoind in path somewhere
    bitcoin_d = Bitcoind.create()
    return bitcoin_d


@pytest.fixture
def match_key(bitcoind, set_master_key, reset_seed_words):
    # load simulator w/ existing bip32 master key of testnet instance

    # bummer: dumpmasterprivkey RPC call was removed!
    #prv = bitcoind.dumpmasterprivkey()

    def doit():
        print("match_key: doit()")
        from tempfile import mktemp
        fn = mktemp()
        bitcoind.supply_wallet.dumpwallet(fn)
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


@pytest.fixture
def bitcoind_finalizer(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt, extract=True):

        rv = bitcoind.rpc.finalizepsbt(b64encode(psbt).decode('ascii'), extract)
        return b64decode(rv.get('psbt', '')), rv.get('hex'), rv['complete']

    return doit


@pytest.fixture
def bitcoind_analyze(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt):
        return bitcoind.rpc.analyzepsbt(b64encode(psbt).decode('ascii'))

    return doit


@pytest.fixture
def bitcoind_decode(bitcoind):
    # Use bitcoind to finalize a PSBT and get out txn

    def doit(psbt):
        return bitcoind.rpc.decodepsbt(b64encode(psbt).decode('ascii'))

    return doit


@pytest.fixture
def bitcoind_wallet(bitcoind):
    # Use bitcoind to create a temporary wallet file
    w_name = 'ckcc-test-wallet-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=False)
    return conn


@pytest.fixture
def bitcoind_d_wallet(bitcoind):
    # Use bitcoind to create a temporary DESCRIPTOR-based wallet file
    w_name = 'ckcc-test-desc-wallet-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    return conn


@pytest.fixture
def bitcoind_d_wallet_w_sk(bitcoind):
    # Use bitcoind to create a temporary DESCRIPTOR-based wallet file
    w_name = 'ckcc-test-desc-wallet-w-sk-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=False, blank=False,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    return conn


@pytest.fixture
def bitcoind_d_sim_watch(bitcoind):
    # watch only descriptor wallet simulator
    w_name = 'ckcc-test-desc-wallet-sim-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    descriptors = [
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943",
            "active": True,
            "desc": "wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)#erexmnep",
            "internal": False},
        {
            "desc": "wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/1/*)#ghu8xxfe",
            "active": True,
            "internal": True,
            "timestamp": "now"
        }
    ]
    conn.importdescriptors(descriptors)
    return conn

@pytest.fixture
def bitcoind_d_sim_sign(bitcoind):
    # Use bitcoind to create a clone of simulator wallet with private keys
    w_name = 'ckcc-test-desc-wallet-sim-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=False, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    # below is simulator descriptor wallet
    descriptors = [
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943",
            "active": True,
            "desc": "wpkh([0f056943/84h/1h/0h]tprv8fRh8AYC5iQitbbtzwVaUUyXVZh3Y7HxVYSbqzf45eao9SMfEc3MexJx4y6pU1WjjxcEiYArEjhRTSy5mqfXzBtSncTYhKfxQWywcfeqxFE/0/*)#mzg0pna0",
            "internal": False
        },
        {
            "timestamp": "now",
            "active": True,
            "desc": "wpkh([0f056943/84h/1h/0h]tprv8fRh8AYC5iQitbbtzwVaUUyXVZh3Y7HxVYSbqzf45eao9SMfEc3MexJx4y6pU1WjjxcEiYArEjhRTSy5mqfXzBtSncTYhKfxQWywcfeqxFE/1/*)#2kdwuxdh",
            "internal": True
        },
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943",
            "active": True,
            "desc": "pkh([0f056943/44h/1h/0h]tprv8g2F84LJV3jWVuWyDZB4EwHGwe8esEG8H6Gxn4CCdNgQTrtH7CMywCmwzuMGZjz13sQ9rcCZucCm6i2zigkYGSPUvCzDQxGW8RCy7FpPdrg/0/*)#kjnlnm3v",
            "internal": False
        },
        {
            "timestamp": "now",
            "active": True,
            "desc": "pkh([0f056943/44h/1h/0h]tprv8g2F84LJV3jWVuWyDZB4EwHGwe8esEG8H6Gxn4CCdNgQTrtH7CMywCmwzuMGZjz13sQ9rcCZucCm6i2zigkYGSPUvCzDQxGW8RCy7FpPdrg/1/*)#8xk7wwp5",
            "internal": True
        },
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943",
            "active": True,
            "desc": "sh(wpkh([0f056943/49h/1h/0h]tprv8fXojhVHnKUsegFf4CXvmhXRGWq8GBzDvxHYQNRDrJJWCyqTrcYi7vdbSn65CHETVPdw4sxc75v23Ev7o8fCePazRf917CMt1C3mjnKV4Jq/0/*))#0qf5gv2y",
            "internal": False
        },
        {
            "timestamp": "now",
            "active": True,
            "desc": "sh(wpkh([0f056943/49h/1h/0h]tprv8fXojhVHnKUsegFf4CXvmhXRGWq8GBzDvxHYQNRDrJJWCyqTrcYi7vdbSn65CHETVPdw4sxc75v23Ev7o8fCePazRf917CMt1C3mjnKV4Jq/1/*))#6p8zsnlm",
            "internal": True
        },
    ]
    conn.importdescriptors(descriptors)
    return conn

# EOF
