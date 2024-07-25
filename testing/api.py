# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# needs local bitcoind in PATH

import os, time, uuid, socket, shutil, pytest, tempfile, subprocess, signal, base64
from authproxy import AuthServiceProxy, JSONRPCException
from helpers import xfp2str
from ckcc.protocol import CCProtocolPacker


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
        self.has_bdb = True

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
                # needed for newest master
                # TODO legacy wallet will be deprecated in 26
                "-deprecatedrpc=create_bdb",
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
        signal.signal(signal.SIGTERM, self.cleanup)

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
        try:
            self.supply_wallet = self.create_wallet(wallet_name="supply", descriptors=False)
        except JSONRPCException as e:
            assert "BDB wallet creation is deprecated" in str(e)
            self.has_bdb = False
            self.supply_wallet = self.create_wallet(wallet_name="supply", descriptors=True)

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

    def cleanup(self, *args, **kwargs):
        if self.bitcoind_proc is not None and self.bitcoind_proc.poll() is None:
            self.bitcoind_proc.kill()
        time.sleep(0.5)
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


@pytest.fixture
def bitcoind():
    # JSON-RPC connection to a bitcoind instance
    # this assumes that you have bitcoind in path somewhere
    bitcoin_d = Bitcoind.create()
    yield bitcoin_d
    os.killpg(os.getpgid(bitcoin_d.bitcoind_proc.pid), signal.SIGTERM)


@pytest.fixture
def match_key(bitcoind, set_master_key, reset_seed_words):
    # load simulator w/ existing bip32 master key of testnet instance

    # bummer: dumpmasterprivkey RPC call was removed!
    #prv = bitcoind.dumpmasterprivkey()

    # bummer: dumpwallet RPC call was removed does not work with descriptor wallets
    try:
        from tempfile import mktemp
        fn = mktemp()
        bitcoind.supply_wallet.dumpwallet(fn)
        prv = None

        for ln in open(fn, 'rt').readlines():
            if 'extended private masterkey' in ln:
                assert not prv
                prv = ln.split(": ", 1)[1].strip()

        os.unlink(fn)
    except JSONRPCException as e:
        print(str(e))
        assert "Only legacy wallets are supported by this command" in str(e)
        prv_descs = bitcoind.supply_wallet.listdescriptors(True)  # True --> show private
        prv = prv_descs["descriptors"][0]["desc"].replace("pkh(", "").split("/")[0]

    assert prv.startswith('tprv')

    xfp = set_master_key(prv)

    yield xfp


@pytest.fixture
def finalize_v2_v0_convert(bitcoind):
    def doit(psbt_obj):
        # compat wrapper - can be removed after below released
        # https://github.com/bitcoin/bitcoin/pull/21283 PSBTv2
        # convert v2 -> v0 if bitcoind does not support PSBTv2
        # to be able to finalize
        from authproxy import JSONRPCException
        try:
            resp = bitcoind.supply_wallet.finalizepsbt(psbt_obj.as_b64_str())
        except JSONRPCException as e:
            assert "Unsupported version number" in e.error["message"]
            # this version of bitcoind does not support PSBTv2
            # convert to v0 - needed for finalize
            resp = bitcoind.supply_wallet.finalizepsbt(
                base64.b64encode(psbt_obj.to_v0()).decode()
            )
        return resp

    return doit

@pytest.fixture
def bitcoind_wallet(bitcoind):
    # Use bitcoind to create a temporary wallet file
    w_name = 'ckcc-test-wallet-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=not bitcoind.has_bdb)
    yield conn


@pytest.fixture
def bitcoind_d_wallet(bitcoind):
    # Use bitcoind to create a temporary DESCRIPTOR-based wallet file
    w_name = 'ckcc-test-desc-wallet-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    yield conn


@pytest.fixture
def bitcoind_d_wallet_w_sk(bitcoind):
    # Use bitcoind to create a temporary DESCRIPTOR-based wallet file
    w_name = 'ckcc-test-desc-wallet-w-sk-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=False, blank=False,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    yield conn


@pytest.fixture
def bitcoind_d_sim_watch(bitcoind):
    # watch only descriptor wallet simulator
    w_name = 'ckcc-test-desc-wallet-sim-%s' % uuid.uuid4()
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    descriptors = [
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943 segwit v0",
            "active": True,
            "desc": "wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)#erexmnep",
            "internal": False
        },
        {
            "desc": "wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/1/*)#ghu8xxfe",
            "active": True,
            "internal": True,
            "timestamp": "now"
        },
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943 segwit v1",
            "active": True,
            "desc": "tr([0f056943/86h/1h/0h]tpubDCeEX49avtiXrBTv3JWTtco99Ka499jXdZHBRtm7va2gkMAui11ctZjqNAT9dLVNaEozt2C1kfTM88cnvZCXsWLJN2p4viGvsyGjtKVV7A1/0/*)#6ghw47ge",
            "internal": False
        },
        {
            "desc": "tr([0f056943/86h/1h/0h]tpubDCeEX49avtiXrBTv3JWTtco99Ka499jXdZHBRtm7va2gkMAui11ctZjqNAT9dLVNaEozt2C1kfTM88cnvZCXsWLJN2p4viGvsyGjtKVV7A1/1/*)#tuj0gtcp",
            "active": True,
            "internal": True,
            "timestamp": "now"
        },
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943 p2pkh",
            "active": True,
            "desc": "pkh([0f056943/44h/1h/0h]tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB/0/*)#fxwk08tc",
            "internal": False
        },
        {
            "timestamp": "now",
            "active": True,
            "desc": "pkh([0f056943/44h/1h/0h]tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB/1/*)#cjthjjmq",
            "internal": True
        },
        {
            "timestamp": "now",
            "label": "Coldcard 0f056943 p2sh-p2wpkh",
            "active": True,
            "desc": "sh(wpkh([0f056943/49h/1h/0h]tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj/0/*))#weah3vek",
            "internal": False
        },
        {
            "timestamp": "now",
            "active": True,
            "desc": "sh(wpkh([0f056943/49h/1h/0h]tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj/1/*))#mcnpfnvf",
            "internal": True
        },
    ]
    conn.importdescriptors(descriptors)
    yield conn


@pytest.fixture
def bitcoind_d_dev_watch(request, dev, bitcoind, dev_core_import_object):
    name = ""

    if dev.is_simulator:
        settings_set = request.getfixturevalue('settings_set')
        settings_set("chain", "XRT")
        name += "sim"

    assert dev.send_recv(CCProtocolPacker.block_chain()) == "XRT", "needs regtest"
    xfp = xfp2str(dev.master_fingerprint)
    name += xfp
    name += "watch-only"
    w_name = '%s-%s' % (name, uuid.uuid4())
    conn = bitcoind.create_wallet(wallet_name=w_name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    conn.importdescriptors(dev_core_import_object)
    yield conn

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
            "label": "Coldcard 0f056943 segwit v1",
            "active": True,
            "desc": "tr([0f056943/86h/1h/0h]tprv8fxCNe7LnX2rxiS89eqsVD92aJ47ypYd4FgQ9NipWJEHurv95cC2i57yC2mRHnpuHfmgdb17GV9wfSNjswUQXmaY7Qs2Jaa5hEdkxaHy4BK/0/*)#x7dfk9mw",
            "internal": False
        },
        {
            "desc": "tr([0f056943/86h/1h/0h]tprv8fxCNe7LnX2rxiS89eqsVD92aJ47ypYd4FgQ9NipWJEHurv95cC2i57yC2mRHnpuHfmgdb17GV9wfSNjswUQXmaY7Qs2Jaa5hEdkxaHy4BK/1/*)#h2ggtstk",
            "active": True,
            "internal": True,
            "timestamp": "now"
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
    yield conn

# EOF
