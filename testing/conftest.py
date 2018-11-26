# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
import pytest, glob, time
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError

from api import bitcoind, match_key

SIM_PATH = '/tmp/ckcc-simulator.sock'

def pytest_addoption(parser):
    parser.addoption("--dev", action="store_true",
                     default=False, help="run on real dev")
    parser.addoption("--sim", action="store_true",
                     default=True, help="run on simulator")

@pytest.fixture(scope='session')
def dev(request):
    # a connected Coldcard (via USB) .. or the simulator
    # use command line --sim or --dev to pick, default is sim
    from ckcc_protocol.client import ColdcardDevice

    config = request.config

    if config.getoption("--dev"):
        return ColdcardDevice()

    else:
        # manually get the simulator fixture
        simulator = request.getfixturevalue('simulator')

        return simulator


@pytest.fixture(scope='session')
def simulator(request):
    # get a connection to simulator (only, never USB dev)
    from ckcc_protocol.client import ColdcardDevice

    if request.config.getoption("--dev"):
        raise pytest.skip('USB dev')

    try:
        return ColdcardDevice(sn=SIM_PATH)
    except:
        raise
        print("Simulator is required for this test")
        raise pytest.fail('missing simulator')

@pytest.fixture(scope='module')
def sim_exec(simulator):
    # run code in the simulator's interpretor

    def doit(cmd):
        return simulator.send_recv(b'EXEC' + cmd.encode('utf-8')).decode('utf-8')

    return doit

@pytest.fixture(scope='module')
def sim_eval(simulator):
    # eval an expression in the simulator's interpretor

    def doit(cmd):
        return simulator.send_recv(b'EVAL' + cmd.encode('utf-8')).decode('utf-8')

    return doit

@pytest.fixture(scope='module')
def sim_execfile(simulator):
    # run a whole file in the simulator's interpretor
    import os

    def doit(fname, timeout=None):
        fn = os.path.realpath(fname)
        hook = 'execfile("%s")' % fn
        return simulator.send_recv(b'EXEC' + hook.encode('utf-8'), timeout=timeout).decode('utf-8')

    return doit

@pytest.fixture(scope='module')
def need_keypress(dev):

    def doit(k):
        if hasattr(dev.dev, 'pipe'):
            dev.send_recv(CCProtocolPacker.sim_keypress(k.encode('ascii')))
        else:
            # try to use debug interface to simulate the press
            # XXX for some reason, picocom must **already** be running for this to work.
            # - otherwise, this locks up
            devs = list(glob.glob('/dev/tty.usbmodem*'))
            if len(devs) == 1:
                with open(devs[0], 'wb', 0) as fd:
                    fd.write(k.encode('ascii'))
            else:
                # need actual user interaction
                print("NOW, on the Coldcard, press key: %s" % k)

    return doit
    
@pytest.fixture(scope='module')
def master_xpub(dev):
    r = dev.send_recv(CCProtocolPacker.get_xpub('m'), timeout=None, encrypt=1)

    assert r[1:4] == 'pub', r

    if r[0:4] == dev.master_xpub[0:4]:
        assert r == dev.master_xpub
    else:
        # testnet vs. mainnet
        from pycoin.key.BIP32Node import BIP32Node
        a = BIP32Node.from_wallet_key(r)
        b = BIP32Node.from_wallet_key(dev.master_xpub)

        assert a.secret_exponent() == b.secret_exponent()

    return r

@pytest.fixture(scope='module')
def unit_test(sim_execfile):
    def doit(filename):
        rv = sim_execfile(filename)
        if rv: pytest.fail(rv)
    return doit


@pytest.fixture(scope='module')
def addr_vs_path(master_xpub):
    from pycoin.key.BIP32Node import BIP32Node
    from ckcc_protocol.constants import AF_CLASSIC, AFC_PUBKEY, AF_P2WPKH, AFC_SCRIPT
    from ckcc_protocol.constants import AF_P2WPKH_P2SH
    from bech32 import bech32_decode, convertbits
    from pycoin.encoding import a2b_hashed_base58, hash160

    def doit(given_addr, path, addr_fmt):
        mk = BIP32Node.from_wallet_key(master_xpub)
        sk = mk.subkey_for_path(path[2:])

        if addr_fmt == AF_CLASSIC:
            # easy
            assert sk.address() == given_addr

        elif addr_fmt & AFC_PUBKEY:

            pkh = sk.hash160(use_uncompressed=False)

            if addr_fmt == AF_P2WPKH:
                hrp, data = bech32_decode(given_addr)
                decoded = convertbits(data[1:], 5, 8, False)
                assert hrp in {'tb', 'bc' }
                assert bytes(decoded[-20:]) == pkh
            else:
                assert addr_fmt == AF_P2WPKH_P2SH
                assert given_addr[0] in '23'
                expect = a2b_hashed_base58(given_addr)[1:]
                assert len(expect) == 20
                assert hash160(b'\x00\x14' + pkh) == expect

        elif addr_fmt & AFC_SCRIPT:
            raise pytest.fail('multisig/p2sh addr not handled')
        else:
            raise ValueError(addr_fmt)

    return doit



@pytest.fixture(scope='module')
def capture_enabled(sim_eval):
    # need to have sim_display imported early, see unix/frozen-modules/ckcc
    # - could be xfail or xskip here
    assert sim_eval("'sim_display' in sys.modules") == 'True'

@pytest.fixture(scope='module')
def cap_menu(sim_execfile):
    "Return menu items as a list"
    def doit():
        return sim_execfile('devtest/cap-menu.py').split('\n')

    return doit

@pytest.fixture(scope='module')
def cap_screen(sim_execfile):
    def doit():
        return sim_execfile('devtest/cap-screen.py')

    return doit

@pytest.fixture(scope='module')
def cap_story(sim_execfile):
    # returns (title, body) of whatever story is being actively shown
    def doit():
        return sim_execfile('devtest/cap-story.py').split('\0', 1)

    return doit

@pytest.fixture(scope='module')
def get_secrets(sim_execfile):
    # returns big dict based on what we'd normally put into a backup file.
    def doit():
        from json import loads
        rv = dict()
        resp = sim_execfile('devtest/get-secrets.py')
        assert 'Error' not in resp
        for ln in resp.split('\n'):
            ln = ln.strip()
            if '#' in ln:
                ln = ln[0:ln.index('#')]
            if not ln: continue

            assert ' = ' in ln
            n, v = ln.split(' = ', 1)
            rv[n] = loads(v)
        return rv

    return doit

@pytest.fixture
def goto_home(cap_menu, need_keypress):

    def doit():
        # get to top, force a redraw
        for i in range(10):
            need_keypress('x')
            time.sleep(.01)      # required

        need_keypress('0')
        
        # check menu contents
        m = cap_menu()
        assert 'Ready To Sign' in m

    return doit

@pytest.fixture
def pick_menu_item(cap_menu, need_keypress):
    def doit(text):
        need_keypress('0')
        m = cap_menu()
        assert text in m, "%r not in menu: %r" % (text, m)

        for label in m:
            if label == text:
                need_keypress('y')
                time.sleep(.01)      # required
                return
            need_keypress('8')
            time.sleep(.01)      # required

        assert False, 'not reached'

    return doit


@pytest.fixture(scope='module')
def microsd_path(simulator):
    # open a file from the simulated microsd

    def doit(fn):
        return '../unix/work/MicroSD/' + fn

    return doit

@pytest.fixture(scope='module')
def open_microsd(simulator, microsd_path):
    # open a file from the simulated microsd

    def doit(fn, mode='rb'):
        return open(microsd_path(fn), mode)

    return doit

@pytest.fixture()
def set_master_key(sim_exec, sim_execfile, simulator):
    # load simulator w/ a specific bip32 master key

    def doit(prv):
        assert prv[1:4] == 'prv'

        sim_exec('import main; main.TPRV = %r; ' % prv)
        rv = sim_execfile('devtest/set_tprv.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()

        print("sim xfp: 0x%08x" % simulator.master_fingerprint)

    yield doit

    # Important cleanup: restore normal key, because other tests assume that

    simulator_fixed_xprv = "tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4"
    doit(simulator_fixed_xprv)

@pytest.fixture()
def set_seed_words(sim_exec, sim_execfile, simulator, set_master_key):
    # load simulator w/ a specific bip32 master key

    def doit(words):

        sim_exec('import main; main.WORDS = %r; ' % words.split())
        rv = sim_execfile('devtest/set_seed.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()

        print("sim xfp: 0x%08x" % simulator.master_fingerprint)

    yield doit

    # Important cleanup: restore normal key, because other tests assume that

    simulator_fixed_xprv = "tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4"
    set_master_key(simulator_fixed_xprv)


@pytest.fixture()
def settings_set(sim_exec):

    def doit(key, val):
        x = sim_exec("from main import settings; settings.set('%s', %r)" % (key, val))
        assert x == ''

    return doit

#EOF
