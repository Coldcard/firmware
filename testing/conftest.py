# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
import pytest, glob, time, sys
from pprint import pprint
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError
from helpers import B2A, U2SAT

from api import bitcoind, match_key


SIM_PATH = '/tmp/ckcc-simulator.sock'

# Simulator normally powers up with this 'wallet'
simulator_fixed_xprv = "tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4"
simulator_fixed_words = "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify"
simulator_fixed_xfp = 0x4369050f

def pytest_addoption(parser):
    parser.addoption("--dev", action="store_true",
                     default=False, help="run on real dev")
    parser.addoption("--sim", action="store_true",
                     default=True, help="run on simulator")
    parser.addoption("--manual", action="store_true",
                     default=False, help="operator must press keys on real CC")

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

    if not request.config.getoption("--sim") or request.config.getoption("--dev"):
        raise pytest.skip('need simulator for this test, have real device')

    try:
        return ColdcardDevice(sn=SIM_PATH)
    except:
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
def need_keypress(dev, request):

    def doit(k):
        if hasattr(dev.dev, 'pipe'):
            # simulator has special USB command
            dev.send_recv(CCProtocolPacker.sim_keypress(k.encode('ascii')))
        elif request.config.getoption("--manual"):
            # need actual user interaction
            print("==> NOW, on the Coldcard, press key: %r" % k, file=sys.stderr)
        else:
            # try to use debug interface to simulate the press
            # XXX for some reason, picocom must **already** be running for this to work.
            # - otherwise, this locks up
            devs = list(glob.glob('/dev/tty.usbmodem*'))
            if len(devs) == 1:
                with open(devs[0], 'wb', 0) as fd:
                    fd.write(k.encode('ascii'))
            else:
                raise pytest.fail('need to provide keypresses')

    return doit
    
@pytest.fixture(scope='module')
def master_xpub(dev):
    r = dev.send_recv(CCProtocolPacker.get_xpub('m'), timeout=None, encrypt=1)

    assert r[1:4] == 'pub', r

    if r[0:4] == dev.master_xpub[0:4]:
        assert r == dev.master_xpub
    elif dev.master_xpub:
        # testnet vs. mainnet difference
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
def get_pp_sofar(sim_execfile):
    # get entry value for bip39 passphrase
    def doit():
        from json import loads
        rv = dict()
        resp = sim_execfile('devtest/get_pp_sofar.py')
        assert 'Error' not in resp
        return resp

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
def goto_home(cap_menu, need_keypress, pick_menu_item):

    def doit():
        # get to top, force a redraw
        for i in range(10):
            need_keypress('x')
            time.sleep(.01)      # required

            # special case to get out of passphrase menu
            if 'CANCEL' in cap_menu():
                pick_menu_item('CANCEL')
                time.sleep(.01)
                need_keypress('y')

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
        simulator.check_mitm()

        print("sim xfp: 0x%08x" % simulator.master_fingerprint)

    yield doit

    # Important cleanup: restore normal key, because other tests assume that

    doit(simulator_fixed_xprv)

@pytest.fixture()
def set_seed_words(sim_exec, sim_execfile, simulator):
    # load simulator w/ a specific bip32 master key

    def doit(words):

        sim_exec('import main; main.WORDS = %r; ' % words.split())
        rv = sim_execfile('devtest/set_seed.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()
        simulator.check_mitm()

        print("sim xfp: 0x%08x" % simulator.master_fingerprint)

    yield doit

    # Important cleanup: restore normal key, because other tests assume that

    doit(simulator_fixed_words)

@pytest.fixture()
def reset_seed_words(sim_exec, sim_execfile, simulator):
    # load simulator w/ a specific bip39 seed phrase

    def doit():
        words = simulator_fixed_words

        sim_exec('import main; main.WORDS = %r; ' % words.split())
        rv = sim_execfile('devtest/set_seed.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()
        simulator.check_mitm()

        print("sim xfp: 0x%08x (reset)" % simulator.master_fingerprint)
        assert simulator.master_fingerprint == simulator_fixed_xfp

        return words

    yield doit




@pytest.fixture()
def settings_set(sim_exec):

    def doit(key, val):
        x = sim_exec("from main import settings; settings.set('%s', %r)" % (key, val))
        assert x == ''

    return doit

@pytest.fixture(scope='session')
def repl(dev=None):
    # Provide an interactive connection to the REPL. Has to be real device, with
    # dev features enabled. Best really with unit in factory mode.
    import sys, serial
    from serial.tools.list_ports import comports

    # NOTE: 
    # - tested only on Mac, but might work elsewhere.
    # - board needs to be reset between runs, because USB protocol (not serial) is disabled by this

    class USBRepl:
        def __init__(self):
            for d in comports():
                if d.pid != 0xcc10: continue
                if dev:
                    if d.serial_number != dev.serial: continue
                self.sio = serial.Serial(d.device, write_timeout=1)

                print("Connected to: %s" % d.device)
                break
            else:
                raise RuntimeError("Can't find usb serial port")

            self.sio.timeout = 0.250
            greet = self.sio.readlines()
            if greet and b'Welcome to Coldcard!' in greet[1]:
                self.sio.write(b'\x03')     # ctrl-C
                while 1:
                    self.sio.timeout = 1
                    lns = self.sio.readlines()
                    if not lns: break

            # hit enter, expect prompt
            self.sio.timeout = 0.100
            self.sio.write(b'\r')
            ln = self.sio.readlines()
            assert ln[-1] == b'>>> ', ln

            self.sio.timeout = 0.250

        def eval(self, cmd, max_time=3):
            # send a command, wait for it to finish (next prompt) and eval the response
            print("eval: %r" % cmd)

            self.sio.write(cmd.encode('ascii') + b'\r')

            self.sio.timeout = max_time
            lines = []
            while 1:
                resp = self.sio.readline().decode('ascii')
                if resp.startswith('>>> '): break
                lines.append(resp)

            if any('Traceback' in l for l in lines):
                raise RuntimeError(''.join(lines))

            if len(lines) == 0:
                raise RuntimeError("timeout/got nothing")

            if len(lines) == 1:
                # cmd printed nothing, meaning it returned None and REPL hid that
                assert lines[0].startswith(cmd), lines
                return None

            try:
                return eval(lines[-1])
            except:
                raise RuntimeError(''.join(lines))
                
            

        def exec(self, cmd, proc_time=1):
            # send a (one line) command and read the one-line response
            print("exec: %r" % cmd)

            self.sio.write(cmd.encode('ascii') + b'\r')

            self.sio.timeout = 0.2
            echo = self.sio.readline()
            #print("echo: %r" % echo.decode('ascii'))

            assert cmd.encode('ascii') in echo

            self.sio.timeout = proc_time
            resp =  self.sio.readline().decode('ascii')

            #print("resp: %r" % resp)

            return resp

    return USBRepl()

@pytest.fixture()
def decode_with_bitcoind(bitcoind):

    def doit(raw_txn):
        # verify our understanding of a TXN (and esp its outputs) matches
        # the same values as what bitcoind generates

        try:
            return bitcoind.decoderawtransaction(B2A(raw_txn))
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            return bitcoind.decoderawtransaction(B2A(raw_txn))

    return doit


@pytest.fixture()
def check_against_bitcoind(bitcoind, sim_exec, sim_execfile):

    def doit(hex_txn, fee, num_warn=0, change_outs=None):
        # verify our understanding of a TXN (and esp its outputs) matches
        # the same values as what bitcoind generates

        try:
            decode = bitcoind.decoderawtransaction(hex_txn)
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            decode = bitcoind.decoderawtransaction(hex_txn)

        #print("Bitcoin code says:", end=''); pprint(decode)

        # leverage bitcoind's transaction decoding
        ex = dict(  lock_time = decode['locktime'],
                    had_witness = False,        # input txn doesn't have them, typical?
                    num_inputs = len(decode['vin']),
                    num_outputs = len(decode['vout']),
                    miner_fee = U2SAT(fee),
                    warnings_expected = num_warn,
                    total_value_out = sum(U2SAT(i['value']) for i in decode['vout']),
                    destinations = [(U2SAT(i['value']), i['scriptPubKey']['addresses'][0])
                                         for i in decode['vout']],
            )

        if change_outs is not None:
            ex['change_outs'] = set(change_outs)

        # need this for reliability
        time.sleep(0.01)

        # check we understood it right
        rv= sim_exec('import main; main.EXPECT = %r; ' % ex)
        if rv: pytest.fail(rv)
        rv = sim_execfile('devtest/check_decode.py')
        if rv: pytest.fail(rv)

        print(" [checks out against bitcoind] ")

        return decode


    return doit

#EOF
