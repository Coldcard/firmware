# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, glob, time, sys, random, re
from pprint import pprint
from ckcc.protocol import CCProtocolPacker, CCProtoError
from helpers import B2A, U2SAT, prandom
from api import bitcoind, match_key, bitcoind_finalizer, bitcoind_analyze, bitcoind_decode, explora
from api import bitcoind_wallet
from binascii import b2a_hex, a2b_hex
from constants import *

# lock down randomness
random.seed(42)

def pytest_addoption(parser):
    parser.addoption("--dev", action="store_true",
                     default=False, help="run on real dev")
    parser.addoption("--sim", action="store_true",
                     default=True, help="run on simulator")
    parser.addoption("--manual", action="store_true",
                     default=False, help="operator must press keys on real CC")

    parser.addoption("--mk", default=3, help="Assume mark N hardware")

    parser.addoption("--duress", action="store_true",
                     default=False, help="assume logged-in with duress PIN")

    parser.addoption("--ms-danger", action="store_true",
                     default=False, help="Operate with multisig checks off")

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
def sim_exec(dev):
    # run code in the simulator's interpretor

    def doit(cmd):
        s = dev.send_recv(b'EXEC' + cmd.encode('utf-8'))
        return s.decode('utf-8') if not isinstance(s, str) else s

    return doit

@pytest.fixture(scope='module')
def sim_eval(dev):
    # eval an expression in the simulator's interpretor

    def doit(cmd, timeout=None):
        return dev.send_recv(b'EVAL' + cmd.encode('utf-8'), timeout=timeout).decode('utf-8')

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
def is_simulator(dev):
    def doit():
        return hasattr(dev.dev, 'pipe')
    return doit

@pytest.fixture(scope='module')
def sim_card_ejected(sim_exec, is_simulator):
    def doit(ejected):
        if not is_simulator():
            # assuming no card on device
            if not ejected:
                raise pytest.fail('cant insert on real dev')
            else:
                return

        # see unix/frozen-modules/pyb.py class SDCard
        cmd = f'import pyb; pyb.SDCard.ejected={ejected}; RV.write("ok")'
        assert sim_exec(cmd) == 'ok'

    yield doit
    if is_simulator():
        doit(False)

@pytest.fixture(scope='module')
def send_ux_abort(simulator):

    def doit():
        # simulator has special USB command
        # - this is a special "key"
        simulator.send_recv(CCProtocolPacker.sim_ux_abort())

    return doit

@pytest.fixture(scope='module')
def need_keypress(dev, request):

    def doit(k, timeout=1000):
        if request.config.getoption("--manual"):
            # need actual user interaction
            print("==> NOW, on the Coldcard, press key: %r (then enter here)" % k, file=sys.stderr)
            input()
        else:
            # simulator has special USB command, and can be used on real device w/ enuf setup
            dev.send_recv(CCProtocolPacker.sim_keypress(k.encode('ascii')), timeout=timeout)

        if 0:
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
    if hasattr(dev.dev, 'pipe'):
        # this works better against simulator in HSM mode, where the xpub cmd may be disabled
        return simulator_fixed_xpub

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
def get_settings(sim_execfile):
    # get all settings
    def doit():
        from json import loads
        resp = sim_execfile('devtest/get-settings.py')
        assert 'Traceback' not in resp
        return loads(resp)

    return doit

@pytest.fixture(scope='module')
def get_setting(sim_execfile, sim_exec):
    # get an indivudal setting
    def doit(name):
        from json import loads
        sim_exec('import main; main.SKEY = %r; ' % name)
        resp = sim_execfile('devtest/get-setting.py')
        assert 'Traceback' not in resp
        return loads(resp)

    return doit

@pytest.fixture(scope='module')
def addr_vs_path(master_xpub):
    from pycoin.key.BIP32Node import BIP32Node
    from ckcc_protocol.constants import AF_CLASSIC, AFC_PUBKEY, AF_P2WPKH, AFC_SCRIPT
    from ckcc_protocol.constants import AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH
    from bech32 import bech32_decode, convertbits
    from pycoin.encoding import a2b_hashed_base58, hash160
    from  pycoin.key.BIP32Node import PublicPrivateMismatchError
    from hashlib import sha256

    def doit(given_addr, path=None, addr_fmt=None, script=None):
        if not script:
            try:
                # prefer using xpub if we can
                mk = BIP32Node.from_wallet_key(master_xpub)
                sk = mk.subkey_for_path(path[2:])
            except PublicPrivateMismatchError:
                mk = BIP32Node.from_wallet_key(simulator_fixed_xprv)
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
            assert script, 'need a redeem/witness script'
            if addr_fmt == AF_P2SH:
                assert given_addr[0] in '23'
                expect = a2b_hashed_base58(given_addr)[1:]
                assert hash160(script) == expect

            elif addr_fmt == AF_P2WSH:
                hrp, data = bech32_decode(given_addr)
                assert hrp in {'tb', 'bc' }
                decoded = convertbits(data[1:], 5, 8, False)
                assert bytes(decoded[-32:]) == sha256(script).digest()

            elif addr_fmt == AF_P2WSH_P2SH:
                assert given_addr[0] in '23'
                expect = a2b_hashed_base58(given_addr)[1:]
                assert hash160(b'\x00\x20' + sha256(script).digest()) == expect

            else:
                raise pytest.fail(f'not ready for {addr_fmt:x} yet')
        else:
            raise ValueError(addr_fmt)

        return sk if not script else None

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
def cap_image(sim_execfile):

    def flip(raw):
        reorg = bytearray(128*64)
        j = 0 
        for y in range(64//8):
            for by in range(8):
                for x in range(128):
                    reorg[j] = 255 if (raw[x+(128*y)] & (1 << by)) else 0
                    j += 1
        return bytes(reorg)

    # returns Pillow image  of whatever story is being actively shown on OLED
    def doit():
        from PIL import Image

        raw = a2b_hex(sim_execfile('devtest/cap-image.py'))
        assert len(raw) == (128*64//8)
        return Image.frombytes('L', (128,64), flip(raw), 'raw')

    return doit

@pytest.fixture(scope='module')
def cap_screen_qr(cap_image):
    def doit(x=4, w=64):

        try:
            import zbar
        except ImportError:
            raise pytest.skip('need zbar-py module')
        import numpy
        from PIL import ImageOps

        # see <http://qrlogo.kaarposoft.dk/qrdecode.html>

        img = cap_image()
        img = img.crop( (x, 0, x+w, w) )
        img = ImageOps.expand(img, 16, 255)
        img = img.resize( (256, 256))
        img.save('debug/last-qr.png')
        #img.show()
    
        scanner = zbar.Scanner()
        np = numpy.array(img.getdata(), 'uint8').reshape(img.width, img.height)

        for sym, value, *_ in scanner.scan(np):
            assert sym == 'QR-Code', 'unexpected symbology: ' + sym
            value = str(value, 'ascii')
            return value

        raise pytest.fail('qr code not found')

    return doit

@pytest.fixture(scope='module')
def get_pp_sofar(sim_execfile):
    # get entry value for bip39 passphrase
    def doit():
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
        if text not in m:
            raise KeyError(text, "%r not in menu: %r" % (text, m))

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

@pytest.fixture(scope="function")
def set_master_key(sim_exec, sim_execfile, simulator, reset_seed_words):
    # load simulator w/ a specific bip32 master key

    def doit(prv):
        assert prv[1:4] == 'prv'

        sim_exec('import main; main.TPRV = %r; ' % prv)
        rv = sim_execfile('devtest/set_tprv.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()
        simulator.check_mitm()

        #print("sim xfp: 0x%08x" % simulator.master_fingerprint)

        return simulator.master_fingerprint

    yield doit

    # Important cleanup: restore normal key, because other tests assume that
    # - actually need seed words for all tests
    reset_seed_words()

@pytest.fixture(scope="function")
def set_xfp(sim_exec, sim_execfile, simulator, reset_seed_words):
    # set the XFP, without really knowing the private keys
    # - won't be able to sign, but should accept PSBT for signing

    def doit(xfp):
        assert len(xfp) == 8, "expect 8 hex digits"

        import struct
        need_xfp, = struct.unpack("<I", a2b_hex(xfp))

        sim_exec('from main import settings; settings.set("xfp", 0x%x);' % need_xfp)

    yield doit

    # Important cleanup: restore normal key, because other tests assume that
    reset_seed_words()

@pytest.fixture(scope="function")
def set_encoded_secret(sim_exec, sim_execfile, simulator, reset_seed_words):
    # load simulator w/ a specific secret

    def doit(encoded):
        assert 17 <= len(encoded) <= 72

        encoded += bytes(72- len(encoded))

        sim_exec('import main; main.ENCODED_SECRET = %r; ' % encoded)
        rv = sim_execfile('devtest/set_encoded_secret.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()
        simulator.check_mitm()

        #print("sim xfp: 0x%08x" % simulator.master_fingerprint)

        return simulator.master_fingerprint

    yield doit

    # Important cleanup: restore normal key, because other tests assume that
    # - actually need seed words for all tests
    reset_seed_words()

@pytest.fixture(scope="function")
def set_seed_words(sim_exec, sim_execfile, simulator, reset_seed_words):
    # load simulator w/ a specific bip32 master key

    def doit(words):

        sim_exec('import main; main.WORDS = %r; ' % words.split())
        rv = sim_execfile('devtest/set_seed.py')
        if rv: pytest.fail(rv)

        simulator.start_encryption()
        simulator.check_mitm()

        #print("sim xfp: 0x%08x" % simulator.master_fingerprint)
        return simulator.master_fingerprint

    yield doit

    # Important cleanup: restore normal key, because other tests assume that

    reset_seed_words()

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

        #print("sim xfp: 0x%08x (reset)" % simulator.master_fingerprint)
        assert simulator.master_fingerprint == simulator_fixed_xfp

        return words

    return doit


@pytest.fixture()
def settings_set(sim_exec):

    def doit(key, val):
        x = sim_exec("nvstore.settings.set('%s', %r)" % (key, val))
        assert x == ''

    return doit

@pytest.fixture()
def settings_get(sim_exec):

    def doit(key):
        cmd = f"RV.write(repr(nvstore.settings.get('{key}')))"
        resp = sim_exec(cmd)
        assert 'Traceback' not in resp, resp
        return eval(resp)

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
def decode_psbt_with_bitcoind(bitcoind):

    def doit(raw_psbt):
        # verify our understanding of a PSBT against bitcoind
        from base64 import b64encode

        try:
            return bitcoind.decodepsbt(b64encode(raw_psbt).decode('ascii'))
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            return bitcoind.decodepsbt(b64encode(raw_psbt).decode('ascii'))

    return doit

@pytest.fixture()
def check_against_bitcoind(bitcoind, sim_exec, sim_execfile):

    def doit(hex_txn, fee, num_warn=0, change_outs=None, dests=[]):
        # verify our understanding of a TXN (and esp its outputs) matches
        # the same values as what bitcoind generates

        try:
            decode = bitcoind.decoderawtransaction(hex_txn)
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            decode = bitcoind.decoderawtransaction(hex_txn)

        #print("Bitcoin code says:", end=''); pprint(decode)

        if dests:
            # check we got right destination address(es)
            for outn, expect_addr in dests:
                assert decode['vout'][outn]['scriptPubKey']['addresses'][0] == expect_addr

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

@pytest.fixture
def try_sign_microsd(open_microsd, cap_story, pick_menu_item, goto_home, need_keypress, microsd_path):

    # like "try_sign" but use "air gapped" file transfer via microSD

    def doit(f_or_data, accept=True, finalize=False, accept_ms_import=False, complete=False, encoding='binary', del_after=0):

        if f_or_data[0:5] == b'psbt\xff':
            ip = f_or_data
            filename = 'memory'
        else:
            filename = f_or_data
            ip = open(f_or_data, 'rb').read()
            if ip[0:10] == b'70736274ff':
                ip = a2b_hex(ip.strip())
            assert ip[0:5] == b'psbt\xff'

        psbtname = 'ftrysign'

        # population control
        from glob import glob; import os
        pat = microsd_path(psbtname+'*.psbt')
        for f in glob(pat):
            assert 'psbt' in f
            os.unlink(f)

        if encoding == 'hex':
            ip = b2a_hex(ip)
        elif encoding == 'base64':
            from base64 import b64encode, b64decode
            ip = b64encode(ip)
        else:
            assert encoding == 'binary'

        with open_microsd(psbtname+'.psbt', 'wb') as sd:
            sd.write(ip)

        goto_home()
        pick_menu_item('Ready To Sign')

        time.sleep(.1)
        _, story = cap_story()
        if 'Choose PSBT file' in story:
            need_keypress('y')
            time.sleep(.1)
            
        pick_menu_item(psbtname+'.psbt')

        time.sleep(.1)
        
        if accept_ms_import:
            # XXX would be better to do cap_story here, but that would limit test to simulator
            need_keypress('y')
            time.sleep(0.050)

        title, story = cap_story()
        assert title == 'OK TO SEND?'

        if accept != None:
            need_keypress('y' if accept else 'x')

        if accept == False:
            time.sleep(0.050)

            # look for "Aborting..." ??
            return ip, None, None

        # wait for it to finish
        for r in range(10):
            time.sleep(0.1)
            title, story = cap_story()
            if title == 'PSBT Signed': break
        else:
            assert False, 'timed out'

        txid = None
        lines = story.split('\n')
        if 'Final TXID:' in lines:
            txid = lines[-1]
            result_fname = lines[-4]
        else:
            result_fname = lines[-1]

        result = open_microsd(result_fname, 'rb').read()

        if encoding == 'hex' or finalize:
            result = a2b_hex(result.strip())
        elif encoding == 'base64':
            result = b64decode(result)
        else:
            assert encoding == 'binary'

        in_file = microsd_path(psbtname+'.psbt')

        # read back final product
        if finalize:

            if del_after:
                if not txid:
                    txid = re.findall('[0-9a-f]{64}', result_fname)[0]
                assert result_fname == txid+'.txn'
                assert not os.path.exists(in_file)
            else:
                assert 'final' in result_fname
                assert os.path.exists(in_file)

            from pycoin.tx.Tx import Tx
            # parse it a little
            assert result[0:4] != b'psbt', 'still a PSBT, but asked for finalize'
            t = Tx.from_bin(result)
            assert t.version in [1, 2]
            assert t.id() == txid

        else:
            assert result[0:5] == b'psbt\xff'

            if complete:
                assert '-signed' in result_fname
            else:
                assert '-part' in result_fname

            if del_after:
                assert not os.path.exists(in_file)

            from psbt import BasicPSBT
            was = BasicPSBT().parse(ip) 
            now = BasicPSBT().parse(result)
            assert was.txn == now.txn
            assert was != now

        return ip, result, txid

    return doit

@pytest.fixture
def try_sign(start_sign, end_sign):

    def doit(filename_or_data, accept=True, finalize=False, accept_ms_import=False):
        ip = start_sign(filename_or_data, finalize=finalize)
        return ip, end_sign(accept, finalize=finalize, accept_ms_import=accept_ms_import)

    return doit

@pytest.fixture
def start_sign(dev):

    def doit(filename, finalize=False, stxn_flags=0x0):
        if filename[0:5] == b'psbt\xff':
            ip = filename
            filename = 'memory'
        else:
            ip = open(filename, 'rb').read()
            if ip[0:10] == b'70736274ff':
                ip = a2b_hex(ip.strip())
            assert ip[0:5] == b'psbt\xff'

        ll, sha = dev.upload_file(ip)

        dev.send_recv(CCProtocolPacker.sign_transaction(ll, sha, finalize, flags=stxn_flags))

        return ip

    return doit

@pytest.fixture
def end_sign(dev, need_keypress):
    from ckcc_protocol.protocol import CCUserRefused

    def doit(accept=True, in_psbt=None, finalize=False, accept_ms_import=False, expect_txn=True):

        if accept_ms_import:
            # XXX would be better to do cap_story here, but that would limit test to simulator
            need_keypress('y')
            time.sleep(0.050)

        if accept != None:
            need_keypress('y' if accept else 'x', timeout=None)

        if accept == False:
            with pytest.raises(CCUserRefused):
                done = None
                while done == None:
                    time.sleep(0.050)
                    done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)
            return
        else:
            done = None
            while done == None:
                time.sleep(0.050)
                done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

        assert len(done) == 2

        resp_len, chk = done
        psbt_out = dev.download_file(resp_len, chk)

        if not expect_txn:
            # skip checks; it's text
            return psbt_out

        if not finalize:
            if in_psbt:
                from psbt import BasicPSBT
                assert BasicPSBT().parse(in_psbt) != None
        else:
            from pycoin.tx.Tx import Tx
            # parse it
            res = psbt_out
            assert res[0:4] != b'psbt', 'still a PSBT, but asked for finalize'
            t = Tx.from_bin(res)
            assert t.version in [1, 2]

        return psbt_out

    return doit

# use these for hardware version support
@pytest.fixture(scope='session')
def is_mark1(request):
    return int(request.config.getoption('--mk')) == 1

@pytest.fixture(scope='session')
def is_mark2(request):
    return int(request.config.getoption('--mk')) == 2

@pytest.fixture(scope='session')
def is_mark3(request):
    return int(request.config.getoption('--mk')) == 3

# useful fixtures related to multisig
from test_multisig import (import_ms_wallet, make_multisig, offer_ms_import, fake_ms_txn,
                                make_ms_address, clear_ms, make_myself_wallet)
from test_bip39pw import set_bip39_pw, clear_bip39_pw

#EOF
