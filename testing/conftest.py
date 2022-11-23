# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, sys, random, re, ndef, os, glob
from ckcc.protocol import CCProtocolPacker
from helpers import B2A, U2SAT, prandom
from api import bitcoind, match_key, bitcoind_finalizer, bitcoind_analyze, bitcoind_decode
from api import bitcoind_wallet, bitcoind_d_wallet, bitcoind_d_wallet_w_sk, bitcoind_d_sim_sign, bitcoind_d_sim_watch
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

    parser.addoption("--mk", default=4, help="Assume mark N hardware")

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
    # - can work on real product too, if "debug build" is used.

    def doit(cmd, binary=False):
        s = dev.send_recv(b'EXEC' + cmd.encode('utf-8'), timeout=60000, encrypt=False)
        if binary: return s
        #print(f'sim_exec: {cmd!r} -> {s!r}')
        return s.decode('utf-8') if not isinstance(s, str) else s

    return doit

@pytest.fixture(scope='module')
def sim_eval(dev):
    # eval an expression in the simulator's interpretor
    # - can work on real product too, if "debug build" is used.

    def doit(cmd, timeout=None):
        return dev.send_recv(b'EVAL' + cmd.encode('utf-8'), timeout=timeout).decode('utf-8')

    return doit

@pytest.fixture(scope='module')
def sim_execfile(simulator):
    # run a whole file in the simulator's interpretor
    # - requires shared filesystem
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
            # simulator has special USB command, and can be used on real device in dev builds
            dev.send_recv(CCProtocolPacker.sim_keypress(k.encode('ascii')), timeout=timeout)

    return doit

@pytest.fixture(scope='module')
def enter_number(need_keypress):
    def doit(number):
        number = str(number) if not isinstance(number, str) else number
        for d in number:
            need_keypress(d)
        need_keypress('y')

    return doit

@pytest.fixture(scope='module')
def enter_pin(enter_number, need_keypress, cap_screen):
    def doit(pin):
        assert '-' in pin
        a,b = pin.split('-')
        enter_number(a)

        # capture words? hard to know in general what they should be tho
        words = cap_screen().split('\n')[2:4]

        need_keypress('y')
        enter_number(b)

        return words

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
    # get an individual setting
    def doit(name, default=None):
        from json import loads
        sim_exec('import main; main.SKEY = %r; main.DEFAULT=%r' % (name, default))
        resp = sim_execfile('devtest/get-setting.py')
        assert 'Traceback' not in resp
        return loads(resp)

    return doit

@pytest.fixture(scope='module')
def addr_vs_path(master_xpub):
    from pycoin.key.BIP32Node import BIP32Node
    from ckcc_protocol.constants import AF_CLASSIC, AFC_PUBKEY, AF_P2WPKH, AFC_SCRIPT
    from ckcc_protocol.constants import AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH
    from bech32 import bech32_decode, convertbits, Encoding
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


        if addr_fmt in {None,  AF_CLASSIC}:
            # easy
            assert sk.address() == given_addr

        elif addr_fmt & AFC_PUBKEY:

            pkh = sk.hash160(use_uncompressed=False)

            if addr_fmt == AF_P2WPKH:
                hrp, data, enc = bech32_decode(given_addr)
                assert enc == Encoding.BECH32
                decoded = convertbits(data[1:], 5, 8, False)
                assert hrp in {'tb', 'bc' , 'bcrt'}
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
                hrp, data, enc = bech32_decode(given_addr)
                assert enc == Encoding.BECH32
                assert hrp in {'tb', 'bc' , 'bcrt'}
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
def cap_menu(sim_exec):
    "Return menu items as a list"
    def doit():
        rv = sim_exec('from ux import the_ux; RV.write(repr('
                            '[i.label for i in the_ux.top_of_stack().items]))')
        if 'Traceback' in rv:
            raise RuntimeError(rv)      # not looking at a menu, typically
        return eval(rv)

    return doit

@pytest.fixture(scope='module')
def is_ftux_screen(sim_exec):
    "are we presenting a view from ftux.py"
    def doit():
        rv = sim_exec('from ux import the_ux; RV.write(repr('
                            'type(the_ux.top_of_stack())))')
        return 'FirstTimeUX' in rv

    return doit

@pytest.fixture
def expect_ftux(cap_menu, cap_story, need_keypress, is_ftux_screen):
    # seed was entered, FTUX happens, get to main menu
    def doit():
        # first time UX here
        while is_ftux_screen():
            _, story = cap_story()
            if not story: 
                break
            # XXX test more here
            if 'Enable NFC' in story:
                need_keypress('x')
            elif 'Enable USB' in story:
                need_keypress('y')
            elif 'Disable USB' in story:
                need_keypress('x')
            else:
                raise ValueError(story)

        m = cap_menu()
        assert m[0] == 'Ready To Sign'

    return doit


@pytest.fixture(scope='module')
def cap_screen(sim_exec):
    def doit():
        # capture text shown; 4 lines or so?
        return sim_exec('RV.write(sim_display.full_contents)')

    return doit

@pytest.fixture(scope='module')
def cap_story(sim_exec):
    # returns (title, body) of whatever story is being actively shown
    def doit():
        rv = sim_exec("RV.write('\0'.join(sim_display.story or []))")
        return rv.split('\0', 1) if rv else ('','')

    return doit

@pytest.fixture(scope='module')
def cap_image(sim_exec):

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

        #raw = a2b_hex(sim_execfile('devtest/cap-image.py'))
        raw = a2b_hex(sim_exec('''
from glob import dis;
from ubinascii import hexlify as b2a_hex;
RV.write(b2a_hex(dis.dis.buffer))'''))

        assert len(raw) == (128*64//8)
        return Image.frombytes('L', (128,64), flip(raw), 'raw')

    return doit

QR_HISTORY = []

@pytest.fixture(scope='session')
def qr_quality_check():
    # Use this with cap_screen_qr 
    print("QR codes will be captured and shown at end of run.")
    yield None

    # quick test:
    #   py.test test_drv_entro.py -k test_path_index --ff -k '0-64-bytes'
    #

    global QR_HISTORY
    if not QR_HISTORY: return

    import textwrap
    from PIL import Image, ImageOps, ImageFont, ImageDraw
    w,h = QR_HISTORY[0][1].size
    count = len(QR_HISTORY)
    TH = 32

    scale=3
    rv = Image.new('RGB', (w*scale, ((h*scale)+TH)*count), color=(64,64,64))
    y = 0
    try:
        fnt = ImageFont.truetype('Courier', size=10)
    except:
        try:
            fnt = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', size=10)
        except:
            fnt = ImageFont.load_default()

    dr = ImageDraw.Draw(rv)
    mw = int((w*scale) / dr.textsize('M', fnt)[0])

    for test_name, img in QR_HISTORY:
        if '[' in test_name:
            test_name = test_name[test_name.index('['):].replace(' (call)','')
        else:
            test_name = test_name.replace(' (call)','')

        img = img.resize((w*scale,h*scale), resample=Image.NEAREST)
        rv.paste(img, (0, y))
        y += (h*scale)

        dr.multiline_text((4, y+3), textwrap.fill(test_name, mw), font=fnt, fill=(0,255,0))
        y += TH

    #rv = rv.resize(tuple(c*4 for c in rv.size), resample=Image.NEAREST)

    rv.save('debug/all-qrs.png')
    rv.show()



@pytest.fixture(scope='module')
def cap_screen_qr(cap_image):
    def doit(x=0, w=64):
        # NOTE: version=4 QR is pixel doubled to be 66x66 with 2 missing lines at bottom
        # LATER: not doing that anymore; v=3 doubled, all higher 1:1 pixels (tiny)
        global QR_HISTORY

        try:
            import zbar
        except ImportError:
            raise pytest.skip('need zbar-py module')
        import numpy, os
        from PIL import ImageOps

        # see <http://qrlogo.kaarposoft.dk/qrdecode.html>

        orig_img = cap_image()

        # document it
        if x < 10:
            # removes dups: happen when same image samples for two different
            # QR's in side-by-side mode
            tname = os.environ.get('PYTEST_CURRENT_TEST')
            QR_HISTORY.append( (tname, orig_img) )

        img = orig_img.crop( (x, 0, x+w, w) )
        img = ImageOps.expand(img, 16, 0)
        img = img.resize( (256, 256))
        img.save('debug/last-qr.png')
        #img.show()
    
        scanner = zbar.Scanner()
        np = numpy.array(img.getdata(), 'uint8').reshape(img.width, img.height)

        for sym, value, *_ in scanner.scan(np):
            assert sym == 'QR-Code', 'unexpected symbology: ' + sym
            return value            # bytes, could be binary

        # debug: check debug/last-qr.png
        raise pytest.fail('qr code not found')

    return doit

@pytest.fixture(scope='module')
def get_pp_sofar(sim_exec):
    # get entry value for bip39 passphrase
    def doit():
        resp = sim_exec('import seed; RV.write(seed.pp_sofar)')
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
            time.sleep(.1)      # required

            m = cap_menu()

            if 'CANCEL' in m:
                # special case to get out of passphrase menu
                pick_menu_item('CANCEL')
                time.sleep(.01)
                need_keypress('y')

            if m[0] in { 'New Seed Words',  'Ready To Sign'}:
                break
        else:
            raise pytest.fail("trapped in a menu")

        return m

    return doit

@pytest.fixture
def pick_menu_item(cap_menu, need_keypress):
    WRAP_IF_OVER = 16       # see ../shared/menu.py

    def doit(text):
        print(f"PICK menu item: {text}")
        need_keypress('0')
        m = cap_menu()
        if text not in m:
            raise KeyError(text, "%r not in menu: %r" % (text, m))

        m_pos = m.index(text)

        if len(m) > WRAP_IF_OVER and m_pos > (len(m)//2):
            # use wrap around, work up from bottom
            for n in range(len(m) - m_pos):
                need_keypress('5')
                time.sleep(.01)      # required
            need_keypress('y')
            time.sleep(.01)      # required
        else:
            # go down
            for n in range(m_pos):
                need_keypress('8')
                time.sleep(.01)      # required
            need_keypress('y')
            time.sleep(.01)      # required

    return doit


@pytest.fixture(scope='module')
def virtdisk_path(request, is_simulator, only_mk4):
    # get a path to indicated filename on emulated/shared dir

    def doit(fn):
        # could use: ckcc.get_sim_root_dirs() here
        if is_simulator():
            assert os.path.isdir('../unix/work/VirtDisk')
            return '../unix/work/VirtDisk/' + fn
        elif sys.platform == 'darwin':

            if not request.config.getoption("--manual"):
                raise pytest.fail('must use --manual CLI option')

            return '/Volumes/COLDCARD/' + fn
        else:
            raise pytest.fail('need to know where Mk4 gets mounted')

    return doit

@pytest.fixture(scope='module')
def virtdisk_wipe(dev, only_mk4, virtdisk_path):
    def doit():
        for fn in glob.glob(virtdisk_path('*')):
            if os.path.isdir(fn): continue
            if 'readme' in fn.lower(): continue
            if 'gitignore' in fn: continue
            print(f'RM {fn}')
            os.remove(fn)
    return doit


@pytest.fixture(scope='module')
def microsd_path(simulator):
    # open a file from the simulated microsd

    def doit(fn):
        # could use: ckcc.get_sim_root_dirs() here
        return '../unix/work/MicroSD/' + fn

    return doit

@pytest.fixture(scope='module')
def open_microsd(simulator, microsd_path):
    # open a file from the simulated microsd

    def doit(fn, mode='rb'):
        return open(microsd_path(fn), mode)

    return doit

@pytest.fixture(scope="module")
def clean_microsd(microsd_path):
    def doit():
        dir = microsd_path("")
        ls = os.listdir(dir)
        for fname in ls:
            if fname in ["README.md", ".gitignore", "messages", "psbt"]:
                continue
            os.remove(dir + fname)
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

        sim_exec('from main import settings; settings.put_volatile("xfp", 0x%x);' % need_xfp)

    yield doit

    sim_exec('from main import settings; settings.overrides.clear();')

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
def use_mainnet(settings_set):
    def doit():
        settings_set('chain', 'BTC')
    yield doit
    settings_set('chain', 'XTN')


@pytest.fixture(scope="function")
def use_regtest(settings_set):
    def doit():
        settings_set('chain', 'XRT')
    yield doit
    settings_set('chain', 'XTN')


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
        x = sim_exec("settings.set('%s', %r)" % (key, val))
        assert x == ''

    return doit

@pytest.fixture()
def settings_get(sim_exec):

    def doit(key):
        cmd = f"RV.write(repr(settings.get('{key}')))"
        resp = sim_exec(cmd)
        assert 'Traceback' not in resp, resp
        return eval(resp)

    return doit

@pytest.fixture()
def settings_remove(sim_exec):

    def doit(key):
        x = sim_exec("settings.remove_key('%s')" % key)
        assert x == ''

    return doit

@pytest.fixture(scope='module')
def repl(request, is_mark4):
    return request.getfixturevalue('mk4_repl' if is_mark4 else 'old_mk_repl')
    

@pytest.fixture(scope='module')
def mk4_repl(sim_eval, sim_exec):
    # Provide an interactive connection to the REPL, using the debug build USB commands

    class Mk4USBRepl:
        def eval(self, cmd, max_time=3):
            # send a command, wait for it to finish
            resp = sim_eval(cmd)
            print(f"eval: {cmd} => {resp}")
            if 'Traceback' in resp:
                raise RuntimeError(resp)
            return eval(resp)

        def exec(self, cmd, proc_time=1, raw=False):
            # send a (one line) command and read the one-line response
            resp = sim_exec(cmd)
            print(f"exec: {cmd} => {resp}")
            if raw: return resp
            return eval(resp) if resp else None

    return Mk4USBRepl()

@pytest.fixture(scope='module')
def old_mk_repl(dev=None):
    # Provide an interactive connection to the REPL. Has to be real device, with
    # dev features enabled. Best really with unit in factory mode.
    import sys, serial
    from serial.tools.list_ports import comports

    # NOTE: 
    # - tested only on Mac, but might work elsewhere.
    # - board needs to be reset between runs, because USB protocol (not serial) is disabled by this
    # - relies on virtual COM port present on Mk1-3 but not mk4

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
            return bitcoind.rpc.decoderawtransaction(B2A(raw_txn))
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
def check_against_bitcoind(bitcoind, use_regtest, sim_exec, sim_execfile):

    def doit(hex_txn, fee, num_warn=0, change_outs=None, dests=[]):
        # verify our understanding of a TXN (and esp its outputs) matches
        # the same values as what bitcoind generates

        try:
            decode = bitcoind.rpc.decoderawtransaction(hex_txn)
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            decode = bitcoind.rpc.decoderawtransaction(hex_txn)

        #print("Bitcoin code says:", end=''); pprint(decode)

        if dests:
            # check we got right destination address(es)
            for outn, expect_addr in dests:
                assert decode['vout'][outn]['scriptPubKey']['address'] == expect_addr

        # leverage bitcoind's transaction decoding
        ex = dict(  lock_time = decode['locktime'],
                    had_witness = False,        # input txn doesn't have them, typical?
                    num_inputs = len(decode['vin']),
                    num_outputs = len(decode['vout']),
                    miner_fee = U2SAT(fee),
                    warnings_expected = num_warn,
                    total_value_out = sum(U2SAT(i['value']) for i in decode['vout']),
                    destinations = [(U2SAT(i['value']), i['scriptPubKey']['address'])
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
            os.remove(f)

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
                time.sleep(0.00)
                done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

        assert len(done) == 2

        resp_len, chk = done
        psbt_out = dev.download_file(resp_len, chk)

        if not expect_txn:
            # skip checks; it's text
            return psbt_out

        sigs = []

        if not finalize:
            from psbt import BasicPSBT
            tp = BasicPSBT().parse(psbt_out)
            assert tp is not None

            for i in tp.inputs:
                sigs.extend(i.part_sigs.values())
        else:
            from pycoin.tx.Tx import Tx
            # parse it
            res = psbt_out
            assert res[0:4] != b'psbt', 'still a PSBT, but asked for finalize'
            t = Tx.from_bin(res)
            assert t.version in [1, 2]

            # TODO: pull out signatures from signed txn, but pycoin not helpful on that
                    
        for sig in sigs:
            assert len(sig) <= 71, "overly long signature observed"

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
def is_mark3(dev):
    v = dev.send_recv(CCProtocolPacker.version()).split()
    return (v[4] == 'mk3')

@pytest.fixture(scope='session')
def is_mark4(dev):
    v = dev.send_recv(CCProtocolPacker.version()).split()
    return (v[4] == 'mk4')

@pytest.fixture(scope='session')
def mk_num(dev):
    # return 1..4 as number (mark number)
    v = dev.send_recv(CCProtocolPacker.version()).split()[4]
    assert v[0:2] == 'mk'
    return int(v[2:])

@pytest.fixture(scope='session')
def only_mk4(dev):
    # better: ask it .. use USB version cmd
    v = dev.send_recv(CCProtocolPacker.version()).split()
    if v[4] != 'mk4':
        raise pytest.skip("Mk4 only")

@pytest.fixture(scope='session')
def only_mk3(dev):
    # better: ask it .. use USB version cmd
    v = dev.send_recv(CCProtocolPacker.version()).split()
    if v[4] != 'mk3':
        raise pytest.skip("Mk3 only")

@pytest.fixture(scope='module')
def rf_interface(only_mk4, sim_exec):
    # provide a read/write connection over NFC
    # - requires pyscard module and NFC-V reader like HID OMNIKEY 5022CL
    raise pytest.xfail('broken NFC-V challenges')
    class RFHandler:
        def __init__(self, want_atr=None):
            from smartcard.System import readers as get_readers
            from smartcard.Exceptions import CardConnectionException, NoCardException

            readers = get_readers()
            if not readers:
                raise pytest.fail("no card readers found")

            # search for our card
            for r in readers:
                try:
                    conn = r.createConnection()
                except:
                    print(f"Fail: {r}");
                    continue
                
                try:
                    conn.connect()
                    atr = conn.getATR()
                except (CardConnectionException, NoCardException):
                    print(f"Empty reader: {r}")
                    continue

                if want_atr and atr != want_atr:
                    continue

                # accept first suitable "card"
                break
            else:
                raise pytest.fail("did not find NFC target")

            self.conn = conn

        def apdu(self, cls, ins, data=b'', p1=0, p2=0):
            # send APDU
            lst = [ cls, ins, p1, p2, len(data)] + list(data)
            resp, sw1, sw2 = self.conn.transmit(lst)
            resp = bytes(resp)
            return hex((sw1 << 8) | sw2), resp
            
        # XXX not simple; Omnikey wants secure channel (AES) for this
        def read_nfc(self):
            return b'helllo'
        def write_nfc(self, ccfile):
            pass

    # get the CC into NFC tap mode (but no UX)
    sim_exec('glob.NFC.set_rf_disable(0)')

    time.sleep(3)

    yield RFHandler()

    sim_exec('glob.NFC.set_rf_disable(1)')

@pytest.fixture()
def nfc_read(request, only_mk4):
    # READ data from NFC chip
    # - perfer to do over NFC reader, but can work over USB too
    def doit_usb():
        sim_exec = request.getfixturevalue('sim_exec')
        rv = sim_exec('RV.write(glob.NFC.dump_ndef() if glob.NFC else b"")', binary=True)
        if b'Traceback' in rv: raise pytest.fail(rv.decode('utf-8'))
        return rv

    try:
        raise NotImplementedError
        rf = request.getfixturevalue('rf_interface')
        return rf.read_nfc
    except:
        return doit_usb

@pytest.fixture()
def nfc_write(request, only_mk4):
    # WRITE data into NFC "chip"
    def doit_usb(ccfile):
        sim_exec = request.getfixturevalue('sim_exec')
        need_keypress = request.getfixturevalue('need_keypress')
        rv = sim_exec('list(glob.NFC.big_write(%r))' % ccfile)
        if 'Traceback' in rv: raise pytest.fail(rv)
        need_keypress('y')      # to end the animation and have it check value immediately

    try:
        raise NotImplementedError
        rf = request.getfixturevalue('rf_interface')
        return rf.write_nfc
    except:
        return doit_usb

def ccfile_wrap(recs):
    CC_FILE = bytes([0xE2, 0x43, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00,   0x03])
    if len(recs) >= 255:      # testing code limitation here FIXME
        raise pytest.xfail('cant do NFC > 250 bytes yet in tests')
    return CC_FILE + bytes([len(recs)]) + recs + b'\xfe'


@pytest.fixture()
def nfc_write_text(nfc_write):
    def doit(text):
        msg = b''.join(ndef.message_encoder([ndef.TextRecord(text), ]))
        return nfc_write(ccfile_wrap(msg))
    return doit

@pytest.fixture()
def nfc_read_json(nfc_read):
    def doit():
        import json
        got = list(ndef.message_decoder(nfc_read()))
        assert len(got) == 1
        got = got[0]
        assert got.type == 'application/json'
        return json.loads(got.data)

    return doit

@pytest.fixture()
def nfc_read_text(nfc_read):
    def doit():
        got = list(ndef.message_decoder(nfc_read()))
        assert len(got) == 1
        got = got[0]
        assert got.type == 'urn:nfc:wkt:T'
        return got.text
    return doit

@pytest.fixture()
def nfc_block4rf(sim_eval):
    # wait until RF is enabled and something to read (doesn't read it tho)
    def doit(timeout=15):
        for i in range(timeout*4):
            rv = sim_eval('glob.NFC.rf_on')
            if rv: break
            sleep(0.250)
        else:
            raise pytest.fail("NFC timeout")

    return doit

@pytest.fixture
def load_shared_mod():
    # load indicated file.py as a module
    # from <https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path>
    def doit(name, path):
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return doit

# useful fixtures related to multisig
from test_multisig import (import_ms_wallet, make_multisig, offer_ms_import, fake_ms_txn,
                                make_ms_address, clear_ms, make_myself_wallet)
from test_bip39pw import set_bip39_pw, clear_bip39_pw

# EOF
