# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, sys, random, re, ndef, os, glob, hashlib, json, functools, io, math, bech32, pdb
from subprocess import check_output
from ckcc.protocol import CCProtocolPacker
from helpers import B2A, U2SAT, hash160, taptweak
from base58 import decode_base58_checksum
from bip32 import BIP32Node
from msg import verify_message
from api import bitcoind, match_key
from api import bitcoind_wallet, bitcoind_d_wallet, bitcoind_d_wallet_w_sk, bitcoind_d_sim_sign, bitcoind_d_dev_watch
from api import bitcoind_d_sim_watch, finalize_v2_v0_convert
from binascii import b2a_hex, a2b_hex
from constants import *
from charcodes import *
from core_fixtures import _need_keypress, _sim_exec, _cap_story, _cap_menu, _cap_screen
from core_fixtures import _press_select, _pick_menu_item, _enter_complex, _dev_hw_label


# lock down randomness
random.seed(42)

if sys.platform == 'darwin':
    # BUGFIX: my ARM-based MacOS system uses rosetta to run Python in x86 mode
    # and so I needed this?
    # - this assumes "brew install secp256k1"
    os.environ['PYSECP_SO'] = '/usr/local/lib/libsecp256k1.dylib'

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
    parser.addoption("--psbt2", action="store_true",
                     default=False, help="fake_txn produces PSBTv2")
    parser.addoption("--Q", action="store_true", default=False,
                     help="Uses Q simulator when running 'login_settings_tests' module")
    parser.addoption("--headless", action="store_true", default=False,
                     help="Simulator is running in headless mode")
    # to make bitcoind produce psbt v2 one currently needs https://github.com/achow101/bitcoin/tree/psbt2
    # or wait until https://github.com/bitcoin/bitcoin/pull/21283 merged and released

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
    f = functools.partial(_sim_exec, dev)
    return f

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
def send_ux_abort(simulator):

    def doit():
        # simulator has special USB command
        # - this is a special "key"
        simulator.send_recv(CCProtocolPacker.sim_ux_abort())

    return doit

@pytest.fixture
def OK(is_q1):
    return "ENTER" if is_q1 else "OK"

@pytest.fixture
def X(is_q1):
    return "CANCEL" if is_q1 else "X"

@pytest.fixture(scope='module')
def need_keypress(dev, request):
    def doit(k, timeout=1000):
        if request.config.getoption("--manual"):
            # need actual user interaction
            print("==> NOW, on the Coldcard, press key: %r (then enter here)" % k, file=sys.stderr)
            input()
        else:
            # simulator has special USB command, and can be used on real device in dev builds
            _need_keypress(dev, k, timeout=timeout)

    return doit


@pytest.fixture(scope='module')
def enter_number(need_keypress, press_select):
    def doit(number):
        number = str(number) if not isinstance(number, str) else number
        for d in number:
            need_keypress(d)
        press_select()

    return doit

@pytest.fixture
def enter_complex(dev, is_q1):
    # full entry mode
    # - just left to right here
    # - not testing case swap, because might remove that
    f = functools.partial(_enter_complex, dev, is_q1)
    return f

@pytest.fixture(scope='module')
def enter_hex(need_keypress, enter_text, is_q1):
    def doit(hex_str):
        if is_q1:
            return enter_text(hex_str)

        for ch in hex_str:
            int_ch = int(ch, 16)
            for i in range(int_ch):
                need_keypress("5")  # up
            need_keypress("9")  # next
        need_keypress('y')

    return doit

@pytest.fixture(scope='module')
def enter_pin(enter_number, press_select, cap_screen, is_q1):
    def doit(pin):
        assert '-' in pin
        a,b = pin.split('-')
        enter_number(a)

        scr = cap_screen().split('\n')
        if is_q1:
            words = [i.strip() for i in scr[7].split()]
        else:
            # capture words? hard to know in general what they should be tho
            words = scr[2:4]
            press_select()

        enter_number(b)

        return words

    return doit


@pytest.fixture(scope='module')
def do_keypresses(need_keypress):
    # do a series of keypresses, any kind
    def doit(value):
        for ch in value:
            need_keypress(ch)

    return doit
    

@pytest.fixture(scope='module')
def enter_text(need_keypress, is_q1):
    # enter a text value, might be a number or string ... on Q can be multiline
    def doit(value, multiline=False):
        if not multiline:
            assert KEY_ENTER not in value
        if not is_q1:
            assert value.isdigit(), f'bad value: {value}'
            assert not multiline

        for ch in value:
            need_keypress(ch)

        if is_q1:
            time.sleep(0.010)
            need_keypress(KEY_ENTER if not multiline else KEY_CANCEL)
        else:
            need_keypress('y')

    return doit

    
@pytest.fixture(scope='module')
def master_xpub(dev):
    if hasattr(dev.dev, 'pipe'):
        # this works better against simulator in HSM mode, where the xpub cmd may be disabled
        return simulator_fixed_tpub

    r = dev.send_recv(CCProtocolPacker.get_xpub('m'), timeout=None, encrypt=1)

    assert r[1:4] == 'pub', r

    if r[0:4] == dev.master_xpub[0:4]:
        assert r == dev.master_xpub
    elif dev.master_xpub:
        # testnet vs. mainnet difference
        a = BIP32Node.from_wallet_key(r)
        b = BIP32Node.from_wallet_key(dev.master_xpub)

        assert a.node == b.node

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
    from bip32 import BIP32Node
    from ckcc_protocol.constants import AF_CLASSIC, AFC_PUBKEY, AF_P2WPKH, AFC_SCRIPT
    from ckcc_protocol.constants import AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH
    from bech32 import bech32_decode, convertbits, decode, Encoding
    from hashlib import sha256

    def doit(given_addr, path=None, addr_fmt=None, script=None, chain="XTN"):
        if not script:
            try:
                # prefer using xpub if we can
                mk = BIP32Node.from_wallet_key(master_xpub)
                mk._netcode = chain
                sk = mk.subkey_for_path(path)
            except:
                mk = BIP32Node.from_wallet_key(simulator_fixed_tprv)
                mk._netcode = chain
                sk = mk.subkey_for_path(path)

        if addr_fmt == AF_P2TR:
            tweaked_xonly = taptweak(sk.sec()[1:])
            decoded = decode(given_addr[:2], given_addr)
            assert not given_addr.startswith("bcrt")  # regtest
            assert tweaked_xonly == bytes(decoded[1])

        elif addr_fmt in {None,  AF_CLASSIC}:
            # easy
            assert sk.address(chain=chain) == given_addr

        elif addr_fmt & AFC_PUBKEY:

            pkh = sk.hash160()

            if addr_fmt == AF_P2WPKH:
                hrp, data, enc = bech32_decode(given_addr)
                assert enc == Encoding.BECH32
                decoded = convertbits(data[1:], 5, 8, False)
                assert hrp in {'tb', 'bc' , 'bcrt'}
                assert bytes(decoded[-20:]) == pkh
            else:
                assert addr_fmt == AF_P2WPKH_P2SH
                assert given_addr[0] in '23'
                expect = decode_base58_checksum(given_addr)[1:]
                assert len(expect) == 20
                assert hash160(b'\x00\x14' + pkh) == expect

        elif addr_fmt & AFC_SCRIPT:
            assert script, 'need a redeem/witness script'
            if addr_fmt == AF_P2SH:
                assert given_addr[0] in '23'
                expect = decode_base58_checksum(given_addr)[1:]
                assert hash160(script) == expect

            elif addr_fmt == AF_P2WSH:
                hrp, data, enc = bech32_decode(given_addr)
                assert enc == Encoding.BECH32
                assert hrp in {'tb', 'bc' , 'bcrt'}
                decoded = convertbits(data[1:], 5, 8, False)
                assert bytes(decoded[-32:]) == sha256(script).digest()

            elif addr_fmt == AF_P2WSH_P2SH:
                assert given_addr[0] in '23'
                expect = decode_base58_checksum(given_addr)[1:]
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
def cap_menu(dev):
    "Return menu items as a list"
    f = functools.partial(_cap_menu, dev)
    return f

@pytest.fixture(scope='module')
def is_ftux_screen(sim_exec):
    "are we presenting a view from ftux.py??"
    def doit():
        rv = sim_exec('from ux import the_ux; RV.write(repr('
                            'type(the_ux.top_of_stack())))')
        return 'FirstTimeUX' in rv

    return doit

@pytest.fixture
def expect_ftux(cap_menu, cap_story, press_select, is_ftux_screen):
    # seed was entered, FTUX happens, get to main menu
    def doit():
        # first time UX here
        while is_ftux_screen():
            _, story = cap_story()
            if not story: 
                break
            press_select()

        m = cap_menu()
        assert m[0] == 'Ready To Sign'

    return doit


@pytest.fixture(scope='module')
def cap_screen(dev):
    f = functools.partial(_cap_screen, dev)
    return f

@pytest.fixture(scope='module')
def cap_text_box(cap_screen):
    # provides text inside a lined box on the screen right now - Q1 only
    def doit():
        # capture text shown; 4-10 lines or so?
        lines = cap_screen().split('\n')
        rv = []
        for ln in lines:
            ll = ln.find('\x03')        # left-side vertical line
            rr = ln.find('\x07')        # right-side vertical line (dashed)
            if ll >=0 and rr >= ll:
                rv.append(ln[ll+1:rr])
        return rv

    return doit

@pytest.fixture(scope='module')
def cap_story(dev):
    # returns (title, body) of whatever story is being actively shown
    f = functools.partial(_cap_story, dev)
    return f


@pytest.fixture(scope='module')
def cap_image(request, sim_exec, is_q1, is_headless):

    def flip(raw):
        reorg = bytearray(128*64)
        j = 0 
        for y in range(64//8):
            for by in range(8):
                for x in range(128):
                    reorg[j] = 255 if (raw[x+(128*y)] & (1 << by)) else 0
                    j += 1
        return bytes(reorg)

    # returns Pillow image of whatever pixels are being actively shown on OLED/LCD
    def doit():
        from PIL import Image

        if is_q1:
            if is_headless:
                raise pytest.skip("headless mode: QR tests disabled")
            # trigger simulator to capture a snapshot into a named file, read it.
            fn = os.path.realpath(f'./debug/snap-{random.randint(int(1E6), int(9E6))}.png')
            try:
                sim_exec(f"from glob import dis; dis.dis.save_snapshot({fn!r})")
                for _ in range(20):
                    time.sleep(0.10)
                    try:
                        rv = Image.open(fn)
                        break
                    except:
                        # PIL parsing errors and FileNotFoundError
                        continue
            finally:
                os.remove(fn)
            return rv
        else:
            # reads internal memory buffer of intended screen contents
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

    scale=2
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
    left, top, right, bottom = dr.textbbox((0, 0), text='M', font=fnt)
    size = (right - left, bottom - top)
    mw = int((w*scale) / size[0])

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
    def doit(no_history=False):
        # NOTE: version=4 QR is pixel doubled to be 66x66 with 2 missing lines at bottom
        # LATER: not doing that anymore; v={1,2,3} doubled, all higher 1:1 pixels (tiny)
        global QR_HISTORY

        try:
            import zbar
        except ImportError:
            raise pytest.skip('need zbar-py module')
        import numpy, os
        from PIL import ImageOps, ImageDraw

        # see <http://qrlogo.kaarposoft.dk/qrdecode.html>

        orig_img = cap_image()

        if not no_history:
            # document it
            tname = os.environ.get('PYTEST_CURRENT_TEST')
            QR_HISTORY.append( (tname, orig_img) )

        if orig_img.width == 128:
            # Mk3/4 - pull out just the QR, blow it up 16x
            x, w = 2, 64
            img = orig_img.crop( (x, 0, x+w, w) )
            img = ImageOps.expand(img, 16, 0)       # add border
            img = img.resize( (256, 256))
        else:
            # Q - convert to greyscale
            # - and trim progress bar (does cause readability issues)
            # - MAYBE: blow up the size, helps on fine 1:1 QR cases.
            w, h = orig_img.size        # 320x240
            img = orig_img.crop( (0, 0, w, h-5) ).convert('L')

        img.save('debug/last-qr.png')
        #img.show()

        # Above usually works @ zoom=1, but not always!
        # - simulate what users do... move phone back and forth until it scans
        oo = img
        for zoom in range(1, 7):
            if zoom > 1:
                w, h = oo.size
                img = oo.resize( (w*zoom, h*zoom) )

            # Important: w/h reversed in shape of NP array
            np = numpy.array(img.getdata(), 'uint8').reshape(img.height, img.width)

            scanner = zbar.Scanner()
            for sym, value, *_ in scanner.scan(np):
                if sym == 'QR-Code':
                    return value            # bytes, could be binary

        # for debug, check debug/last-qr.png
        raise RuntimeError('qr code not found')

    return doit

@pytest.fixture(scope='module')
def get_pp_sofar(sim_exec):
    # get entry value for bip39 passphrase
    def doit():
        resp = sim_exec('import seed; RV.write(seed.PassphraseMenu.pp_sofar)')
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
            if not ln: continue
            if ln[0] == '#': continue

            assert ' = ' in ln
            n, v = ln.split(' = ', 1)
            rv[n] = loads(v)
        return rv

    return doit

@pytest.fixture(scope='module')
def press_select(dev, has_qwerty):
    f = functools.partial(_press_select, dev, has_qwerty)
    return f

@pytest.fixture(scope='module')
def press_cancel(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_CANCEL if has_qwerty else 'x', **kws)
    return doit

@pytest.fixture(scope='module')
def press_delete(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_DELETE if has_qwerty else 'x', **kws)
    return doit

@pytest.fixture(scope='module')
def press_nfc(need_keypress, has_qwerty):
    def doit(num=3, **kws):
        need_keypress(KEY_NFC if has_qwerty else str(num), **kws)
    return doit

@pytest.fixture(scope='module')
def press_up(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_UP if has_qwerty else "5", **kws)
    return doit

@pytest.fixture(scope='module')
def press_down(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_DOWN if has_qwerty else "8", **kws)
    return doit

@pytest.fixture(scope='module')
def press_left(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_LEFT if has_qwerty else "7", **kws)
    return doit

@pytest.fixture(scope='module')
def press_right(need_keypress, has_qwerty):
    def doit(**kws):
        need_keypress(KEY_RIGHT if has_qwerty else "9", **kws)
    return doit

@pytest.fixture
def goto_home(cap_menu, press_cancel, press_select, pick_menu_item, cap_screen):

    def doit():
        # get to top, force a redraw
        for i in range(10):
            press_cancel()
            time.sleep(.1)      # required

            m = cap_menu()

            if 'CANCEL' in m:
                # special case to get out of passphrase menu
                pick_menu_item('CANCEL')
                time.sleep(.01)
                if "Are you SURE ?" in cap_screen():
                    press_select()

            chk = cap_screen()
            if m[0] not in chk:
                # menu vs. screen wrong ... happens if looking at a story, not a menu
                press_cancel()
                continue

            if m[0] in { 'New Seed Words',  'Ready To Sign'}:
                break
            if len(m) > 1 and (m[1] == "Ready To Sign") and (m[0][0] in "<["):
                # ephemeral has XFP as first menu item
                break
        else:
            raise pytest.fail("trapped in a menu")

        return m

    return doit

@pytest.fixture(scope="module")
def pick_menu_item(dev, has_qwerty):
    f = functools.partial(_pick_menu_item, dev, has_qwerty)
    return f

@pytest.fixture(scope='module')
def virtdisk_path(request, is_simulator, needs_virtdisk):
    # get a path to indicated filename on emulated/shared dir

    def doit(fn):
        # could use: ckcc.get_sim_root_dirs() here
        if is_simulator():
            get_setting = request.getfixturevalue('get_setting')
            if not get_setting('vidsk', False):
                raise pytest.xfail('virtdisk disabled')
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
def virtdisk_wipe(dev, needs_virtdisk, virtdisk_path):
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

@pytest.fixture
def microsd_wipe(microsd_path):
    def doit():
        dir = microsd_path("")
        ls = os.listdir(dir)
        for fname in ls:
            if fname in ["README.md", ".gitignore", "messages", "psbt"]:
                continue
            os.remove(dir + fname)
    return doit

@pytest.fixture(scope='module')
def open_microsd(simulator, microsd_path):
    # open a file from the simulated microsd

    def doit(fn, mode='rb'):
        return open(microsd_path(fn), mode)

    return doit

@pytest.fixture(scope='module')
def settings_path(simulator):
    # open a file from the simulated microsd

    def doit(fn):
        # could use: ckcc.get_sim_root_dirs() here
        return '../unix/work/settings/' + fn

    return doit

@pytest.fixture
def settings_slots(settings_path):
    def doit():
        return [fn
                for fn in os.listdir(settings_path(""))
                if fn.endswith(".aes")]
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
def set_xfp(sim_exec):
    # set the XFP, without really knowing the private keys
    # - won't be able to sign, but should accept PSBT for signing

    def doit(xfp):
        assert len(xfp) == 8, "expect 8 hex digits"

        import struct
        need_xfp, = struct.unpack("<I", a2b_hex(xfp))

        sim_exec('from main import settings; settings.set("xfp", 0x%x);' % need_xfp)

    yield doit

    sim_exec('from main import settings; settings.set("xfp", 0x%x);' % simulator_fixed_xfp)


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
def use_testnet(settings_set):
    def doit(do_testnet=True):
        settings_set('chain', 'XTN' if do_testnet else 'BTC')
    yield doit
    settings_set('chain', 'XTN')

@pytest.fixture(scope="function")
def use_regtest(request, settings_set):
    if request.config.getoption("--manual"):
        def xrt_warn():
            print("NOTE: Device may need to be set for XRT chain!")
        yield xrt_warn
        return

    def doit():
        settings_set('chain', 'XRT')
    yield doit
    settings_set('chain', 'XTN')


@pytest.fixture(scope="function")
def set_seed_words(sim_exec, sim_execfile, simulator, reset_seed_words):
    # load simulator w/ a specific bip32 master key

    def doit(words):
        cmd = 'import main; main.WORDS = %r;' % words.split()
        sim_exec(cmd)
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
        cmd = 'import main; main.WORDS = %r;' % words.split()
        sim_exec(cmd)
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

    def doit(key, def_val=None):
        cmd = f"RV.write(repr(settings.get('{key}', {def_val!r})))"
        resp = sim_exec(cmd)
        assert 'Traceback' not in resp, resp
        return eval(resp)

    return doit

@pytest.fixture()
def master_settings_get(sim_exec):

    def doit(key):
        cmd = f"RV.write(repr(settings.master_get('{key}')))"
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
def repl(request):
    return request.getfixturevalue('mk4_repl')
    

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
            return bitcoind.rpc.decoderawtransaction(B2A(raw_txn))

    return doit

@pytest.fixture()
def decode_psbt_with_bitcoind(bitcoind):

    def doit(raw_psbt):
        # verify our understanding of a PSBT against bitcoind
        from base64 import b64encode

        try:
            return bitcoind.rpc.decodepsbt(b64encode(raw_psbt).decode('ascii'))
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            return bitcoind.rpc.decodepsbt(b64encode(raw_psbt).decode('ascii'))

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
def try_sign_microsd(open_microsd, cap_story, pick_menu_item, goto_home,
                     need_keypress, microsd_path, cap_screen):

    # like "try_sign" but use "air gapped" file transfer via microSD

    def doit(f_or_data, accept=True, finalize=False, accept_ms_import=False,
             complete=False, encoding='binary', del_after=0, nfc_push_tx=False):
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
        title, story = cap_story()
        if not "OK TO SEND" in title:
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

        if nfc_push_tx:
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

            from ctransaction import CTransaction
            # parse it a little
            assert result[0:4] != b'psbt', 'still a PSBT, but asked for finalize'
            t = CTransaction()
            t.deserialize(io.BytesIO(result))
            assert t.nVersion in [1, 2]
            assert t.txid().hex() == txid

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
            need_keypress('y', timeout=None)
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
            from ctransaction import CTransaction
            # parse it
            res = psbt_out
            assert res[0:4] != b'psbt', 'still a PSBT, but asked for finalize'
            t = CTransaction()
            t.deserialize(io.BytesIO(res))
            assert t.nVersion in [1, 2]

            # TODO: pull out signatures from signed txn
                    
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
def dev_hw_label(dev):
    # gets a short string that labels product: mk4 / q1, etc
    return _dev_hw_label(dev)

@pytest.fixture(scope='session')
def is_mark3(dev_hw_label):
    return (dev_hw_label == 'mk3')

@pytest.fixture(scope='session')
def is_mark4(dev_hw_label):
    return (dev_hw_label == 'mk4')

@pytest.fixture(scope='session')
def is_q1(dev_hw_label):
    return (dev_hw_label == 'q1')


@pytest.fixture(scope="session")
def is_headless(request):
    return request.config.getoption('--headless')

@pytest.fixture(scope='session')
def is_mark4plus(is_mark4, is_q1):
    # mark4 PLUS ... so Q1 and Mk4
    return is_mark4 or is_q1

@pytest.fixture(scope='session')
def mk_num(dev_hw_label):
    # return 1..4 as number (mark number)
    # - give 4 here for Q1
    v = dev_hw_label
    if v[0:2] == 'mk':
        return int(v[2:])
    elif v == 'q1':
        return 4
    else:
        raise ValueError(v)

@pytest.fixture(scope='session')
def only_mk4(is_mark4):
    # NOTE: avoid this, and try to be more specific! ie. NFC vs. QR etc
    if not is_mark4:
        raise pytest.skip("Mk4 only")

@pytest.fixture(scope='session')
def only_q1(is_q1):
    if not is_q1:
        raise pytest.skip("Q only")

@pytest.fixture(scope='session')
def needs_nfc(is_mark4, is_q1):
    if is_mark4 or is_q1:
        return
    raise pytest.skip("Needs NFC support")

@pytest.fixture(scope='session')
def needs_virtdisk(is_mark4, is_q1):
    # TODO/MAYBE: test if feature enabled in settings?
    if is_mark4 or is_q1:
        return
    raise pytest.skip("Needs VirtDisk support")

@pytest.fixture(scope='session')
def only_mk4plus(mk_num):
    # Mk4 and Q1
    if mk_num < 4:
        raise pytest.skip("Mk4/Q1 only")

@pytest.fixture(scope='session')
def only_mk3(mk_num):
    if mk_num != 3:
        raise pytest.skip("Mk3 only")

@pytest.fixture(scope='session')
def has_qwerty(is_q1):
    # has a full keyboard on product?
    return is_q1

@pytest.fixture(scope='module')
def rf_interface(needs_nfc, sim_exec):
    # provide a read/write connection over NFC
    # - requires pyscard module and desktop NFC-V reader which doesn't exist
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
def nfc_read(request, needs_nfc):
    # READ data from NFC chip
    # - perfer to do over NFC reader, but can work over USB too
    def doit_usb():
        sim_exec = request.getfixturevalue('sim_exec')
        rv = sim_exec('RV.write(glob.NFC.dump_ndef() if glob.NFC else b"DISABLED")', binary=True)
        if b'Traceback' in rv: raise pytest.fail(rv.decode('utf-8'))
        if rv == b'DISABLED': raise pytest.xfail('NFC disabled')
        return rv

    try:
        raise NotImplementedError
        rf = request.getfixturevalue('rf_interface')
        return rf.read_nfc
    except:
        return doit_usb

@pytest.fixture()
def nfc_write(request, needs_nfc, is_q1):
    # WRITE data into NFC "chip"
    def doit_usb(ccfile):
        sim_exec = request.getfixturevalue('sim_exec')
        press_select = request.getfixturevalue('press_select')
        rv = sim_exec('list(glob.NFC.big_write(%r))' % ccfile)
        if 'Traceback' in rv: raise pytest.fail(rv)
        press_select()      # to end the animation and have it check value immediately

    try:
        raise NotImplementedError
        rf = request.getfixturevalue('rf_interface')
        return rf.write_nfc
    except:
        return doit_usb

@pytest.fixture()
def enable_nfc(needs_nfc, sim_exec, settings_set):
    def doit():
        settings_set('nfc', 1)
        sim_exec('import nfc; nfc.NFCHandler.startup()')
    return doit

@pytest.fixture()
def nfc_disabled(needs_nfc, settings_get):
    def doit():
        return not bool(settings_get('nfc', 0))
    return doit

@pytest.fixture()
def scan_a_qr(sim_exec, is_q1):
    # simulate a QR being scanned 
    # XXX limitation: our USB protocol can't send a v40 QR, limit is more like 30 or so

    def doit(qr):
        if not is_q1:
            raise pytest.xfail('needs scanner')
        assert isinstance(qr, str)
        qr = qr.encode('ascii')
        rv = sim_exec(f'glob.SCAN._q.put_nowait({qr!r})')
        if 'Traceback' in rv: raise pytest.fail(rv)

    return doit


def ccfile_wrap(recs):
    from struct import pack
    CC_FILE = bytes([0xE2, 0x43, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00,   0x03])

    ln = len(recs)
    rv = bytearray(CC_FILE)
    if ln <= 0xfe:
        rv.append(ln)
    else:
        rv.append(0xff)
        rv.extend(pack('>H', ln))

    rv.extend(recs)
    rv.extend(b'\xfe')

    return rv

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
            time.sleep(.25)
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
        mod.const = int         # pre-define const() to improve portability
        spec.loader.exec_module(mod)
        return mod
    return doit

@pytest.fixture
def verify_detached_signature_file(microsd_path, virtdisk_path):
    def doit(fnames, sig_fname, way, addr_fmt=None):
        fpaths = []
        for fname in fnames:
            if way == "sd":
                path = microsd_path(fname)
            else:
                path = virtdisk_path(fname)
            fpaths.append(path)

        if way == "sd":
            sig_path = microsd_path(sig_fname)
        else:
            sig_path = virtdisk_path(sig_fname)

        with open(sig_path, "r") as sf:
            sig_contents = sf.read()

        split_sig = sig_contents.split("\n")
        assert split_sig[0] == "-----BEGIN BITCOIN SIGNED MESSAGE-----"
        h1_index = split_sig.index("-----BEGIN BITCOIN SIGNATURE-----")
        assert split_sig[h1_index] == "-----BEGIN BITCOIN SIGNATURE-----"
        msg = "\n".join(split_sig[1:h1_index])
        address = split_sig[h1_index + 1]
        sig = split_sig[h1_index + 2]
        assert split_sig[h1_index + 3] == "-----END BITCOIN SIGNATURE-----"

        if addr_fmt is not None:
            if addr_fmt == AF_CLASSIC:
                assert address[0] in "1mn"
            elif addr_fmt == AF_P2WPKH:
                assert address[:3] in ["tb1", "bc1"] or address[:5] == "bcrt1"
            elif addr_fmt == AF_P2WPKH_P2SH:
                assert address[0] in "23"
            else:
                raise ValueError("Can only sign with single signature address formats")

        fcontents = []
        for fn, fpath in zip(fnames, fpaths):
            rb = fpath.endswith(".pdf")
            with open(fpath, 'rb' if rb else 'rt') as fp:
                contents = fp.read()
                fcontents.append(contents)
            if not rb:
                contents = contents.encode()
            fn_addendum = "  %s" % fn
            assert (hashlib.sha256(contents).digest().hex() + fn_addendum) in msg

        assert verify_message(address, sig, msg) is True
        try:
            os.unlink(sig_path)
        except: pass
        return fcontents[0], address

    return doit

@pytest.fixture
def load_export_and_verify_signature(microsd_path, virtdisk_path, verify_detached_signature_file):
    def doit(export_story, way, addr_fmt=None, is_json=False, label="wallet", fpattern=None,
             tail_check=None):
        if label is not None:
            assert f'{label} file written' in export_story
            assert 'signature file written' in export_story
        if tail_check:
            header, fname, sig_header, sig_fn, tail = export_story.split("\n\n")
            assert tail_check in tail
        else:
            header, fname, sig_header, sig_fn = export_story.split("\n\n")

        if fpattern:
            assert fpattern in fname
            assert fpattern in sig_fn
        if is_json:
            assert fname.endswith(".json")

        contents, address = verify_detached_signature_file([fname], sig_fn, way, addr_fmt)

        if is_json:
            return json.loads(contents), address
        return contents, address
    return doit

@pytest.fixture
def load_export(need_keypress, cap_story, microsd_path, virtdisk_path, nfc_read_text, nfc_read_json,
                load_export_and_verify_signature, is_q1, press_cancel, press_select, readback_bbqr,
                cap_screen_qr):
    def doit(way, label, is_json, sig_check=True, addr_fmt=AF_CLASSIC, ret_sig_addr=False,
             tail_check=None, sd_key=None, vdisk_key=None, nfc_key=None, ret_fname=False,
             fpattern=None, qr_key=None):
        
        s_label = None
        if label == "Address summary":
            s_label = "address summary"

        key_map = {
            "sd": sd_key or "1",
            "vdisk": vdisk_key or "2",
            "nfc": nfc_key or (KEY_NFC if is_q1 else "3"),
            "qr": qr_key or (KEY_QR if is_q1 else "4"),
        }
        time.sleep(0.2)
        title, story = cap_story()
        if way == "sd":
            if f"({key_map['sd']}) to save {s_label if s_label else label} file to SD Card" in story:
                need_keypress(key_map['sd'])

        elif way == "nfc":
            if f"{key_map['nfc'] if is_q1 else '(3)'} to share via NFC" not in story:
                pytest.skip("NFC disabled")
            else:
                need_keypress(key_map['nfc'])
                time.sleep(0.2)
                if is_json:
                    nfc_export = nfc_read_json()
                else:
                    nfc_export = nfc_read_text()
                time.sleep(0.3)
                press_cancel()  # exit NFC animation
                return nfc_export
        elif way == "qr":
            if 'file written' in story:
                assert not is_q1
                # mk4 only does QR if fits in normal QR, becaise it can't do BBQr
                pytest.skip('no BBQr on Mk4')

            need_keypress(key_map["qr"])
            time.sleep(0.3)
            try:
                file_type, data = readback_bbqr()
                if file_type == "J":
                    return json.loads(data)
                elif file_type == "U":
                    return data.decode('utf-8') if not isinstance(data, str) else data
                else:
                    raise NotImplementedError
            except:
                raise
                res = cap_screen_qr().decode('ascii')
                try:
                    return json.loads(res)
                except:
                    return res
        else:
            # virtual disk
            if f"({key_map['vdisk']}) to save to Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress(key_map['vdisk'])

        time.sleep(0.2)
        title, story = cap_story()
        if sig_check:
            export, sig_addr = load_export_and_verify_signature(story, way, is_json=is_json,
                                                                addr_fmt=addr_fmt, label=label,
                                                                tail_check=tail_check,
                                                                fpattern=fpattern)
        else:
            assert f"{label} file written" in story
            if tail_check:
                header, fname, tail = story.split("\n\n")
                assert tail_check in tail
            else:
                header, fname = story.split("\n\n")
            if fpattern:
                assert fpattern in fname
            if is_json:
                assert fname.endswith(".json")
            if way == "sd":
                path = microsd_path(fname)
            else:
                path = virtdisk_path(fname)
            with open(path, "r") as f:
                export = f.read()
                if is_json:
                    export = json.loads(export)

            press_select()

        if ret_sig_addr and sig_addr:
            return export, sig_addr
        if ret_fname:
            # ret_fname now only works if sig is not checked
            return export, fname
        return export
    return doit


@pytest.fixture
def tapsigner_encrypted_backup(microsd_path, virtdisk_path):
    def doit(way, testnet=True):
        # create backup
        node = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN" if testnet else "BTC")
        plaintext = node.hwif(as_private=True) + '\n' + random.choice(["m", "m/84h/0h/0h", "m/44'/0'/0'/0'"])
        if testnet:
            assert "tprv" in plaintext
        else:
            assert "xprv" in plaintext
        from bsms.encryption import aes_256_ctr_encrypt
        from base64 import b64encode
        backup_key = os.urandom(16)  # 128 bit
        backup_key_hex = backup_key.hex()
        ciphertext_hex = aes_256_ctr_encrypt(backup_key, bytes(16), plaintext)
        ciphertext = bytes.fromhex(ciphertext_hex)
        ciphertext_b64 = b64encode(ciphertext).decode()
        fname = "backup-A4MQA-3135-02-15T0113.aes"
        if way == "sd":
            fpath = microsd_path(fname)
        elif way == "vdisk":
            fpath = virtdisk_path(fname)
        else:
            fpath = None
            fname = ciphertext_b64
        if fpath:
            with open(fpath, "wb") as f:
                f.write(ciphertext)
        # in case of NFC fname is b64 encoded backup itself
        return fname, backup_key_hex, node
    return doit

@pytest.fixture
def choose_by_word_length(need_keypress):
    # for use in seed XOR menu system
    def doit(num_words):
        if num_words == 12:
            need_keypress('1')
        elif num_words == 18:
            need_keypress("2")
        else:
            need_keypress("y")
    return doit

# workaround: need these fixtures to be global so I can call test from a test
from test_se2 import clear_all_tricks, new_trick_pin, new_pin_confirmed, goto_trick_menu, se2_gate


@pytest.fixture
def verify_backup_file(goto_home, pick_menu_item, cap_story, need_keypress):
    def doit(fn):
        # Check on-device verify UX works.
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Backup')
        pick_menu_item('Verify Backup')
        time.sleep(0.1)
        pick_menu_item(os.path.basename(fn))

        time.sleep(0.1)
        title, body = cap_story()
        assert "Backup file CRC checks out okay" in body
    return doit


@pytest.fixture
def check_and_decrypt_backup(microsd_path):
    def doit(fn, passphrase):
        # List contents using unix tools
        pn = microsd_path(fn)
        out = check_output(['7z', 'l', pn], encoding='utf8')
        xfname, = re.findall('[a-z0-9]{4,30}.txt', out)
        print(f"Filename inside 7z: {xfname}")
        assert xfname in out
        assert 'Method = 7zAES' in out

        xfn_path = microsd_path(xfname)
        if os.path.exists(xfn_path):
            os.remove(xfn_path)

        # does decryption; at least for CRC purposes
        args = ['7z', 'e', '-p' + ' '.join(passphrase), pn, xfname, '-o' + microsd_path("")]
        out = check_output(args, encoding='utf8')
        assert "Extracting archive" in out, out
        assert "Everything is Ok" in out, out

        with open(xfn_path, "r") as f:
            res = f.read()

        return res

    return doit


@pytest.fixture
def restore_backup_cs(unit_test, pick_menu_item, cap_story, cap_menu,
                      press_select, word_menu_entry, get_setting, is_q1,
                      need_keypress, scan_a_qr, cap_screen):
    # restore backup with clear seed as first step
    def doit(fn, passphrase, avail_settings=None, pass_way=None):
        unit_test('devtest/clear_seed.py')

        m = cap_menu()
        assert m[0] == 'New Seed Words'
        pick_menu_item('Import Existing')
        pick_menu_item('Restore Backup')

        time.sleep(.1)
        pick_menu_item(fn)

        time.sleep(.1)
        if is_q1 and pass_way and pass_way == "qr":
            need_keypress(KEY_QR)
            time.sleep(.1)
            qr = ' '.join(w[:4] for w in passphrase)
            scan_a_qr(qr)
            for _ in range(20):
                scr = cap_screen()
                if 'ENTER if all done' in scr:
                    break
                time.sleep(.1)
            press_select()
        else:
            word_menu_entry(passphrase, has_checksum=False)

        time.sleep(.3)
        title, body = cap_story()
        # on simulator Disable USB is always off - so FTUX all the time
        assert title == 'NO-TITLE'  # no Welcome!
        assert "best security practices" in body
        assert "USB disabled" in body
        assert "NFC disabled" in body
        assert "VirtDisk disabled" in body
        assert "You can change these under Settings > Hardware On/Off" in body
        press_select()

        time.sleep(.3)
        title, body = cap_story()
        assert title == 'Success!'
        assert 'has been successfully restored' in body

        if avail_settings:
            for key in avail_settings:
                assert get_setting(key)

        # after successful restore - user is in default mode - all OFF
        # (besides USB on simulator - that is always ON)
        assert not get_setting("nfc")
        assert not get_setting("vidsk")

        # avoid simulator reboot; restore normal state
        unit_test('devtest/abort_ux.py')

    return doit

@pytest.fixture
def seed_story_to_words():
    # Q may display words in a number of different ways to get them all onto the screen,
    # so need to be more general about searching screen for the words.

    def doit(story: str):
        # filter those that starts with space, number and colon --> actual words
        # NOTE: will show xprv/tprv in full if we are not storing
        #       words (ie. BIP-32 loaded as master secret). So just return that string.
        if story[1:4] == 'prv':
            return story.split()[0]

        words = [(int(idx), word) for idx, word in re.findall(r'(\d{1,2}):\s?(\w+)', story)]
        return [w for _,w in sorted(words)]

    return doit

@pytest.fixture
def sd_cards_eject(is_q1, sim_exec, is_simulator):
    def doit(slot_a=1, slot_b=1):
        if not is_simulator():
            return

        slot_a = slot_a if is_q1 else not slot_a
        cmd = (f'from machine import Pin;'
               f'import files;'
               f'files.CardSlot.sd_detect = Pin("SD_DETECT",value={slot_a});')
        if is_q1:
            cmd += f'files.CardSlot.sd_detect2 = Pin("SD_DETECT2",value={slot_b});'
        assert sim_exec(cmd) == ''
    return doit

@pytest.fixture
def set_addr_exp_start_idx(pick_menu_item, cap_menu, enter_number):
    def doit(start_idx):
        start_idx_mi = "Start Idx: 0"
        m = cap_menu()
        if start_idx:
            assert start_idx_mi in m
            pick_menu_item(start_idx_mi)
            enter_number(start_idx)
            time.sleep(.1)
            assert ("Start Idx: %d" % start_idx) in cap_menu() \
                            or ("Start:%d" % start_idx) in cap_menu()
        else:
            assert start_idx_mi not in m

    return doit


@pytest.fixture
def go_to_passphrase(cap_story, press_select, goto_home, pick_menu_item):
    # drill to the enter passphrase menu
    def doit():
        goto_home()
        pick_menu_item('Passphrase')

        _, story = cap_story()
        if 'add a passphrase to your BIP-39 seed words' in story:
            assert "100 characters max" in story
            assert "ASCII" in story
            press_select()  # skip warning
            time.sleep(.1)

    return doit

@pytest.fixture
def goto_address_explorer(goto_home, pick_menu_item, need_keypress,
                          cap_story):
    def doit():
        goto_home()
        pick_menu_item('Address Explorer')

        _, story = cap_story()
        # axi - below msg can be disabled
        if "menu lists the first payment address" in story:
            need_keypress('4') # click into stub menu
            time.sleep(0.01)

    return doit

@pytest.fixture
def txout_explorer(cap_story, press_cancel, need_keypress, is_q1):
    def doit(data, chain="XTN"):
        time.sleep(.1)
        title, story = cap_story()
        assert title == 'OK TO SEND?'
        assert "Press (2) to explore txn" in story
        need_keypress("2")
        time.sleep(.1)

        n = 10
        for i in range(0, len(data), n):
            d = data[i:i + n]
            time.sleep(.1)
            _, story = cap_story()
            ss = story.split("\n\n")
            assert len(ss) == (len(d) * 2) + 1
            assert "Press RIGHT to see next group" in ss[-1]
            if i:
                assert " LEFT to go back." in ss[-1]
            else:
                assert "LEFT" not in ss[-1]

            for i, (sa, sb, (af, amount, change)) in enumerate(zip(ss[:-1:2], ss[1::2], d), start=i):
                if change:
                    assert f"Output {i} (change):" == sa
                else:
                    assert f"Output {i}:" == sa

                txt_amount, _, addr = sb.split("\n")
                assert txt_amount == f'{amount / 100000000:.8f} {chain}'
                if af == "p2pkh":
                    if chain == "BTC":
                        assert addr.startswith("1")
                    else:
                        assert addr[0] in "mn"
                elif af in ("p2wpkh", "p2wsh"):
                    target = "bc1q" if chain == "BTC" else "tb1q"
                    assert addr.startswith(target)
                elif af in ("p2sh", "p2wpkh-p2sh", "p2wsh-p2sh"):
                    target = "3" if chain == "BTC" else "2"
                    assert addr.startswith(target)
                else:
                    raise ValueError(f"'{af}' not implemented")

            need_keypress(KEY_RIGHT if is_q1 else "9")

        # 10 outputs per story
        # currently sitting at the last story in explorer
        # try to go further (must not work and story is unchanged)
        for _ in range(2):
            need_keypress(KEY_RIGHT if is_q1 else "9")
            time.sleep(.1)
            _, xstory = cap_story()
            assert story == xstory

        # go back to first explorer story
        story_nums = math.ceil(len(data) / 10)
        for _ in range(story_nums):
            need_keypress(KEY_LEFT if is_q1 else "7")
            time.sleep(.1)

        _, story = cap_story()
        assert "Output 0" in story.split("\n\n")[0]

        # currently sitting at the first story in explorer
        # try to go further (must not work and story is unchanged)
        for _ in range(2):
            need_keypress(KEY_LEFT if is_q1 else "7")
            time.sleep(.1)
            _, xstory = cap_story()
            assert story == xstory

        # leave explorer - will return back to sign story
        press_cancel()
        time.sleep(.1)
        title, _ = cap_story()
        assert title == 'OK TO SEND?'
        press_cancel()

    return doit

@pytest.fixture
def validate_address():
    # Check whether an address is covered by the given subkey
    def doit(addr, sk):
        if addr[0] in '1mn':
            chain = "XTN" if addr[0] != "1" else "BTC"
            assert addr == sk.address(addr_fmt="p2pkh", chain=chain)
        elif addr[0:4] in {'bc1q', 'tb1q'}:
            chain = "XTN" if addr[0:4] != 'bc1q' else "BTC"
            assert addr == sk.address(addr_fmt="p2wpkh", chain=chain)
        elif addr[0:6] == "bcrt1q":
            assert addr == sk.address(addr_fmt="p2wpkh", chain="XRT")
        elif addr[0:4] in {'bc1p', 'tb1p'}:
            chain = "XTN" if addr[0:4] != 'bc1p' else "BTC"
            assert addr == sk.address(addr_fmt="p2tr", chain=chain)
        elif addr[0:6] == "bcrt1p":
            assert addr == sk.address(addr_fmt="p2tr", chain="XRT")
        elif addr[0] in '23':
            chain = "XTN" if addr[0] != '3' else "BTC"
            assert addr == sk.address(addr_fmt="p2sh-p2wpkh", chain=chain)
        else:
            raise ValueError(addr)
    return doit


@pytest.fixture
def skip_if_useless_way(is_q1, nfc_disabled):
    # when NFC is disabled, no point trying to do a PSBT via NFC
    # - important: run_sim_tests.py will enable NFC for complete testing
    # - similarly: the Mk4 and earlier had no QR scanner, so cannot use that as input
    def doit(way):
        if way == "qr" and not is_q1:
            raise pytest.skip("mk4 QR not supported")
        if way == 'nfc' and nfc_disabled():
            # runner will test these cases, but fail faster otherwise
            raise pytest.skip("NFC disabled")

    return doit


@pytest.fixture(scope="session")
def dev_core_import_object(dev):

    import sys
    sys.path.append("../shared")
    from descriptor import Descriptor

    ders = [
        ("m/44h/1h/0h", AF_CLASSIC),
        ("m/49h/1h/0h", AF_P2WPKH_P2SH),
        ("m/84h/1h/0h", AF_P2WPKH)
    ]
    descriptors = []
    for idx, (path, addr_format) in enumerate(ders):
        # get rid of change and address bip32 indexes
        path = "/".join(path.split("/")[:-2])
        subpath = path.format(account=0)  # e.g. "m/44h/1h/0h"
        ek = dev.send_recv(CCProtocolPacker.get_xpub(subpath), timeout=None)
        d = Descriptor([(dev.master_fingerprint, subpath, ek)], addr_format)
        for i in range(2):
            descriptors.append({
                "timestamp": "now",
                "active": True,
                "desc": d.serialize(internal=i),
                "internal": bool(i)
            })
    return descriptors


# useful fixtures
from test_backup import backup_system
from test_bbqr import readback_bbqr, render_bbqr, readback_bbqr_ll
from test_bip39pw import set_bip39_pw
from test_drv_entro import derive_bip85_secret, activate_bip85_ephemeral
from test_ephemeral import generate_ephemeral_words, import_ephemeral_xprv, goto_eph_seed_menu
from test_ephemeral import ephemeral_seed_disabled_ui, restore_main_seed, confirm_tmp_seed
from test_ephemeral import verify_ephemeral_secret_ui, get_identity_story, get_seed_value_ux, seed_vault_enable
from test_multisig import import_ms_wallet, make_multisig, offer_ms_import, fake_ms_txn
from test_multisig import make_ms_address, clear_ms, make_myself_wallet, import_multisig
from test_se2 import goto_trick_menu, clear_all_tricks, new_trick_pin, se2_gate, new_pin_confirmed
from test_seed_xor import restore_seed_xor
from test_ux import pass_word_quiz, word_menu_entry
from txn import fake_txn

# EOF
