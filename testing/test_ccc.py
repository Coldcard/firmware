# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests related to CCC feature
#
#
import pytest, requests, re, time, random, json, glob, os, hashlib
from binascii import a2b_hex, b2a_hex
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, parse_qs
from onetimepass import get_totp
from helpers import prandom
from pysecp256k1.ecdh import ecdh, ECDH_HASHFP_CLS
from pysecp256k1 import ec_seckey_verify, ec_pubkey_parse, ec_pubkey_serialize, ec_pubkey_create
from mnemonic import Mnemonic
from bip32 import BIP32Node
from constants import AF_P2WSH
from charcodes import KEY_QR
from bbqr import split_qrs


# TODO: we will rotate the server key before release.
SERVER_PUBKEY = '036d0f95c3aaf5cd3e8be561b07814fbb1c9ee2171ed301828151975411472a2fd'


def py_ckcc_hashfp(output, x, y, data=None):
    try:
        m = hashlib.sha256()
        m.update(x.contents.raw)
        m.update(y.contents.raw)
        output.contents.raw = m.digest()
        return 1
    except:
        return 0


ckcc_hashfp = ECDH_HASHFP_CLS(py_ckcc_hashfp)


def make_session_key(his_pubkey=None):
    # - second call: given the pubkey of far side, calculate the shared pt on curve
    # - creates session key based on that
    while True:
        my_seckey = prandom(32)
        try:
            ec_seckey_verify(my_seckey)
            break
        except: continue

    my_pubkey = ec_pubkey_create(my_seckey)

    his_pubkey = ec_pubkey_parse(bytes.fromhex(SERVER_PUBKEY))

    # do the D-H thing
    shared_key = ecdh(my_seckey, his_pubkey, hashfp=ckcc_hashfp)

    return shared_key, ec_pubkey_serialize(my_pubkey)


@pytest.fixture
def make_2fa_url():
    def doit(shared_secret=b'A'*16, nonce='12345678',
                wallet='Example wallet name', is_q=0, prod=True, encrypted=False):

        base = 'http://127.0.0.1:5070/2fa?' if not prod else 'https://coldcard.com/2fa?'

        assert is_q in {0, 1}
        assert len(shared_secret) == 16     # base32
        assert isinstance(nonce, str)       # hex digits or 8 dec digits in Mk4 mode

        from urllib.parse import quote

        qs = f'ss={shared_secret}&q={is_q}&g={nonce}&nm={quote(wallet)}'

        print(f'2fa URL: {qs}')

        if not encrypted:
            return base + qs

        # pick eph key
        ses_key, pubkey = make_session_key()

        import pyaes
        enc = pyaes.AESModeOfOperationCTR(ses_key, pyaes.Counter(0)).encrypt

        qs = urlsafe_b64encode(pubkey + enc(qs.encode('ascii')))

        return base + qs.decode('ascii')

    return doit

@pytest.fixture
def roundtrip_2fa():
    def doit(url, shared_secret, local=False):
        if local:
            url = url.replace('https://coldcard.com/', 'http://127.0.0.1:5070/')

        if int(time.time() % 30) > 29:
            # avoid end of time period
            time.sleep(3)

        answer = '%06d' % get_totp(shared_secret)
        assert len(answer) == 6

        resp = requests.post(url, data=dict(answer=answer))

        # server HTML will have this line in response for our use
        #   <!--TESTING CCC-AUTH:00000FFF -->

        if '<!--TESTING' not in resp.text:
            raise RuntimeError("server did not accept code")

        ans = re.search('<!--TESTING (\S*)', resp.text).group(1)

        #print(f'Got answer: {ans}')

        return ans

        
    return doit

@pytest.mark.parametrize('shared_secret', [ '6SPAJXWD3XJTUQWO', 'TU3QZ7VFMTJCPSS6' ])
@pytest.mark.parametrize('q_mode', [ True, False] )
@pytest.mark.parametrize('enc', [ True] )
def test_2fa_server(shared_secret, q_mode, make_2fa_url, enc, roundtrip_2fa):

    nonce = prandom(32).hex() if q_mode else str(random.randint(1000_0000, 9999_9999))

    # TODO command line flag to select local coldcard.com or production version

    url = make_2fa_url(shared_secret, nonce, is_q=int(q_mode), encrypted=enc, prod=True)

    #print(url)

    ans = roundtrip_2fa(url, shared_secret)

    assert ans == f'CCC-AUTH:{nonce}'.upper() if q_mode else nonce

    # NOTE: cannot re-start same test until next 30-second period because of rate limiting
    # check on server side.


@pytest.fixture
def setup_ccc(goto_home, pick_menu_item, cap_story, press_select, pass_word_quiz, is_q1,
             seed_story_to_words, cap_menu, OK, word_menu_entry, press_cancel):
    def doit(c_words=None):
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Coldcard Co-signing")
        time.sleep(.1)
        title, story = cap_story()
        assert title == "Coldcard Co-Signing"
        press_select()

        time.sleep(.1)
        title, story = cap_story()
        assert title == "CCC Key C"
        assert f"Press {OK} to generate new 12-word seed phrase"
        assert "(1)" in story
        assert "(2)" in story

        if c_words is None:
            nwords = 12  # always 12 words if generate by us
            press_select()
            time.sleep(.1)
            title, story = cap_story()
            assert f'Record these {nwords} secret words!' in story

            if is_q1:
                c_words = seed_story_to_words(story)
            else:
                c_words = [w[3:].strip() for w in story.split('\n') if w and w[2] == ':']
            assert len(c_words) == nwords

            count, _, _ = pass_word_quiz(c_words)
            assert count == nwords

        else:
            # manual import of C key
            word_menu_entry(c_words)

        seed = Mnemonic.to_seed(" ".join(c_words))
        expect = BIP32Node.from_master_secret(seed)
        xfp = expect.fingerprint().hex().upper()

        m = cap_menu()

        assert m[0] == f"CCC [{xfp}]"
        assert "Spending Policy" in m
        assert "Export CCC XPUBs" in m
        assert "Temporary Mode" in m  # TODO strange name -> Activate as TMP?
        assert "Multisig Wallets" in m
        assert "Build 2-of-N" in m[-2]
        assert "Remove CCC" == m[-1]

        pick_menu_item("Spending Policy")
        time.sleep(.1)
        m = cap_menu()

        assert "Max Magnitude" in m
        assert "Limit Velocity" in m
        if is_q1:
            assert "Whitelist Addresses" in m
        else:
            assert "Whitelist" in m
        assert "Web 2FA" in m
        # TODO allow setting above values here

        press_cancel()  # leave Spending Policy

        return c_words

    return doit

@pytest.fixture
def enter_enabled_ccc(goto_home, pick_menu_item, cap_story, press_select, is_q1,
                      word_menu_entry, cap_menu):
    def doit(c_words, first_time=False):
        if not first_time:
            goto_home()
            pick_menu_item("Advanced/Tools")
            pick_menu_item("Coldcard Co-signing")
            time.sleep(.1)
            title, story = cap_story()
            assert title == "CCC Enabled"
            assert "policy cannot be viewed, changed nor disabled while on the road" in story
            assert "if you have the seed words (for key C) you may proceed" in story
            press_select()
            time.sleep(.1)
            word_menu_entry(c_words)

    return doit


@pytest.fixture
def ccc_ms_setup(microsd_path, virtdisk_path, scan_a_qr, is_q1, cap_menu, pick_menu_item,
                 cap_story, press_select, need_keypress, enter_number):
    def doit(b_words=12, way="sd", addr_fmt=AF_P2WSH):
        if isinstance(b_words, int):
            assert b_words in (12,24)
            words = Mnemonic('english').generate(strength=128 if b_words == 12 else 256)
            b39_seed = Mnemonic.to_seed(words)
        else:
            assert isinstance(b_words, list)
            b39_seed = Mnemonic.to_seed(" ".join(b_words))

        master = BIP32Node.from_master_secret(b39_seed)
        xfp = master.fingerprint().hex().upper()
        label = "p2wsh" if addr_fmt == AF_P2WSH else "p2sh_p2wsh"
        derive = f"m/48h/1h/0h/{'2' if addr_fmt == AF_P2WSH else '1'}h"
        derived = master.subkey_for_path(derive)

        data = json.dumps({
            f"{label}_deriv": derive,
            f"{label}": derived.hwif(),
            "account": "0",
            "xfp": xfp
        })
        if way in ("sd", "vdisk"):
            path_f = microsd_path if way == "sd" else virtdisk_path
            for fn in glob.glob(path_f('ccxp-*.json')):
                os.remove(fn) # cleanup as we want to control N

            fname = f"ccxp-{xfp}.json"
            with open(path_f(fname), "w") as f:
                f.write(data)

        m = cap_menu()
        target_mi = None
        for mi in m:
            if "Build 2-of-N" in mi:
                target_mi = mi
                break
        else:
            assert False, "not in CCC menu"

        pick_menu_item(target_mi)
        time.sleep(.1)
        title, story = cap_story()
        assert "one other device, as key B" in story
        assert "You will need to export the XPUB from another Coldcard" in story
        press_select()

        time.sleep(.1)
        title, story = cap_story()
        assert title == "QR or SD Card?"
        if way in ("sd", "vdisk"):
            press_select()
        else:
            need_keypress(KEY_QR)
            _, parts = split_qrs(data, 'J', max_version=20)
            for p in parts:
                scan_a_qr(p)
                time.sleep(.1)

        # casual on-device multisig create
        if addr_fmt == AF_P2WSH:
            press_select()
        else:
            need_keypress("1")

        # CCC C key account number
        enter_number("0")
        time.sleep(.1)
        title, story = cap_story()
        assert "Create new multisig wallet" in story
        assert "Policy: 2 of 3" in story
        assert "Coldcard Cosign" in story
        press_select()

    return doit


def test_test_test(setup_ccc, enter_enabled_ccc, ccc_ms_setup):
    words = setup_ccc()
    enter_enabled_ccc(words, first_time=True)
    ccc_ms_setup()

# EOF
