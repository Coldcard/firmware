# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests related to CCC feature
#
#
import pytest, requests, re, time, random, json, glob, os, hashlib, struct, base64
from binascii import a2b_hex
from base64 import urlsafe_b64encode
from onetimepass import get_totp
from helpers import prandom
from pysecp256k1.ecdh import ecdh, ECDH_HASHFP_CLS
from pysecp256k1 import ec_seckey_verify, ec_pubkey_parse, ec_pubkey_serialize, ec_pubkey_create
from mnemonic import Mnemonic
from bip32 import BIP32Node
from constants import AF_P2WSH
from charcodes import KEY_QR
from bbqr import split_qrs
from psbt import BasicPSBT


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
              seed_story_to_words, cap_menu, OK, word_menu_entry, press_cancel, press_delete,
              enter_number, scan_a_qr, cap_screen, settings_get):
    def doit(c_words=None, mag=None, vel=None, whitelist=None, w2fa=None):
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

        whitelist_mi = "Whitelist Addresses" if is_q1 else "Whitelist"
        mag_mi = "Max Magnitude"
        vel_mi = "Limit Velocity"
        mi_2fa = "Web 2FA"

        time.sleep(.1)
        m = cap_menu()
        assert mag_mi in m
        assert vel_mi in m
        assert whitelist_mi in m
        assert mi_2fa in m

        # setting above values here
        if mag:
            pick_menu_item(mag_mi)
            press_delete()  # default is 1 BTC
            enter_number(mag)
            time.sleep(.1)
            title, story = cap_story()
            assert f"{mag} {'BTC' if int(mag) < 1000 else 'SATS'}" in story
            press_select()

        if vel:
            pick_menu_item(vel_mi)

        if whitelist:
            pick_menu_item(whitelist_mi)
            time.sleep(.1)
            m = cap_menu()
            assert "(none yet)" in m
            assert "Import from File" in m
            if is_q1:
                assert "Scan QR" in m
                pick_menu_item("Scan QR")
                for i, addr in enumerate(whitelist, start=1):
                    scan_a_qr(addr)
                    time.sleep(.5)
                    scr = cap_screen()
                    assert f"Got {i} so far" in scr
                    assert "ENTER to apply" in scr

                press_select()
                time.sleep(.1)
                _, story = cap_story()
                if len(whitelist) == 1:
                    assert "Added new address to whitelist" in story
                else:
                    assert f"Added {len(whitelist)} new addresses to whitelist" in story

                for addr in whitelist:
                    assert addr in story

                press_select()
                time.sleep(.1)
                m = cap_menu()
                mi_addrs = [a for a in m if '⋯' in a]
                for mia, addr in zip(mi_addrs, whitelist):
                    _start, _end = mia.split('⋯')
                    assert addr.startswith(_start)
                    assert addr.endswith(_end)

                press_cancel()
            else:
                assert "Scan QR" not in m

            assert settings_get("ccc")["pol"]["addrs"] == whitelist

        if w2fa:
            pick_menu_item(mi_2fa)



        # TODO check settings object data

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
        if is_q1:
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

        # something that we need for fake_ms_tx
        return struct.unpack('<I', a2b_hex(xfp))[0], master, derived

    return doit


@pytest.fixture
def bitcoind_create_watch_only_wallet(pick_menu_item, need_keypress, microsd_path,
                                      cap_story, bitcoind):
    def doit(ms_menu_item):
        pick_menu_item(ms_menu_item)
        pick_menu_item("Descriptors")
        pick_menu_item("Bitcoin Core")
        time.sleep(.1)
        need_keypress("1")
        time.sleep(.1)
        title, story = cap_story()
        assert "Bitcoin Core multisig setup file written" in story
        fname = story.split("\n\n")[-1]
        with open(microsd_path(fname), "r") as f:
            res = f.read()

        res = res.replace("importdescriptors ", "").strip()
        r1 = res.find("[")
        r2 = res.find("]", -1, 0)
        res = res[r1: r2]
        res = json.loads(res)

        bitcoind_wo = bitcoind.create_wallet(
            wallet_name=f"watch_only_ccc", disable_private_keys=True,
            blank=True, passphrase=None, avoid_reuse=False, descriptors=True
        )
        res = bitcoind_wo.importdescriptors(res)
        # remove junk
        for obj in res:
            assert obj["success"], obj

        return bitcoind_wo

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("mag_ok", [True, False])
@pytest.mark.parametrize("mag", [1000000, None, 2])
def test_ccc_magnitude(mag_ok, mag, setup_ccc, enter_enabled_ccc, ccc_ms_setup, start_sign,
                       cap_menu, cap_story, bitcoind, end_sign, settings_set,
                       bitcoind_create_watch_only_wallet):

    settings_set("ccc", None)

    if mag_ok:
        # always try limit/border value
        if mag is None:
            to_send = 1
        else:
            to_send = mag / 100000000 if mag > 1000 else mag
    else:
        if mag is None:
            to_send = 1.1
        else:
            to_send = ((mag / 100000000)+1) if mag > 1000 else (mag+0.001)

    words = setup_ccc(mag=mag)
    enter_enabled_ccc(words, first_time=True)
    ccc_ms_setup()

    m = cap_menu()
    for mi in m:
        if "2/3: Coldcard Cosign" in mi:
            target_mi = mi
            break
    else:
        assert False

    bitcoind_wo = bitcoind_create_watch_only_wallet(target_mi)

    multi_addr = bitcoind_wo.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=5.0)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT
    psbt_resp = bitcoind_wo.walletcreatefundedpsbt(
        [], [{bitcoind.supply_wallet.getnewaddress(): to_send}], 0, {"fee_rate": 20}
    )
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title
    if not mag_ok:
        assert "(1 warning below)" in story
        assert "CCC: Violates spending policy - magnitude. Won't sign." in story
    else:
        assert "warning" not in story

    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)

    if mag_ok:
        assert len(po.inputs[0].part_sigs) == 2  # CC key signed
        res = bitcoind_wo.finalizepsbt(base64.b64encode(signed).decode())
        assert res["complete"]
        tx_hex = res["hex"]
        res = bitcoind_wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
        res = bitcoind_wo.sendrawtransaction(tx_hex)
        assert len(res) == 64  # tx id
    else:
        assert len(po.inputs[0].part_sigs) == 1  # CC key did NOT sign


@pytest.mark.bitcoind
@pytest.mark.parametrize("whitelist_ok", [True, False])
def test_ccc_whitelist(whitelist_ok, setup_ccc, enter_enabled_ccc, ccc_ms_setup, start_sign,
                       cap_menu, cap_story, bitcoind, end_sign, settings_set,
                       bitcoind_create_watch_only_wallet):

    settings_set("ccc", None)
    settings_set("chain", "XRT")

    whitelist = [
        "bcrt1qqca9eefwz8tzn7rk6aumhwhapyf5vsrtrddxxp",
        "bcrt1q7nck280nje50gzjja3gyguhp2ds6astu5ndhkj",
        "bcrt1qhexpvdhwuerqq0h24j06g8y5eumjjdr28ng4vv",
        "bcrt1q3ylr55pk7rl0rc06d8th7h25zmcuvvg8wt0yl3",
    ]

    if whitelist_ok:
        send_to = whitelist[0]
    else:
        send_to = bitcoind.supply_wallet.getnewaddress()

    words = setup_ccc(whitelist=whitelist)
    enter_enabled_ccc(words, first_time=True)
    ccc_ms_setup()

    m = cap_menu()
    for mi in m:
        if "2/3: Coldcard Cosign" in mi:
            target_mi = mi
            break
    else:
        assert False

    bitcoind_wo = bitcoind_create_watch_only_wallet(target_mi)

    multi_addr = bitcoind_wo.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=5.0)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT
    psbt_resp = bitcoind_wo.walletcreatefundedpsbt(
        [], [{send_to: 1}], 0, {"fee_rate": 2}
    )
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title
    if not whitelist_ok:
        assert "(1 warning below)" in story
        assert "CCC: Violates spending policy - whitelist. Won't sign." in story
    else:
        assert "warning" not in story

    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)

    if whitelist_ok:
        assert len(po.inputs[0].part_sigs) == 2  # CC key signed
        res = bitcoind_wo.finalizepsbt(base64.b64encode(signed).decode())
        assert res["complete"]
        tx_hex = res["hex"]
        res = bitcoind_wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
        res = bitcoind_wo.sendrawtransaction(tx_hex)
        assert len(res) == 64  # tx id
    else:
        assert len(po.inputs[0].part_sigs) == 1  # CC key did NOT sign

# EOF
