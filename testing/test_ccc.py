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

# pubkey for production server. 
SERVER_PUBKEY = '0231301ec4acec08c1c7d0181f4ffb8be70d693acccc86cccb8f00bf2e00fcabfd'

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
def make_2fa_url(request):
    def doit(shared_secret=b'A'*16, nonce='12345678',
                wallet='Example wallet name', is_q=0, encrypted=False):

        lh = request.config.getoption("--localhost")

        base = 'http://127.0.0.1:5070/2fa?' if lh else 'https://coldcard.com/2fa?'

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

        qs = urlsafe_b64encode(pubkey + enc(qs.encode('ascii'))).rstrip(b'=')

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

        # build right TOTP answer
        answer = '%06d' % get_totp(shared_secret)
        assert len(answer) == 6

        # send both request and answer at same time (we know it works that way)
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

    # NOTE: use '--localhost' command line flag to select local coldcard.com or production

    url = make_2fa_url(shared_secret, nonce, is_q=int(q_mode), encrypted=enc)
    #print(url)

    ans = roundtrip_2fa(url, shared_secret)

    assert ans == f'CCC-AUTH:{nonce}'.upper() if q_mode else nonce

    # NOTE: cannot re-start same test until next 30-second period because of rate limiting
    # check on server side.

@pytest.mark.parametrize('shared_secret', [ '6SPAJXWD3XJTUQWO'])
@pytest.mark.parametrize('label_len', [ 10] + list(range(20,25)))
@pytest.mark.parametrize('q_mode', [ True, False] )
def test_2fa_links(shared_secret, label_len, q_mode, roundtrip_2fa, sim_exec, request):
    # Unit test for embedded encryption and padding of special links
    # NOTE: use '--localhost' command line flag to select local coldcard.com vs. production
    lh = request.config.getoption("--localhost")

    label = 'Z' * label_len
    z= sim_exec(f'from web2fa import make_web2fa_url; RV.write(repr(make_web2fa_url({label!r}, {shared_secret!r})))')
    nonce, url = eval(z)

    assert '/2fa' in url
    assert url.startswith('coldcard.com')       # protocol would be added by NDEF

    if lh:
        url = url.replace('coldcard.com', 'http://127.0.0.1:5070')
    else:
        url = 'https://' + url

    # test the server would work on this
    ans = roundtrip_2fa(url, shared_secret)

    assert ans == f'CCC-AUTH:{nonce}'.upper() if q_mode else nonce

@pytest.fixture
def get_last_violation(sim_exec):
    def doit():
        return sim_exec('from ccc import CCCFeature; RV.write(CCCFeature.last_fail_reason)')
    return doit

_skip_quiz = False

@pytest.fixture
def setup_ccc(goto_home, pick_menu_item, cap_story, press_select, pass_word_quiz, is_q1,
              seed_story_to_words, cap_menu, OK, word_menu_entry, press_cancel, press_delete,
              enter_number, scan_a_qr, cap_screen, settings_get, need_keypress):

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
            nwords = 12  # always 12 words if generated by us
            press_select()
            time.sleep(.1)
            title, story = cap_story()
            assert f'Record these {nwords} secret words!' in story

            if is_q1:
                c_words = seed_story_to_words(story)
            else:
                c_words = [w[3:].strip() for w in story.split('\n') if w and w[2] == ':']
            assert len(c_words) == nwords

            global _skip_quiz
            if not _skip_quiz:
                count, _, _ = pass_word_quiz(c_words)
                assert count == nwords
                _skip_quiz = True
            else:
                # skip the quiz, faster
                time.sleep(.1)
                need_keypress('6')      # undocumented quiz-skip
                time.sleep(.1)
                press_select()

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
        assert "Multisig Wallets" in m
        assert "↳ Build 2-of-N" in m
        assert "Load Key C" in m
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

            assert settings_get("ccc")["pol"]["mag"] == mag

        if vel:
            if not settings_get("ccc")["pol"]["mag"]:
                title, story = cap_story()
                assert 'Velocity limit requires' in story
                assert 'starting value' in story
                press_select()

            pick_menu_item(vel_mi)
            pick_menu_item(vel)  # actually a full menu item
            if vel == "Unlimited":
                target = 0
            else:
                target = int(vel.split()[0])

            time.sleep(.2)
            assert settings_get("ccc")["pol"]["vel"] == target

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
            assert "policy cannot be viewed, changed" in story
            assert "if you have the seed words" in story
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


@pytest.fixture
def policy_sign(start_sign, end_sign, cap_story, get_last_violation):
    def doit(wallet, psbt, violation=None):
        start_sign(base64.b64decode(psbt))
        time.sleep(.1)
        title, story = cap_story()
        assert 'OK TO SEND?' == title
        if violation:
            assert "(1 warning below)" in story
            assert "CCC: Violates spending policy. Won't sign." in story
            assert get_last_violation() == violation
        else:
            assert "warning" not in story

        signed = end_sign(accept=True)
        po = BasicPSBT().parse(signed)

        if violation is None:
            assert not get_last_violation()

            assert len(po.inputs[0].part_sigs) == 2  # CC key signed
            res = wallet.finalizepsbt(base64.b64encode(signed).decode())
            assert res["complete"]
            tx_hex = res["hex"]
            res = wallet.testmempoolaccept([tx_hex])
            assert res[0]["allowed"]
            res = wallet.sendrawtransaction(tx_hex)
            assert len(res) == 64  # tx id
        else:
            assert len(po.inputs[0].part_sigs) == 1  # CC key did NOT sign

    return doit

@pytest.mark.bitcoind
@pytest.mark.parametrize("mag_ok", [True, False])
@pytest.mark.parametrize("mag", [1000000, None, 2])
def test_ccc_magnitude(mag_ok, mag, setup_ccc, enter_enabled_ccc, ccc_ms_setup,
                       cap_menu, bitcoind, settings_set, policy_sign,
                       bitcoind_create_watch_only_wallet):

    settings_set("ccc", None)
    settings_set("chain", "XRT")

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

    words = setup_ccc(mag=mag, vel="Unlimited")
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

    policy_sign(bitcoind_wo, psbt, violation=None if mag_ok else "magnitude")


@pytest.mark.bitcoind
@pytest.mark.parametrize("whitelist_ok", [True, False])
def test_ccc_whitelist(whitelist_ok, setup_ccc, enter_enabled_ccc, ccc_ms_setup,
                       cap_menu, bitcoind, settings_set, policy_sign,
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

    words = setup_ccc(whitelist=whitelist, vel="Unlimited")
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
    policy_sign(bitcoind_wo, psbt, violation=None if whitelist_ok else "whitelist")


@pytest.mark.bitcoind
@pytest.mark.parametrize("velocity_mi", ['6 blocks (hour)', '48 blocks (8h)'])
def test_ccc_velocity(velocity_mi, setup_ccc, enter_enabled_ccc, ccc_ms_setup,
                       cap_menu, bitcoind, settings_set, policy_sign,
                       bitcoind_create_watch_only_wallet, settings_get):

    settings_set("ccc", None)
    settings_set("chain", "XRT")

    blocks = int(velocity_mi.split()[0])

    words = setup_ccc(vel=velocity_mi)
    enter_enabled_ccc(words, first_time=True)
    ccc_ms_setup()

    assert settings_get("ccc")["pol"]["block_h"] == 0

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
    # create funded PSBT, first tx
    init_block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]  # block height
    psbt_resp = bitcoind_wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                                   init_block_height)  # nLockTime set to current block height
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == init_block_height
    policy_sign(bitcoind_wo, psbt)  # success as this is first tx that sets block height from 0

    assert settings_get("ccc")["pol"]["block_h"] == init_block_height

    # mine some, BUT not enough to satisfy velocity policy
    bitcoind.supply_wallet.generatetoaddress(blocks - 1, bitcoind.supply_wallet.getnewaddress())
    block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]
    psbt_resp = bitcoind_wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                                   block_height)
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == block_height
    policy_sign(bitcoind_wo, psbt, violation="velocity")

    assert settings_get("ccc")["pol"]["block_h"] == init_block_height  # still initial block height as above failed

    # mine the remaining one block to satisfy velocity policy
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]
    psbt_resp = bitcoind_wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                                   block_height)
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == block_height
    policy_sign(bitcoind_wo, psbt)  # success

    assert settings_get("ccc")["pol"]["block_h"] == block_height  # updated block height

# TODO
# - policy-fail reason submenu; check display
# - weird nLockTime values: 0, time_t, backwards
# - check velocity is exactly right to block number vs. required gap
# - check txn rewind fails
# - check txn re-sign fails (if velocity in effect)
# - check any warning is blocked
#       - check too-big fee is blocked


# EOF
