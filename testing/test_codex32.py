# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.

import itertools, os, pytest, re, sys, time

from conftest import enable_nfc

sys.path.append('../shared')

from bip32 import BIP32Node, PrvKeyNode
from charcodes import KEY_NFC, KEY_QR
from ckcc.protocol import CCProtocolPacker
from codex32 import CHARSET, IDX_ORDER, SECRET, UX_CHARSET, Share, generate_share
from constants import simulator_fixed_tprv, simulator_fixed_words
from helpers import prandom
from mnemonic import Mnemonic


SHARES = [
    'ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq'
    '9dsuypw2ragmel',
    'ms10testsqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0j'
    'qgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu0ax3uvrcss9'
    'ddwnst',
    'CX100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZY'
    'GSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06GPUHWUSDF'
    '58Y65T8',
]

CW_SHARES = [Share.from_seed(bytes(range(size)), 'cw', 'test', SECRET, 2, 1).to_string()
             for size in (16, 24, 32)]
CW_SHARE_A = Share.from_seed(bytes(range(16)), 'cw', 'test', 'a', 2, 3).to_string()

IMPORT_SHARES = [
    # PR #536: generated with each supported size, HRP and padding value.
    'MS10K00LS8ZPDUP22440CHE0CMPA5YD6M5AESJRWAGPE79SR',
    'ms13k00ls8zpdup22440che0cmpa5yd6m5a6zc77kr93cj87',
    'ms10k00lswyut295tnddaz6hul8svd33v84qpue82vx0kdfgms98ngfew83amqydgzd9w6chwh',
    'MS13K00LSWYUT295TNDDAZ6HUL8SVD33V84QPUE82VX0KDFGMS98NGFEW83AMYP43NJFWJRLC4',
    'MS10K00LSJ9D5C8LA5YS3HF5RJRX7UVZTXWLRYYM02W3D2MX7NX24908PAJP5642TCPS0VTHTXK9322Y6KM7UGLH8KPNA4HT4N5MPPD0H0TK0TG63QZKZ5N2V06DSLR',
    'ms13k00lsj9d5c8la5ys3hf5rjrx7uvztxwlryym02w3d2mx7nx24908pajp5642tcps0vthtxk9322y6km7uglh8kpna4ht4n5mppd0h0tk0tg695las2njqkzxe0q',
    'cx10cashsycd6tv7snm3nm2l365apdfpec88pnetqrdueqteemch8g2gz0vqan469hfrp965g0lm8zj8w6szju9tj8ck7sdgehgtnj2y3cjcsqlt3p5k282t0hcth63',
    'CX13CASHSYCD6TV7SNM3NM2L365APDFPEC88PNETQRDUEQTEEMCH8G2GZ0VQAN469HFRP965G0LM8ZJ8W6SZJU9TJ8CK7SDGEHGTNJ2Y3CJCSQLT94FACE2NRWQQ72J',
    # PR #536: valid alternate padding encodings which previously failed round-trip.
    'MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW',
    'ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma',
    'MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK',
    'CX100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06GPUHWUSDF58Y65T8',
    # Non-secret shares: valid for interpolation, rejected as wallet secrets.
    'ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm',
    'MS13TVDWAPW7963ERA8QZ6GYG9ANN0ASGAKDXSMNGXKR7J25K6YL2ZZ6M4598LDLZWPS9HDGAP',
    'ms15khcexcmt8zmtdvty36nwuwpencndgyluve8v3c2xswvrg8wvgw2a74nags4adcpf48f3tnnct53nfaqn8l2jzakj27f5uxy97aqgnsu7qwsv6ua42x2nmvcj0ya',
    'cx13k00lcleua295dm29f332szk65mpt6vakx070smsxmzqaeez94wqrs7r4a2gwrjcnyp7wy9mx55vu2madmjmt5qzf9a4zx758kr6c287mxyreavqkkgclympu8q4',
]

INVALID_C32 = [
    ('ms10tvdwaujsp0xs8s68tlt8sl0t05qzezapfeh987l2vpl2',
     'non-secret share with threshold 0'),
    ('ms10tvdwafl9jgd4wpdvmzwrw3dd7weqwfwrjuk7w8s6068gkn30ftgcqdu65uf8feaav4n3c3',
     'non-secret share with threshold 0'),
    ('ms10tvdwardhgn06pfkvxad5v3sg0psvljjc4uwwq7np06lsydxxjul63gh783mepr4hn4pa39qlztpztydpexqjschskghk7d6es24cnnqf90p8h6d8weskgdqkrxy',
     'non-secret share with threshold 0'),
    ('ms1xcty8nyr409jwe99yxu8pw9x73ahqe2hpuqlclkk6uctt', 'invalid threshold'),
    ('ms103372s7d8uuuz5p6lczzfyh9xjrsuqdnau743ct5s7sak', 'incorrect checksum'),
    ('ms10eyfpsrkmky8ppcf2zrk90tdv5r2zfr52zddyzcd5jcs09qlhnhu2eh77m9tccdklvtz2kc',
     'incorrect checksum'),
    ('ms10qch3snfxxucuw82zn9tra2cugxkamywa647quzv2kpvz0tusqkvvcqhj8yc0lnxzfdse9gahd2mtf2vygz0z5a29k7y44wx5era6utzr0zlralh64jyl8e6zesh',
     'incorrect checksum'),
    ('cx10ccess653rz5e40h6e47h5qfwgluekkvzyemdxymm2c37k3nq5lnk662tul5sz2mjncql8ehvdthr2fzdvenpkr36ejcae2ujuzllsqursh9n07u00x8h5ywvyu6',
     'incorrect checksum'),
    ('cx11c8tesdygmp6dsr7v8kfdhg5dw7r0sk5fr9d6d9z7493eyg4m9q0jy5wz2e4remd2cs9z8kgvnf4rlj35my8g2kelw98n65wfcpwkre9zkhde96t4f4hfnpnsvt4',
     'invalid separator'),
    ('ms11ngygs00c0k3h3v5x7h2rck49muwlxm99x3m3qmmh6u65wzyc7v4qzmfn3lmfgcesy3y57m',
     'invalid separator'),
]


def native_encoding(value):
    # Independent conversion of a secret S into ordinary 72-byte wallet storage.
    value = value.lower()
    assert value[8] == 's'
    hrp, encoded = value.split('1')
    checksum_len = 15 if len(value) == 127 else 13
    body = encoded[:-checksum_len]
    values = [CHARSET.index(ch) for ch in body]

    def convert(items, pad):
        accumulator = 0
        bits = 0
        packed = bytearray()
        for item in items:
            accumulator = (accumulator << 5) | item
            bits += 5
            while bits >= 8:
                bits -= 8
                packed.append((accumulator >> bits) & 0xff)
                accumulator &= (1 << bits) - 1
        if pad and bits:
            packed.append(accumulator << (8 - bits))
        return packed, accumulator

    seed, pad = convert(values[6:], False)
    result = bytearray(72)
    if hrp == 'cx':
        assert len(seed) == 64
        result[0] = 1
    elif hrp == 'cw':
        result[0] = 0x80 | (len(seed) // 8 - 2)
    else:
        result[0] = len(seed)
    result[1:1+len(seed)] = seed
    return bytes(result)


def parse_rendered_codex32(text):
    groups = [(int(idx), value) for idx, value in
              re.findall(r'(\d+):\s?([0-9A-Za-z]+)', text)]
    return ''.join(value for _, value in sorted(groups))


def test_q1_codex32_four_column_spacing(sim_exec, only_q1):
    rendered = sim_exec(
        'from seed import render_codex32; RV.write(render_codex32(%r))' % SHARES[3])
    lines = rendered.splitlines()

    assert len(lines) == 8
    assert [len(line) for line in lines] == ([33] * 7) + [32]
    for row, line in enumerate(lines):
        assert line.startswith('%d:' % (row + 1))
        assert line[8:11] == '%2d:' % (row + 9)
        assert line[17:20] == '%2d:' % (row + 17)
        assert line[26:29] == '%2d:' % (row + 25)


def bip32_node_from_codex32_share(share, testnet=True):
    seed = share.to_seed_and_pad()[0]
    netcode = 'XTN' if testnet else 'BTC'
    if share.hrp == 'cx':
        node = PrvKeyNode(key=seed[32:64], chain_code=seed[:32], testnet=testnet)
        return BIP32Node(netcode=netcode, node=node)
    if share.hrp == 'cw':
        seed = Mnemonic.to_seed(Mnemonic('english').to_mnemonic(seed))
    return BIP32Node.from_master_secret(seed, netcode=netcode)

@pytest.fixture
def active_secret(sim_exec):
    def doit():
        return sim_exec(
            'from utils import B2A; '
            'raw = pa.tmp_value if pa.tmp_value else pa.fetch(); '
            'RV.write(B2A(raw))')
    return doit

@pytest.fixture
def enter_bech32(is_q1, need_keypress, press_select):
    # Preserved from both PRs: drive the actual Mk character picker and Q keyboard.
    def doit(target, charset=UX_CHARSET.upper(), submit=True):
        if is_q1:
            for ch in target:
                need_keypress(ch)
                time.sleep(.01)
        else:
            target = target.upper()
            half = len(charset) // 2
            for pos, ch in enumerate(target):
                if pos:
                    time.sleep(.1)
                    need_keypress('9')

                idx = charset.index(ch)
                if idx > half:
                    for _ in range(len(charset) - idx):
                        need_keypress('8')
                        time.sleep(.01)
                else:
                    for _ in range(idx):
                        need_keypress('5')
                        time.sleep(.01)

        if submit:
            press_select()

    return doit


@pytest.fixture
def goto_codex32_menu(goto_home, pick_menu_item, need_keypress):
    def doit(tmp=False, seed_vault=False, tmp_active=False):
        goto_home()
        if tmp:
            pick_menu_item('Advanced/Tools')
            pick_menu_item('Temporary Seed')
            if not seed_vault and not tmp_active:
                need_keypress('4')
        pick_menu_item('Codex32')

    return doit


@pytest.fixture
def goto_shamir_split(goto_home, pick_menu_item, cap_story, cap_screen, press_select, settings_get):
    def doit(active=None, words=None):
        if words is None:
            words = bool(settings_get('words', True))
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Danger Zone')
        pick_menu_item('Seed Functions')
        pick_menu_item('Shamir Split')
        time.sleep(.1)
        if words or not settings_get('c32', False):
            title, story = cap_story()
            assert title == 'WARNING'
            hrp = 'CW1' if words else 'CX1'
            assert story.startswith("This split will use %s, COLDCARD's extension to Codex32.\n\n"
                                    "To recover, you'll need COLDCARD or software that explicitly"
                                    " supports %s.\n\n" % (hrp, hrp))
            if words:
                assert ("Recovery restores your original English BIP-39 seed words. Any"
                        " BIP-39 passphrase must be backed up separately and entered"
                        " after recovery.") in story
            elif active == 'BIP-39 passphrase':
                assert ("Recovery restores your current passphrase wallet's keys, not your"
                        " seed words or passphrase. The passphrase is not needed for"
                        " recovery and cannot be changed on the recovered wallet.") in story
            else:
                assert ("Recovery restores an extended-key wallet, not seed words. You"
                        " cannot apply a BIP-39 passphrase to the recovered wallet.") in story
                assert 'current passphrase wallet' not in story
            press_select()
            time.sleep(.1)
        title, story = cap_story()
        assert title == 'Shamir Split'
        assert 'CX1' not in story
        assert 'Split the current wallet using Codex32 Shamir sharing.' in story
        assert 'Each split uses fresh randomness and a new ID.' in story
        if active:
            warning = 'WARNING: The split will use the wallet derived from the active %s.' % active
            assert story.index(warning) < story.index('Split the current wallet')
            assert 'WARNING' in cap_screen()
        else:
            assert 'wallet derived from the active' not in story
        press_select()
        time.sleep(.1)

    return doit


@pytest.mark.parametrize('text', [SHARES[0], CW_SHARE_A, SHARES[3]])
def test_calculate_checksum_manual(text, goto_codex32_menu, pick_menu_item, cap_story,
                                   cap_screen, press_select, enter_bech32, press_cancel,
                                   cap_menu, sim_exec, is_q1, enable_nfc, enable_hw_ux,
                                   load_export, need_keypress, microsd_path, virtdisk_path,
                                   garbage_collector, is_headless, cap_screen_qr, goto_home):
    goto_home()
    enable_nfc()
    enable_hw_ux('vdisk')
    goto_codex32_menu(tmp=True)
    snapshot = ('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value, '
                'settings.nvram_key, settings.current)))')
    before = sim_exec(snapshot)
    pick_menu_item('Calculate Checksum' if is_q1 else 'Calc Checksum')
    assert 'cannot detect existing transcription mistakes' in cap_story()[1]
    press_select()
    time.sleep(.2)
    assert 'Header + payload' in cap_screen()
    checksum_len = 15 if len(text) == 127 else 13
    body = text[:-checksum_len]
    if is_q1:
        # Exercise lowercase and uppercase keystrokes in the same entry.
        body = ''.join(c.lower() if pos % 2 else c.upper() for pos, c in enumerate(body))
    # Grouping spaces are allowed, but the payload (including padding) is unchanged.
    body = ' '.join(body[i:i+4] for i in range(0, len(body), 4))
    enter_bech32(body, submit=False)
    if is_q1:
        time.sleep(.2)
        screen = ''.join(c for c in cap_screen() if c.isalnum())
        assert body.upper().replace(' ', '') in screen
    press_select()
    time.sleep(.2)
    title, story = cap_story()
    assert title == "Share '%s'" % text[8].upper()
    assert 'Checksum:\n\n' + text[-checksum_len:].upper() in story
    assert parse_rendered_codex32(story.split('Codex32:', 1)[1]) == text.upper()
    assert 'to show QR code' in story
    assert 'to share via NFC' in story
    for way, path_f in [('sd', microsd_path), ('vdisk', virtdisk_path)]:
        if way == 'sd':
            need_keypress('1')
        exported, fname = load_export(way, label=None, is_json=False, ret_fname=True)
        garbage_collector.append(path_f(fname))
        garbage_collector.append(path_f(fname.rsplit('.', 1)[0] + '.sig'))
        assert exported == text.upper()
        press_cancel()
        time.sleep(.2)
    assert load_export('nfc', label=None, is_json=False) == text.upper()
    time.sleep(.2)
    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '4')
        time.sleep(.3)
        assert cap_screen_qr().decode('ascii') == text.upper()
        press_cancel()
        time.sleep(.2)
    assert sim_exec(snapshot) == before
    press_cancel()
    time.sleep(.2)
    assert ('Calculate Checksum' if is_q1 else 'Calc Checksum') in cap_menu()


@pytest.mark.parametrize('case', ['lower', 'upper', 'mixed'])
def test_calculate_checksum_scan_case(case, is_q1, goto_codex32_menu, pick_menu_item,
                                      press_select, need_keypress, scan_a_qr, cap_screen,
                                      cap_story, press_cancel, cap_menu, active_secret):
    if not is_q1:
        pytest.skip('requires Q scanner')
    before = active_secret()
    body = 'ms10tests' + 'q' * 26
    if case == 'upper':
        body = body.upper()
    elif case == 'mixed':
        body = body[:-1] + 'Q'
    goto_codex32_menu(tmp=True)
    pick_menu_item('Calculate Checksum')
    press_select()
    time.sleep(.2)
    need_keypress(KEY_QR)
    time.sleep(.2)
    scan_a_qr(body)
    time.sleep(1)
    # Short scans stay in the editor and must retain their original case.
    assert body in ''.join(c for c in cap_screen() if c.isalnum())
    press_select()
    time.sleep(.2)
    title, story = cap_story()
    if case == 'mixed':
        assert title == 'FAILED'
        assert 'mixed case' in story
        press_select()
        press_cancel()
        press_cancel()
    else:
        assert title == "Share 'S'"
        assert parse_rendered_codex32(story.split('Codex32:', 1)[1]) == \
            Share.from_body(body).to_string()
        press_cancel()
    assert 'Calculate Checksum' in cap_menu()
    assert active_secret() == before


@pytest.mark.parametrize('at_entry', [False, True])
def test_calculate_checksum_cancel(at_entry, goto_codex32_menu, pick_menu_item,
                                   press_select, press_cancel, cap_menu, is_q1,
                                   active_secret):
    before = active_secret()
    goto_codex32_menu(tmp=True)
    pick_menu_item('Calculate Checksum' if is_q1 else 'Calc Checksum')
    if at_entry:
        press_select()
        time.sleep(.2)
        press_cancel()
        time.sleep(.2)
        if is_q1:
            press_cancel()
        else:
            press_select()
    else:
        press_cancel()
    time.sleep(.2)
    assert ('Calculate Checksum' if is_q1 else 'Calc Checksum') in cap_menu()
    assert active_secret() == before


def test_calculate_checksum_retry(goto_codex32_menu, pick_menu_item, cap_story,
                                  press_select, enter_bech32, press_delete,
                                  press_cancel, active_secret, is_q1):
    before = active_secret()
    goto_codex32_menu(tmp=True)
    pick_menu_item('Calculate Checksum' if is_q1 else 'Calc Checksum')
    press_select()
    time.sleep(.2)
    body = 'ms10tests' + 'q' * 27
    enter_bech32(body)
    time.sleep(.2)
    title, story = cap_story()
    assert title == 'FAILED'
    assert 'ms codex32 length' in story
    press_select()
    time.sleep(.2)
    # The rejected input is retained. Remove the extra payload symbol.
    press_delete()
    press_select()
    time.sleep(.2)
    title, story = cap_story()
    assert title == "Share 'S'"
    assert parse_rendered_codex32(story.split('Codex32:', 1)[1]) == \
        Share.from_seed(bytes(16), 'ms', 'test', 's', 0).to_string()
    assert active_secret() == before
    press_cancel()


@pytest.fixture
def shamir_split_settings(enter_number, cap_screen, cap_story, press_select):
    def doit(num_shares, threshold):
        time.sleep(.1)
        assert 'Number of shares (2-9):' in cap_screen()
        enter_number(num_shares)
        time.sleep(.1)
        assert 'Threshold (2-%d):' % num_shares in cap_screen()
        enter_number(threshold)
        time.sleep(.1)
        if threshold == num_shares:
            title, story = cap_story()
            assert title == 'WARNING'
            assert 'N-of-N has no redundancy. Consider a lower threshold.' in story
            press_select()
            time.sleep(.1)

    return doit


@pytest.fixture
def export_shares(cap_story, press_select, cap_menu, pick_menu_item, need_keypress,
                  load_export, press_cancel, microsd_path, virtdisk_path, garbage_collector):
    def doit(way, num_shares, threshold, hrp=None, sec_length=None):
        title, story = cap_story()
        assert title == 'WARNING'
        assert 'Keep threshold-or-more shares on separate devices.' in story
        assert 'equivalent to storing your seed there in plaintext.' in story
        press_select()
        time.sleep(.2)

        menu = cap_menu()
        header = re.fullmatch(r'%d of %d \[([0-9A-Z]{4})\]' %
                              (threshold, num_shares), menu[0])
        assert header
        uid = header.group(1).lower()
        assert len(menu) == num_shares + 1
        shares = []
        fnames = []
        for pos, label in enumerate(menu[1:], 1):
            assert label == "Share '%s'" % IDX_ORDER[pos].upper()
            pick_menu_item(label)
            title, story = cap_story()
            assert title == label
            value = parse_rendered_codex32(story)
            share = Share.parse(value)
            assert share.threshold == threshold
            assert share.uid == uid
            if hrp:
                assert share.hrp == hrp
            if sec_length:
                assert len(share.to_seed_and_pad()[0]) == sec_length

            if way == 'sd':
                need_keypress('1')
            value = load_export(way, label=None, is_json=False, ret_fname=True)
            if isinstance(value, tuple):
                value, fname = value
                path_f = microsd_path if way == 'sd' else virtdisk_path
                garbage_collector.append(path_f(fname))
                garbage_collector.append(path_f(fname.rsplit('.', 1)[0] + '.sig'))
                fnames.append(fname)
            assert value == share.to_string()
            shares.append(share)
            if way != 'nfc':
                press_cancel()
            press_cancel()

        assert len(shares) == num_shares
        return uid, shares, fnames

    return doit


@pytest.fixture
def generate_shares_from_secret():
    def doit(num_shares, threshold, mnemonic=None, xprv=None, slen=None, uid='cash'):
        if mnemonic or xprv:
            if mnemonic:
                node = BIP32Node.from_master_secret(Mnemonic.to_seed(mnemonic), netcode='XTN')
            else:
                node = BIP32Node.from_wallet_key(xprv)
            seed = node.node.chain_code + bytes(node.node.private_key)
            hrp = 'cx'
        else:
            seed = os.urandom(slen or 16)
            node = BIP32Node.from_master_secret(seed, netcode='XTN')
            hrp = 'ms'

        secret = Share.from_seed(seed, hrp, uid, SECRET, threshold)
        basis = [secret]
        shares = []
        for pos in range(1, threshold):
            payload = ''.join(CHARSET[b & 31] for b in os.urandom(len(secret.payload)))
            share = Share(hrp, uid, payload, IDX_ORDER[pos], threshold)
            basis.append(share)
            shares.append(share.to_string())

        for pos in range(threshold, num_shares + 1):
            shares.append(generate_share(basis, IDX_ORDER[pos]).to_string())

        return secret, shares, node

    return doit


@pytest.fixture
def shamir_verify_recover(dev):
    def doit(shares, threshold):
        expected = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
        for combo in itertools.combinations(shares, threshold):
            recovered = generate_share(combo, SECRET)
            node = bip32_node_from_codex32_share(
                recovered, testnet=expected.startswith('tpub'))
            assert node.hwif() == expected

    return doit


@pytest.fixture
def goto_shamir_recover(goto_codex32_menu, pick_menu_item, cap_story, cap_screen,
                        press_select, need_keypress):
    def doit(tmp=False, seed_vault=False, tmp_active=False):
        goto_codex32_menu(tmp=tmp, seed_vault=seed_vault, tmp_active=tmp_active)
        pick_menu_item('Shamir Recover')
        time.sleep(.1)
        if tmp:
            title, warning = cap_story()
            assert title == 'WARNING'
            expected = ('The recovered Codex32 seed will be temporary and will not be saved to '
                        'the Secure Element.')
            assert warning == expected
            assert 'recovered Codex32 seed' in cap_screen().replace('\n', ' ')
            press_select()
            time.sleep(.1)
        _, story = cap_story()
        assert 'Import shares from one Codex32 set.' in story
        assert 'Their HRP, ID, threshold and length must match.' in story
        assert 'Order does not matter.' in story
        assert "include this Coldcard's" not in story
        press_select()

    return doit


def check_recover_story(story, threshold=None, uid=None, num_collected=0, hrp=None):
    assert 'Collected: %d' % num_collected in story
    assert 'Threshold: %s' % ('?' if threshold is None else threshold) in story
    assert 'ID: %s' % ('?' if uid is None else uid.upper()) in story
    assert 'HRP: %s' % ('?' if hrp is None else hrp.upper()) in story


@pytest.fixture
def import_codex32_ui(microsd_path, virtdisk_path, pick_menu_item, cap_story,
                      need_keypress, is_q1, press_nfc, nfc_write_text,
                      scan_a_qr, goto_codex32_menu, garbage_collector,
                      enter_bech32):
    def doit(way, value, tmp=False, seed_vault=False, tmp_active=False):
        fname = 'test-c32-import.txt'
        if way in ('sd', 'vdisk'):
            path_f = microsd_path if way == 'sd' else virtdisk_path
            fpath = path_f(fname)
            garbage_collector.append(fpath)
            with open(fpath, 'w') as fd:
                fd.write(value)

        goto_codex32_menu(tmp=tmp, seed_vault=seed_vault, tmp_active=tmp_active)
        pick_menu_item('Import Codex32')
        time.sleep(.1)
        _, story = cap_story()
        if way == 'sd':
            need_keypress('1')
        elif way == 'vdisk':
            need_keypress('2')
        elif way == 'nfc':
            assert ('press %s to import via NFC' %
                    (KEY_NFC if is_q1 else '(3)')) in story
            press_nfc()
            time.sleep(.2)
            nfc_write_text(value)
            time.sleep(.3)
        elif way == 'qr':
            need_keypress(KEY_QR)
            scan_a_qr(value)
            time.sleep(1)
        else:
            assert '(0) to enter manually' in story
            need_keypress('0')
            enter_bech32(value.lower())
            time.sleep(.5)

        if way in ('sd', 'vdisk'):
            time.sleep(.1)
            pick_menu_item(fname)

    return doit


@pytest.fixture
def pass_codex32_quiz(cap_story, need_keypress):
    def doit(value):
        parts = [value[i:i+4] for i in range(0, len(value), 4)]
        for _ in parts:
            time.sleep(.05)
            title, story = cap_story()
            pos = int(re.search(r'Group (\d+) is\?', title).group(1)) - 1
            choices = dict(re.findall(r' ([123]): ([0-9A-Z]+)', story))
            need_keypress(next(key for key, part in choices.items() if part == parts[pos]))

    return doit


@pytest.mark.parametrize('share', SHARES + CW_SHARES)
def test_native_secret_survives_backup(share, set_encoded_secret, sim_exec, get_secrets):
    encoded = native_encoding(share)
    expected = encoded
    set_encoded_secret(encoded)

    assert sim_exec('from utils import B2A; RV.write(B2A(pa.fetch()))') == encoded.hex()
    assert encoded[65:] == bytes(7)
    backup = get_secrets()
    assert 'codex32' not in backup
    parsed = Share.parse(share)
    if parsed.hrp == 'ms':
        assert backup['bip32_master_key'] == parsed.to_seed_and_pad()[0].hex()
    else:
        assert 'bip32_master_key' not in backup
    assert ('mnemonic' in backup) == share.lower().startswith('cw1')

    backup_hex = backup['raw_secret']
    if len(backup_hex) % 2:
        backup_hex += '0'
    assert bytes.fromhex(backup_hex).ljust(72, b'\0') == expected


@pytest.mark.parametrize('share,display', [
    *[(share, 'master') for share in SHARES[:3]],
    (SHARES[3], 'xprv'),
    *[(share, 'words') for share in CW_SHARES],
])
def test_view_seed_words_codex32(share, display, set_encoded_secret, goto_home,
                                            pick_menu_item, cap_menu, cap_story, press_select,
                                            press_cancel, is_q1, need_keypress, cap_screen_qr,
                                            is_headless, seed_story_to_words, settings_set):
    encoded = native_encoding(share)
    set_encoded_secret(encoded)
    settings_set('chain', 'XTN')

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    assert 'View Codex32' not in cap_menu()

    pick_menu_item('View Secret')
    time.sleep(.01)
    press_select()
    time.sleep(.01)

    title, body = cap_story()
    parsed = Share.parse(share)
    if display == 'master':
        raw = parsed.to_seed_and_pad()[0]
        assert raw.hex() in body
        expected_qr = Share.from_seed(raw, 'ms', 'seed', SECRET, 0).to_string()
        assert parse_rendered_codex32(body.split('Codex32:', 1)[1]) == expected_qr
        assert title == ('Master Secret' if is_q1 else 'NO-TITLE')
        assert share.upper() not in body
    elif display == 'xprv':
        expected_qr = bip32_node_from_codex32_share(parsed).hwif(as_private=True)
        assert body.startswith(expected_qr)
        assert title == ('Extended Private Key' if is_q1 else 'NO-TITLE')
        assert share.upper() not in body
    else:
        words = Mnemonic('english').to_mnemonic(parsed.to_seed_and_pad()[0]).split()
        assert seed_story_to_words(body) == words
        assert title == ('Seed words (%d):' % len(words) if is_q1 else 'NO-TITLE')
        expected_qr = ' '.join(word[:4] for word in words).upper()
        assert share.upper() not in body

    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '1')
        assert cap_screen_qr().decode('ascii') == expected_qr
        press_cancel()
        time.sleep(.1)
        assert cap_story() == [title, body]
    press_cancel()


def test_c32_flag_lifecycle(set_encoded_secret, reset_seed_words, settings_get,
                                  set_master_key):
    reset_seed_words()
    assert not settings_get('c32')
    set_encoded_secret(native_encoding(SHARES[0]))
    assert settings_get('c32')
    set_master_key(simulator_fixed_tprv)
    assert not settings_get('c32')
    reset_seed_words()
    assert not settings_get('c32')


@pytest.mark.parametrize('seed_type', ['words', 'xprv', 'ms', 'cx'])
def test_integration(seed_type, unit_test, set_seed_words,
                     import_codex32_ui, expect_ftux, goto_shamir_split,
                     shamir_split_settings, export_shares,
                     press_cancel, press_select, dev, settings_set, active_secret,
                     recover_codex32_shares, sim_exec, reset_seed_words,
                     microsd_path, garbage_collector, pick_menu_item, need_keypress,
                     fake_txn, try_sign):
    unit_test('devtest/clear_seed.py')
    native = seed_type in ('ms', 'cx')
    if seed_type == 'words':
        set_seed_words(simulator_fixed_words)
    elif seed_type == 'xprv':
        fname = 'integration-xprv.txt'
        path = microsd_path(fname)
        garbage_collector.append(path)
        with open(path, 'w') as fd:
            fd.write(simulator_fixed_tprv)
        pick_menu_item('Import Existing')
        pick_menu_item('Import XPRV')
        need_keypress('1')
        pick_menu_item(fname)
        expect_ftux()
    else:
        original = Share.from_seed(bytes(range(64)), seed_type, 'test', SECRET, 0, 1)
        import_codex32_ui('sd', original.to_string())
        expect_ftux()
    settings_set('chain', 'XTN')
    expected = dev.send_recv(CCProtocolPacker.get_xpub())
    psbt = fake_txn(2, 2, master_xpub=expected, segwit_in=True)
    _, signed_before = try_sign(psbt, finalize=True)

    goto_shamir_split()
    shamir_split_settings(3, 2)
    hrp = 'cw' if seed_type == 'words' else seed_type if native else 'cx'
    uid, shares, fnames = export_shares('sd', 3, 2, hrp=hrp,
                                       sec_length=32 if seed_type == 'words' else 64)
    press_cancel()
    press_select()

    unit_test('devtest/clear_seed.py')
    # Recover the master seed directly from the device's exported files.
    recover_codex32_shares([shares[2].to_string(), shares[0].to_string()], 'sd',
                           fnames=[fnames[2], fnames[0]])
    expect_ftux()
    settings_set('chain', 'XTN')
    assert sim_exec('RV.write(repr(pa.tmp_value))') == 'None'
    assert dev.send_recv(CCProtocolPacker.get_xpub()) == expected
    if native:
        assert active_secret() == native_encoding(original.to_string()).hex()
    _, signed_after = try_sign(psbt, finalize=True)
    assert signed_after == signed_before
    reset_seed_words()


@pytest.mark.parametrize('hrp,size', [('ms', 32), ('cx', 64), ('cw', 24)])
def test_recover_then_resplit(hrp, size, unit_test, recover_codex32_shares, expect_ftux,
                              settings_set, dev, active_secret, sim_exec, goto_shamir_split,
                              shamir_split_settings, export_shares, press_cancel, press_select,
                              reset_seed_words):
    original = Share.from_seed(bytes(range(size)), hrp, 'cash', SECRET, 2, pad_val=1)
    first = Share.from_seed(bytes(reversed(range(size))), hrp, 'cash', 'a', 2, pad_val=0)
    old_shares = [first] + [generate_share([original, first], index) for index in ('c', 'd')]

    unit_test('devtest/clear_seed.py')
    recover_codex32_shares([s.to_string() for s in old_shares[:2]], 'sd')
    expect_ftux()
    settings_set('chain', 'XTN')
    assert active_secret() == native_encoding(original.to_string()).hex()
    xpub = dev.send_recv(CCProtocolPacker.get_xpub())
    snapshot = 'RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))'
    before = sim_exec(snapshot)

    goto_shamir_split()
    shamir_split_settings(5, 3)
    _, shares, fnames = export_shares('sd', 5, 3, hrp=hrp, sec_length=size)
    uid = shares[0].uid

    assert uid != original.uid
    assert sim_exec(snapshot) == before
    assert active_secret() == native_encoding(original.to_string()).hex()
    assert dev.send_recv(CCProtocolPacker.get_xpub()) == xpub
    expected = Share.from_seed(original.to_seed_and_pad()[0], hrp, uid, SECRET, 3)
    for subset in itertools.combinations(shares, 3):
        recovered = generate_share(subset, SECRET)
        assert recovered.to_string() == expected.to_string()
        assert recovered.to_seed_and_pad() == (original.to_seed_and_pad()[0], 0)
        assert bip32_node_from_codex32_share(recovered).hwif() == xpub
    for subset in itertools.combinations(old_shares, 2):
        assert generate_share(subset, SECRET).to_string() == original.to_string()
    press_cancel()
    press_select()

    unit_test('devtest/clear_seed.py')
    selected = (4, 0, 2)
    recover_codex32_shares([shares[i].to_string() for i in selected], 'sd',
                           fnames=[fnames[i] for i in selected])
    expect_ftux()
    settings_set('chain', 'XTN')
    assert active_secret() == native_encoding(expected.to_string()).hex()
    assert dev.send_recv(CCProtocolPacker.get_xpub()) == xpub
    reset_seed_words()


@pytest.mark.parametrize('sec_type,m_n,way,passphrase', [
    ('words12', (2, 3), 'sd', ''),
    ('cw12', (2, 3), 'sd', ''),
    ('words12', (7, 9), 'nfc', ''),
    ('words24', (2, 3), 'qr', ''),
    ('words24', (7, 9), 'sd', ''),
    ('xprv', (2, 3), 'nfc', ''),
    ('xprv', (7, 9), 'qr', ''),
    ('xprv', (2, 3), 'sd', ''),
    ('words12', (2, 3), 'sd', 'test'),
    ('words24', (2, 3), 'sd', 'test'),
])
def test_bip32_compat_shamir_split(sec_type, m_n, way, passphrase, set_seed_words, set_master_key,
                                   set_encoded_secret,
                                   reset_seed_words, goto_shamir_split, shamir_split_settings,
                                   shamir_verify_recover, export_shares, skip_if_useless_way, press_cancel,
                                   press_select, cap_story, is_headless, set_bip39_pw, dev, enable_nfc):
    if way == 'qr' and is_headless:
        pytest.skip('headless mode: QR tests disabled')

    enable_nfc()
    skip_if_useless_way(way)
    if sec_type == 'cw12':
        set_encoded_secret(native_encoding(CW_SHARES[0]))
    elif sec_type == 'words12':
        set_seed_words('record castle hammer issue crumble foil clap upper wealth mutual '
                       'giraffe charge')
    elif sec_type == 'xprv':
        set_master_key(
            'tprv8ZgxMBicQKsPe2yGEX7PePdnNDMPe38D4Zm6zySg12VqFzxHjW4ZuVVYwhD65oH6eFPPozhX9YcB3Su8AScVV4584GRk1te63awwJFGS941')
    else:
        reset_seed_words()

    if passphrase:
        master_xpub = dev.send_recv(CCProtocolPacker.get_xpub())
        set_bip39_pw(passphrase, reset=False)
        assert dev.send_recv(CCProtocolPacker.get_xpub()) != master_xpub

    threshold, num_shares = m_n
    goto_shamir_split(active='BIP-39 passphrase' if passphrase else None)
    shamir_split_settings(num_shares, threshold)
    word_backup = not passphrase and sec_type != 'xprv'
    size = 16 if sec_type in ('words12', 'cw12') else 32
    _, shares, _ = export_shares(way, num_shares, threshold,
                                 hrp='cw' if word_backup else 'cx',
                                 sec_length=size if word_backup else 64)
    shamir_verify_recover(shares, threshold)

    press_cancel()
    time.sleep(.1)
    _, story = cap_story()
    assert 'This split uses fresh randomness.' in story
    assert 'Make sure you exported all shares.' in story
    press_select()
    reset_seed_words()


@pytest.mark.parametrize('size', [16, 24, 32])
@pytest.mark.parametrize('threshold,total', [(2, 3), (7, 9)])
def test_cw1_words_roundtrip(size, threshold, total, set_seed_words, goto_shamir_split,
                             shamir_split_settings, export_shares, press_cancel, press_select,
                             recover_codex32_shares, unit_test, expect_ftux, settings_set,
                             get_secrets, active_secret, set_bip39_pw, dev, reset_seed_words,
                             goto_home, pick_menu_item, cap_story):
    entropy = bytes(range(size))
    words = Mnemonic('english').to_mnemonic(entropy)
    set_seed_words(words)
    original = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
    goto_shamir_split()
    shamir_split_settings(total, threshold)
    _, shares, _ = export_shares('sd', total, threshold, hrp='cw', sec_length=size)
    for subset in itertools.combinations(shares, threshold):
        assert generate_share(subset, SECRET).to_seed_and_pad() == (entropy, 0)
    assert len(shares[0].to_string()) == {16: 48, 24: 61, 32: 74}[size]
    press_cancel()
    press_select()

    unit_test('devtest/clear_seed.py')
    recover_codex32_shares([s.to_string() for s in shares[-threshold:]], 'sd')
    expect_ftux()
    settings_set('chain', 'XTN')
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == original
    assert get_secrets()['mnemonic'] == words
    recovered = generate_share(shares[-threshold:], SECRET)
    assert active_secret() == native_encoding(recovered.to_string()).hex()
    assert recovered.to_seed_and_pad() == (entropy, 0)

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('View Secret')
    press_select()
    body = cap_story()[1]
    for word in words.split():
        assert word in body
    press_cancel()

    # Restored words still support the ordinary passphrase flow, independently
    # checked against the BIP39 implementation on the host.
    set_bip39_pw('TREZOR', reset=False)
    expected = BIP32Node.from_master_secret(Mnemonic.to_seed(words, 'TREZOR'), netcode='XTN')
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == expected.hwif()
    assert expected.hwif() != original
    reset_seed_words()


@pytest.mark.parametrize('kind,missing_words', [
    ('words', False), ('words', True), ('xprv', False),
    ('ms', False), ('cx', False), ('cw', False),
])
def test_shamir_split_warning_settings(kind, missing_words, reset_seed_words, set_master_key,
                                          set_encoded_secret, sim_exec, goto_shamir_split,
                                          shamir_split_settings, export_shares,
                                          shamir_verify_recover, press_cancel, press_select):
    reset_seed_words()
    if kind == 'xprv':
        set_master_key(simulator_fixed_tprv)
    elif kind in ('ms', 'cx', 'cw'):
        value = {'ms': SHARES[0], 'cx': SHARES[3], 'cw': CW_SHARES[0]}[kind]
        set_encoded_secret(native_encoding(value))

    words = kind in ('words', 'cw')
    if missing_words:
        # Legacy words wallets may not have this setting yet.
        sim_exec("settings.remove_key('words')")

    goto_shamir_split(words=words)
    shamir_split_settings(3, 2)
    hrp = 'cw' if words else 'cx' if kind == 'xprv' else kind
    _, shares, _ = export_shares('sd', 3, 2, hrp=hrp)
    shamir_verify_recover(shares, 2)
    press_cancel()
    press_select()
    reset_seed_words()


def test_shamir_split_storage_warning(reset_seed_words, goto_shamir_split,
                                      shamir_split_settings, cap_story, press_cancel,
                                      cap_menu, press_select):
    reset_seed_words()
    goto_shamir_split()
    shamir_split_settings(3, 2)

    title, story = cap_story()
    assert title == 'WARNING'
    assert 'Keep threshold-or-more shares on separate devices.' in story
    press_cancel()
    time.sleep(.2)

    assert re.fullmatch(r'2 of 3 \[[0-9A-Z]{4}\]', cap_menu()[0])

    press_cancel()
    time.sleep(.1)
    _, story = cap_story()
    assert 'This split uses fresh randomness.' in story
    press_select()


@pytest.mark.parametrize('threshold', [1, 9])
def test_shamir_split_rejects_threshold_outside_share_range(threshold, reset_seed_words, goto_shamir_split,
                                                            enter_number, cap_screen, cap_story, press_select):
    reset_seed_words()
    goto_shamir_split()
    assert 'Number of shares (2-9):' in cap_screen()
    enter_number(3)
    time.sleep(.1)
    assert 'Threshold (2-3):' in cap_screen()
    enter_number(threshold)
    time.sleep(.1)

    title, story = cap_story()
    assert title == 'FAILED'
    assert 'Threshold must be between 2 and 3.' in story
    press_select()


@pytest.mark.parametrize('num_shares', [0, 1])
def test_shamir_split_rejects_too_few_shares(num_shares, reset_seed_words, goto_shamir_split,
                                             enter_number, cap_screen, cap_story, press_select):
    reset_seed_words()
    goto_shamir_split()
    assert 'Number of shares (2-9):' in cap_screen()
    enter_number(num_shares)
    time.sleep(.1)

    title, story = cap_story()
    assert title == 'FAILED'
    assert 'Number of shares must be at least 2.' in story
    press_select()


def test_shamir_split_m_of_m_warning_cancel(reset_seed_words, goto_shamir_split,
                                            enter_number, cap_screen, cap_story, press_cancel):
    reset_seed_words()
    goto_shamir_split()
    assert 'Number of shares (2-9):' in cap_screen()
    enter_number(3)
    time.sleep(.1)
    assert 'Threshold (2-3):' in cap_screen()
    enter_number(3)
    time.sleep(.1)

    title, story = cap_story()
    assert title == 'WARNING'
    assert 'N-of-N has no redundancy. Consider a lower threshold.' in story
    press_cancel()


@pytest.mark.parametrize('hrp,sec_len,m_n,way,initial_threshold', [
    ('ms', 16, (3, 5), 'sd', 0),
    ('ms', 16, (9, 9), 'nfc', 0),
    ('ms', 32, (3, 5), 'qr', 0),
    ('ms', 32, (9, 9), 'sd', 0),
    ('ms', 64, (3, 5), 'nfc', 0),
    ('ms', 64, (9, 9), 'qr', 0),
    ('cx', 64, (3, 5), 'sd', 0),
    ('ms', 16, (3, 5), 'vdisk', 0),
    ('ms', 16, (3, 5), 'sd', 2),
    ('cx', 64, (9, 9), 'sd', 0),
])
def test_codex32_shamir_split(hrp, sec_len, m_n, way, initial_threshold, set_encoded_secret, goto_shamir_split,
                              shamir_split_settings, shamir_verify_recover, export_shares, skip_if_useless_way,
                              press_cancel, press_select, cap_story, is_headless, enable_nfc):

    if way == 'qr' and is_headless:
        pytest.skip('headless mode: QR tests disabled')

    enable_nfc()  # can be disabled by previous fixtures
    skip_if_useless_way(way)
    secret = Share.from_seed(prandom(sec_len), hrp, 'cash', SECRET, initial_threshold)
    set_encoded_secret(native_encoding(secret.to_string()))

    threshold, num_shares = m_n
    goto_shamir_split()
    shamir_split_settings(num_shares, threshold)
    _, shares, _ = export_shares(way, num_shares, threshold, hrp=hrp, sec_length=sec_len)
    shamir_verify_recover(shares, threshold)

    press_cancel()
    time.sleep(.1)
    _, story = cap_story()
    assert 'This split uses fresh randomness.' in story
    press_select()


@pytest.fixture
def recover_codex32_shares(goto_shamir_recover, cap_story, need_keypress, is_q1, press_nfc,
                           nfc_write_text, scan_a_qr, enter_bech32, microsd_path,
                           virtdisk_path, garbage_collector, pick_menu_item, cap_screen):

    def doit(shares, way, tmp=False, seed_vault=False, fnames=None, spaced=False):
        def format_share(value):
            return ' '.join(value[i:i+4] for i in range(0, len(value), 4)) if spaced else value

        first = Share.parse(shares[0])
        threshold = first.threshold
        uid = first.uid
        goto_shamir_recover(tmp=tmp, seed_vault=seed_vault)
        time.sleep(.1)
        _, story = cap_story()
        check_recover_story(story)

        if way in ('sd', 'vdisk') and fnames is None:
            path_f = microsd_path if way == 'sd' else virtdisk_path
            fnames = []
            for value in shares[:threshold]:
                fname = '%s_share_%s.txt' % (uid, value[8])
                fpath = path_f(fname)
                with open(fpath, 'w') as fd:
                    fd.write(format_share(value))
                garbage_collector.append(fpath)
                fnames.append(fname)

        for pos, value in enumerate(shares[:threshold], 1):
            if way == 'nfc':
                press_nfc()
                time.sleep(.1)
                nfc_write_text(format_share(value))
                time.sleep(.4)
            elif way == 'qr':
                assert is_q1
                need_keypress(KEY_QR)
                scan_a_qr(format_share(value))
                time.sleep(1)
            elif way == 'input':
                need_keypress('0')
                if pos > 1:
                    time.sleep(.1)
                    if is_q1:
                        assert value[:8].upper() in cap_screen()
                    else:
                        # Mk text capture only includes the selected picker character.
                        assert cap_screen().splitlines()[-1] == value[7].upper()
                    if not is_q1:
                        need_keypress('9')
                    value = value[8:]
                value = format_share(value)
                # Q must accept lowercase keystrokes with the uppercase prefix.
                value = value.lower() if is_q1 else value.upper()
                enter_bech32(value)
            else:
                need_keypress('1' if way == 'sd' else '2')
                time.sleep(.1)
                pick_menu_item(fnames[pos-1])

            if pos < threshold:
                time.sleep(.1)
                _, story = cap_story()
                check_recover_story(story, threshold, uid, pos, first.hrp)

    return doit


@pytest.mark.parametrize('sec_type', ['mnemonic', 'xprv', 'ms16', 'ms32', 'ms64'])
@pytest.mark.parametrize('m_n', [(2, 3), (7, 9)])
def test_shamir_recover_secret_types(sec_type, m_n, generate_shares_from_secret,
                                     recover_codex32_shares, unit_test, expect_ftux,
                                     settings_set, dev, sim_exec, reset_seed_words, active_secret):
    unit_test('devtest/clear_seed.py')
    threshold, num_shares = m_n
    if sec_type == 'mnemonic':
        secret, shares, node = generate_shares_from_secret(
            num_shares, threshold, mnemonic=simulator_fixed_words)
    elif sec_type == 'xprv':
        secret, shares, node = generate_shares_from_secret(
            num_shares, threshold, xprv=simulator_fixed_tprv)
    else:
        secret, shares, node = generate_shares_from_secret(
            num_shares, threshold, slen=int(sec_type[2:]))

    recover_codex32_shares(shares, 'sd')
    expect_ftux()
    settings_set('chain', 'XTN')
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == node.hwif()
    assert active_secret() == native_encoding(secret.to_string()).hex()
    reset_seed_words()


@pytest.mark.parametrize('hrp,size,way', [
    ('ms', 16, 'sd'),
    ('ms', 16, 'nfc'),
    ('ms', 16, 'qr'),
    ('ms', 64, 'vdisk'),
    ('ms', 16, 'input'),  # Mk character picker must retain the next share's prefix.
    ('ms', 64, 'input'),
    ('cx', 64, 'input'),
    ('cx', 64, 'vdisk'),
    ('cx', 64, 'nfc'),
    ('cx', 64, 'qr'),
])
def test_shamir_recover_import_ways(hrp, size, way, is_q1, skip_if_useless_way, set_seed_words, generate_shares_from_secret,
                                    recover_codex32_shares, confirm_tmp_seed, verify_ephemeral_secret_ui, dev, enable_nfc,
                                    sim_exec, enable_hw_ux, settings_set, reset_seed_words, active_secret):
    if way == 'input' and size == 64 and not is_q1:
        pytest.skip('long manual entry covered on Q')
    set_seed_words('extra sport youth surge capital category kid ginger extend way cause hamster')
    settings_set('seedvault', False)

    enable_nfc()
    skip_if_useless_way(way)
    if hrp == 'cx':
        secret, shares, node = generate_shares_from_secret(3, 2, mnemonic='abandon ' * 11 + 'about')
    else:
        secret, shares, node = generate_shares_from_secret(3, 2, slen=size)
    recover_codex32_shares(shares, way, tmp=True, spaced=way in ('input', 'vdisk'))
    confirm_tmp_seed(expect_xfp=node.fingerprint().hex().upper())
    verify_ephemeral_secret_ui(xpub=node.hwif(),
                               expected_xfp=node.fingerprint().hex().upper())
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == node.hwif()
    assert active_secret() == native_encoding(secret.to_string()).hex()
    reset_seed_words()


def test_shamir_recover_warning_with_only_temporary_seed(unit_test, import_codex32_ui,
                                                         confirm_tmp_seed, goto_shamir_recover,
                                                         cap_story, press_cancel, sim_exec, reset_seed_words):
    unit_test('devtest/clear_seed.py')
    try:
        import_codex32_ui('sd', IMPORT_SHARES[0], tmp=True)
        confirm_tmp_seed()
        state = sim_exec(
            'from pincodes import pa; '
            'RV.write(repr(pa.is_secret_blank() and bool(pa.tmp_value)))')
        assert state == 'True'

        goto_shamir_recover(tmp=True, tmp_active=True)
        time.sleep(.1)
        _, story = cap_story()
        check_recover_story(story)
        press_cancel()
    finally:
        reset_seed_words()


@pytest.mark.parametrize('tmp', [False, True])
def test_shamir_recover_seedless_saved_shares(tmp, unit_test, import_codex32_ui,
                                             confirm_tmp_seed, goto_shamir_recover,
                                             cap_story, press_cancel, press_select,
                                             need_keypress, microsd_path, garbage_collector,
                                             pick_menu_item, sim_exec, master_settings_get,
                                             reset_seed_words):
    unit_test('devtest/clear_seed.py')
    sim_exec('settings.load()')
    try:
        if tmp:
            import_codex32_ui('sd', IMPORT_SHARES[0], tmp=True)
            confirm_tmp_seed()

        share = Share.from_seed(os.urandom(16), 'ms', 'name', 'a', 2, 0)
        fname = 'seedless_share.txt'
        path = microsd_path(fname)
        garbage_collector.append(path)
        with open(path, 'w') as fd:
            fd.write(share.to_string())

        goto_shamir_recover(tmp=tmp, tmp_active=tmp)
        need_keypress('1')
        pick_menu_item(fname)
        press_cancel()
        story = cap_story()[1]
        assert 'Press (1) to Save & Exit.' in story
        assert ('WARNING: Without a master wallet, saved shares will not be'
                ' protected by encryption.') in story
        need_keypress('1')
        time.sleep(.1)
        assert master_settings_get('c32_shares') == [share.to_string()]

        # Reload the seedless settings from flash, including when a temporary seed is active.
        reload_saved = ('from nvstore import SettingsObject; '
                        'saved = SettingsObject(bytes(32)); saved.load(); '
                        'RV.write(repr(saved.get("c32_shares"))); ')
        if tmp:
            reload_saved += 'SettingsObject.master_sv_data["c32_shares"] = saved.get("c32_shares")'
        else:
            reload_saved += 'settings.load()'
        assert eval(sim_exec(reload_saved)) == [share.to_string()]

        goto_shamir_recover(tmp=tmp, tmp_active=tmp)
        check_recover_story(cap_story()[1], 2, 'name', 1, 'ms')
        press_cancel()
        press_cancel()  # Keep collecting.
        check_recover_story(cap_story()[1], 2, 'name', 1, 'ms')
        press_cancel()
        press_select()  # Discard the saved collection.
        time.sleep(.1)
        assert master_settings_get('c32_shares') == []
        assert sim_exec(reload_saved) == '[]'
    finally:
        reset_seed_words()


def test_shamir_recover_failures(reset_seed_words, goto_shamir_recover, generate_shares_from_secret,
                                 microsd_path, garbage_collector, need_keypress, pick_menu_item, cap_story,
                                 enable_nfc, press_nfc, nfc_write_text, press_select, press_cancel, cap_menu,
                                 import_ephemeral_xprv, confirm_tmp_seed, sim_exec, active_secret,
                                 master_settings_get):
    reset_seed_words()
    import_ephemeral_xprv('sd', from_main=True, seed_vault=False)
    snapshot = 'RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))'
    before = sim_exec(snapshot)
    enable_nfc()
    secret, shares, _ = generate_shares_from_secret(3, 2, slen=16, uid='ua7l')
    goto_shamir_recover(tmp=True, tmp_active=True)
    _, story = cap_story()
    check_recover_story(story)

    fname = 'ua7l_share_a.txt'
    fpath = microsd_path(fname)
    with open(fpath, 'w') as fd:
        fd.write(shares[0])
    garbage_collector.append(fpath)
    need_keypress('1')
    pick_menu_item(fname)
    time.sleep(.1)
    _, story = cap_story()
    check_recover_story(story, 2, 'ua7l', 1, 'ms')
    assert not master_settings_get('c32_shares')

    def send_bad(value, message):
        press_nfc()
        time.sleep(.1)
        nfc_write_text(value)
        time.sleep(.3)
        title, body = cap_story()
        assert title == 'FAILED'
        assert message in body
        assert sim_exec(snapshot) == before
        press_select()
        time.sleep(.1)
        _, body = cap_story()
        check_recover_story(body, 2, 'ua7l', 1, 'ms')

    send_bad(Share.from_seed(os.urandom(32), 'ms', 'ua7l', 'c', 2, 0).to_string(),
             'Share set does not match the first share.')
    send_bad(Share.from_seed(os.urandom(64), 'cx', 'ua7l', 'c', 2, 0).to_string(),
             'Share set does not match the first share.')
    send_bad(Share.from_seed(os.urandom(16), 'ms', 'ua7l', 'c', 3, 0).to_string(),
             'Share set does not match the first share.')
    send_bad(Share.from_seed(os.urandom(16), 'ms', 'cash', 'c', 2, 0).to_string(),
             'Share set does not match the first share.')
    send_bad(secret.to_string(), "Use 'Import Codex32' for secret share 's'.")
    send_bad(shares[0], 'That share index was already collected.')
    send_bad(Share.from_seed(os.urandom(16), 'ms', 'ua7l', 'a', 2, 0).to_string(),
             'That share index was already collected.')

    for value, error in INVALID_C32:
        send_bad(value, error)

    press_cancel()
    time.sleep(.1)
    _, story = cap_story()
    assert 'Discard collected shares?' in story
    assert 'Without a master wallet' not in story
    press_cancel()
    time.sleep(.1)
    _, story = cap_story()
    check_recover_story(story, 2, 'ua7l', 1, 'ms')
    assert sim_exec(snapshot) == before
    # Canceling discard keeps collecting; only Save & Exit writes the partial set.
    assert not master_settings_get('c32_shares')
    press_cancel()
    assert 'Press (1) to Save & Exit.' in cap_story()[1]
    need_keypress('1')
    time.sleep(.1)
    assert 'Shamir Recover' in cap_menu()
    sim_exec('from nvstore import SettingsObject; '
             'saved = SettingsObject(SettingsObject.master_nvram_key); saved.load(); '
             'SettingsObject.master_sv_data["c32_shares"] = saved.get("c32_shares", [])')
    goto_shamir_recover(tmp=True, tmp_active=True)
    check_recover_story(cap_story()[1], 2, 'ua7l', 1, 'ms')
    press_nfc()
    time.sleep(.1)
    nfc_write_text(shares[1])
    time.sleep(.3)
    confirm_tmp_seed()
    assert active_secret() == native_encoding(secret.to_string()).hex()
    assert master_settings_get('c32_shares') == []

    # Confirming discard clears the collection without replacing the active wallet.
    before = sim_exec(snapshot)
    goto_shamir_recover(tmp=True, tmp_active=True)
    need_keypress('1')
    pick_menu_item(fname)
    time.sleep(.1)
    press_cancel()
    press_select()
    time.sleep(.1)
    assert 'Shamir Recover' in cap_menu()
    assert sim_exec(snapshot) == before
    assert master_settings_get('c32_shares') == []
    reset_seed_words()


@pytest.mark.parametrize('hrp,size', [('ms', 16), ('ms', 32), ('cx', 64), ('cw', 24)])
@pytest.mark.parametrize('state', ['blank', 'current', 'temporary', 'blank_temporary'])
@pytest.mark.parametrize('threshold', [2, 7])
def test_derive_codex32_shares(hrp, size, state, threshold, reset_seed_words, unit_test, set_encoded_secret,
                              import_ephemeral_xprv, goto_codex32_menu, pick_menu_item,
                              cap_story, cap_menu, press_select, press_cancel, need_keypress,
                              microsd_path, garbage_collector, sim_exec, master_settings_get):
    reset_seed_words()
    output_indices = IDX_ORDER[threshold + 1:10].upper()
    if (hrp, size, threshold) == ('ms', 16, 2):
        # Published BIP-93 vector: A + C -> D, including nonzero padding.
        a = Share.parse('MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM')
        c = Share.parse('MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN')
        shares = [a, c]
        expected = 'MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG'
    else:
        shares = [Share.from_seed(os.urandom(size), hrp, 'name', idx, threshold, 1)
                  for idx in IDX_ORDER[1:threshold + 1]]
        expected = generate_share(shares, output_indices[0].lower()).to_string()
    if state in ('blank', 'blank_temporary'):
        unit_test('devtest/clear_seed.py')
        sim_exec('settings.load()')
        if state == 'blank_temporary':
            import_ephemeral_xprv('sd', from_main=True, seed_vault=False)
    elif state == 'current':
        set_encoded_secret(native_encoding(SHARES[0]))
    else:
        import_ephemeral_xprv('sd', from_main=True, seed_vault=False)
    snapshot = 'RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))'
    before = sim_exec(snapshot)
    goto_codex32_menu(tmp=state != 'blank', tmp_active=state in ('temporary', 'blank_temporary'))
    pick_menu_item('Derive Shares')
    title, story = cap_story()
    assert title == 'WARNING'
    assert 'Import a threshold number of shares from one Codex32 set.' in story
    assert "enough shares to reconstruct the secret share 'S' and recover the combined wallet." in story
    assert ('Your active wallet will remain unchanged.' in story) == (state != 'blank')
    press_select()
    assert "include this Coldcard's" not in cap_story()[1]
    press_select()

    for pos, share in enumerate(shares):
        if pos:
            check_recover_story(cap_story()[1], threshold, 'name', pos, hrp)
        else:
            check_recover_story(cap_story()[1])
        name = 'derive_%s.txt' % share.index
        path = microsd_path(name)
        garbage_collector.append(path)
        with open(path, 'w') as fd:
            fd.write(share.to_string())
        need_keypress('1')
        pick_menu_item(name)

        if share == shares[0]:
            press_cancel()
            assert 'Press (1) to Save & Exit.' in cap_story()[1]
            need_keypress('1')
            time.sleep(.1)
            assert master_settings_get('c32_shares') == [share.to_string()]
            pick_menu_item('Derive Shares')
            press_select()  # warning
            press_select()  # collection introduction
            check_recover_story(cap_story()[1], threshold, 'name', 1, hrp)

    assert master_settings_get('c32_shares') == []
    menu = cap_menu()
    assert menu[0] == '%d required [NAME]' % threshold
    assert menu[1:] == ["Share '%s'" % idx for idx in output_indices]
    secret = generate_share(shares, SECRET).to_string()
    for index in output_indices[:2]:
        pick_menu_item("Share '%s'" % index)
        value = parse_rendered_codex32(cap_story()[1])
        if index == output_indices[0]:
            assert value == expected
        assert value == generate_share(shares, index.lower()).to_string()
        derived = Share.parse(value)
        for omitted in range(threshold):
            combo = shares[:omitted] + shares[omitted + 1:] + [derived]
            assert generate_share(combo, SECRET).to_string() == secret
        need_keypress('1')
        story = cap_story()[1]
        assert 'written:' in story
        assert ('Signature:' in story) == (state != 'blank')
        path = microsd_path(story.split('\n\n')[1])
        garbage_collector.append(path)
        if state != 'blank':
            garbage_collector.append(microsd_path(story.split('\n\n')[-1]))
        with open(path) as fd:
            assert fd.read() == value
        press_cancel()  # export result
        press_cancel()  # share display
    press_cancel()
    title, story = cap_story()
    assert title == 'DISCARD?'
    assert 'Exit and discard collected shares?' in story
    press_cancel()  # keep the session, including its original inputs
    pick_menu_item("Share '%s'" % output_indices[0])
    assert parse_rendered_codex32(cap_story()[1]) == expected
    press_cancel()
    press_cancel()
    press_select()
    assert 'Derive Shares' in cap_menu()
    assert sim_exec(snapshot) == before
    reset_seed_words()


def test_shamir_recover_invalid_key(reset_seed_words, recover_codex32_shares,
                                     cap_story, sim_exec, settings_get):
    reset_seed_words()
    snapshot = 'RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))'
    before = sim_exec(snapshot)
    invalid = Share.from_seed(bytes(range(32)) + bytes(32), 'cx', 'zerq', SECRET, 2)
    first = Share.from_seed(bytes(range(64)), 'cx', 'zerq', 'a', 2, 0)
    second = generate_share([invalid, first], 'c')
    recover_codex32_shares([first.to_string(), second.to_string()], 'sd', tmp=True)
    title, body = cap_story()
    assert title == 'FAILED'
    assert 'bip32 lottery winner' in body
    assert sim_exec(snapshot) == before
    assert settings_get('c32_shares', []) == []
    reset_seed_words()


@pytest.mark.parametrize('size', ['128-bit', '256-bit'])
@pytest.mark.parametrize('tmp', [False, True])
@pytest.mark.parametrize('dice', [False, True])
def test_new_codex32_wallet(size, tmp, dice, unit_test, goto_codex32_menu, pick_menu_item,
                            enter_mash_entropy, cap_story, is_q1, need_keypress, cap_screen_qr, active_secret,
                            press_cancel, press_nfc, nfc_read_text, enable_nfc,
                            press_select, pass_codex32_quiz, expect_ftux, confirm_tmp_seed,
                            verify_ephemeral_secret_ui, dev, sim_exec, reset_seed_words, is_headless):
    if not tmp:
        unit_test('devtest/clear_seed.py')
    enable_nfc()
    goto_codex32_menu(tmp=tmp)
    pick_menu_item('Generate')
    if dice:
        pick_menu_item('Advanced')
        pick_menu_item(size + ' Dice Roll')
        assert 'only source of randomness' in cap_story()[1]
        press_select()
        rolls = ('123456' * 17)[:50 if size == '128-bit' else 99]
        for ch in rolls[:-1]:
            need_keypress(ch)
        press_select()
        time.sleep(.1)
        story = cap_story()[1]
        assert 'need at least %d rolls' % len(rolls) in story
        assert 'word seeds' not in story
        press_select()
        need_keypress(rolls[-1])
        press_select()
    else:
        pick_menu_item(size)
        time.sleep(3.2)
        enter_mash_entropy()
    time.sleep(1.2)

    title, story = cap_story()
    assert title == ('Record Codex32' if is_q1 else 'NO-TITLE')
    value = parse_rendered_codex32(story.split('\n\n', 1)[0])
    assert value == value.upper()
    share = Share.parse(value)
    assert len(share.to_seed_and_pad()[0]) == (16 if size == '128-bit' else 32)
    if dice:
        from hashlib import sha256
        assert share.to_seed_and_pad()[0] == sha256(rolls.encode('ascii')).digest()[:16 if size == '128-bit' else 32]
    assert (share.uid, share.index, share.threshold) == ('seed', SECRET, 0)
    assert share.to_seed_and_pad()[1] == 0
    assert 'ID:' not in story
    assert 'change ID' not in story
    if tmp:
        assert 'Press (6) to skip the verification.' in story

    need_keypress(KEY_QR if is_q1 else '1')
    if not (is_q1 and is_headless):
        assert cap_screen_qr().decode('ascii') == value
    press_cancel()
    press_nfc()
    time.sleep(.2)
    assert nfc_read_text() == value
    time.sleep(.1)
    press_cancel()

    if tmp:
        need_keypress('6')
        time.sleep(.1)
        _, story = cap_story()
        assert 'Skip verification of the recorded Codex32 share?' in story
        press_select()
        confirm_tmp_seed()
    else:
        press_select()
        pass_codex32_quiz(value)
        expect_ftux()

    actual_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
    node = bip32_node_from_codex32_share(
        share, testnet=actual_xpub.startswith('tpub'))
    assert actual_xpub == node.hwif()
    assert active_secret() == native_encoding(value).hex()
    displayed = sim_exec(
        'from stash import SensitiveValues; from actions import render_master_secrets\n'
        'with SensitiveValues() as sv:\n'
        '    RV.write(render_master_secrets(sv.mode, sv.raw, sv.node)[2])')
    assert displayed == value
    if tmp:
        verify_ephemeral_secret_ui(xpub=actual_xpub)
    reset_seed_words()


@pytest.fixture
def start_codex32_generation(reset_seed_words, unit_test, settings_set, sim_exec,
                              goto_codex32_menu, pick_menu_item, enter_mash_entropy,
                              cap_story):
    def doit(tmp):
        reset_seed_words()
        settings_set('seedvault', False)
        if not tmp:
            unit_test('devtest/clear_seed.py')
        before = sim_exec('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))')
        goto_codex32_menu(tmp=tmp)
        pick_menu_item('Generate')
        pick_menu_item('128-bit')
        time.sleep(3.2)
        enter_mash_entropy()
        time.sleep(1.2)
        value = parse_rendered_codex32(cap_story()[1].split('\n\n')[0])
        assert len(value) == 48
        return before, value
    return doit


@pytest.mark.parametrize('tmp', [False, True])
def test_codex32_quiz_wrong_answer_and_review(tmp, start_codex32_generation,
                                             press_select, cap_story, need_keypress, pass_codex32_quiz,
                                             confirm_tmp_seed, expect_ftux, sim_exec, reset_seed_words,
                                             active_secret):
    before, value = start_codex32_generation(tmp)
    press_select()
    title, story = cap_story()
    group = int(re.search(r'Group (\d+) is\?', title).group(1)) - 1
    right = value[group*4:(group+1)*4]
    choices = dict(re.findall(r' ([123]): ([0-9A-Z]+)', story))
    need_keypress(next(k for k, text in choices.items() if text != right))
    time.sleep(2.3)
    assert cap_story()[0] == title
    press_select()  # Review the recorded groups without passing this question.
    assert parse_rendered_codex32(cap_story()[1]) == value
    assert sim_exec('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))') == before
    press_select()
    assert cap_story()[0] == title
    pass_codex32_quiz(value)
    if tmp:
        confirm_tmp_seed()
    else:
        expect_ftux()
    assert active_secret() == native_encoding(value).hex()
    reset_seed_words()


@pytest.mark.parametrize('tmp', [False, True])
@pytest.mark.parametrize('stage', ['record', 'quiz'])
def test_codex32_generation_discard(tmp, stage, start_codex32_generation,
                                    press_select, press_cancel, cap_story,
                                    sim_exec, cap_menu, reset_seed_words):
    before, value = start_codex32_generation(tmp)
    if stage == 'quiz':
        press_select()
        assert cap_story()[0].startswith('Group ')
    press_cancel()
    assert 'Throw away this secret and stop?' in cap_story()[1]
    press_cancel()  # Keep the same secret and return to its recording screen.
    assert parse_rendered_codex32(cap_story()[1].split('\n\n')[0]) == value
    assert sim_exec('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))') == before
    if stage == 'quiz':
        press_select()
    press_cancel()
    assert 'Throw away this secret and stop?' in cap_story()[1]
    press_select()
    assert sim_exec('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value)))') == before
    assert '128-bit' in cap_menu()
    reset_seed_words()


@pytest.mark.parametrize('value', IMPORT_SHARES[:13] + CW_SHARES)
def test_import_codex32_vectors(value, unit_test, import_codex32_ui,
                                expect_ftux, sim_exec, dev, settings_set, reset_seed_words, active_secret):
    unit_test('devtest/clear_seed.py')
    import_codex32_ui('sd', value)
    expect_ftux()
    settings_set('chain', 'XTN')
    share = Share.parse(value)
    assert active_secret() == native_encoding(value).hex()
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == \
        bip32_node_from_codex32_share(share).hwif()
    reset_seed_words()


@pytest.mark.parametrize('value', SHARES + CW_SHARES)
@pytest.mark.parametrize('way,tmp', [
    ('sd', True),
    ('vdisk', False),
    ('nfc', True),
    ('qr', False),
    ('input', True),
])
def test_import_codex32(way, tmp, value, is_q1, skip_if_useless_way,
                        enable_nfc, enable_hw_ux, import_codex32_ui, expect_ftux,
                        confirm_tmp_seed, verify_ephemeral_secret_ui, sim_exec, dev, settings_set,
                        reset_seed_words, unit_test, set_seed_words, active_secret):
    if way == 'input' and len(value) == 127 and not is_q1:
        pytest.skip('long manual entry covered on Q')
    settings_set('seedvault', False)
    if tmp:
        set_seed_words('extra sport youth surge capital category kid ginger extend way cause hamster')
    else:
        unit_test('devtest/clear_seed.py')
    if way == 'nfc':
        enable_nfc()
    elif way == 'vdisk':
        enable_hw_ux('vdisk')
    skip_if_useless_way(way)

    entered = ' '.join(value[i:i+4] for i in range(0, len(value), 4)) if len(value) == 127 else value
    import_codex32_ui(way, entered, tmp=tmp)
    share = Share.parse(value)
    node = bip32_node_from_codex32_share(share)
    if tmp:
        confirm_tmp_seed(expect_xfp=node.fingerprint().hex().upper())
        verify_ephemeral_secret_ui(xpub=node.hwif())
    else:
        expect_ftux()
        settings_set('chain', 'XTN')
    assert active_secret() == native_encoding(value).hex()
    assert dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000) == node.hwif()
    reset_seed_words()


@pytest.mark.parametrize('key', [0,
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
], ids=['zero', 'order', 'above-order'])
@pytest.mark.parametrize('state,vault', [
    ('blank', False), ('main', False), ('temporary', False),
    ('main', True), ('temporary', True),
])
def test_import_codex32_invalid_key_preserves_state(key, state, vault,
                                                    unit_test, reset_seed_words, settings_set,
                                                    sim_exec, import_codex32_ui, cap_story):
    reset_seed_words()
    if state == 'blank':
        unit_test('devtest/clear_seed.py')
    settings_set('seedvault', vault)
    if state == 'temporary':
        sim_exec('from stash import SecretStash; '
                 'pa.tmp_secret(SecretStash.encode(master_secret=bytes(range(32))))')

    snapshot = (
        'RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value, '
        'pa.is_secret_blank(), settings.nvram_key, settings.current, '
        'settings.master_get("seeds", []))))')
    before = sim_exec(snapshot)
    value = Share.from_seed(bytes(32) + key.to_bytes(32, 'big'),
                            'cx', 'test', SECRET, 0).to_string()
    try:
        import_codex32_ui('sd', value, tmp=state != 'blank',
                          seed_vault=vault, tmp_active=state == 'temporary')
        title, story = cap_story()
        assert title == 'FAILED'
        assert 'Failed to import.' in story
        assert 'bip32 lottery winner' in story
        assert sim_exec(snapshot) == before
    finally:
        reset_seed_words()


@pytest.mark.parametrize('value,error', INVALID_C32)
def test_import_codex32_garbage(value, error, unit_test, import_codex32_ui, cap_story, reset_seed_words):
    unit_test('devtest/clear_seed.py')
    import_codex32_ui('sd', value)
    title, story = cap_story()
    assert title == 'FAILED'
    assert 'Unable to parse Codex32 share.' in story
    assert error in story
    reset_seed_words()


@pytest.mark.parametrize('value', IMPORT_SHARES[13:] + [CW_SHARE_A])
@pytest.mark.parametrize('state,vault', [('blank', False), ('main', True), ('temporary', True)])
def test_non_secret_import_preserves_state(value, state, vault, unit_test, reset_seed_words,
                                           settings_set, sim_exec, import_codex32_ui, cap_story):
    reset_seed_words()
    if state == 'blank':
        unit_test('devtest/clear_seed.py')
    settings_set('seedvault', vault)
    if state == 'temporary':
        sim_exec('from stash import SecretStash; '
                 'pa.tmp_secret(SecretStash.encode(master_secret=bytes(range(32))))')
    snapshot = ('RV.write(repr((bytes(pa.fetch(bypass_tmp=True)), pa.tmp_value, '
                'pa.is_secret_blank(), settings.nvram_key, settings.current, '
                'settings.master_get("seeds", []))))')
    before = sim_exec(snapshot)
    try:
        import_codex32_ui('sd', value, tmp=state != 'blank', seed_vault=vault,
                          tmp_active=state == 'temporary')
        title, story = cap_story()
        assert title == 'FAILED'
        assert 'Failed to import.' in story
        assert 'Need secret share S. Use Shamir Recover' in story
        assert sim_exec(snapshot) == before
    finally:
        reset_seed_words()


def test_recover_does_not_use_seed_vault(reset_seed_words, settings_set, goto_shamir_recover,
                                      cap_story, press_cancel):
    reset_seed_words()
    settings_set('seedvault', True)
    goto_shamir_recover(tmp=True, seed_vault=True)
    assert 'Seed Vault' not in cap_story()[1]
    press_cancel()
    reset_seed_words()


@pytest.mark.parametrize('size', [24, 48])
def test_shamir_split_unsupported_master_size(size, reset_seed_words, set_encoded_secret,
                                             goto_shamir_split, shamir_split_settings,
                                             cap_story, sim_exec):
    encoded = bytes([size]) + bytes(range(size)) + bytes(71-size)
    set_encoded_secret(encoded)
    goto_shamir_split()
    shamir_split_settings(3, 2)
    title, story = cap_story()
    assert title == 'FAILED'
    assert 'MS1 requires a 128, 256 or 512-bit master seed.' in story
    assert sim_exec('from utils import B2A; RV.write(B2A(pa.fetch()))') == encoded.hex()
    reset_seed_words()
