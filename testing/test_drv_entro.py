# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test drv_entro.py features
#
import pytest, time, re
from binascii import a2b_hex, b2a_hex
from helpers import B2A
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import Key
from mnemonic import Mnemonic
from charcodes import KEY_QR

HISTORY = set()

# XPRV from spec: xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
EXAMPLE_XPRV = '011b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed900000000000000'


@pytest.fixture
def derive_bip85_secret(goto_home, press_select, pick_menu_item, cap_story, enter_text,
                        set_encoded_secret, set_seed_words, settings_set, is_q1,
                        seed_story_to_words):
    def doit(mode, index, expect=None, entropy=None, sim_sec=None, chain="BTC"):
        if sim_sec:
            if len(sim_sec.split(" ")) in (12,18,24):
                set_seed_words(sim_sec)
            else:
                set_encoded_secret(a2b_hex(sim_sec))

        if chain:
            settings_set('chain', chain)

        goto_home()
        time.sleep(.1)
        pick_menu_item('Advanced/Tools')
        time.sleep(.1)
        pick_menu_item('Derive Seed B85' if not is_q1 else 'Derive Seeds (BIP-85)')

        time.sleep(0.1)
        title, story = cap_story()

        assert 'seed value' in story
        assert 'other wallet systems' in story

        press_select()
        time.sleep(0.1)
        title, story = cap_story()
        if "You have a temporary seed active - deriving from temporary" in story:
            press_select()

        time.sleep(0.1)
        pick_menu_item(mode)

        enter_text(str(index) if index is not None else '')

        time.sleep(0.1)
        title, story = cap_story()

        assert f'Path Used (index={index}):' in story
        assert "m/83696968h/" in story
        assert f"/{index}h" in story

        if entropy is not None:
            assert f"Raw Entropy:\n{entropy}" in story

        can_import = False

        if ' words' in mode:
            num_words = int(mode.split()[0])
            assert f'Seed words ({num_words}):' in story
            assert f"m/83696968h/39h/0h/{num_words}h/{index}h" in story
            assert '1:' in story
            assert f'{num_words}:' in story
            got = seed_story_to_words(story)
            if expect:
                assert ' '.join(got) == expect
            can_import = 'words'

        elif 'XPRV' in mode:
            assert 'Derived XPRV:' in story
            assert f"m/83696968h/32h/{index}h" in story
            if expect:
                assert expect in story
            can_import = 'xprv'

        elif 'WIF' in mode:
            assert 'WIF (privkey)' in story
            assert f"m/83696968h/2h/{index}h" in story
            if expect:
                assert expect in story

        elif 'bytes hex' in mode:
            width = int(mode.split('-')[0])
            assert width in {32, 64}
            assert f'Hex ({width} bytes):' in story
            assert f"m/83696968h/128169h/{width}h/{index}h" in story
            if expect:
                assert expect in story

        elif 'Passwords' == mode:
            assert "Password:" in story
            assert f"m/83696968h/707764h/21h/{index}h" in story
            if expect:
                assert expect in story
            assert "(0) to type password over USB" in story

        else:
            raise ValueError(mode)

        return can_import, story

    return doit


@pytest.fixture
def activate_bip85_ephemeral(need_keypress, cap_story, sim_exec, reset_seed_words,
                             confirm_tmp_seed):
    def doit(do_import, reset=True, expect=None, entropy=None, save_to_vault=False):
        _, story = cap_story()
        assert '(0) to switch to derived secret' in story

        try:
            time.sleep(0.1)
            need_keypress('0')

            confirm_tmp_seed(seedvault=save_to_vault)

            encoded = sim_exec('from pincodes import pa; RV.write(repr(pa.fetch()))')
            print(encoded)
            assert 'Error' not in encoded
            encoded = eval(encoded)
            assert len(encoded) == 72

            marker = encoded[0]
            if do_import == 'words':
                assert marker & 0x80 == 0x80
                width = ((marker & 0x3) + 2) * 8
                assert width in {16, 24, 32}
                if entropy:
                    assert encoded[1:1 + width] == a2b_hex(entropy)
            elif do_import == 'xprv':
                assert marker == 0x01
                if expect:
                    node = BIP32Node.from_hwif(expect)
                    ch, pk = encoded[1:33], encoded[33:65]
                    assert node.chain_code() == ch
                    assert node.secret_exponent() == int(B2A(pk), 16)

        finally:
            # required cleanup
            if reset:
                reset_seed_words()

    return doit


@pytest.mark.parametrize('mode,index,entropy,expect', [ 
    ('12 words', 0,
        '6250b68daf746d12a24d58b4787a714b', 
        'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'),
    ('18 words', 0,
        '938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc',
         'near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token'),
    ('24 words', 0,
        'ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f',
        'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano'),

    ('WIF (privkey)', 0,
        '7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1',
        'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'),
    ('XPRV (BIP-32)', 0,
        None,
        'xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX'),
    ('32-bytes hex', 0,
        None,
        'ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc'),
    ('64-bytes hex', 0,
        None,
        '492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c'),

    ('Passwords', 0,
     None,
     "dKLoepugzdVJvdL56ogNV"),
])
def test_bip_vectors(mode, index, entropy, expect, cap_story, need_keypress,
                     load_export_and_verify_signature, derive_bip85_secret,
                     activate_bip85_ephemeral, press_select, press_cancel):

    do_import, story = derive_bip85_secret(mode, index, expect, entropy, sim_sec=EXAMPLE_XPRV)

    # write to SD
    msg = story.split('Press', 1)[0]
    assert 'Press (1) to save' in story
    need_keypress('1')

    time.sleep(0.1)
    title, story = cap_story()
    contents,_ = load_export_and_verify_signature(story, "sd", fpattern="drv", label=None)
    assert contents.strip() == msg.strip()
    press_select()
    time.sleep(0.1)
    title, story = cap_story()

    if do_import:
        activate_bip85_ephemeral(do_import, expect=expect, entropy=entropy)
    else:
        assert 'show QR code' in story

    press_cancel()


def test_allow_bip32_max_int(pick_menu_item, goto_home, enter_number, is_q1,
                             press_select, cap_screen, press_cancel, cap_story,
                             settings_set):
    max_int = 2147483647
    to_input = 9999999999
    mi = 'Derive Seed B85' if not is_q1 else 'Derive Seeds (BIP-85)'
    goto_home()
    # by default only indexes up to 9999 are allowed
    pick_menu_item("Advanced/Tools")
    pick_menu_item(mi)
    press_select()
    pick_menu_item("12 words")
    enter_number(to_input)
    time.sleep(.1)
    scr = cap_screen()
    assert "index=9999" in scr  # does not allow to go over this value
    press_cancel()

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("B85 Idx Values")
    time.sleep(.1)
    _, story = cap_story()
    assert "Allow unlimited indexes for BIP-85 derivations?" in story
    assert "DANGER" in story
    press_select()
    pick_menu_item("Unlimited")

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item(mi)
    press_select()
    pick_menu_item("12 words")
    enter_number(to_input)
    time.sleep(.1)
    scr = cap_screen()
    assert f"index={max_int}" in scr
    press_cancel()
    settings_set("b85max", 0)


@pytest.mark.qrcode
@pytest.mark.parametrize('mode,pattern', [ 
    ('WIF (privkey)', r'[1-9A-HJ-NP-Za-km-z]{51,52}' ),
    ('XPRV (BIP-32)', r'[tx]prv[1-9A-HJ-NP-Za-km-z]{107}'),
    ('32-bytes hex', r'[a-f0-9]{64}'),
    ('64-bytes hex', r'[a-f0-9]{128}'),
    ('12 words', r'[a-f0-9]{32}'),
    ('18 words', r'[a-f0-9]{48}'),
    ('24 words', r'[a-f0-9]{64}'),
    ('Passwords', r'[a-zA-Z0-9+/]{21}'),
])
@pytest.mark.parametrize('index', [0, 1, 10, 100, 1000, 9999, 2147483647])
def test_path_index(mode, pattern, index, need_keypress, cap_screen_qr, seed_story_to_words,
                    derive_bip85_secret, reset_seed_words, is_q1, press_cancel, settings_set):
    reset_seed_words()
    settings_set("b85max", 1)

    # Uses any key on Simulator; just checking for operation + entropy level
    _, story = derive_bip85_secret(mode, index)

    assert f'Path Used (index={index}):' in story
    assert "m/83696968h/" in story
    assert f"/{index}h" in story

    got = re.findall(pattern, story)[0]

    assert len(set(got)) >= 12

    global HISTORY
    assert got not in HISTORY
    HISTORY.add(got)

    if mode == "Passwords":
        from base64 import b64encode
        raw = re.findall(r'[a-f0-9]{64}', story)[0]
        exp = b64encode(a2b_hex(raw)).decode('ascii')[0:21]
        assert exp == got
    elif 'words' in mode:
        exp = Mnemonic('english').to_mnemonic(a2b_hex(got)).split()
        assert seed_story_to_words(story) == exp
    elif 'XPRV' in mode:
        node = BIP32Node.from_hwif(got)
        assert str(b2a_hex(node.chain_code()), 'ascii') in story
        assert hex(node.secret_exponent())[2:] in story
    elif 'WIF' in mode:
        key = Key.from_text(got)
        assert hex(key.secret_exponent())[2:] in story

    if index == 0:
        assert 'show QR code' in story
        need_keypress(KEY_QR if is_q1 else '4')

        qr = cap_screen_qr().decode('ascii')

        if mode == "Passwords":
            assert qr == exp == got
        elif 'words' in mode:
            gw = qr.lower().split()
            assert gw == [i[0:4] for i in exp]

        elif 'hex' in mode:
            assert qr.lower() == got

        elif 'XPRV' in mode:
            assert qr == got

        elif 'WIF' in mode:
            assert qr == got

    press_cancel()
    settings_set("b85max", 0)


def test_type_passwords(dev, cap_menu, pick_menu_item, goto_home,
                        cap_story, press_select, cap_screen, enter_text):
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Keyboard EMU')
    _, story = cap_story()
    story1 = "This mode adds a top-level menu item for typing deterministically-generated passwords (BIP-85), directly into an attached USB computer (as an emulated keyboard)."
    assert story1 == story
    press_select()
    pick_menu_item('Enable')
    time.sleep(0.3)
    goto_home()
    menu = cap_menu()
    assert "Type Passwords" in menu
    pick_menu_item("Type Passwords")
    time.sleep(0.1)
    # here we accessed index loop and can derive
    for index in [0, 10, 100, 1000, 9999]:
        time.sleep(0.5)
        enter_text(str(index))
        time.sleep(1)
        _, story = cap_story()
        assert "Place mouse at required password prompt, then press OK to send keystrokes." in story
        split_story = story.split("\n\n")
        _, pwd = split_story[1].split("\n")
        _, path = split_story[2].split("\n")
        assert path == f"m/83696968h/707764h/21h/{index}h"
        assert len(pwd) == 21
        assert "=" not in pwd
        press_select()  # does nothing on simulator
        time.sleep(0.2)

    # exit Enter Password menu
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Keyboard EMU')
    pick_menu_item('Default Off')
    menu = cap_menu()
    assert "Type Passwords" not in menu

# EOF
