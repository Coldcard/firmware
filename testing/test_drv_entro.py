# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test drv_entro.py features
#
import pytest, time, os, re
from binascii import a2b_hex, b2a_hex
from helpers import B2A
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import Key
from mnemonic import Mnemonic

# XPRV from spec: xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
EXAMPLE_XPRV = '011b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed900000000000000'


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
def test_bip_vectors(mode, index, entropy, expect,
        set_encoded_secret, dev, cap_menu, pick_menu_item,
        goto_home, cap_story, need_keypress, microsd_path, settings_set, sim_eval, sim_exec,
        reset_seed_words
):

    set_encoded_secret(a2b_hex(EXAMPLE_XPRV))
    settings_set('chain', 'BTC')

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Derive Seed B85')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'seed value' in story
    assert 'other wallet systems' in story
    
    need_keypress('y')
    time.sleep(0.1)
    
    pick_menu_item(mode) 

    if index is not None:
        time.sleep(0.1)
        for n in str(index):
            need_keypress(n)

    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()

    assert f'Path Used (index={index}):' in story
    assert "m/83696968'/" in story
    assert f"/{index}'" in story

    if entropy is not None:
        assert f"Raw Entropy:\n{entropy}" in story

    do_import = False

    if ' words' in mode:
        num_words = int(mode.split()[0])
        assert f'Seed words ({num_words}):' in story
        assert f"m/83696968'/39'/0'/{num_words}'/{index}'" in story
        assert '\n 1: ' in story
        assert f'\n{num_words}: ' in story
        got = [ln[4:] for ln in story.split('\n') if len(ln)>5 and ln[2] == ':']
        assert ' '.join(got) == expect
        do_import = 'words'

    elif 'XPRV' in mode:
        assert 'Derived XPRV:' in story
        assert f"m/83696968'/32'/{index}'" in story
        assert expect in story
        do_import = 'xprv'

    elif 'WIF' in mode:
        assert 'WIF (privkey)' in story
        assert f"m/83696968'/2'/{index}'" in story
        assert expect in story

    elif 'bytes hex' in mode:
        width = int(mode.split('-')[0])
        assert width in { 32, 64}
        assert f'Hex ({width} bytes):' in story
        assert f"m/83696968'/128169'/{width}'/{index}'" in story
        assert expect in story

    elif 'Passwords' == mode:
        assert "Password:" in story
        assert f"m/83696968'/707764'/21'/{index}'" in story
        assert expect in story
        assert "2 to type password over USB" in story

    else:
        raise ValueError(mode)

    # write to SD
    msg = story.split('Press', 1)[0]
    if 1:
        assert 'Press 1 to save' in story
        need_keypress('1')

        time.sleep(0.1)
        title, story = cap_story()
    
        assert title == 'Saved'
        fname = story.split('\n')[-1]
        need_keypress('y')

        time.sleep(0.1)
        title, story = cap_story()

        assert story.startswith(msg)

        path = microsd_path(fname)
        assert path.endswith('.txt')
        txt = open(path, 'rt').read()

        assert txt.strip() == msg.strip()


    if do_import:
        assert '2 to switch to derived secret' in story

        try:
            time.sleep(0.1)
            need_keypress('2')

            if 0:   # screen was removed
                time.sleep(0.1)
                title, story = cap_story()
                assert title == "WARNING"
                assert 'Press 4 to prove you read to the end of this message and accept all consequences.' in story
                need_keypress("4")

            time.sleep(0.1)
            title, story = cap_story()
            assert 'master key in effect' in story

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
                assert encoded[1:1+width] == a2b_hex(entropy)
            elif do_import == 'xprv':
                assert marker == 0x01
                node = BIP32Node.from_hwif(expect)
                ch, pk = encoded[1:33], encoded[33:65]
                assert node.chain_code() == ch
                assert node.secret_exponent() == int(B2A(pk), 16)

        finally:
            # required cleanup
            reset_seed_words()

    else:
        assert '3 to view as QR code' in story

    need_keypress('x')

HISTORY = set()

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
@pytest.mark.parametrize('index', [0, 1, 10, 100, 1000, 9999])
def test_path_index(mode, pattern, index,
        dev, cap_menu, pick_menu_item,
        goto_home, cap_story, need_keypress, cap_screen_qr, qr_quality_check
):
    # Uses any key on Simulator; just checking for operation + entropy level

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Derive Seed B85')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'seed value' in story
    assert 'other wallet systems' in story
    
    need_keypress('y')
    time.sleep(0.1)
    
    pick_menu_item(mode) 

    if index is not None:
        time.sleep(0.1)
        for n in str(index):
            need_keypress(n)

    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()

    assert f'Path Used (index={index}):' in story
    assert "m/83696968'/" in story
    assert f"/{index}'" in story

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
        assert '\n'.join(f'{n+1:2d}: {w}' for n, w in enumerate(exp)) in story
    elif 'XPRV' in mode:
        node = BIP32Node.from_hwif(got)
        assert str(b2a_hex(node.chain_code()), 'ascii') in story
        assert hex(node.secret_exponent())[2:] in story
    elif 'WIF' in mode:
        key = Key.from_text(got)
        assert hex(key.secret_exponent())[2:] in story

    if index == 0:
        assert '3 to view as QR code' in story
        need_keypress('3')

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


def test_type_passwords(dev, cap_menu, pick_menu_item,
        goto_home, cap_story, need_keypress, cap_screen
):
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Keyboard EMU')
    _, story = cap_story()
    story1 = "This mode adds a top-level menu item for typing deterministically-generated passwords (BIP-85), directly into an attached USB computer (as an emulated keyboard)."
    assert story1 == story
    need_keypress("y")
    pick_menu_item('Enable')
    time.sleep(0.3)
    goto_home()
    menu = cap_menu()
    assert "Type Passwords" in menu
    pick_menu_item("Type Passwords")
    time.sleep(1)
    _, story = cap_story()
    story2 = 'Type Passwords (BIP-85)\n\nThis feature derives a deterministic password according BIP-85, from the seed. The password will be sent as keystrokes via USB to the host computer.'
    assert story == story2
    need_keypress("y")
    time.sleep(0.5)
    # here we accessed index loop and can derive
    for index in [0, 10, 100, 1000, 9999]:
        time.sleep(0.5)
        for n in str(index):
            need_keypress(n)
        need_keypress("y")
        time.sleep(1)
        _, story = cap_story()
        assert "Place mouse at required password prompt, then press OK to send keystrokes." in story
        split_story = story.split("\n\n")
        _, pwd = split_story[1].split("\n")
        _, path = split_story[2].split("\n")
        assert path == f"m/83696968'/707764'/21'/{index}'"
        assert len(pwd) == 21
        assert "=" not in pwd
        need_keypress("y")  # does nothing on simulator
        time.sleep(0.2)
    # exit Enter Password menu
    need_keypress("x")
    pick_menu_item('Settings')
    pick_menu_item('Keyboard EMU')
    pick_menu_item('Default Off')
    menu = cap_menu()
    assert "Type Passwords" not in menu

# EOF
