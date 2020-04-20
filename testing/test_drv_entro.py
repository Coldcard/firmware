# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# test drv_entro.py features
#
import pytest, time, os
from binascii import a2b_hex
from helpers import B2A
from pycoin.key.BIP32Node import BIP32Node

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
    ('XPRV', 0,
        None,
        'xprv9s21ZrQH143K3KJoGoKpsDsWdDNDBKs1wqFymBpCGJtrYXrfKzykGDBadZq5SrNde22F83X9qhFZr4uyV9TptTgLqCBc6XFN9tssphdxVeg'),     # XXX no second-source on this one
    ('32-bytes hex', 0,
        None,
        'ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc'),
    ('64-bytes hex', 0,
        None,
        '492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c'),
])
def test_bip_vectors(mode, index, entropy, expect,
        set_encoded_secret, dev, cap_menu, pick_menu_item,
        goto_home, cap_story, need_keypress, microsd_path, settings_set, sim_eval, sim_exec
):

    set_encoded_secret(a2b_hex(EXAMPLE_XPRV))
    settings_set('chain', 'BTC')

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('Derive Entropy')

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

    if 'words' in mode:
        num_words = int(mode.split()[0])
        assert f'Seed words ({num_words}):' in story
        assert f"m/83696968'/39'/0'/{num_words}'/{index}'" in story
        assert '\n 1: ' in story
        assert f'\n{num_words}: ' in story
        got = [ln[4:] for ln in story.split('\n') if len(ln)>5 and ln[2] == ':']
        assert ' '.join(got) == expect
        do_import = 'words'

    elif mode == 'XPRV':
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

            time.sleep(0.1)
            title, story = cap_story()
            assert 'New master key in effect' in story

            encoded = sim_eval('main.pa.fetch()')
            print(encoded)
            assert encoded.startswith('bytearray(b')
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
            sim_exec('import main; from pincodes import PinAttempt; '
                        'main.pa = PinAttempt(); main.pa.setup("12-12"); main.pa.login();')


    need_keypress('x')

# EOF
