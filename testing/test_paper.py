# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Tests for paper-wallet feature
#
# Paper wallet features MUST work on both device with and without secrets.
# This module can and should be run with `-l` and without it.
#
import random

import pytest, time, os, shutil, re
from pycoin.key.Key import Key
from pycoin.encoding import from_bytes_32
from binascii import a2b_hex
from hashlib import sha256
from ckcc_protocol.constants import *
from bech32 import bech32_decode, convertbits, Encoding


@pytest.mark.parametrize('mode', ["classic", 'segwit'])
@pytest.mark.parametrize('pdf', [False, True])
@pytest.mark.parametrize('netcode', ["XTN", "BTC"])
def test_generate(mode, pdf, netcode, dev, cap_menu, pick_menu_item, goto_home, cap_story,
                  need_keypress, microsd_path, verify_detached_signature_file, settings_set,
                  press_select):
    # test UX and operation of the 'bitcoin core' wallet export
    mx = "Don't make PDF"

    settings_set("chain", netcode)

    goto_home()
    pick_menu_item('Advanced/Tools')
    try:
        pick_menu_item('Paper Wallets')
    except:
        raise pytest.skip('Feature absent')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'pick a random' in story
    assert 'MANY RISKS' in story

    press_select()

    time.sleep(0.1)
    if mode == 'segwit':
        pick_menu_item('Classic P2PKH')
        pick_menu_item('Segwit P2WPKH')
        time.sleep(0.5)

    if pdf:
        assert mx in cap_menu()
        shutil.copy('../docs/paperwallet.pdf', microsd_path('paperwallet.pdf'))
        pick_menu_item(mx)

        time.sleep(0.2)
        pick_menu_item('paperwallet.pdf')


    pick_menu_item('GENERATE WALLET')

    time.sleep(0.1)
    title, story = cap_story()
    if "Press (1) to save paper wallet file to SD Card" in story:
        need_keypress("1")
        time.sleep(0.2)
        title, story = cap_story()

    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    sig_file = story[-1]
    if not pdf:
        fname = story[-2]
        fnames = [fname]
    else:
        fname = story[-3]
        pdf_name = story[-2]
        fnames = [fname, pdf_name]
        assert pdf_name.endswith('.pdf')

    assert fname.endswith('.txt')
    assert sig_file.endswith(".sig")
    verify_detached_signature_file(fnames, sig_file, "sd",
                                   addr_fmt=AF_CLASSIC if mode == "classic" else AF_P2WPKH)

    path = microsd_path(fname)
    with open(path, 'rt') as fp:
        hdr = None
        for ln in fp:
            ln = ln.rstrip()
            if not ln: continue

            if ln[0] != ' ':
                hdr = ln
                continue

            if '█' in ln:
                continue

            val = ln.strip()
            if 'Deposit address' in hdr:
                assert val == fname.split('.', 1)[0].split('-', 1)[0]
                txt_addr = val
                if mode != 'segwit':
                    addr = Key.from_text(val)
                else:
                    hrp, data, enc = bech32_decode(val)
                    assert hrp in {'tb', 'bc', 'bcrt'}
                    assert enc == Encoding.BECH32
                    decoded = convertbits(data[1:], 5, 8, False)[-20:]
                    addr = Key(hash160=bytes(decoded), is_compressed=True, netcode=netcode)
            elif hdr == 'Private key:':         # for QR case
                assert val == wif
            elif 'Private key' in hdr and 'WIF=Wallet' in hdr:
                wif = val
                k1 = Key.from_text(val)
            elif 'Private key' in hdr and 'Hex, 32 bytes' in hdr:
                k2 = Key(secret_exponent=from_bytes_32(a2b_hex(val)), is_compressed=True)
            elif 'Bitcoin Core command':
                assert wif in val
                assert 'importmulti' in val or 'importprivkey' in val
            else:
                print(f'{hdr} => {val}')
                raise ValueError(hdr)

        assert k1.sec() == k2.sec()
        assert k1.public_pair() == k2.public_pair()
        assert addr.address() == k1.address()

        os.unlink(path)

    if not pdf: return

    path = microsd_path(pdf_name)
    with open(path, 'rb') as fp:

        d = fp.read()
        assert wif.encode('ascii') in d
        assert txt_addr.encode('ascii') in d

        os.unlink(path)

@pytest.mark.parametrize('rolls', [ '123123', '123'*30] )
def test_dice_generate_failure_num_attempts(rolls, dev, cap_menu, pick_menu_item,
                                            goto_home, cap_story, need_keypress,
                                            microsd_path, press_select, press_cancel):
    # verify the math for dice rolling method

    goto_home()
    pick_menu_item('Advanced/Tools')
    try:
        pick_menu_item('Paper Wallets')
    except:
        raise pytest.skip('Feature absent')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'pick a random' in story
    assert 'MANY RISKS' in story

    press_select()

    time.sleep(0.1)
    pick_menu_item('Use Dice')

    for ch in rolls:
        time.sleep(0.01)
        need_keypress(ch)

    press_select()
    time.sleep(0.1)
    title, story = cap_story()
    assert 'Not enough dice rolls!!!' in story
    assert 'For 256-bit security you need at least 99 rolls' in story
    assert 'Press OK to add more dice rolls. X to exit' in story
    press_cancel()

@pytest.mark.parametrize('rolls', ['123'*34, "1"*99, "64"*50])
def test_dice_generate_failure_distribution(rolls, dev, cap_menu, pick_menu_item,
                                            goto_home, cap_story, need_keypress,
                                            microsd_path, press_select):
    # verify the math for dice rolling method

    goto_home()
    pick_menu_item('Advanced/Tools')
    try:
        pick_menu_item('Paper Wallets')
    except:
        raise pytest.skip('Feature absent')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'pick a random' in story
    assert 'MANY RISKS' in story

    press_select()

    time.sleep(0.1)
    pick_menu_item('Use Dice')

    for ch in rolls:
        time.sleep(0.01)
        need_keypress(ch)

    press_select()
    time.sleep(0.1)
    title, story = cap_story()
    assert 'Distribution of dice rolls is not random' in story
    assert 'Some numbers occurred more than 30% of the time' in story
    # exit

@pytest.mark.parametrize('rolls', [
    '123456'*17,
    "".join([str(random.SystemRandom().randint(1,6)) for _ in range(99)]),
    "".join([str(random.SystemRandom().randint(1,6)) for _ in range(99)]),
])
@pytest.mark.parametrize('netcode', ["XTN", "BTC"])
def test_dice_generate(rolls, netcode, dev, cap_menu, pick_menu_item, goto_home,
                       cap_story, need_keypress, microsd_path, press_select,
                       verify_detached_signature_file, settings_set):
    # verify the math for dice rolling method

    settings_set("chain", netcode)

    goto_home()
    pick_menu_item('Advanced/Tools')
    try:
        pick_menu_item('Paper Wallets')
    except:
        raise pytest.skip('Feature absent')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'pick a random' in story
    assert 'MANY RISKS' in story

    press_select()

    time.sleep(0.1)
    pick_menu_item('Use Dice')

    for ch in rolls:
        time.sleep(0.01)
        need_keypress(ch)

    press_select()
    time.sleep(0.1)
    if len(rolls) < 99:
        title, story = cap_story()
        assert 'need 50' in story
        press_select()

    time.sleep(0.4)

    title, story = cap_story()
    if "Press (1) to save paper wallet file to SD Card" in story:
        need_keypress("1")
        time.sleep(0.2)
        title, story = cap_story()

    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    sig_file = story[-1]
    fname = story[-2]

    assert sig_file.endswith('.sig')
    assert fname.endswith('.txt')
    _, address = verify_detached_signature_file([fname], sig_file, "sd", addr_fmt=AF_CLASSIC)

    addr,_ = fname.split('.')
    if '-' in addr:
        # junk in working dir
        addr,_ = addr.split('-')

    assert addr == address
    
    path = microsd_path(fname)
    with open(path, 'rt') as fp:
        hx = re.findall(r'[0-9a-f]{64}', fp.read())
        assert len(hx) == 1
        val, = hx

        k2 = Key(secret_exponent=from_bytes_32(a2b_hex(val)), is_compressed=True, netcode=netcode)
        assert addr == k2.address()

        assert val == sha256(rolls.encode('ascii')).hexdigest()

        os.unlink(path)

# EOF
