# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Tests for paper-wallet feature
#
# Paper wallet features MUST work on both device with and without secrets.
# This module can and should be run with `-l` and without it.
#

import pytest, time, os, shutil, re, random, json
from binascii import a2b_hex
from hashlib import sha256
from bip32 import PrivateKey
from ckcc_protocol.constants import *


@pytest.mark.parametrize('mode', ["classic", 'segwit', 'taproot'])
@pytest.mark.parametrize('pdf', [False, True])
@pytest.mark.parametrize('netcode', ["XRT", "BTC", "XTN"])
def test_generate(mode, pdf, netcode, dev, cap_menu, pick_menu_item, goto_home, cap_story,
                  need_keypress, microsd_path, verify_detached_signature_file, settings_set,
                  press_select, validate_address, bitcoind):
    # test UX and operation of the 'bitcoin core' wallet export
    mx = "Don't make PDF"

    settings_set("chain", netcode)

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Paper Wallets')

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

    if mode == 'taproot':
        pick_menu_item('Classic P2PKH')
        pick_menu_item('Taproot P2TR')
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
    if "Press (1)" in story:
        need_keypress("1")
        time.sleep(0.2)
        title, story = cap_story()

    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    sig_file = story[-1]
    if not pdf:
        if mode == "taproot":
            fname = story[-1]
        else:
            fname = story[-2]
            fnames = [fname]
    else:
        if mode == "taproot":
            fname = story[-2]
            pdf_name = story[-1]
        else:
            fname = story[-3]
            pdf_name = story[-2]
            fnames = [fname, pdf_name]
        assert pdf_name.endswith('.pdf')

    assert fname.endswith('.txt')
    if mode != 'taproot':
        assert sig_file.endswith(".sig")
        verify_detached_signature_file(fnames, sig_file, "sd",
                                       addr_fmt=AF_CLASSIC if mode == "classic" else AF_P2WPKH)

    path = microsd_path(fname)
    _wif = None
    _sk = None
    _addr = None
    _idesc = None
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
                _addr = val
            elif hdr == 'Private key:':         # for QR case
                assert val == _wif
            elif 'Private key' in hdr and 'WIF=Wallet' in hdr:
                _wif = val
            elif 'Private key' in hdr and 'Hex, 32 bytes' in hdr:
                _sk = val
            elif 'Bitcoin Core command':
                assert _wif in val
                if 'importdescriptors' in val:
                    _idesc = val
                assert 'importprivkey' in val or 'importdescriptors' in val
            else:
                print(f'{hdr} => {val}')
                raise ValueError(hdr)

    if netcode != "XRT":
        from bip32 import PrivateKey
        k1 = PrivateKey.from_wif(_wif)
        k2 = PrivateKey.parse(a2b_hex(_sk))
        assert k1 == k2
        validate_address(_addr, k1)
    else:
        if mode == "segwit":
            assert _addr.startswith("bcrt1q")
        elif mode == "taproot":
            assert _addr.startswith("bcrt1p")
        else:
            assert _addr[0] in "mn"

        # bitcoind on regtest
        conn = bitcoind.create_wallet(wallet_name="paper", disable_private_keys=False, blank=True,
                                      passphrase=None, avoid_reuse=False, descriptors=True)
        desc_obj_s, desc_obj_e = _idesc.find("["), _idesc.find("]") + 1
        desc_obj = json.loads(_idesc[desc_obj_s:desc_obj_e])
        desc = desc_obj[0]["desc"]
        res = conn.importdescriptors(desc_obj)
        assert res[0]["success"]
        assert _addr == conn.deriveaddresses(desc)[0]
        bitcoind.delete_wallet_files()

    if not pdf: return

    path = microsd_path(pdf_name)
    with open(path, 'rb') as fp:

        d = fp.read()
        assert _wif.encode('ascii') in d
        assert _addr.encode('ascii') in d

        os.unlink(path)

@pytest.mark.parametrize('rolls', [ '123123', '123'*30] )
def test_dice_generate_failure_num_attempts(rolls, dev, cap_menu, pick_menu_item,
                                            goto_home, cap_story, need_keypress, OK, X,
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
    assert f'Press {OK} to add more dice rolls. {X} to exit' in story
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
@pytest.mark.parametrize('testnet', [True, False])
def test_dice_generate(rolls, testnet, dev, cap_menu, pick_menu_item, goto_home,
                       cap_story, need_keypress, microsd_path, press_select,
                       verify_detached_signature_file, settings_set):
    # verify the math for dice rolling method

    settings_set("chain", "XTN" if testnet else "BTC")

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

        k2 = PrivateKey(sec_exp=a2b_hex(val))
        assert addr == k2.K.address(chain="XTN" if testnet else "BTC", addr_fmt="p2pkh")

        assert val == sha256(rolls.encode('ascii')).hexdigest()

        os.unlink(path)

# EOF
