# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Tests for paper-wallet feature
#
import pytest, time, struct, os, shutil, re
from pycoin.key.Key import Key
from pycoin.encoding import from_bytes_32
from base64 import b64encode
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
from helpers import xfp2str
import json
from conftest import simulator_fixed_xfp, simulator_fixed_xprv
from bech32 import bech32_decode, convertbits, Encoding


@pytest.mark.parametrize('mode', [ "classic", 'segwit'])
@pytest.mark.parametrize('pdf', [ False, True])
def test_generate(mode, pdf, dev, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path):
    # test UX and operation of the 'bitcoin core' wallet export
    mx = "Don't make PDF"

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

    need_keypress('y')

    time.sleep(0.1)
    if mode == 'segwit':
        pick_menu_item('Classic Address')
        pick_menu_item('Segwit/Bech32')
        time.sleep(0.5)

    if pdf:
        assert mx in cap_menu()
        shutil.copy('../docs/paperwallet.pdf', microsd_path('paperwallet.pdf'))
        pick_menu_item(mx)

        time.sleep(0.2)
        title, story = cap_story()
        assert 'Pick PDF' in story
        need_keypress('y')

        pick_menu_item('paperwallet.pdf')


    pick_menu_item('GENERATE WALLET')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    if not pdf:
        fname = story[-1]
    else:
        fname = story[-2]
        pdf_name = story[-1]
        assert pdf_name.endswith('.pdf')

    assert fname.endswith('.txt')

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
                    assert hrp in {'tb', 'bc' }
                    assert enc == Encoding.BECH32
                    decoded = convertbits(data[1:], 5, 8, False)[-20:]
                    addr = Key(hash160=bytes(decoded), is_compressed=True, netcode='XTN')
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

@pytest.mark.parametrize('rolls', [ '123123', '123'*30, '123456'*17] )
def test_dice_generate(rolls, dev, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path):
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

    need_keypress('y')

    time.sleep(0.1)
    pick_menu_item('Use Dice')

    for ch in rolls:
        time.sleep(0.01)
        need_keypress(ch)

    need_keypress('y')
    time.sleep(0.1)
    if len(rolls) < 99:
        title, story = cap_story()
        assert 'need 50' in story
        need_keypress('y')

    time.sleep(0.4)

    title, story = cap_story()
    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    fname = story[-1]

    assert fname.endswith('.txt')

    addr,_ = fname.split('.')
    if '-' in addr:
        # junk in working dir
        addr,_ = addr.split('-')
    
    path = microsd_path(fname)
    with open(path, 'rt') as fp:
        hx = re.findall(r'[0-9a-f]{64}', fp.read())
        assert len(hx) == 1
        val, = hx

        k2 = Key(secret_exponent=from_bytes_32(a2b_hex(val)), is_compressed=True, netcode='XTN')
        assert addr == k2.address()

        assert val == sha256(rolls.encode('ascii')).hexdigest()

        os.unlink(path)


# EOF
