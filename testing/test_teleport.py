# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Key Teleport (a Q-only feature)
#
# - you'll need v1.0.1 of bbqr library for this to work
#
import pytest, time, re
from helpers import prandom
from binascii import a2b_hex
from bbqr import split_qrs, join_qrs
from charcodes import KEY_QR, KEY_NFC
from base64 import b32encode

from test_bbqr import readback_bbqr

# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1, is_headless):
    if not is_q1 or is_headless:
        raise pytest.skip('Q1 only (not headless)')

@pytest.fixture()
def rx_start(grab_payload, goto_home, pick_menu_item):
    def doit():
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Key Teleport (start)')

        return grab_payload(': Receive', 'R')

    return doit
    

@pytest.fixture()
def grab_payload(press_select, need_keypress, press_cancel, nfc_read_url,  cap_story, nfc_block4rf, cap_screen_qr):

    # start the Rx process, capturing numeric code
    def doit(expect_in_title, tt_code, allow_reuse=True, reset_pubkey=False):

        title, story = cap_story()
    
        if 'Reuse' in title and tt_code == 'R':
            assert allow_reuse
            assert 'press (R)' in story

            if reset_pubkey:
                # make a new key anyway
                need_keypress('r')
            else:
                press_select()

            title, story = cap_story()

        assert 'Teleport' in title
        assert expect_in_title in title

        assert 'QR' in story

        code, = re.findall(' (\w{8})  =  ', story)
        assert len(code) == 8

        nfc_raw = None
        if KEY_NFC in story:
            # test NFC case -- when enabled
            need_keypress(KEY_NFC)
            
            # expect NFC animation
            nfc_block4rf()

            url = nfc_read_url().replace('%24', '$')

            assert url.startswith('https://keyteleport.com#')

            nfc_data = url.rsplit('#')[1]
            assert nfc_data.startswith(f'B$2{tt_code}0100') 

            filetype, nfc_raw = join_qrs([nfc_data])     # update your bbqr install if fails
            assert filetype == tt_code

        need_keypress(KEY_QR)

        qr_data = cap_screen_qr().decode()

        filetype, qr_raw = join_qrs([qr_data])
        assert filetype == tt_code

        if nfc_raw: assert nfc_raw == qr_raw

        press_cancel()
        press_cancel()

        return code, qr_data
        
    return doit

@pytest.fixture()
def rx_complete(press_select, need_keypress, press_cancel, cap_story, scan_a_qr, enter_complex, cap_screen, goto_home):
    # finish the teleport by doing QR and getting data
    def doit(data, pw):
        goto_home()
        need_keypress(KEY_QR)
        time.sleep(.250)        # required
        scan_a_qr(data)

        time.sleep(.250)        # required
        scr = cap_screen()
        assert 'Teleport Password (text)' in scr

        enter_complex(pw)
        time.sleep(.150)        # required


    return doit

@pytest.fixture()
def tx_start(press_select, need_keypress, press_cancel, goto_home, pick_menu_item, cap_story, scan_a_qr, enter_complex, cap_screen):

    # start the Tx process, capturing password and leaving you are picker menu
    def doit(rx_qr, rx_code):
        goto_home()
        need_keypress(KEY_QR)
        time.sleep(.250)        # required
        scan_a_qr(rx_qr)

        time.sleep(.250)        # required
        scr = cap_screen()
        assert 'Teleport Password (number)' in scr

        enter_complex(rx_code)
        time.sleep(.150)        # required

        title, story = cap_story()
        assert title == 'Key Teleport: Send'

        assert 'secure notes' in story
        assert 'WARNING' in story
        press_select()

    return doit

def test_rx_reuse(rx_start, settings_remove):

    code, enc_pubkey = rx_start(True, True)
    assert code.isdigit()
    code2, enc_pubkey2 = rx_start(True, False)
    assert code2 == code
    assert enc_pubkey2 == enc_pubkey

    code3, pk3 = rx_start(True, True)
    assert code3 != code

def test_tx_quick_note(rx_start, tx_start, settings_remove, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select):
    # Send a quick-note
    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey, code)

    m = cap_menu()
    assert 'Master Seed Words' in m
    assert 'Quick Text Message' in m
    # other contents require other features to be enabled

    msg = b32encode(prandom(10)).decode('ascii')

    pick_menu_item('Quick Text Message')

    enter_complex(msg)

    time.sleep(.150)        # required
    pw, data = grab_payload('Teleport Password', 'S')
    assert len(pw) == 8
    
    # now, send that back
    rx_complete(data, pw)

    # should arrive in notes menu
    m = cap_menu()
    assert m[-1] == 'Import'
    mi = [i for i in m if i.endswith(': Quick Note')]
    assert mi
    pick_menu_item(mi[-1])      # most recent test

    # view note
    m = cap_menu()
    assert m[0] == '"Quick Note"'
    pick_menu_item(m[0])

    _, body = cap_story()
    assert body == msg

    # cleanup
    press_cancel()
    pick_menu_item('Delete')
    press_select()
    
        
# EOF
