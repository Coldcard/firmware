# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# UX and interactions related to Settings > Pin Options
#
# - altho this can pass on the simulator, it's much more interesting to test with "bare metal"
# - need this to recover:
#       from main import pa; pa.change(is_duress=1, new_pin=b'', old_pin=b'77-77')
# - same tests are needed in three modes: normal login, secondary PIN used for login, and
#   duress PIN used for login.
#
import pytest, time, os
from helpers import xfp2str

DEF_PIN = '12-12'
CLR_PIN = '999999-999999'

@pytest.fixture
def get_duress_secret(sim_eval):
    def doit(pin):
        # read the duress secret
        rv = sim_eval(f'main.pa.fetch(duress_pin=b"{pin}")', timeout=9000)
        if rv.startswith('Traceback'):
            raise RuntimeError(rv)
        assert rv[0:2] == "b'"
        return eval(rv)
    return doit

@pytest.fixture
def verify_pin_set(sim_eval):
    def doit(pin, secondary=False, duress=False, brickme=False):
        # check the SE holds the indicated PIN code
        kws = ''
        if secondary:
            kws += ", is_secondary=1"
        if duress:      # not used
            kws += ", is_duress=1"
        if brickme:
            kws += ", is_brickme=1"
        rv = sim_eval(f'main.pa.change(new_pin=b"{pin}", old_pin=b"{pin}" {kws})', timeout=9000)
        if rv != 'None':
            raise RuntimeError(rv)

    return doit

@pytest.fixture
def get_secondary_login(sim_eval):
    def doit():
        return sim_eval('main.pa.is_secondary') == 'True'
    return doit

@pytest.fixture
def goto_pin_options(pick_menu_item, goto_home):
    def doit():
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('PIN Options')

    return doit

@pytest.fixture
def enter_pin(cap_screen, need_keypress):
    def doit(pin):
        time.sleep(.01)      # required?
        scr = cap_screen().split('\n')
        title = scr[1]
        assert scr[2] == 'Enter PIN Prefix'
        for ch in pin:
            if ch != '-':
                time.sleep(.05)      # required?
                need_keypress(ch)
                time.sleep(.05)      # required?
                continue

            if ch == '-':
                need_keypress('y')
                time.sleep(.1)      # required

                scr = cap_screen().split('\n')
                assert ('Recognize these?' in scr) or ('Write these down:' in scr)
                words = scr[2:4]
                need_keypress('y')

                time.sleep(.1)      # required
                scr = cap_screen().split('\n')
                assert scr[-1] == 'Enter rest of PIN'

        need_keypress('y')
        time.sleep(0.1)

        return title, words


    return doit

@pytest.fixture
def change_pin(cap_screen, cap_story, cap_menu, need_keypress, enter_pin):
    def doit(old_pin, new_pin, hdr_text):
        # use standard menus and UX to change a PIN 
        title, story = cap_story()
        assert title == hdr_text
        assert ('We strongly recommend' in story) or (CLR_PIN in story)
        need_keypress('y')
        time.sleep(0.01)      # required

        assert max(len(i) for i in new_pin.split('-')) <= 6
        assert 2 <= min(len(i) for i in new_pin.split('-'))

        # give old pin, if there was one
        if old_pin != None:
            title, words = enter_pin(old_pin)
            assert title == 'Old '+hdr_text

        title, words2 = enter_pin(new_pin)
        assert title == 'New '+hdr_text

        # confirm, if not clearing the PIN
        if new_pin != CLR_PIN:
            title, words3 = enter_pin(new_pin)
            assert title == 'New '+hdr_text
            assert words2 == words3

        # saving/verifying can take tens of seconds.
        time.sleep(3) 
        for retries in range(10):
            if 'Login Now' in cap_menu():
                break
            time.sleep(2)
        else:
            raise pytest.fail("Menu didn't come back")

        return words2

    return doit

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_main_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin, verify_pin_set, get_secondary_login):
    goto_pin_options()

    try:
        pick_menu_item('Change Main PIN')
    except KeyError:
        # secondary login, for example
        assert get_secondary_login()
        raise pytest.skip('cant change main from secondary')

    change_pin(DEF_PIN, new_pin, 'Main PIN')
    verify_pin_set(new_pin)

    pick_menu_item('Change Main PIN')
    change_pin(new_pin, DEF_PIN, 'Main PIN')
    verify_pin_set(DEF_PIN)

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_duress_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin, get_duress_secret):
    goto_pin_options()

    pick_menu_item('Duress PIN')
    change_pin(None, new_pin, 'Duress PIN')

    # duress secret should be complex
    d_secret = get_duress_secret(new_pin)
    assert len(set(d_secret)) > 20
    assert d_secret[0] == 0x01, "not xprv?"

    # changing PIN shouldn't change secret
    pick_menu_item('Duress PIN')
    change_pin(new_pin, '123-123', 'Duress PIN')
    rb = get_duress_secret('123-123')
    assert rb == d_secret

    pick_menu_item('Duress PIN')
    change_pin('123-123', CLR_PIN, 'Duress PIN')

    # clearing PIN should clear secret
    zz = get_duress_secret('')
    assert zz == b'\0'*72

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_secondary_pin(is_mark3, goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin, verify_pin_set, get_secondary_login):

    if get_secondary_login():
        raise pytest.skip('not intended for use under secondary login')

    goto_pin_options()

    if is_mark3:
        raise pytest.skip('mark3 doesnt support secondary wallet')

    pick_menu_item('Second Wallet')
    change_pin(None, new_pin, 'Second PIN')
    verify_pin_set(new_pin, secondary=1)

    pick_menu_item('Second Wallet')
    change_pin(new_pin, CLR_PIN, 'Second PIN')
    verify_pin_set('', secondary=1)

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_secondary_from_secondary_pin(is_mark3, goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin, verify_pin_set, get_secondary_login):

    # when logged into secondary wallet, you can't clear PIN, and we use a 23-23 as value
    if not get_secondary_login():
        raise pytest.skip('intended for use under secondary login')
    if is_mark3:
        raise pytest.skip('mark3 doesnt support secondary wallet')

    goto_pin_options()

    ASSUME_PIN = '23-23'

    pick_menu_item('Second Wallet')
    change_pin(ASSUME_PIN, new_pin, 'Second PIN')
    verify_pin_set(new_pin)

    pick_menu_item('Second Wallet')
    change_pin(new_pin, ASSUME_PIN, 'Second PIN')
    verify_pin_set(ASSUME_PIN)

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_brickme_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin, verify_pin_set, get_secondary_login):

    goto_pin_options()

    try:
        pick_menu_item('Brick Me PIN')
    except KeyError:
        # secondary login, for example
        assert get_secondary_login()
        raise pytest.skip('cant do brickme in this mode')

    change_pin(None, new_pin, 'Brickme PIN')
    verify_pin_set(new_pin, brickme=1)

    pick_menu_item('Brick Me PIN')
    change_pin(new_pin, CLR_PIN, 'Brickme PIN')
    verify_pin_set('', brickme=1)

# EOF
