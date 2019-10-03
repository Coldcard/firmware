# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# UX and interactions related to Settings > Pin Options
#
import pytest, time, os
from helpers import xfp2str

DEF_PIN = '12-12'
CLR_PIN = '999999-999999'

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
                need_keypress(ch)
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
        title, story = cap_story()
        assert title == hdr_text
        assert ('will be changing the' in story) or (CLR_PIN in story)
        need_keypress('y')
        time.sleep(0.01)      # required

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
            if 'Change Main PIN' in cap_menu():
                break
            time.sleep(2)
        else:
            raise pytest.fail("Menu didn't come back")

        return words2

    return doit

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-65454321', '123456-12'])
def test_main_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin):
    goto_pin_options()

    pick_menu_item('Change Main PIN')
    change_pin(DEF_PIN, new_pin, 'Main PIN')

    pick_menu_item('Change Main PIN')
    change_pin(new_pin, DEF_PIN, 'Main PIN')

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-65454321', '123456-12'])
def test_duress_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin):
    goto_pin_options()
    pick_menu_item('Duress PIN')
    change_pin(None, new_pin, 'Duress PIN')

    pick_menu_item('Duress PIN')
    change_pin(new_pin, '123-123', 'Duress PIN')

    pick_menu_item('Duress PIN')
    change_pin('123-123', CLR_PIN, 'Duress PIN')

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-65454321', '123456-12'])
def test_secondary_pin(is_mark3, goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin):

    goto_pin_options()

    if is_mark3:
        raise pytest.skip('mark3 doesnt support secondary wallet')

    pick_menu_item('Second Wallet')
    change_pin(None, new_pin, 'Second PIN')

    pick_menu_item('Second Wallet')
    change_pin(new_pin, CLR_PIN, 'Second PIN')

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-65454321', '123456-12'])
def test_brickme_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen, need_keypress, change_pin, new_pin):

    goto_pin_options()

    pick_menu_item('Brick Me PIN')
    change_pin(None, new_pin, 'Brickme PIN')

    pick_menu_item('Brick Me PIN')
    change_pin(new_pin, CLR_PIN, 'Brickme PIN')

# EOF
