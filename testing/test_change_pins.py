# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# UX and interactions related to Settings > Pin Options
#
# - altho this can pass on the simulator, it's much more interesting to test with "bare metal"
# - need this to recover:
#       from main import pa; pa.change(is_duress=1, new_pin=b'', old_pin=b'77-77')
# - same tests are needed in three modes: normal login, secondary PIN used for login, and
#   duress PIN used for login.
# - my convention for known PINS:
#       12-12       main wallet
#       23-23       secondary wallet (mk1/2)
#       33-33       main duress wallet
#       66-66       brickme
#
import pytest, time
from charcodes import KEY_RIGHT, KEY_ENTER


CLR_PIN = '999999-999999'

@pytest.fixture(scope='session')
def under_duress(request):
    # add flag: --duress to commandline to indicate this mode
    return request.config.getoption('duress') 


@pytest.fixture
def verify_pin_set(sim_exec):
    def doit(pin, secondary=False, duress=False, brickme=False):
        # check the SE holds the indicated PIN code
        kws = ''
        if secondary:
            kws += ", is_secondary=1"
        if duress:      # not used
            kws += ", is_duress=1"
        if brickme:
            kws += ", is_brickme=1"
        rv = sim_exec(f'from pincodes import pa; RV.write(repr(pa.change(new_pin=b"{pin}", old_pin=b"{pin}" {kws})))')
        if rv != 'None':
            raise RuntimeError(rv)

    return doit


@pytest.fixture
def goto_pin_options(pick_menu_item, goto_home):
    def doit():
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Login Settings')

    return doit

@pytest.fixture
def my_enter_pin(cap_screen, need_keypress, is_q1, press_right, press_select):
    def doit(pin):
        time.sleep(.01)  # required?
        scr = cap_screen().split('\n')
        title = scr[1]

        if is_q1:
            assert scr[2] == 'Enter first part of PIN'
            prefix, suffix = pin.split("-")
            for n in prefix:
                need_keypress(n)
                time.sleep(.1)

            # move second part
            press_right()
            time.sleep(.1)
            scr = cap_screen().split('\n')

            assert scr[2] == 'Enter second part of PIN'
            words = scr[-3].split("  ")  # split on 2 spaces
            assert len(words) == 2

            for n in suffix:
                need_keypress(n)
                time.sleep(.1)

            press_select()

        else:
            assert scr[2] == 'Enter PIN Prefix'
            for ch in pin:
                if ch != '-':
                    time.sleep(.05)      # required?
                    need_keypress(ch)
                    time.sleep(.05)      # required?
                    continue

                if ch == '-':
                    press_select()
                    time.sleep(.1)      # required

                    scr = cap_screen().split('\n')

                    assert ('Recognize these?' in scr) or ('Write these down:' in scr)
                    words = scr[2:4]
                    press_select()

                    time.sleep(.1)      # required
                    scr = cap_screen().split('\n')
                    assert scr[-1] == 'Enter rest of PIN'

            press_select()

        time.sleep(0.1)
        return title, words

    return doit


@pytest.fixture
def change_pin(cap_screen, cap_story, cap_menu, press_select, my_enter_pin, press_cancel):
    def doit(old_pin, new_pin, hdr_text, expect_fail=None):
        # use standard menus and UX to change a PIN
        title, story = cap_story()
        assert title == hdr_text
        assert "changing the main PIN used to unlock your Coldcard" in story
        assert "ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN!" in story
        assert "Write it down" in story
        press_select()
        time.sleep(0.01)      # required

        assert max(len(i) for i in new_pin.split('-')) <= 6
        assert 2 <= min(len(i) for i in new_pin.split('-'))

        # give old pin, if there was one
        if old_pin != None:
            title, words = my_enter_pin(old_pin)
            assert title == 'Old '+hdr_text

        title, words2 = my_enter_pin(new_pin)
        if old_pin == None and title == 'Old '+hdr_text:
            raise ValueError("PIN was set, but we though it wouldnt be")
        assert title == 'New '+hdr_text

        # confirm, if not clearing the PIN
        if new_pin != CLR_PIN:
            title, words3 = my_enter_pin(new_pin)
            assert title == 'New '+hdr_text
            assert words2 == words3

        if expect_fail:
            title, story = cap_story()
            assert title == 'Try Again'
            assert expect_fail in story
            press_cancel()
            return

        # saving/verifying can take tens of seconds.
        time.sleep(5) 
        for retries in range(10):
            try:
                if 'Test Login Now' in cap_menu():
                    break
            except:
                # USB not ready when busy in bootloader code
                pass
            time.sleep(1)
        else:
            raise pytest.fail("Menu didn't come back")

        return words2

    return doit

@pytest.mark.parametrize('new_pin', ['77-77', '123456-654321', '79-654321', '123456-12'])
def test_main_pin(goto_pin_options, pick_menu_item, cap_story, cap_screen,
                  change_pin, new_pin, verify_pin_set, under_duress):
    goto_pin_options()
    pick_menu_item("Change Main PIN")
    DEF_PIN = '12-12' if not under_duress else '33-33'

    change_pin(DEF_PIN, new_pin, 'Main PIN')
    verify_pin_set(new_pin)

    pick_menu_item('Change Main PIN')
    change_pin(new_pin, DEF_PIN, 'Main PIN')
    verify_pin_set(DEF_PIN)

# EOF
