# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# to run it on both Mk4 and Q:
#   pytest login_settings_tests.py; sleep 10; pytest --Q login_settings_tests.py
#
# or use test runner:
#   python run_sim_tests --login
#
#   python run_sim_tests --q1 --login -k countdown --pdb
#
import pytest, time, pdb
from core_fixtures import _pick_menu_item, _cap_menu, _cap_story, _cap_screen
from core_fixtures import _need_keypress, _enter_complex, _press_select, _press_cancel
from ckcc_protocol.client import ColdcardDevice
from run_sim_tests import ColdcardSimulator, clean_sim_data


def _set_nickname(device, is_Q, nickname):
    # needs to be already in Login Settings
    _pick_menu_item(device, is_Q, "Set Nickname")
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "give this Coldcard nickname and it will be shown before login"
    _press_select(device, is_Q)
    # enter nick
    _enter_complex(device, is_Q, nickname, b39pass=False)
    time.sleep(1)

def _set_scramble_pin_entry(device, is_Q):
    # needs to be already in Login Settings
    _pick_menu_item(device, is_Q, "Scramble Keys")
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "randomize the order of the key" in story
    assert "cameras and shoulder-surfers are defeated" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    # Choose scrambled
    _pick_menu_item(device, is_Q, "Scramble Keys")

def _set_login_countdown(device, is_Q, val):
    # needs to be in Login Settings already
    _pick_menu_item(device, is_Q, "Login Countdown")
    _pick_menu_item(device, is_Q, val)

def _set_kill_key(device, is_Q, val):
    _pick_menu_item(device, is_Q, "Kill Key")
    time.sleep(.1)
    _, story = _cap_story(device)
    if is_Q:
        assert "press this key at any point during login" in story
    else:
        assert "press this key while the anti- phishing words are shown during login" in story
        assert ("Best if this does not match the first number"
                " of the second half of your PIN.") in story

    assert "your seed phrase will be immediately wiped" in story
    _press_select(device, is_Q)
    _pick_menu_item(device, is_Q, val)

def _set_calculator_login(device):
    # needs to be already in Login Settings
    is_Q = True
    _pick_menu_item(device, is_Q, "Calculator Login")
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "Boots into calculator mode" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    # Choose scrambled
    _pick_menu_item(device, is_Q, "Calculator Login")

def _remap_pin(pin, key_map):
    # remap pin
    remap_pin = ""
    for ch in pin:
        if ch.isdigit():
            remap_pin += key_map[ch]
        else:
            remap_pin += ch
    return remap_pin

def _login(device, is_Q, pin, scrambled=False, mk4_kbtn=None, num_failed=None):
    orig_pin = pin
    time.sleep(.1)
    scr = _cap_screen(device)
    if num_failed:
        assert f"{num_failed} failures, {13-num_failed} tries left" in scr
    if is_Q:
        top = scr.split("\n")[0].split()
        is_scrambled = len(top) == 10
    else:
        top = scr.split()
        is_scrambled = len(top) == 13
        top = [i for i in top if i.isdigit()]

    assert scrambled == is_scrambled, "should have been looking at scrambled keys"

    if is_scrambled:
        order = [str(i) for i in range(1, 10)] + ["0"]
        key_map = dict(zip(top, order))
        pin = _remap_pin(pin, key_map)

    pre, suff = pin.split("-")
    for ch in pre:
        _need_keypress(device, ch)
    _press_select(device, is_Q)

    if not is_Q:
        # intermediate step in mk4 where anti-phishing words are shown
        # needs confirmation
        # mk4 randomizes twice - different mapping for prefix and for suffix
        # Q randomizes just once
        if mk4_kbtn:
            _need_keypress(device, mk4_kbtn)
            time.sleep(.5)
            # now we MUST be dead
            with pytest.raises(Exception):
                _press_select(device, is_Q, timeout=1000)
            return True

        _press_select(device, is_Q)  # confirm anti-phishing words
        time.sleep(1)
        if is_scrambled:
            scr = _cap_screen(device)
            top = scr.split()
            top = [i for i in top if i.isdigit()]
            suff = _remap_pin(orig_pin, dict(zip(top, order))).split("-")[1]

    for ch in suff:
        _need_keypress(device, ch)
    _press_select(device, is_Q)


@pytest.mark.parametrize("nick", [100*"$", "$", 10*"20"+ "  "+"8080"+ " " + "XX"+ "    "+ "YY"])
def test_set_nickname(nick, request):
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    time.sleep(.1)
    _set_nickname(device, is_Q, nick)
    time.sleep(1)
    sim.stop()  # power off
    # new simulator instance - but should get us directly to the last used settings
    sim = ColdcardSimulator(args= ["--q1" if is_Q else "", "--early-usb"])

    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    scr = _cap_screen(device)
    target = "".join(scr.strip().split("\n"))
    if is_Q:
        nick = nick.replace(" " * 4, "")
    else:
        nick = nick.replace(" " * 4, " " * 2)  # max two spaces in sequence (Mk4)
    assert nick == target
    sim.stop()


def test_randomize_pin_keys(request):
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _set_scramble_pin_entry(device, is_Q)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _login(device, is_Q, "22-22", scrambled=True)
    time.sleep(3)
    m = _cap_menu(device)
    assert "Ready To Sign" in m
    sim.stop()

@pytest.mark.parametrize("lcdwn", [" 5 minutes", "15 minutes"])
def test_login_countdown(lcdwn, request):
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _set_login_countdown(device, is_Q, lcdwn)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    secs = int(lcdwn.strip().split()[0])
    _login(device, is_Q, "22-22")
    time.sleep(.15)
    scr = " ".join(_cap_screen(device).split("\n"))
    assert "Login countdown in effect" in scr
    assert "Must wait:" in scr
    assert f"{secs}s" in scr
    time.sleep(secs + 1)
    _login(device, is_Q, "22-22")
    time.sleep(3)
    m = _cap_menu(device)
    assert "Ready To Sign" in m
    sim.stop()

@pytest.mark.parametrize("kbtn", [("A", "1"), ("/", "9")])
@pytest.mark.parametrize("when", [True, False])
def test_kill_key(kbtn, when, request):
    is_Q = request.config.getoption('--Q')
    kbtn = kbtn[0] if is_Q else kbtn[1]
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _set_kill_key(device, is_Q, kbtn)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args= ["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    if is_Q:
        possible_kbtn = [chr(65 + i) for i in range(26)] + [i for i in '\',./']
    else:
        possible_kbtn = [str(d) for d in range(10)]

    possible_kbtn.remove(kbtn)  # remove actual kbtn

    if when and is_Q:
        # assert that no other key is kbtn
        for btn in possible_kbtn:
            _need_keypress(device, btn)
        # below would raise if we are no longer alive
        _need_keypress(device, possible_kbtn[0], timeout=1000)
        # kill it before inserting PIN prefix
        _need_keypress(device, kbtn)
    else:
        # insert PIN prefix
        _need_keypress(device, "2")
        _need_keypress(device, "2")
        _press_select(device, is_Q)
        time.sleep(1)

        # assert that no other key is kbtn
        for btn in possible_kbtn:
            _need_keypress(device, btn)

        # below would raise if we are no longer alive
        _need_keypress(device, possible_kbtn[0], timeout=1000)
        # kill it now
        _need_keypress(device, kbtn)

    time.sleep(.5)
    # now we MUST be dead
    with pytest.raises(Exception):
        _press_select(device, is_Q, timeout=1000)
    sim.stop()


def test_terms_ok(request):
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--early-usb", "-w", "--q1" if is_Q else ""])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    time.sleep(.1)

    _, story = _cap_story(device)
    assert "By using this product, you are accepting our Terms of Sale and Use" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "new Coldcard should have arrived SEALED in a bag" in story
    assert "look for any signs of tampering" in story
    assert "Take pictures and contact support@coinkite" in story
    _press_select(device, is_Q)
    time.sleep(2)
    # choose new PIN
    _press_select(device, is_Q)
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "Pick the main wallet's PIN code" in story
    assert "two parts" in story
    assert "must be between 2 to 6 digits long" in story
    assert "THERE IS ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN!" in story
    assert "Write it down." in story
    _press_select(device, is_Q)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "WARNING" in title
    assert "There is ABSOLUTELY NO WAY to 'reset the PIN' or 'factory reset' the Coldcard" in story
    assert "Press (6)" in story
    _need_keypress(device, "6")
    time.sleep(.2)
    # 1st PIN entry
    _login(device, is_Q, "22-22")
    time.sleep(.5)
    # confirm PIN
    _login(device, is_Q, "22-22")
    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["-l", "--q1" if is_Q else "", "--early-usb", "--pin", "22-22"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _login(device, is_Q, "22-22")
    time.sleep(3)
    m = _cap_menu(device)
    assert "New Seed Words" in m
    sim.stop()


@pytest.mark.parametrize("brick", [True, False])
def test_wrong_pin_input(request, brick):
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--early-usb", "--q1" if is_Q else "", "--pin", "22-22"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    time.sleep(.1)
    num_attmeptss = 13
    for ii, i in enumerate(range(31, 43), start=1):
        pin = f"{i}-{i}"
        scr_num_failed = (ii - 1) if ii > 1 else None
        _login(device, is_Q, pin, num_failed=scr_num_failed)
        time.sleep(.5)
        title, story = _cap_story(device)
        if ii > 4:
            assert title == "WARNING"
            assert pin in story  # showing to user to double-check his input
            assert "BRICKS ITSELF FOREVER" in story
            assert f"{num_attmeptss - ii + 1} attempts left" in story
            _press_select(device, is_Q)
            time.sleep(.1)
            title, story = _cap_story(device)

        assert "WRONG PIN" in title
        assert f"{num_attmeptss - ii} attempts left" in story
        assert f"{ii} failure" in story
        _press_select(device, is_Q)
        time.sleep(.1)

    if brick:
        # one more wrong pin
        _login(device, is_Q, "91-11", num_failed=12)
        time.sleep(.5)
        title, story = _cap_story(device)
        assert "WARNING" == title
        _press_select(device, is_Q)
        time.sleep(.1)
        title, story = _cap_story(device)
        assert title == "I Am Brick!"
        assert "After 13 failed PIN attempts this Coldcard is locked forever" in story
        assert "no way to reset or recover the secure element" in story
        assert "forever inaccessible" in story
        assert "Restore your seed words onto a new Coldcard" in story
    else:
        _login(device, is_Q, "22-22", num_failed=12)
        time.sleep(.5)
        title, story = _cap_story(device)
        assert "WARNING" == title
        _press_select(device, is_Q)
        time.sleep(.1)
        m = _cap_menu(device)
        assert "Ready To Sign" in m

    sim.stop()


@pytest.mark.parametrize("nick", [None, "In trust we trust NOT"])
@pytest.mark.parametrize("randomize", [False, True])
@pytest.mark.parametrize("login_ctdwn", [None, " 5 minutes", "15 minutes"])
@pytest.mark.parametrize("kill_btn", [None, ("Z", "8"), ("/", "7")])
@pytest.mark.parametrize("kill_when", [True, False])
def test_login_integration(request, nick, randomize, login_ctdwn, kill_btn, kill_when):
    is_Q = request.config.getoption('--Q')
    if kill_btn:
        kill_btn = kill_btn[0] if is_Q else kill_btn[1]
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")

    if nick:
        _set_nickname(device, is_Q, nick)
        time.sleep(.5)
    if randomize:
        _set_scramble_pin_entry(device, is_Q)
        time.sleep(.5)
    if kill_btn:
        _set_kill_key(device, is_Q, kill_btn)
        time.sleep(.5)
    if login_ctdwn:
        _set_login_countdown(device, is_Q, login_ctdwn)
        time.sleep(.5)

    # at this point all is set - reboot and test
    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    if nick:
        scr = _cap_screen(device)
        assert nick in scr
        if kill_btn and is_Q:  # cannot use kbtn while nickname is show on Mk4
            # lets kill here while nickname is shown
            _need_keypress(device, kill_btn)
            time.sleep(.1)
            # now we MUST be dead
            with pytest.raises(Exception):
                _press_select(device, is_Q, timeout=1000)
            sim.stop()
            return  # done here
        else:
            # move on, nick there, continue to login
            _press_select(device, is_Q)

    if kill_btn and kill_when and is_Q:
        # kill it before even trying to insert any PIN (not possible on Mk4)
        _need_keypress(device, kill_btn)
        time.sleep(.1)
        with pytest.raises(Exception):
            _press_select(device, is_Q, timeout=1000)
        sim.stop()
        return  # done here

    was_killed = _login(device, is_Q, "22-22", scrambled=randomize,
                        mk4_kbtn=kill_btn if kill_when else None)
    if was_killed:
        sim.stop()
        return

    if login_ctdwn:
        time.sleep(.1)
        scr = _cap_screen(device).replace("\n", " ")  # fix for Mk4
        secs = int(login_ctdwn.strip().split()[0])
        assert "Login countdown in effect" in scr
        assert "Must wait:" in scr
        assert f"{secs}s" in scr
        time.sleep(secs + 1)
        if kill_btn and not kill_when and is_Q:
            _need_keypress(device, kill_btn)
            time.sleep(.1)
            with pytest.raises(Exception):
                _press_select(device, is_Q, timeout=1000)
            sim.stop()
            return  # done here

        # second login after countdown is done
        was_killed = _login(device, is_Q, "22-22", scrambled=randomize,
                            mk4_kbtn=None if kill_when else kill_btn)
        if was_killed:
            sim.stop()
            return

    time.sleep(3)
    m = _cap_menu(device)
    assert "Ready To Sign" in m
    sim.stop()

def test_calc_login(request):
    is_Q = request.config.getoption('--Q')
    if not is_Q: raise pytest.skip("Q only")
    
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _set_calculator_login(device)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    scr = _cap_screen(device)
    assert 'ECC Calculator' in scr

    def entry(cmd, delay=.5):
        _enter_complex(device, True, cmd, b39pass=False)
        time.sleep(delay)
        return _cap_screen(device)

    scr = entry('45*22/55')
    assert '>> 45*22/55' in scr
    assert '18.0' in scr

    for pfl in range(2,7):
        entry('cls')
        prefix = ''.join(chr(49 + i) for i in range(pfl)) + '-'
        scr = entry(prefix)
        assert f'>> {prefix}' in scr
        assert "('" in scr

    entry('cls')
    scr = entry("123456-123456")
    assert '# 11 tries remain' in scr

    scr = entry("00-123456")
    assert '# 10 tries remain' in scr

    entry("22-22")
    # no feedback just does login

    time.sleep(3)
    m = _cap_menu(device)

    assert "Ready To Sign" in m
    sim.stop()

@pytest.mark.parametrize("word_check", [True, False])
@pytest.mark.parametrize("randomize", [True, False])
def test_sssp_bypass_pin(request, word_check, randomize):
    main_pin = "22-22"
    bypass_pin = "111-111"
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    if randomize:
        _pick_menu_item(device, is_Q, "Settings")
        _pick_menu_item(device, is_Q, "Login Settings")
        _set_scramble_pin_entry(device, is_Q)
        time.sleep(1)

        for _ in range(2):
            _press_cancel(device, is_Q)

        time.sleep(.1)

    _pick_menu_item(device, is_Q, "Advanced/Tools")
    _pick_menu_item(device, is_Q, "Spending Policy")
    _pick_menu_item(device, is_Q, "Single-Signer")
    _press_select(device, is_Q)  # confirm story
    # now create bypass PIN
    # 1st entry
    _login(device, is_Q, bypass_pin)
    # 2nd confirmation entry
    _login(device, is_Q, bypass_pin)

    if word_check:
        _pick_menu_item(device, is_Q, "Word Check")
        title, story = _cap_story(device)
        assert "Enable?" in story
        assert "must provide the first and last seed words" in story
        _press_select(device, is_Q)

    time.sleep(2)  # needed here to actually save to settings
    sim.stop()

    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", main_pin, "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    # first login, but with main PIN, ends up in SSSP
    _login(device, is_Q, main_pin, scrambled=randomize)
    time.sleep(.1)
    menu = _cap_menu(device)
    assert "Settings" not in menu

    sim.stop()

    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", main_pin, "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    # now bypass PIN, normal operation
    time.sleep(.1)
    _login(device, is_Q, bypass_pin, scrambled=randomize)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Spending Policy Unlock" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    _login(device, is_Q, main_pin, scrambled=randomize)
    time.sleep(.1)

    if word_check:
        # first do incorrect words
        if is_Q:
            assert "First and Last Seed Word" in _cap_screen(device)
            # just because of auto-fil feature
            _enter_complex(device, is_Q, "wif")
            _enter_complex(device, is_Q, "kic")
        else:
            # this is not a text input field - but word nest menu
            # wife -> 3xUP, 3xDOWN, DOWN
            for _ in range(3):
                _need_keypress(device, "5")
            _press_select(device, is_Q)
            time.sleep(.1)

            for _ in range(3):
                _need_keypress(device, "8")
            _press_select(device, is_Q)
            time.sleep(.1)

            _need_keypress(device, "8")
            _press_select(device, is_Q)

            time.sleep(.1)
            # abandon -> 3xOK
            for _ in range(3):
                _press_select(device, is_Q)

        time.sleep(.1)
        title, story = _cap_story(device)
        assert "Sorry, those words are incorrect" in story
        _press_select(device, is_Q)
        time.sleep(.1)
        # now insert correct words
        if is_Q:
            # just because of auto-fil feature
            _enter_complex(device, is_Q, "wif")
            _enter_complex(device, is_Q, "clar")
        else:
            # wife -> 3xUP, 3xDOWN, DOWN
            for _ in range(3):
                _need_keypress(device, "5")
            _press_select(device, is_Q)
            time.sleep(.1)

            for _ in range(3):
                _need_keypress(device, "8")
            _press_select(device, is_Q)
            time.sleep(.1)

            _need_keypress(device, "8")
            _press_select(device, is_Q)

            # clarify 2xDOWN, 4xDOWN, 2xDOWN
            for _ in range(2):
                _need_keypress(device, "8")
            _press_select(device, is_Q)
            time.sleep(.1)

            for _ in range(4):
                _need_keypress(device, "8")
            _press_select(device, is_Q)
            time.sleep(.1)

            for _ in range(2):
                _need_keypress(device, "8")
            _press_select(device, is_Q)
            time.sleep(.1)

    menu = _cap_menu(device)
    assert "Settings" in menu  # not in SSSP

    sim.stop()


def test_sssp_login_countdown(request):
    bypass_pin = "236-156"
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1"] if is_Q else [])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _set_login_countdown(device, is_Q, " 5 minutes")

    time.sleep(.2)
    for _ in range(2):  # go back
        _press_cancel(device, is_Q)

    time.sleep(.1)
    _pick_menu_item(device, is_Q, "Advanced/Tools")
    _pick_menu_item(device, is_Q, "Spending Policy")
    _pick_menu_item(device, is_Q, "Single-Signer")
    _press_select(device, is_Q)  # confirm story
    # now create bypass PIN
    # 1st entry
    time.sleep(.1)
    _login(device, is_Q, bypass_pin)
    # 2nd confirmation entry
    _login(device, is_Q, bypass_pin)

    time.sleep(2)
    sim.stop()  # power off

    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    secs = 5

    _login(device, is_Q, bypass_pin)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Spending Policy Unlock" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    _login(device, is_Q, "22-22")

    time.sleep(.15)
    scr = " ".join(_cap_screen(device).split("\n"))
    assert "Login countdown in effect" in scr
    assert "Must wait:" in scr
    assert f"{secs}s" in scr
    time.sleep(secs + 1)
    _login(device, is_Q, "22-22")
    time.sleep(3)
    m = _cap_menu(device)
    assert "Ready To Sign" in m
    sim.stop()


def test_sssp_trick_pins(request):
    # only testing countdown TP
    ct_pin = "89-89"
    bypass_pin = "15-16"
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _login(device, is_Q, "22-22")

    _pick_menu_item(device, is_Q, "Settings")
    _pick_menu_item(device, is_Q, "Login Settings")
    _pick_menu_item(device, is_Q, "Trick PINs")

    # now countdown TP
    _pick_menu_item(device, is_Q, "Add New Trick")
    time.sleep(.1)

    for ch in ct_pin[:2]:
        _need_keypress(device, ch)
        time.sleep(.1)
    _press_select(device, is_Q)

    if not is_Q:
        # anti-phishing words
        _press_select(device, is_Q)

    for ch in ct_pin[-2:]:
        _need_keypress(device, ch)
        time.sleep(.1)
    _press_select(device, is_Q)

    _pick_menu_item(device, is_Q, "Login Countdown")
    _press_select(device, is_Q)
    time.sleep(.1)

    _pick_menu_item(device, is_Q, "Just Countdown")
    for _ in range(2):
        _press_select(device, is_Q)
        time.sleep(.1)

    # adjust countdown to lowest possible value
    _pick_menu_item(device, is_Q, f'↳{ct_pin}')
    _pick_menu_item(device, is_Q, '↳Countdown')
    _need_keypress(device, "4")
    _pick_menu_item(device, is_Q, " 5 minutes")

    for _ in range(10):
        _press_cancel(device, is_Q)

    time.sleep(.1)
    _pick_menu_item(device, is_Q, "Advanced/Tools")
    _pick_menu_item(device, is_Q, "Spending Policy")
    _pick_menu_item(device, is_Q, "Single-Signer")
    _press_select(device, is_Q)  # confirm story
    # now create bypass PIN
    # 1st entry
    time.sleep(.1)
    _login(device, is_Q, bypass_pin)
    # 2nd confirmation entry
    _login(device, is_Q, bypass_pin)

    time.sleep(2)
    sim.stop()

    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)

    _login(device, is_Q, bypass_pin)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Spending Policy Unlock" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    # try to log in with countdown TP instead of main
    # send you directly into countdown
    _login(device, is_Q, ct_pin)
    time.sleep(.15)
    scr = " ".join(_cap_screen(device).split("\n"))
    assert "Login countdown in effect" in scr
    assert "Must wait:" in scr
    assert "5s" in scr
    time.sleep(6)

    sim.stop()

# EOF
