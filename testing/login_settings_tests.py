# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# to run it on both Mk4 and Q:
#   python login_settings_tests.py; sleep 10; python --Q login_settings_tests.py
#
import pytest, time, pdb
from charcodes import KEY_ENTER, KEY_DOWN, KEY_UP, KEY_HOME, KEY_DELETE
from ckcc_protocol.client import ColdcardDevice, CCProtocolPacker, CKCC_SIMULATOR_PATH
from run_sim_tests import ColdcardSimulator, clean_sim_data

# Our own test fixtures are (mostly) session/module scoped
# as multiple tests are intended to be run on single simulator instance
# hence all this duplication below
# ===
def _sim_exec(device, cmd):
    s = device.send_recv(b'EXEC' + cmd.encode('utf-8'), timeout=60000, encrypt=False)
    return s.decode('utf-8') if not isinstance(s, str) else s

def _cap_story(device):
    cmd = "RV.write('\0'.join(sim_display.story or []))"
    rv = _sim_exec(device, cmd)
    return rv.split('\0', 1) if rv else ('','')

def _cap_menu(device):
    rv = _sim_exec(device, 'from ux import the_ux; RV.write(repr('
                           '[i.label for i in the_ux.top_of_stack().items]))')
    if 'Traceback' in rv:
        raise RuntimeError(rv)
    return eval(rv)

def _cap_screen(device):
    return _sim_exec(device, 'RV.write(sim_display.full_contents)')

def _need_keypress(device, k, timeout=None):
    device.send_recv(CCProtocolPacker.sim_keypress(k.encode('ascii')), timeout=timeout)

def _press_select(device, is_Q, timeout=None):
    _need_keypress(device, KEY_ENTER if is_Q else "y", timeout=timeout)

def _pick_menu_item(device, text, is_Q):
    _need_keypress(device, KEY_HOME if is_Q else "0")
    m = _cap_menu(device)
    if text not in m:
        raise KeyError(text, "%r not in menu: %r" % (text, m))

    target = [mi for mi in m if "⋯" not in mi]
    if target:
        assert target[0][0:33].strip() in _cap_screen(device), 'not in menu mode'
    else:
        print("⋯ in all menu items - not sure about free - but continue")

    m_pos = m.index(text)

    if len(m) > 16 and m_pos > (len(m)//2):
        # use wrap around, work up from bottom
        for n in range(len(m) - m_pos):
            _need_keypress(device, KEY_UP)
            time.sleep(.01)      # required

        _press_select(device, is_Q)
        time.sleep(.01)      # required
    else:
        # go down
        for n in range(m_pos):
            _need_keypress(device, KEY_DOWN)
            time.sleep(.01)      # required

        _press_select(device, is_Q)
        time.sleep(.01)      # required

def _mk4_enter_complex(device, target):
    symbols = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

    for pos, d in enumerate(target):
        time.sleep(.01)  # required
        if d.isalpha():
            if pos != 0:  # A is already default first
                _need_keypress(device, '1')

            if d.islower():
                time.sleep(.01)  # required
                _need_keypress(device, '1')

            cnt = ord(d.lower()) - ord('a')

        elif d.isdigit():
            _need_keypress(device, '2')
            if d == '0':
                time.sleep(.01)  # required
                _need_keypress(device, '8')
                cnt = 0
            else:
                cnt = ord(d) - ord('1')
        else:
            assert d in symbols
            if pos == 0:
                _need_keypress(device, '3')

            cnt = symbols.find(d)

        for i in range(cnt):
            time.sleep(.01)  # required
            _need_keypress(device, '5')

        if pos != len(target) - 1:
            time.sleep(.01)  # required
            _need_keypress(device, '9')
# ===

def _set_nickname(device, nickname, is_Q):
    # needs to be already in Login Settings
    _pick_menu_item(device, "Set Nickname", is_Q)
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "give this Coldcard nickname and it will be shown before login"
    _press_select(device, is_Q)
    # enter nick
    if is_Q:
        for ch in nickname:
            _need_keypress(device, ch)
            time.sleep(.05)
    else:
        _mk4_enter_complex(device, nickname)

    _press_select(device, is_Q)
    time.sleep(1)

def _set_scramble_pin_entry(device, is_Q):
    # needs to be already in Login Settings
    _pick_menu_item(device, "Scramble Keys", is_Q)
    time.sleep(.1)
    _, story = _cap_story(device)
    assert "randomize the order of the key" in story
    assert "cameras and shoulder-surfers are defeated" in story
    _press_select(device, is_Q)
    time.sleep(.1)
    # Choose scrambled
    _pick_menu_item(device, "Scramble Keys", is_Q)

def _set_login_countdown(device, val, is_Q):
    # needs to be in Login Settings already
    _pick_menu_item(device, "Login Countdown", is_Q)
    _pick_menu_item(device, val, is_Q)

def _set_kill_key(device, val, is_Q):
    _pick_menu_item(device, "Kill Key", is_Q)
    time.sleep(.1)
    _, story = _cap_story(device)
    if is_Q:
        assert "press this key at any point during login" in story
    else:
        assert "press this key while the anti-phishing words are shown during login" in story
        assert ("Best if this does not match the first number"
                " of the second half of your PIN.") in story

    assert "your seed phrase will be immediately wiped" in story
    _press_select(device, is_Q)
    _pick_menu_item(device, val, is_Q)

def _remap_pin(pin, key_map):
    # remap pin
    remap_pin = ""
    for ch in pin:
        if ch.isdigit():
            remap_pin += key_map[ch]
        else:
            remap_pin += ch
    return remap_pin

def _login(device, pin, is_Q, scrambled=False, mk4_kbtn=None):
    orig_pin = pin
    scr = _cap_screen(device)
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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

    _pick_menu_item(device, "Settings", is_Q)
    _pick_menu_item(device, "Login Settings", is_Q)
    time.sleep(.1)
    _set_nickname(device, nick, is_Q)
    time.sleep(1)
    sim.stop()  # power off
    # new simulator instance - but should get us directly to the last used settings
    sim = ColdcardSimulator(args= ["--q1" if is_Q else "", "--early-usb"])

    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

    _pick_menu_item(device, "Settings", is_Q)
    _pick_menu_item(device, "Login Settings", is_Q)
    _set_scramble_pin_entry(device, is_Q)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _login(device, "22-22", is_Q, scrambled=True)
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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

    _pick_menu_item(device, "Settings", is_Q)
    _pick_menu_item(device, "Login Settings", is_Q)
    _set_login_countdown(device, lcdwn, is_Q)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    secs = int(lcdwn.strip().split()[0])
    _login(device, "22-22", is_Q)
    time.sleep(.15)
    scr = " ".join(_cap_screen(device).split("\n"))
    assert "Login countdown in effect" in scr
    assert "Must wait:" in scr
    assert f"{secs}s" in scr
    time.sleep(secs + 1)
    _login(device, "22-22", is_Q)
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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

    _pick_menu_item(device, "Settings", is_Q)
    _pick_menu_item(device, "Login Settings", is_Q)
    _set_kill_key(device, kbtn, is_Q)

    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args= ["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
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
    _login(device, "22-22", is_Q)
    time.sleep(.5)
    # confirm PIN
    _login(device, "22-22", is_Q)
    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["-l", "--q1" if is_Q else "", "--early-usb", "--pin", "22-22"])
    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _login(device, "22-22", is_Q)
    time.sleep(3)
    m = _cap_menu(device)
    assert "New Seed Words" in m
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
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _pick_menu_item(device, "Settings", is_Q)
    _pick_menu_item(device, "Login Settings", is_Q)

    if nick:
        _set_nickname(device, nick, is_Q)
        time.sleep(.5)
    if randomize:
        _set_scramble_pin_entry(device, is_Q)
        time.sleep(.5)
    if kill_btn:
        _set_kill_key(device, kill_btn, is_Q)
        time.sleep(.5)
    if login_ctdwn:
        _set_login_countdown(device, login_ctdwn, is_Q)
        time.sleep(.5)

    # at this point all is set - reboot and test
    time.sleep(1)
    sim.stop()  # power off
    sim = ColdcardSimulator(args=["--q1" if is_Q else "", "--pin", "22-22", "--early-usb"])
    sim.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)

    if nick:
        scr = _cap_screen(device)
        assert nick in scr
        if kill_btn and is_Q:  # cannot use kbtn while nickname is show on Mk4
            # lets kill here while nickname is shown
            _need_keypress(device, kill_btn)

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
        with pytest.raises(Exception):
            _press_select(device, is_Q, timeout=1000)
        sim.stop()
        return  # done here

    was_killed = _login(device, "22-22", is_Q, scrambled=randomize,
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
            with pytest.raises(Exception):
                _press_select(device, is_Q, timeout=1000)
            sim.stop()
            return  # done here

        # second login after countdown is done
        was_killed = _login(device, "22-22", is_Q, scrambled=randomize,
                            mk4_kbtn=None if kill_when else kill_btn)
        if was_killed:
            sim.stop()
            return

    time.sleep(3)
    m = _cap_menu(device)
    assert "Ready To Sign" in m
    sim.stop()

# EOF
