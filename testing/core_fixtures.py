# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Base for some pytest fixtures.
# Allows testers to escape pytest scoping.
# Fixtures in conftest.py are (mostly) session/module scoped
# as multiple tests are intended to be run on single simulator instance.
# Below functions are injected with proper scoped `device` in conftest.py
# using funtools.partial.
#
import time
from charcodes import *
from ckcc_protocol.client import CCProtocolPacker

def _sim_exec(device, cmd, binary=False, timeout=60000):
    s = device.send_recv(b'EXEC' + cmd.encode('utf-8'), timeout=timeout, encrypt=False)
    if binary: return s
    # print(f'sim_exec: {cmd!r} -> {s!r}')
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
    btn = KEY_ENTER if is_Q else "y"
    _need_keypress(device, btn, timeout=timeout)

def _dev_hw_label(device):
    # gets a short string that labels product: mk4 / q1, etc
    v = device.send_recv(CCProtocolPacker.version()).split()
    return v[4]

def _pick_menu_item(device, is_Q, text):
    print(f"PICK menu item: {text}")
    WRAP_IF_OVER = 16  # see ../shared/menu.py .. this is larger of 10 or 16

    _need_keypress(device, KEY_HOME if is_Q else "0")
    m = _cap_menu(device)
    if text not in m:
        raise KeyError(text, "%r not in menu: %r" % (text, m))

    if is_Q:
        # double check we're looking at this menu, not stale data
        # added strip as cap_screen does not contain whitespaces
        # that are present in coundown chooser
        # find menu item that does not contain triple dot char
        target = [mi for mi in m if "⋯" not in mi]
        if target:
            assert target[0][0:33].strip() in _cap_screen(device), 'not in menu mode'
        else:
            print("⋯ in all menu items - not sure about free - but continue")

    m_pos = m.index(text)

    if len(m) > WRAP_IF_OVER and m_pos > (len(m)//2):
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

def _enter_complex(device, is_Q, target, apply=False, b39pass=True):
    if b39pass:
        try:
            _pick_menu_item(device, is_Q, 'Edit Phrase')
        except:
            assert is_Q

    if is_Q:
        for ch in target:
            _need_keypress(device, ch)
            time.sleep(.1)
        _press_select(device, is_Q)
        return

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

    time.sleep(0.01)  # required
    _press_select(device, is_Q)

    if apply:
        _pick_menu_item(device, is_Q, "APPLY")

# EOF
