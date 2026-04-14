# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Base for some pytest fixtures.
# Allows testers to escape pytest scoping.
# Fixtures in conftest.py are (mostly) session/module scoped
# as multiple tests are intended to be run on single simulator instance.
# Below functions are injected with proper scoped `device` in conftest.py
# using funtools.partial.
#
import time, re
from charcodes import *
from ckcc_protocol.client import CCProtocolPacker

def _sim_exec(device, cmd, binary=False, timeout=60000):
    s = device.send_recv(b'EXEC' + cmd.encode('utf-8'), timeout=timeout, encrypt=False)
    if binary: return s
    # print(f'sim_exec: {cmd!r} -> {s!r}')
    return s.decode('utf-8') if not isinstance(s, str) else s

def _sim_eval(device, cmd, binary=False, timeout=None):
    s = device.send_recv(b'EVAL' + cmd.encode('utf-8'), timeout=timeout)
    if binary: return s
    return s.decode('utf-8')

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

def _press_cancel(device, is_Q, timeout=None):
    btn = KEY_CANCEL if is_Q else "x"
    _need_keypress(device, btn, timeout=timeout)

def _dev_hw_label(device):
    # gets a short string that labels product: mk4 / q1, etc
    v = device.send_recv(CCProtocolPacker.version()).split()
    return v[4]

def _pick_menu_item(device, is_Q, text):
    print(f"PICK menu item: {text}")
    WRAP_IF_OVER = 10  # see ../shared/menu.py

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


def _pass_word_quiz(device, is_Q, words, prefix='', preload=None):
    if not preload:
        _press_select(device, is_Q)
        time.sleep(.01)

    count = 0
    last_title = None
    while 1:
        title, body = preload or _cap_story(device)
        preload = None

        if not title.startswith('Word ' + prefix): break
        assert title.endswith(' is?')
        assert not last_title or last_title != title, "gave wrong ans?"

        wn = int(title.split()[1][len(prefix):])
        assert 1 <= wn <= len(words)
        wn -= 1

        ans = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
        assert len(ans) == 3

        correct = ans.index(words[wn])
        assert 0 <= correct < 3

        # print("Pick %d: %s" % (correct, ans[correct]))

        _need_keypress(device, chr(49 + correct))
        time.sleep(.1)
        count += 1

        last_title = title

    return count, title, body


def _do_keypresses(device, value):
    for ch in value:
        _need_keypress(device, ch)

def _word_menu_entry(device, is_Q, words, has_checksum=True, q_accept=True):
    if is_Q:
        # easier for us on Q, but have to anticipate the autocomplete
        for n, w in enumerate(words, start=1):
            _do_keypresses(device, w[0:2])
            time.sleep(0.1)
            if 'Next key' in _cap_screen(device):
                _do_keypresses(device, w[2])
                time.sleep(.01)

            if 'Next key' in _cap_screen(device):
                if len(w) > 3:
                    _do_keypresses(device, w[3])
                else:
                    _do_keypresses(device, KEY_DOWN)
                time.sleep(.01)

            pat = rf'{n}:\s?{w}'
            for x in range(10):
                if re.search(pat, _cap_screen(device)):
                    break
                time.sleep(0.02)
            else:
                raise RuntimeError('timeout')

        if len(words) == 23:
            _do_keypresses(device, KEY_DOWN)
            time.sleep(.03)
            cap_scr = _cap_screen(device)
            while 'Next key' in cap_scr:
                target = cap_scr.split("\n")[-1].replace("Next key: ", "")
                # picks first choice!?
                _do_keypresses(device, target[0])
                time.sleep(.03)
                cap_scr = _cap_screen(device)
        else:
            cap_scr = _cap_screen(device)

        if has_checksum:
            assert 'Valid words' in cap_scr
        else:
            assert 'Press ENTER if all done' in cap_scr

        if q_accept:
            _do_keypresses(device, '\r')
        return

    # do the massive drilling-down to pick a specific pass phrase
    assert len(words) in {1, 12, 18, 23, 24}

    for word in words:
        while 1:
            menu = _cap_menu(device)
            which = None
            for m in menu:
                if '-' not in m:
                    if m == word:
                        which = m
                        break
                else:
                    assert m[-1] == '-'
                    if m == word[0:len(m)-1]+'-':
                        which = m
                        break

            assert which, "cant find: " + word

            _pick_menu_item(device, is_Q, which)
            if '-' not in which:
                break

# EOF
