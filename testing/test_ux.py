# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, re, hashlib, shutil, functools, ndef
from binascii import b2a_hex
from helpers import xfp2str, prandom
from charcodes import KEY_QR, KEY_NFC, KEY_DELETE, KEY_ENTER, OUT_CTRL_ADDRESS
from constants import AF_CLASSIC, simulator_fixed_words, simulator_fixed_xfp
from mnemonic import Mnemonic
from bip32 import BIP32Node
from core_fixtures import _pass_word_quiz, _word_menu_entry

mnem = Mnemonic('english')
wordlist = mnem.wordlist

@pytest.fixture
def enable_hw_ux(pick_menu_item, cap_story, press_select, goto_home):
    def doit(way, disable=False):
        pick_menu_item("Settings")
        pick_menu_item("Hardware On/Off")
        if way == "vdisk":
            pick_menu_item("Virtual Disk")
            _, story = cap_story()
            if "emulate a virtual disk drive" in story:
                press_select()
            if disable:
                pick_menu_item("Default Off")
            else:
                pick_menu_item("Enable")
        elif way == "nfc":
            pick_menu_item("NFC Sharing")
            _, story = cap_story()
            if "(Near Field Communications)" in story:
                press_select()
            if disable:
                pick_menu_item("Default Off")
            else:
                pick_menu_item("Enable NFC")
        else:
            raise RuntimeError("TODO")

        goto_home()

    return doit

def test_get_secrets(get_secrets, master_xpub):
    v = get_secrets()

    assert 'xpub' in v
    assert v['xpub'] == master_xpub

def test_home_menu(cap_menu, cap_story, cap_screen, need_keypress, reset_seed_words,
                   press_select, press_cancel, press_down, is_q1):
    reset_seed_words()
    # get to top, force a redraw
    press_cancel()
    press_cancel()
    press_cancel()
    press_cancel()
    need_keypress('0')
    
    # check menu contents
    m = cap_menu()
    assert 'Ready To Sign' in m
    if not is_q1:
        assert 'Secure Logout' in m
    assert 'Address Explorer' in m
    assert 'Advanced/Tools' in m
    assert 'Settings' in m
    if len(m) == 7:
        assert 'Passphrase' in m
    else:
        assert len(m) == 6

    # check 4 lines of menu are shown right
    scr = cap_screen().rstrip()
    chk = '\n'.join(m)
    if is_q1:
        assert scr == chk
    else:
        # does not fit to single screen on mk4
        assert scr in chk
        # go down to the bottom
        for i in range(6):
            press_down()

        scr = cap_screen().rstrip()
        assert scr in chk

    # pick first item, expect a story
    need_keypress('0')
    press_select()

    time.sleep(.01)      # required

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert 'transactions' in body or 'Choose PSBT' in body, body
    
    press_cancel()

@pytest.fixture
def word_menu_entry(dev, cap_menu, pick_menu_item, is_q1, do_keypresses, cap_screen):
    f = functools.partial(_word_menu_entry, dev, is_q1)
    return f

@pytest.fixture
def pass_word_quiz(dev, need_keypress, cap_story, press_select, is_q1):
    f = functools.partial(_pass_word_quiz, dev, is_q1)
    return f


@pytest.mark.qrcode
@pytest.mark.parametrize('seed_words, xfp', [
    ( 'abandon ' * 11 + 'about', 0x0adac573),
    ( 'abandon ' * 17 + 'agent', 0xc38a8be0),
    ( 'abandon ' * 23 + 'art', 0x24d73654 ),
    ( simulator_fixed_words, simulator_fixed_xfp),
    ])
@pytest.mark.parametrize("way", ["input", "qr", "seedqr"])
def test_import_seed(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, is_q1,
                     cap_menu, word_menu_entry, seed_words, xfp, get_secrets, press_select,
                     reset_seed_words, cap_screen_qr, qr_quality_check, expect_ftux,
                     is_headless, get_identity_story, way, scan_a_qr, cap_screen):

    if "qr" in way and not is_q1:
        raise pytest.skip("Mk4 QR")
    
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')

    sw = seed_words.split(' ')
    pick_menu_item('%d Words' % len(sw))

    if way == "input":
        word_menu_entry(sw)

    else:
        assert "qr" in way
        need_keypress(KEY_QR)
        if way == "qr":
            qr = ' '.join(w[:4] for w in sw)
        else:
            qr = ''.join('%04d' % wordlist.index(w) for w in sw)

        scan_a_qr(qr)
        time.sleep(1)
        scr = cap_screen()
        assert "Valid words!" in scr
        press_select()

    expect_ftux()

    istory, parsed_ident = get_identity_story()

    assert xfp2str(xfp) == parsed_ident["xfp"]

    v = get_secrets()

    assert f'Press {KEY_QR if is_q1 else "(3)"} to show QR code' in istory
    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '3')
        qr = cap_screen_qr().decode('ascii')
        assert qr == v['xpub']

    assert v['mnemonic'] == seed_words
    reset_seed_words()


@pytest.mark.veryslow           # 40 minutes realtime, skp with "-m not\ veryslow" on cmd line
@pytest.mark.parametrize('pos', range(0, 0x800, 23))
def test_all_bip39_words(pos, goto_home, pick_menu_item, cap_story, unit_test,
                         cap_menu, word_menu_entry, get_secrets, reset_seed_words,
                         expect_ftux, is_q1):

    # try every single word! In 23-word batches (89 of them)
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')

    sw = []
    for i in range(pos, pos+23):
        try:
            sw.append(wordlist[i])
        except IndexError:
            sw.append('abandon')

    assert len(sw) == 23

    pick_menu_item('24 Words')
    word_menu_entry(sw)

    if not is_q1:
        m = cap_menu()
        assert len(m) == 9, repr(m)
        sw.append(m[0])
        pick_menu_item(m[0])

    print("Words: %r" % sw)

    expect_ftux()

    v = get_secrets()
    if is_q1:
        assert v["mnemonic"].split(" ")[:-1] == sw
        mnem.check(v["mnemonic"])
    else:
        assert v['mnemonic'] == ' '.join(sw)

    reset_seed_words()

@pytest.mark.qrcode
@pytest.mark.parametrize('count', [20, 40, 51, 99, 104])
@pytest.mark.parametrize('nwords', [12, 24])
def test_import_from_dice(count, nwords, goto_home, pick_menu_item, cap_story, need_keypress,
                          unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words,
                          cap_screen, cap_screen_qr, qr_quality_check, expect_ftux, press_select,
                          press_cancel, is_q1, seed_story_to_words, is_headless):
    import random
    from hashlib import sha256
    
    unit_test('devtest/clear_seed.py')

    pick_menu_item('New Seed Words')
    pick_menu_item('Advanced')

    pick_menu_item(f'{nwords} Word Dice Roll')
    title, warning = cap_story()
    assert title == 'WARNING'
    assert 'only source of randomness' in warning
    assert 'wallet derived from the rolls entered so far' in warning
    press_select()
    time.sleep(0.1)

    gave = ''
    for i in range(count):
        if count == 104:
            ch = chr(random.randint(0x30+1, 0x30+6))
        else:
            ch = chr(0x31 + (i % 6))
        time.sleep(0.01)
        need_keypress(ch)
        gave += ch
        
    time.sleep(0.1)
    screen = cap_screen()
    digest = sha256(gave.encode('ascii')).hexdigest()
    assert digest[:32] in screen
    assert digest[32:] in screen
    press_select()

    time.sleep(0.1)
    title, body = cap_story()
    threshold = 99 if nwords == 24 else 50
    if count < threshold:
        assert 'Not enough dice rolls' in body
        assert str(len(gave)) in body

        time.sleep(0.1)
        press_select()  # add more dice rolls
        for i in range(threshold - count):
            ch = chr(0x31 + (i % 6))
            time.sleep(0.01)
            need_keypress(ch)
            gave += ch

        press_select()
        time.sleep(0.1)
        title, body = cap_story()

    target = f'Record these {nwords}'
    assert 'Press (4)' not in body
    if is_q1:
        assert target in title
        words = [i[:4].upper() for i in seed_story_to_words(body)]
    else:
        assert target in body
        assert  "(1) to view as QR Code" in body
        words = [i[4:4+4].upper() for i in re.findall(r'[ 0-9][0-9]: \w*', body)]

    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '1')

        qr = cap_screen_qr()
        assert qr.decode('ascii').split() == words
        press_cancel()      # close QR

    need_keypress('6')
    time.sleep(0.1)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    press_select()
    time.sleep(0.1)

    v = get_secrets()

    rs = v['raw_secret']
    if len(rs)%2 == 1:
        rs += '0'

    if nwords == 24:
        assert rs == '82' + sha256(gave.encode('ascii')).hexdigest()
    elif nwords == 12:
        assert rs == '80' + sha256(gave.encode('ascii')).hexdigest()[0:32]
    else:
        raise ValueError(nwords)

    expect_ftux()

@pytest.mark.parametrize('multiple_runs', range(3))
@pytest.mark.parametrize('nwords', [12, 24])
@pytest.mark.parametrize('entropy_method', ['mash', 'dice', 'coin'])
def test_new_wallet(nwords, goto_home, pick_menu_item, cap_story, expect_ftux,
                    cap_menu, get_secrets, unit_test, pass_word_quiz, multiple_runs,
                    reset_seed_words, is_q1, seed_story_to_words, need_keypress,
                    cap_screen, entropy_method, sim_exec, press_select):
    # generate a random wallet, and check seeds are what's shown to user, etc
    
    unit_test('devtest/clear_seed.py')
    m = cap_menu()
    pick_menu_item('New Seed Words')
    pick_menu_item(f'{nwords} Words')

    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']

    def finish_entropy():
        # Queue a finishing ENTER plus a lagging ENTER before the UX can run.
        # collect_*_entropy must clear the second event before showing the words.
        key = KEY_ENTER if is_q1 else 'y'
        sim_exec("from glob import numpad; numpad.inject(%r); numpad.inject(%r)" % (key, key))

    label, intro = {
        'mash': ('Mash Keys', 'Only the timing between presses is credited as entropy.'),
        'dice': ('Dice Rolls', 'Physical die rolls will be mixed into the seed.'),
        'coin': ('Coin Flips', 'Physical coin flips will be mixed into the seed.'),
    }[entropy_method]
    pick_menu_item(label)
    _, story = cap_story()
    assert intro in story
    if entropy_method == 'mash':
        assert 'Each press after the first adds one timing gap, credited with two bits.' in story
        assert 'You may keep mashing to add more timing entropy.' in story
    press_select()
    time.sleep(0.1)

    if entropy_method == 'mash':
        screen = cap_screen()
        assert 'Mash Keys' in screen
        assert ('0 / 65 mashes' if is_q1 else '0 / 65') in screen
        if is_q1:
            assert 'Press random keys' in screen

        for i in range(64):
            need_keypress(str(i % 10))

        time.sleep(0.1)
        screen = cap_screen()
        assert 'Mash Keys' in screen
        assert ('64 / 65 mashes' if is_q1 else '64 / 65') in screen
        need_keypress('9')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('65 / 65 mashes' in screen and
                'Keep mashing or ENTER when done' in screen) if is_q1 else \
               '65  OK=Done' in screen
        need_keypress('8')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('66 / 65 mashes' in screen and
                'Keep mashing or ENTER when done' in screen) if is_q1 else \
               '66  OK=Done' in screen
        finish_entropy()

    elif entropy_method == 'dice':
        screen = cap_screen()
        assert ('Dice Rolls' if is_q1 else 'Roll Dice') in screen
        assert ('0 / 50 rolls' if is_q1 else '0 / 50') in screen
        if is_q1:
            assert 'Enter each roll: 1-6' in screen

        gave = ''
        for i in range(49):
            ch = str(1 + (i % 6))
            need_keypress(ch)
            gave += ch

        time.sleep(0.1)
        screen = cap_screen()
        assert ('49 / 50 rolls' if is_q1 else '49 / 50') in screen
        digest = hashlib.sha256(gave.encode('ascii')).hexdigest()
        assert digest[:32] not in screen
        assert digest[32:] not in screen

        need_keypress('2')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('50 / 50 rolls' in screen and
                'Keep rolling or ENTER when done' in screen) if is_q1 else \
               '50  OK=Done' in screen
        need_keypress('3')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('51 / 50 rolls' in screen and
                'Keep rolling or ENTER when done' in screen) if is_q1 else \
               '51  OK=Done' in screen
        finish_entropy()

    elif entropy_method == 'coin':
        screen = cap_screen()
        assert ('Coin Flips' if is_q1 else 'Coin: 1=H 0=T') in screen
        if is_q1:
            assert '1 = Heads, 0 = Tails' in screen
        assert ('0 / 128 flips' if is_q1 else '0 / 128') in screen

        for i in range(127):
            need_keypress('1' if i % 2 else '0')

        time.sleep(0.1)
        screen = cap_screen()
        assert ('Coin Flips' if is_q1 else 'Coin: 1=H 0=T') in screen
        assert ('127 / 128 flips' if is_q1 else '127 / 128') in screen
        need_keypress('1')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('128 / 128 flips' in screen and
                'Keep flipping or ENTER when done' in screen) if is_q1 else \
               '128  OK=Done' in screen
        need_keypress('0')
        time.sleep(0.1)
        screen = cap_screen()
        assert ('129 / 128 flips' in screen and
                'Keep flipping or ENTER when done' in screen) if is_q1 else \
               '129  OK=Done' in screen
        finish_entropy()

    time.sleep(0.1)

    title, body = cap_story()
    target = f'Record these {nwords} secret words!'
    if is_q1:
        assert target in title
    else:
        assert title == 'NO-TITLE'
        assert target in body
    assert 'Press (4)' not in body

    if is_q1:
        words = seed_story_to_words(body)
    else:
        words = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
    assert len(words) == nwords

    print("Words: %r" % words)

    count, _, _ = pass_word_quiz(words)
    assert count == nwords

    time.sleep(1)

    expect_ftux()

    v = get_secrets()
    assert v['mnemonic'].split(' ') == words

    reset_seed_words()


@pytest.mark.parametrize('nwords', [12, 24])
def test_view_trng_words_verifies_dice_mix(nwords, pick_menu_item, cap_menu, cap_story, unit_test,
                                           press_select, need_keypress, seed_story_to_words, is_q1,
                                           cap_screen, press_down):
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item(f'{nwords} Words')

    assert cap_menu()[-2:] == ['View TRNG Words', 'CANCEL']
    pick_menu_item('View TRNG Words')
    title, body = cap_story()
    base_words = seed_story_to_words(body)
    base_seed = bytes(mnem.to_entropy(' '.join(base_words)))
    assert title == 'TRNG Words'
    assert len(base_words) == 24
    assert 'full 256-bit device seed' in body
    assert 'All 256 bits are used' in body
    assert 'STM32 TRNG + SE1 + SE2' in body
    assert 'KEEP SECRET' in body
    assert 'Scroll to see TRNG words.' in body

    if is_q1:
        press_down()
        press_down()
        time.sleep(0.1)
        shown = {int(n) for n in re.findall(r'(?<!\d)(\d{1,2}):', cap_screen())}
        assert shown == set(range(1, 25))

    press_select()
    time.sleep(0.1)
    assert cap_menu()[-2:] == ['View TRNG Words', 'CANCEL']

    pick_menu_item('Dice Rolls')
    press_select()
    rolls = ('123456' * 8) + '12'
    for ch in rolls:
        need_keypress(ch)
    time.sleep(0.1)
    done_key = KEY_ENTER if is_q1 else 'y'
    need_keypress(done_key)
    time.sleep(0.1)

    _, body = cap_story()
    words = seed_story_to_words(body) if is_q1 else \
        [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']

    dice_hash = hashlib.sha256(b'CC\x01D' + rolls.encode()).digest()
    mix = b'CC\x01SMD' + base_seed + dice_hash
    final_seed = hashlib.sha256(hashlib.sha256(mix).digest()).digest()
    expected_seed = final_seed[:16] if nwords == 12 else final_seed
    assert words == mnem.to_mnemonic(expected_seed).split()

    # Throw away the test words instead of committing them.
    need_keypress('x')
    press_select()
    time.sleep(0.1)


@pytest.mark.parametrize('nwords', [12, 24])
def test_view_trng_words_verifies_coin_mix(nwords, pick_menu_item, cap_menu, cap_story, unit_test,
                                           press_select, need_keypress, seed_story_to_words, is_q1):
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item(f'{nwords} Words')

    assert cap_menu()[-2:] == ['View TRNG Words', 'CANCEL']
    pick_menu_item('View TRNG Words')
    title, body = cap_story()
    base_words = seed_story_to_words(body)
    base_seed = bytes(mnem.to_entropy(' '.join(base_words)))
    assert title == 'TRNG Words'
    assert len(base_words) == 24

    press_select()
    time.sleep(0.1)
    assert cap_menu()[-2:] == ['View TRNG Words', 'CANCEL']

    pick_menu_item('Coin Flips')
    press_select()
    flips = '01' * 64
    for ch in flips:
        need_keypress(ch)
    time.sleep(0.1)
    done_key = KEY_ENTER if is_q1 else 'y'
    need_keypress(done_key)
    time.sleep(0.1)

    _, body = cap_story()
    words = seed_story_to_words(body) if is_q1 else \
        [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']

    coin_hash = hashlib.sha256(b'CC\x01C' + flips.encode()).digest()
    mix = b'CC\x01SMC' + base_seed + coin_hash
    final_seed = hashlib.sha256(hashlib.sha256(mix).digest()).digest()
    expected_seed = final_seed[:16] if nwords == 12 else final_seed
    assert words == mnem.to_mnemonic(expected_seed).split()

    # Throw away the test words instead of committing them.
    need_keypress('x')
    press_select()
    time.sleep(0.1)


def test_new_wallet_entropy_cancel(pick_menu_item, cap_menu, cap_story,
                                   unit_test, press_cancel, press_select,
                                   sim_eval):
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item('12 Words')

    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']
    pick_menu_item('Mash Keys')
    _, story = cap_story()
    assert 'Only the timing between presses is credited as entropy.' in story
    press_cancel()
    time.sleep(0.1)

    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']

    # Also cancel after raw-edge capture has been enabled. The collector's
    # finally block must restore normal keypad IRQ handling.
    pick_menu_item('Mash Keys')
    press_select()
    time.sleep(0.1)
    assert sim_eval("__import__('glob').numpad._mash_mode") == 'True'
    press_cancel()
    time.sleep(0.1)
    assert sim_eval("__import__('glob').numpad._mash_mode") == 'False'
    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']

    pick_menu_item('CANCEL')
    time.sleep(0.1)

    assert cap_menu()[0] == '12 Words'


def test_new_wallet_rejects_biased_dice(pick_menu_item, cap_menu, unit_test,
                                        need_keypress, press_select, cap_story):
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item('12 Words')
    pick_menu_item('Dice Rolls')
    press_select()
    time.sleep(0.1)

    for _ in range(50):
        need_keypress('1')
    press_select()
    time.sleep(0.1)

    _, story = cap_story()
    assert 'Distribution of dice rolls is not random' in story
    assert 'Some numbers occurred more than 30% of the time' in story
    press_select()
    time.sleep(0.1)

    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']
    pick_menu_item('CANCEL')


def test_new_wallet_rejects_biased_coin(pick_menu_item, cap_menu, unit_test,
                                        need_keypress, press_select, cap_story):
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item('12 Words')
    pick_menu_item('Coin Flips')
    press_select()
    time.sleep(0.1)

    for _ in range(128):
        need_keypress('1')
    press_select()
    time.sleep(0.1)

    _, story = cap_story()
    assert 'Distribution of coin flips is not random' in story
    assert 'Heads or tails occurred more than 65% of the time' in story
    press_select()
    time.sleep(0.1)

    assert cap_menu() == ['Mash Keys', 'Dice Rolls', 'Coin Flips',
                          'View TRNG Words', 'CANCEL']
    pick_menu_item('CANCEL')


def test_mash_allows_single_key(pick_menu_item, unit_test, need_keypress,
                                press_select, press_cancel, cap_story):
    # Todd's construction gets entropy from timing and works with one button.
    unit_test('devtest/clear_seed.py')
    pick_menu_item('New Seed Words')
    pick_menu_item('12 Words')
    pick_menu_item('Mash Keys')
    press_select()
    time.sleep(0.1)

    for _ in range(65):
        need_keypress('1')
    press_select()
    time.sleep(0.1)

    title, story = cap_story()
    assert 'Record these 12 secret words' in title + story

    # Throw away the generated words.
    press_cancel()
    press_select()
    time.sleep(0.1)


def test_mk_mash_debounce_state_machine(sim_exec, sim_eval, is_mark4, is_mark5):
    # Normal simulator key injection bypasses the Mk membrane scan path.
    if not (is_mark4 or is_mark5):
        pytest.skip('membrane keypad only')

    setup = '''\
import mempad, uasyncio, utime
from glob import numpad
mempad._saved_call_later_ms = mempad.call_later_ms
mempad.call_later_ms = lambda *a, **k: None
numpad.timer.deinit()
while numpad.scans:
    numpad.scans.popleft()
numpad._char_reported.clear()
numpad._test_mash_events = []
events = numpad._test_mash_events
numpad._key_event = lambda key, timestamp=None, events=events: events.append((key, timestamp))
numpad._mash_mode = True
numpad.waiting_for_any = False
numpad._mash_press_timestamp = 123
numpad._scan_count = 1
for i in range(len(numpad._history)):
    numpad._history[i] = 0
numpad._history[0] = 1
numpad.lp_time = utime.ticks_ms()
uasyncio.create_task(numpad._finish_scan())
'''
    try:
        assert sim_exec(setup) == ''
        time.sleep(0.05)

        # The 5ms queue poll must not erase an edge while its 60Hz debounce
        # samples are still being collected.
        state = '(glob.numpad.waiting_for_any, glob.numpad._mash_press_timestamp, '
        state += 'glob.numpad._scan_count, glob.numpad._history[0])'
        assert sim_eval(state) == '(False, 123, 1, 1)'

        # Supply the remaining two down samples and emit the accepted press.
        assert sim_exec('''\
import uasyncio
from glob import numpad
numpad.cols[0].value(0)
numpad.cols[1].value(1)
numpad.cols[2].value(1)
numpad._measure_irq(numpad.timer)
numpad._measure_irq(numpad.timer)
uasyncio.create_task(numpad._finish_scan())
''') == ''
        time.sleep(0.05)
        assert sim_eval('glob.numpad._test_mash_events') == "[('y', 123)]"
        assert sim_eval('glob.numpad._mash_press_timestamp') == 'None'

        # Three all-up samples re-arm raw-edge capture immediately, before
        # the async queue consumer emits the release event.
        assert sim_exec('''\
from glob import numpad
for c in numpad.cols:
    c.value(1)
for i in range(3):
    numpad._measure_irq(numpad.timer)
''') == ''
        state = '(glob.numpad.waiting_for_any, glob.numpad._mash_press_timestamp, '
        state += 'glob.numpad._scan_count, sum(glob.numpad._history))'
        assert sim_eval(state) == '(True, None, 0, 0)'
        assert sim_eval('glob.numpad._test_mash_events') == "[('y', 123)]"

        assert sim_exec('''\
import uasyncio
from glob import numpad
uasyncio.create_task(numpad._finish_scan())
''') == ''
        time.sleep(0.05)
        events = "[('y', 123), ('', None)]"
        assert sim_eval('glob.numpad._test_mash_events') == events
        assert sim_eval(state) == '(True, None, 0, 0)'

        # A falling-edge glitch that never debounces must eventually re-arm.
        assert sim_exec('''\
import uasyncio, utime
from glob import numpad
numpad.waiting_for_any = False
numpad._mash_press_timestamp = 456
numpad._scan_count = 1
numpad._history[0] = 1
numpad.lp_time = utime.ticks_add(utime.ticks_ms(), -251)
uasyncio.create_task(numpad._finish_scan())
''') == ''
        time.sleep(0.05)
        assert sim_eval(state) == '(True, None, 0, 0)'
    finally:
        sim_exec('''\
import mempad
from glob import numpad
mempad.call_later_ms = mempad._saved_call_later_ms
del mempad._saved_call_later_ms
del numpad._key_event
del numpad._test_mash_events
numpad._mash_mode = False
numpad._mash_press_timestamp = None
numpad._finish_scan_active = False
numpad._wait_any()
''')


def test_mash_entropy_includes_timing(goto_home, pick_menu_item, cap_story,
                                      need_keypress, press_select, sim_exec,
                                      unit_test, expect_ftux):
    # Identical base seed and identical key sequence, twice. Only press
    # timing may differ, so the resulting words must differ: proves that
    # timing reaches the hash and keys alone cannot regenerate the seed.
    unit_test('devtest/clear_seed.py')
    sim_exec("import seed; seed._orig_gs = seed.generate_seed;"
             " seed.generate_seed = lambda: bytes(32)")
    try:
        stories = []
        for _ in range(2):
            goto_home()
            pick_menu_item('New Seed Words')
            pick_menu_item('12 Words')
            pick_menu_item('Mash Keys')
            press_select()
            for i in range(65):
                need_keypress(str(i % 10))
            press_select()
            time.sleep(0.1)

            _, body = cap_story()
            stories.append(body)

            # throw the words away, do not commit them
            need_keypress('x')
            press_select()
            time.sleep(0.1)

        assert stories[0] != stories[1]
    finally:
        sim_exec("import seed; seed.generate_seed = seed._orig_gs")


@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
def test_import_prv(way, testnet, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu,
                    get_secrets, microsd_path, reset_seed_words, scan_a_qr, is_q1, press_nfc,
                    nfc_write_text, settings_set, virtdisk_path, expect_ftux, garbage_collector,
                    enable_hw_ux, skip_if_useless_way):

    unit_test('devtest/clear_seed.py')
    netcode = "XTN" if testnet else "BTC"
    settings_set('chain', netcode)

    if way in ["nfc", "vdisk"]:
        enable_hw_ux(way)

    skip_if_useless_way(way)

    node = BIP32Node.from_master_secret(prandom(32), netcode=netcode)
    prv = node.hwif(as_private=True)+'\n'
    if testnet:
        assert "tprv" in prv
    else:
        assert "xprv" in prv

    if way in ["sd", "vdisk"]:
        fname = 'test-%d.txt' % os.getpid()
        path_f = microsd_path if way == "sd" else virtdisk_path
        fpath = path_f(fname)
        garbage_collector.append(fpath)
        with open(fpath, "w") as f:
            f.write(prv)

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')
    pick_menu_item('Import XPRV')
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import extended private key file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            press_nfc()
            time.sleep(0.2)
            nfc_write_text(prv)
            time.sleep(0.3)
    elif way == "qr":
        need_keypress(KEY_QR)
        scan_a_qr(prv)
        time.sleep(1)
    else:
        # virtual disk
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way in ["sd", "vdisk"]:
        time.sleep(0.1)
        pick_menu_item(fname)

    expect_ftux()

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

    reset_seed_words()


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize("testnet", [True, False])
def test_seed_import_tapsigner(way, testnet, cap_menu, pick_menu_item, goto_home, cap_story,
                               need_keypress, reset_seed_words, dev, try_sign, enter_hex, unit_test,
                               settings_set, get_secrets, tapsigner_encrypted_backup, nfc_write_text,
                               press_nfc, press_select, is_q1, enable_hw_ux, skip_if_useless_way,
                               scan_a_qr):

    unit_test('devtest/clear_seed.py')
    netcode = "XTN" if testnet else "BTC"
    settings_set('chain', netcode)

    if way in ["nfc", "vdisk"]:
        enable_hw_ux(way)

    skip_if_useless_way(way)

    fname, backup_key_hex, node = tapsigner_encrypted_backup(way, testnet=testnet)

    m = cap_menu()
    assert m[0] == 'New Seed Words'
    pick_menu_item('Import Existing')
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            press_nfc()
            time.sleep(0.2)
            nfc_write_text(fname)  # fname is b64 encoded backup itself
            time.sleep(0.3)
    elif way == "qr":
        need_keypress(KEY_QR)
        scan_a_qr(fname)  # fname is b64 encoded backup itself
        time.sleep(1)
    else:
        # virtual disk
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way in ["sd", "vdisk"]:
        time.sleep(0.1)
        pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert "your TAPSIGNER" in story
    assert "back of the card" in story
    press_select()  # yes I have backup key
    enter_hex(backup_key_hex)
    unit_test('devtest/abort_ux.py')

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

    reset_seed_words()


@pytest.mark.qrcode
@pytest.mark.parametrize('mode', ['words', 'xprv', 'ms'])
@pytest.mark.parametrize('b39_word', ['', 'AbcZz1203'])
def test_show_seed(mode, b39_word, goto_home, pick_menu_item, cap_story, need_keypress,
                   sim_exec, cap_menu, get_secrets, cap_screen_qr, set_bip39_pw,
                   set_encoded_secret, qr_quality_check, reset_seed_words,
                   press_select, is_q1, seed_story_to_words, is_headless):

    reset_seed_words()
    if mode == 'words':
        set_bip39_pw(b39_word, reset=False)
        if b39_word:
            seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=b39_word)
            node = BIP32Node.from_master_secret(seed, netcode="XTN")
            expect = node.hwif(as_private=True)
        else:
            words = simulator_fixed_words.split(" ")

    else:
        if b39_word: return

        if mode == 'xprv':
            set_encoded_secret(b'\x01' + prandom(64))
            v = get_secrets()
            expect = v['xprv']
        elif mode == 'ms':
            set_encoded_secret(b'\x20' + prandom(32))
            v = get_secrets()
            expect = v['raw_secret'][2:2+64]
            if len(expect) % 2 == 1:
                expect += '0'
        

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('View Seed Words')
    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'secret seed words' in body
    assert 'or extended private key' in body
    assert 'can control all funds' in body
    press_select()      # skip warning
    time.sleep(0.01)

    title, body = cap_story()
    if not is_q1:
        assert title == 'NO-TITLE'

    if mode == 'words' and not b39_word:
        assert '24' in (title if is_q1 else body)

        lines = body.split('\n')
        if is_q1:
            assert seed_story_to_words(body) == words
        else:
            assert lines[1:25] == ['%2d: %s' % (n+1, w) for n,w in enumerate(words)]

        assert "BIP-39 Passphrase" not in body
        qr_expect = ' '.join(w[0:4].upper() for w in words)

    else:
        assert expect in body
        qr_expect = expect
        if b39_word:
            assert body.startswith("BIP-39 Passphrase in effect\n\n")
            assert b39_word not in body
            assert "Seed words" not in body
        else:
            assert "BIP-39 Passphrase" not in body

    if not is_q1:
        assert '(1) to view as QR Code' in body

    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '1')
        qr = cap_screen_qr().decode('ascii')
        assert qr == qr_expect

    press_select()      # clear screen

@pytest.mark.qrcode
@pytest.mark.parametrize("data", [
    (simulator_fixed_words, [2007, 1585, 123, 131, 745, 43, 1506, 1930, 664, 749, 1200, 113, 1321, 330, 1764, 698, 1160, 656, 647, 1424, 135, 767, 987, 335]),
    ("task tube actor end cannon potato sign card occur donkey soup baby tooth bless barely pull gap priority", [1776, 1872, 21, 588, 267, 1350, 1602, 276, 1222, 521, 1663, 136, 1830, 189, 148, 1386, 762, 1367]),
    ("vacuum bridge buddy supreme exclude milk consider tail expand wasp pattern nuclear", [1924,222,235,1743,631,1124,378,1770,641,1980,1290,1210]),
    ("approve fruit lens brass ring actual stool coin doll boss strong rate", "008607501025021714880023171503630517020917211425"),
    ("good battle boil exact add seed angle hurry success glad carbon whisper", "080301540200062600251559007008931730078802752004"),
    ("forum undo fragile fade shy sign arrest garment culture tube off merit", "073318950739065415961602009907670428187212261116"),
    ("sound federal bonus bleak light raise false engage round stock update render quote truck quality fringe palace foot recipe labor glow tortoise potato still", "166206750203018810361417065805941507171219081456140818651401074412730727143709940798183613501710"),
    ("atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid meadow quick medal plate wisdom swap noble shallow", "011416550964188800731119157218870156061002561932122514430573003611011405110613292018175411971576"),
    ("attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire", "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643"),
])
def test_show_seed_qr(data, goto_home, pick_menu_item, cap_story, press_select,
                      sim_exec, cap_menu, get_secrets, cap_screen_qr,
                      set_encoded_secret, qr_quality_check, set_seed_words, is_q1):
    n = 4  # SeedQr 4 str chars for each index
    words, qr_expect = data
    if isinstance(qr_expect, str):
        qr_expect = [int(qr_expect[i:i+n]) for i in range(0, len(qr_expect), n)]
    set_seed_words(words)

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Export SeedQR')

    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'can control all funds' in body
    press_select()  # skip warning
    time.sleep(0.01)

    qr = cap_screen_qr().decode('ascii')
    qr = [int(qr[i:i+n]) for i in range(0, len(qr), n)]
    assert qr == qr_expect

    press_select()  # clear screen

def test_destroy_seed(goto_home, pick_menu_item, cap_story, press_select,
                      sim_exec, cap_menu, get_secrets, is_q1):
    # Check UX of destroying seeds, rarely used?

    #v = get_secrets()
    #words = v['mnemonic'].split(' ')

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Destroy Seed')
    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'All funds will be lost' in body
    assert 'Saved temporary seed settings and Seed Vault are lost' in body
    press_select()
    time.sleep(0.01)

    title, body = cap_story()
    assert 'Are you REALLY sure though' in body
    assert 'certainly cause' in body
    assert 'accept all consequences' in body
    press_select()         # wants 4
    time.sleep(0.01)


def test_menu_wrapping(goto_home, pick_menu_item, cap_story, cap_menu,
                       press_select, press_up, press_down, press_cancel,
                       is_q1, settings_remove):
    settings_remove("wa")  # disable
    goto_home()
    # first try that infinite scroll is turned off
    # home
    assert len(cap_menu()) < 10

    for i in range(10):
        press_down()

    # sitting at Logout
    # one up to get to settings
    if not is_q1:
        press_up()

    press_select()
    pick_menu_item("Buried Settings")
    pick_menu_item("Menu Wrapping")
    press_select()
    pick_menu_item("Always Wrap")
    time.sleep(1)
    press_cancel()  # back to Settings
    press_cancel()  # back to home menu
    press_cancel()  # at Ready To Sign

    press_up()  # Settings as we just went over the top in home menu
    if not is_q1:
        press_up()
    press_select()

    pick_menu_item("Buried Settings")
    pick_menu_item("Menu Wrapping")
    pick_menu_item("Default")
    time.sleep(1)
    press_cancel()  # back in home menu
    press_cancel()  # at Ready To Sign
    press_up()
    press_select()
    menu = cap_menu()
    assert "Buried Settings" not in menu
    goto_home()

def test_chain_changes_settings_xpub(pick_menu_item, cap_story, press_select,
                                     get_identity_story):
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("tpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    pick_menu_item("Bitcoin")
    time.sleep(0.2)
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("xpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    time.sleep(0.2)
    _, story = cap_story()
    assert "Testnet must only be used by developers" in story
    press_select()
    pick_menu_item("Regtest")
    time.sleep(0.2)
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("tpub")

@pytest.mark.parametrize("clear", [1, 0])
@pytest.mark.parametrize("f_len", [50, 500, 5000])
def test_sign_file_from_list_files(f_len, goto_home, cap_story, pick_menu_item, need_keypress,
                                   microsd_path, cap_menu, verify_detached_signature_file,
                                   press_select, clear, unit_test, reset_seed_words):
    if clear:
        unit_test('devtest/clear_seed.py')
    else:
        reset_seed_words()

    fname = "test_sign_listed.pdf"
    signame = "test_sign_listed.sig"
    fpath = microsd_path(fname)
    contents = prandom(f_len)
    digest = hashlib.sha256(contents).digest().hex()
    with open(fpath, "wb") as f:
        f.write(contents)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item('File Management')
    pick_menu_item('List Files')
    time.sleep(0.1)
    pick_menu_item(fname)
    time.sleep(0.1)
    _, story = cap_story()
    assert f"SHA256({fname})" in story
    assert digest in story
    if clear:
        assert "(4) to sign file digest and export detached signature" not in story
    else:
        assert "(4) to sign file digest and export detached signature" in story
        need_keypress("4")
        time.sleep(0.1)
        _, story = cap_story()
        assert f"Signature file {signame} written" in story
        need_keypress("y")
        time.sleep(0.1)
        verify_detached_signature_file([fname], signame, "sd", AF_CLASSIC)
        time.sleep(0.1)
        _, story = cap_story()

    assert "(6) to delete" in story

    need_keypress("6")
    time.sleep(0.1)
    menu = cap_menu()
    assert "List Files" in menu


def test_rename_from_list_files(goto_home, cap_story, pick_menu_item, need_keypress, is_q1,
                                microsd_path, press_select, cap_screen, enter_complex, cap_menu):
    def clear(fname):
        for i in range(len(fname)):
            if not is_q1 and not i:
                # Mk4 different menu entry UX
                continue
            need_keypress(KEY_DELETE if is_q1 else "x")
            time.sleep(0.01)

    fname = "file_to_rename.pdf"
    fpath = microsd_path(fname)
    contents = prandom(64)
    digest = hashlib.sha256(contents).digest().hex()
    with open(fpath, "wb") as f:
        f.write(contents)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item('File Management')
    pick_menu_item('List Files')
    time.sleep(0.1)
    pick_menu_item(fname)
    time.sleep(0.1)
    _, story = cap_story()
    assert f"SHA256({fname})" in story
    assert digest in story
    assert "Press (1) to rename file" in story
    need_keypress("1")
    time.sleep(0.1)
    if is_q1:
        scr = cap_screen()
        assert fname in scr

    clear(fname)

    bad_fnames = ["renamed file.txt", "/sd/renamed_file.txt", "renamed\\file.txt"]
    for bad in bad_fnames:
        enter_complex(bad, b39pass=False)
        time.sleep(.1)
        title, story = cap_story()
        assert title == "Failure"
        assert "Failed to rename the file" in story
        assert "illegal char" in story
        press_select()
        time.sleep(.1)
        need_keypress("1")  # rename again
        time.sleep(.1)
        clear(fname)
        if not is_q1:
            need_keypress("1")  # toggle case back to upper (enter complex expect to start in that state)

    new_fname = "renamed_file.txt"
    enter_complex(new_fname, b39pass=False)
    time.sleep(.1)
    _, story = cap_story()
    assert f"SHA256({new_fname})" in story
    assert digest in story
    assert not os.path.exists(fpath)
    assert os.path.exists(microsd_path(new_fname))

    # delete (6) from the same loop must blank the *renamed* file, not the stale old path
    assert "(6) to delete" in story
    need_keypress("6")
    time.sleep(.1)
    menu = cap_menu()
    assert "List Files" in menu
    assert not os.path.exists(microsd_path(new_fname))
    assert not os.path.exists(fpath)


def test_bip39_pw_signing_xfp_ux(pick_menu_item, press_select, cap_story, enter_complex, enable_nfc,
                                 reset_seed_words, cap_menu, go_to_passphrase, microsd_wipe):
    microsd_wipe()  # need to wipe all PSBT on SD card so we do not proceed to signing
    enable_nfc()
    go_to_passphrase()
    enter_complex("21coinkite21", apply=True)
    time.sleep(0.3)
    title, story = cap_story()
    assert title == "[0C9DC99D]"
    assert 'Above is the master key fingerprint of the new wallet' in story
    press_select()  # confirm passphrase
    time.sleep(0.1)
    m = cap_menu()
    assert m[0] == "[0C9DC99D]"
    pick_menu_item("Ready To Sign")
    time.sleep(0.1)
    title_sign, _ = cap_story()
    assert title_sign == title
    reset_seed_words()  # for subsequent tests


def test_q1_seed_word_entry_bug(word_menu_entry, unit_test, pick_menu_item,
                                is_q1, do_keypresses, press_select, expect_ftux):
    # internal/issues/750
    if not is_q1:
        raise pytest.skip("Q only")

    unit_test('devtest/clear_seed.py')
    pick_menu_item('Import Existing')
    pick_menu_item('24 Words')
    sw = ["abandon"] * 23
    sw += ["art"]
    word_menu_entry(sw, q_accept=False)
    do_keypresses("art")
    # now we are yikes if bug not fixed
    press_select()
    expect_ftux()


def test_q1_seed_word_bad_qr_keeps_words(unit_test, pick_menu_item, is_q1, do_keypresses,
                                         need_keypress, scan_a_qr, cap_screen):
    if not is_q1:
        raise pytest.skip("Q only")

    unit_test('devtest/clear_seed.py')
    pick_menu_item('Import Existing')
    pick_menu_item('12 Words')

    do_keypresses("aba")
    time.sleep(1)
    assert "1: abandon" in cap_screen()

    need_keypress(KEY_QR)
    scan_a_qr("not a seed qr")
    time.sleep(1)

    screen = cap_screen()
    assert "1: abandon" in screen
    assert "Unable to decode as secret" in screen


def test_custom_pushtx_url(goto_home, pick_menu_item, press_select, enter_complex,
                           cap_story, cap_menu, settings_remove, need_keypress,
                           press_cancel, is_q1, settings_get, OK):
    goto_home()
    settings_remove('ptxurl')  # empty slate

    pick_menu_item("Settings")
    pick_menu_item("NFC Push Tx")
    time.sleep(.1)
    title, story = cap_story()
    if title == "PUSH TX":
        assert "immediately broadcast" in story
        assert "tap any NFC-enabled phone on the COLDCARD" in story
        assert "choose a provider by URL here, or give your own URL" in story
        assert "transaction details could be linked by the service" in story
        press_select()

    time.sleep(.1)
    title, story = cap_story()
    if f"This feature requires NFC to be enabled. {OK} to enable" in story:
        press_select()

    time.sleep(.3)
    m = cap_menu()
    assert "coldcard.com" in m
    assert "mempool.space" in m
    assert "Custom URL..." in m
    assert "Disable" in m

    pick_menu_item("Custom URL...")
    time.sleep(.1)
    if not is_q1:
        # move to next char
        need_keypress("9")
        need_keypress("1")
    enter_complex("s://selfhosted.com/pushtx#", b39pass=False)
    time.sleep(.1)
    m = cap_menu()
    assert "selfhosted.com" in m
    assert settings_get('ptxurl') == "https://selfhosted.com/pushtx#"

    pick_menu_item("selfhosted.com")
    if is_q1:
        need_keypress(KEY_DELETE)
    else:
        need_keypress("1")  # get him to letters, so clean switch to symbols
    enter_complex("?", b39pass=False)
    time.sleep(.1)
    m = cap_menu()
    assert "selfhosted.com" in m
    assert settings_get('ptxurl') == "https://selfhosted.com/pushtx?"

    pick_menu_item("selfhosted.com")
    for _ in range(len("https://selfhosted.com/pushtx?") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("httphttps://a.com/pushtx#", b39pass=False)
    time.sleep(.1)
    title, story = cap_story()
    assert "Must start with http:// or https://." in story
    press_select()

    for _ in range(len("httphttps://a.com/pushtx#") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("http://sh.sk/ptx%", b39pass=False)

    time.sleep(.1)
    title, story = cap_story()
    assert "Final char must be # or ? or &." in story
    press_select()

    for _ in range(len("http://sh.sk/ptx%") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("http://s.s#", b39pass=False)

    time.sleep(.1)
    title, story = cap_story()
    assert "Too short." in story
    press_select()

    for _ in range(len("http://s.s#") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    press_cancel()
    time.sleep(.1)
    press_select()
    time.sleep(.1)
    assert settings_get('ptxurl', None) is None


@pytest.mark.parametrize("fname,ftype", [
    ("ccbk-start.json", "J"),
    ("ckcc-backup.txt", "U"),
    ("devils-txn.txn", "T"),
    ("example-change.psbt", "P"),
    ("sim_conso5.psbt", "P"),  # binary psbt
    ("payjoin.psbt", "U"),  # base64 string in file
    ("worked-unsigned.psbt", "U"),  # hex string psbt
    ("coldcard-export.json", "J"),
    ("coldcard-export.sig", "U"),
])
def test_bbqr_share_files(fname, ftype, readback_bbqr, need_keypress, src_root_dir,
                          goto_home, pick_menu_item, is_q1, cap_menu, sim_root_dir):
    goto_home()
    if not is_q1:
        pick_menu_item("Advanced/Tools")
        pick_menu_item("File Management")
        assert "BBQr File Share" not in cap_menu()
        return

    fpath = f"{src_root_dir}/testing/data/" + fname
    shutil.copy2(fpath, f'{sim_root_dir}/MicroSD')
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("BBQr File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    file_type, rb = readback_bbqr()
    assert file_type == ftype
    with open(fpath, "rb") as f:
        res = f.read()

    assert res == rb
    os.remove(f'{sim_root_dir}/MicroSD/' + fname)

@pytest.mark.parametrize("fname", [
    "ccbk-start.json",
    "devils-txn.txn",
    "payjoin.psbt",  # base64 string in file
])
def test_qr_share_files(fname, pick_menu_item, goto_home, is_q1, cap_menu, cap_screen_qr,
                        src_root_dir, sim_root_dir):
    goto_home()
    if not is_q1:
        pick_menu_item("Advanced/Tools")
        pick_menu_item("File Management")
        assert "QR File Share" not in cap_menu()
        return

    fpath = f"{src_root_dir}/testing/data/" + fname
    shutil.copy2(fpath, f'{sim_root_dir}/MicroSD')
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("QR File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    qr = cap_screen_qr()
    with open(fpath, "r") as f:
        res = f.read()

    assert res == qr.decode()
    os.remove(f'{sim_root_dir}/MicroSD/' + fname)


@pytest.mark.parametrize("way", ["nfc", "qr"])
def test_share_binary_txn_file(way, goto_home, pick_menu_item, src_root_dir, sim_root_dir,
                                press_select, cap_story, cap_screen_qr, is_q1,enable_nfc,
                                nfc_read, nfc_block4rf, garbage_collector):
    if way == "qr" and not is_q1:
        pytest.skip("QR share is Q1 only")

    if way == "nfc":
        enable_nfc()

    with open(f"{src_root_dir}/testing/data/devils-txn.txn", "r") as f:
        binary = bytes.fromhex(f.read().strip())
    assert binary[2:8] != bytes(6)

    fname = "binary-l01.txn"
    dst = f"{sim_root_dir}/MicroSD/{fname}"
    garbage_collector.append(dst)
    with open(dst, "wb") as f:
        f.write(binary)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("NFC File Share" if way == "nfc" else "QR File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    time.sleep(.2)

    title, story = cap_story()
    assert "ERROR" not in title

    if way == "nfc":
        nfc_block4rf()
        res = nfc_read()
        got_txn = None
        for got in ndef.message_decoder(res):
            if got.type == 'urn:nfc:ext:bitcoin.org:txn':
                got_txn = bytes(got.data)
                break
        assert got_txn == binary
        press_select()
    else:
        qr = cap_screen_qr()
        assert qr.decode().lower() == b2a_hex(binary).decode().lower()


@pytest.mark.parametrize("word,cs_word", [
    # few combos with all words with length 8 + their longest possible checksum word
    ("acoustic", "decrease"),
    ("electric", "witness"),
    ("umbrella", "convince"),
    ("universe", "hamster"),
])
def test_q1_24_8char_words(set_seed_words, is_q1, goto_home, pick_menu_item, press_select,
                           cap_story, cap_screen, word, cs_word):
    # /issues/965
    # vectors calculated with `coldcard-mpy`:
    #
    #  w8 = [w for w in bip39.wordlist_en if len(w) >= 8]
    #  for w in w8:
    #      wl = ([w]*23)
    #      ds = list(bip39.a2b_words_guess(wl))
    #      print(w, max(ds, key=len))
    if not is_q1:
        raise pytest.skip("only Q")

    # longest words in wordlist_en have 8 chars
    words = ([word] * 23) + [cs_word]
    set_seed_words(" ".join(words))

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("Seed Functions")
    pick_menu_item('View Seed Words')
    time.sleep(.01)
    press_select()  # skip warning
    time.sleep(0.01)

    title, body = cap_story()
    assert '24' in title
    scr = cap_screen().split("\n")
    assert "Seed words (24)" in scr[0]
    assert scr[1] == ""
    # 8 rows
    assert len(scr[2:]) == 8

    x = 1
    y = 9
    z = 17
    for row in scr[2:]:
        # each row contains 3 colons (aka 3 words)
        srow = [r for r in row.split(" ") if r]  # filter empty strings
        assert len(srow) == 3  # three columns

        # 8 words for each column
        (tx, w0), (ty, w1), (tz, w2) = [pr.split(":") for pr in srow]
        assert x == int(tx) and y == int(ty) and z == int(tz)
        x += 1
        y += 1
        z += 1

        if int(tz) == 24:
            # last line with checksum word
            assert w2 == cs_word
            assert w0 == w1 == word
        else:
            assert w0 == w1 == w2 == word


def test_file_picker_suffixes(pick_menu_item, goto_home, cap_story, microsd_wipe, press_select,
                              microsd_path):
    # make sure no .txt, .7z & .pdf files are not on the SD card
    microsd_wipe()
    # create files that must not be recognized, because they're missing the dot
    for fn in ["backup7z", "backuptxt", "template:pdf"]:
        with open(microsd_path(fn), "w") as f:
            f.write("dummy")

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("I Am Developer.")
    pick_menu_item("Restore Bkup")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: .7z OR .txt" in story
    press_select()

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Paper Wallets")
    press_select()
    pick_menu_item("Don't make PDF")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: .pdf" in story

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("Sign Text File")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: .txt OR .json" in story
    microsd_wipe()


@pytest.mark.parametrize("already_set", [True, False])
def test_nickname_cancel_preserves_existing(already_set, goto_home, pick_menu_item, need_keypress,
                                            settings_set, settings_get, press_cancel, press_select,
                                            settings_remove, sim_exec):
    nick = 'CancelTest'

    if already_set:
        settings_set("nick", nick, prelogin=True)
    else:
        settings_remove("nick", prelogin=True)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Login Settings')
    pick_menu_item('Set Nickname')
    if not already_set:
        press_select()  # intro

    press_cancel()

    new_nick = settings_get("nick", False, prelogin=True)
    if already_set:
        assert nick == new_nick
    else:
        assert new_nick is False

    settings_remove("nick")  # clean-up


@pytest.mark.parametrize('chain', ['BTC', 'XTN'])
@pytest.mark.parametrize('rz', [8, 5, 2, 0])
@pytest.mark.parametrize('amount', [
    '1.1',
    '50',
    '0.12345678',
    '1.10000000',
])
def test_bip21_amount_display(amount, chain, rz, settings_set, settings_remove, scan_a_qr,
                              cap_story, goto_home, need_keypress, press_cancel):
    settings_set('chain', chain)
    settings_set('rz', rz)

    whole, _, frac = amount.partition('.')
    sats = int((whole or '0') + (frac + '00000000')[:8])

    if rz == 8:
        amt = '%d.%08d %s' % (sats // 100000000, sats % 100000000, chain)
    elif rz == 5:
        amt = '%d.%05d m%s' % (sats // 100000, sats % 100000, chain)
    elif rz == 2:
        amt = '%d.%02d bits' % (sats // 100, sats % 100)
    else:
        assert rz == 0
        amt = '%d sats' % sats

    expected = 'Amount: %s' % amt

    # base58 P2PKH decodes regardless of chain setting (we exploit bug here to not need to specify 2 addrs)
    addr = 'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'
    url = 'bitcoin:%s?amount=%s' % (addr, amount)

    goto_home()
    need_keypress(KEY_QR)
    time.sleep(.1)
    scan_a_qr(url)
    time.sleep(.5)

    title, body = cap_story()
    assert title == 'Payment Address', title
    assert expected in body

    press_cancel()
    settings_set('chain', 'XTN')
    settings_remove('rz')


@pytest.mark.parametrize('amount', [
    '999999999',        # 9-digit whole part: 99,999,999 > 21M BTC supply
    '999999999.0',      # same, with explicit fractional zero
    '1.123456789',      # 9-digit fractional part: sub-satoshi precision
    'abc',              # not numeric at all
    '1.5a',             # mixed digits + alpha in fractional part
    '-1.0',             # negative sign breaks isdigit()
    '1,5',              # comma not handled (no dot found, whole isn't digits)
    '',                 # empty string
])
def test_bip21_amount_display_corrupt(amount, scan_a_qr, cap_story, goto_home,
                                       need_keypress, press_cancel):
    addr = 'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'
    url = 'bitcoin:%s?amount=%s' % (addr, amount)

    goto_home()
    need_keypress(KEY_QR)
    time.sleep(.1)
    scan_a_qr(url)
    time.sleep(.5)

    title, body = cap_story()
    assert title == 'Payment Address', title
    assert 'Amount: (corrupt)' in body
    press_cancel()


@pytest.mark.parametrize('field', ['label', 'message', 'lightning'])
def test_bip21_metadata_control_chars(field, scan_a_qr, cap_story, goto_home,
                                       need_keypress, press_cancel):
    addr = 'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'
    fake_addr = 'tb1qupyd58ndsh7lut0et0vtrq432jvu9jtdyws9n9'
    url = 'bitcoin:%s?%s=Pay%%20to%%3A%%0A%%02%s' % (addr, field, fake_addr)

    goto_home()
    need_keypress(KEY_QR)
    time.sleep(.1)
    scan_a_qr(url)
    time.sleep(.5)

    title, body = cap_story()
    assert title == 'Payment Address', title
    assert '%s: (corrupt)' % field.title() in body
    assert fake_addr not in body
    press_cancel()


def test_bip21_parameter_name_control_chars(scan_a_qr, cap_story, goto_home,
                                             need_keypress, press_cancel):
    addr = 'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'
    fake_addr = 'tb1qupyd58ndsh7lut0et0vtrq432jvu9jtdyws9n9'
    bad_key = OUT_CTRL_ADDRESS + fake_addr
    url = 'bitcoin:%s?amount=1&%s=1' % (addr, bad_key)

    goto_home()
    need_keypress(KEY_QR)
    time.sleep(.1)
    scan_a_qr(url)
    time.sleep(.5)

    title, body = cap_story()
    assert title == 'Payment Address'
    assert 'And values for: (corrupt)' in body
    assert fake_addr not in body
    press_cancel()


@pytest.mark.onetime
def test_dump_menutree(sim_execfile):
    # saves to ../unix/work/menudump.txt
    sim_execfile('devtest/menu_dump.py')

if 0:
    # show what the final word can be (debug only) Mk4 only
    def test_23_words(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words, cap_screen_qr, qr_quality_check):
        
        unit_test('devtest/clear_seed.py')

        m = cap_menu()
        assert m[0] == 'New Seed Words'    
        pick_menu_item('Import Existing')

        seed_words = 'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary'

        sw = seed_words.split(' ')
        pick_menu_item('24 Words')

        word_menu_entry(sw)

        print('\n'.join(cap_menu()))


# EOF
