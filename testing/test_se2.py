# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Mk4 SE2 (second secure element) test cases and fixtures.
#
# - use 'simulator.py' without '--eff' for these
#
import pytest, struct, time
from collections import namedtuple
from mnemonic import Mnemonic

# see from mk4-bootloader/se2.h and/or shared/trick_pins.py
const = lambda x: x
NUM_TRICKS      = const(14)
TC_WIPE         = const(0x8000)
TC_BRICK        = const(0x4000)
TC_FAKE_OUT     = const(0x2000)
TC_WORD_WALLET  = const(0x1000)
TC_XPRV_WALLET  = const(0x0800)
TC_DELTA_MODE   = const(0x0400)
TC_REBOOT       = const(0x0200)
TC_RFU          = const(0x0100)
TC_BLANK_WALLET = const(0x0080)
TC_COUNTDOWN    = const(0x0040)         # tc_arg = minutes of delay

ENOENT = 2
ALL_BLK = (1<<NUM_TRICKS)-1

# avoid using slot 10 due to bug141
BUG_SLOT = 10
SLOTS = [i for i in range(NUM_TRICKS) if i != BUG_SLOT]

# everything in this file is mk4 only
@pytest.fixture(autouse=True)
def THIS_FILE_requires_mk4plus(only_mk4plus):
    pass


'''
TRICK_SLOT_LAYOUT = {
    "slot_num": 0 | uctypes.INT32,
    "tc_flags": 4 | uctypes.UINT16,
    "tc_arg": 6 | uctypes.UINT16,
    "xdata": (8 | uctypes.ARRAY, 64 | uctypes.UINT8),
    "pin": (8+64 | uctypes.ARRAY, 16 | uctypes.UINT8),
    "pin_len": (8+64+16) | uctypes.INT32,
    "blank_slots": (8+64+16+4) | uctypes.UINT32,
    "spare": ((8+64+16+4+4) | uctypes.ARRAY, 8|uctypes.INT32),
}
'''
TRICK_FMT = 'IHH64s16sII32s'
TRICK_FMT_FLDS = 'slot_num tc_flags tc_arg xdata pin pin_len blank_slots spare'
assert struct.calcsize(TRICK_FMT) == 128

SlotInfo = namedtuple('SlotInfo', TRICK_FMT_FLDS)

def make_slot(**kws):
    for f in 'slot_num tc_flags tc_arg pin_len blank_slots'.split():
        kws.setdefault(f, 0)
    for f in 'xdata pin spare'.split():
        kws.setdefault(f, b'')

    return SlotInfo(**kws)

def decode_slot(data):
    assert len(data) == 128
    return SlotInfo(*struct.unpack(TRICK_FMT, data))

@pytest.fixture(scope='function')
def se2_gate(sim_exec):
    # not-so-low-level method: include auth data for main PIN
    def doit(method_num, obj=None, buf=None):
        # rc, data = 
        if obj:
            buf = struct.pack(TRICK_FMT, *obj)
        elif not buf:
            buf = bytes(128)
        assert b'Traceback' not in buf, buf
        assert len(buf) == 128

        cmd = 'import struct; '\
            f'rc,b = pa.trick_request({method_num}, {buf!r}); RV.write(struct.pack("I", rc) + b)'
        #print(cmd)
        rv = sim_exec(cmd, binary=1)
        assert len(rv) == 4 + 128, repr(rv)
        rc, = struct.unpack('I', rv[0:4])
        return rc, rv[4:]

    return doit

# CRUD on the trick-PIN slots
# - see ../stm32/mk4-bootloader/se2.c
# - vs ../unix/variant/sim_se2.py

def test_se2_clear_n_set(se2_gate):
    # simple stuff
    rc, data = se2_gate(0)     # clear all
    assert rc == 0


    # fill it
    for i in SLOTS:
        s = make_slot(slot_num=i, pin=('%02d'%i).encode(), pin_len=2, tc_flags=i)
        rc, data = se2_gate(2, s)
        assert rc == 0

    # read back
    for i in SLOTS:
        xp = ('%02d'%i).encode()
        s = make_slot(pin=xp, pin_len=2)
        rc, data = se2_gate(1, s)
        got = decode_slot(data)
        assert got.slot_num == got.tc_flags == i

    # test all full
    s = make_slot(pin=b'junk', pin_len=4)
    rc, data = se2_gate(1, s)
    assert rc == ENOENT
    got = decode_slot(data)
    assert got.slot_num == 0xffff_ffff
    assert got.tc_flags == got.tc_arg == 0
    assert got.blank_slots in (0, (1<<BUG_SLOT))        # workaround in place
        
    rc, data = se2_gate(0)     # clear all
    assert rc == 0

    # test all cleared
    for i in SLOTS:
        xp = ('%02d'%i).encode()
        s = make_slot(pin=xp, pin_len=2)
        rc, data = se2_gate(1, s)
        assert rc == ENOENT
        got = decode_slot(data)
        assert got.slot_num == 0xffff_ffff
        assert got.tc_flags == got.tc_arg == 0
        assert got.blank_slots == ALL_BLK


def test_blank_slots(se2_gate):
    # arbitrary slots can be blanked
    rc, data = se2_gate(0)     # clear all
    assert rc == 0

    # fill it
    for i in SLOTS:
        s = make_slot(slot_num=i, pin=('%02d'%i).encode(), pin_len=2, tc_flags=i)
        rc, data = se2_gate(2, s)
        assert rc == 0

    blanked = [ 2,3,  8, 12, BUG_SLOT ]
    bmask = sum(1<<n for n in blanked)
    s = make_slot(slot_num=0, pin=b'junk', pin_len=4, blank_slots=bmask)
    rc, data = se2_gate(2, s)
    assert rc==0

    # read back
    # - slot zero should be unaffected by the above
    for i in SLOTS:
        xp = ('%02d'%i).encode()
        s = make_slot(pin=xp, pin_len=2)
        rc, data = se2_gate(1, s)
        got = decode_slot(data)
        if i in blanked:
            assert rc == ENOENT
            assert got.blank_slots == bmask
        else:
            assert rc == 0
            assert got.slot_num == got.tc_flags == i

@pytest.fixture
def goto_trick_menu(goto_home, pick_menu_item, cap_menu):
    def doit():
        menu = cap_menu()       # bugfix
        if menu[0] in {'Trick PINs:', 'Add New Trick'}:
            return
        if 'New Seed Words' in menu:
            raise pytest.skip("need seed set first for these tests")

        goto_home()
        time.sleep(.1)
        pick_menu_item('Settings')
        time.sleep(.1)
        menu = cap_menu()
        while "Login Settings" not in menu:
            time.sleep(.3)
            menu = cap_menu()
        pick_menu_item('Login Settings')
        time.sleep(.1)
        menu = cap_menu()
        while "Trick PINs" not in menu:
            time.sleep(.3)
            menu = cap_menu()
        pick_menu_item('Trick PINs')

    return doit

@pytest.fixture
def clear_all_tricks(goto_trick_menu, pick_menu_item, press_select, cap_story):
    def doit():
        goto_trick_menu()
        time.sleep(.1)
        pick_menu_item('Delete All')
        time.sleep(.1)
        press_select()
        time.sleep(.1)
        _, story = cap_story()
        if 'duress wallet' in story:
            time.sleep(.1)
            press_select()

    return doit

def test_ux_trick_menus(goto_trick_menu, pick_menu_item, cap_menu,
                        press_select, cap_story):
    # get there, and wipe any existing
    goto_trick_menu()

    for step in range(2):
        menu = cap_menu()
        has_some = (menu[1][0] == '↳')
        if has_some:
            assert menu[0] == 'Trick PINs:'
        else:
            assert menu[-3] == 'Add New Trick'

        assert 'Delete All' in menu

        has_wrong = ('↳WRONG PIN' in menu)
        if not has_wrong:
            assert 'Add If Wrong' in menu
        else:
            assert 'Add If Wrong' not in menu

        if not has_some and not has_wrong:
            assert len(menu) == 3

        if not has_some:
            break

        assert step == 0
        pick_menu_item('Delete All')
        time.sleep(.1)
        press_select()
        time.sleep(.1)
        title, story = cap_story()

        if 'SURE' in story:
            time.sleep(.1)
            assert 'duress wallet' in story
            press_select()
            time.sleep(.1)

    # all clear now


@pytest.fixture(scope='function')
def new_trick_pin(goto_trick_menu, pick_menu_item, cap_menu, press_select,
                  cap_story, enter_pin, se2_gate, is_simulator, is_q1):
    # using menus and UX, setup a new trick PIN
    def doit(new_pin, op_mode, expect=None):
        goto_trick_menu()

        m = cap_menu()
        if f'↳{new_pin}' in m:
            # delete it first
            pick_menu_item(f'↳{new_pin}')
            pick_menu_item('Delete Trick')

            time.sleep(.1)
            title, story = cap_story()
            where = title if is_q1 else story
            assert 'Are you SURE' in where
            if 'on this duress wallet' in story:
                # extra confirm step, seen only for trick pins which lead to duress wallet
                time.sleep(.1)
                press_select()

                time.sleep(.1)
                title, story = cap_story()
                where = title if is_q1 else story
                assert 'Are you SURE' in where

            assert new_pin in story
            time.sleep(.1)
            press_select()

            time.sleep(.1)
            m = cap_menu()
            assert f'↳{new_pin}' not in m

            # test really blanked in SE2
            rc, sl = se2_gate(1, make_slot(pin=new_pin.encode('ascii'), pin_len=len(new_pin)))
            assert rc == ENOENT

        pick_menu_item('Add New Trick')
        words = enter_pin(new_pin)

        # for simulator at least, we know this... but not when used in "bare metal" mode.
        #if is_simulator() and new_pin[0:3] == '11-':
        #    assert words == ['quality', 'antique']

        time.sleep(.1)
        m = cap_menu()
        assert m[0] == f'[{new_pin}]'
        assert set(m[1:]) == {'Duress Wallet', 'Just Reboot', 'Wipe Seed', \
                                'Delta Mode', 'Look Blank', 'Brick Self', 'Login Countdown'}

        pick_menu_item(op_mode)
        
        time.sleep(.1)
        _, story = cap_story()
        if expect:
            assert expect in story
        press_select()

    return doit

@pytest.fixture(scope='function')
def new_pin_confirmed(cap_menu, press_select, cap_story, se2_gate):
    # from Ok? screen, check it worked right
    def doit(new_pin, op_mode, xflags, xargs=0, confirm=True):
        if confirm:
            time.sleep(.1)
            _, story = cap_story()
            assert f'PIN {new_pin}' in story
            assert op_mode in story
            assert story.endswith('Ok?')

            press_select()

        # should be back on trick-menu page, with new one there
        m = cap_menu()
        assert f'↳{new_pin}' in m
        assert m[0] == 'Trick PINs:'

        # check SE2 setup right
        
        rc, sl = se2_gate(1, make_slot(pin=new_pin.encode('ascii'), pin_len=len(new_pin)))
        assert rc == 0
        sl = decode_slot(sl)
        if sl.pin_len:
            assert sl.pin[0:sl.pin_len].decode('ascii') == new_pin      # simulator only

        if xflags is not None:
            assert sl.tc_flags == xflags
        if xargs is not None:
            assert sl.tc_arg == xargs

    return doit

@pytest.mark.parametrize('new_pin, op_mode, expect, but_dont, xflags', [
    ('11-33', 'Just Reboot', 'Reboot when this PIN', False, TC_REBOOT), 
    ('11-55', 'Look Blank', 'Look and act like a freshly', False, TC_BLANK_WALLET), 
    ('11-66', 'Brick Self', 'Become a brick instantly', False, TC_BRICK), 
    ('11-44', 'Wipe Seed', 'Wipe the seed and maybe do', True, 0),  # see wipe_choices_1
    ('11-77', 'Duress Wallet', 'Goes directly to a ', True, 0),     # see duress_choices
    ('11-88', 'Login Countdown', 'Pretends a login countdown', True, 0), 
    ('11-99', 'Delta Mode', 'Logs into REAL seed', True, 0), 
])
def test_ux_add_simple(new_pin, op_mode, expect, but_dont, xflags, 
                new_trick_pin, new_pin_confirmed, press_cancel, enter_pin
):
    # Do the simple ones, test the first level of the others
    new_trick_pin(new_pin, op_mode, expect)

    if but_dont:
        press_cancel()
    else:
        new_pin_confirmed(new_pin, op_mode, xflags)

@pytest.mark.parametrize('num_wrong', [0, 1, 3, 9, 99])
@pytest.mark.parametrize('op_mode, expect, xflags', [
    ('Wipe, Stop', 'Seed is wiped and a message', TC_WIPE), 
    ('Wipe & Reboot', 'Seed is wiped and Coldcard reboots', TC_WIPE|TC_BLANK_WALLET), 
    ('Silent Wipe', 'Seed is silently wiped', TC_WIPE|TC_FAKE_OUT), 
    ('Brick Self', 'Become a brick instantly', TC_BRICK),
    ('Last Chance', 'Wipe seed, then give one more try', TC_WIPE|TC_BRICK),
    # ('Look Blank', 'Look and act like a freshly', TC_BLANK_WALLET),
    ('Just Reboot', 'Reboot when this ', TC_REBOOT), 
])
def test_ux_wrong_pin(num_wrong, op_mode, expect, xflags, enter_number,
                      cap_menu, pick_menu_item, cap_story, goto_trick_menu,
                      new_pin_confirmed, press_select, enter_pin, is_q1):
    # wrong pin choices, not implementation
    goto_trick_menu()
    pick_menu_item('Add If Wrong')
    time.sleep(.1)
    _, story = cap_story()
    assert 'After N incorrect' in story

    press_select()
    enter_number(num_wrong)

    time.sleep(.1)
    m = cap_menu()

    real_num_wrong = num_wrong
    if num_wrong <= 1:
        real_num_wrong = 1
        assert m[0] == '[ANY WRONG PIN]'
    elif num_wrong >= 12:
        real_num_wrong = 12
        assert m[0] == '[12th WRONG PIN]'
    else:
        assert m[0][0:2] == f'[{num_wrong}'
        assert m[0].endswith(' WRONG PIN]')

    pick_menu_item(op_mode)
        
    time.sleep(.1)
    _, story = cap_story()
    assert expect in story

    time.sleep(.1)
    press_select()
    time.sleep(.1)
    _, story = cap_story()
    assert f"{real_num_wrong} Wrong PINs" in story
    assert op_mode in story
    assert "Ok?" in story
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert 'Add If Wrong' not in m
    pick_menu_item('↳WRONG PIN')
    pick_menu_item('Delete Trick')
    time.sleep(.1)
    title, story = cap_story()
    where = title if is_q1 else story
    assert "Are you SURE" in where
    assert "Remove special handling of wrong PINs?" in story
    press_select()
    time.sleep(.1)


@pytest.mark.parametrize('subchoice, expect, xflags', [
    ( 'Wipe & Reboot', 'wiped and Coldcard reboots', TC_WIPE|TC_REBOOT ),
    ( 'Silent Wipe', 'code was just wrong', TC_WIPE|TC_FAKE_OUT ),
    ( 'Say Wiped, Stop', 'message is shown', TC_WIPE ),
])
def test_ux_wipe_choices_1(subchoice, expect, xflags,  new_trick_pin,
                           new_pin_confirmed, pick_menu_item, cap_story,
                           press_select):

    # first level only, see test_duress_choices() for wipe+duress/other choices

    new_pin = '11-123'
    new_trick_pin(new_pin, 'Wipe Seed', 'Wipe the seed and maybe do')

    pick_menu_item(subchoice)

    _, story = cap_story()
    assert expect in story

    press_select()

    new_pin_confirmed(new_pin, subchoice, xflags)


@pytest.mark.parametrize('subchoice, expect, xflags', [
    ('Wipe & Countdown', 'Seed is wiped at start of countdown', TC_WIPE|TC_COUNTDOWN),
    ('Countdown & Brick', 'countdown, then system is bricked', TC_WIPE|TC_BRICK|TC_COUNTDOWN),
    ('Just Countdown', 'has no effect on seed', TC_COUNTDOWN),
])
def test_ux_countdown_choices(subchoice, expect, xflags, new_trick_pin, new_pin_confirmed,
                              pick_menu_item, cap_story, need_keypress, press_select,
                              press_cancel):

    # first level only, see test_duress_choices() for wipe+duress/other choices
    new_pin = '11-123'
    default_duration = 60  # in minutes
    new_trick_pin(new_pin, 'Login Countdown', 'Pretends a login countdown timer')

    pick_menu_item(subchoice)

    _, story = cap_story()
    assert expect in story

    press_select()

    new_pin_confirmed(new_pin, subchoice, xflags, default_duration)

    # proof for off by one bug in version<=5.1.4
    prev = "(1 hour)"
    for label, val in [(" 5 minutes", 5), ("24 hours", 24*60),
                      (" 3 days", 3*24*60), (" 1 week", 7*24*60),
                      ("28 days later", 28*24*60)]:
        # change duration
        pick_menu_item(f'↳{new_pin}')
        pick_menu_item(f'↳Countdown')
        time.sleep(.1)
        _, story = cap_story()
        assert prev in story
        assert "Press (4)" in story
        need_keypress("4")
        time.sleep(.1)
        pick_menu_item(label)
        time.sleep(.5)
        pick_menu_item(f'↳Countdown')
        _, story = cap_story()
        active_duration = "(" + label.strip() + ")"
        assert active_duration in story
        press_cancel()
        press_cancel()
        new_pin_confirmed(new_pin, subchoice, xflags, val, confirm=False)
        prev = active_duration


@pytest.mark.parametrize('with_wipe', [False, True])
@pytest.mark.parametrize('words12', [False, True])
@pytest.mark.parametrize('subchoice, expect, xflags, xargs', [
    ( 'BIP-85 Wallet #1', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1001 ),
    ( 'BIP-85 Wallet #2', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1002 ),
    ( 'BIP-85 Wallet #3', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1003 ),
    ( 'Legacy Wallet', 'fixed derivation', TC_WIPE|TC_XPRV_WALLET, 0 ),
    # ( 'Blank Coldcard', 'freshly wiped Coldcard', TC_WIPE|TC_BLANK_WALLET, 0 ),
])
def test_ux_duress_choices(with_wipe, subchoice, expect, xflags, xargs, words12,
        reset_seed_words, repl, clear_all_tricks, import_ms_wallet, get_setting, clear_ms,
        new_trick_pin, new_pin_confirmed, cap_menu, pick_menu_item, cap_story, need_keypress,
        press_select, press_cancel, seed_story_to_words, is_q1, set_seed_words,
        stop_after_activated=False,

):
    if words12:
        # random 12 word mnemonic
        set_seed_words("message upset stumble decorate measure milk "
                       "east eternal soon hover middle mean")
        if subchoice != 'Legacy Wallet':
            xargs += 1000

    # import multisig
    clear_ms()
    import_ms_wallet(2, 2, dev_key=words12)
    press_select()
    time.sleep(.1)
    assert len(get_setting('multisig')) == 1

    # after Wipe Seed -> Wipe->Wallet choice, another level
    clear_all_tricks()

    new_pin = '11-234'
    if with_wipe:
        new_trick_pin(new_pin, 'Wipe Seed', 'Wipe the seed and maybe do more')

        pick_menu_item('Wipe -> Wallet')
        _, story = cap_story()
        assert 'Seed is silently wiped, and' in story
        press_select()
    else:
        new_trick_pin(new_pin, 'Duress Wallet', 'Goes directly to a specific duress wallet')
        xflags &= ~TC_WIPE

    pick_menu_item(subchoice)
    _, story = cap_story()
    assert expect in story
    press_select()

    op_mode = subchoice 
    if with_wipe:
        op_mode += ' (after wiping secret)'

    new_pin_confirmed(new_pin, op_mode, xflags, xargs)

    if with_wipe or (TC_BLANK_WALLET & xflags):
        return

    # check saved wallet data is right
    # - duress wallet math is right, bip85 and legacy
    # - test apply wallet feature
    pick_menu_item(f'↳{new_pin}')
    m = cap_menu()
    assert 'Activate Wallet' in m
    pick_menu_item('↳Duress Wallet')
    _, story = cap_story()
    assert ('BIP-85 derived' in story) or ('The legacy' in story)
    assert (f'#{xargs}' in story) or ('XPRV-based' in story)
    assert 'Press (6) to view associated' in story
    need_keypress('6')
    time.sleep(.1)
    _, story = cap_story()

    from bip32 import BIP32Node

    if story[1:4] == 'prv':
        assert TC_XPRV_WALLET & xflags
        wallet = BIP32Node.from_wallet_key(story)
    else:
        if is_q1:
            words = seed_story_to_words(story)
        else:
            ln = story.split('\n')
            assert ln[0] == ('Seed words (12):' if words12 else 'Seed words (24):')
            words = [i[4:] for i in ln[1:25]]

        seed = Mnemonic.to_seed(' '.join(words), passphrase='')
        wallet = BIP32Node.from_master_secret(seed, netcode='XTN')      # dev might be BTC

    press_cancel()
    time.sleep(.1)
    pick_menu_item('Activate Wallet')
    time.sleep(.1)
    _, story = cap_story()
    assert 'This will temporarily load' in story

    press_select()
    time.sleep(.1)
    if stop_after_activated: return
    _, story = cap_story()
    assert 'temporary master key is in effect now' in story

    xp = repl.eval("settings.get('xpub')")
    assert xp == wallet.hwif(as_private=False)

    assert not get_setting('multisig')  # multisig is not copied

    # re-login to recover normal seed
    reset_seed_words()
    repl.exec('pa.tmp_value=False; pa.setup(pa.pin); pa.login()')


@pytest.mark.parametrize('true_pin, fake_pin, is_prob, expect_arg', [
    ( '12-12', '23-23', False, 0x1212), 
    ( '99-99', '23-23', False, 0x9999), 
    ( '123-123', '44-44', True, 0), 
    ( '123-123', '444-444', True, 0), 
    ( '123-123', '443-123', True, 0), 
    ( '443-123', '444-444', False, 0x3123), 
    ( '123-121', '123-124', False, 0xfff1), 
    ( '123-122', '123-144', False, 0xff22), 
    ( '123-123', '123-444', False, 0xf123), 
    ( '123-124', '124-444', False, 0x312f), 
])
def test_deltamode_validate(true_pin, fake_pin, is_prob, expect_arg, sim_exec):
    # unit test: validate/calc delta mode values
    # - all strings here, no bytes
    cmd = f'from trick_pins import validate_delta_pin; '\
            f'RV.write(str(validate_delta_pin({true_pin!r}, {fake_pin!r})))'
    prob, tc_arg = eval(sim_exec(cmd))
    assert bool(prob) == is_prob, prob
    assert expect_arg == tc_arg, 'got 0x%04x' % tc_arg

    if is_prob: return

    # try it out, low-level
    pin_b4 = sim_exec('RV.write(pa.pin)')
    assert isinstance(pin_b4, str) and 'b' not in pin_b4

    try:
        if pin_b4 != true_pin:
            # change main pin
            rv = sim_exec(f'RV.write(repr(pa.change(new_pin=b{true_pin!r})))')
            assert rv == 'None'
            rv = sim_exec(f'pa.setup(b{true_pin!r}); RV.write(repr(pa.login()))')
            assert rv == 'True'

        # save a slot w/ new delta-mode trick
        cmd = f'from trick_pins import tp; '\
                f'b, s = tp.update_slot(b{fake_pin!r}, new=1, tc_flags={TC_DELTA_MODE}, tc_arg={tc_arg}); RV.write(repr(s.slot_num))'
        slot_num = eval(sim_exec(cmd))
        
        # try it out
        ok = eval(sim_exec(f'pa.setup(b{fake_pin!r}); RV.write(repr(pa.login()))'))
        assert ok, f'failed to login using: {fake_pin}'

        fl, ar = eval(sim_exec('RV.write(repr(pa.get_tc_values()))'))
        assert fl & TC_DELTA_MODE
        assert ar == 0      # gets blanked by bootrom

        is_d = eval(sim_exec('RV.write(repr(pa.is_deltamode()))'))
        assert is_d == True

        # restore: login to real 
        cmd = f'pa.setup(b{true_pin!r}); RV.write(repr(pa.login()))'
        ok = eval(sim_exec(cmd))
        assert ok, 'couldnt get back to real login from delta'

        is_d = eval(sim_exec('RV.write(repr(pa.is_deltamode()))'))
        assert is_d == False

        # delete slot
        cmd = f'from trick_pins import tp; tp.clear_slots([{slot_num}])'
        sim_exec(cmd)

        # restore main pin
        if pin_b4 != true_pin:
            rv = sim_exec(f'RV.write(repr(pa.change(new_pin=b{pin_b4!r})))')
            assert rv == 'None'
            rv = sim_exec(f'pa.setup(b{pin_b4!r}); RV.write(repr(pa.login()))')
            assert rv == 'True'

    except:
        # fix damage? hard to do
        print("REMINDER: Restart simulator to reset state!?")
        raise

from test_change_pins import change_pin, goto_pin_options, my_enter_pin

@pytest.fixture(scope='function')
def force_main_pin(change_pin, goto_pin_options, pick_menu_item, repl):
    # make main-pin match needs
    def doit(want_pin, expect_fail=None):
        pin_b4 = repl.eval('pa.pin').decode('ascii')
        if pin_b4 == want_pin:
            assert not expect_fail
            return
        goto_pin_options()
        pick_menu_item('Change Main PIN')
        change_pin(pin_b4, want_pin, "Main PIN", expect_fail=expect_fail)
        if not expect_fail:
            got = repl.eval('pa.pin')
            if isinstance(got, list):
                got = repl.eval('pa.pin')       # real-dev bugfix/workaround
            assert got.decode('ascii') == want_pin
        return pin_b4

    yield doit

    doit('12-12')

@pytest.mark.parametrize('true_pin, fake_pin, is_prob, expect_arg', [
    ( '12-12', '23-23', False, 0x1212), 
    ( '99-99', '23-23', False, 0x9999), 
    ( '123-123', '44-44', True, 0), 
    ( '123-123', '444-444', True, 0), 
    ( '123-123', '443-123', True, 0), 
    ( '443-123', '444-444', False, 0x3123), 
    ( '123-121', '123-124', False, 0xfff1), 
    ( '123-122', '123-144', False, 0xff22), 
    ( '123-123', '123-444', False, 0xf123), 
    ( '123-124', '124-444', False, 0x312f), 
])
def test_ux_deltamode_wrong(true_pin, fake_pin, is_prob, expect_arg, repl,
                            force_main_pin, clear_all_tricks, new_trick_pin,
                            new_pin_confirmed, cap_menu, pick_menu_item,
                            cap_story, press_select, press_cancel):

    force_main_pin(true_pin)

    clear_all_tricks()

    new_trick_pin(fake_pin, 'Delta Mode', 'somewhat riskier mode')

    if is_prob:
        _, story = cap_story()
        assert 'must be' in story
        press_cancel()

    else:
        new_pin_confirmed(fake_pin, 'Delta Mode', TC_DELTA_MODE, expect_arg)

        pick_menu_item('Delete All')
        time.sleep(.1)
        press_select()

@pytest.mark.parametrize('true_pin', ['12-12', '123456-123456'])
def test_ux_changing_pins(true_pin, repl, force_main_pin, goto_trick_menu,
        clear_all_tricks, new_trick_pin, new_pin_confirmed, pick_menu_item):

    # main vs. tricks
    force_main_pin(true_pin)

    clear_all_tricks()

    # make some delta pins
    pl = len(true_pin)
    if pl == 5:
        dmodes = ['23-23', '23-24', '44-44']
    else:
        dmodes = [true_pin[:-4]+'9999', true_pin[:-4]+'0000']

    for dp in dmodes:
        #dp = dp.encode('ascii')
        new_trick_pin(dp, 'Delta Mode', 'somewhat riskier mode')
        new_pin_confirmed(dp, 'Delta Mode', TC_DELTA_MODE, None)

    for dp in dmodes:
        force_main_pin(dp, expect_fail='already in use')

    if pl == 5:
        cases = ['5' + true_pin, '77777-77777']
    else:
        cases = ['7' + true_pin[1:], '000000-000000' ]

    for case in cases:
        force_main_pin(case, expect_fail='makes problems with a Delta Mode')

    clear_all_tricks()

def test_se2_trick_backups(goto_trick_menu, clear_all_tricks, repl, unit_test,
        new_trick_pin, new_pin_confirmed, pick_menu_item, press_select):
    def decode_backup(txt):
        import json
        vals = dict()
        trimmed = dict()
        for ln in txt.split('\n'):
            if not ln: continue
            if ln[0] == '#': continue

            k, v = ln.split(' = ', 1)

            v = json.loads(v)

            if k.startswith('duress_') or k.startswith('fw_'):
                # no space in USB xfer for thesE!
                trimmed[k] = v
            else:
                vals[k] = v

        return vals, trimmed

    clear_all_tricks()

    # - make wallets of all duress types (x2 each)
    # - plus a few simple ones
    # - perform a backup and check result

    for n in range(8):
        goto_trick_menu()
        pin = '123-%04d'%n
        new_trick_pin(pin, 'Duress Wallet', None)
        item = 'BIP-85 Wallet #%d' % (n%4) if (n%4 != 0) else 'Legacy Wallet'
        pick_menu_item(item)
        press_select()
        new_pin_confirmed(pin, item, None, None)

    for pin, op_mode, expect, _, xflags in [
        ('11-33', 'Just Reboot', 'Reboot when this PIN', False, TC_REBOOT), 
        ('11-55', 'Look Blank', 'Look and act like a freshly', False, TC_BLANK_WALLET), 
    ]:
        new_trick_pin(pin, op_mode, expect)
        new_pin_confirmed(pin, op_mode, xflags)

    # works, but not the best test
    #unit_test('devtest/backups.py')

    bk = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)

    assert 'Coldcard backup file' in bk

    # decode it
    vals, trimmed = decode_backup(bk)

    assert 'duress_xprv' in trimmed
    assert 'duress_1001_words' in trimmed
    assert 'duress_1002_words' in trimmed
    assert 'duress_1003_words' in trimmed

    unit_test('devtest/clear_seed.py')
    
    repl.exec(f'import backups; backups.restore_from_dict_ll({vals!r})')

    # recover from recovery
    repl.exec(f'import backups; pa.setup(pa.pin); pa.login(); from actions import goto_top_menu; goto_top_menu()')

    bk2 = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)
    assert 'Traceback' not in bk2

    vals2, tr2 = decode_backup(bk2)

    # HW switches are set to default OFF after clone or backup
    # changed here 7819f0b4d8d4e2c5efa666d0baf46817ad3000a7
    if 'setting.nfc' in vals and vals['setting.nfc']:
        vals['setting.nfc'] = 0  # restoring from backup always set NFC to default OFF
    if 'setting.vidsk' in vals and vals['setting.vidsk']:
        vals['setting.vidsk'] = 0  # restoring from backup always set VDisk to default OFF

    assert vals == vals2
    assert trimmed == tr2

def build_duress_wallets(request, seed_vault=False):
    # Call a bunch of stuff in this file to build out all 4 possible
    # duress wallets, and save them each into Seed Vault.

    # fixtures I need directly
    cap_story = request.getfixturevalue('cap_story')
    need_keypress = request.getfixturevalue('need_keypress')
    press_select = request.getfixturevalue('press_select')
    restore_main_seed = request.getfixturevalue('restore_main_seed')

    # fixtures I need in test_ux_duress_choices
    args = {f: request.getfixturevalue(f)
              for f in ['reset_seed_words', 'repl', 'clear_all_tricks', 'new_trick_pin', 'clear_ms',
                        'import_ms_wallet', 'get_setting', 'press_select', 'press_cancel', 'is_q1',
                        'new_pin_confirmed', 'cap_menu', 'pick_menu_item', 'cap_story', 'need_keypress',
                        'seed_story_to_words', 'set_seed_words']}

    for (subchoice, expect, xflags, xargs) in [
        ( 'BIP-85 Wallet #1', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1001 ),
        ( 'BIP-85 Wallet #2', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1002 ),
        ( 'BIP-85 Wallet #3', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1003 ),
        ( 'Legacy Wallet', 'fixed derivation', TC_WIPE|TC_XPRV_WALLET, 0 )
    ]:
        test_ux_duress_choices(subchoice=subchoice, expect=expect, xflags=xflags, xargs=xargs,
                               with_wipe=False, stop_after_activated=True, words12=False, **args)
        time.sleep(.1)
        _, story = cap_story()
        assert '(1) to store temporary seed' in story
        need_keypress('1')
        time.sleep(.1)
        _, story = cap_story()
        assert 'Saved to Seed Vault' in story

        press_select()
        time.sleep(0.1)
        _, story = cap_story()
        assert 'temporary master key is in effect now' in story
        press_select()

        # re-login to reset to normal seed
        # .. because cant get into trick menu when non-master seed is set (says Unavailable)
        restore_main_seed(seed_vault=seed_vault)

    # number of entries created
    return 4



# TODO
# - make trick and do login, check arrives right state?
# - out of slots
# - out of slots iff using wallet feature
# - countdown implementation?

# EOF
