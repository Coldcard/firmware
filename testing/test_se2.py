# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Mk4 SE2 (second secure element) test cases and fixtures.
#
import pytest, struct, time
from helpers import B2A
from binascii import b2a_hex, a2b_hex
from collections import namedtuple


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

from collections import namedtuple
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
        assert len(buf) == 128

        cmd = 'from pincodes import pa; import struct; '\
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
    for i in range(NUM_TRICKS):
        s = make_slot(slot_num=i, pin=('%02d'%i).encode(), pin_len=2, tc_flags=i)
        rc, data = se2_gate(2, s)
        assert rc == 0

    # read back
    for i in range(NUM_TRICKS):
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
    assert got.tc_flags == got.tc_arg == got.blank_slots == 0
        
    rc, data = se2_gate(0)     # clear all
    assert rc == 0

    # test all cleared
    for i in range(NUM_TRICKS):
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
    for i in range(NUM_TRICKS):
        s = make_slot(slot_num=i, pin=('%02d'%i).encode(), pin_len=2, tc_flags=i)
        rc, data = se2_gate(2, s)
        assert rc == 0

    blanked = [ 2,3,  8, 12 ]
    bmask = sum(1<<n for n in blanked)
    s = make_slot(slot_num=0, pin=b'junk', pin_len=4, blank_slots=bmask)
    rc, data = se2_gate(2, s)
    assert rc==0

    # read back
    # - slot zero should be unaffected by the above
    for i in range(NUM_TRICKS):
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

def test_trick_menus(goto_home, pick_menu_item, cap_menu, need_keypress, enter_pin):
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Login Settings')
    pick_menu_item('Trick PINs')

    for step in range(2):
        menu = cap_menu()
        has_some = (menu[1][0] == '↳')
        if has_some:
            assert menu[0] == 'Trick PINs:'
            assert 'Delete All' in menu
        else:
            assert 'Delete All' not in menu
            assert menu[-2] == 'Add New Trick'

        has_wrong = ('↳WRONG PIN' in menu)
        if not has_wrong:
            assert 'Add If Wrong' in menu
        else:
            assert 'Add If Wrong' not in menu

        if not has_some and not has_wrong:
            assert len(menu) == 2

        if has_some:
            assert step == 0
            pick_menu_item('Delete All')
            time.sleep(.1)
            need_keypress('y')
            time.sleep(.1)
        else:
            break
    # all clear now


@pytest.fixture(scope='function')
def new_trick_pin(goto_home, pick_menu_item, cap_menu, need_keypress, cap_story, enter_pin, se2_gate):
    # using menus and UX, setup a new trick PIN
    def doit(new_pin, op_mode, expect=None):
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Login Settings')
        pick_menu_item('Trick PINs')

        m = cap_menu()
        if f'↳{new_pin}' in m:
            # delete it first
            pick_menu_item(f'↳{new_pin}')
            pick_menu_item('Delete Trick')

            time.sleep(.1)
            _,story = cap_story()
            assert 'Are you SURE' in story
            if 'on this duress wallet' in story:
                # extra confirm step, seen only for trick pins which lead to duress wallet
                time.sleep(.1)
                need_keypress('y')

                time.sleep(.1)
                _,story = cap_story()
                assert 'Are you SURE' in story

            assert new_pin in story
            time.sleep(.1)
            need_keypress('y')

            time.sleep(.1)
            m = cap_menu()
            assert f'↳{new_pin}' not in m

            # test really blanked in SE2
            rc, sl = se2_gate(1, make_slot(pin=new_pin.encode('ascii'), pin_len=len(new_pin)))
            assert rc == ENOENT

        pick_menu_item('Add New Trick')
        words = enter_pin(new_pin)

        
        if new_pin[0:3] == '11-':
            # for simulator at least:
            assert words == ['quality', 'antique']
        else:
            print(f'{pin} => {words}')

        time.sleep(.1)
        m = cap_menu()
        assert m[0] == f'[{new_pin}]'
        assert set(m[1:]) == {'Duress Wallet', 'Just Reboot', 'Wipe Seed', \
                                'Delta Mode', 'Look Blank', 'Brick Self', 'Login Countdown'}

        pick_menu_item(op_mode)
        
        _, story = cap_story()
        if expect:
            assert expect in story
        need_keypress('y')

    return doit

@pytest.fixture(scope='function')
def new_pin_confirmed(cap_menu, need_keypress, cap_story, se2_gate):
    # from Ok? screen, check it worked right
    def doit(new_pin, op_mode, xflags, xargs=0):
        _, story = cap_story()
        assert f'PIN {new_pin}' in story
        assert op_mode in story
        assert story.endswith('Ok?')

        need_keypress('y')

        # should be back on trick-menu page, with new one there
        m = cap_menu()
        assert f'↳{new_pin}' in m
        assert m[0] == 'Trick PINs:'

        # check SE2 setup right
        
        rc, sl = se2_gate(1, make_slot(pin=new_pin.encode('ascii'), pin_len=len(new_pin)))
        assert rc == 0
        sl = decode_slot(sl)
        assert sl.pin[0:sl.pin_len].decode('ascii') == new_pin
        assert sl.tc_flags == xflags
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
def test_add_simple(new_pin, op_mode, expect, but_dont, xflags, 
                new_trick_pin, new_pin_confirmed, goto_home, pick_menu_item, cap_menu, need_keypress, cap_story, enter_pin):

    new_trick_pin(new_pin, op_mode, expect)

    if but_dont:
        need_keypress('x')
        return

    new_pin_confirmed(new_pin, op_mode, xflags)

@pytest.mark.parametrize('subchoice, expect, xflags', [
    ( 'Wipe & Reboot', 'wiped and Coldcard reboots', TC_WIPE|TC_REBOOT ),
    ( 'Silent Wipe', 'code was just wrong', TC_WIPE|TC_FAKE_OUT ),
    ( 'Say Wiped, Stop', 'message is shown', TC_WIPE ),
])
def test_wipe_choices_1(subchoice, expect, xflags, 
        new_trick_pin, new_pin_confirmed, cap_menu, pick_menu_item, cap_story, need_keypress):

    # first level only, see test_duress_choices() for wipe+duress/other choices

    new_pin = '11-123'
    new_trick_pin(new_pin, 'Wipe Seed', 'Wipe the seed and maybe do')
    m = cap_menu()

    pick_menu_item(subchoice)

    _, story = cap_story()
    assert expect in story

    need_keypress('y')

    new_pin_confirmed(new_pin, subchoice, xflags)
    
@pytest.mark.parametrize('with_wipe', [False, True])
@pytest.mark.parametrize('subchoice, expect, xflags, xargs', [
    ( 'BIP-85 Wallet #1', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1001 ),
    ( 'BIP-85 Wallet #2', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1002 ),
    ( 'BIP-85 Wallet #3', "functional 'duress' wallet", TC_WIPE|TC_WORD_WALLET, 1003 ),
    ( 'Legacy Wallet', 'fixed derivation', TC_WIPE|TC_XPRV_WALLET, 0 ),
    ( 'Blank Coldcard', 'freshly wiped Coldcard', TC_WIPE|TC_BLANK_WALLET, 0 ),
])
def test_duress_choices(with_wipe, subchoice, expect, xflags, xargs,
        new_trick_pin, new_pin_confirmed, cap_menu, pick_menu_item, cap_story, need_keypress):

    # after Wipe Seed -> Wipe->Wallet choice, another level

    new_pin = '11-234'
    if with_wipe:
        new_trick_pin(new_pin, 'Wipe Seed', 'Wipe the seed and maybe do more')

        pick_menu_item('Wipe -> Wallet')
        _, story = cap_story()
        assert 'Seed is silently wiped, and' in story
        need_keypress('y')
    else:
        new_trick_pin(new_pin, 'Duress Wallet', 'Goes directly to a specific duress wallet')
        xflags &= ~TC_WIPE

    pick_menu_item(subchoice)
    _, story = cap_story()
    assert expect in story
    need_keypress('y')

    op_mode = subchoice 
    if with_wipe:
        op_mode += ' (after wiping secret)'

    new_pin_confirmed(new_pin, op_mode, xflags, xargs)


# EOF
