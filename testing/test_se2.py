# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Mk4 SE2 (second secure element) test cases and fixtures.
#
import pytest, struct
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
def se2_ll_gate(sim_exec):
    # low-level method
    def doit(buf_io, arg2):
        got = sim_exec('b=bytearray(%r); ckcc.gate(22, b, %r); repr([rv, b])' % (buf_io, arg2))
        print(got)

    return doit

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

def test_se2_clear_n_set(se2_gate):
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

# EOF
