# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# trick_pins.py - manage the "trick" PIN codes, which can do anything but let you in!
#
# - mk4+ only
# - uses SE2 to storage PIN codes and actions to perform
# - replaces old "duress wallet" and "brickme" features 
# - changes require knowledge of real PIN code (it is checked)
# 
import version, uctypes, errno
from ubinascii import hexlify as b2a_hex

''' from se2.h
{
    int         slot_num;           // or -1 if not found
    uint8_t     tc_flags;           // TC_* bitmask
    uint8_t     arg;                // one byte of argument is stored.
    uint8_t     seed_words[32];     // binary
    char        pin[16];            // ascii
    int         pin_len;
    uint32_t    blank_slots;        // 1 indicates unused slot
    uint32_t    spare[8];           // RFU
} trick_slot_t;
'''
TRICK_SLOT_LAYOUT = {
    "slot_num": 0 | uctypes.INT32,
    "tc_flags": 4 | uctypes.UINT8,
    "arg": 5 | uctypes.UINT8,
    "_align1": 6 | uctypes.UINT8,
    "_align2": 7 | uctypes.UINT8,
    "seed_words": (8 | uctypes.ARRAY, 32 | uctypes.UINT8),
    "pin": (8+32 | uctypes.ARRAY, 16 | uctypes.UINT8),
    "pin_len": (8+32+16) | uctypes.INT32,
    "blank_slots": (8+32+16+4) | uctypes.UINT32,
    "spare": ((8+32+16+4+4) | uctypes.ARRAY, 8|uctypes.INT32),
}
TC_WIPE         = const(0x80)
TC_BRICK        = const(0x40)
TC_FAKE_OUT     = const(0x20)
TC_WALLET       = const(0x10)
TC_BOOTROM_MASK = const(0xf0)
NUM_TRICKS      = const(14)

def make_slot():
    b = bytearray(uctypes.sizeof(TRICK_SLOT_LAYOUT))
    return b, uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)

class TrickPinMgmt:

    def __init__(self):
        assert uctypes.sizeof(TRICK_SLOT_LAYOUT) == 96

        # we track known PINS as a dictionary:
        # key=pin
        # value=(tc_flags, arg, ...)
        from glob import settings
        self.tp = settings.get('tp', {})

    def update_record(self):
        from glob import settings
        settings.set('tp', self.tp)

    def roundtrip(self, method_num, slot_buf=None):
        from pincodes import pa

        if slot_buf is not None:
            arg = slot_buf
        else:
            # use zeros
            arg = bytes(uctypes.sizeof(TRICK_SLOT_LAYOUT))

        rc, data = pa.trick_request(method_num, arg)

        if slot_buf is not None:
            # overwrite request w/ result (works inplace)
            slot_buf[:] = data

        return rc

    def clear_all(self):
        # get rid of them all
        self.roundtrip(0)
        self.tp = {}
        self.update_record()

    def clear_slots(self, slot_nums):
        # remove some slots, not all
        b, slot = make_slot()
        slot.blank_slots = sum(1<<s for s in slot_nums)
        self.roundtrip(2)

    def get_empty_slot(self, qty_needed=1):
        # do impossible search, so we can get block_slots field back
        b, slot = make_slot()
        slot.pin_len = 1
        self.roundtrip(1, b)
        blk = slot.blank_slots
        avail = [i for i in range(NUM_TRICKS) if (1<<i & blk)]
        if qty_needed == 1:
            return avail[0] if avail else None
        else:
            for sn in avail:
                if all((sn+i in avail) for i in range(1, qty_needed)):
                    return sn
            return None

    def get_by_pin(self, pin):
        # fetch slot details based on a PIN code (which must be known already somehow)
        b, slot = make_slot()

        slot.pin_len = len(pin)
        slot.pin[0:slot.pin_len] = pin

        rc = self.roundtrip(1, b)
        if rc == errno.ENOENT:
            return None, None

        # these fields are zeros on return:
        #slot.pin_len = len(pin)
        #slot.pin[0:slot.pin_len] = pin

        return b, slot

    def update_slot(self, pin, new_pin=None, tc_flags=None, arg=None, seed=None, node=None):
        # create or update a trick pin
        b, slot = self.get_by_pin(pin)
        if not slot:
            b, slot = make_slot()
            assert new_pin == pin

            # pick a free slot
            sn = self.get_empty_slot(bool(seed))
            if sn == None:
                # we are full
                raise RuntimeError("no space")

            slot.slot_num = sn

        if new_pin is not None:
            slot.pin_len = len(pin)
            slot.pin[0:slot.pin_len] = pin
        if tc_flags is not None:
            slot.tc_flags = tc_flags
        if arg is not None:
            slot.arg = arg
        if seed is not None:
            assert len(seed) == 32
            slot.tc_flags |= TC_WALLET
            slot.seed_words[:] = seed

        slot.blank_slots = 0
        rc = self.roundtrip(2, b)
        assert rc == 0

        return b, slot

tp = TrickPinMgmt()

# EOF
