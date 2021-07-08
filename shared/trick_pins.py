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

# see from mk4-bootloader/se2.h
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
TC_WIPE         = const(0x8000)
TC_BRICK        = const(0x4000)
TC_FAKE_OUT     = const(0x2000)
TC_WORD_WALLET  = const(0x1000)
TC_XPRV_WALLET  = const(0x0800)
TC_DELTA_MODE   = const(0x0400)
TC_REBOOT       = const(0x0200)
TC_RFU          = const(0x0100)
NUM_TRICKS      = const(14)

def make_slot():
    b = bytearray(uctypes.sizeof(TRICK_SLOT_LAYOUT))
    return b, uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)

class TrickPinMgmt:

    def __init__(self):
        assert uctypes.sizeof(TRICK_SLOT_LAYOUT) == 128

        # we track known PINS as a dictionary:
        # key=pin
        # value=(slot_num, tc_flags, arg, ...)
        from glob import settings
        self.tp = settings.get('tp', {})

    def update_record(self):
        from glob import settings
        settings.set('tp', self.tp)
        settings.save()

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

    def get_available_slots(self):
        # do an impossible search, so we can get block_slots field back
        b, slot = make_slot()
        slot.pin_len = 1
        self.roundtrip(1, b)        # expects ENOENT=2

        blk = slot.blank_slots
        return [i for i in range(NUM_TRICKS) if (1<<i & blk)]

    def find_empty_slots(self, qty_needed):
        # locate a slot (or 3) that are available for use
        avail = self.get_available_slots()
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

    def update_slot(self, pin, new=False, new_pin=None, tc_flags=None, tc_arg=None, secret=None):
        # create or update a trick pin
        # - doesn't support wallet to no-wallet transitions
        '''
        >>> from pincodes import pa; pa.setup(b'12-12'); pa.login(); from trick_pins import *
        '''
        assert isinstance(pin, bytes)

        b, slot = self.get_by_pin(pin)
        if not slot:
            if not new: raise KeyError("wrong pin")

            # Making a new entry
            b, slot = make_slot()
            new_pin = pin

            # pick a free slot
            sn = self.find_empty_slots(1 if not secret else 1+(len(secret)//32))
            if sn == None:
                # we are full
                raise RuntimeError("no space")

            slot.slot_num = sn

        if new_pin is not None:
            slot.pin_len = len(new_pin)
            slot.pin[0:slot.pin_len] = new_pin
            if new_pin != pin:
                self.tp.pop(pin, None)
            pin = new_pin

        if tc_flags is not None:
            assert 0 <= tc_flags <= 65536
            slot.tc_flags = tc_flags

        if tc_arg is not None:
            assert 0 <= tc_arg <= 65536
            slot.tc_arg = tc_arg

        if secret is not None:
            # expecting an encoded secret
            if len(secret) == 32:
                slot.tc_flags |= TC_WORD_WALLET
                slot.xdata[0:32] = secret
            elif len(secret) == 65:
                # expecting 65 bytes encoded already
                assert secret[0] == 0x01
                slot.tc_flags |= TC_XPRV_WALLET
                slot.xdata[0:64] = secret[1:65]

        # Save config for later
        # - never document real pin digits
        record = (slot.slot_num, slot.tc_flags, 
                        0xffff if slot.tc_flags & TC_DELTA_MODE else slot.tc_arg)

        slot.blank_slots = 0
        rc = self.roundtrip(2, b)
        assert rc == 0

        # record key details.
        self.tp[pin] = record
        self.update_record()

        return b, slot

tp = TrickPinMgmt()

# EOF
