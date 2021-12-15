# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# - do not import this file before trick_pins has had a chance to be imported
#
from binascii import a2b_base64, b2a_base64
from errno import ENOENT

class SecondSecureElement:
    def __init__(self):
        # restore state, or reconstruct some guesses
        self.load()

        if not self.state:
            # reconstruct based on user-space understanding of SE2 content
            # - can't work with duress wallet cases here (no data)
            # - mostly here so sim_settings works w/ non-empty defaults
            from glob import settings
            from trick_pins import TC_FAKE_OUT, TC_WORD_WALLET, TC_XPRV_WALLET
            from trick_pins import TC_DELTA_MODE, make_slot, TRICK_SLOT_LAYOUT

            for pin, (slot_num, tc_flags, tc_arg) in settings.get('tp', {}).items():
                if (tc_flags & (TC_DELTA_MODE | TC_WORD_WALLET | TC_XPRV_WALLET)):
                    continue
                #assert not (tc_flags & (TC_DELTA_MODE | TC_WORD_WALLET | TC_XPRV_WALLET)), \
                                    #'unhandled simulated case: 0x%x' % tc_flags

                b, s = make_slot()
                s.pin_len = len(pin)
                s.pin[:s.pin_len] = pin.encode()
                s.tc_flags = tc_flags
                s.tc_arg = tc_arg
                s.slot_num = slot_num

                self.state[slot_num] = bytes(b)

    # Storage: base64 encoded binary for all the slot numbers in a dict

    def save(self):
        from glob import settings
        settings.set('_se2', [b2a_base64(i) for i in self.state.values()])

    def load(self):
        from glob import settings
        from trick_pins import TRICK_SLOT_LAYOUT
        import uctypes

        self.state = {}

        s = settings.get('_se2', None)
        if not s:
            return

        for record in s:
            b = a2b_base64(record)
            slot = uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)
            self.state[slot.slot_num] = b

    def callgate(self, buf_io, arg2):
        # ckcc.callgate(22, ...)
        from trick_pins import TRICK_SLOT_LAYOUT, NUM_TRICKS
        from pincodes import PIN_ATTEMPT_SIZE
        import uctypes

        orig = buf_io[PIN_ATTEMPT_SIZE:]
        slot = uctypes.struct(uctypes.addressof(orig), TRICK_SLOT_LAYOUT)
        pc = bytes(slot.pin[0:slot.pin_len])       # keep as bytes, not ascii

        if arg2 == 0:       # clear all
            self.state.clear()
            self.save()
            return 0

        elif arg2 == 1:     # get by pin
            blank = (1 << NUM_TRICKS)-1
            for b in self.state.values():
                xs = uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)
                blank &= ~(1<<xs.slot_num)
                if xs.pin[:len(pc)] == pc:
                    buf_io[PIN_ATTEMPT_SIZE:] = b
                    return 0

            #print("SE2: pin %r not found, blank=0x%x" % (pc, blank))
            # impt: populate "blank slots" field.
            slot.blank_slots = blank
            slot.slot_num = ~0
            buf_io[PIN_ATTEMPT_SIZE:] = orig
            return ENOENT

        elif arg2 == 2:     # update slot
            self.state[slot.slot_num] = bytes(orig)
            self.save()

        return 0

SE2 = SecondSecureElement()

