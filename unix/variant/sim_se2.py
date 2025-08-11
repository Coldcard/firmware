# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# - do not import this file before trick_pins has had a chance to be imported
#
from binascii import a2b_base64, b2a_base64
from binascii import unhexlify as a2b_hex
from errno import ENOENT

# these flags are masked-out from mpy so even it can't tell they happened
TC_HIDDEN_MASK = const(0xf800)

class SecondSecureElement:
    def __init__(self):
        # restore state, or reconstruct some guesses
        self.wallet = None
        self.load()

    def reconstruct(self, tp):
        # reconstruct based on user-space understanding of SE2 content
        # - can't work with duress wallet cases here (no data)
        # - mostly here so sim_settings works w/ non-empty defaults
        print("SIM SE2: found no state, trying to reconstruct")
        from glob import settings
        from trick_pins import TC_FAKE_OUT, TC_WORD_WALLET, TC_XPRV_WALLET
        from trick_pins import TC_DELTA_MODE, make_slot, TRICK_SLOT_LAYOUT

        print(" .. tp = %r" % tp)
        if not tp: return

        for pin, (slot_num, tc_flags, tc_arg) in tp.items():
            if (tc_flags & (TC_DELTA_MODE | TC_WORD_WALLET | TC_XPRV_WALLET)):
                print("cant do duress cases")
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
            print("slot[%d] <= flags=0x%x arg=0x%x" % (slot_num, tc_flags, tc_arg))

    # Storage: base64 encoded binary for all the slot numbers in a dict

    def save(self):
        from nvstore import SettingsObject

        s = SettingsObject()
        s.set('_se2', [b2a_base64(i) for i in self.state.values()])
        s.save()
        print("saved SE2 data: " + ', '.join(str(i) for i in self.state.keys()))

    def load(self):
        from trick_pins import TRICK_SLOT_LAYOUT
        import uctypes
        from nvstore import SettingsObject
        from sim_secel import SECRETS

        self.state = {}

        obj = SettingsObject()
        obj.set_key(a2b_hex(SECRETS["_pin1_secret"]))
        obj.load()
        # merging default values as they contain useful nfc,vidsk info
        dv = obj.default_values()
        obj.current.update(dv)
        s = obj.get('_se2', None) or []

        for record in s:
            b = a2b_base64(record)
            slot = uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)
            self.state[slot.slot_num] = b
            print("SE2 slot %d is populated" % slot.slot_num)
        else:
            print("no SE2 data")

        if not self.state:
            self.reconstruct(obj.get('tp'))

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
            if slot.blank_slots:
                for sn in range(NUM_TRICKS):
                    if ((1 << sn) & slot.blank_slots) == 0:
                        continue
                    if sn in self.state:
                        del self.state[sn]
            else:
                self.state[slot.slot_num] = bytes(orig)
            self.save()

        return 0

    def stop(self):
        print("Real device would stop here.")
        import time
        while 1:
            time.sleep(60)

    def get_by_pin(self, pc, num_fails):
        from trick_pins import TRICK_SLOT_LAYOUT
        import uctypes
        wrong_pin = None

        for b in self.state.values():
            xs = uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)

            if xs.pin[:2] == b'!p':
                # what to do for wrong pins
                if xs.tc_arg >= num_fails:
                    wrong_pin = xs
                continue

            if xs.pin[:len(pc)] == pc:
                return xs

        return wrong_pin


    def try_trick_login(self, pin, num_fails):
        # similar to stm32/mk4-bootloader/se2.c se2_test_trick_pin(safety_mode=False)
        xs = self.get_by_pin(pin.encode(), num_fails)
        if not xs: 
            self.wallet = None      # bugfix: normal login after trick login (SP unlock case)
            return None

        tc_flags = xs.tc_flags
        tc_arg = xs.tc_arg
        print("PIN %s is a TRICK! flags=0x%x arg=%d" % (pin, tc_flags, tc_arg))

        from trick_pins import TC_WIPE, TC_BRICK, TC_REBOOT, TC_FAKE_OUT 
        from trick_pins import TC_WORD_WALLET, TC_XPRV_WALLET, TC_DELTA_MODE

        # implement our part of the trick
        if tc_flags & TC_WIPE:
            print("TRICK PIN: wipes seed")
            if tc_flags == TC_WIPE:
                self.stop()

        if tc_flags & TC_BRICK:
            print("TRICK PIN: would brick")
            self.stop()

        if tc_flags & TC_REBOOT:
            print("TRICK PIN: would reboot")
            self.stop()

        if tc_flags & TC_FAKE_OUT:
            # pretend was not valid PIN, but above might have wiped stuff
            print("TRICK PIN: fake out")
            return None

        if tc_flags & TC_WORD_WALLET:
            print("TRICK PIN: word wallet")
            if xs.xdata[16:32] == bytes(16):
                self.wallet = bytes([0x80]) + xs.xdata[0:16] + bytes(72-17)     # 12-words
            else:
                self.wallet = bytes([0x82]) + xs.xdata[0:32] + bytes(72-33)     # 24-words

        if tc_flags & TC_XPRV_WALLET:
            print("TRICK PIN: xprv wallet")
            self.wallet = bytes([0x01]) + xs.xdata[0:64] + bytes(72-65)

        if tc_flags & TC_DELTA_MODE:
            print("TRICK PIN: delta mode")
            self.wallet = 'delta'
            tc_arg = 0

        # 'default' be an empty wallet
        if not self.wallet:
            self.wallet = bytes(72)

        tc_flags &= ~TC_HIDDEN_MASK

        return (tc_flags, tc_arg)

SE2 = SecondSecureElement()
