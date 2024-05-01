# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# trick_pins.py - manage the "trick" PIN codes, which can do anything but let you in!
#
# - mk4+ only
# - uses SE2 to store PIN codes (hashed) and what actions to perform for each
# - replaces old "duress wallet" and "brickme" features 
# - changes require knowledge of real PIN code (it is checked)
# 
import uctypes, errno, ngu, sys, stash, bip39, version
from menu import MenuSystem, MenuItem
from ux import ux_show_story, ux_confirm, ux_dramatic_pause, ux_enter_number, the_ux
from stash import SecretStash
from drv_entro import bip85_derive

# see from mk4-bootloader/se2.h
NUM_TRICKS      = const(14)
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
# for our use, not implemented in bootrom
TC_BLANK_WALLET = const(0x0080)
TC_COUNTDOWN    = const(0x0040)         # tc_arg = minutes of delay

# tc_args encoding:
# TC_WORD_WALLET -> BIP-85 index, 1001..1003 for 24 words, 2001..2003 for 12-words

# special "pin" used as catch-all for wrong pins
WRONG_PIN_CODE = '!p'
    
def validate_delta_pin(true_pin, proposed_delta_pin):
    # Check delta pin proposal works w/ limitations and
    # provide error msg, and/or calc required tc_arg value.
    right = true_pin.replace('-', '')
    fake = proposed_delta_pin.replace('-', '')

    if (len(right) != len(fake)) or (right[0:-4] != fake[0:-4]):
        prob = '''\
Trick PIN must be same length (%d) as true PIN and \
up to last four digits can be different between true PIN and trick.''' % len(right)
        return prob, 0

    a = 0
    for i in range(4):
        dx = -(1+i)
        if right[dx] == fake[dx]:
            # no need to reveal this digit to SE2 hacker if same
            a |= 0xf << (i*4)
        else:
            a |= (ord(right[-(1+i)]) - 0x30) << (i*4)

    return None, a

def construct_duress_secret(flags, tc_arg):
    # is duress wallet required and if so, what are the secret values (32 or 64 bytes)
    if flags & TC_WORD_WALLET:
        # derive the secret via BIP-85
        nwords = 24 if (tc_arg//1000 == 1) else 12
        mmode = 0 if (nwords == 12) else 2          # weak: based on menu design
        new_secret, _, _, path = bip85_derive(mmode, tc_arg)
        path = "BIP85(words=%d, index=%d)" % (nwords, tc_arg)

    elif flags & TC_XPRV_WALLET:
        # use old method for duress wallets
        with stash.SensitiveValues() as sv:
            node, path = sv.duress_root()
            new_secret = SecretStash.encode(xprv=node)[1:65]
            assert len(new_secret) == 64
    else:
        return (None, None)

    return path, new_secret

def make_slot():
    b = bytearray(uctypes.sizeof(TRICK_SLOT_LAYOUT))
    return b, uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)

class TrickPinMgmt:

    def __init__(self):
        assert uctypes.sizeof(TRICK_SLOT_LAYOUT) == 128
        self.reload()

    def reload(self):
        # we track known PINS as a dictionary:
        #   pin (in ascii) => (slot_num, tc_flags, arg)
        from glob import settings
        self.tp = settings.get('tp', {})

    def save_record(self):
        # commit changes back to settings
        from glob import settings
        if self.tp:
            settings.set('tp', self.tp)
        else:
            settings.remove_key('tp')
        settings.save()

    def roundtrip(self, method_num, slot_buf=None):
        from pincodes import pa

        if slot_buf is not None:
            arg = slot_buf
        else:
            # use zeros
            assert method_num == 0
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
        self.save_record()

    def forget_pin(self, pin):
        # forget about settings for a PIN
        self.tp.pop(pin, None)
        self.save_record()

    def restore_pin(self, new_pin):
        # remember/restore PIN that we "forgot", return T if worked
        b, slot = tp.get_by_pin(new_pin)
        if slot is None: return False

        record = (slot.slot_num, slot.tc_flags, 
                        0xffff if slot.tc_flags & TC_DELTA_MODE else slot.tc_arg)
        self.tp[new_pin] = record
        self.save_record()

        return True

    def clear_slots(self, slot_nums):
        # remove some slots, not all
        b, slot = make_slot()
        slot.blank_slots = sum(1<<s for s in slot_nums)
        self.roundtrip(2, b)

    def get_available_slots(self):
        # do an impossible search, so we can get blank_slots field back
        b, slot = make_slot()
        slot.pin_len = 1
        self.roundtrip(1, b)        # expects ENOENT=2

        blk = slot.blank_slots

        if not version.has_qwerty:
            # bug workaround: don't use slot 10, in Mk4 bootrom 3.1.4 and earlier
            blk &= ~(1<<10)

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

        if isinstance(pin, str):
            pin = pin.encode()

        slot.pin_len = len(pin)
        slot.pin[0:slot.pin_len] = pin

        rc = self.roundtrip(1, b)
        if rc == errno.ENOENT:
            return None, None

        # these fields are zeros on return, but we need them for CRUD
        slot.pin_len = len(pin)
        slot.pin[0:slot.pin_len] = pin

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
                raise RuntimeError("no space left")

            slot.slot_num = sn

        if new_pin is not None:
            slot.pin_len = len(new_pin)
            slot.pin[0:slot.pin_len] = new_pin
            if new_pin != pin:
                self.tp.pop(pin.decode(), None)
            pin = new_pin

        if tc_flags is not None:
            assert 0 <= tc_flags <= 65536
            slot.tc_flags = tc_flags

        if tc_arg is not None:
            assert 0 <= tc_arg <= 65536
            slot.tc_arg = tc_arg

        if secret is not None:
            # expecting an encoded secret
            if len(secret) <= 32:
                # words.
                assert slot.tc_flags & TC_WORD_WALLET
                slot.xdata[0:len(secret)] = secret
            elif len(secret) == 64:
                # expecting 64 bytes encoded already
                assert slot.tc_flags & TC_XPRV_WALLET
                slot.xdata[0:64] = secret
            else:
                raise ValueError()

        # Save config for later
        # - deltamode: don't document real pin digits
        record = (slot.slot_num, slot.tc_flags, 
                        0xffff if slot.tc_flags & TC_DELTA_MODE else slot.tc_arg)

        slot.blank_slots = 0
        rc = self.roundtrip(2, b)
        assert rc == 0

        # record key details.
        self.tp[pin.decode()] = record
        self.save_record()

        return b, slot

    def all_tricks(self):
        # put them in order, with "wrong" last
        return sorted(self.tp.keys(), key=lambda i: i if (i != WRONG_PIN_CODE) else 'Z')

    def was_countdown_pin(self):
        # was the trick pin just used? if so how much delay needed (or zero if not)
        from pincodes import pa
        tc_flags, tc_arg = pa.get_tc_values()

        if tc_flags & TC_COUNTDOWN:
            return tc_arg or 60
        else:
            return 0

    def get_deltamode_pins(self):
        # iterate over all delta-mode PIN's defined.
        for k, (sn,flags,args) in self.tp.items():
            if flags & TC_DELTA_MODE:
                yield k

    def get_duress_pins(self):
        # iterate over all duress wallets
        for k, (sn,flags,args) in self.tp.items():
            if flags & (TC_WORD_WALLET | TC_XPRV_WALLET):
                yield k

    def check_new_main_pin(self, pin):
        # user is trying to change main PIN to new value; check for issues
        # - dups bad but also: delta mode pin might not work w/ longer main true pin
        # - return error msg or None
        assert isinstance(pin, str)
        if pin in self.tp:
            return 'That PIN is already in use as a Trick PIN.'

        for d_pin in self.get_deltamode_pins():
            prob, _ = validate_delta_pin(pin, d_pin)
            if prob:
                return 'That PIN value makes problems with a Delta Mode Trick PIN.'

    def main_pin_has_changed(self, new_main_pin):
        # update any delta-mode entries we have
        for d_pin in self.get_deltamode_pins():
            prob, arg = validate_delta_pin(new_main_pin, d_pin)
            assert not prob             # see check_new_main_pin() above
            self.update_slot(d_pin.encode(), tc_arg=arg)

    def backup_duress_wallets(self, sv):
        # for backup file, yield (label, path, pairs-of-data)
        done = set()
        for pin in self.get_duress_pins():
            sn, flags, arg = self.tp[pin]

            if (flags, arg) in done:
                continue
            done.add( (flags, arg) ) 

            if flags & TC_WORD_WALLET:
                label = "Duress: BIP-85 Derived wallet"
                nwords = 12 if ((arg // 1000) == 2) else 24
                path = "BIP85(words=%d, index=%d)" % (nwords, arg)
                b, slot = tp.get_by_pin(pin)
                words = bip39.b2a_words(slot.xdata[0:(32 if nwords==24 else 16)])

                d = [ ('duress_%d_words' % arg, words) ]
            elif flags & TC_XPRV_WALLET:
                label = "Duress: XPRV Wallet"
                node, path = sv.duress_root()
                path = 'path = ' + path
                # backwards compat name, but skipping xpub this time
                d = [ ('duress_xprv', sv.chain.serialize_private(node)) ]

            yield (label, path, d)

    def restore_backup(self, vals):
        # restoring backup value
        # - need to re-populate SE2 w/ these values, including duress wallets
        # - being restored: vals=self.tp
        # - CAUTION: new true-pin may not match old true-pin; skip any that would
        #     not work w/ new pin (conflicting value, or deltamode issues)
        from pincodes import pa
        true_pin = pa.pin.decode()

        for pin in vals:
            (sn, flags, arg) = vals[pin]

            if pin == true_pin:
                # drop conflicting trick pin vs. (new) true pin
                continue

            if flags & TC_DELTA_MODE:
                prob = validate_delta_pin(true_pin, pin)
                if prob:
                    # just forget it, no UI here to report issue
                    continue           

            try:
                # might need to construct a BIP-85 or XPRV secret to match
                path, new_secret = construct_duress_secret(flags, arg)

                b, slot = tp.update_slot(pin.encode(), new=True,
                                     tc_flags=flags, tc_arg=arg, secret=new_secret)
            except Exception as exc:
                sys.print_exception(exc)        # not visible
            

tp = TrickPinMgmt()

class TrickPinMenu(MenuSystem):

    def __init__(self):
        self.WillWipeMenu = None
        super().__init__(self.construct())

    @classmethod
    async def make_menu(cls, *unused):
        # used to build menu at runtime, in response to parent menu item
        return cls()

    @property
    def current_pin(self):
        from pincodes import pa
        return pa.pin.decode()

    def construct(self):
        # Dynamic menu with PIN codes as the items, plus a few static choices

        # not going to work well if tmp secret in effect
        from pincodes import pa
        if bool(pa.tmp_value):
            return [MenuItem('Not Available')]

        tp.reload()
        tricks = tp.all_tricks()

        if self.current_pin in tricks:
            # They got into here with a trick PIN, so it must be 
            # a deltamode pin, or something else tricky ... hide it from menu
            # since it reveals that fact to attacker.
            tricks.remove(self.current_pin)

        has_wrong = False

        rv = []

        if tricks:
            rv.append(MenuItem('Trick PINs:'))
            for pin in tricks:
                if pin == WRONG_PIN_CODE:
                    rv.append(MenuItem('↳WRONG PIN', menu=self.pin_submenu, arg=pin))
                else:
                    rv.append(MenuItem('↳'+pin, menu=self.pin_submenu, arg=pin))


        rv.append(MenuItem('Add New Trick', f=self.add_new))
        has_wrong = any(pin == WRONG_PIN_CODE for pin in tricks)
        if not has_wrong:
            rv.append(MenuItem('Add If Wrong', f=self.set_any_wrong))

        # even if menu "looks" empty, many times we need this anyway
        rv.append(MenuItem('Delete All', f=self.clear_all))

        return rv

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    async def done_picking(self, item, parents):
        # done picking/drilling down tree.
        # - shows point-form summary and gets confirmation
        from glob import dis

        wants_wipe = (self.WillWipeMenu in parents)
        self.WillWipeMenu = None        # memory free

        flags = item.flags
        tc_arg = item.arg

        if self.proposed_pin == WRONG_PIN_CODE:
            if tc_arg == 0:
                msg = "Any Wrong PIN\n↳%s" % item.label
            else:
                msg = "%d Wrong PINs\n↳%s" % (tc_arg, item.label)
        else:
            msg = "PIN %s\n↳%s" % (self.proposed_pin, item.label)

            if wants_wipe:
                msg += " (after wiping secret)"
                flags |= TC_WIPE

        msg += '\n\n'

        path, new_secret = construct_duress_secret(flags, tc_arg)


        if path:
            msg += "Duress wallet will use path:\n\n%s\n\n" % path

        if flags & TC_DELTA_MODE:
            # Calculate the value needed for args: BCD encoded final 4 digits
            # of the true PIN!
            prob, a = validate_delta_pin(self.current_pin, self.proposed_pin)
            if prob:
                await ux_show_story(prob, 'Sorry!')
                return
            tc_arg = a

        msg += "Ok?"
        ch = await ux_show_story(msg)
        if ch != 'y': return

        # save it
        dis.fullscreen("Saving...")
        try:
            bpin = self.proposed_pin.encode()
            tp.update_slot(bpin, new=True, tc_flags=flags,
                           tc_arg=tc_arg, secret=new_secret)
            await ux_dramatic_pause("Saved.", 1)
        except BaseException as exc:
            sys.print_exception(exc)
            await ux_show_story("Failed: %s" % exc)

        self.update_contents()


    async def get_new_pin(self, existing_pin=None):
        # get a new PIN code and check not a dup
        # - show msg if aborted
        # - recover "forgotten" pins

        from login import LoginUX
        lll = LoginUX()
        lll.is_setting = True
        lll.subtitle = "New Trick PIN"
        new_pin = await lll.prompt_pin()

        if new_pin is None:
            return

        if new_pin == existing_pin:
            await ux_show_story("That isn't a new value")
            return

        have = tp.all_tricks()
        if existing_pin and (existing_pin in have):
            have.remove(existing_pin)

        if (new_pin == self.current_pin) or (new_pin in have):
            await ux_show_story("That PIN (%s) is already in use. All PIN codes must be unique." % new_pin)
            return

        # check if we "forgot" this pin, and read it back if we did.
        # - important this is after the above checks so we don't reveal any trick pin used
        #   to get here
        if tp.restore_pin(new_pin):
            await ux_show_story("Hmm. I remember that PIN now.")
            self.update_contents()
            return

        return new_pin

    async def add_new(self, *a):
        # Add a new PIN code
        from pincodes import pa
        from glob import settings

        if pa.is_secret_blank() or pa.is_blank() or not pa.pin:
            await ux_show_story("Please set true PIN and wallet seed before creating trick pins.")
            return

        # get the new pin
        self.proposed_pin = await self.get_new_pin()
        if not self.proposed_pin: return
        nwords = settings.get('words', 24)
        if nwords == 12:
            dbase = 2000
        else:
            # 24-word typical duress wallet
            # - cannot handle 18-word seeds exactly, so map to 24
            # - also XPRV -> duress word wallet will be 24-word type
            dbase = 1000

        b85 = "This PIN will lead to a functional 'duress' wallet using seed words produced by the standard BIP-85 process. Index number is %d...%d for #1..#3 duress wallets. Same number of seed words as your true seed." \
                % (dbase+1, dbase+3)

        DuressOptions = [
            #              xxxxxxxxxxxxxxxx
            StoryMenuItem('BIP-85 Wallet #1', b85, arg=dbase+1, flags=TC_WORD_WALLET),
            StoryMenuItem('BIP-85 Wallet #2', b85, arg=dbase+2, flags=TC_WORD_WALLET),
            StoryMenuItem('BIP-85 Wallet #3', b85, arg=dbase+3, flags=TC_WORD_WALLET),
            StoryMenuItem('Legacy Wallet', "Uses duress wallet created on Mk3 Coldcard, using a fixed derivation.\n\nRecommended only for existing UTXO compatibility.", flags=TC_XPRV_WALLET),
        ]
        self.WillWipeMenu = MenuSystem([
            #              xxxxxxxxxxxxxxxx
            StoryMenuItem('Wipe & Reboot', "Seed is wiped and Coldcard reboots without notice.",
                            flags=TC_WIPE|TC_REBOOT),
            StoryMenuItem('Silent Wipe', "Seed is silently wiped and Coldcard acts as if PIN code was just wrong.",
                            flags=TC_WIPE|TC_FAKE_OUT),
            StoryMenuItem('Wipe -> Wallet', "Seed is silently wiped, and Coldcard logs into a duress wallet. Select type of wallet on next menu.", menu=DuressOptions),
            StoryMenuItem('Say Wiped, Stop', "Seed is wiped and a message is shown.",
                            flags=TC_WIPE),
        ])
        from countdowns import lgto_map
        def_to = settings.get('lgto', 0) or 60   # use 1hour or current countdown length as default

        countdown_menu = MenuSystem([
            #              xxxxxxxxxxxxxxxx
            StoryMenuItem('Wipe & Countdown', "Seed is wiped at start of countdown.",
                            flags=TC_WIPE|TC_COUNTDOWN, arg=def_to),
            StoryMenuItem('Countdown & Brick', "Does the countdown, then system is bricked.",
                            flags=TC_WIPE|TC_BRICK|TC_COUNTDOWN, arg=def_to),
            StoryMenuItem('Just Countdown', "Shows countdown, has no effect on seed.",
                            flags=TC_COUNTDOWN, arg=def_to),
        ])
        FirstMenu = [
            #MenuItem('"%s" =>' % self.proposed_pin),
            MenuItem('[%s]' % self.proposed_pin),
            StoryMenuItem('Brick Self', "Become a brick instantly and forever.", flags=TC_BRICK),
            StoryMenuItem('Wipe Seed', "Wipe the seed and maybe do more. See next menu.",
                                            menu=self.WillWipeMenu),
            StoryMenuItem('Duress Wallet', "Goes directly to a specific duress wallet. No side effects.", menu=DuressOptions),
            StoryMenuItem('Login Countdown', "Pretends a login countdown timer (%s) is in effect. Can wipe seed or brick system or do nothing." % lgto_map[def_to].strip(),
                    menu=countdown_menu),
            StoryMenuItem('Look Blank', "Look and act like a freshly- wiped Coldcard but don't affect actual seed.", flags=TC_BLANK_WALLET),
            StoryMenuItem('Just Reboot', "Reboot when this PIN is entered. Doesn't do anything else.", flags=TC_REBOOT),
            StoryMenuItem('Delta Mode', '''\
Advanced! Logs into REAL seed and allows attacker to do most things, \
but will produce incorrect signatures when signing PSBT files. \
Wipes seed if they try to do certain actions that might reveal \
the seed phrase, but still a somewhat riskier mode.

For this mode only, trick PIN must be same length as true PIN and \
differ only in final 4 positions (ignoring dash).\
''', flags=TC_DELTA_MODE),
        ]
        m = MenuSystem(FirstMenu)
        m.goto_idx(1)
        the_ux.push(m)


    async def set_any_wrong(self, *a):
        ch = await ux_show_story('''\
After X incorrect PIN attempts, this feature will be triggered. It can wipe \
the seed phrase, and/or brick the Coldcard. Regardless of this (or any other \
setting) the Coldcard will always brick after 13 failed PIN attempts.''')
        if ch == 'x': return

        self.proposed_pin = WRONG_PIN_CODE
        num = await ux_enter_number("#of wrong attempts", 12)
        if num is None: return

        # - can't do countdown here because of only one tc_arg value per slot
        # - zero and one effectively the same
        if num == 0:
            num = 1

        rel = ['', 'ANY', '2nd', '3rd'][num] if num <= 3 else ('%dth' % num)

        m = MenuSystem([
            #              xxxxxxxxxxxxxxxx
            MenuItem('[%s WRONG PIN]' % rel),
            StoryMenuItem('Wipe, Stop', "Seed is wiped and a message is shown.",
                arg=num, flags=TC_WIPE),
            StoryMenuItem('Wipe & Reboot', "Seed is wiped and Coldcard reboots without notice.",
                            arg=num, flags=TC_WIPE|TC_REBOOT),
            StoryMenuItem('Silent Wipe', "Seed is silently wiped and Coldcard acts as if PIN code was just wrong.",
                            arg=num, flags=TC_WIPE|TC_FAKE_OUT),
            StoryMenuItem('Brick Self', "Become a brick instantly and forever.", flags=TC_BRICK, arg=num),
            StoryMenuItem('Last Chance', "Wipe seed, then give one more try and then brick if wrong PIN.", arg=num, flags=TC_WIPE|TC_BRICK),
            StoryMenuItem('Just Reboot', "Reboot when this happens. Doesn't do anything else.", arg=num, flags=TC_REBOOT),
        ])

        m.goto_idx(1)
        the_ux.push(m)

    async def clear_all(self, m,l,item):
        if not await ux_confirm("Remove ALL TRICK PIN codes and special wrong-pin handling?"):
            return

        if any(tp.get_duress_pins()):
            if not await ux_confirm("Any funds on the duress wallet(s) have been moved already?"):
                return

        tp.clear_all()
        m.update_contents()

    async def hide_pin(self, m,l, item):
        pin, slot_num, flags = item.arg

        if flags & TC_DELTA_MODE:
            await ux_show_story('''Delta mode PIN will be hidden if trick PIN menu is shown \
to attacker, and we need to update this record if the main PIN is changed, so we don't support \
hiding this item.''')
            return

        if pin != WRONG_PIN_CODE:
            msg = '''This will hide the PIN from the menus but it will still be in effect.

You can restore it by trying to re-add the same PIN (%s) again later.''' % pin
        else:
            msg = "This will hide what happens with wrong PINs from the menus but it will still be in effect."

        if not await ux_confirm(msg): return

        # just a settings change
        tp.forget_pin(pin)

        self.pop_submenu()

    def pop_submenu(self):
        the_ux.pop()
        m = the_ux.top_of_stack()
        m.update_contents()

    async def change_pin(self, m,l, item):
        # Change existing PIN code.
        old_pin, slot_num, flags, tc_arg = item.arg

        new_pin = await self.get_new_pin(old_pin)
        if new_pin is None:
            return

        if flags & TC_DELTA_MODE:
            # if delta mode ... must apply rules to new PIN
            prob, a = validate_delta_pin(self.current_pin, new_pin)
            if prob:
                await ux_show_story(prob, 'Sorry!')
                return
            tc_arg = a

        try:
            tp.update_slot(old_pin.encode(), new_pin=new_pin.encode(), tc_arg=tc_arg)
            await ux_dramatic_pause("Changed.", 1)

            self.pop_submenu()      # too lazy to get redraw right
        except BaseException as exc:
            sys.print_exception(exc)
            await ux_show_story("Failed: %s" % exc)

    async def delete_pin(self, m,l, item):
        pin, slot_num, flags = item.arg

        if flags & (TC_WORD_WALLET | TC_XPRV_WALLET):
            if not await ux_confirm("Any funds on this duress wallet have been moved already?"):
                return

        if pin == WRONG_PIN_CODE:
            msg = "Remove special handling of wrong PINs?"
        else:
            msg = "Removing trick PIN:\n  %s\n\nOk?" % pin

        if not await ux_confirm(msg):
            return

        if flags & TC_WORD_WALLET:
            nslots = 2
        elif flags & TC_XPRV_WALLET:
            nslots = 3
        else:
            nslots = 1

        tp.clear_slots(range(slot_num, slot_num+nslots))
        tp.forget_pin(pin)

        self.pop_submenu()

    async def activate_wallet(self, m, l, item):
        # load the secrets of a wallet for immediate use
        # - duress or blank wallet
        pin, flags, arg = item.arg

        ch = await ux_show_story('''\
This will temporarily load the secrets associated with this trick wallet \
so you may perform transactions with it. Reboot the Coldcard to restore \
normal operation.''')
        if ch != 'y': return

        from pincodes import pa, AE_SECRET_LEN
        b, slot = tp.get_by_pin(pin)
        assert slot

        # TC_BLANK_WALLET here would be nice, but no support working w/ fake empty secret

        # emulate stash.py encoding
        name = 'Duress #%d' % (arg % 10)
        if flags & TC_XPRV_WALLET:
            encoded = b'\x01' + slot.xdata[0:64]
            name = 'Mk3 Duress'
        elif flags & TC_WORD_WALLET and (arg // 1000 == 1):
            encoded = b'\x82' + slot.xdata[0:32]
        elif flags & TC_WORD_WALLET and (arg // 1000 == 2):
            encoded = b'\x80' + slot.xdata[0:16]
        else:
            raise ValueError            #('f=0x%x a=%d' % (flags, arg))

        from glob import dis
        from seed import set_ephemeral_seed
        from actions import goto_top_menu

        # switch over to new secret!
        dis.fullscreen("Applying...")
        await set_ephemeral_seed(encoded, meta=name)
        goto_top_menu()

    async def countdown_details(self, m, l, item):
        # explain details of the countdown case
        # - allow change of time period
        from countdowns import lgto_map, lgto_va, lgto_ch
        from menu import start_chooser

        pin, flags, arg = item.arg

        # "arg" can be out-of-date, if they edited timer value after parent was
        # rendered, where arg was captured into item.arg ... so don't use it.
        cd_val = tp.tp[pin][2]

        msg = 'Shows login countdown (%s)' % lgto_map.get(cd_val, '???').strip()
        if flags & TC_WIPE:
            msg += ', wipes the seed'
        else:
            msg += ' and reboots at end of countdown'
        if flags & TC_BRICK:
            msg += ' and bricks system at end of countdown'

        msg += '.\n\nPress (4) to change time.'
        ch = await ux_show_story(msg, escape='4')
        if ch != '4': return

        def adjust_countdown_chooser():
            # 'disabled' choice not appropriate for this case
            ch = lgto_ch[1:]
            va = lgto_va[1:]

            def set_it(idx, text):
                new_val = va[idx]
                # save it
                try:
                    b, slot = tp.update_slot(pin.encode(), tc_flags=flags, tc_arg=new_val)
                except BaseException as exc:
                    sys.print_exception(exc)

            return va.index(cd_val), lgto_ch[1:], set_it

        start_chooser(adjust_countdown_chooser)

    async def duress_details(self, m, l, item):
        # explain details of a duress wallet
        pin, flags, arg = item.arg
        if flags & TC_XPRV_WALLET:
            msg = '''The legacy duress wallet will be activated if '%s' is provded. \
You probably created this on an older Mk2 or Mk3 Coldcard. \
Wallet is XPRV-based and derived from a fixed path.''' % pin
        elif flags & TC_WORD_WALLET:
            nwords = 12 if (arg // 1000 == 2) else 24
            msg = '''BIP-85 derived wallet (%d words), with index #%d, is provided if '%s'.''' \
                        % (nwords, arg, pin)
        else:
            raise ValueError(hex(flags))

        ch = await ux_show_story(msg + '\n\nPress (6) to view associated secrets.', escape='6')
        if ch != '6': return

        b, s = tp.get_by_pin(pin)
        if s == None:
            # could not find in SE2. Our settings vs. SE2 are not in sync.
            msg = "Not found in SE2. Delete and remake."
        else:
            from actions import render_master_secrets

            assert s.tc_flags == flags
            if flags & TC_XPRV_WALLET:
                node = ngu.hdnode.HDNode()
                ch, pk = s.xdata[0:32], s.xdata[32:64]
                node.from_chaincode_privkey(ch, pk)

                msg, *_ = render_master_secrets('xprv', None, node)
            elif flags & TC_WORD_WALLET:
                raw = s.xdata[0:(32 if nwords == 24 else 16)]
                msg, *_ = render_master_secrets('words', raw, None)
            else:
                raise ValueError(hex(flags))

        await ux_show_story(msg, sensitive=True)
        

    async def pin_submenu(self, menu, label, item):
        # drill down into a sub-menu per existing PIN
        # - data display only, no editing; just clear and redo
        pin = item.arg
        slot_num, flags, arg = tp.tp[pin] if (pin in tp.tp) else (-1, 0, 0)

        rv = []

        if pin != WRONG_PIN_CODE:
            rv.append(MenuItem('PIN %s' % pin))
        else:
            rv.append(MenuItem("After %d wrong:" % arg))

        if flags & (TC_WORD_WALLET | TC_XPRV_WALLET):
            rv.append(MenuItem("↳Duress Wallet", f=self.duress_details, arg=(pin, flags, arg)))
        elif flags & TC_BLANK_WALLET:
            rv.append(MenuItem("↳Blank Wallet"))
        elif flags & TC_COUNTDOWN:
            rv.append(MenuItem("↳Countdown", f=self.countdown_details, arg=(pin, flags, arg)))
        elif flags & TC_FAKE_OUT:
            rv.append(MenuItem("↳Pretends Wrong"))
        elif flags & TC_DELTA_MODE:
            rv.append(MenuItem("↳Delta Mode"))

        for m, msg in [
            (TC_WIPE,   '↳Wipes seed'),
            (TC_BRICK,  '↳Bricks CC'),
            (TC_REBOOT, '↳Reboots'),
        ]:
            if flags & m:
                rv.append(MenuItem(msg))

        if flags & (TC_WORD_WALLET | TC_XPRV_WALLET):
            rv.append(MenuItem("Activate Wallet", f=self.activate_wallet, arg=(pin, flags, arg)))

        rv.extend([
            MenuItem('Hide Trick', f=self.hide_pin, arg=(pin, slot_num, flags)),
            MenuItem('Delete Trick', f=self.delete_pin, arg=(pin, slot_num, flags)),
        ])
        if pin != WRONG_PIN_CODE:
            rv.append(
                MenuItem('Change PIN', f=self.change_pin, arg=(pin, slot_num, flags, arg)),
            )

        return rv

class StoryMenuItem(MenuItem):
    def __init__(self, label, story, flags=0, **kws):
        self.story = story
        self.flags = flags
        super().__init__(label, **kws)

    async def activate(self, menu, idx):
        from glob import dis

        ch = await ux_show_story(self.story)
        if ch == 'x':
            return

        dis.fullscreen('Wait...')

        if getattr(self, 'next_menu', None):
            # drill down more
            return await super().activate(menu, idx)

        # pop some levels, and note the drill-down path that was used
        parents = []
        while 1:
            the_ux.pop()
            parent = the_ux.top_of_stack()
            assert parent

            parents.insert(0, parent)

            if isinstance(parent, TrickPinMenu):
                await parent.done_picking(self, parents)
                return

# EOF
