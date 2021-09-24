# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# trick_pins.py - manage the "trick" PIN codes, which can do anything but let you in!
#
# - mk4+ only
# - uses SE2 to storage PIN codes and actions to perform
# - replaces old "duress wallet" and "brickme" features 
# - changes require knowledge of real PIN code (it is checked)
# 
import version, uctypes, errno, ngu, sys, ckcc, stash
from ubinascii import hexlify as b2a_hex
from menu import MenuSystem, MenuItem
from ux import ux_show_story, ux_confirm, ux_dramatic_pause, ux_enter_number, the_ux, ux_aborted
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

# special "pin" used as catch-all for wrong pins
WRONG_PIN_CODE = '!p'

def make_slot():
    b = bytearray(uctypes.sizeof(TRICK_SLOT_LAYOUT))
    return b, uctypes.struct(uctypes.addressof(b), TRICK_SLOT_LAYOUT)

class TrickPinMgmt:

    def __init__(self):
        assert uctypes.sizeof(TRICK_SLOT_LAYOUT) == 128
        self.reload()

    def reload(self):
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

    def forget_pin(self, pin):
        # forget about settings for a PIN
        self.tp.pop(pin, None)
        self.update_record()

    def restore_pin(self, new_pin):
        # remember/restore PIN that we "forgot", return T if worked
        b, slot = tp.get_by_pin(new_pin)
        if slot is None: return False

        record = (slot.slot_num, slot.tc_flags, 
                        0xffff if slot.tc_flags & TC_DELTA_MODE else slot.tc_arg)
        self.tp[new_pin] = record

        return True

    def clear_slots(self, slot_nums):
        # remove some slots, not all
        b, slot = make_slot()
        slot.blank_slots = sum(1<<s for s in slot_nums)
        self.roundtrip(2)

    def get_available_slots(self):
        # do an impossible search, so we can get blank_slots field back
        if ckcc.is_simulator():     # XXX FIXME
            return list(range(NUM_TRICKS))

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
                raise RuntimeError("no space")

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
            if len(secret) == 32:
                assert slot.tc_flags & TC_WORD_WALLET
                slot.xdata[0:32] = secret
            elif len(secret) == 64:
                # expecting 64 bytes encoded already
                assert slot.tc_flags & TC_XPRV_WALLET
                slot.xdata[0:64] = secret

        # Save config for later
        # - never document real pin digits
        record = (slot.slot_num, slot.tc_flags, 
                        0xffff if slot.tc_flags & TC_DELTA_MODE else slot.tc_arg)

        slot.blank_slots = 0
        rc = self.roundtrip(2, b)
        assert rc == 0

        # record key details.
        self.tp[pin.decode()] = record
        self.update_record()

        return b, slot

    def all_tricks(self):
        # put them in order, with "wrong" last
        return sorted(self.tp.keys(), key=lambda i: i if (i != WRONG_PIN_CODE) else 'Z')

tp = TrickPinMgmt()

class TrickPinMenu(MenuSystem):

    def __init__(self):
        from pincodes import pa
        self.current_pin = pa.pin.decode()
        self.WillWipeMenu = None

        super().__init__(self.construct(avail=(not pa.tmp_value)))

    def construct(self, avail=True):
        # Dynamic menu with PIN codes as the items, plus a few static choices

        if not avail:
            return [MenuItem('Not available')]

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

        if tricks:
            rv.append(MenuItem('Delete All', f=self.clear_all))

        return rv

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    async def done_picking(self, item, parents):
        # done picking/drilling down tree.
        wants_wipe = (self.WillWipeMenu in parents)
        self.WillWipeMenu = None        # memory free

        flags = item.flags
        tc_arg = item.arg

        if self.proposed_pin == WRONG_PIN_CODE:
            msg = "%d Wrong PINs\n↳%s" % (tc_arg, item.label)
        else:
            msg = "PIN %s\n↳%s" % (self.proposed_pin, item.label)

            if wants_wipe:
                msg += " (after wiping secret)"
                flags |= TC_WIPE

        msg += '\n\n'

        path = None
        new_secret = None
        if flags & TC_WORD_WALLET:
            # derive the secret via BIP-85
            new_secret, _, _, path = bip85_derive(2, tc_arg)
            path = "BIP85(words=24, index=%d)" % tc_arg
        elif flags & TC_XPRV_WALLET:
            # use old method for duress wallets
            with stash.SensitiveValues() as sv:
                node, path = sv.duress_root()
                new_secret = SecretStash.encode(xprv=node)[1:65]
                assert len(new_secret) == 64

        if path:
            msg += "Duress wallet will use path:\n\n%s\n\n" % path

        if flags & TC_DELTA_MODE:
            # Calculate the value needed for args: BCD encoded final 4 digits
            # of the true PIN!
            right = self.current_pin.replace('-', '')
            fake = self.proposed_pin.replace('-', '')
            prob = None
            if (len(right) != len(fake)) or (right[0:-4] != fake[0:-4]):
                prob = '''\
Trick PIN must be same length (%d) as true PIN and \
only up to last four digits can be different between true PIN and trick.''' % len(right)
                await ux_show_story(prob, 'Sorry!')
                return

            a = 0
            for i in range(4):
                dx = -(1+i)
                if right[dx] == fake[dx]:
                    # no need to reveal this digit to SE2 hacker if same
                    a |= 0xf << (i*4)
                else:
                    a |= (ord(right[-(1+i)]) - 0x30) << (i*4)

            print("arg = 0x%04x" % a)
            tc_arg = a

        msg += "Ok?"
        ch = await ux_show_story(msg)
        if ch != 'y': return

        # save it
        try:
            bpin = self.proposed_pin.encode()
            b, slot = tp.update_slot(bpin, new=True, tc_flags=flags,
                                        tc_arg=tc_arg, secret=new_secret)
            await ux_dramatic_pause("Saved.", 1)
        except BaseException as exc:
            sys.print_exception(exc)
            await ux_show_story("Failed.")

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
            await ux_show_story("That PIN (%s) is already in use. All PIN codes must be unique." % new_pin);
            return

        # check if we "forgot" this pin, and read it back if we did.
        # - important this is after the above checks so we don't reveal a deltamode pin in use
        if tp.restore_pin(new_pin):
            await ux_show_story("Hmm. I remember that PIN now.")
            self.update_contents()
            return

        return new_pin

    async def add_new(self, *a):
        # Add a new PIN code
        from pincodes import pa

        if pa.is_secret_blank() or pa.is_blank() or not pa.pin:
            await ux_show_story("Please set true PIN and wallet seed before creating trick pins.")
            return

        # get the new pin
        self.proposed_pin = await self.get_new_pin()
        if not self.proposed_pin: return

        b85 = "This PIN will lead to a functional 'duress' wallet using seed words produced by the standard BIP-85 process. Index number is 1001 / 1002 / 1003 for #1..#3 duress wallets."

        DuressOptions = [
            #              xxxxxxxxxxxxxxxx
            StoryMenuItem('BIP-85 Wallet #1', b85, arg=1001, flags=TC_WORD_WALLET),
            StoryMenuItem('BIP-85 Wallet #2', b85, arg=1002, flags=TC_WORD_WALLET),
            StoryMenuItem('BIP-85 Wallet #3', b85, arg=1003, flags=TC_WORD_WALLET),
            StoryMenuItem('Legacy Wallet', "Uses duress wallet created on Mk3 Coldcard, using a fixed derivation.\n\nRecommended only for existing UTXO compatibility.", flags=TC_XPRV_WALLET),
            StoryMenuItem('Blank Coldcard', "Look and act like a freshly wiped Coldcard", flags=TC_BLANK_WALLET),
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
        FirstMenu = [
            #MenuItem('"%s" =>' % self.proposed_pin),
            MenuItem('[%s]' % self.proposed_pin),
            StoryMenuItem('Brick Self', "Become a brick instantly and forever.", flags=TC_BRICK),
            StoryMenuItem('Wipe Seed', "Wipe the seed and maybe do more. See next menu.",
                                            menu=self.WillWipeMenu),
            StoryMenuItem('Duress Wallet', "Goes directly to a specific duress wallet. No side effects.", menu=DuressOptions),
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

        rel = ['', '1st', '2nd', '3rd'][num] if num <= 3 else ('%dth' % num)

        m = MenuSystem([
            #              xxxxxxxxxxxxxxxx
            MenuItem('[%s WRONG PIN]' % rel),
            StoryMenuItem('Wipe, Stop', "Seed is wiped and a message is shown.",
                arg=num, flags=TC_WIPE),
            StoryMenuItem('Wipe & Reboot', "Seed is wiped and Coldcard reboots without notice.",
                            arg=num, flags=TC_WIPE|TC_REBOOT),
            StoryMenuItem('Silent Wipe', "Seed is silently wiped and Coldcard acts as if PIN code was just wrong.",
                            arg=num, flags=TC_WIPE|TC_FAKE_OUT),
            StoryMenuItem('Brick Self', "Become a brick instantly and forever.", flags=TC_BRICK),
            StoryMenuItem('Last Chance', "Wipe seed, then give one more try and then brick if wrong PIN.", arg=num, flags=TC_WIPE|TC_BRICK),
            StoryMenuItem('Look Blank', "Look and act like a freshly- wiped Coldcard but don't affect actual seed.", arg=num, flags=TC_BLANK_WALLET),
            StoryMenuItem('Just Reboot', "Reboot when this happens. Doesn't do anything else.", arg=num, flags=TC_REBOOT),
        ])

        m.goto_idx(1)
        the_ux.push(m)

    async def clear_all(self, m,l,item):
        if not await ux_confirm("Removing all trick PIN codes and special wrong-pin handling. Be sure to move the funds from any duress wallets."):
            return
        tp.clear_all()
        m.update_contents()

    async def hide_pin(self, m,l, item):
        pin, slot_num, flags = item.arg

        if flags & TC_DELTA_MODE:
            await ux_show_story('''Delta mode PIN will be hidden when this menu is shown \
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
        old_pin, slot_num, flags = item.arg

        new_pin = await self.get_new_pin(old_pin)
        if new_pin is None:
            return

        # TODO XXX chcek if delta mode ... must apply rules to new PIN
        #if flags & TC_DELTA_MODE:

        try:
            tp.update_slot(old_pin.encode(), new_pin=new_pin.encode())
            await ux_dramatic_pause("Changed.", 1)

            self.pop_submenu()      # too lazy to get redraw right
        except BaseException as exc:
            sys.print_exception(exc)
            await ux_show_story("Failed.")

    async def delete_pin(self, m,l, item):
        pin, slot_num, flags = item.arg

        if flags & (TC_WORD_WALLET | TC_XPRV_WALLET):
            if not await ux_confirm("The funds on this duress wallet have been moved already?"):
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
        if flags & TC_XPRV_WALLET:
            encoded = b'\x01' + slot.xdata[0:64]
        elif flags & TC_WORD_WALLET:
            encoded = b'\x82' + slot.xdata[0:32]
        else:
            raise ValueError(hex(flags))

        from glob import dis

        # switch over to new secret!
        dis.fullscreen("Applying...")
        pa.tmp_secret(encoded)
        tp.reload()

        await ux_show_story("New master key in effect until next power down.")

        from actions import goto_top_menu
        goto_top_menu()

    async def duress_details(self, m, l, item):
        # explain details of a duress wallet
        pin, flags, arg = item.arg
        if flags & TC_XPRV_WALLET:
            msg = '''The legacy duress wallet will be activated if '%s' is provded. \
You probably created this on an older Mk2 or Mk3 Coldcard. \
Wallet is XPRV-based and derived from a fixed path.''' % pin
        else:
            msg = '''BIP85-derived wallet (24 words), with index #%d, is provided if '%s'.''' \
                        % (arg, pin)

        ch = await ux_show_story(msg + '\n\nPress 6 to view associated secrets.', escape='6')
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
            else:
                msg, *_ = render_master_secrets('words', s.xdata[0:32], None)

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
                MenuItem('Change PIN', f=self.change_pin, arg=(pin, slot_num, flags)),
            )

        return rv

class StoryMenuItem(MenuItem):
    def __init__(self, label, story, flags=0, **kws):
        self.story = story
        self.flags = flags
        super().__init__(label, **kws)

    async def activate(self, menu, idx):
        ch = await ux_show_story(self.story)
        if ch == 'x':
            return

        if getattr(self, 'next_menu', None):
            # drill down more
            return await super().activate(menu, idx)

        # pop all, and note the path used
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
