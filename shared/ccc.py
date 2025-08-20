# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ccc.py - ColdCard Co-sign feature. Be a leg in a 2-of-3 that is signed based on a policy.
#
# Rebranding/single-signer additions:
#
# - "CCC" (was "ColdCard Cosigning") will now be branded as "Spending Policy: Multisig" 
# - single singer policies will be called "Spending Policy: Single Sig"
# - internally: CCC is the multisig stuff, vs SSSP: Single Signer Spending Policy
# - "hobbled" refers to less-than full control over Coldcard, even though you have main PIN
#
import gc, chains, version, ngu, web2fa, bip39, re
from chains import NLOCK_IS_TIME
from utils import swab32, xfp2str, truncate_address, deserialize_secret, show_single_address
from glob import settings, dis
from ux import ux_confirm, ux_show_story, the_ux, OK, ux_dramatic_pause, ux_enter_number, ux_aborted
from menu import MenuSystem, MenuItem, start_chooser
from seed import seed_words_to_encoded_secret
from stash import SecretStash
from charcodes import KEY_QR, KEY_CANCEL, KEY_NFC
from exceptions import SpendPolicyViolation


# limit to number of addresses in list
MAX_WHITELIST = const(25)

class LastFailReason:
    # We don't show the user the reason for policy fail (by design, so attacker
    # cannot maximize their take against the policy), but during setup/experiments
    # we offer to show the reason in the menu. Includes both SS and MS cases.
    # - now holding this in a setting so they can power-cycle and bypass to view
    
    @classmethod
    def record(cls, msg):
        settings.put('lfr', msg)

    @classmethod
    def get(cls):
        return settings.get('lfr', None)

    @classmethod
    def clear(cls):
        settings.remove_key('lfr')

class SpendingPolicy(dict):
    # Details of what is allowed or not. Same for single vs. multisig signing.
    # - a dict() but with write-thru to setting value

    def __init__(self, nvkey, pol_dict=None):
        # deserialize and construct
        #assert nvkey in { 'ccc', 'sssp' }
        self.nvkey = nvkey
        super().__init__()

        if pol_dict is not None:
            self.clear()
            self.update(pol_dict.items())
        else:
            v = dict(settings.get(self.nvkey, {})).get('pol', None)
            if v is not None:
                self.update(v.items())      # mpy bugfix, when called with SpendingPolicy
            

    def _update_policy(self):
        # serialize the spending policy, save it
        v = dict(settings.get(self.nvkey, {}))
        v['pol'] = self.copy()
        settings.set(self.nvkey, v)

    def update_policy_key(self, **kws):
        # update a few elements of the spending policy
        # - all settings "saved" as they are changed.
        # - return updated policy
        self.update(kws)
        self._update_policy()

    def meets_policy(self, psbt):
        # Does policy allow signing this? Else raise why. Return T if web2fa required.
        pol = self

        # not safe to sign any txn w/ warnings: might be complaining about
        # massive miner fees, or weird OP_RETURN stuff
        if psbt.warnings:
            raise SpendPolicyViolation("has warnings")

        # Magnitude: size limits for output side (non change)
        magnitude = pol.get("mag", None)
        if magnitude is not None:
            if magnitude < 1000:
                # it is a BTC, convert to sats
                magnitude = magnitude * 100000000

            outgoing = psbt.total_value_out - psbt.total_change_value
            if outgoing > magnitude:
                raise SpendPolicyViolation("magnitude")

        # Velocity: if zero => no velocity checks
        velocity = pol.get("vel", None)
        if velocity:
            if not psbt.lock_time:
                raise SpendPolicyViolation("no nLockTime")

            if psbt.lock_time >= NLOCK_IS_TIME:
                # this is unix timestamp - not allowed - fail
                raise SpendPolicyViolation("nLockTime not height")

            block_h = pol.get("block_h", chains.current_chain().ccc_min_block)
            if psbt.lock_time <= block_h:
                raise SpendPolicyViolation("rewound (%d)" % psbt.lock_time)

            # we won't sign txn unless old height + velocity >= new height
            if psbt.lock_time < (block_h + velocity):
                raise SpendPolicyViolation("velocity (%d)" % psbt.lock_time)

        # Whitelist of outputs addresses
        wl = pol.get("addrs", None)
        if wl:
            c = chains.current_chain()
            wl = set(wl)
            for idx, txo in psbt.output_iter():
                out = psbt.outputs[idx]
                if not out.is_change:  # ignore change
                    addr = c.render_address(txo.scriptPubKey)
                    if addr not in wl:
                        raise SpendPolicyViolation("whitelist: " + addr)

        # Web 2FA
        # - slow, requires UX, and they might not acheive it...
        # - wait until about to do signature
        if pol.get('web2fa', False):
            psbt.warnings.append(('CCC', 'Web 2FA required.'))
            return True

    async def web2fa_challenge(self, msg):
        # they are trying to sign something, so make them get out their phone
        # - at this point they have already ok'ed the details of the txn
        # - and we have approved other elements of the spending policy.
        # - could show MS wallet name, or txn details but will not because that is
        #   an info leak to Coinkite... and we just don't want to know.
        assert self.get('web2fa')

        ok = await web2fa.perform_web2fa(msg, self.get('web2fa'))
        if not ok:
            LastFailReason.record('2FA Fail')
            raise SpendPolicyViolation

    def update_last_signed(self, psbt):
        # Call after successfully signing a PSBT ... notes the height involved.
        # - might add other things besides height here someday
        LastFailReason.clear()

        old_h = self.get('block_h', 1)

        if old_h < psbt.lock_time < NLOCK_IS_TIME:
            # always update last block height, even if velocity isn't enabled yet
            # - attacker might have changed to testnet, but there is no
            #   reason to ever lower block height. strictly ascending
            self.update_policy_key(block_h=psbt.lock_time)
            settings.save()

class SSSPFeature:
    # Using setting value "sssp"

    @classmethod
    def is_enabled(cls):
        return sssp_spending_policy('en')

    @classmethod
    def update_last_signed(cls, psbt):
        # new PSBT has been completely signed successfully.
        if not cls.is_enabled():
            return
        pol = cls.get_policy()
        pol.update_last_signed(psbt)

    @classmethod
    def default_policy(cls):
        # a very basic and permissive policy, but non-zero too.
        # - 1BTC per day
        chain = chains.current_chain()
        return SpendingPolicy('sssp', dict(mag=1, vel=144,
                                        block_h=chain.ccc_min_block, web2fa='', addrs=[]))

    @classmethod
    def get_policy(cls):
        # de-serialize just the spending policy
        return SpendingPolicy('sssp')

    @classmethod
    def can_allow(cls, psbt):
        # We are looking at a PSBT: should we let user sign it, or block?
        # - return (block_signing, needs_2fa_step)
        if not cls.is_enabled():
            exists = bool(settings.get('sssp', False))
            if exists:
                # this will not block CCC co-signing, because that test is already
                # done before this call.
                psbt.warnings.append(('SP', "Spending Policy defined but disabled."))
            return False, False

        try:
            # check policy
            pol = cls.get_policy()
            needs_2fa = pol.meets_policy(psbt)
        except SpendPolicyViolation as e:
            LastFailReason.record(str(e))
            # caller will show msg
            return True, False

        return False, needs_2fa

    @classmethod
    async def web2fa_challenge(cls):
        # they are trying to sign something, so make them get out their phone
        # - at this point they have already ok'ed the details of the txn
        # - and we have approved other elements of the spending policy.
        # - could show MS wallet name, or txn details but will not because that is
        #   an info leak to Coinkite... and we just don't want to know.
        await cls.get_policy().perform_web2fa('Approve Transaction')


class CCCFeature:
    # Using setting value "ccc"

    @classmethod
    def is_enabled(cls):
        # Is the feature enabled right now?
        return bool(settings.get('ccc', False))

    @classmethod
    def words_check(cls, words):
        # Test if words provided are right
        enc = seed_words_to_encoded_secret(words)
        exp = cls.get_encoded_secret()
        return enc == exp

    @classmethod
    def get_num_words(cls):
        # return 12 or 24
        return SecretStash.is_words(cls.get_encoded_secret())

    @classmethod
    def get_encoded_secret(cls):
        # Gets the key C as encoded binary secret, compatible w/
        # encodings used in stash.
        return deserialize_secret(settings.get('ccc')['secret'])

    @classmethod
    def get_xfp(cls):
        # Just the XFP value for our key C
        ccc = settings.get('ccc')
        return ccc['c_xfp'] if ccc else None

    @classmethod
    def get_master_xpub(cls):
        ccc = settings.get('ccc')
        return ccc['c_xpub'] if ccc else None

    @classmethod
    def init_setup(cls, words):
        # Encode 12 or 24 words into the secret to held as key C.
        # - also capture XFP and XPUB for key C
        # TODO: move to "storage locker"?
        assert len(words) in (12, 24)
        enc = seed_words_to_encoded_secret(words)
        _,_,node = SecretStash.decode(enc)

        chain = chains.current_chain()
        xfp = swab32(node.my_fp())
        xpub = chain.serialize_public(node)     # fully useless value tho

        # NOTE: b_xfp and b_xpub still needed, but that's another step, not yet.

        v = dict(secret=SecretStash.storage_serialize(enc),
                 c_xfp=xfp, c_xpub=xpub,
                 pol=CCCFeature.default_policy())

        settings.put('ccc', v)
        settings.save()

    @classmethod
    def default_policy(cls):
        # a very basic and permissive policy, but non-zero too.
        # - 1BTC per day
        chain = chains.current_chain()
        return SpendingPolicy('ccc', dict(mag=1, vel=144, 
                                        block_h=chain.ccc_min_block, web2fa='', addrs=[]))

    @classmethod
    def get_policy(cls):
        # de-serialize just the spending policy
        return SpendingPolicy('ccc')

    @classmethod
    def remove_ccc(cls):
        # delete our settings complete; lose key C .. already confirmed
        # - leave MS in place
        settings.remove_key('ccc')
        settings.save()

    @classmethod
    def could_cosign(cls, psbt):
        # We are looking at a PSBT: can we sign it, and would we?
        # - if we **could** but will not, due to policy, add warning msg
        # - return (we could sign, needs 2fa step)
        if not cls.is_enabled():
            return False, False

        ms = psbt.active_multisig
        if not ms:
            # not multisig, so ignore/permit
            return False, False

        # TODO: if key B has already signed the PSBT, and so we don't need key C,
        #       don't try to sign; maybe show warning?

        xfp = cls.get_xfp()
        if  xfp not in ms.xfp_paths:
            # does not involve us
            return False, False

        try:
            # check policy
            pol = cls.get_policy()
            needs_2fa = pol.meets_policy(psbt)
        except SpendPolicyViolation as e:
            LastFailReason.record(str(e))
            psbt.warnings.append(('CCC', "Violates spending policy. Won't sign."))
            return False, False

        return True, needs_2fa

    @classmethod
    def sign_psbt(cls, psbt):
        # do the math
        psbt.sign_it(cls.get_encoded_secret(), cls.get_xfp())
        LastFailReason.clear()

        pol = cls.get_policy()
        pol.update_last_signed(psbt)

    @classmethod
    async def web2fa_challenge(cls):
        # do UX for web2fa; user is given option to proceed even if it fails
        # (without the co-signing)
        await cls.get_policy().web2fa_challenge('Approve Transaction: Co-Sign')


def render_mag_value(mag):
    # handle integer bitcoins, and satoshis in same value
    if mag < 1000:
        return '%d BTC' % mag
    else:
        return '%d SATS' % mag


class CCCConfigMenu(MenuSystem):
    def __init__(self):
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    def construct(self):
        from multisig import MultisigWallet, make_ms_wallet_menu

        my_xfp = CCCFeature.get_xfp()
        items = [
            MenuItem(('[%s] Co-Signing' if version.has_qwerty else '[%s]')
                            % xfp2str(my_xfp), f=self.show_ident),
            MenuItem('Spending Policy', 
                menu=lambda *a: SpendingPolicyMenu.be_a_submenu(CCCFeature.get_policy())),
            MenuItem('Export CCC XPUBs', f=self.export_xpub_c),
            MenuItem('Multisig Wallets'),
        ]

        # look for wallets that are defined related to CCC feature, shortcut to them
        count = 0
        for ms in MultisigWallet.get_all():
            if my_xfp in ms.xfp_paths:
                items.append(MenuItem('↳ %d/%d: %s' % (ms.M, ms.N, ms.name),
                                        menu=make_ms_wallet_menu, arg=ms.storage_idx))
                count += 1

        items.append(MenuItem('↳ Build 2-of-N', f=self.build_2ofN, arg=count))

        if LastFailReason.get():
            #         xxxxxxxxxxxxxxxx
            items.insert(1, MenuItem('Last Violation', f=self.debug_last_fail))

        items.append(MenuItem('Load Key C', f=self.enter_temp_mode))
        items.append(MenuItem('Remove CCC', f=self.remove_ccc))

        return items

    async def debug_last_fail(self, *a):
        # debug for customers: why did we reject that last txn?
        pol = CCCFeature.get_policy()
        bh = pol.get('block_h', None)
        msg = ''
        if bh:
            msg += "CCC height:\n\n%s\n\n" % bh

        lfr = LastFailReason.get()
        msg += 'The most recent policy check failed because of:\n\n%s\n\nPress (4) to clear.' \
                    % lfr
        ch = await ux_show_story(msg, escape='4')

        if ch == '4':
            LastFailReason.clear()
            self.update_contents()

    async def remove_ccc(self, *a):
        # disable and remove feature
        if not await ux_confirm('Key C will be lost, and policy settings forgotten.'
                                ' This unit will only be able to partly sign transactions.'
                                ' To completely remove this wallet, proceed to the multisig'
                                ' menu and remove related wallet entries.'):
            return

        if not await ux_confirm("Funds in related wallet/s may be impacted.", confirm_key='4'):
            return await ux_aborted()

        CCCFeature.remove_ccc()
        the_ux.pop()

    async def on_cancel(self):
        # trying to exit from CCCConfigMenu
        from seed import in_seed_vault

        enc = CCCFeature.get_encoded_secret()

        if in_seed_vault(enc):
            # remind them to clear the seed-vault copy of Key C because it defeats feature
            await ux_show_story("Key C is in your Seed Vault. If you are done with setup, "
                                "you MUST delete it from the Vault!", title='REMINDER')

        the_ux.pop()

    async def export_xpub_c(self, *a):
        # do standard Coldcard export for multisig setups
        xfp = CCCFeature.get_xfp()
        enc = CCCFeature.get_encoded_secret()

        from multisig import export_multisig_xpubs
        await export_multisig_xpubs(xfp=xfp, alt_secret=enc, skip_prompt=True)

    async def build_2ofN(self, m, l, i):
        count = i.arg
        # ask for a key B, assume A and C are defined => export MS config and import into self.
        # - like the airgap setup, but assume A and C are this Coldcard
        m = '''Builds simple 2-of-N multisig wallet, with this Coldcard's main secret (key A), \
the CCC policy-controlled key C, and at least one other device, as key B. \
\nYou will need to export the XPUB from another Coldcard and place it on an SD Card, or \
be ready to show it as a QR, before proceeding.'''
        if await ux_show_story(m) != 'y':
            return

        from multisig import create_ms_step1

        # picks addr fmt, QR or not, gets at least one file, then...
        await create_ms_step1(for_ccc=(CCCFeature.get_encoded_secret(), count))

        # prompt for file, prompt for our acct number, unless already exported to this card?

    async def show_ident(self, *a):
        # give some background? or just KISS for now?
        xfp = xfp2str(CCCFeature.get_xfp())
        xpub = CCCFeature.get_master_xpub()
        await ux_show_story(
            "Key C:\n\n"
            "XFP (Master Fingerprint):\n\n  %s\n\n"
            "Master Extended Public Key:\n\n  %s " % (xfp, xpub))

    async def enter_temp_mode(self, *a):
        # apply key C as temp seed, so you can do anything with it
        # - just a shortcut, since they have the words, and could enter them
        # - one-way trip because the CCC feature won't be enabled inside the temp seed settings
        if await ux_show_story(
            'Loads the CCC controlled seed (key C) as a Temporary Seed and allows '
            'easy use of all Coldcard features on that key.\n\nIf you save into Seed Vault, '
            'access to CCC Config menu is quick and easy.') != 'y':
            return

        from seed import set_ephemeral_seed
        from actions import goto_top_menu

        enc = CCCFeature.get_encoded_secret()
        await set_ephemeral_seed(enc, origin='Key C from CCC')

        goto_top_menu()


class SPAddrWhitelist(MenuSystem):
    # simulator arg:    --seq tcENTERENTERsENTERwENTER
    def __init__(self, pol):
        self.policy = pol
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def be_a_submenu(cls, pol, *a):
        return cls(pol)

    def construct(self):
        # list of addresses
        addrs = self.policy.get('addrs', [])
        maxxed = (len(addrs) >= MAX_WHITELIST)

        items = []
        # better to show usability options at the top, as we can have up to 25 addresses in the menu
        if version.has_qr:
            items.append(MenuItem('Scan QR', f=(self.maxed_out if maxxed else self.scan_qr),
                                                    shortcut=KEY_QR))

        items.append(MenuItem('Import from File',
                f=(self.maxed_out if maxxed else self.import_file)))

        # show most recent added addresses at the top of the menu list
        a_items = [MenuItem(truncate_address(a), f=self.edit_addr, arg=a) for a in addrs[::-1]]

        if a_items:
            items += a_items
            if len(a_items) > 1:
                items.append(MenuItem("Clear Whitelist", f=self.clear_all))
        else:
            items.append(MenuItem("(none yet)"))

        return items

    async def edit_addr(self, menu, idx, item):
        # show detail and offer delete
        addr = item.arg
        msg = ('Spends to this address will be permitted:\n\n%s'
               '\n\nPress (4) to delete.' % show_single_address(addr))
        ch = await ux_show_story(msg, escape='4')
        if ch == '4':
            self.delete_addr(addr)

    def delete_addr(self, addr):
        # no confirm, stakes are low
        addrs = self.policy.get('addrs', [])
        addrs.remove(addr)
        self.policy.update_policy_key(addrs=addrs)
        self.update_contents()

    async def clear_all(self, *a):
        if await ux_confirm("Remove all addresses from the whitelist?", confirm_key='4'):
            self.policy.update_policy_key(addrs=[])
            self.update_contents()

    async def import_file(self, *a):
        # Import from a file, or NFC.
        # - simulator:  --seq tcENTERENTERsENTERwENTERiENTER1
        # - very forgiving, does not care about file format
        # - but also silent on all errors
        from ux import import_export_prompt
        from glob import NFC
        from actions import file_picker
        from files import CardSlot
        from utils import cleanup_payment_address

        choice = await import_export_prompt("List of addresses", is_import=True, no_qr=True)

        if choice == KEY_CANCEL:
            return
        elif choice == KEY_NFC:
            addr = await NFC.read_address()
            if not addr:
                # error already displayed in nfc.py
                return

            await self.add_addresses([addr])
            return

        # loose RE to match any group of chars that could be addresses
        # - really just removing whitespace and punctuation
        # - lacking re.findall(), so using re.split() on negatives
        pat = re.compile(r'[^A-Za-z0-9]')

        # pick a likely-looking file: just looking at size and extension
        fn = await file_picker(suffix=['csv', 'txt'],
                                min_size=20, max_size=20000,
                                none_msg="Must contain payment addresses", **choice)

        if not fn: return

        results = []
        with CardSlot(readonly=True, **choice) as card:
            with open(fn, 'rt') as fd:
                for ln in fd.readlines():
                    if len(results) >= MAX_WHITELIST:
                        # no need to clog memory and parse more, we're done
                        break
                    for here in pat.split(ln):
                        if len(here) >= 4:
                            try:
                                addr = cleanup_payment_address(here)
                                results.append(addr)
                            except: pass

        if not results:
            await ux_show_story("Unable to find any payment addresses in that file.")
        else:
            # silently limit to first 25 results; lets them use addresses.csv easily
            await self.add_addresses(results[:MAX_WHITELIST])


    async def scan_qr(self, *a):
        # Scan and return a text string. For things like BIP-39 passphrase
        # and perhaps they are re-using a QR from something else. Don't act on contents.
        from ux_q1 import QRScannerInteraction
        q = QRScannerInteraction()

        got = []
        ln = ''
        while 1:
            here = await q.scan_for_addresses("Bitcoin Address(es) to Whitelist", line2=ln)
            if not here: break
            for addr in here:
                if addr not in got:
                    got.append(addr)
                    ln = 'Got %d so far. ENTER to apply.' % len(got)

        if got:
            # import them
            await self.add_addresses(got)

    async def maxed_out(self, *a):
        await ux_show_story("Max %d items in whitelist. Please make room first." % MAX_WHITELIST)

    async def add_addresses(self, more_addrs):
        # add new entries, if unique; preserve ordering
        addrs = self.policy.get('addrs', [])
        new = []
        for a in more_addrs:
            if a not in addrs:
                addrs.append(a)
                new.append(a)

        if not new:
            await ux_show_story("Already in whitelist:\n\n" +
                                '\n\n'.join(show_single_address(a) for a in more_addrs))
            return

        if len(addrs) > MAX_WHITELIST:
            return await self.maxed_out()

        self.policy.update_policy_key(addrs=addrs)
        self.update_contents()

        if len(new) > 1:
            await ux_show_story("Added %d new addresses to whitelist:\n\n%s" %
                (len(new), '\n\n'.join(show_single_address(a) for a in new)))
        else:
            await ux_show_story("Added new address to whitelist:\n\n%s" %
                                        show_single_address(new[0]))

class SPCheckedMenuItem(MenuItem):
    # Show a checkmark if **policy** setting is defined and not the default
    # - only works inside SpendingPolicyMenu
    def __init__(self, label, polkey, **kws):
        super().__init__(label, **kws)
        self.polkey = polkey

    def is_chosen(self):
        # should we show a check in parent menu? check the policy
        m = the_ux.top_of_stack()
        #assert isinstance(m, SpendingPolicyMenu)
        return bool(m.policy.get(self.polkey, False))

class SpendingPolicyMenu(MenuSystem):
    # Build menu stack that allows edit of all features of the spending
    # policy. 
    # - supports both CCC and SSSP modes w/ same policies
    # - Key C is set already at this point.
    # - and delete/cancel CCC (clears setting?)
    # - be a sticky menu that's hard to exit (ie. SAVE choice and no cancel out)

    def __init__(self, pol):
        self.policy = pol
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def be_a_submenu(cls, pol, *a):
        return cls(pol)

    def construct(self):
        items = [
            #                xxxxxxxxxxxxxxxx
            SPCheckedMenuItem('Max Magnitude', 'mag', f=self.set_magnitude),
            SPCheckedMenuItem('Limit Velocity', 'vel', f=self.set_velocity),
            SPCheckedMenuItem('Whitelist' + (' Addresses' if version.has_qr else ''),
                                    'addrs',
                                menu=lambda *a: SPAddrWhitelist.be_a_submenu(self.policy)),
            SPCheckedMenuItem('Web 2FA', 'web2fa', f=self.toggle_2fa),
        ]

        if self.policy.get('web2fa'):
            items.extend([
                MenuItem('↳ Test 2FA', f=self.test_2fa),
                MenuItem('↳ Enroll More', f=self.enroll_more_2fa),
            ])

        return items

    async def test_2fa(self, *a):
        ss = self.policy.get('web2fa')
        assert ss
        ok = await web2fa.perform_web2fa('Testing Only', ss)

        await ux_show_story('Correct code was given.' if ok else 'Failed or aborted.')

    async def enroll_more_2fa(self, *a):
        # let more phones in on the party, but they get same shared secret
        ss = self.policy.get('web2fa')
        assert ss
        await web2fa.web2fa_enroll(ss)

    async def set_magnitude(self, *a):
        # Looks decent on both Q and Mk4...
        was = self.policy.get('mag', 0)
        val = await ux_enter_number('Transaction Max:', max_value=int(1e8),
                                    can_cancel=True, value=(was or ''))

        args = dict(mag=val)
        if (val is None) or (val == was):
            msg = "Did not change"
            val = was
        else:
            msg = "You have set the"
            unchanged = False

        if not val:
            msg = "No check for maximum transaction size will be done. "
            if self.policy.get('vel', 0):
                msg += 'Velocity check also disabled. '
                args['vel'] = 0
        else:
            msg += " maximum per-transaction: \n\n  %s" % render_mag_value(val)

        self.policy.update_policy_key(**args)

        await ux_show_story(msg, title="TX Magnitude")
        
    async def set_velocity(self, *a):
        mag = self.policy.get('mag', 0) or 0

        if not mag:
            msg = 'Velocity limit requires a per-transaction magnitude to be set.'\
                  ' This has been set to 1BTC as a starting value.'
            self.policy.update_policy_key(mag=1)

            await ux_show_story(msg)

        start_chooser(self.velocity_chooser)


    def velocity_chooser(self):
        # offer some useful values from a menu
        vel = self.policy.get('vel', 0)        # in blocks

        # reminder: dont forget the poor Mk4 users
        #        xxxxxxxxxxxxxxxx
        ch = [  'Unlimited',
                '6 blocks (hour)',
                '24 blocks (4h)',
                '48 blocks (8h)',
                '72 blocks (12h)',
                '144 blocks (day)',
                '288 blocks (2d)',
                '432 blocks (3d)',
                '720 blocks (5d)',
                '1008 blocks (1w)',
                '2016 blocks (2w)',
                '3024 blocks (3w)',
                '4032 blocks (4w)',
              ]
        va = [0] + [int(x.split()[0]) for x in ch[1:]]

        try:
            which = va.index(vel)
        except ValueError:
            which = 0

        def set(idx, text):
            self.policy.update_policy_key(vel=va[idx])

        return which, ch, set

    async def toggle_2fa(self, *a):
        if self.policy.get('web2fa'):
            # enabled already

            if not await ux_confirm("Disable web 2FA check? Effect is immediate."):
                return

            self.policy.update_policy_key(web2fa='')
            self.update_contents()

            await ux_show_story("Web 2FA has been disabled. If you re-enable it, a new "
                    "secret will be generated, so it is safe to remove it from your "
                    "phone at this point.")

            return

        ch = await ux_show_story('''When enabled, any spend (signing) requires \
use of mobile 2FA application (TOTP RFC-6238). Shared-secret is picked now, \
and loaded on your phone via QR code.

WARNING: You will not be able to sign transactions if you do not have an NFC-enabled \
phone with Internet access and 2FA app holding correct shared-secret.''',
                    title="Web 2FA")
        if ch != 'y':
            return

        # challenge them, and don't set unless it works
        ss = await web2fa.web2fa_enroll()
        if not ss:
            return

        # update state
        self.policy.update_policy_key(web2fa=ss)
        self.update_contents()

async def gen_or_import():
    # returns 12 words, or None to abort
    from seed import WordNestMenu, generate_seed, approve_word_list, SeedVaultChooserMenu

    msg = "Press %s to generate a new 12-word seed phrase to be used "\
          "as the Coldcard Co-Signing Secret (key C).\n\nOr press (1) to import existing "\
          "12-words or (2) for 24-words import." % OK

    if settings.master_get("seedvault", False):
        msg += ' Press (6) to import from Seed Vault.'

    ch = await ux_show_story(msg, escape='126', title="CCC Key C")

    if ch in '12':
        nwords = 24 if ch == '2' else 12

        async def done_key_C_import(words):
            if not version.has_qwerty:
                WordNestMenu.pop_all()
            await enable_step1(words)

        if version.has_qwerty:
            from ux_q1 import seed_word_entry
            await seed_word_entry('Key C Seed Words', nwords, done_cb=done_key_C_import)
        else:
            nxt = WordNestMenu(nwords, done_cb=done_key_C_import)
            the_ux.push(nxt)

        return None     # will call parent again

    elif ch == '6':
        # pick existing from Seed Vault
        picked = await SeedVaultChooserMenu.pick(words_only=True)
        if picked:
            words = SecretStash.decode_words(deserialize_secret(picked.encoded))
            await enable_step1(words)

        return None

    elif ch == 'y':
        # normal path: pick 12 words, quiz them
        await ux_dramatic_pause('Generating...', 3)
        seed = generate_seed()
        words = await approve_word_list(seed, 12)
    else:
        return None

    return words


async def toggle_ccc_feature(*a):
    # The only menu item show to user!
    if settings.get('ccc'):
        return await modify_ccc_settings()

    # enable the feature -- not simple!
    # - create C key (maybe import?)
    # - collect a policy setup, maybe 2FA enrol too
    # - lock that down
    # - TODO copy
    ch = await ux_show_story('''\
Adds an additional seed to your Coldcard, and enforces a "spending policy" whenever \
it signs with that key. Spending policies can restrict: magnitude (BTC out), \
velocity (blocks between txn), address whitelisting, and/or require confirmation by 2FA phone app.

Assuming the use of a 2-of-3 multisig wallet, keys are as follows:\n
A=Coldcard (master seed), B=Backup Key (offline/recovery), C=Spending Policy Key. 

Spending policy cannot be viewed or changed without knowledge of key C.\
''',
        title="Coldcard Co-Signing" if version.has_qwerty else 'CC Co-Sign')

    if ch != 'y': 
        # just a tourist
        return

    await enable_step1(None)

async def enable_step1(words):
    if not words:
        words = await gen_or_import()
        if not words: return

    dis.fullscreen("Wait...")
    dis.busy_bar(True)
    try:
        # do BIP-32 basics: capture XFP and XPUB and encoded version of the secret
        CCCFeature.init_setup(words)
    finally:
        dis.busy_bar(False)

    # continue into config menu
    m = CCCConfigMenu()

    the_ux.push(m)

async def modify_ccc_settings():
    # Generally not expecting changes to policy on the fly because
    # that's the whole point. Use the B key to override individual spends
    # but if you can prove you have C key, then it's harmless to allow changes
    # since you could just spend as needed.

    enc = CCCFeature.get_encoded_secret()
    bypass = False

    from seed import in_seed_vault
    if in_seed_vault(enc):
        # If seed vault enabled and they have the key C in there already, just go
        # directly into menu (super helpful for debug/setup/testing time). We do warn tho.
        await ux_show_story('''You have a copy of the CCC key C in the Seed Vault, so \
you may proceed to change settings now.\n\nYou must delete that key from the vault once \
setup and debug is finished, or all benefit of this feature is lost!''', title='REMINDER')

        bypass = True

    else:
        ch = await ux_show_story(
            "Spending policy cannot be viewed, changed nor disabled, "
            "unless you have the seed words for key C.",
            title="CCC Enabled")

        if ch != 'y': return

    if bypass:
        # doing full decode cycle here for better testing
        chk, raw, _ = SecretStash.decode(enc)
        assert chk == 'words'
        words = bip39.b2a_words(raw).split(' ')
        await key_c_challenge(words)
        return

    # small info-leak here: exposing 12 vs 24 words, but we expect most to be 12 anyway
    nwords = CCCFeature.get_num_words()

    import seed
    if version.has_qwerty:
        from ux_q1 import seed_word_entry
        await seed_word_entry('Enter Seed Words', nwords, done_cb=key_c_challenge)
    else:
        return seed.WordNestMenu(nwords, done_cb=key_c_challenge)

NUM_CHALLENGE_FAILS = 0

async def key_c_challenge(words):
    # They entered some words, if they match our key C then allow edit of policy

    if not version.has_qwerty:
        from seed import WordNestMenu
        WordNestMenu.pop_all()

    dis.fullscreen('Verifying...')
    
    if not CCCFeature.words_check(words):
        # keep an in-memory counter, and after 3 fails, reboot
        global NUM_CHALLENGE_FAILS
        NUM_CHALLENGE_FAILS += 1
        if NUM_CHALLENGE_FAILS >= 3:
            from utils import clean_shutdown
            clean_shutdown()

        await ux_show_story("Sorry, those words are incorrect.")
        return

    # success. they are in.

    # got to config menu
    m = CCCConfigMenu()
    the_ux.push(m)

def sssp_spending_policy(key, default=False, change=None):
    # This function can be used to check if feature(s) are enabled in
    # the single-signer policy settings. Might be used while hobbled.
    # keys:
    #   'en' = feature enabled; hobble on next boot
    #   'notes' = allow access to knows
    #   'words' = add first/last seed words to challenge to unlock
    #   'okeys' = allow BIP-39 and/or seed vault

    v = settings.get('sssp', dict())

    if key in { 'en', 'notes', 'words', 'okeys' }:
        # booleans: present or removed from dict
        if change is not None:
            if change:
                v[key] = True
            else:
                v.pop(key, None)

            settings.put('sssp', v)
            settings.save()

        return (key in v) or default

    raise KeyError(key)

    return default

async def sssp_feature_menu(*a):
    # Show the top menu for SSSP feature, or enable access first time.
    from pincodes import pa
    from actions import goto_top_menu

    if pa.hobbled_mode == 2:
        # allow exit from test-drive mode, directly into editing settings
        pa.hobbled_mode = False
        goto_top_menu()
    elif settings.get('sssp'):
        # normal entry into menu system, after the first time
        assert not pa.hobbled_mode
    else:
        # tell them a story, and maybe enable feature
        en = await sssp_enable()
        if not en: return

    m = SSSPConfigMenu()
    the_ux.push(m)

async def sssp_enable():
    # enabling the feature
    # - collect and setup a new trick pin
    # - set sssp settings w/ something non-empty but still disabled.
    # - return T if they completed enabling process

    from login import LoginUX
    from trick_pins import tp
    from pincodes import pa

    # enable the feature -- not simple!
    # - pick new (trick pin) that lets you back here.
    # - collect a policy setup, maybe 2FA enrol too
    # - lock that down
    ch = await ux_show_story('''\
You can define a "spending policy" which stops you from signing \
transactions unless conditions are met.
Spending policies can restrict: magnitude (BTC out), \
velocity (blocks between txn), address whitelisting, \
and/or require confirmation by 2FA phone app.

When active, your COLDCARD \
is locked into a special mode that restricts seed access, backups, settings and other features.

First step is to define a new PIN code that is used when you want to bypass or \
disable this feature.
''',
        title="Spending Policy")

    if ch != 'y': 
        # just a tourist
        return


    # re-use existing PIN if there for some reason
    new_pin = tp.has_sp_unlock()

    if not new_pin:
        # all existing PINS
        have = set(tp.all_tricks())
        have.add(pa.pin.decode())

        while 1:
            lll = LoginUX()
            lll.is_setting = True
            lll.subtitle = "Spending Policy" + (" Unlock" if version.has_qwerty else '')

            new_pin = await lll.get_new_pin()
            if new_pin is None:
                return

            if (new_pin not in have):
                tp.define_unlock_pin(new_pin)
                break

            await ux_show_story("That PIN (%s) is already in use. All PIN codes must be unique."
                                            % new_pin)

    # all features disabled to to start
    settings.set('sssp', dict(en=False, pol={}))
    settings.save()

    # continue into config menu
    return True

async def sssp_word_challenge(*a):
    # Ask for first/last seed word and verify. Return if correct answers given.
    # Reboots on failure.
    from stash import SensitiveValues

    with SensitiveValues() as sv:
        if sv.mode == 'words':
            words = bip39.b2a_words(sv.raw).split(' ')
            want_words = words[:1] + words[-1:]
            assert len(want_words) == 2
        else:
            # they are using XPRV or something, skip test entirely
            return

    got_words = None
    for retry in range(2):
        if version.has_qwerty:
            # see special rendering code for this case in ux_q1.py:ux_draw_words(num_words=2)
            from ux_q1 import seed_word_entry
            got_words = await seed_word_entry('First and Last Seed Words', 2, has_checksum=False)
        else:
            from seed import WordNestMenu

            # TODO: fix bugs here on Mk4. really not working. XXX 

            got_words = None
            async def check_challenge_cb(words):
                WordNestMenu.pop_all()
                got_words = words

            m = WordNestMenu(num_words=2, has_checksum=False, done_cb=check_challenge_cb)
            the_ux.push(m)
            await m.interact()

        if got_words == want_words:
            # success - done
            return

        await ux_show_story("Sorry, those words are incorrect.")

    # they failed; log them out ... they can just try login again
    from actions import login_now
    login_now()

    # NOT-REACHED

class SSSPCheckedMenuItem(MenuItem):
    # Show a checkmark if **top level** security setting is defined and not the default
    # - only works inside SSSPPolicyMenu?
    # - similar to menu.py:ToggleMenuItem

    def __init__(self, label, polkey, story, **kws):
        super().__init__(label, **kws)
        self.polkey = polkey
        self.story = story

    def is_chosen(self):
        # should we show a check in menu? check the current SSSP settings
        return sssp_spending_policy(self.polkey)

    async def activate(self, menu, idx):
        # do simple toggle on request
        was = sssp_spending_policy(self.polkey)

        msg = self.story + "\n\n%s?" % ('Disable' if was else 'Enable')

        ch = await ux_show_story(msg)
        if ch == 'x': return

        sssp_spending_policy(self.polkey, change=(not was))


class SSSPConfigMenu(MenuSystem):
    def __init__(self):
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    def construct(self):
        from multisig import MultisigWallet, make_ms_wallet_menu

        items = [
            #         xxxxxxxxxxxxxxxx
            MenuItem('Edit Policy...', 
                menu=lambda *a: SpendingPolicyMenu.be_a_submenu(SSSPFeature.get_policy())),
            SSSPCheckedMenuItem('Word Check', 'words', 'To change Spending Policy, in addition to special PIN, you must provide the first and last seed words.'),
            SSSPCheckedMenuItem('Allow Notes', 'notes', 'Allow (read-only) access to secure notes and passwords? Otherwise, they are inaccessible.'),
            SSSPCheckedMenuItem('Related Keys', 'okeys', 'Allow access to BIP-39 passphrase wallets based on master seed, or Seed Vault (if any). Same spending Policy applies to all.'),
            #MenuItem('Test Word Challenge', f=sssp_word_challenge),     # XXX test only?
        ]

        if LastFailReason.get():
            #                         xxxxxxxxxxxxxxxx
            items.insert(1, MenuItem('Last Violation', f=self.debug_last_fail))

        items.append(MenuItem('Remove Policy', f=self.remove_sssp))
        items.append(MenuItem('Test Drive', f=self.test_drive))
        items.append(MenuItem('ACTIVATE', f=self.activate_feature))

        return items

    async def activate_feature(self, *a):
        # Policy is being set in stone now; confirm and switch to hobble mode, etc.
        from trick_pins import tp

        bypass_pin = tp.has_sp_unlock()

        if not bypass_pin:
            msg = "You have no Spending Policy bypass PIN defined, so changes to this COLDCARD cannot be made past this point. Only option will be to destroy seed and reload everything."
        else:
            msg = "To return to normal unlimited spending mode, you will need to enter the special pin (%s), then the Main PIN" % bypass_pin
            if sssp_spending_policy('words'):
                msg += ', followed by the first and last seed words'
            msg += '.'

        if not await ux_confirm(msg, 'CONTINUE?'):
            return

        # set it for next login
        sssp_spending_policy('en', change=True)

        # make it real ... could reboot here instead, but no need.
        from pincodes import pa
        from actions import goto_top_menu

        pa.hobbled_mode = True
        goto_top_menu()

    async def test_drive(self, *a):
        # allow test drive of feature
        if not await ux_confirm("See what COLDCARD operation will look like with Spending Policy enabled.", 'CONTINUE?'):
            return

        from pincodes import pa
        from actions import goto_top_menu

        pa.hobbled_mode = 2      # Truthy value to indicate they can escape easily
        goto_top_menu()

    async def debug_last_fail(self, *a):
        # debug for customers: why did we reject that last txn?
        pol = SSSPFeature.get_policy()
        bh = pol.get('block_h', None)
        msg = ''
        if bh:
            msg += "Last height:\n\n%s\n\n" % bh

        lfr = LastFailReason.get()
        msg += 'The most recent policy check failed because of:\n\n%s\n\nPress (4) to clear.' \
                    % lfr
        ch = await ux_show_story(msg, escape='4')

        if ch == '4':
            LastFailReason.clear()
            self.update_contents()

    async def remove_sssp(self, *a):
        # disable and remove feature
        if not await ux_confirm('Bypass PIN will be removed, and all spending policy settings forgotten.'):
            return

        settings.remove_key('sssp')
        settings.save()

        from trick_pins import tp
        tp.delete_sp_unlock_pins()

        the_ux.pop()


# EOF
