# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ccc.py - ColdCard Cosign feature. Be a leg in a 2-of-3 that signed based on policy.
#
import gc, chains, version, ngu, web2fa, bip39, re
from utils import swab32, a2b_hex, b2a_hex, xfp2str, truncate_address
from glob import settings
from ux import ux_confirm, ux_show_story, the_ux, OK, ux_dramatic_pause, ux_enter_number
from menu import MenuSystem, MenuItem
from seed import seed_words_to_encoded_secret
from stash import SecretStash, len_from_marker, len_to_numwords
from charcodes import KEY_QR, KEY_CANCEL, KEY_NFC

class CCCFeature:
    @classmethod
    def is_enabled(cls):
        # Is the feature enabled right now?
        return bool(settings.get('ccc', False))

    @classmethod
    def words_check(cls, words):
        # Test if words provided are right
        enc = seed_words_to_encoded_secret(words)
        exp = cls.get_encoded_secret()
        return (enc == exp)

    @classmethod
    def get_num_words(cls):
        # return 12 or 24 
        marker = cls.get_encoded_secret()[0]
        return len_to_numwords(len_from_marker(marker))

    @classmethod
    def get_encoded_secret(cls):
        # get the key C as encoded binary secret, compatible w/
        # encodings used in stash
        # TODO: move to "storage locker"?
        return a2b_hex(settings.get('ccc')['secret'])

    @classmethod
    def get_xfp(cls):
        # just the XFP
        return settings.get('ccc')['c_xfp']

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

        v = dict(secret=b2a_hex(enc), c_xfp=xfp, c_xpub=xpub, pol=CCCFeature.default_policy())
        settings.put('ccc', v)
        settings.save()

    @classmethod
    def default_policy(cls):
        # a very basic an permissive policy, but non-zero too.
        # - 1BTC per day
        return dict(mag=1, vel=144, web2fa='', addr=[])

    @classmethod
    def get_policy(cls):
        # de-serialize just the spending policy
        return dict(settings.get('ccc', dict(pol={})).get('pol'))

    @classmethod
    def update_policy(cls, pol):
        # serialize the spending policy, save it
        v = dict(settings.get('ccc', {}))
        v['pol'] = dict(pol)
        settings.set('ccc', v)
        return dict(pol)

    @classmethod
    def update_policy_key(cls, **kws):
        # update a few elements of the spending policy
        # - all settings "saved" as they are changed.
        # - return updated policy
        p = cls.get_policy()
        p.update(kws)
        return cls.update_policy(p)

    @classmethod
    def remove_ccc(cls):
        # delete our settings complete; lose key C .. already confirmed
        # - leave MS in place
        settings.remove_key('ccc')
        settings.save()

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
            #         xxxxxxxxxxxxxxxx
            MenuItem('CCC [%s]' % xfp2str(my_xfp), f=self.show_ident),
            MenuItem('Spending Policy', menu=CCCPolicyMenu.be_a_submenu),
            MenuItem('Export CCC XPUBs', f=self.export_xpub_c),
            MenuItem('Temporary Mode', f=self.enter_temp_mode),
            MenuItem('Multisig Wallets'),
        ]

        # look for wallets that are defined related to CCC feature, shortcut to them
        for ms in MultisigWallet.get_all():
            if my_xfp in ms.xfp_paths:
                items.append(MenuItem('↳ %d/%d: %s' % (ms.M, ms.N, ms.name),
                            menu=make_ms_wallet_menu, arg=ms.storage_idx))

        items.append(MenuItem('↳ Build 2-of-N', f=self.build_2ofN))
        items.append(MenuItem('Remove CCC', f=self.remove_ccc))

        return items

    async def remove_ccc(self, *a):
        if not await ux_confirm('''Key C will be lost, and policy settings forgotten. \
This unit will only be able to partly sign transactions. To completely remove this \
wallet, proceed to the miltisig menu and remove related wallet entry.'''):
            return

        if not await ux_confirm("Last chance. Funds in this wallet may be impacted."):
            return

        CCCFeature.remove_ccc()
        the_ux.pop()

    async def on_cancel(self):
        # trying to exit from CCCConfigMenu
        from seed import in_seed_vault

        enc = CCCFeature.get_encoded_secret()
        if in_seed_vault(enc):
            # remind them to clear the seed-vault copy of Key C because it defeats feature
            await ux_show_story('''Key C is in your seed vault. If you are done with setup, \
you MUST delete it from the Seed Vault.''', title='REMINDER')

        the_ux.pop()

    async def export_xpub_c(self, *a):
        # do standard Coldcard export for multisig setups
        xfp = CCCFeature.get_xfp()
        enc = CCCFeature.get_encoded_secret()

        from multisig import export_multisig_xpubs
        await export_multisig_xpubs(*a, xfp=xfp, alt_secret=enc, skip_prompt=True)

    async def build_2ofN(self, *a):
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
        await create_ms_step1(for_ccc=CCCFeature.get_encoded_secret())

        # prompt for file, prompt for our acct number, unless already exported to this card?

    async def show_ident(self, *a):
        # give some background? or just KISS for now?
        xfp = xfp2str(CCCFeature.get_xfp())
        await ux_show_story("XFP (Extended Finger Print) of key C is:\n\n  %s" % xfp)

    async def enter_temp_mode(self, *a):
        # apply key C as temp seed, so you can do anything with it
        # - just a shortcut, since they have the words, and could enter them
        # - one-way trip because the CCC feature won't be enabled inside the temp seed settings
        if await ux_show_story(
                'Loads the CCC controled seed (key C) as a Temporary Seed and allows '
                'easy use of all Coldcard features on that key.\n\nSave into Seed Vault '
                'to permit easy access to CCC Config menu.') != 'y':
            return

        from seed import set_ephemeral_seed
        from actions import goto_top_menu

        enc = CCCFeature.get_encoded_secret()
        await set_ephemeral_seed(enc, meta='Key C from CCC')

        goto_top_menu()

class PolCheckedMenuItem(MenuItem):
    # Show a checkmark if **policy** setting is defined and not the default
    # TODO on Q, should show value right-justified in menu display!
    # - only works inside CCCPolicyMenu
    def __init__(self, label, polkey, **kws):
        super().__init__(label, **kws)
        self.polkey = polkey

    def is_chosen(self):
        # should we show a check in parent menu? check the policy
        m = the_ux.top_of_stack()
        assert isinstance(m, CCCPolicyMenu)
        return bool(m.policy.get(self.polkey, False))


class CCCAddrWhitelist(MenuSystem):
    # simulator arg:    --seq tcENTERENTERsENTERwENTER
    def __init__(self):
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def be_a_submenu(cls, *a):
        return cls()

    def construct(self):
        # list of addresses
        addrs = CCCFeature.get_policy().get('addr', [])

        items = [MenuItem(truncate_address(a), f=self.edit_addr, arg=a) for a in addrs]

        if not items:
            items.append(MenuItem("(none yet)"))

        if version.has_qr:
            items.append(MenuItem('Scan QR', f=self.scan_qr, shortcut=KEY_QR))

        items.append(MenuItem('Import from File', f=self.import_file))

        return items

    async def edit_addr(self, menu, idx, item):
        # show detail and offer delete
        addr = item.arg
        msg = 'Spends to this address will be permitted:\n\n%s\n\nPress (4) to delete.' % addr
        ch = await ux_show_story(msg, escape='4')
        if ch == '4':
            self.delete_addr(addr)

    def delete_addr(self, addr):
        # no confirm, stakes are low
        addrs = CCCFeature.get_policy().get('addr', [])
        addrs.remove(addr)
        CCCFeature.update_policy_key(addrs=addrs)
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
                                min_size=20, max_size=5000,
                                none_msg="Must contain payment addresses", **choice)

        if not fn: return

        results = []
        with CardSlot(readonly=True, **choice) as card:
            with open(fn, 'rt') as fd:
                for ln in fd.readlines():
                    for here in pat.split(ln):
                        print(here)
                        if len(here) >= 4:
                            try:
                                addr = cleanup_payment_address(here)
                                results.append(addr)
                            except: pass

        if not results:
            await ux_show_story("Unable to find any payment addresses in that file.")
        else:
            await self.add_addresses(results)


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
            got.extend(here)
            ln = 'Got %d so far. ENTER to apply.' % len(got)
            
        if got:
            # import them
            await self.add_addresses(got)
        
    async def add_addresses(self, more_addrs):
        # add new entries, if unique; preserve ordering
        addrs = CCCFeature.get_policy().get('addr', [])
        new = []
        for a in more_addrs:
            if a not in addrs:
                addrs.append(a)
                new.append(a)

        if not new:
            await ux_show_story("Already in whitelist:\n\n" + '\n\n'.join(more_addrs))
            return

        CCCFeature.update_policy_key(addrs=addrs)
        self.update_contents()

        if len(new) > 1:
            await ux_show_story("Added %d new addresses to whitelist:\n\n%s" %
                (len(new), '\n\n'.join(new)))
        else:
            await ux_show_story("Added new address to whitelist:\n\n%s" % new[0])
            

class CCCPolicyMenu(MenuSystem):
    # Build menu stack that allows edit of all features of the spending
    # policy. Key C is set already at this point.
    # - and delete/cancel CCC (clears setting?)
    # - be a sticky menu that's hard to exit (ie. SAVE choice and no cancel out)

    def __init__(self):
        self.policy = CCCFeature.get_policy()
        items = self.construct()
        super().__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def be_a_submenu(cls, *a):
        return cls()

    def construct(self):
        items = [
            #                xxxxxxxxxxxxxxxx
            PolCheckedMenuItem('Max Magnitude', 'mag', f=self.set_magnitude),
            PolCheckedMenuItem('Limit Velocity', 'vel', chooser=self.velocity_chooser),
            PolCheckedMenuItem('Whitelist' + (' Addresses' if version.has_qr else ''),
                                    'addr', menu=CCCAddrWhitelist.be_a_submenu),
            PolCheckedMenuItem('Web 2FA', 'web2fa', f=self.toggle_2fa),
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
        ok = await web2fa.perform_web2fa('CCC Test', ss)

        await ux_show_story('Correct code was given.' if ok else 'Failed or aborted.')

    async def enroll_more_2fa(self, *a):
        # let more phones in on the party
        ss = self.policy.get('web2fa')
        assert ss
        await web2fa.web2fa_enroll('CCC', ss)

    async def set_magnitude(self, *a):
        was = self.policy.get('mag', 0)
        val = await ux_enter_number('Per Txn Max Out', max_value=int(1e8),
                                            can_cancel=True, value=(was or ''))

        if (val is None) or (val == was):
            msg = "Did not change"
            val = was
        else:
            msg = "You can have set the"
            unchanged = False

        if not val:
            msg = "No check for maximum transaction size will be done. "
        else:
            msg += " maximum per-transaction: \n\n  %s" % render_mag_value(val)

        self.policy = CCCFeature.update_policy_key(mag=val)

        await ux_show_story(msg, title="Txn Magnitude")
        
    def velocity_chooser(self):
        # offer some useful values from a menu
        vel = self.policy.get('vel', 0)        # in blocks

        # reminder: dont forget the poor Mk4 users
        #        xxxxxxxxxxxxxxxx
        ch = [  'Unlimited',
                '6 blocks (1 hr)',
                '24 blocks (4h)',
                '48 blocks (8h)',
                '72 blocks (12h)',
                '144 blocks (day)',
                '288 blocks (2d)',
                '432 blocks (3d)',
                '1008 blocks (wk)',
              ]
        va = [0] + [int(x.split()[0]) for x in ch[1:]]

        try:
            which = va.index(vel)
        except ValueError:
            which = 0

        def set(idx, text):
            self.policy = CCCFeature.update_policy_key(vel=va[idx])

        return which, ch, set

    async def toggle_2fa(self, *a):
        if self.policy.get('web2fa'):
            # enabled already

            if not await ux_confirm("Disable web 2FA check? Effect is immediate."):
                return

            self.policy = CCCFeature.update_policy_key(web2fa='')
            self.update_contents()

            await ux_show_story("Web 2FA has been disabled. If you re-enable it, a new "
                    "secret will be generated, so it is safe to remove it from your "
                    "phone at this point.")

            return

        ch = await ux_show_story('''When enabled, any spend (signing) requires 
use of mobile 2FA application (TOTP RFC-6238). Shared-secret is picked now, 
and loaded on your phone via QR code.

WARNING: You will not be able to sign transactions if you do not have an NFC-enabled 
phone with Internet access and 2FA app holding correct shared-secret.''',
                    title="Web 2FA")
        if ch != 'y':
            return

        # challenge them, and don't set unless it works
        ss = await web2fa.web2fa_enroll('CCC')
        if not ss:
            return

        # update state
        self.policy = CCCFeature.update_policy_key(web2fa=ss)
        self.update_contents()

async def gen_or_import():
    # returns 12 words, or None to abort
    from seed import WordNestMenu, generate_seed, approve_word_list

    ch = await ux_show_story(
        "Press %s to generate a new 12-word seed phrase to be used "
        "as the Coldcard Cosigning Secret (key C).\n\nOr press (1) to import existing "
        "12-words or (2) for 24-words import." % OK,
        escape='12', title="CCC Key C")

    if ch == '1' or ch == '2':
        nwords = 24 if ch == '2' else 12

        async def done_key_C_import(words):
            await enable_step1(words)

        if version.has_qwerty:
            from ux_q1 import seed_word_entry
            await seed_word_entry('Key C Seed Words', nwords, done_cb=done_key_C_import)
        else:
            words = WordNestMenu(nwords, done_cb=done_key_C_import)

        return None     # will call parent again

    elif ch == 'y':
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
    ch = await ux_show_story('''\
This feature creates a new 2-of-3 multisig wallet. A, B, and C keys are as follows:\n
A=This Coldcard, B=Backup Key, C=Policy Key ... blah balh
''',
        title="Coldcard Co-Signing")

    if ch != 'y': 
        # just a tourist
        return

    await enable_step1(None)

async def enable_step1(words):
    if not words:
        words = await gen_or_import()
        if not words: return

    # do BIP-32 basics: capture XFP and XPUB and encoded version of the secret
    CCCFeature.init_setup(words)

    # push them directly into policy submenu first time.
    m = CCCConfigMenu()
    the_ux.push(m)

    # that will lead back to a "nested" menu other setup

async def modify_ccc_settings():
    # Generally not expecting changes to policy on the fly because
    # that's the whole point. Use the B key to override individual spends
    # but if you can prove you have C key, then it's harmless to allow changes
    # since you could just spend as needed.

    enc = CCCFeature.get_encoded_secret()
    bypass = False

    from seed import in_seed_vault
    if in_seed_vault(enc):
        # if seed vault enabled and they have the secret there, just go
        # allow easy access to menu (impt for debug/setup/testing time).
        await ux_show_story('''You have a copy of the CCC key C in the Seed Vault, so \
you may proceed to change settings now.\n\nYou must delete that key from the vault once \
setup and debug is finished, or all benefit of this feature is lost!''')

        bypass = True

    else:
        ch = await ux_show_story(
            "Spending policy cannot be viewed, changed nor disabled, "
            "unless you have the seed words for key C.",
            title="CCC Enabled", escape='6')

        if ch == '6' and version.is_devmode:
            # debug hack: skip word entry
            bypass = True

    if bypass:
        # - doing full decode cycle here for better testing
        chk, raw, _ = SecretStash.decode(enc)
        assert chk == 'words'
        words = bip39.b2a_words(raw).split(' ')
        await key_c_challenge(words)
        return
        
    if ch != 'y': return

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
    from glob import dis

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
    

# EOF
