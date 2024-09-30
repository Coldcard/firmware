# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ccc.py - ColdCard Cosign feature. Be a leg in a 2-of-3 that signed based on policy.
#
import gc, chains, version, ngu, web2fa
from ubinascii import b2a_base64, a2b_base64
from utils import b2a_base64url, swab32
from glob import settings
from ux import ux_confirm, ux_show_story, the_ux, OK, ux_dramatic_pause, ux_enter_number
from menu import MenuSystem, MenuItem

class CCCFeature:
    @classmethod
    def words_check(cls, words):
        # test if words provided are right
        w = settings.get('ccc', {})['words']
        return (words == w)

    @classmethod
    def default_policy(cls):
        return dict(mag=1, vel=0, web2fa='', addr=[])

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

    @classmethod
    def update_policy_key(cls, **kws):
        # update a single element of the spending policy
        # - used for web2fa
        p = cls.get_policy()
        p.update(kws)
        cls.update_policy(p)

    @classmethod
    def remove_ccc(cls):
        # already confirmed
        settings.remove_key('ccc')
        settings.save()

def render_mag_value(mag):
    # handle integer bitcoins, and satoshis in same value
    if mag < 1000:
        return '%d BTC' % mag
    else:
        return '%d SATS' % mag

class CheckedMenuItem(MenuItem):
    # Show a checkmark if policy setting is defined and not the default
    # TODO on Q, should show value right-justified in menu display
    def __init__(self, label, polkey, **kws):
        super().__init__(label, **kws)
        self.polkey = polkey

    def is_chosen(self):
        # should we show a check in parent menu? check the policy
        m = the_ux.top_of_stack()
        assert isinstance(m, CCCPolicyMenu)
        return bool(m.policy.get(self.polkey, False))

class CCCPolicyMenu(MenuSystem):
    # Build menu stack that allows edit of all features of the spending
    # policy. Key C is set already at this point.
    # - and delete/cancel CCC (clears setting?)
    # - be a sticky menu that's hard to exit (ie. SAVE choice and no cancel out)

    def __init__(self, first_time=True):
        self.first_time = first_time
        self.policy = CCCFeature.get_policy() if not first_time else CCCFeature.default_policy()
        items = self.construct()
        super(CCCPolicyMenu, self).__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    def construct(self):
        items = [
            #                xxxxxxxxxxxxxxxx
            CheckedMenuItem('Max Magnitude', 'mag', f=self.set_magnitude),
            CheckedMenuItem('Limit Velocity', 'vel', chooser=self.velocity_chooser),
            CheckedMenuItem('Whitelisted' + (' Addresses' if version.has_qr else ''),
                                    'addr', f=self.edit_whitelist),
            CheckedMenuItem('Web 2FA', 'web2fa', f=self.toggle_2fa),
        ]

        if self.policy.get('web2fa'):
            items.extend([
                MenuItem('↳ Test 2FA', f=self.test_2fa),
                MenuItem('↳ Enroll More', f=self.enroll_more_2fa),
            ])

        if not self.first_time:
            # NOTE: if they are setting it up, do **not** offer to cancel or abort
            # because if they are this far, already saved 12 words and done a bunch
            # of work.
            items.append(MenuItem('CANCEL Changes', f=self.cancel_changes))

        items.append(MenuItem('SAVE & APPLY', f=self.done_apply))

        return items

    async def remove_policy(self, *a):
        if not await ux_confirm("Key C will be lost, and policy settings forgotten. This unit will only be able to partly sign transactions (1 of 3). To completely remove this wallet, proceed to the miltisig wallet and remove entry there as well."):
            return

        CCCFeature.remove_ccc()
        the_ux.pop()

    async def cancel_changes(self, *a):
        if not await ux_confirm("Your changes on to the policy, if any, will be forgotten."):
            return
        the_ux.pop()

    async def done_apply(self, *a):
        if not await ux_confirm("Policy will be saved and cannot be changed again without "
                    "the secret (key C) words."):
            return

        # commit change
        CCCFeature.update_policy(self.policy)

        the_ux.pop()

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
        
    async def edit_whitelist(self, *a):
        pass

    async def set_magnitude(self, *a):
        was = self.policy.get('mag', 0)
        val = await ux_enter_number('Per Txn Max Out', int(1e8), can_cancel=True)
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

        self.policy['mag'] = val

        await ux_show_story(msg, title="Txn Magnitude")
        
    def velocity_chooser(self):
        # offer some useful values from a menu
        vel = self.policy.get('vel', 0)        # in blocks

        # TODO better/more values
        ch = [  'Disabled/Unlimited',
                ' 1 hour (6 blocks)',
                '10 hours (60)',
                ' 1 week (1024)',
                ' 2 weeks (2048)',
              ]
        va = [ 0, 6, 60, 1024, 2048 ]

        try:
            which = va.index(vel)
        except ValueError:
            which = 0

        def set(idx, text):
            self.policy['vel'] = va[idx]

        return which, ch, set

    async def toggle_2fa(self, *a):
        if self.policy.get('web2fa'):
            # enabled already

            if not await ux_confirm("Disable web 2FA check? Effect is immediate."):
                return


            # Save just that one setting right now, but don't commit other changes they
            # might have made in this menu already. Reason: we don't want the old shared
            # secret to go back into effect if they fail to commit on this menu.
            CCCFeature.update_policy_key(web2fa='')

            self.policy['web2fa'] = ''
            self.update_contents()

            await ux_show_story("Web 2FA has been disabled. If you re-enable it, a new secret will be generated, so it is safe to remove it from your phone at this point.")

            return

        ch = await ux_show_story('''When enabled, any spend (signing) requires 
the use of mobile 2FA application (TOTP RFC-6238). Shared-secret is picked now, 
and loaded on your phone.

WARNING: You will not be able to sign transactions, if you do not have an NFC-enabled 
phone with Internet access and 2FA app holding correct shared-secret.''',
                    title="Web 2FA")
        if ch != 'y':
            return

        # challenge them, and don't set until confirmed end-to-end success
        ss = await web2fa.web2fa_enroll('CCC')
        if not ss:
            return

        # update w/o confirm step because very annoying to need to re-do? or maybe not IDK
        CCCFeature.update_policy_key(web2fa=ss)
        self.policy['web2fa'] = ss
        self.update_contents()

async def gen_or_import12():
    # returns 12 words, or None to abort
    from seed import WordNestMenu, generate_seed, approve_word_list

    ch = await ux_show_story(
        "Press %s to generate a new 12 word master secret seed phrase to be used "
        "as the Coldcard Secret (key C). Press (1) to import existing 12 words." % OK,
        escape='1', title="CCC Key C")

    if ch == '1':
        async def done_key_C_import(words):
            await enable_step1(words)

        if version.has_qwerty:
            from ux_q1 import seed_word_entry
            await seed_word_entry('Key C Seed Words', 12, done_cb=done_key_C_import)
        else:
            words = WordNestMenu(12, done_cb=done_key_C_import)

        return None     # will call parent again

    elif ch == 'y':
        await ux_dramatic_pause('Generating...', 3)
        seed = generate_seed()
        words = await approve_word_list(seed, 12)
    else:
        return None

    return words


async def ephemeral_seed_import(nwords):
    async def import_done_cb(words):
        dis.fullscreen("Applying...")
        await set_ephemeral_seed_words(words, meta='Imported')


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

    print('ch=' + repr(ch))
    if ch != 'y': 
        # just a tourist
        return

    await enable_step1(None)

async def enable_step1(words):
    if not words:
        words = await gen_or_import12()
        if not words: return

    assert len(words) == 12

    # do BIP-32 basics
    from stash import SecretStash
    from seed import seed_words_to_encoded_secret
    enc = seed_words_to_encoded_secret(words)
    _,_,node = SecretStash.decode(enc)

    chain = chains.current_chain()
    xfp = swab32(node.my_fp())
    xpub = chain.serialize_public(node)

    # TODO: b_xfp and b_xpub needed?

    v = dict(words=words, c_xfp=xfp, c_xpub=xpub, pol=CCCFeature.default_policy())
    settings.put('ccc', v)
    settings.save()

    m = CCCPolicyMenu(first_time=True)
    the_ux.push(m)

async def modify_ccc_settings():
    # generally not expecting changes to policy on the fly because
    # that's the whole point. Use the B key to override individual spends
    # but if you can prove you have C key, then harmless to allow changes
    # since you could just spend as needed.

    # TODO: if seed vault enabled and any 12-word secrets,
    #       add "Press (1) to choose from Vault", etc
    ch = await ux_show_story(
            "Spending policy cannot be viewed, changed nor disabled while on the road. "
            "But if you have the seed words (for key C) you may proceed.",
            title="CCC Enabled", escape='6' if version.is_devmode else None)

    if ch == '6':
        # debug hack: skip word entry
        assert version.is_devmode
        w = settings.get('ccc')['words']
        await key_c_challenge(w)
        return
        
    if ch != 'y': return

    import seed
    if version.has_qwerty:
        from ux_q1 import seed_word_entry
        await seed_word_entry('Enter Seed Words', 12,
                                            done_cb=key_c_challenge)
    else:
        return seed.WordNestMenu(12, done_cb=key_c_challenge)

async def key_c_challenge(words):
    # They entered some words, if they match our key C then allow edit of policy
    assert len(words) == 12
    from glob import dis

    dis.fullscreen('Verifying...')
    
    if not CCCFeature.words_check(words):
        await ux_show_story("Sorry, those words are incorrect.")
        # TODO: keep an in-memory counter, and after 3 fails, reboot
        return

    # pop stack
    the_ux.pop()
    m = CCCPolicyMenu(first_time=False)
    the_ux.push(m)


    

# EOF
