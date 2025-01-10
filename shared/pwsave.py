# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# pwsave.py - Save bip39 passphrases into encrypted file on MicroSD (if desired)
#
import stash, ujson, ngu, pyb, os, version, aes256ctr
from files import CardSlot, CardMissingError, needs_microsd
from ux import ux_dramatic_pause, ux_confirm, ux_show_story, OK, X
from utils import xfp2str, problem_file_line, B2A
from menu import MenuItem, MenuSystem
from glob import settings


class PassphraseSaver:
    # Encrypts BIP-39 passphrase very carefully, and appends
    # to a file on MicroSD card. Order is preserved.
    # AES-256 CTR with key=SHA256(SHA256(salt + derived key off master + salt))
    # where: salt=sha256(microSD serial # details)
    def __init__(self):
        self.key = None

    @staticmethod
    def filename(card):
        # Construct actual filename to use.
        # - some very minor obscurity, but we aren't relying on that.
        return card.get_sd_root() + '/.tmp.tmp'

    @classmethod
    def has_file(cls):
        # Is a card inserted with the required file(name) in place?
        if CardSlot.is_inserted():
            try:
                with CardSlot() as card:
                    # check if passphrases file exists on SD (dont read it)
                    if card.exists(cls.filename(card)):
                        return True
            except: pass
        return False

    def _calc_key(self, card, force=False):
        # calculate the key to be used.
        if not force and self.key:
            return

        salt = card.get_id_hash()

        with stash.SensitiveValues(bypass_tmp=True) as sv:
            self.key = bytearray(sv.encryption_key(salt))

    def _read(self, card):
        # Return a list of saved passphrases, or empty list if fail.
        # Fail silently in all cases. Expect to see lots of noise here.
        assert self.key
        decrypt = aes256ctr.new(self.key)

        try:
            fname = self.filename(card)
            with open(fname, 'rb') as f:
                msg = f.read()
            txt = decrypt.cipher(msg)

            return ujson.loads(txt)
        except:
            return []

    async def _save(self, card, data):
        assert self.key
        encrypt = aes256ctr.new(self.key)
        msg = encrypt.cipher(ujson.dumps(data))

        # overwrites whatever already there
        with open(self.filename(card), 'wb') as fd:
            fd.write(msg)

    async def delete(self, idx):
        with CardSlot() as card:
            self._calc_key(card)
            data = self._read(card)

            try:
                del data[idx]
            except IndexError: pass

            await self._save(card, data)
            if not data:
                return True  # is empty

    async def append(self, xfp, bip39pw):
        from glob import dis
        dis.fullscreen('Reading...')
        with CardSlot() as card:
            self._calc_key(card)
            data = self._read(card)

            to_add = dict(xfp=xfp, pw=bip39pw)
            if to_add not in data:
                dis.fullscreen('Saving...')
                data.append(to_add)
                await self._save(card, data)


class PassphraseSaverMenu(MenuSystem):

    def update_contents(self):
        tmp = PassphraseSaverMenu.construct()
        self.replace_items(tmp)

    @staticmethod
    async def apply(menu, idx, item):
        # apply the password immediately and drop them at top menu
        from actions import goto_top_menu
        from ux import ux_show_story
        from seed import set_bip39_passphrase
        from pincodes import pa

        bypass_tmp = True
        pw, expect_xfp = item.arg
        if pa.tmp_value and settings.get("words", True):
            xfp = settings.get("xfp", 0)
            title = "[%s]" % xfp2str(xfp)
            msg = (
                "Temporary seed is active. Press (1)"
                " to add passphrase to the current active"
                " temporary seed."
            )
            escape = "1x"
            if settings.master_get("words", True):
                escape += "y"
                msg += (" Press %s to add to master seed." % OK)

            msg += ("Press %s to exit." % X)

            ch = await ux_show_story(msg, title=title, escape=escape,
                                     strict_escape=True)
            if ch == "x": return
            if ch == '1':
                bypass_tmp = False

        applied = await set_bip39_passphrase(pw, bypass_tmp=bypass_tmp,
                                             summarize_ux=False)
        if not applied:
            return

        xfp = settings.get('xfp', 0)

        # verification step
        if xfp == expect_xfp:
            # feedback that it worked
            await ux_show_story("Passphrase restored.", title="[%s]" % xfp2str(xfp))
        else:
            got = xfp2str(xfp)
            exp = xfp2str(expect_xfp)
            await ux_show_story("XFP verification failed. Restored wallet XFP [%s] "
                                "does not match expected XFP [%s] from "
                                "saved passphrase file." % (got, exp))
            return

        goto_top_menu()

    @staticmethod
    async def delete_entry(menu, idx, item):
        from ux import the_ux
        from glob import dis

        pw_saver, i = item.arg
        if await ux_confirm("Delete saved passphrase?"):
            dis.fullscreen("Wait...")
            try:
                is_empty = await pw_saver.delete(i)
                the_ux.pop()
                if not is_empty:
                    m = the_ux.top_of_stack()
                    m.update_contents()
                else:
                    # remove .tmp.tmp file after last passphrase
                    # is deleted
                    with CardSlot() as card:
                        f_path = pw_saver.filename(card)
                        os.remove(f_path)
                    the_ux.pop()
                    m = the_ux.top_of_stack()
                    m.update_contents()
            except CardMissingError:
                await needs_microsd()
            except Exception as e:
                await ux_show_story(
                    title="ERROR",
                    msg='Delete failed!\n\n%s\n%s' % (e, problem_file_line(e))
                )

    @classmethod
    def construct(cls):
        # We have a list of xfp+pw fields. Make a menu.
        # Read file, decrypt and make a menu to show; OR return None
        # if any error hit.
        pw_saver = PassphraseSaver()
        with CardSlot() as card:
            pw_saver._calc_key(card)
            data = pw_saver._read(card)

            if not data: return None

        # Challenge: we need to hint at which is which, but don't want to
        # show the password on-screen.
        # - simple algo:
        #   - show either first N or last N chars only
        #   - pick which set which is all-unique, if neither, try N+1
        #
        pws = []
        for i in data:
            p, x = i.get('pw'), i.get('xfp')
            if (p,x) not in pws:
                pws.append( (p, x) )

        for N in range(1, 8):
            parts = [i[0:N] + ('*'*(len(i)-N if len(i) > N else 0)) for i,_ in pws]
            if len(set(parts)) == len(pws): break
            parts = [('*'*(len(i)-N if len(i) > N else 0)) + i[-N:] for i,_ in pws]
            if len(set(parts)) == len(pws): break
        else:
            # give up: show it all!
            parts = [i for i,_ in pws]

        items = []
        for i, (pw, label) in enumerate(zip(pws, parts)):
            xfp_ui = "[%s]" % xfp2str(pw[1])
            submenu = MenuSystem([
                MenuItem(xfp_ui),
                MenuItem("Restore", f=cls.apply, arg=pw),
                MenuItem("Delete", f=cls.delete_entry, arg=(pw_saver, i)),
            ])
            submenu.goto_idx(1)     # skip cursor to "Restore"
            items.append(MenuItem(label or "(empty)", menu=submenu))
        return items

#
# Support for using MicroSD as second factor to the login PIN.
#

class MicroSD2FA(PassphraseSaver):
    def filename(self, card):
        # Construct actual filename to use.
        # - want to support same card authorizing multiple CC, so cant be fixed filename
        # - dont want to search tho, so should be deterministic
        # - serial number of CC is nearly public but hmac anyway
        # - if this file was written from a trick pin situation, it would have
        #   correct filename but contents would not decrypt since AES key is based off seed

        k = ngu.hash.sha256s(version.serial_number())
        h = ngu.hmac.hmac_sha256(k, b'silly?')

        return card.get_sd_root() + '/.%s.2fa' % B2A(h[0:8])

    @classmethod
    def get_nonces(cls):
        # this is the only setting: list of nonce values we have saved to various cards
        return settings.get('sd2fa') or []

    def read_card(self):
        # Read the data, if any, and if decrypted correctly

        # Read file, decrypt and make a menu to show; OR return None
        # if any error hit.
        try:
            with CardSlot() as card:
                self._calc_key(card, force=True)
                if not self.key: return None

                data = self._read(card)
                if not data: return None
        except CardMissingError:
            # late fail
            return None

        return data

    @classmethod
    def enforce_policy(cls):
        # If feature enabled, and if so check authorized card is inserted right now.
        nonces = cls.get_nonces()
        if not nonces:
            # feature not in use, no problem
            return

        try:
            ok = cls.authorized_card_present(nonces)
            assert ok == True
        except:
            # die. wrong
            import callgate
            settings.remove_key("sd2fa")
            settings.save()
            callgate.fast_wipe(silent=False)

        # proceed w/o any notice
        return

    @classmethod
    def authorized_card_present(cls, nonces):
        # Check if good card present
        
        if not CardSlot.is_inserted():
            # no card present, so nope
            return False

        s = cls()
        got = s.read_card()
        if not got:
            # garbage seen, missing file, etc => fail
            return False

        # check it is in the list of authorized cards
        return (got['nonce'] in nonces)
    
    async def enroll(self):
        # Write little file, update our settings to allow this card to auth.
        from glob import dis, settings

        nonce = B2A(ngu.random.bytes(8))

        v = list(self.get_nonces())

        # encrypt and save; always appends.

        dis.fullscreen('Saving...')

        try:
            with CardSlot() as card:
                self._calc_key(card, force=True)

                data = dict(nonce=nonce)

                encrypt = aes256ctr.new(self.key)
                msg = encrypt.cipher(ujson.dumps(data))

                with open(self.filename(card), 'wb') as fd:
                    fd.write(msg)

            # update setting as well
            # TODO use general method that handles memory overflow
            v.append(nonce)
            settings.set('sd2fa', v)
            settings.save()

            await ux_dramatic_pause("Saved.", 1)

            return

        except CardMissingError:
            return await needs_microsd()

    async def remove(self, nonce):
        # remove indicated nonce from records
        # - doesn't delete file, since might not have card anymore and useless w/o nonce
        v = self.get_nonces()
        assert nonce in v, 'missing card nonce'
        v2 = [i for i in v if i != nonce]
        if not v2:
            settings.remove_key('sd2fa')
        else:
            settings.set('sd2fa', v2)
        settings.save()

    @classmethod
    def menu(cls):
        # menu contents needed for current state
        from menu import MenuItem

        existing = cls.get_nonces()
        menu = []

        menu.append(MenuItem("Add Card", f=cls.menu_enroll, arg=len(existing)))

        if existing:
            menu.append(MenuItem("Check Card", f=cls.menu_check_card))

        for n, card_nonce in enumerate(existing):
            menu.append(MenuItem("Remove Card #%d" % (n+1), f=cls.menu_edit, arg=card_nonce))

        return menu

    @classmethod
    async def menu_check_card(cls, *a):
        
        ok = cls.authorized_card_present(cls.get_nonces())
        if not ok:
            await ux_show_story("This card would NOT be accepted during login.", title="FAIL")
        else:
            await ux_show_story("This card is enrolled and would be accepted during login.", title="PASS")

    @classmethod
    async def menu_enroll(cls, menu, label, item):
        count = item.arg

        if not CardSlot.is_inserted():
            return await needs_microsd()

        # careful: if they re-enrolled same card twice, confusion will result
        if count:
            ok = cls.authorized_card_present(cls.get_nonces())
            if ok:
                await ux_show_story("Need a different MicroSD card. "
                                    "This card would already be accepted.")
                return

        ctx = 'this card or one of the others' if count >= 1 else 'it'

        ok = await ux_confirm("Add this card to authorized set? Going forward %s must be "
                              "present during login process or the seed will be wiped!" % ctx)
        if not ok:
            return

        await cls().enroll()

        menu.replace_items(cls.menu())

    @classmethod
    async def menu_edit(cls, menu, label, item):
        # only allowing delete for now... could show details or something
        ok = await ux_confirm("Remove this card from authorized set?")
        if not ok:
            return
            
        # delete magic file if we can, but more importantly our nonce
        await cls().remove(item.arg)
        
        menu.replace_items(cls.menu())
        
# EOF
