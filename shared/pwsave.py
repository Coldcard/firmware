# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# pwsave.py - Save bip39 passphrases into encrypted file on MicroSD (if desired)
#
import sys, stash, ujson, os, ngu
from files import CardSlot, CardMissingError

class PassphraseSaver:
    # Encrypts BIP-39 passphrase very carefully, and appends
    # to a file on MicroSD card. Order is preserved.
    # AES-256 CTR with key=SHA256(SHA256(salt + derived key off master + salt))
    # where: salt=sha256(microSD serial # details)

    def filename(self, card):
        # Construct actual filename to use.
        # - some very minor obscurity, but we aren't relying on that.
        return card.get_sd_root() + '/.tmp.tmp'

    def _calc_key(self, card):
        # calculate the key to be used.
        if getattr(self, 'key', None): return

        try:
            salt = card.get_id_hash()

            with stash.SensitiveValues(bypass_pw=True) as sv:
                self.key = bytearray(sv.encryption_key(salt))

        except:
            self.key = None

    def _read(self, card):
        # Return a list of saved passphrases, or empty list if fail.
        # Fail silently in all cases. Expect to see lots of noise here.
        decrypt = ngu.aes.CTR(self.key)

        try:
            msg = open(self.filename(card), 'rb').read()
            txt = decrypt.cipher(msg)
            return ujson.loads(txt)
        except:
            return []


    async def append(self, xfp, bip39pw):
        # encrypt and save; always appends.
        from ux import ux_dramatic_pause
        from glob import dis
        from actions import needs_microsd

        while 1:
            dis.fullscreen('Saving...')

            try:
                with CardSlot() as card:
                    self._calc_key(card)

                    data = self._read(card) if self.key else []

                    data.append(dict(xfp=xfp, pw=bip39pw))

                    encrypt = ngu.aes.CTR(self.key)

                    msg = encrypt.cipher(ujson.dumps(data))

                    with open(self.filename(card), 'wb') as fd:
                        fd.write(msg)

                await ux_dramatic_pause("Saved.", 1)
                return

            except CardMissingError:
                ch = await needs_microsd()
                if ch == 'x':       # undocumented, but needs escape route
                    break

            
    def make_menu(self):
        from menu import MenuItem, MenuSystem
        from actions import goto_top_menu
        from ux import ux_show_story
        from seed import set_bip39_passphrase
        import pyb

        # Very quick check for card not present case.
        if not pyb.SDCard().present():
            return None

        # Read file, decrypt and make a menu to show; OR return None
        # if any error hit.
        try:
            with CardSlot() as card:

                self._calc_key(card)
                if not self.key: return None

                data = self._read(card)

                if not data: return None

        except CardMissingError:
            # not an error: they just aren't using feature
            return None

        # We have a list of xfp+pw fields. Make a menu.

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

        async def doit(menu, idx, item):
            # apply the password immediately and drop them at top menu
            pw, expect_xfp = item.arg
            set_bip39_passphrase(pw)

            from glob import settings
            from utils import xfp2str
            xfp = settings.get('xfp')

            # verification step; I don't see any way for this to go wrong
            assert xfp == expect_xfp

            # feedback that it worked
            await ux_show_story("Passphrase restored.", title="[%s]" % xfp2str(xfp))

            goto_top_menu()


        return MenuSystem((MenuItem(label or '(empty)', f=doit, arg=pw) for pw, label in zip(pws, parts)))
        
# EOF
