# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# xor_seedsave.py - Save xor seedwords into encrypted file on MicroSD (if desired)
#
import sys, stash, ujson, os, ngu
from actions import file_picker
from files import CardSlot, CardMissingError
from ux import ux_show_story

class XORSeedSaver:
    # Encrypts a 12-word seed very carefully, and appends
    # to a file on MicroSD card.
    # AES-256 CTR with key=SHA256(SHA256(salt + derived key off master + salt))
    # where: salt=sha256(microSD serial # details)

    def _calc_key(self, card):
        # calculate the key to be used.
        if getattr(self, 'key', None): return

        try:
            salt = card.get_id_hash()

            with stash.SensitiveValues(bypass_pw=True) as sv:
                self.key = bytearray(sv.encryption_key(salt))

        except:
            self.key = None

    def _read(self, filename):
        # Return 24 words from encrypted file, or empty list if fail.
        # Fail silently in all cases.
        decrypt = ngu.aes.CTR(self.key)

        try:
            msg = open(filename, 'rb').read()
            txt = decrypt.cipher(msg)
            val = ujson.loads(txt)

            # If contents are not what we expect, return nothing
            if not type(val) is list:
                return []
            if not len(val) == 24:
                return []
            
            return val
        except:
            return []

    def _write(self, filename, words):
        # Encrypt and save words to file.
        # Allow exceptions to throw as validation should 
        # have been performed before calling.
        encrypt = ngu.aes.CTR(self.key)
        json = ujson.dumps(words)
        contents = encrypt.cipher(json)
        open(filename, 'wb').write(contents)

    async def read_from_card(self): 
        import pyb
        if not pyb.SDCard().present():
            await ux_show_story("Insert an SDCard and try again.")
            return None

        choices = await file_picker(None, suffix='xor')
        filename = await file_picker('Choose your XOR file.', choices=choices)

        if not filename:
            return None
        
        # Read file, decrypt and make a menu to show; OR return None
        # if any error hit.
        try:
            with CardSlot() as card:
                self._calc_key(card)
                if not self.key:
                    await ux_show_story("Failed to read file!\n\nNo action has been taken.")
                    return None

                data = self._read(filename)
                if not data:
                    await ux_show_story("Failed to read file!\n\nNo action has been taken.")
                    return None
    
                return data
        except CardMissingError:
            # not an error: they just aren't using feature
            await ux_show_story("Failed to read file!\n\nNo action has been taken.")
            return None

    async def save_to_card(self, words):
        msg = ('Confirm these %d secret words:\n') % len(words)
        msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))
        ch = await ux_show_story(msg, sensitive=True)
        if ch == 'x': return

        import pyb
        while not pyb.SDCard().present():
            ch = await ux_show_story('Please insert an SDCard!')
            if ch == 'x': return

        from glob import dis
        # Show progress:
        dis.fullscreen('Encrypting...')

        with CardSlot() as card:
            filename, nice = card.pick_filename('seedwords.xor')
            self._calc_key(card)
            self._write(filename, words)
            await ux_show_story('XOR file written:\n\n%s' % nice)

        return None

# EOF
