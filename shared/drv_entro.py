# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-85: Deterministic Entropy From BIP32 Keychains, by
#         Ethan Kosakovsky <ethankosakovsky@protonmail.com>
#
# Using the system's BIP-32 master key, safely derive seeds phrases/entropy for other
# wallet systems, which may expect seed phrases, XPRV, or other entropy.
#
import stash, seed, ngu, chains, bip39, version, glob
from ux import ux_show_story, ux_enter_bip32_index, the_ux, ux_confirm, ux_dramatic_pause
from menu import MenuItem, MenuSystem
from ubinascii import hexlify as b2a_hex
from ubinascii import b2a_base64
from auth import write_sig_file
from utils import chunk_writer


BIP85_PWD_LEN = 21

def drv_entro_start(*a):

    # UX entry
    ch = await ux_show_story('''\
Create Entropy for Other Wallets (BIP-85)

This feature derives "entropy" based mathematically on this wallet's seed value. \
This will be displayed as a 12 or 24 word seed phrase, \
or formatted in other ways to make it easy to import into \
other wallet systems.

You can recreate this value later, based \
only on the seed-phrase or backup of this Coldcard.

There is no way to reverse the process, should the other wallet system be compromised, \
so the other wallet is effectively segregated from the Coldcard and yet \
still backed-up.''')
    if ch != 'y': return

    if stash.bip39_passphrase:
        if not await ux_confirm('''You have a BIP-39 passphrase set right now and so that will become wrapped into the new secret.'''):
            return

    choices = [ '12 words', '18 words', '24 words', 'WIF (privkey)',
                'XPRV (BIP-32)', '32-bytes hex', '64-bytes hex', 'Passwords']

    m = MenuSystem([MenuItem(c, f=drv_entro_step2) for c in choices])
    the_ux.push(m)

def bip85_derive(picked, index):
    # implement the core step of BIP85 from our master secret

    if picked in (0,1,2):
        # BIP-39 seed phrases (we only support English)
        num_words = (12, 18, 24)[picked]
        width = (16, 24, 32)[picked]        # of bytes
        path = "m/83696968'/39'/0'/{num_words}'/{index}'".format(num_words=num_words, index=index)
        s_mode = 'words'
    elif picked == 3:
        # HDSeed for Bitcoin Core: but really a WIF of a private key, can be used anywhere
        s_mode = 'wif'
        path = "m/83696968'/2'/{index}'".format(index=index)
        width = 32
    elif picked == 4:
        # New XPRV
        path = "m/83696968'/32'/{index}'".format(index=index)
        s_mode = 'xprv'
        width = 64
    elif picked in (5, 6):
        width = 32 if picked == 5 else 64
        path = "m/83696968'/128169'/{width}'/{index}'".format(width=width, index=index)
        s_mode = 'hex'
    elif picked == 7:
        width = 64
        # hardcoded width for now
        # b"pwd".hex() --> 707764
        path = "m/83696968'/707764'/{pwd_len}'/{index}'".format(pwd_len=BIP85_PWD_LEN, index=index)
        s_mode = 'pw'
    else:
        raise ValueError(picked)

    with stash.SensitiveValues() as sv:
        node = sv.derive_path(path)
        entropy = ngu.hmac.hmac_sha512(b'bip-entropy-from-k', node.privkey())
    
        sv.register(entropy)

        # truncate for this application
        new_secret = entropy[0:width]
            
    return new_secret, width, s_mode, path


def bip85_pwd(secret):
    # Convert raw secret (64 bytes) into type-able password text.

    # See BIP85 specification.
    #   path --> m/83696968'/707764'/{pwd_len}'/{index}'
    #
    # Base64 encode whole 64 bytes of entropy.
    # Slice pwd_len from base64 encoded string [0:pwd_len]
    # we use hardcoded pwd_len=21, which has cca 126 bits of entropy

    # python bas64 puts newline at the end - strip
    assert len(secret) == 64
    secret_b64 = b2a_base64(secret).decode().strip()
    return secret_b64[:BIP85_PWD_LEN]

async def drv_entro_step2(_1, picked, _2):
    from glob import dis
    from files import CardSlot, CardMissingError, needs_microsd

    msg = "Index Number?"
    if picked == 7:
        # Passwords
        msg = "Password Index?"
    index = await ux_enter_bip32_index(msg)
    if index is None:
        return

    dis.fullscreen("Working...")
    new_secret, width, s_mode, path = bip85_derive(picked, index)

    # Reveal to user!
    encoded = None
    chain = chains.current_chain()
    qr = None
    qr_alnum = False

    if s_mode == "pw":
        pw = bip85_pwd(new_secret)
        qr = pw
        msg = 'Password:\n' + pw

    elif s_mode == 'words':
        # BIP-39 seed phrase, various lengths
        words = bip39.b2a_words(new_secret).split(' ')

        # encode more tightly for QR
        qr = ' '.join(w[0:4] for w in words)
        qr_alnum = True

        msg = 'Seed words (%d):\n' % len(words)
        msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))

        encoded = stash.SecretStash.encode(seed_phrase=new_secret)

    elif s_mode == 'wif':
        # for Bitcoin Core: a 32-byte of secret exponent, base58 w/ prefix 0x80
        # - always "compressed", so has suffix of 0x01 (inside base58)
        # - we're not checking it's on curve
        # - we have no way to represent this internally, since we rely on bip32

        # append 0x01 to indicate it's a compressed private key
        pk = new_secret + b'\x01'
        qr = ngu.codecs.b58_encode(chain.b58_privkey + pk)

        msg = 'WIF (privkey):\n' + qr

    elif s_mode == 'xprv':
        # Raw XPRV value.
        ch, pk = new_secret[0:32], new_secret[32:64]
        master_node = ngu.hdnode.HDNode().from_chaincode_privkey(ch, pk)

        encoded = stash.SecretStash.encode(xprv=master_node)
        qr = chain.serialize_private(master_node)
        
        msg = 'Derived XPRV:\n' + qr

    elif s_mode == 'hex':
        # Random hex number for whatever purpose
        qr = str(b2a_hex(new_secret), 'ascii')
        msg = ('Hex (%d bytes):\n' % width) + qr

        qr_alnum = True

        stash.blank_object(new_secret)
        new_secret = None       # no need to print it again
    else:
        raise ValueError(s_mode)

    msg += '\n\nPath Used (index=%d):\n  %s' % (index, path)

    if new_secret:
        msg += '\n\nRaw Entropy:\n' + str(b2a_hex(new_secret), 'ascii')

    prompt = '\n\nPress (1) to save to MicroSD card'
    if encoded is not None:
        prompt += ', (2) to switch to derived secret'
    elif s_mode == 'pw':
        prompt += ', (2) to type password over USB'
    if (qr is not None) and version.has_fatram:
        prompt += ', (3) to view as QR code'
        if glob.NFC:
            prompt += ', (4) to share via NFC'
    if glob.VD:
        prompt += ", (6) to save to Virtual Disk"

    prompt += '.'

    while 1:
        ch = await ux_show_story(msg+prompt, sensitive=True, escape='12346')

        if ch in "16":
            # write to SD card or Virtual Disk: simple text file
            if ch == "1":
                force_vdisk = False
            else:
                force_vdisk = True
            try:
                with CardSlot(force_vdisk=force_vdisk) as card:
                    fname, out_fn = card.pick_filename('drv-%s-idx%d.txt' % (s_mode, index))
                    body = msg + "\n"
                    with open(fname, 'wt') as fp:
                        chunk_writer(fp, body)

                    h = ngu.hash.sha256s(body.encode())
                    sig_nice = write_sig_file([(h, fname)], derive=path)

            except CardMissingError:
                await needs_microsd()
                continue
            except Exception as e:
                await ux_show_story('Failed to write!\n\n\n'+str(e))
                continue

            story = "Filename is:\n\n%s" % out_fn
            story += "\n\nSignature filename is:\n\n%s" % sig_nice
            await ux_show_story(story, title='Saved')
        elif ch == '3' and version.has_fatram:
            from ux import show_qr_code
            await show_qr_code(qr, qr_alnum)
            continue
        elif ch == '2' and s_mode == 'pw':
            # gets confirmation then types it
            await single_send_keystrokes(qr, path)
            continue
        elif ch == '4' and glob.NFC and qr:
            # Share any of these over NFC
            await glob.NFC.share_text(qr)
            continue
        else:
            break

    if new_secret is not None:
        stash.blank_object(new_secret)
    stash.blank_object(msg)

    if ch == '2' and (encoded is not None):
        # switch over to new secret!
        await seed.set_ephemeral_seed(encoded, name='Derived #%d' % index)
        from actions import goto_top_menu
        goto_top_menu()

    if encoded is not None:
        stash.blank_object(encoded)


async def password_entry(*args, **kwargs):
    from glob import dis
    from usb import EmulatedKeyboard

    # cache of length of 1
    # (index, path, password)
    cache = tuple()

    with EmulatedKeyboard() as kbd:
        if await kbd.connect(): return

        while True:
            the_ux.pop()
            index = await ux_enter_bip32_index("Password Index?", can_cancel=True)
            if index is None:
                break

            if cache and index == cache[0]:
                path, pw = cache[1:]
            else:
                dis.fullscreen("Working...")
                new_secret, _, _, path = bip85_derive(7, index)
                pw = bip85_pwd(new_secret)
                cache = (index, path, pw)

            await send_keystrokes(kbd, pw, path)

    the_ux.pop()        # WHY?

async def send_keystrokes(kbd, password, path):
    ch = await ux_show_story(
        "Place mouse at required password prompt, then press OK to send keystrokes.\n\n"
        "Password:\n%s\n\n"
        "Path:\n%s" % (password, path),
    )

    if ch == 'y':
        await kbd.send_keystrokes(password + '\r')

        await ux_dramatic_pause("Sent.", 0.250)
        return True

    await ux_dramatic_pause("Aborted.", 1)

    return False

async def single_send_keystrokes(password, path):
    # switches to USB mode required, then does send
    from usb import EmulatedKeyboard

    with EmulatedKeyboard() as kbd:
        if await kbd.connect(): return
        await send_keystrokes(kbd, password, path)

# EOF
