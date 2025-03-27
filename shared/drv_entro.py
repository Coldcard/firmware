# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-85: Deterministic Entropy From BIP32 Keychains, by
#         Ethan Kosakovsky <ethankosakovsky@protonmail.com>
#
# Using the system's BIP-32 master key, safely derive seeds phrases/entropy for other
# wallet systems, which may expect seed phrases, XPRV, or other entropy.
#
import stash, seed, ngu, chains, bip39
from ux import ux_show_story, ux_enter_bip32_index, the_ux, ux_confirm, ux_dramatic_pause, OK
from menu import MenuItem, MenuSystem
from ubinascii import hexlify as b2a_hex
from ubinascii import b2a_base64
from msgsign import write_sig_file
from utils import chunk_writer, xfp2str, swab32
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL

BIP85_PWD_LEN = 21

async def drv_entro_start(*a):
    from pincodes import pa

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

    if pa.tmp_value:
        if stash.bip39_passphrase:
            msg = ('You have a BIP-39 passphrase set right now '
                   'and so it will be wrapped into the new secret.')
        else:
            msg = 'You have a temporary seed active - deriving from temporary.'

        if not await ux_confirm(msg):
            return

    # XXX any change in this ordering will break lots of stuff! Bad design.
    choices = [ '12 words', '18 words', '24 words', 'WIF (privkey)',
                'XPRV (BIP-32)', '32-bytes hex', '64-bytes hex', 'Passwords']

    m = MenuSystem([MenuItem(c, f=drv_entro_step2) for c in choices])
    the_ux.push(m)

def bip85_derive(picked, index):
    # implement the core step of BIP85 from our master secret
    path = "m/83696968h/"
    if picked in (0,1,2):
        # BIP-39 seed phrases (we only support English)
        num_words = stash.SEED_LEN_OPTS[picked]
        width = (16, 24, 32)[picked]        # of bytes
        path += "39h/0h/%dh/%dh" % (num_words, index)
        s_mode = 'words'
    elif picked == 3:
        # HDSeed for Bitcoin Core: but really a WIF of a private key
        s_mode = 'wif'
        path += "2h/%dh" % index
        width = 32
    elif picked == 4:
        # New XPRV
        path += "32h/%dh" % index
        s_mode = 'xprv'
        width = 64
    elif picked in (5, 6):
        width = 32 if picked == 5 else 64
        path += "128169h/%dh/%dh" % (width, index)
        s_mode = 'hex'
    elif picked == 7:
        width = 64
        # hardcoded width for now
        # b"pwd".hex() --> 707764
        path += "707764h/%dh/%dh" % (BIP85_PWD_LEN, index)
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
    #   path --> m/83696968h/707764h/{pwd_len}h/{index}h
    #
    # Base64 encode whole 64 bytes of entropy.
    # Slice pwd_len from base64 encoded string [0:pwd_len]
    # we use hardcoded pwd_len=21, which has cca 126 bits of entropy

    # python bas64 puts newline at the end - strip
    assert len(secret) == 64
    secret_b64 = b2a_base64(secret).decode().strip()
    return secret_b64[:BIP85_PWD_LEN]

async def pick_bip85_password():
    # ask for index and then return the pw (see notes.py)
    return await drv_entro_step2(None, 7, None, just_pick=True)

async def drv_entro_step2(_1, picked, _2, just_pick=False):
    from glob import dis, settings, NFC
    from files import CardSlot, CardMissingError, needs_microsd
    from ux import ux_render_words, export_prompt_builder, import_export_prompt_decode

    msg = "Password Index?" if picked == 7 else "Index Number?"
    index = await ux_enter_bip32_index(msg, unlimited=settings.get("b85max", False))
    if index is None:
        return

    dis.fullscreen("Working...")
    new_secret, width, s_mode, path = bip85_derive(picked, index)

    if just_pick:
        return bip85_pwd(new_secret)

    # Reveal to user!
    encoded = None
    chain = chains.current_chain()
    qr = None
    qr_alnum = False
    node = None

    if s_mode == "pw":
        pw = bip85_pwd(new_secret)
        qr = pw
        msg = 'Password:\n' + pw

    elif s_mode == 'words':
        # BIP-39 seed phrase, various lengths
        wstr = bip39.b2a_words(new_secret)
        words = wstr.split(' ')

        # slow: 2+ seconds
        ms = bip39.master_secret(wstr)
        hd = ngu.hdnode.HDNode()
        hd.from_master(ms)
        node = hd

        # encode more tightly for QR
        qr = ' '.join(w[0:4] for w in words)
        qr_alnum = True

        msg = 'Seed words (%d):\n' % len(words)
        msg += ux_render_words(words)

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
        node = master_node

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

    # Add the standard export prompt at the end, with extra (5) option sometimes.

    key0 = None
    if encoded is not None:
        key0 = 'to switch to derived secret'
    elif s_mode == 'pw':
        key0 = 'to type password over USB'
    prompt, escape = export_prompt_builder('data', key0=key0,
                                           no_qr=(not qr), force_prompt=True)
    title = None
    if node:
        # we can show master xfp of derived wallet in story
        try:
            title = "[" + xfp2str(swab32(node.my_fp())) + "]"
        except: pass
    while 1:
        ch = await ux_show_story(msg+'\n\n'+prompt, title=title, escape=escape,
                                 strict_escape=True, sensitive=True)
        choice = import_export_prompt_decode(ch)
        if isinstance(choice, dict):
            # write to SD card or Virtual Disk: simple text file
            try:
                with CardSlot(**choice) as card:
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
        elif choice == KEY_CANCEL:
            break
        elif choice == KEY_QR:
            from ux import show_qr_code
            await show_qr_code(qr, qr_alnum)
        elif choice == '0':
            if s_mode == 'pw':
                # gets confirmation then types it
                await single_send_keystrokes(qr, path)
            elif encoded is not None:
                # switch over to new secret!
                dis.fullscreen("Applying...")
                from actions import goto_top_menu
                from glob import settings
                xfp_str = xfp2str(settings.get("xfp", 0))
                await seed.set_ephemeral_seed(
                    encoded,
                    origin='BIP85 Derived from [%s], index=%d' % (xfp_str, index)
                )
                goto_top_menu()
                break

        elif NFC and choice == KEY_NFC:
            # Share any of these over NFC
            await NFC.share_text(qr)

    stash.blank_object(msg)
    stash.blank_object(new_secret)
    stash.blank_object(encoded)
    stash.blank_object(node)


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
    # Prompt them for timing reasons, then send.
    msg = "Place mouse at required password prompt, then press %s to send keystrokes." % OK

    if path:
        # for BIP-85 usage, be chatty and confirm p/w value on screen (debatable)
        msg += "\n\nPassword:\n%s" % password
        msg += "\n\nPath:\n%s" % path

    ch = await ux_show_story(msg)

    if ch == 'y':
        await kbd.send_keystrokes(password + '\r')

        await ux_dramatic_pause("Sent.", 0.250)
        return True

    await ux_dramatic_pause("Aborted.", 1)

    return False

async def single_send_keystrokes(password, path=None):
    # switches to USB mode required, then does send
    from usb import EmulatedKeyboard

    with EmulatedKeyboard() as kbd:
        if await kbd.connect(): return
        await send_keystrokes(kbd, password, path)

# EOF
