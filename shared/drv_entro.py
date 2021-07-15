# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-85: Deterministic Entropy From BIP32 Keychains, by
#         Ethan Kosakovsky <ethankosakovsky@protonmail.com>
#
# Using the system's BIP-32 master key, safely derive seeds phrases/entropy for other
# wallet systems, which may expect seed phrases, XPRV, or other entropy.
#
import stash, ngu, chains, bip39, version
from ux import ux_show_story, ux_enter_number, the_ux, ux_confirm
from menu import MenuItem, MenuSystem
from ubinascii import hexlify as b2a_hex
from serializations import hash160

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
                'XPRV (BIP-32)', '32-bytes hex', '64-bytes hex']

    m = MenuSystem([MenuItem(c, f=drv_entro_step2) for c in choices])
    the_ux.push(m)

def drv_entro_step2(_1, picked, _2):
    from glob import dis
    from files import CardSlot, CardMissingError

    the_ux.pop()

    index = await ux_enter_number("Index Number?", 9999)

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
    else:
        raise ValueError(picked)

    dis.fullscreen("Working...")
    encoded = None

    with stash.SensitiveValues() as sv:
        node = sv.derive_path(path)
        entropy = ngu.hmac.hmac_sha512(b'bip-entropy-from-k', node.privkey())
    
        sv.register(entropy)

        # truncate for this application
        new_secret = entropy[0:width]
            

    # only "new_secret" is interesting past here (node already blanked at this point)
    del node

    # Reveal to user!
    chain = chains.current_chain()
    qr = None
    qr_alnum = False

    if s_mode == 'words':
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

    prompt = '\n\nPress 1 to save to MicroSD card'
    if encoded is not None:
        prompt += ', 2 to switch to derived secret'
    if (qr is not None) and version.has_fatram:
        prompt += ', 3 to view as QR code.'

    while 1:
        ch = await ux_show_story(msg+prompt, sensitive=True, escape='123')

        if ch == '1':
            # write to SD card: simple text file
            try:
                with CardSlot() as card:
                    fname, out_fn = card.pick_filename('drv-%s-idx%d.txt' % (s_mode, index))

                    with open(fname, 'wt') as fp:
                        fp.write(msg)
                        fp.write('\n')
            except CardMissingError:
                await needs_microsd()
                continue
            except Exception as e:
                await ux_show_story('Failed to write!\n\n\n'+str(e))
                continue

            await ux_show_story("Filename is:\n\n%s" % out_fn, title='Saved')
        elif ch == '3' and version.has_fatram:
            from ux import show_qr_code
            await show_qr_code(qr, qr_alnum)
            continue
        else:
            break

    if new_secret is not None:
        stash.blank_object(new_secret)
    stash.blank_object(msg)

    if ch == '2' and (encoded is not None):
        from glob import dis
        from pincodes import pa

        # switch over to new secret!
        dis.fullscreen("Applying...")

        pa.tmp_secret(encoded)

        await ux_show_story("New master key in effect until next power down.")

    if encoded is not None:
        stash.blank_object(encoded)

# EOF
