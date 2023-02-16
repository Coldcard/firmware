# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Seed XOR Feature
# - use bitwise XOR on 24-word phrases
# - for secret spliting on paper
# - all combination of partial XOR seed phrases are working wallets
#
from menu import MenuItem, MenuSystem
from xor_seedsave import XORSeedSaver
import stash, ngu, chains, bip39, random
from ux import ux_show_story, ux_enter_number, the_ux, ux_confirm, ux_dramatic_pause
from seed import word_quiz, WordNestMenu, set_seed_value
from glob import settings
from actions import goto_top_menu

def xor32(*args):
    # bit-wise xor between all args
    rv = bytearray(32)

    for i in range(32):
        for a in args:
            rv[i] ^= a[i]

    return rv

async def xor_split_start(*a):

    ch = await ux_show_story('''\
Seed XOR Split

This feature splits your BIP-39 seed phrase into multiple parts. \
Each part is 24 words and looks and functions as a normal BIP-39 wallet.

We recommend spliting into just two parts, but permit up to four.

If ANY ONE of the parts is lost, then ALL FUNDS are lost and the original \
seed phrase cannot be reconstructed.

Finding a single part does not help an attacker construct the original seed.

Press 2, 3 or 4 to select number of parts to split into. ''', strict_escape=True, escape='234x')
    if ch == 'x': return

    num_parts = int(ch)

    ch = await ux_show_story('''\
Split Into {n} Parts

On the following screen you will be shown {n} lists of 24-words. \
The new words, when reconstructed, will re-create the seed already \
in use on this Coldcard.

The new parts are generated deterministically from your seed, so if you \
repeat this process later, the same {t} words will be shown.

If you would prefer a random split using the TRNG, press (2). \
Otherwise, press OK to continue.'''.format(n=num_parts, t=num_parts*24), escape='2')

    use_rng = (ch == '2')
    if ch == 'x': return

    await ux_dramatic_pause('Generating...', 2)

    raw_secret = bytes(32)
    try:
        with stash.SensitiveValues() as sv:
            words = None
            if sv.mode == 'words':
                words = bip39.b2a_words(sv.raw).split(' ')

            if not words or len(words) != 24:
                await ux_show_story("Need 24-seed words for this feature.")
                return

            # checksum of target result is useful.
            chk_word = words[-1]
            del words

            # going to need the secret
            raw_secret = bytearray(sv.raw)
            assert len(raw_secret) == 32
    
        parts = []
        for i in range(num_parts-1):
            if use_rng:
                here = random.bytes(32)
                assert len(set(here)) > 4       # TRNG failure?
                mask = ngu.hash.sha256d(here)
            else:
                mask = ngu.hash.sha256d(b'Batshitoshi ' + raw_secret 
                                            + b'%d of %d parts' % (i, num_parts))
            parts.append(mask)

        parts.append(xor32(raw_secret, *parts))

        assert xor32(*parts) == raw_secret      # selftest

    finally:
        stash.blank_object(raw_secret)

    word_parts = [bip39.b2a_words(p).split(' ') for p in parts]

    while 1:
        ch = await show_n_parts(word_parts, chk_word)
        if ch == 'x': 
            if not use_rng: return
            if await ux_confirm("Stop and forget those words?"):
                return
            continue

        for ws, part in enumerate(word_parts):
            print('ws, part, %s, %s'%(ws, part))
            ch = await word_quiz(part, title='Word %s%%d is?' % chr(65+ws))
            if ch == 'x': 
                break
        else:
            break

    await ux_show_story('''\
Quiz Passed!\n
You have confirmed the details of the new split.''')

# list of seed phrases
import_xor_parts = []

class XORWordNestMenu(WordNestMenu):
    @staticmethod
    async def all_done(new_words):
        # So we have another part, might be done or not.
        global import_xor_parts
        assert len(new_words) == 24
        import_xor_parts.append(new_words)

        XORWordNestMenu.pop_all()

        num_parts = len(import_xor_parts)
        seed = xor32(*(bip39.a2b_words(w) for w in import_xor_parts))

        msg = "You've entered %d parts so far.\n\n" % num_parts
        if num_parts >= 2:
            chk_word = bip39.b2a_words(seed).split(' ')[-1]
            msg += "If you stop now, the 24th word of the XOR-combined seed phrase\nwill be:\n\n"
            msg += "24: %s\n\n" % chk_word

        if all((not x) for x in seed):
            # zero seeds are never right.
            msg += "ZERO WARNING\nProvided seed works out to all zeros "\
                    "right now. You may have doubled a part or made some other mistake.\n\n"

        msg += "Press (1) to enter next list of words, or (2) if done with all words."

        ch = await ux_show_story(msg, strict_escape=True, escape='12x', sensitive=True)

        if ch == 'x':
            # give up
            import_xor_parts.clear()          # concern: we are contaminated w/ secrets
            return None
        elif ch == '1':
            # do another list of words. 
            # fast-track to manual entry if no secret set yet.
            from pincodes import pa
            nxt = XORWordNestMenu(num_words=24) if pa.is_secret_blank() else XORSourceMenu()
            the_ux.push(nxt)
        elif ch == '2':
            # done; import on temp basis, or be the main secret
            from pincodes import pa
            enc = stash.SecretStash.encode(seed_phrase=seed)

            if pa.is_secret_blank():
                # save it since they have no other secret
                set_seed_value(encoded=enc)

                # update menu contents now that wallet defined
                goto_top_menu(first_time=True)
            else:
                pa.tmp_secret(enc)
                await ux_show_story("New master key in effect until next power down.")
                goto_top_menu()

        return None

    def tr_label(self):
        global import_xor_parts
        pn = len(import_xor_parts)
        return chr(65+pn) + ' Word' 




class XORSourceMenu(MenuSystem):
    def __init__(self):
        items = [
            MenuItem('Enter Manually', menu=self.manual_entry),
            MenuItem('From SDCard', f=self.from_sdcard)
        ]
        
        super(XORSourceMenu, self).__init__(items)

    async def manual_entry(*a):
        return XORWordNestMenu(num_words=24)

    async def from_sdcard(*a):
        new_words = await XORSeedSaver().read_from_card()
        if not new_words:
            return None

        return await XORWordNestMenu.all_done(new_words)





async def show_n_parts(parts, chk_word):
    num_parts = len(parts)
    msg = 'Record these %d lists of 24-words each.\n\n' % num_parts

    for n,words in enumerate(parts):
        msg += 'Part %s:\n' % chr(65+n)
        msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))
        msg += '\n\n'

    msg += 'The correctly reconstructed seed phrase will have this final word, which we recommend recording:\n\n24: %s' % chk_word

    msg += '\n\nPlease check and double check your notes. There will be a test! ' 

    return await ux_show_story(msg, sensitive=True)

async def xor_restore_start(*a):
    # shown on import menu when no seed of any kind yet
    # - or operational system
    ch = await ux_show_story('''\
To import a seed split using XOR, you must import all the parts.
It does not matter the order (A/B/C or C/A/B) and the Coldcard
cannot determine when you have all the parts. You may stop at
any time and you will have a valid wallet.''')
    if ch == 'x': return

    global import_xor_parts
    import_xor_parts.clear()

    from pincodes import pa

    if not pa.is_secret_blank():
        msg = "Since you have a seed already on this Coldcard, the reconstructed XOR seed will be temporary and not saved. Wipe the seed first if you want to commit the new value into the secure element."
        if settings.get('words', 24) == 24:
            msg += '''\n
Press (1) to include this Coldcard's seed words into the XOR seed set, or OK to continue without.'''

        ch = await ux_show_story(msg, escape='1')

        if ch == 'x':
            return
        elif ch == '1':
            with stash.SensitiveValues() as sv:
                if sv.mode == 'words':
                    words = bip39.b2a_words(sv.raw).split(' ')
                    if len(words) == 24:
                        import_xor_parts.append(words)

    # fast-track to manual entry if no secret set yet.
    if pa.is_secret_blank():
        return XORWordNestMenu(num_words=24)
    
    return XORSourceMenu()

async def xor_save_start(*a):
    from pincodes import pa 
    if pa.has_tmp_seed():
        ch = await ux_show_story('''\
The current master key is a temporary one; the file will be encrypted with this key.

Press OK to continue. X to cancel.
''')
        if ch == 'x': return

    ch = await ux_show_story('''\
Have your 24-word phrase ready. You will enter the 24 words which will then be encrypted using the master key and stored on your SDCard.

Press OK to continue. X to cancel.
''')
    if ch == 'x': return


    async def callback(new_words):
        WordNestMenu.pop_all()
        return await XORSeedSaver().save_to_card(new_words)

    return WordNestMenu(num_words=24, done_cb=callback)

# EOF
