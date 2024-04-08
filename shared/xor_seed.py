# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Seed XOR Feature
# - use bitwise XOR on 24-word phrases
# - for secret spliting on paper
# - all combination of partial XOR seed phrases are working wallets
#
import stash, ngu, bip39, random
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause, ux_render_words
from seed import word_quiz, WordNestMenu, set_seed_value, set_ephemeral_seed
from glob import settings
from actions import goto_top_menu
from version import has_qwerty
from charcodes import KEY_CANCEL


def xor(*args):
    # bit-wise xor between all args
    vlen = len(args[0])
    # all have to be same length
    assert all(len(e) == vlen for e in args)
    rv = bytearray(vlen)

    for i in range(vlen):
        for a in args:
            rv[i] ^= a[i]

    return rv

async def xor_split_start(*a):

    ch = await ux_show_story('''\
Seed XOR Split

This feature splits your BIP-39 seed phrase into multiple parts. \
Each part looks and functions as a normal BIP-39 wallet.

We recommend spliting into just two parts, but permit up to four.

If ANY ONE of the parts is lost, then ALL FUNDS are lost and the original \
seed phrase cannot be reconstructed.

Finding a single part does not help an attacker construct the original seed.

Press 2, 3 or 4 to select number of parts to split into. ''', strict_escape=True, escape='234x')
    if ch == 'x': return

    num_parts = int(ch)

    ch = await ux_show_story('''\
Split Into {n} Parts

On the following screen you will be shown {n} lists of words. \
The new words, when reconstructed, will re-create the seed already \
in use on this Coldcard.

The new parts are generated deterministically from your seed, so if you \
repeat this process later, the same words will be shown.

If you would prefer a random split using the TRNG, press (2). \
Otherwise, press OK to continue.'''.format(n=num_parts), escape='2')

    use_rng = (ch == '2')
    if ch == 'x': return

    await ux_dramatic_pause('Generating...', 2)

    raw_secret = bytes(32)
    try:
        with stash.SensitiveValues() as sv:
            words = None
            if sv.mode == 'words':
                words = bip39.b2a_words(sv.raw).split(' ')

            # checksum of target result is useful
            chk_word = words[-1]

            vlen = stash.numwords_to_len(len(words))

            del words

            # going to need the secret
            raw_secret = bytearray(sv.raw)
            assert len(raw_secret) in (16, 24, 32)
    
        parts = []
        for i in range(num_parts-1):
            if use_rng:
                here = ngu.random.bytes(vlen)
                assert len(set(here)) > 4       # TRNG failure?
                mask = ngu.hash.sha256d(here)
            else:
                mask = ngu.hash.sha256d(b'Batshitoshi ' + raw_secret
                                        + b'%d of %d parts' % (i, num_parts))
            parts.append(mask[:vlen])

        parts.append(xor(raw_secret, *parts))

        assert xor(*parts) == raw_secret      # selftest

    finally:
        stash.blank_object(raw_secret)

    word_parts = [bip39.b2a_words(p).split(' ') for p in parts]

    while 1:
        ch = await show_n_parts(word_parts, chk_word)
        if ch == KEY_CANCEL:
            if not use_rng: return
            if await ux_confirm("Stop and forget those words?"):
                return
            continue

        for ws, part in enumerate(word_parts):
            ch = await word_quiz(part, title='Word %s%%d is?' % chr(65+ws))
            if ch == KEY_CANCEL: break
        else:
            break

    await ux_show_story('''\
Quiz Passed!\n
You have confirmed the details of the new split.''')

# list of seed phrases
import_xor_parts = []

async def xor_all_done(new_words):
    # So we have another part, might be done or not.
    global import_xor_parts
    import_xor_parts.append(new_words)
    target_words = len(new_words)

    XORWordNestMenu.pop_all()

    num_parts = len(import_xor_parts)
    enc_parts = [bip39.a2b_words(w) for w in import_xor_parts]
    seed = xor(*enc_parts)

    msg = "You've entered %d parts so far.\n\n" % num_parts
    if num_parts >= 2:
        chk_word = bip39.b2a_words(seed).split(' ')[-1]
        msg += "If you stop now, the %dth word of the XOR-combined seed phrase\nwill be:\n\n" % target_words
        msg += "%d: %s\n\n" % (target_words, chk_word)

    if all((not x) for x in seed):
        # zero seeds are never right.
        msg += "ZERO WARNING\nProvided seed works out to all zeros "\
                "right now. You may have doubled a part or made some other mistake.\n\n"

    msg += "Press (1) to enter next list of words, or (2) if done with all words."

    ch = await ux_show_story(msg, strict_escape=True, escape='12x'+KEY_CANCEL, sensitive=True)
    if ch == 'x':
        # give up
        import_xor_parts.clear()          # concern: we are contaminated w/ secrets
        return None

    elif ch == '1':
        # do another list of words
        if has_qwerty:
            from ux_q1 import seed_word_entry
            await seed_word_entry("Part %s Words" % chr(65+len(import_xor_parts)),
                                                target_words, done_cb=xor_all_done)
        else:
            nxt = XORWordNestMenu(num_words=target_words, done_cb=xor_all_done)
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
            # set as ephemeral seed, maybe save it too
            # below is super costly as we need to bip32 generate master secret from entropy bytes
            # only need XFPs for UI
            # xfps = [
            #     xfp2str(swab32(
            #         stash.SecretStash.decode(stash.SecretStash.encode(seed_phrase=i))[2].my_fp()
            #     ))
            #     for i in enc_parts
            # ]
            await set_ephemeral_seed(
                enc,
                meta='SeedXOR(%d parts, check: "%s")' % (
                    num_parts, chk_word
                )
            )
            goto_top_menu()

    return None

class XORWordNestMenu(WordNestMenu):
    def tr_label(self):
        global import_xor_parts
        pn = len(import_xor_parts)
        return chr(65+pn) + ' Word' 

async def show_n_parts(parts, chk_word):
    num_parts = len(parts)
    seed_len = len(parts[0])
    msg = 'Record these %d lists of %d-words each: ' % (num_parts, seed_len)

    for n,words in enumerate(parts):
        msg += 'Part %s:\n' % chr(65+n)
        msg += ux_render_words(words, leading_blanks=0)
        msg += '\n\n'

    msg += ('The correctly reconstructed seed phrase will have this final word,'
            ' which we recommend recording:\n\n%d: %s\n\n' % (seed_len, chk_word))

    msg += 'Please check and double check your notes. There will be a test! '

    return await ux_show_story(msg, sensitive=True)

async def xor_restore_start(*a):
    # shown on import menu when no seed of any kind yet
    # - or operational system
    ch = await ux_show_story('''\
To import a seed split using XOR, you must import all the parts.
It does not matter the order (A/B/C or C/A/B) and the Coldcard
cannot determine when you have all the parts. You may stop at
any time and you will have a valid wallet. Combined seed parts
have to be equal length. No way to combine seed parts of different 
length. Press OK for 24 words XOR, press (1) for 12 words XOR, 
or press (2) for 18 words XOR.''', escape="12")
    if ch == 'x': return

    desired_num_words = 24
    if ch == "1":
        desired_num_words = 12
    elif ch == "2":
        desired_num_words = 18

    curr_num_words = settings.get('words', desired_num_words)

    global import_xor_parts
    import_xor_parts.clear()

    from pincodes import pa

    escape = ""
    if not pa.is_secret_blank():
        msg = ("Since you have a seed already on this Coldcard, the reconstructed XOR seed will be "
               "temporary and not saved. Wipe the seed first if you want to commit the new value "
               "into the secure element.")
        if curr_num_words == desired_num_words:
            escape += "1"
            msg += ("\nPress (1) to include this Coldcard's seed words into the XOR seed set, "
                    "or OK to continue without.")

        ch = await ux_show_story(msg, escape=escape)

        if ch == 'x':
            return
        elif ch == '1':
            with stash.SensitiveValues() as sv:
                if sv.mode == 'words':
                    words = bip39.b2a_words(sv.raw).split(' ')
                    import_xor_parts.append(words)

    if has_qwerty:
        from ux_q1 import seed_word_entry
        await seed_word_entry("Part A Words", desired_num_words, done_cb=xor_all_done)
    else:
        return XORWordNestMenu(num_words=desired_num_words, done_cb=xor_all_done)

# EOF
