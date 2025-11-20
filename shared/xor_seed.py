# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Seed XOR Feature
# - use bitwise XOR on 24-word phrases
# - for secret spliting on paper
# - all combination of partial XOR seed phrases are working wallets
#
import ngu, bip39, version
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause
from ux import show_qr_code, ux_render_words, OK
from seed import word_quiz, WordNestMenu, set_seed_value, set_ephemeral_seed, seed_vault_iter
from glob import settings
from menu import MenuSystem, MenuItem
from actions import goto_top_menu
from utils import encode_seed_qr, deserialize_secret, xor
from charcodes import KEY_QR
from stash import SecretStash, blank_object, SensitiveValues, numwords_to_len, len_to_numwords

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
Otherwise, press {ok} to continue.'''.format(n=num_parts, ok=OK), escape='2')

    use_rng = (ch == '2')
    if ch == 'x': return

    await ux_dramatic_pause('Generating...', 2)

    raw_secret = bytes(32)
    try:
        with SensitiveValues(enforce_delta=True) as sv:
            words = None
            if sv.mode == 'words':
                words = bip39.b2a_words(sv.raw).split(' ')

            # checksum of target result is useful
            chk_word = words[-1]

            vlen = numwords_to_len(len(words))

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
        blank_object(raw_secret)

    word_parts = [bip39.b2a_words(p).split(' ') for p in parts]

    while 1:
        ch = await show_n_parts(word_parts, chk_word)
        if ch == "x":
            if not use_rng: return
            if await ux_confirm("Stop and forget those words?"):
                return
            continue

        if ch in "4"+KEY_QR:
            qrs = []
            for wl in word_parts:
                qrs.append(encode_seed_qr(wl))

            from qrs import XORQRDisplaySingle
            o = XORQRDisplaySingle(qrs, True, 0, sidebar=None)
            await o.interact_bare()
            continue

        for ws, part in enumerate(word_parts):
            ch = await word_quiz(part, title='Word %s%%d is?' % chr(65+ws))
            if ch == "x": break
        else:
            break

    await ux_show_story('''\
Quiz Passed!\n
You have confirmed the details of the new split.''')

# list of seed phrases
# - stores encoded secret bytes (not word lists)
import_xor_parts = []

async def xor_all_done(data):
    # So we have another part, might be done or not.
    global import_xor_parts

    chk_words = None

    if data is None:
        # special case, needs something already in import_xor_parts
        target_words = len_to_numwords(len(import_xor_parts[0]))
    else:
        new_encoded = bip39.a2b_words(data) if isinstance(data, list) else data
        import_xor_parts.append(new_encoded)
        target_words = len_to_numwords(len(new_encoded))

    XORWordNestMenu.pop_all()

    num_parts = len(import_xor_parts)
    seed = xor(*import_xor_parts)

    msg = "You've entered %d parts so far.\n\n" % num_parts
    if num_parts >= 2:
        chk_words = bip39.b2a_words(seed).split(' ')
        chk_word = chk_words[-1]
        msg += "If you stop now, the %dth word of the XOR-combined seed phrase will be:\n\n" % target_words
        msg += "%d: %s\n\n" % (target_words, chk_word)

    if all((not x) for x in seed):
        # zero seeds are never right.
        msg += "ZERO WARNING\nProvided seed works out to all zeros "\
                "right now. You may have doubled a part or made some other mistake.\n\n"

    msg += "Press (1) to enter next list of words."
    escape = "1"+KEY_QR
    if num_parts >= 2:
        msg += " Or (2) if done with all words."
        escape += "2"

    while True:
        ch = await ux_show_story(msg, escape=escape, sensitive=True)
        if ch in 'x':
            # give up - needs confirmation
            if import_xor_parts:
                if not await ux_confirm("Throw away those words and stop this process?"):
                    continue
            import_xor_parts.clear()          # concern: we are contaminated w/ secrets
        elif chk_words and ch == KEY_QR:
            rv = encode_seed_qr(chk_words)
            await show_qr_code(rv, True, msg="SeedQR", is_secret=True)
            continue
        elif ch == '1':
            # do another list of words
            if version.has_qwerty:
                from ux_q1 import seed_word_entry
                await seed_word_entry("Part %s Words" % chr(65+len(import_xor_parts)),
                                      target_words, done_cb=xor_all_done)
            else:
                nxt = XORWordNestMenu(num_words=target_words, done_cb=xor_all_done)
                the_ux.push(nxt)

        elif ch == '2':
            # done; import on temp basis, or be the main secret
            from pincodes import pa
            from glob import dis

            enc = SecretStash.encode(seed_phrase=seed)

            if pa.is_secret_blank():
                # save it since they have no other secret
                set_seed_value(encoded=enc)
                # update menu contents now that wallet defined
                goto_top_menu(first_time=True)
            else:
                dis.fullscreen("Applying...")
                # set as ephemeral seed, maybe save it too
                # below is super costly as we need to bip32 generate master secret from entropy bytes
                # only need XFPs for UI
                # xfps = [
                #     xfp2str(swab32(
                #         SecretStash.decode(SecretStash.encode(seed_phrase=i))[2].my_fp()
                #     ))
                #     for i in enc_parts
                # ]
                await set_ephemeral_seed(enc,
                    origin='SeedXOR(%d parts, check: "%s")' % (num_parts, chk_word))

                goto_top_menu()

        break

class XORWordNestMenu(WordNestMenu):
    def tr_label(self):
        global import_xor_parts
        pn = len(import_xor_parts)
        return chr(65+pn) + ' Word'

async def show_n_parts(parts, chk_word):
    num_parts = len(parts)
    seed_len = len(parts[0])
    msg = '%d lists of %d-words each:' % (num_parts, seed_len)

    for n,words in enumerate(parts):
        msg += '\n\nPart %s:\n' % chr(65+n)
        msg += ux_render_words(words)

    msg += ('\n\nThe correctly reconstructed seed phrase will have this final word,'
            ' which we recommend recording:\n\n%d: %s\n\n' % (seed_len, chk_word))

    msg += 'Please check and double check your notes. There will be a test! '
    if not version.has_qwerty:
        msg += 'Press (4) to view QR Codes. '

    # allow QR codes on both Mk4 & Q
    return await ux_show_story(msg, title="Record these:", sensitive=True, escape="4",
                               hint_icons=KEY_QR)

async def xor_restore_start(*a):
    # shown on import menu when no seed of any kind yet
    # - or operational system
    ch = await ux_show_story('''\
To import a seed split using XOR, you must import all the parts. \
It does not matter the order (A/B/C or C/A/B) and the Coldcard \
cannot determine when you have all the parts. You may stop at \
any time and you will have a valid wallet. Combined seed parts \
have to be equal length.\n
Press %s for 24 words XOR, press (1) for 12 words XOR, \
or press (2) for 18 words XOR.''' % OK, escape="12")
    if ch == 'x': return

    desired_num_words = 24
    if ch == "1":
        desired_num_words = 12
    elif ch == "2":
        desired_num_words = 18

    global import_xor_parts
    import_xor_parts.clear()

    from pincodes import pa
    from glob import dis

    escape = ""
    if not pa.is_secret_blank():
        msg = ("Since you have a seed already on this Coldcard, the reconstructed XOR seed will be "
               "temporary and not saved. Wipe the seed first if you want to commit the new value "
               "into the secure element.")

        curr_num_words = settings.get('words', desired_num_words)
        if (curr_num_words == desired_num_words) and not pa.hobbled_mode:
            escape += "1"
            msg += ("\n\nPress (1) to include this Coldcard's seed words into the XOR seed set, "
                    "or %s to continue without." % OK)

        ch = await ux_show_story(msg, escape=escape)

        if ch == 'x':
            return

        if ch == '1':
            assert not pa.hobbled_mode
            dis.fullscreen("Wait...")
            with SensitiveValues(enforce_delta=True) as sv:
                if sv.mode == 'words':
                    # needs copy here [:] otherwise rewritten with zeros in __exit__
                    import_xor_parts.append(sv.raw[:])

        # Add from Seed Vault?
        # filter only those that are correct length and type from seed vault
        opt = []
        for i, rec in enumerate(seed_vault_iter()):
            raw = deserialize_secret(rec.encoded)

            nw = SecretStash.is_words(raw)
            if nw and nw == desired_num_words:
                # it is words, and right length
                sk = SecretStash.decode_words(raw, bin_mode=True)
                opt.append((i, rec.xfp, sk))

            blank_object(raw)

        if opt:
            escape = "2"
            msg = ("Seed Vault is enabled. %d stored seeds have suitable type and length."
                   "\n\nPress (2) to add from Seed Vault and then (1) to select seeds,"
                   " press %s to continue normally.") % (len(opt), OK)
            ch = await ux_show_story(msg, escape=escape)
            if ch == 'x': return
            if ch == "2":
                rv = [MenuItem("%2d: [%s]" % (i, xfp_str)) for i, xfp_str, _ in opt]
                the_ux.push(MenuSystem(rv, multichoice=True))
                selected = await the_ux.top_of_stack().interact()
                if selected:
                    import_xor_parts += [opt[i][-1] for i in range(len(opt)) if i in selected]

                    return await xor_all_done(None)

    if version.has_qwerty:
        from ux_q1 import seed_word_entry
        # if current loaded seed is added to xor - it is always A
        await seed_word_entry("Part %s Words" % (chr(65+len(import_xor_parts))),
                              desired_num_words, done_cb=xor_all_done)
    else:
        return XORWordNestMenu(num_words=desired_num_words, done_cb=xor_all_done)

# EOF
