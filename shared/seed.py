# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# seed.py - bip39 seeds and words
#
# references:
# - <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
# - <https://iancoleman.io/bip39/#english>
# - zero values:
#    - 'abandon' * 23 + 'art'
#    - 'abandon' * 17 + 'agent'
#    - 'abandon' * 11 + 'about'
#
from menu import MenuItem, MenuSystem
from utils import pop_count, xfp2str
import ngu, uctypes, bip39, random, version
from uhashlib import sha256
from ux import ux_show_story, the_ux, ux_dramatic_pause, ux_confirm, show_qr_code
from ux import PressRelease
from pincodes import AE_SECRET_LEN, AE_LONG_SECRET_LEN
from actions import goto_top_menu
from stash import SecretStash, SensitiveValues
from ubinascii import hexlify as b2a_hex
from pwsave import PassphraseSaver
from glob import settings, dis
from pincodes import pa

# seed words lengths we support: 24=>256 bits, and recommended
VALID_LENGTHS = (24, 18, 12)

# bit flag that means "also include bare prefix as a valid word"
_PREFIX_MARKER = const(1<<26)
    
def letter_choices(sofar='', depth=0, thres=5):
    # make a list of word completions based on indicated prefix
    if not sofar:
        # all letters:
        # - except 'x' which isn't used in the wordlist.
        # - and q- which is really qu-, because English.
        return [('%s-' % chr(97+i)) if i != 16 else 'qu-'  for i in range(26) if i != 23]

    exact, nexts, matched = bip39.next_char(sofar)
    #print("[%d] %s => x=%r n=%r m=%r" % (depth, sofar, exact, nexts, matched))

    if not nexts:
        # no more choices; done
        return [matched]

    rv = []
    if exact:
        # ie: "act" plus "action", "actor"
        rv.append(sofar)

    if len(nexts) == 1 and matched:
        # aba => abandon (unambig first 3 chars)
        # but not: age => age, agent (abig first 3)
        rv.append(matched)
    else:
        for w in nexts:
            rv.append(sofar + w + '-')

    # replace bab- => baby and other cases where prefix is unique
    # - doesn't grow menu length
    if len(sofar) >= 2:
        for n, w in enumerate(rv):
            if w[-1] != '-': continue
            exact, nexts, matched = bip39.next_char(w[:-1])
            if matched:
                rv[n] = matched

    if len(rv) <= thres:
        if depth == 0:
            # examples:
            #   z => ze- and zo-  ... better if all 4 z-words are shown
            #   y => 6 choices
            # - above thres=5, we get menus w/60+ entries
            # - recurse only one level also to keep size down
            a = []
            for i in rv:
                if i[-1] != '-':
                    a.append(i)
                else:
                    a.extend(letter_choices(i[:-1], depth+1))
            return a

    return rv

'''
# 100% working test code (keep)

thres=2 => min/max/avg = 2 / 20 / 4.221338  nodes=628
thres=3 => min/max/avg = 2 / 20 / 4.371667  nodes=600
thres=4 => min/max/avg = 2 / 31 / 4.593250  nodes=563
thres=5 => min/max/avg = 2 / 34 / 4.882917  nodes=521
thres=6 => min/max/avg = 2 / 58 / 5.397826  nodes=460
thres=7 => min/max/avg = 2 / 61 / 5.618721  nodes=438
thres=8 => min/max/avg = 2 / 61 / 5.793839  nodes=422
thres=9 => min/max/avg = 2 / 66 / 5.485588  nodes=451

def test_lc():
    for thres in range(2, 10):
        terms = set()
        todo = set(letter_choices(''))
        sizes = []
        while todo:
            w = todo.pop()
            assert w not in terms
            if w[-1] == '-':
                h = letter_choices(w[:-1], thres=thres)
                assert len(h) == len(set(h))
                sizes.append(len(h))
                todo.update(h)
            else:
                terms.add(w)

        assert len(terms) == 2048

        print("thres=%d => min/max/avg = %d / %d / %f  nodes=%d" % 
                    (thres, min(sizes), max(sizes), sum(sizes)/len(sizes), len(sizes)))
'''


class WordNestMenu(MenuSystem):
    # singleton (cls level) vars
    words = []
    target_words = None
    has_checksum = True
    done_cb = None

    def __init__(self, num_words=None, has_checksum=True, done_cb=None, items=None, is_commit=False):

        if num_words is not None:
            WordNestMenu.target_words = num_words
            WordNestMenu.has_checksum = has_checksum
            WordNestMenu.words = []
            WordNestMenu.done_cb = done_cb or self.all_done
            is_commit = True

        if not items:
            items = [MenuItem(i, menu=self.next_menu) for i in letter_choices()]

        self.is_commit = is_commit

        super(WordNestMenu, self).__init__(items)

    @staticmethod
    async def next_menu(self, idx, choice):

        words = WordNestMenu.words
        cls = self.__class__

        if choice.label[-1] == '-':
            ch = letter_choices(choice.label[0:-1])

            return cls(items=[MenuItem(i, menu=self.next_menu) for i in ch])

        # terminal choice, start next word
        words.append(choice.label)

        assert len(words) <= self.target_words

        if len(words) == 23 and self.has_checksum:
            # we can provide final 8 choices, but only for 24-word case
            final_words = list(bip39.a2b_words_guess(words))

            async def picks_chk_word(s, idx, choice):
                # they picked final word, the word includes valid checksum bits
                words.append(choice.label)
                await cls.done_cb(words.copy())

            items = [MenuItem(w, f=picks_chk_word) for w in final_words]
            items.append(MenuItem('(none above)', f=self.explain_error))
            return cls(is_commit=True, items=items)

        # add a few top-items in certain cases
        if len(words) == self.target_words:
            if self.has_checksum:
                try:
                    bip39.a2b_words(' '.join(words))
                    correct = True
                except ValueError:
                    correct = False
            else:
                correct = True

            # they have checksum right, so they are certainly done.
            if correct:
                # they are done, don't force them to do any more!
                return await cls.done_cb(words.copy())
            else:
                # give them a chance to confirm and/or start over
                return cls(is_commit=True, items = [
                            MenuItem('(INCORRECT)', f=self.explain_error),
                            MenuItem('(start over)', f=self.start_over)])


        # pop stack to reset depth, and start again at a- .. z-
        cls.pop_all()

        return cls(items=None, is_commit=True)

    @classmethod
    def pop_all(cls):
        while isinstance(the_ux.top_of_stack(), cls):
            the_ux.pop()

    def on_cancel(self):
        # user pressed cancel on a menu (so he's going upwards)
        # - if it's a step where we added to the word list, undo that.
        # - but keep them in our system until:
        # - when the word list is empty and they cancel, stop
        words = WordNestMenu.words
        if self.is_commit and words:
            words.pop()

            # replace the menu we are show w/ top-level (a-) menu
            the_ux.pop()
            nxt = WordNestMenu(is_commit=True)
            the_ux.push(nxt)
        else:
            the_ux.pop()

    @staticmethod
    async def all_done(new_words):
        # save the new seed value
        set_seed_value(new_words)
        
        # clear menu stack
        goto_top_menu(first_time=True)

        return None

    async def explain_error(self, *a):

        await ux_show_story('''\
You've got a mistake in your words. We know because the checksum does not \
verify. It's probably best to start over again, but you can back out \
individual words if you wish.''')

    async def start_over(self, *a):

        # pop everything we've done off the stack
        self.pop_all()

        # begin again, empty but same settings
        self.words = []
        the_ux.push(self.__class__(num_words=WordNestMenu.target_words))

    def tr_label(self):
        return 'Word'

    def late_draw(self, dis):
        # add an overlay with "word N" in small text, top right.
        from display import FontTiny

        count = len(self.words)
        if count >= self.target_words:
            # on final DONE/incorrect screen
            return

        dis.progress_bar(count / self.target_words)

        count += 1
        invert = (self.cursor == self.ypos)

        y = 6
        dis.text(-8, y-4, "%d" % count, invert=invert)
        dis.text(-18-(6 if count >= 10 else 0), y, self.tr_label(), FontTiny, invert=invert)


async def show_words(words, prompt=None, escape=None, extra='', ephemeral=False):
    msg = (prompt or 'Record these %d secret words!\n') % len(words)
    msg += '\n'.join('%2d: %s' % (i, w) for i, w in enumerate(words, start=1))
    msg += '\n\nPlease check and double check your notes.'
    if not ephemeral:
        # user can skip quiz for ephemeral secrets
        msg += " There will be a test!"


    if version.has_fatram:
        escape = (escape or '') + '1'
        extra += 'Press (1) to view as QR Code. '

    if extra:
        msg += '\n\n'
        msg += extra

    while 1:
        ch = await ux_show_story(msg, escape=escape, sensitive=True)
        if ch == '1':
            await show_qr_code(' '.join(w[0:4] for w in words), True)
            continue
        break

    return ch

async def add_dice_rolls(count, seed, judge_them):
    from glob import dis
    from display import FontTiny, FontLarge

    md = sha256(seed)
    pr = PressRelease()

    # fixed parts of screen
    dis.clear()
    y = 38
    dis.text(0, y, "Press 1-6 for each dice"); y += 13
    dis.text(0, y, "roll to mix in.")
    dis.save()

    while 1:
        # Note: cannot scroll this msg because 5=up arrow
        dis.restore()
        dis.text(None, 0, '%d rolls' % count, FontLarge)

        hx = str(b2a_hex(md.digest()), 'ascii')
        dis.text(0, 20, hx[0:32], FontTiny)
        dis.text(0, 20+7, hx[32:], FontTiny)

        dis.show()

        ch = await pr.wait()

        if ch in '123456':
            count += 1

            dis.restore()
            dis.text(None, 0, '%d rolls' % count, FontLarge)
            dis.show()

            # this is slow enough to see
            md.update(ch)

        elif ch == 'x':
            # Because the change (roll) has already been applied,
            # only let them abort if it's early still
            if count < 10 and judge_them:
                return 0, seed
        elif ch == 'y':
            if count < 99 and judge_them:
                if not count:
                    return 0, seed
                ok = await ux_confirm('''\
You only provided %d dice rolls, and each roll adds only 2.585 bits of entropy. \
For 128-bit security, which is considered the minimum, you need 50 rolls, and \
for 256-bits of security, 99 rolls.''' % count)
                if not ok: continue
            break

    if count:
        seed = md.digest()

    return count, seed

async def new_from_dice(nwords):
    # Use lots of (D6) dice rolls to create seed entropy.
    # Note: only 2.585 bits of entropy per roll, so need lots!
    # 50 => 128bits, 99 => 256bits

    seed = b''
    count = 0

    count, seed = await add_dice_rolls(count, seed, True)
    if count == 0: return

    words = await approve_word_list(seed, nwords)
    if words:
        set_seed_value(words)
        # send them to home menu, now with a wallet enabled
        goto_top_menu(first_time=True)

async def set_ephemeral_seed(encoded):
    pa.tmp_secret(encoded)
    xfp = settings.get("xfp", "")
    if xfp:
        xfp = "[" + xfp2str(xfp) + "]\n"
    await ux_show_story("%sNew ephemeral master key in effect until next power down.\n\nIt is NOT stored anywhere." % xfp)

async def set_ephemeral_seed_words(words):
    encoded = seed_words_to_encoded_secret(words)
    await set_ephemeral_seed(encoded)
    goto_top_menu()

async def ephemeral_seed_generate_from_dice(nwords):
    # Use lots of (D6) dice rolls to create seed entropy.
    # Note: only 2.585 bits of entropy per roll, so need lots!
    # 50 => 128bits, 99 => 256bits

    seed = b''
    count = 0

    count, seed = await add_dice_rolls(count, seed, True)
    if count == 0: return

    words = await approve_word_list(seed, nwords, ephemeral=True)
    if words:
        await set_ephemeral_seed_words(words)

def generate_seed():
    seed = random.bytes(32)
    assert len(set(seed)) > 4       # TRNG failure
    # hash to mitigate possible bias in TRNG
    seed = ngu.hash.sha256s(seed)
    return seed

async def make_new_wallet(nwords):
    # Pick a new random seed.
    await ux_dramatic_pause('Generating...', 3)
    seed = generate_seed()
    words = await approve_word_list(seed, nwords)
    if words:
        set_seed_value(words)
        # send them to home menu, now with a wallet enabled
        goto_top_menu(first_time=True)

async def ephemeral_seed_import_done_cb(words):
    dis.fullscreen("Applying...")
    await set_ephemeral_seed_words(words)

async def ephemeral_seed_import(nwords):
    return WordNestMenu(nwords, done_cb=ephemeral_seed_import_done_cb)

async def ephemeral_seed_generate(nwords):
    await ux_dramatic_pause('Generating...', 3)
    seed = generate_seed()
    words = await approve_word_list(seed, nwords, ephemeral=True)
    if words:
        await set_ephemeral_seed_words(words)

async def approve_word_list(seed, nwords, ephemeral=False):
    # Force the user to write the seeds words down, give a quiz, then save them.

    # LESSON LEARNED: if the user is writting down the words, as we have
    # vividly instructed, then it's a big deal to lose those words and have to start
    # over. So confirm that action, and don't volunteer it.

    if nwords == 12:
        seed = seed[0:16]

    words = bip39.b2a_words(seed).split(' ')
    assert len(words) == nwords
    extra_msg = 'Press (4) to add some dice rolls into the mix. '
    if ephemeral:
        # document quiz skipping if generating ephemeral seed
        extra_msg += "Press (6) to skip word quiz. "

    while 1:
        # show the seed words
        ch = await show_words(words, escape='46', extra=extra_msg, ephemeral=ephemeral)
        if ch == 'x': 
            # user abort, but confirm it!
            if await ux_confirm("Throw away those words and stop this process?"):
                return
            else:
                continue

        if ch == '4':
            # dice roll mode
            count, new_seed = await add_dice_rolls(0, seed, False)
            if count:
                seed = new_seed[0:16] if nwords == 12 else new_seed
                words = bip39.b2a_words(seed).split(' ')

            continue

        if ch == '6':
            # wants to skip the quiz (undocumented)
            if await ux_confirm("Skipping the quiz means you might have "
                                        "recorded the seed wrong and will be crying later."):
                break

        # Perform a test, to check they wrote them down
        ch = await word_quiz(words)
        if ch == 'x':
            # user abort quiz
            if await ux_confirm("Throw away those words and stop this process? Press X to see the word list again and restart the quiz."):
                return

            # show the words again, but don't change them
            continue

        # quiz passed
        break

    return words

def seed_words_to_encoded_secret(words):
    # seed without checksum
    seed = bip39.a2b_words(words)  # checksum check
    # encode it for our limited secret space
    nv = SecretStash.encode(seed_phrase=seed)
    return nv

def set_seed_value(words=None, encoded=None):
    # Save the seed words into secure element, and reboot. BIP-39 password
    # is not set at this point (empty string)
    if words:
        nv = seed_words_to_encoded_secret(words)
    else:
        nv = encoded

    from glob import dis
    try:
        dis.fullscreen('Applying...')
        dis.busy_bar(True)
        pa.change(new_secret=nv)

        # re-read settings since key is now different
        # - also captures xfp, xpub at this point
        pa.new_main_secret(nv)

        # check and reload secret
        pa.reset()
        pa.login()
    finally:
        dis.busy_bar(False)

def set_bip39_passphrase(pw):
    # apply bip39 passphrase for now (volatile)

    # takes a bit, so show something
    from glob import dis
    dis.fullscreen("Working...")

    # set passphrase
    import stash
    stash.bip39_passphrase = pw

    # capture updated XFP
    with stash.SensitiveValues() as sv:
        # can't do it without original seed words (late, but caller has checked)
        assert sv.mode == 'words'

        sv.capture_xpub()

    # Might need to bounce the USB connection, because our pubkey has changed,
    # altho if they have already picked a shared session key, no need, and
    # would only affect MitM test, which has already been done.

async def remember_bip39_passphrase():
    # Compute current xprv and switch to using that as root secret.
    import stash
    from glob import dis

    dis.fullscreen('Check...')

    with stash.SensitiveValues() as sv:
        nv = SecretStash.encode(xprv=sv.node)

    # Important: won't write new XFP to nvram if pw still set
    stash.bip39_passphrase = ''

    dis.fullscreen('Saving...')
    pa.change(new_secret=nv)

    # re-read settings since key is now different
    # - also captures xfp, xpub at this point
    pa.new_main_secret(nv)

    # check and reload secret
    pa.reset()
    pa.login()

def clear_seed():
    from glob import dis
    import utime, callgate

    dis.fullscreen('Clearing...')
    dis.busy_bar(True)

    # clear settings associated with this key, since it will be no more
    settings.blank()

    if version.mk_num >= 4:
        callgate.fast_wipe(True)
        # NOT REACHED
    else:
        # save a blank secret (all zeros is a special case, detected by bootloader)
        nv = bytes(AE_SECRET_LEN)
        pa.change(new_secret=nv)

        if version.has_608:
            # wipe the long secret too
            nv = bytes(AE_LONG_SECRET_LEN)
            pa.ls_change(nv)

    dis.busy_bar(False)
    dis.fullscreen('Reboot...')
    utime.sleep(1)

    # security: need to reboot to really be sure to clear the secrets from main memory.
    from machine import reset
    reset()

async def word_quiz(words, limited=None, title='Word %d is?'):
    # Perform a test, to check they wrote them down
    # Return X if they cancel early.
    # Can just pick a subset # of words, with limited arg.

    wl = len(words)     # 24 or 12, etc.

    if limited is not None:
        # truncate to some N randomly-selected words in the list
        # and always the last word
        order = list(range(wl-1))
        random.shuffle(order)

        order = order[0:limited-1]
        order.append(wl-1)
    else:
        order = list(range(wl))
        
    random.shuffle(order)

    for o in order:
        # always 3 choices: right answer, wrong from correct set, random word
        right = words[o]

        choices = [right]
        while 1:
            n = words[random.randbelow(wl)]
            if n in choices: continue
            choices.append(n)
            break

        while 1:
            n = bip39.wordlist_en[random.randbelow(0x800)]
            if n in choices: continue
            choices.append(n)
            break

        while 1:
            random.shuffle(choices)
            
            msg = '\n'.join(' %d: %s' % (i+1, choices[i]) for i in range(3))
            msg += '\n\nWhich word is right?\n\nX to give up, OK to see all the words again.'

            ch = await ux_show_story(msg, title=title % (o+1), escape='123', sensitive=True)
            if ch == 'x':
                # user abort
                return 'x'
            elif ch == 'y':
                await show_words(words)
                continue

            if ch in '123':
                n = ord(ch) - ord('1')

                if choices[n] == right:
                    break

            await ux_dramatic_pause('Wrong!', 2)

    return


class EphemeralSeedMenu(MenuSystem):

    @staticmethod
    async def ephemeral_seed_import(menu, label, item):
        return await ephemeral_seed_import(item.arg)

    @staticmethod
    async def ephemeral_seed_generate(menu, label, item):
        return await ephemeral_seed_generate(item.arg)

    @staticmethod
    async def ephemeral_seed_generate_from_dice(menu, label, item):
        return await ephemeral_seed_generate_from_dice(item.arg)

    @classmethod
    def construct(cls):
        from glob import NFC, settings
        from actions import nfc_recv_ephemeral

        import_ephemeral_menu = [
            MenuItem("24 Words", f=cls.ephemeral_seed_import, arg=24),
            MenuItem("18 Words", f=cls.ephemeral_seed_import, arg=18),
            MenuItem("12 Words", f=cls.ephemeral_seed_import, arg=12),
            MenuItem("Import via NFC", f=nfc_recv_ephemeral, predicate=lambda: NFC is not None),
        ]
        gen_ephemeral_menu = [
            MenuItem("24 Words", f=cls.ephemeral_seed_generate, arg=24),
            MenuItem("12 Words", f=cls.ephemeral_seed_generate, arg=12),
            MenuItem("24 Word Dice Roll", f=cls.ephemeral_seed_generate_from_dice, arg=24),
            MenuItem("12 Word Dice Roll", f=cls.ephemeral_seed_generate_from_dice, arg=12),
        ]

        rv = [
            MenuItem("Generate Seed", menu=gen_ephemeral_menu),
            MenuItem("Import Seed", menu=import_ephemeral_menu),
        ]
        if pa.tmp_value:
            xfp = settings.get("xfp", "")
            if xfp:
                rv.insert(0, MenuItem("[%s]" % xfp2str(xfp)))
            else:
                rv.insert(0, MenuItem("[Active]"))

        return rv

async def make_ephemeral_seed_menu(*a):
    if not pa.tmp_value:
        # force a warning on them, unless they are already doing it.
        ch = await ux_show_story(
            "Ephemeral seed is a temporary secret stored solely in device RAM, persisted for only a single boot. "
            "This defeats all of the benefits of Coldcard's secure element design."
            "\n\nPress (4) to prove you read to the end of this message and accept all consequences.",
            title="WARNING",
            escape="4"
        )
        if ch != "4":
            return

    rv = EphemeralSeedMenu.construct()
    return EphemeralSeedMenu(rv)


pp_sofar = ''

class PassphraseMenu(MenuSystem):
    # Collect up to 100 chars as a BIP-39 passphrase

    # singleton (cls level) vars
    done_cb = None

    def __init__(self, done_cb=None, items=None):
        global pp_sofar
        pp_sofar = ''

        items = [
            #         xxxxxxxxxxxxxxxx
            MenuItem('Edit Phrase', f=self.view_edit_phrase),
            MenuItem('Add Word', menu=self.word_menu),
            MenuItem('Add Numbers', f=self.add_numbers),
            MenuItem('Clear All', f=self.empty_phrase),
            MenuItem('APPLY', f=self.done_apply),
            MenuItem('CANCEL', f=self.done_cancel),
        ]

        try:
            saved = PassphraseSaver().make_menu()
            if saved:
                items.insert(0, MenuItem('Restore Saved', menu=saved))
        except:
            # don't want bugs/corrupt files to make rest of menu inaccessible
            pass

        super(PassphraseMenu, self).__init__(items)

    def on_cancel(self):
        # zip to cancel item when they fail to exit via X button
        self.goto_idx(self.count - 1)

    async def word_menu(self, *a):
        return SingleWordMenu()

    async def add_numbers(self, *a):
        # collect a series of digits
        from glob import dis
        from display import FontTiny, FontSmall
        global pp_sofar

        # allow key repeat on X only
        press = PressRelease('1234567890y')
        
        footer = "X to DELETE, or OK when DONE."
        lx = 6
        y = 16
        here = ''

        dis.clear()
        dis.text(None, -1, footer, FontTiny)
        dis.save()

        while 1:
            dis.restore()

            # text centered
            msg = here
            by = y
            bx = dis.text(lx, y, msg[0:16])
            dis.text(lx, y-9, str(pp_sofar, 'ascii').replace(' ', '_'), FontTiny)

            if len(msg) > 16:
                # second line when needed (left just)
                by += 15
                bx = dis.text(lx, by, msg[16:])

            if len(here) < 32:
                dis.icon(bx, by-2, 'sm_box')

            dis.show()

            ch = await press.wait()
            if ch == 'y':
                pp_sofar += here
                self.check_length()
                return
            elif ch == 'x':
                if here:
                    here = here[0:-1]
                else:
                    # quit if they press X on empty screen
                    return
            else:
                if len(here) < 32:
                    here += ch

    async def empty_phrase(self, *a):
        global pp_sofar

        if pp_sofar and len(pp_sofar) >= 3:
            if not await ux_confirm("Press OK to clear passphrase. X to cancel."):
                return

        pp_sofar = ''
        await ux_dramatic_pause('Cleared...', 0.25)

    async def backspace(self, *a):
        global pp_sofar
        if pp_sofar:
            pp_sofar = pp_sofar[0:-1]

    async def view_edit_phrase(self, *a):
        # let them control each character
        global pp_sofar
        pw = await spinner_edit(pp_sofar)
        if pw is not None:
            pp_sofar = pw
            self.check_length()

    @classmethod
    def check_length(cls):
        # enforce a limit of 100 chars
        global pp_sofar
        pp_sofar = pp_sofar[0:100]

    @staticmethod
    async def add_text(_1, _2, item):
        global pp_sofar
        pp_sofar += item.label
        PassphraseMenu.check_length()

        while not isinstance(the_ux.top_of_stack(), PassphraseMenu):
            the_ux.pop()

    async def done_cancel(self, *a):
        global pp_sofar

        if len(pp_sofar) > 3:
            if not await ux_confirm("What you have entered will be forgotten."):
                return

        goto_top_menu()

    async def done_apply(self, *a):
        # apply the passphrase.
        # - important to work on empty string here too.
        from stash import bip39_passphrase
        old_pw = str(bip39_passphrase)

        set_bip39_passphrase(pp_sofar)

        xfp = settings.get('xfp')

        msg = '''Above is the master key fingerprint of the new wallet.

Press X to abort and keep editing passphrase, OK to use the new wallet, or 1 to use and save to MicroSD'''

        ch = await ux_show_story(msg, title="[%s]" % xfp2str(xfp), escape='1')
        if ch == 'x':
            # go back!
            set_bip39_passphrase(old_pw)
            return

        if ch == '1':
            await PassphraseSaver().append(xfp, pp_sofar)

        goto_top_menu()

class SingleWordMenu(WordNestMenu):
    def __init__(self, items=None, **kws):
        if items:
            super(SingleWordMenu, self).__init__(items=items, **kws)
        else:
            super(SingleWordMenu, self).__init__(num_words=1, has_checksum=False, done_cb=None)

    @staticmethod
    async def all_done(new_words):
        # create one more menu w/ the word and some variations on that word
        word = new_words[0]
        options = [word, word[0].upper() + word[1:], word.upper()]
        for w in options[:]:
            options.append(' ' + w)

        # bugfix: in case they cancel from new menu
        WordNestMenu.words = []

        return MenuSystem([MenuItem(w, f=PassphraseMenu.add_text) 
                                    for n,w in enumerate(options)], space_indicators=True)

    def late_draw(self, dis):
        #PassphraseMenu.late_draw(self, dis)
        pass

async def spinner_edit(pw, confirm_exit=True):
    # Allow them to pick each digit using "D-pad"
    from glob import dis
    from display import FontTiny, FontSmall

    # Should allow full unicode, NKDN
    # - but limited to what we can show in FontSmall
    # - so really just ascii; not even latin-1
    # - 8-bit codepoints only
    my_rng = range(32, 127)          # FontSmall.code_range
    symbols = b' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    letters = b'abcdefghijklmnopqrstuvwxyz'
    Letters = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numbers = b'1234567890'
    #assert len(set(symbols+letters+Letters+numbers)) == len(my_rng)
    
    footer1 = "1=Letters  2=Numbers  3=Symbols"
    footer2 = "4=SwapCase  0=HELP"
    y = 20
    pw = bytearray(pw or 'A')

    pos = len(pw)-1       # which part being changed
    n_visible = const(9)
    scroll_x = max(pos - n_visible, 0)

    def cycle_set(which, direction=1):
        # pick next item in set of choices
        for n, s in enumerate(which):
            if pw[pos] == s:
                try:
                    pw[pos] = which[n+direction]
                except IndexError:
                    pw[pos] = which[0 if direction==1 else -1]
                return
        pw[pos] = which[0]

    def change(dx):
        # next/prev within the same subset of related chars
        ch = pw[pos]
        for subset in [symbols, letters, Letters, numbers]:
            if ch in subset:
                return cycle_set(subset, dx)

        # probably unreachable code: numeric up/down
        ch = pw[pos] + dx
        if ch not in my_rng:
            ch = (my_rng.stop-1) if dx < 0 else my_rng.start
            assert ch in my_rng
        pw[pos] = ch

    # pre-render the fixed stuff
    dis.clear()
    dis.text(None, -10, footer1, FontTiny)
    dis.text(None, -1, footer2, FontTiny)
    dis.save()

    # no key-repeat on certain keys
    press = PressRelease('4xy')
    while 1:
        dis.restore()

        lr = pos - scroll_x     # left/right distance of cursor
        if lr < 4 and scroll_x:
            scroll_x -= 1
        elif lr < 0:
            scroll_x = pos
        elif lr >= (n_visible-1):
            # past right edge
            scroll_x += 1

        for i in range(n_visible):
            # calc abs position in string
            ax = scroll_x + i
            x = 4 + (13*i)
            try:
                ch = pw[ax]
            except IndexError:
                continue

            if ax == pos:
                # draw cursor
                if len(pw) < 2*n_visible:
                    dis.text(x-4, y-19, '0x%02X' % ch, FontTiny)
                dis.icon(x-2, y-10, 'spin')

            if ch == 0x20:
                dis.icon(x, y+11, 'space')
            else:
                dis.text(x, y, chr(ch) if ch in my_rng else chr(215), FontSmall)

        if scroll_x > 0:
            dis.text(2, y-14, str(pw, 'ascii')[0:scroll_x].replace(' ', '_'), FontTiny)
        if scroll_x + n_visible < len(pw):
            dis.text(-1, 1, "MORE>", FontTiny)

        dis.show()

        ch = await press.wait()
        if ch == 'y':
            return str(pw, 'ascii')
        elif ch == 'x':
            if len(pw) > 1:
                # delete current char
                pw = pw[0:pos] + pw[pos+1:]
                if pos >= len(pw):
                    pos = len(pw)-1
            else:
                if confirm_exit:
                    pp = await ux_show_story(
                        "OK to leave without any changes? Or X to cancel leaving.")
                    if pp == 'x': continue
                return None

        elif ch == '7':      # left
            pos -= 1
            if pos < 0: pos = 0
        elif ch == '9':      # right
            pos += 1
            if pos >= len(pw):
                if len(pw) < 100 and pw[-3:] != b'   ':
                    pw += ' '       # expand with spaces
                else:
                    pos -= 1        # abort addition

        elif ch == '5':     # up
            change(1)
        elif ch == '8':     # down
            change(-1)
        elif ch == '1':     # alpha
            cycle_set(b'Aa')
        elif ch == '4':     # toggle case
            if (pw[pos] & ~0x20) in range(65, 91):
                pw[pos] ^= 0x20
        elif ch == '2':     # numbers
            cycle_set(numbers)
        elif ch == '3':     # symbols (all of them)
            cycle_set(symbols)
        elif ch == '0':     # help
            help_msg = '''\
Use arrow keys (5789) to select letter and move around. 

1=Letters (Aa..)
2=Numbers (12..)
3=Symbols (!@#&*)
4=Swap Case (q/Q)
X=Delete char

Add more characters by moving past end (right side).'''

            if confirm_exit:
                help_msg += '\nTo quit without changes, delete everything.'
            await ux_show_story(help_msg)

# EOF
