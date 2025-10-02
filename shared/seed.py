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
import ngu, uctypes, bip39, random, version
from ucollections import OrderedDict
from menu import MenuItem, MenuSystem
from utils import xfp2str, parse_extended_key, swab32
from utils import deserialize_secret, problem_file_line, wipe_if_deltamode
from uhashlib import sha256
from ux import ux_show_story, the_ux, ux_dramatic_pause, ux_confirm, OK, X
from ux import PressRelease, ux_input_text, show_qr_code
from actions import goto_top_menu
from stash import SecretStash, SensitiveValues
from ubinascii import hexlify as b2a_hex
from pwsave import PassphraseSaver, PassphraseSaverMenu
from glob import settings, dis
from pincodes import pa
from nvstore import SettingsObject
from files import CardMissingError, needs_microsd
from charcodes import KEY_QR, KEY_ENTER, KEY_CANCEL, KEY_NFC
from uasyncio import sleep_ms
from ucollections import namedtuple

# seed words lengths we support: 24=>256 bits, and recommended
VALID_LENGTHS = (24, 18, 12)

# bit flag that means "also include bare prefix as a valid word"
_PREFIX_MARKER = const(1<<26)

# what we store (in JSON as a tuple) for each seed vault key.
# - 'encoded' is hex, and has is trimmed of right side zeros
VaultEntry = namedtuple('VaultEntry', 'xfp encoded label origin')

def not_hobbled_mode():
    # used as menu predicate and similar
    return not pa.hobbled_mode

def seed_vault_iter():
    # iterate over all seeds in the vault; returns VaultEntry instances.
    # raw vault entries are list type when json.loaded from flash
    for lst in settings.master_get("seeds", []):
        yield VaultEntry(*lst)
    
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

async def commit_new_words(new_words):
    # save the new seed value
    set_seed_value(new_words)

    # clear menu stack
    goto_top_menu(first_time=True)


class WordNestMenu(MenuSystem):
    # singleton (cls level) vars
    words = []
    target_words = None
    has_checksum = True
    done_cb = None

    def __init__(self, num_words=None, has_checksum=True, done_cb=commit_new_words,
                 items=None, is_commit=False, menu_cbf=None, prefix="", words=None):

        if num_words is not None:
            WordNestMenu.target_words = num_words
            WordNestMenu.has_checksum = has_checksum
            WordNestMenu.words = []
            WordNestMenu.done_cb = done_cb
            is_commit = True

        if words:
            WordNestMenu.words = words

        if not items:
            ch = letter_choices(prefix)
            if menu_cbf:
                items = [MenuItem(i, f=menu_cbf) for i in ch]
            else:
                items = [MenuItem(i, menu=self.next_menu)  for i in ch]

        self.is_commit = is_commit

        super(WordNestMenu, self).__init__(items)

    @classmethod
    async def get_n_words(cls, num_words):
        rv = []
        for _ in range(num_words):
            rv = await cls.get_word(rv, num_words)

        return rv

    @classmethod
    async def get_word(cls, words=None, target_words=None):
        # Just block until N words are provided. May only work before menus start?
        from glob import numpad

        async def menu_done_cbf(menu, b, c):
            # duplicates some of the logic of next_menu
            if c.label[-1] == '-':
                lc = c.label[0:-1]
            else:
                cls.words.append(c.label)
                numpad.abort_ux()
                return

            m = cls(prefix=lc, menu_cbf=menu_done_cbf)
            the_ux.push(m)
            await the_ux.interact()

        m = cls(num_words=target_words, menu_cbf=menu_done_cbf, has_checksum=False, words=words)

        the_ux.push(m)
        await the_ux.interact()

        return cls.words

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

        if self.has_checksum and len(words) == (self.target_words - 1):
            # we can provide final choices, but only for 18- and 24-word cases
            # - otherwise, make new menu tree w/ all possible choices (128 total)
            final_words = list(bip39.a2b_words_guess(words))

            async def picks_chk_word(s, idx, choice):
                # they picked final word, the word includes valid checksum bits
                words.append(choice.label)
                await cls.done_cb(words.copy())

            if len(final_words) <= 32:
                # 18 or 24 word cases => 32 or 8 choices are valid
                items = [MenuItem(w, f=picks_chk_word) for w in final_words]
                items.append(MenuItem('(none above)', f=self.explain_error))
                return cls(is_commit=True, items=items)

            # 12 words => 128 valid final words
            # show start letter and under that valid words
            d = OrderedDict()
            for w in final_words:
                if w[0] not in d:
                    d[w[0]] = []
                d[w[0]].append(w)

            items = []
            for s, w_lst in sorted(d.items()):
                sub_items = [MenuItem(w, f=picks_chk_word) for w in w_lst]
                sub_items.append(MenuItem('(none above)', f=self.explain_error))
                items.append(MenuItem(s+"-", menu=cls(items=sub_items)))

            return cls(is_commit=True, items=items)

        if len(words) == self.target_words:
            return await cls.done_cb(words.copy())

        # pop stack to reset depth, and start again at a- .. z-
        cls.pop_all()
        return cls(items=None, is_commit=True)

    @classmethod
    def pop_all(cls):
        while isinstance(the_ux.top_of_stack(), cls):
            the_ux.pop()

    async def on_cancel(self):
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
        if dis.has_lcd: return      # unreachable anyway?

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
    from ux import ux_render_words
    from glob import NFC

    if prompt:
        title = None
        msg = prompt
    else:
        m = 'Record these %d secret words!' % len(words)
        title, msg = (m, "") if version.has_qwerty else (None, m+"\n")

    msg += ux_render_words(words)

    msg += '\n\nPlease check and double check your notes.'
    if not ephemeral:
        # user can skip quiz for ephemeral secrets
        msg += " There will be a test!"

    escape = (escape or '') + '1'
    if not version.has_qwerty:
        title = None
        extra += 'Press (1) to view as QR Code'
        if NFC:
            extra += ", (3) to share via NFC"
            escape += "3"
        extra += "."

    if extra:
        msg += '\n\n'
        msg += extra

    while 1:
        rv = ' '.join(w[0:4] for w in words)
        ch = await ux_show_story(msg, title=title, escape=escape, sensitive=True,
                                 hint_icons=KEY_QR+(KEY_NFC if NFC else ''))
        if ch in ('1'+KEY_QR):
            await show_qr_code(rv, True, is_secret=True)
            continue
        if NFC and (ch in "3"+KEY_NFC):
            await NFC.share_text(rv, is_secret=True)
            continue

        break

    return ch


async def add_dice_rolls(count, seed, judge_them, nwords=None, enforce=False):
    from ux import ux_dice_rolling

    low_entropy_msg = "You only provided %d dice rolls, and each roll adds only 2.585 bits of entropy."
    low_entropy_msg += " For %d-bit security"
    if nwords is not None:
        # do not add this if we generate private key in paper wallets
        low_entropy_msg += ", which is considered the minimum for %d word seeds," % nwords
    low_entropy_msg += " you need at least %d rolls."

    # None is for papaer wallet private key - as it is 32 bytes of entropy we need 99 D6
    if nwords in (24, None):
        threshold = 99
        sec_bit = 256
    else:
        threshold = 50
        sec_bit = 128

    counter = {}
    md = sha256(seed)
    pr = PressRelease()

    # draws initial screen, and returns funct to update count and/or hash
    screen_updater = ux_dice_rolling()
    redraw = False
    while 1:
        if redraw:
            # redraw basic dice screen after different story was shown
            screen_updater = ux_dice_rolling()

        # Note: cannot scroll this msg because 5=up arrow
        hx = str(b2a_hex(md.digest()), 'ascii')
        screen_updater(count, hx)

        ch = await pr.wait()

        if ch in '123456':
            count += 1
            counter[ch] = counter.get(ch, 0) + 1  # mimics defaultdict

            # show udpated count immediately
            screen_updater(count, None)

            # this is slow enough to see
            md.update(ch)

        elif ch in KEY_CANCEL+"x":
            # Because the change (roll) has already been applied,
            # only let them abort if it's early still
            if count < 10 and judge_them:
                return 0, seed
        elif ch in KEY_ENTER+"y":
            if count < threshold and judge_them:
                if not count:
                    return 0, seed

                story = low_entropy_msg % (count, sec_bit, threshold)
                if enforce:
                    ch = await ux_show_story("Not enough dice rolls!!!\n\n" + story +
                                             "\n\nPress %s to add more dice rolls. %s to exit" % (OK, X))
                    if ch == "y":
                        redraw = True
                        continue
                    else:
                        return 0, seed
                else:
                    ok = await ux_confirm(story)
                    if not ok:
                        redraw = True
                        continue

            if judge_them:
                bad_dist = any((v / count) > 0.30 for _, v in counter.items())
                if bad_dist:
                    bad_dist_msg = ("Distribution of dice rolls is not random. "
                                    "Some numbers occurred more than 30% of the time.")
                    if enforce:
                        await ux_show_story(bad_dist_msg)
                        return 0, seed  # exit
                    else:
                        ok = await ux_confirm(bad_dist_msg)
                        if not ok:
                            redraw = True
                            continue
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

    count, seed = await add_dice_rolls(count, seed, True, nwords, enforce=True)
    if count == 0: return

    words = await approve_word_list(seed, nwords)
    if words:
        await commit_new_words(words)

def in_seed_vault(encoded):
    # Test if indicated secret is in the seed vault already.
    hss = None
    for rec in seed_vault_iter():
        if not hss:
            hss = SecretStash.storage_serialize(encoded)
        if hss == rec.encoded:
            return True

    return False

async def add_seed_to_vault(encoded, origin=None, label=None):

    if not settings.master_get("seedvault", False):
        # seed vault disabled
        # this can be re-enabled by attacker in deltamode
        return
    if pa.is_secret_blank() or pa.is_deltamode():
        # do not save anything if no SE secret yet
        # do not offer any access to SV in deltamode
        return

    # do not offer to store secrets that are already in vault
    if in_seed_vault(encoded):
        return

    # stay "read only" in hobbled mode
    if pa.hobbled_mode:
        return

    main_xfp = settings.master_get("xfp", 0)

    # parse encoded
    _,_,node = SecretStash.decode(encoded)
    new_xfp = swab32(node.my_fp())
    new_xfp_str = xfp2str(new_xfp)

    # do not offer to store main seed
    if new_xfp == main_xfp:
        return

    seeds = settings.master_get("seeds", [])

    xfp_ui = "[%s]" % new_xfp_str
    story = ("Press (1) to "
             "store temporary seed into Seed Vault. This way you can easily switch "
             "to this secret and use it as temporary seed in future.\n\nPress %s "
             "to continue without saving." % OK)

    ch = await ux_show_story(story, escape="1")
    if ch != "1":
        # didn't want to save
        return

    # Save it into master settings
    rec = VaultEntry(xfp=new_xfp_str, encoded=SecretStash.storage_serialize(encoded),
                            label=(label or xfp_ui), origin=origin)
    seeds.append(list(rec))

    settings.master_set("seeds", seeds)

    await ux_show_story(xfp_ui + "\nSaved to Seed Vault")

    return True

async def set_ephemeral_seed(encoded, chain=None, summarize_ux=True, bip39pw='',
                             is_restore=False, origin=None, label=None):
    # Capture tmp seed into vault, if so enabled, and regardless apply it as new tmp.
    if not is_restore and not_hobbled_mode():
        await add_seed_to_vault(encoded, origin=origin, label=label)
        dis.fullscreen("Wait...")

    applied, err_msg = pa.tmp_secret(encoded, chain=chain, bip39pw=bip39pw)

    dis.progress_bar_show(1)

    if not applied:
        await ux_show_story(title="FAILED", msg=err_msg)
        return

    xfp = "[" + xfp2str(settings.get("xfp", 0)) + "]"
    if summarize_ux:
        await ux_show_story(title=xfp, msg="New temporary master key is in effect now.")

    return applied

async def set_ephemeral_seed_words(words, origin):
    dis.progress_bar_show(0.1)
    encoded = seed_words_to_encoded_secret(words)
    dis.progress_bar_show(0.5)
    await set_ephemeral_seed(encoded, origin=origin)
    goto_top_menu()

async def ephemeral_seed_generate_from_dice(nwords):
    # Use lots of (D6) dice rolls to create seed entropy.
    # Note: only 2.585 bits of entropy per roll, so need lots!
    # 50 => 128bits, 99 => 256bits

    seed = b''
    count = 0

    count, seed = await add_dice_rolls(count, seed, True, nwords)
    if count == 0: return

    words = await approve_word_list(seed, nwords, ephemeral=True)
    if words:
        dis.fullscreen("Applying...")
        await set_ephemeral_seed_words(words, origin='Dice')

def generate_seed():
    # Generate 32 bytes of best-quality high entropy TRNG bytes.

    seed = ngu.random.bytes(32)
    assert len(set(seed)) > 4       # TRNG failure

    # hash to mitigate any possible bias in TRNG
    return ngu.hash.sha256d(seed)

async def make_new_wallet(nwords):
    # Pick a new random seed.
    await ux_dramatic_pause('Generating...', 3)
    seed = generate_seed()
    words = await approve_word_list(seed, nwords)
    if words:
        await commit_new_words(words)


async def ephemeral_seed_import(nwords):
    async def import_done_cb(words):
        dis.fullscreen("Applying...")
        await set_ephemeral_seed_words(words, origin='Imported')

    if version.has_qwerty:
        from ux_q1 import seed_word_entry
        await seed_word_entry('Ephemeral Seed Words', nwords, done_cb=import_done_cb)
    else:
        return WordNestMenu(nwords, done_cb=import_done_cb)

async def ephemeral_seed_generate(nwords):
    await ux_dramatic_pause('Generating...', 3)
    seed = generate_seed()
    words = await approve_word_list(seed, nwords, ephemeral=True)
    if words:
        dis.fullscreen("Applying...")
        await set_ephemeral_seed_words(words, origin="TRNG Words")

async def set_seed_extended_key(extended_key):
    encoded, chain = xprv_to_encoded_secret(extended_key)
    set_seed_value(encoded=encoded, chain=chain)
    goto_top_menu(first_time=True)

async def set_ephemeral_seed_extended_key(extended_key, origin=None):
    encoded, chain = xprv_to_encoded_secret(extended_key)
    dis.fullscreen("Applying...")
    await set_ephemeral_seed(encoded=encoded, chain=chain, origin=origin)
    goto_top_menu()

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
            if await ux_confirm("Throw away those words and stop this process? "
                                "Press %s to see the word list again and restart the quiz." % X):
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

def xprv_to_encoded_secret(xprv):
    node, chain, _ = parse_extended_key(xprv, private=True)
    if node is None:
        raise ValueError("Failed to parse extended private key.")
    nv = SecretStash.encode(xprv=node)
    node.blank()
    return nv, chain  # need to know chain


def set_seed_value(words=None, encoded=None, chain=None):
    # Save the seed words (or other encoded private key) into secure element.
    # BIP-39 passphrase is not set at this point (empty string).
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
        pa.new_main_secret(nv, chain=chain)

        # check and reload secret
        pa.reset()
        pa.login()
    finally:
        dis.busy_bar(False)


async def calc_bip39_passphrase(pw, bypass_tmp=False):
    from glob import dis, settings

    dis.fullscreen("Working...")

    current_xfp = settings.get("xfp", 0)

    with SensitiveValues(bip39pw=pw, bypass_tmp=bypass_tmp) as sv:
        # can't do it without original seed words (late, but caller has checked)
        assert sv.mode == 'words', sv.mode
        nv = SecretStash.encode(xprv=sv.node)
        xfp = swab32(sv.node.my_fp())

    return nv, xfp, current_xfp

async def set_bip39_passphrase(pw, bypass_tmp=False, summarize_ux=True):
    nv, xfp, parent_xfp = await calc_bip39_passphrase(pw, bypass_tmp=bypass_tmp)
    ret = await set_ephemeral_seed(nv, summarize_ux=summarize_ux, bip39pw=pw,
                                   origin="BIP-39 Passphrase on [%s]" % xfp2str(parent_xfp))
    dis.draw_status(bip39=int(bool(pw)), xfp=xfp, tmp=1)
    return ret

    # Might need to bounce the USB connection, because our pubkey has changed,
    # altho if they have already picked a shared session key, no need, and
    # would only affect MitM test, which has already been done.

async def remember_ephemeral_seed():
    # Compute current xprv and switch to using that as root secret.
    from nvstore import SettingsObject
    from glob import dis

    # we are already at temporary seed, with correct
    # settings in use - no need to call new_main_secret
    # at the end

    # locking down temporary as new master
    # old master settings are destroyed
    dis.fullscreen("Cleanup...")
    assert pa.tmp_value, "no tmp"
    assert SettingsObject.master_nvram_key, "master nvram k"
    old_master = SettingsObject(SettingsObject.master_nvram_key)
    old_master.load()
    old_master.blank()
    del old_master

    # address cache, settings from tmp seeds / seedvault seeds
    # rebuild fs as we want to save current tmp settings immediately
    from files import wipe_flash_filesystem
    wipe_flash_filesystem()

    dis.draw_status(bip39=0, tmp=0)
    dis.fullscreen('Saving...')
    pa.change(new_secret=pa.tmp_value, tmp_lockdown=True)

    # not needed - will be handled by reboot
    SettingsObject.master_nvram_key = None
    SettingsObject.master_sv_data = {}

    # check and reload secret
    pa.reset()
    pa.login()

async def restore_to_main_secret(preserve_settings=False):
    # go back to main se2 secret
    pa.new_main_secret(raw_secret=None, blank=not preserve_settings)

def clear_seed():
    from glob import dis
    import utime, callgate

    dis.fullscreen('Clearing...')
    dis.busy_bar(True)

    # clear settings associated with this key, since it will be no more
    settings.blank()

    callgate.fast_wipe(True)
    # NOT REACHED

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

            msg = '' if not dis.has_lcd else '\n'

            msg += '\n'.join(' %d: %s' % (i+1, choices[i]) for i in range(3))
            msg += '\n\nWhich word is right?\n\n%s to give up, %s to see all the words again.' % (X, OK)

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

async def make_seed_vault_menu(*a):
    rv = SeedVaultMenu.construct()
    return SeedVaultMenu(rv)

class SeedVaultMenu(MenuSystem):

    @staticmethod
    async def _set(menu, label, item):
        from glob import dis
        dis.fullscreen("Applying...")

        encoded = item.arg          # 72 bytes binary

        await set_ephemeral_seed(encoded, is_restore=True)

        goto_top_menu()

    @staticmethod
    async def _remove(menu, label, item):
        from glob import dis, settings

        esc = ""
        tmp_val = False
        idx, rec, encoded = item.arg
        current_active = (pa.tmp_value == bytes(encoded))

        msg = "Remove seed from seed vault"
        if pa.tmp_value and current_active:
            tmp_val = True
            msg += "?\n\n"
        else:
            msg += (" and delete its settings?\n\n"
                    "Press %s to continue, press (1) to "
                    "only remove from seed vault and keep "
                    "encrypted settings for later use.\n\n") % OK
            esc += "1"

        msg += "WARNING: Funds will be lost if wallet is not backed-up elsewhere."

        ch = await ux_show_story(title="[" + rec.xfp + "]", msg=msg, escape=esc)
        if ch == "x": return

        assert not_hobbled_mode()

        dis.fullscreen("Saving...")

        wipe_slot = not current_active and (ch != "1")

        if wipe_slot:
            xs = SettingsObject()
            xs.set_key(encoded)
            xs.load()
            xs.blank()
            del xs


        # CAUTION: will get shadow copy if in tmp seed mode already
        seeds = settings.master_get("seeds", [])
        try:
            del seeds[idx]
        except IndexError:
            pass

        # need to load and work on master secrets, will be slow if on tmp seed
        settings.master_set("seeds", seeds)

        if tmp_val and wipe_slot:
            goto_top_menu()

        # pop menu stack
        the_ux.pop()
        m = the_ux.top_of_stack()
        m.update_contents()

    @staticmethod
    async def _detail(menu, label, item):
        rec, encoded = item.arg

        # - first byte represents type of secret (internal encoding flags)
        txt = SecretStash.summary(encoded[0])

        detail = "Name:\n%s\n\nMaster XFP: %s\nSecret Type: %s\n\nOrigin:\n%s\n\n" \
                        % (rec.label, rec.xfp, txt, rec.origin)

        await ux_show_story(detail)

    @staticmethod
    async def _rename(menu, label, item):
        # let them edit the name
        from glob import dis
        from ux import ux_input_text

        assert not_hobbled_mode()

        idx, old = item.arg
        new_label = await ux_input_text(old.label, confirm_exit=False, max_len=40)

        if not new_label:
            return

        dis.fullscreen("Saving...")
        seeds = settings.master_get("seeds", [])

        # save it
        seeds[idx] = (old.xfp, old.encoded, new_label, old.origin)
        # need to load and work on master secrets, will be slow if on tmp seed
        settings.master_set("seeds", seeds)

        # update label in sub-menu
        menu.items[0].label = new_label
        # take old arg, in rename we cannot change encoded value, so it can be used without
        # the need to deserialize it again
        _, encoded = menu.items[0].arg
        menu.items[0].arg = VaultEntry(*seeds[idx]), encoded

        # and name in parent menu too
        parent = the_ux.parent_of(menu)
        if parent:
            parent.update_contents()

    @staticmethod
    async def _add_current_tmp(*a):
        from pincodes import pa

        assert not_hobbled_mode()

        assert pa.tmp_value
        main_xfp = settings.master_get("xfp", 0)

        new_xfp = settings.get("xfp", 0)
        new_xfp_str = xfp2str(new_xfp)

        # do not offer to store main seed
        if new_xfp == main_xfp:
            return

        xfp_ui = "[%s]" % new_xfp_str

        ch = await ux_show_story(title=xfp_ui, msg="Add to Seed Vault?")
        if ch != "y":
            return

        seeds = settings.master_get("seeds", [])

        # Save it into master settings
        seeds.append(list(VaultEntry(new_xfp_str,
                      SecretStash.storage_serialize(pa.tmp_value),
                      xfp_ui, "unknown origin")))

        settings.master_set("seeds", seeds)

        await ux_show_story(xfp_ui + "\nSaved to Seed Vault")

        m = the_ux.top_of_stack()
        m.update_contents()

    @classmethod
    def construct(cls):
        # Dynamic menu with user-defined names of seeds shown
        from pincodes import pa

        rv = []
        add_current_tmp = MenuItem("Add current tmp", f=cls._add_current_tmp)

        seeds = list(seed_vault_iter())

        if not seeds:
            rv.append(MenuItem('(none saved yet)'))
            if not_hobbled_mode():
                if pa.tmp_value:
                    rv.append(add_current_tmp)
                rv.append(MenuItem("Temporary Seed", menu=make_ephemeral_seed_menu))
        else:
            wipe_if_deltamode()

            tmp_in_sv = False
            for i, rec in enumerate(seeds):
                is_active = False

                # de-serialize encoded secret
                encoded = deserialize_secret(rec.encoded)
                if encoded == pa.tmp_value:
                    is_active = tmp_in_sv = True

                submenu = [
                    MenuItem(rec.label, f=cls._detail, arg=(rec, encoded)),
                    MenuItem('Use This Seed', f=cls._set, arg=encoded),
                    MenuItem('Rename', f=cls._rename, arg=(i, rec),
                             predicate=not_hobbled_mode),
                    MenuItem('Delete', f=cls._remove, arg=(i, rec, encoded),
                             predicate=not_hobbled_mode),
                ]
                if is_active:
                    submenu[1] = MenuItem("Seed In Use")
                    submenu[1].is_chosen = lambda: True

                if pa.tmp_value and (not is_active):
                    # if different ephemeral wallet active
                    # DO NOT offer any modification api (rename/delete)
                    submenu = submenu[:2]

                item = MenuItem('%2d: %s' % (i+1, rec.label), menu=MenuSystem(submenu))
                if is_active:
                    item.is_chosen = lambda: True

                rv.append(item)

            if pa.tmp_value:
                if seeds and (not tmp_in_sv) and not_hobbled_mode():
                    # give em chance to store current active
                    rv.append(add_current_tmp)

                from actions import restore_main_secret
                rv.append(MenuItem("Restore Master", f=restore_main_secret))

        return rv

    def update_contents(self):
        # Reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)

class SeedVaultChooserMenu(MenuSystem):
    def __init__(self, words_only=False):
        self.result = None

        items = []
        for i, rec in enumerate(seed_vault_iter()):
            if words_only and not SecretStash.is_words(deserialize_secret(rec.encoded)):
                continue

            item = MenuItem('%2d: %s' % (i+1, rec.label), arg=rec, f=self.picked)
            items.append(item)

        if not items:
            items.append(MenuItem("(none suitable)"))

        super().__init__(items)

    async def picked(self, menu, idx, mi):
        assert menu == self

        # show as "checked", for a touch
        menu.chosen = idx
        menu.show()
        await sleep_ms(100)

        self.result = mi.arg
        the_ux.pop()            # causes interact to stop

    @classmethod
    async def pick(cls, **kws):
        # nice simple blocking menu present and pick
        m = cls(**kws)

        the_ux.push(m)
        await m.interact()

        return m.result

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
        from glob import NFC
        from actions import nfc_recv_ephemeral, import_xprv
        from actions import restore_backup, scan_any_qr
        from tapsigner import import_tapsigner_backup_file
        from xor_seed import xor_restore_start
        from charcodes import KEY_QR

        import_ephemeral_menu = [
            MenuItem("12 Words", f=cls.ephemeral_seed_import, arg=12),
            MenuItem("18 Words", f=cls.ephemeral_seed_import, arg=18),
            MenuItem("24 Words", f=cls.ephemeral_seed_import, arg=24),
            MenuItem("Import via NFC", f=nfc_recv_ephemeral, predicate=bool(NFC)),
        ]
        gen_ephemeral_menu = [
            MenuItem("12 Words", f=cls.ephemeral_seed_generate, arg=12),
            MenuItem("24 Words", f=cls.ephemeral_seed_generate, arg=24),
            MenuItem("12 Word Dice Roll", f=cls.ephemeral_seed_generate_from_dice, arg=12),
            MenuItem("24 Word Dice Roll", f=cls.ephemeral_seed_generate_from_dice, arg=24),
        ]

        rv = [
            MenuItem("Generate Words", menu=gen_ephemeral_menu, predicate=not_hobbled_mode),
            MenuItem('Import from QR Scan', predicate=version.has_qr,
                     shortcut=KEY_QR, f=scan_any_qr, arg=(True, True)),
            MenuItem("Import Words", menu=import_ephemeral_menu),
            MenuItem("Import XPRV", f=import_xprv, arg=True),  # ephemeral=True
            MenuItem("Tapsigner Backup", f=import_tapsigner_backup_file, arg=True), # ephemeral=True
            MenuItem("Coldcard Backup", f=restore_backup, arg=True),  # tmp=True
            MenuItem("Restore Seed XOR", f=xor_restore_start),
        ]

        return rv


async def make_ephemeral_seed_menu(*a):

    if (not pa.tmp_value) and (not settings.master_get("seedvault", False)):
        # force a warning on them, unless they are already doing it.
        if not await ux_confirm(
            "Temporary seed is a secret completely separate "
            "from the master seed, typically held in device RAM and "
            "not persisted between reboots in the Secure Element. "
            "Enable the Seed Vault feature to store these secrets longer-term.",
            title="WARNING",
            confirm_key="4"
        ):
            return

    rv = EphemeralSeedMenu.construct()
    return EphemeralSeedMenu(rv)

async def start_b39_pw(menu, label, item):
    # Menu item for top-level "Passphrase" item - take in a BIP-39 passphrase

    if not settings.get('b39skip', False):
        howto = '''\n\n\
On the next menu, you can enter a passphrase by selecting \
individual letters, choosing from the word list (recommended), \
or by typing numbers.'''

        msg = '''\
You may add a passphrase to your BIP-39 seed words. \
This creates an entirely new wallet, for every possible passphrase.

By default, the Coldcard uses an empty string as the passphrase.\
%s\

Please write down the fingerprint of all your wallets, so you can \
confirm when you've got the right passphrase. (If you are writing down \
the passphrase as well, it's okay to put them together.) There is no way for \
the Coldcard to know if your entry is correct, and if you have it wrong, \
you will be looking at an empty wallet.

Limitations: 100 characters max length, ASCII characters 32-126 (0x20-0x7e) only.

%s to continue or press (2) to hide this message forever.
''' % (howto if not version.has_qwerty else '', OK)

        ch = await ux_show_story(msg, escape='2')
        if ch == '2':
            settings.set('b39skip', True)
        if ch == 'x':
            return

    if version.has_qwerty and not PassphraseSaver.has_file():
        # no need for any menus if Q and no card present
        pp = await ux_input_text('', prompt="Your BIP-39 Passphrase",
                                 b39_complete=True, scan_ok=True, max_len=100)
        if not pp: return
        
        await apply_pass_value(pp)
    else:
        # provide a menu, especially on Mk4 where it offers a number of input methods
        return PassphraseMenu()


class PassphraseMenu(MenuSystem):
    # Collect up to 100 chars as a BIP-39 passphrase

    # singleton (cls level) vars
    done_cb = None
    pp_sofar = ''

    def __init__(self):
        items = self.construct()
        super(PassphraseMenu, self).__init__(items)

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    def construct(self):
        if version.has_qwerty:
            items = [
                MenuItem('Edit Phrase', f=self.view_edit_phrase, shortcut=KEY_QR),
            ]
        else:
            items = [
                #         xxxxxxxxxxxxxxxx
                MenuItem('Edit Phrase', f=self.view_edit_phrase),
                MenuItem('Add Word', menu=self.word_menu),
                MenuItem('Add Numbers', f=self.add_numbers),
                MenuItem('Clear All', f=self.empty_phrase),
                MenuItem('APPLY', f=self.done_apply),
                MenuItem('CANCEL', f=self.done_cancel),
            ]

        # show Restore option only if required 'hidden' file is present (doesn't read it)
        if PassphraseSaver.has_file():
            items.insert(0, MenuItem('Restore Saved', menu=self.restore_saved))

        return items

    @staticmethod
    async def restore_saved(*a):
        dis.fullscreen("Decrypting...")
        try:
            items = PassphraseSaverMenu.construct()
        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story(title="Failure", msg=str(e) + problem_file_line(e))
            return

        if not items:
            await ux_show_story("Nothing found")
            return

        return PassphraseSaverMenu(items)

    async def on_cancel(self):
        if not version.has_qwerty:
            # zip to cancel item when they fail to exit via X button
            self.goto_idx(self.count - 1)
        else:
            # for Q, just be a normal menu you can exit (but pop() didnt work here?)
            the_ux.pop()

    async def word_menu(self, *a):
        # mk4: add a single word from the wordlist, maybe with space, various capitalizations
        return SingleWordMenu()

    @classmethod
    async def add_numbers(cls, *a):
        # Mk4 only: add some digits (quick, easy)
        from ux_mk4 import ux_input_digits

        pw = await ux_input_digits(cls.pp_sofar)
        if pw is not None:
            cls.pp_sofar = pw
            cls.check_length()

    @classmethod
    async def empty_phrase(cls, *a):
        if len(cls.pp_sofar) >= 3:
            if not await ux_confirm("Press %s to clear passphrase." % OK):
                return

        cls.pp_sofar = ''
        await ux_dramatic_pause('Cleared...', 0.25)

    @classmethod
    async def view_edit_phrase(cls, *a):
        # let them control each character
        pw = await ux_input_text(cls.pp_sofar, prompt="Your BIP-39 Passphrase",
                                 b39_complete=True, scan_ok=True, max_len=100)
        if pw is not None:
            cls.pp_sofar = pw
            cls.check_length()

            if version.has_qwerty and cls.pp_sofar:
                await apply_pass_value(cls.pp_sofar)
                cls.pp_sofar = ''

    @classmethod
    def check_length(cls):
        # enforce a limit of 100 chars
        cls.pp_sofar = cls.pp_sofar[0:100]

    @classmethod
    async def add_text(cls, _1, _2, item):
        cls.pp_sofar += item.label
        cls.check_length()

        while not isinstance(the_ux.top_of_stack(), PassphraseMenu):
            the_ux.pop()

    @classmethod
    async def done_cancel(cls, *a):
        if len(cls.pp_sofar) > 3:
            if not await ux_confirm("What you have entered will be forgotten."):
                return

        cls.pp_sofar = ''
        goto_top_menu()

    @classmethod
    async def done_apply(cls, *a):
        # apply the passphrase
        if not cls.pp_sofar:
            # empty string here - noop
            return

        await apply_pass_value(cls.pp_sofar)
        cls.pp_sofar = ''

async def apply_pass_value(new_pp):
    # Apply provided BIP-39 passphrase to master or current active tmp seed
    # and go to top menu.
    nv, xfp, parent_xfp = await calc_bip39_passphrase(new_pp)
    xfp_str = xfp2str(xfp)
    parent_xfp_str = xfp2str(parent_xfp)

    msg = "current active temporary seed [%s]" if pa.tmp_value else "master seed [%s]"
    msg = msg % parent_xfp_str

    msg = ('Above is the master key fingerprint of the new wallet'
           ' created by adding passphrase to %s.'
           '\n\nPress %s to abort, %s to use the new wallet, (1) to apply'
           ' and save to MicroSD for future.') % (msg, X, OK)

    ch = await ux_show_story(msg, title="[%s]" % xfp_str, escape='1')
    if ch == 'x':
        return

    await set_ephemeral_seed(nv, summarize_ux=False, bip39pw=new_pp,
                             origin="BIP-39 Passphrase on [%s]" % parent_xfp_str)

    if ch == '1':
        try:
            await PassphraseSaver().append(xfp, new_pp)
        except CardMissingError:
            await needs_microsd()
        except Exception as e:
            await ux_show_story(
                title="ERROR",
                msg='Save failed!\n\n%s\n%s' % (e, problem_file_line(e))
            )

    goto_top_menu()

class SingleWordMenu(WordNestMenu):
    # NOTE: not used on Q1
    def __init__(self, items=None, **kws):
        if items:
            super(SingleWordMenu, self).__init__(items=items, **kws)
        else:
            super(SingleWordMenu, self).__init__(num_words=1, has_checksum=False,
                                                 done_cb=self.commit_value)

    @staticmethod
    async def commit_value(new_words):
        # create one more menu w/ the word and some variations on that word
        word = new_words[0]
        options = [word, word[0].upper() + word[1:], word.upper()]
        for w in options[:]:
            options.append(' ' + w)

        # bugfix: in case they cancel from new menu
        WordNestMenu.words = []

        return MenuSystem([MenuItem(w, f=PassphraseMenu.add_text)
                                    for n,w in enumerate(options)], space_indicators=True)


# EOF
