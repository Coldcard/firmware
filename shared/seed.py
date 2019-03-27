# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
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
from utils import pop_count
import tcc, uctypes
from ux import ux_show_story, the_ux, ux_dramatic_pause, ux_confirm
from pincodes import AE_SECRET_LEN
from actions import goto_top_menu
from stash import SecretStash, SensitiveValues
from ckcc import rng_bytes
from random import rng, shuffle

# seed words lengths we support: 24=>256 bits, and recommended
VALID_LENGTHS = (24, 18, 12)

# bit flag that means "also include bare prefix as a valid word"
_PREFIX_MARKER = const(1<<26)

def extend_word(w):
    # try to add as many non-abiguous chars onto end,
    # and append - if we had to stop before we got to final end
    while 1:
        bitmask = tcc.bip39.complete_word(w)

        if bitmask == 0 or bitmask == _PREFIX_MARKER:
            return w

        if pop_count(bitmask) != 1:
            return w+'-'

        for n in range(26):
            msk = 1<<n
            if (msk & bitmask):
                w += chr(97+n)
                break
    
def letter_choices(sofar='', depth=0, thres=5):
    # make a list of word completions based on indicated prefix
    if not sofar:
        # all letters:
        # - except 'x' which isn't used in the wordlist.
        # - and q- which is really qu-, because English.
        return [('%s-' % chr(97+i)) if i != 16 else 'qu-'  for i in range(26) if i != 23]

    bitmask = tcc.bip39.complete_word(sofar)

    if not bitmask:
        # no more choices; done
        return [sofar]

    rv = []
    if bitmask & _PREFIX_MARKER:
        # ie: "act" plus "action", "actor"
        rv.append(sofar)

    for w in (sofar+chr(i+97) for i in range(0, 26) if (bitmask & (1<<i))):
        rv.append(extend_word(w))

    if len(rv) <= thres and depth == 0:
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

        if choice.label[-1] == '-':
            ch = letter_choices(choice.label[0:-1])

            return WordNestMenu(items=[MenuItem(i, menu=self.next_menu) for i in ch])

        # terminal choice, start next word
        words.append(choice.label)

        #print(("words[%d]: " % len(words)) + ' '.join(words))
        assert len(words) <= self.target_words

        # add a few top-items in certain cases
        if len(words) == self.target_words:
            if self.has_checksum:
                correct = tcc.bip39.check(' '.join(words))
            else:
                correct = True

            # they have checksum right, so they are certainly done.
            if correct:
                # they are done, don't force them to do any more!
                await WordNestMenu.done_cb(words.copy())
                return None
            else:
                # give them a chance to confirm and/or start over
                return WordNestMenu(is_commit=True, items = [
                            MenuItem('(INCORRECT)', f=self.explain_error),
                            MenuItem('(start over)', f=self.start_over)])


        # pop stack to reset depth, and start again at a- .. z-
        WordNestMenu.pop_all()

        return WordNestMenu(items=None, is_commit=True)

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
            print('cancel commit')
            words.pop()

            # replace the menu we are show w/ top-level (a-) menu
            the_ux.pop()
            nxt = WordNestMenu(is_commit=True)
            the_ux.push(nxt)
        else:
            print('normal cancel')
            the_ux.pop()

        print(("after cancel[%d]: " % len(words)) + ' '.join(words))

    @staticmethod
    async def all_done(new_words):
        # save the new seed value
        set_seed_value(new_words)
        
        # clear menu stack
        goto_top_menu()

    async def explain_error(self, *a):

        await ux_show_story('''\
You've got a mistake in your words. We know because the checksum does not \
verify. It's probably best to start over again, but you can back out \
individual words if you wish.''')

    async def start_over(self, *a):

        # pop everything we've done off the stack
        WordNestMenu.pop_all()

        # begin again, empty but same settings
        WordNestMenu.words = []
        the_ux.push(WordNestMenu(items=None))

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
        dis.text(-18-(6 if count >= 10 else 0), y, "Word", FontTiny, invert=invert)


async def show_words(words, prompt=None, escape=None):
    msg = (prompt or 'Record these %d secret words!\n') % len(words)
    msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))
    msg += '\n\nPlease check and double check your notes. There will be a test! ' 

    return await ux_show_story(msg, escape=escape)

async def make_new_wallet():
    # pick a new random seed, and force them to 
    # write it down, then save it.

    from main import dis
    from uasyncio import sleep_ms

    # CONCERN: memory is really contaminated with secrets in this process, much more so
    # than during normal operation. Maybe we should block USB and force a reboot as well?

    # LESSON LEARNED: if the user is writting down the words, as we have
    # vividly instructed, then it's a big deal to lose those words and have to start
    # over. So confirm that action, and don't volunteer it.

    # dramatic pause
    await ux_dramatic_pause('Generating...', 4)

    # always full 24-word (256 bit) entropy
    seed = bytearray(32)
    rng_bytes(seed)

    assert len(set(seed)) > 4, "impossible luck?"

    # hash to mitigate bias in TRNG
    seed = tcc.sha256(seed).digest()

    words = tcc.bip39.from_data(seed).split(' ')
    assert len(words) == 24
    
    #print('words: ' + ' '.join(words))

    while 1:
        # show the seed words
        ch = await show_words(words, escape='6')

        if ch == 'x': 
            # user abort
            if await ux_confirm("Throw away those words and stop this process?"):
                return
            else:
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

    # Done!
    set_seed_value(words)

    # send them to home menu, now with a wallet enabled
    goto_top_menu()
                

def set_seed_value(words):
    # Save the seed words into secure element, and reboot. BIP39 password
    # is not set at this point (empty string)
    ok = tcc.bip39.check(' '.join(words))
    assert ok, "seed check: %r" % words

    # map words to bip39 wordlist indices
    data = [tcc.bip39.lookup_word(w) for w in words]

    # map to packed binary representation.
    val = 0
    for v in data:
        val <<= 11
        val |= v

    # remove the checksum part
    vlen = (len(words) * 4) // 3
    val >>= (len(words) // 3)

    # convert to bytes
    seed = val.to_bytes(vlen, 'big')
    assert len(seed) == vlen
    
    from main import dis, pa, settings

    # encode it for our limited secret space
    nv = SecretStash.encode(seed_phrase=seed)

    dis.fullscreen('Applying...')
    pa.change(new_secret=nv)

    # re-read settings since key is now different
    # - also captures xfp, xpub at this point
    pa.new_main_secret(nv)

    # check and reload secret
    pa.reset()
    pa.login()

def set_bip39_passphrase(pw):
    # apply bip39 passphrase for now (volatile)
    import stash

    stash.bip39_passphrase = pw

    with stash.SensitiveValues() as sv:
        if sv.mode != 'words':
            # can't do it without original seed woods
            return 'No BIP39 seed words'

        sv.capture_xpub()

    # Might need to bounce the USB connection, because our pubkey has changed,
    # altho if they have already picked a shared session key, no need, and
    # only affects MitM testing.

async def remember_bip39_passphrase():
    # Compute current xprv and switch to using that as root secret.
    import stash
    from main import dis, pa

    if not stash.bip39_passphrase:
        if not await ux_confirm('''You do not have a BIP39 passphrase set right now, so this command does little except forget the seed words. It does not enhance security.'''):
            return

    dis.fullscreen('Check...')

    with stash.SensitiveValues() as sv:
        if sv.mode != 'words':
            # not a BIP39 derived secret, so cannot work.
            await ux_show_story('''The wallet secret was not based on a seed phrase, so we cannot add a BIP39 passphrase at this time.''', title='Failed')
            return

        nv = SecretStash.encode(xprv=sv.node)
    
    dis.fullscreen('Saving...')
    pa.change(new_secret=nv)

    # re-read settings since key is now different
    # - also captures xfp, xpub at this point
    pa.new_main_secret(nv)

    # check and reload secret
    pa.reset()
    pa.login()

def clear_seed():
    from main import dis, pa, settings
    import utime

    dis.fullscreen('Clearing...')

    # clear settings associated with this key, since it will be no more
    settings.blank()

    # save a blank secret (all zeros is a special case, detected by bootloader)
    nv = bytes(AE_SECRET_LEN)
    pa.change(new_secret=nv)

    dis.fullscreen('Reboot...')
    utime.sleep(1)

    # security: need to reboot to really be sure to clear the secrets from main memory.
    from machine import reset
    reset()

async def word_quiz(words, limited=None):
    # Perform a test, to check they wrote them down
    # Return X if they cancel early.
    # Can just pick a subset # of words, with limited arg.

    wl = len(words)     # 24 or 12, etc.

    if limited is not None:
        # truncate to some N randomly-selected words in the list
        # and always the last word
        order = list(range(wl-1))
        shuffle(order)

        order = order[0:limited-1]
        order.append(wl-1)
    else:
        order = list(range(wl))
        
    shuffle(order)

    for o in order:
        # always 3 choices: right answer, wrong from correct set, random word
        right = words[o]

        choices = [right]
        while 1:
            n = words[rng() % wl]
            if n in choices: continue
            choices.append(n)
            break

        while 1:
            n = tcc.bip39.lookup_nth(rng() % 0x800)
            if n in choices: continue
            choices.append(n)
            break

        while 1:
            shuffle(choices)
            
            msg = '\n'.join(' %d: %s' % (i+1, choices[i]) for i in range(3))
            msg += '\n\nWhich word is right?\n\nX to give up, OK to see all the words again.'

            ch = await ux_show_story(msg, title='Word %d is?' % (o+1), escape='123')
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

# EOF
