# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
import pytest, time, os

def test_get_secrets(get_secrets, master_xpub):
    v = get_secrets()

    assert 'xpub' in v
    assert v['xpub'] == master_xpub


def test_home_menu(capture_enabled, cap_menu, cap_story, cap_screen, need_keypress):

    # get to top, force a redraw
    need_keypress('x')
    need_keypress('x')
    need_keypress('x')
    need_keypress('x')
    need_keypress('0')
    
    # check menu contents
    m = cap_menu()
    assert 'Ready To Sign' in m
    assert 'Secure Logout' in m
    assert 'Advanced' in m
    assert 'Settings' in m
    assert len(m) == 4

    # check 4 lines of menu are shown right
    scr = cap_screen()
    chk = '\n'.join(m[0:4])
    assert scr == chk

    # pick first item, expect a story
    need_keypress('0')
    need_keypress('y')

    time.sleep(.01)      # required

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert 'transactions' in body or 'Choose PSBT' in body, body
    
    need_keypress('x')

@pytest.fixture
def word_menu_entry(cap_menu, pick_menu_item):
    def doit(words):
        # do the massive drilling-down to pick a specific pass phrase
        assert len(words) in {12, 18, 24}

        for word in words:
            while 1:
                menu = cap_menu()
                which = None
                for m in menu:
                    if '-' not in m:
                        if m == word:
                            which = m
                            break
                    else:
                        assert m[-1] == '-'
                        if m == word[0:len(m)-1]+'-':
                            which = m
                            break

                assert which, "cant find: " + word

                pick_menu_item(which)
                if '-' not in which: break

                    


    return doit

@pytest.fixture
def pass_word_quiz(need_keypress, cap_story):
    def doit(words):
        need_keypress('y'); time.sleep(.01) 
        count = 0
        while 1:
            title, body = cap_story()
            if not title.startswith('Word '): break
            assert title.endswith(' is?')

            wn = int(title.split()[1])
            assert 1 <= wn <= len(words)
            wn -= 1

            ans = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
            assert len(ans) == 3
            
            correct = ans.index(words[wn])
            assert 0 <= correct < 3

            #print("Pick %d: %s" % (correct, ans[correct]))

            need_keypress(chr(49 + correct))
            time.sleep(.05) 
            count += 1

        return count, title, body

    return doit

def test_make_backup(goto_home, pick_menu_item, cap_story, need_keypress, open_microsd, microsd_path, unit_test, cap_menu, word_menu_entry, pass_word_quiz):
    # Make an encrypted 7z backup, verify it, and even restore it!

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('Backup')
    pick_menu_item('Backup System')

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert 'Record this' in body
    assert 'password:' in body

    words = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
    assert len(words) == 12

    print("Passphrase: %s" % ' '.join(words))

    # pass the quiz!
    count, title, body = pass_word_quiz(words)
    assert count >= 4

    time.sleep(0.1)

    files = []
    for copy in range(2):
        if copy == 1:
            title, body = cap_story()
            assert 'written:' in body

        fn = [ln.strip() for ln in body.split('\n') if ln.endswith('.7z')][0]

        print("filename %d: %s" % (copy, fn))

        files.append(fn)

        # write extra copy.
        need_keypress('2')
        time.sleep(.01) 

    bk_a = open_microsd(files[0]).read()
    bk_b = open_microsd(files[1]).read()

    assert bk_a == bk_b, "contents mismatch"

    pn = microsd_path(files[0])

    from subprocess import check_output

    # list contents
    out = check_output(['7z', 'l', pn], encoding='utf8')
    assert 'ckcc-backup.txt' in out
    assert 'Method = 7zAES' in out

    # does decryption; at least for CRC purposes
    out = check_output(['7z', 't', '-p'+' '.join(words), pn, 'ckcc-backup.txt'],
                            encoding='utf8')
    assert "Everything is Ok" in out, out

    for i in range(10):
        need_keypress('x')
        time.sleep(.01) 
    
    # try decrypt on microptyhon
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Wallet'    
    pick_menu_item('Import Existing')
    pick_menu_item('Restore Backup')

    # skip 
    title, body = cap_story()
    assert 'files to pick from' in body
    need_keypress('y'); time.sleep(.01) 

    pick_menu_item(files[0])

    word_menu_entry(words)
    title, body = cap_story()
    assert title == 'Success!'
    assert 'has been successfully restored' in body

    # avoid simulator reboot; restore normal state
    unit_test('devtest/abort_ux.py')


@pytest.mark.parametrize('seed_words, xfp', [
    ( 'abandon ' * 11 + 'about', 0x0adac573),
    ( 'abandon ' * 17 + 'agent', 0xc38a8be0),
    ( 'abandon ' * 23 + 'art', 0x24d73654 ),
    ( "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify", 0x4369050f),
    ])
def test_import_seed(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, seed_words, xfp, get_secrets):
    
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Wallet'    
    pick_menu_item('Import Existing')

    sw = seed_words.split(' ')
    pick_menu_item('%d Words' % len(sw))

    word_menu_entry(sw)

    m = cap_menu()
    assert m[0] == 'Ready To Sign'

    pick_menu_item('Advanced')
    pick_menu_item('View Identity')

    title, body = cap_story()

    ex = '%08x' % xfp
    assert '  '+ex in body

    v = get_secrets()

    assert v['mnemonic'] == seed_words

@pytest.mark.parametrize('multiple_runs', range(3))
def test_new_wallet(goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, get_secrets, unit_test, pass_word_quiz, multiple_runs):
    # generate a random wallet, and check seeds are what's shown to user, etc
    
    unit_test('devtest/clear_seed.py')
    m = cap_menu()
    pick_menu_item('New Wallet')

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert 'Record these 24 secret words!' in body


    words = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
    assert len(words) == 24

    print("Words: %r" % words)

    count, _, _ = pass_word_quiz(words)
    assert count == 24

    time.sleep(1)

    m = cap_menu()
    assert m[0] == 'Ready To Sign'

    v = get_secrets()
    assert v['mnemonic'].split(' ') == words


@pytest.mark.parametrize('multiple_runs', range(3))
def test_import_prv(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, microsd_path, multiple_runs):
    
    unit_test('devtest/clear_seed.py')

    fname = 'test-%d.txt' % os.getpid()
    path = microsd_path(fname)

    from pycoin.key.BIP32Node import BIP32Node
    node = BIP32Node.from_master_secret(os.urandom(32))
    open(path, 'wt').write(node.hwif(as_private=True)+'\n')
    print("Created: %s" % path)

    m = cap_menu()
    assert m[0] == 'New Wallet'    
    pick_menu_item('Import Existing')
    pick_menu_item('Import XPRV')

    title, body = cap_story()
    assert 'Select file' in body
    need_keypress('y'); time.sleep(.01) 

    pick_menu_item(fname)
    unit_test('devtest/abort_ux.py')

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

# EOF
