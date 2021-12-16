# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, re
from helpers import xfp2str, prandom

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
    assert 'Address Explorer' in m
    assert 'Advanced' in m
    assert 'Settings' in m
    if len(m) == 6:
        assert 'Passphrase' in m
    else:
        assert len(m) == 5

    # check 4 lines of menu are shown right
    scr = cap_screen()
    chk = '\n'.join(m[0:5])
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
        assert len(words) in {1, 12, 18, 23, 24}

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
    def doit(words, prefix='', preload=None):
        if not preload:
            need_keypress('y'); time.sleep(.01) 

        count = 0
        last_title = None
        while 1:
            title, body = preload or cap_story()
            preload = None

            if not title.startswith('Word '+prefix): break
            assert title.endswith(' is?')
            assert not last_title or last_title != title, "gave wrong ans?"

            wn = int(title.split()[1][len(prefix):])
            assert 1 <= wn <= len(words)
            wn -= 1

            ans = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
            assert len(ans) == 3
            
            correct = ans.index(words[wn])
            assert 0 <= correct < 3

            #print("Pick %d: %s" % (correct, ans[correct]))

            need_keypress(chr(49 + correct))
            time.sleep(.1) 
            count += 1

            last_title = title

        return count, title, body

    return doit

@pytest.mark.qrcode
@pytest.mark.parametrize('multisig', [False, 'multisig'])
def test_make_backup(multisig, goto_home, pick_menu_item, cap_story, need_keypress, open_microsd, microsd_path, unit_test, cap_menu, word_menu_entry, pass_word_quiz, reset_seed_words, import_ms_wallet, get_setting, cap_screen_qr):
    # Make an encrypted 7z backup, verify it, and even restore it!

    if multisig:
        import_ms_wallet(15, 15)
        need_keypress('y')
        time.sleep(.1)
        assert len(get_setting('multisig')) == 1

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

    if 'QR Code' in body:
        need_keypress('1')
        got_qr = cap_screen_qr().decode('ascii').lower().split()
        assert [w[0:4] for w in words] == got_qr
        need_keypress('y')

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


    # Check on-device verify UX works.
    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('Backup')
    pick_menu_item('Verify Backup')
    time.sleep(0.1)
    title, body = cap_story()
    assert "Select file" in body
    need_keypress('y')
    time.sleep(0.1)
    pick_menu_item(os.path.basename(fn))

    time.sleep(0.1)
    title, body = cap_story()
    assert "Backup file CRC checks out okay" in body


    # List contents using unix tools
    from subprocess import check_output
    import re
    pn = microsd_path(files[0])
    out = check_output(['7z', 'l', pn], encoding='utf8')
    xfname, = re.findall('[a-z0-9]{4,30}.txt', out)
    print(f"Filename inside 7z: {xfname}")
    assert xfname in out
    assert 'Method = 7zAES' in out

    # does decryption; at least for CRC purposes
    out = check_output(['7z', 't', '-p'+' '.join(words), pn, xfname], encoding='utf8')
    assert "Everything is Ok" in out, out

    for i in range(10):
        need_keypress('x')
        time.sleep(.01) 

    # test verify on device (CRC check)
    
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

    if multisig:
        assert len(get_setting('multisig')) == 1

    # avoid simulator reboot; restore normal state
    unit_test('devtest/abort_ux.py')
    reset_seed_words()


@pytest.mark.qrcode
@pytest.mark.parametrize('seed_words, xfp', [
    ( 'abandon ' * 11 + 'about', 0x0adac573),
    ( 'abandon ' * 17 + 'agent', 0xc38a8be0),
    ( 'abandon ' * 23 + 'art', 0x24d73654 ),
    ( "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify", 0x4369050f),
    ])
def test_import_seed(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, seed_words, xfp, get_secrets, reset_seed_words, cap_screen_qr, qr_quality_check):
    
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

    assert '  '+xfp2str(xfp) in body

    v = get_secrets()

    assert 'Press 3 to show QR code' in body
    need_keypress('3')
    qr = cap_screen_qr().decode('ascii')
    assert qr == v['xpub']

    assert v['mnemonic'] == seed_words
    reset_seed_words()

wordlist = None

@pytest.mark.veryslow           # 40 minutes realtime, skp with "-m not\ veryslow" on cmd line
@pytest.mark.parametrize('pos', range(0, 0x800, 23))
def test_all_bip39_words(pos, goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words):
    global wordlist
    if not wordlist:
        from mnemonic import Mnemonic
        wordlist = Mnemonic('english').wordlist

    # try every single word! In 23-word batches (89 of them)
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Wallet'    
    pick_menu_item('Import Existing')

    sw = []
    for i in range(pos, pos+23):
        try:
            sw.append(wordlist[i])
        except IndexError:
            sw.append('abandon')

    assert len(sw) == 23

    pick_menu_item('24 Words')
    word_menu_entry(sw)

    m = cap_menu()
    assert len(m) == 9, repr(m)
    sw.append(m[0])
    pick_menu_item(m[0])

    print("Words: %r" % sw)

    m = cap_menu()
    assert m[0] == 'Ready To Sign'

    v = get_secrets()
    assert v['mnemonic'] == ' '.join(sw)

    reset_seed_words()

@pytest.mark.qrcode
@pytest.mark.parametrize('count', [20, 51, 99, 104])
def test_import_from_dice(count, goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words, cap_screen, cap_screen_qr, qr_quality_check):
    import random
    from hashlib import sha256
    
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Wallet'    
    pick_menu_item('Import Existing')
    pick_menu_item('Dice Rolls')

    gave = ''
    for i in range(count):
        if count == 104:
            ch = chr(random.randint(0x30+1, 0x30+6))
        else:
            ch = chr(0x31 + (i % 6))
        time.sleep(0.01)
        need_keypress(ch)
        gave += ch

    title, body = cap_story()
        
    time.sleep(0.1)
    need_keypress('y')

    time.sleep(0.1)
    title, body = cap_story()
    if count < 99:
        assert 'Are you SURE' in body
        assert str(len(gave)) in body

        time.sleep(0.1)
        need_keypress('y')

        time.sleep(0.1)
        title, body = cap_story()

    assert 'Record these 24' in body

    assert '1 to view as QR Code' in body
    words = [i[4:4+4].upper() for i in re.findall(r'[ 0-9][0-9]: \w*', body)]
    need_keypress('1')
    qr = cap_screen_qr()
    assert qr.decode('ascii').split() == words
    need_keypress('x')      # close QR

    need_keypress('6')
    time.sleep(0.1)
    title, body = cap_story()
    assert 'Are you SURE' in body
    need_keypress('y')
    time.sleep(0.1)

    v = get_secrets()

    rs = v['raw_secret']
    if len(rs) == 65:
        rs += '0'

    assert rs == '82' + sha256(gave.encode('ascii')).hexdigest()

@pytest.mark.parametrize('multiple_runs', range(3))
def test_new_wallet(goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, get_secrets, unit_test, pass_word_quiz, multiple_runs, reset_seed_words):
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

    reset_seed_words()


@pytest.mark.parametrize('multiple_runs', range(3))
def test_import_prv(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, microsd_path, multiple_runs, reset_seed_words):
    
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

    reset_seed_words()


@pytest.mark.parametrize('target', ['baby', 'struggle', 'youth'])
@pytest.mark.parametrize('version', range(8))
def test_bip39_pick_words(target, version, goto_home, pick_menu_item, cap_story, need_keypress,
                                cap_menu, word_menu_entry, get_pp_sofar, reset_seed_words):
    # Check we can pick words
    reset_seed_words()

    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01); need_keypress('y'); time.sleep(.01)      # skip warning
    pick_menu_item('Add Word')

    word_menu_entry([target])
    if version%4 == 0:
        mw = target
    if version%4 == 1:
        mw = target.upper()
    if version%4 == 2:
        mw = target.lower()
    if version%4 == 3:
        mw = target.title()
    if version >= 4:
        mw = ' ' + mw

    pick_menu_item(mw)

    chk = get_pp_sofar()

    assert chk == mw

@pytest.mark.parametrize('target', ['123', '1', '4'*32, '12'*8])
@pytest.mark.parametrize('backspaces', [1, 0, 12])
def test_bip39_add_nums(target, backspaces, goto_home, pick_menu_item, cap_story, 
                                cap_menu, word_menu_entry, get_pp_sofar, need_keypress):

    # Check we can pick numbers (appended)
    # - also the "clear all" menu item

    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01); need_keypress('y'); time.sleep(.01)      # skip warning
    pick_menu_item('Add Numbers')

    for d in target:
        time.sleep(.01)      # required
        need_keypress(d)

    if backspaces < len(target):
        for x in range(backspaces):
            time.sleep(.01)      # required
            need_keypress('x')

        if backspaces:
            for d in target[-backspaces:]:
                time.sleep(.01)      # required
                need_keypress(d)

    time.sleep(0.01)      # required
    need_keypress('y')

    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == target

    # And clear it

    pick_menu_item('Clear All')
    time.sleep(0.01)      # required

    need_keypress('y')
    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == ''

@pytest.fixture
def enter_complex(get_pp_sofar, need_keypress, pick_menu_item):
    def doit(target):
        # full entry mode
        # - just left to right here
        # - not testing case swap, because might remove that
        symbols = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

        pick_menu_item('Edit Phrase')

        for pos, d in enumerate(target):
            time.sleep(.01)      # required
            if d.isalpha():
                if pos != 0:        # A is already default first
                    need_keypress('1')

                if d.islower():
                    time.sleep(.01)      # required
                    need_keypress('1')

                cnt = ord(d.lower()) - ord('a')

            elif d.isdigit():
                need_keypress('2')
                if d == '0':
                    time.sleep(.01)      # required
                    need_keypress('8')
                    cnt = 0
                else:
                    cnt = ord(d) - ord('1')
            else:
                assert d in symbols
                if pos == 0:
                    need_keypress('3')

                cnt = symbols.find(d)

            for i in range(cnt):
                time.sleep(.01)      # required
                need_keypress('5')

            if pos != len(target)-1:
                time.sleep(.01)      # required
                need_keypress('9')

        time.sleep(0.01)      # required
        need_keypress('y')

    return doit

@pytest.mark.parametrize('target', ['abc123', 'AbcZz1203', 'Test 123',
        '&*!#^$*&@#^*&^$abcdABCD^%182736',
        'I be stacking sats!! Come at me bro....',
        'Aa'*50,
])
def test_bip39_complex(target, goto_home, pick_menu_item, cap_story, 
                        cap_menu, word_menu_entry, get_pp_sofar, need_keypress, enter_complex):

    # failed run recovery; gets out of edit screen
    #need_keypress('y')
    #need_keypress('x')
    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01); need_keypress('y'); time.sleep(.01)      # skip warning

    enter_complex(target)

    time.sleep(0.01)      # required
    assert get_pp_sofar() == target


@pytest.mark.qrcode
@pytest.mark.parametrize('mode', ['words', 'xprv', 'ms'])
@pytest.mark.parametrize('b39_word', ['', 'AbcZz1203'])
def test_show_seed(mode, b39_word, goto_home, pick_menu_item, cap_story, need_keypress, sim_exec,
                cap_menu, get_pp_sofar, get_secrets, cap_screen_qr, set_encoded_secret, qr_quality_check):
    from constants import simulator_fixed_xprv

    if mode == 'words':
        # Check the seed words are displayed correctly: the new "View Seed Words" feature
        sim_exec("import stash; stash.bip39_passphrase = '%s'" % b39_word)

        v = get_secrets()
        words = v['mnemonic'].split(' ')
    else:
        if b39_word: return

        if mode == 'xprv':
            set_encoded_secret(b'\x01' + prandom(64))
            v = get_secrets()
            expect = v['xprv']
        elif mode == 'ms':
            set_encoded_secret(b'\x20' + prandom(32))
            v = get_secrets()
            expect = v['raw_secret'][2:2+64]
        

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('View Seed Words')
    time.sleep(.01); 
    title, body = cap_story()
    assert 'Are you SURE' in body
    assert 'can control all funds' in body
    need_keypress('y');      # skip warning
    time.sleep(0.01)

    title, body = cap_story()
    assert title == 'NO-TITLE'

    if mode == 'words':
        assert '24' in body

        lines = body.split('\n')
        assert lines[1:25] == ['%2d: %s' % (n+1, w) for n,w in enumerate(words)]

        if b39_word:
            assert lines[26] == 'BIP-39 Passphrase:'
            assert b39_word in lines[27]

            sim_exec("import stash; stash.bip39_passphrase = ''")

        qr_expect = ' '.join(w[0:4].upper() for w in words)

    else:
        assert expect in body
        qr_expect = expect

    assert '1 to view as QR Code' in body
    need_keypress('1')
    qr = cap_screen_qr().decode('ascii')
    assert qr == qr_expect

    need_keypress('y')      # clear screen

def test_destroy_seed(goto_home, pick_menu_item, cap_story, need_keypress, sim_exec,
                                cap_menu, get_secrets):

    # Check UX of destroying seeds, rarely used?

    #v = get_secrets()
    #words = v['mnemonic'].split(' ')

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Destroy Seed')
    time.sleep(.01); 
    title, body = cap_story()
    assert 'Are you SURE' in body
    assert 'All funds will be lost' in body
    need_keypress('y');    
    time.sleep(0.01)

    title, body = cap_story()
    assert 'Are you REALLY sure though' in body
    assert 'certainly cause' in body
    assert 'accept all consequences' in body
    need_keypress('y');         # wants 4
    time.sleep(0.01)


@pytest.mark.onetime
def test_dump_menutree(sim_execfile):
    # saves to ../unix/work/menudump.txt
    sim_execfile('devtest/menu_dump.py')

# EOF
