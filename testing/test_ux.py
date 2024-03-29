# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, re, hashlib, functools
from helpers import xfp2str, prandom
from charcodes import KEY_DOWN, KEY_QR, KEY_NFC
from constants import AF_CLASSIC, simulator_fixed_words, simulator_fixed_xfp
from mnemonic import Mnemonic
from pycoin.key.BIP32Node import BIP32Node
from core_fixtures import _enter_complex


def test_get_secrets(get_secrets, master_xpub):
    v = get_secrets()

    assert 'xpub' in v
    assert v['xpub'] == master_xpub

def test_home_menu(cap_menu, cap_story, cap_screen, need_keypress, reset_seed_words,
                   press_select, press_cancel, is_q1):
    reset_seed_words()
    # get to top, force a redraw
    press_cancel()
    press_cancel()
    press_cancel()
    press_cancel()
    need_keypress('0')
    
    # check menu contents
    m = cap_menu()
    assert 'Ready To Sign' in m
    if not is_q1:
        assert 'Secure Logout' in m
    assert 'Address Explorer' in m
    assert 'Advanced/Tools' in m
    assert 'Settings' in m
    if len(m) == 7:
        assert 'Passphrase' in m
    else:
        assert len(m) == 6

    # check 4 lines of menu are shown right
    scr = cap_screen().rstrip()
    chk = '\n'.join(m)
    assert scr == chk

    # pick first item, expect a story
    need_keypress('0')
    press_select()

    time.sleep(.01)      # required

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert 'transactions' in body or 'Choose PSBT' in body, body
    
    press_cancel()

@pytest.fixture
def word_menu_entry(cap_menu, pick_menu_item, is_q1, do_keypresses, cap_screen):
    def doit(words, has_checksum=True):
        if is_q1:
            # easier for us on Q, but have to anticipate the autocomplete
            for n, w in enumerate(words, start=1):
                do_keypresses(w[0:2])
                time.sleep(0.50)
                if 'Next key' in cap_screen():
                    do_keypresses(w[2])
                    time.sleep(.1)
                if 'Next key' in cap_screen():
                    if len(w) > 3:
                        do_keypresses(w[3])
                    else:
                        do_keypresses(KEY_DOWN)
                    time.sleep(.1)

                pat = rf'{n}:\s?{w}'
                for x in range(10):
                    if re.search(pat, cap_screen()):
                        break
                    time.sleep(0.20)
                else:
                    raise RuntimeError('timeout')

            if len(words) == 23:
                do_keypresses(KEY_DOWN)
                cap_scr = cap_screen()
                while 'Next key' in cap_scr:
                    target = cap_scr.split("\n")[-1].replace("Next key: ", "")
                    do_keypresses(target[0])
                    time.sleep(.1)
                    cap_scr = cap_screen()
            else:
                cap_scr = cap_screen()

            if has_checksum:
                assert 'Valid words' in cap_scr
            else:
                assert 'Press ENTER if all done' in cap_scr
            do_keypresses('\r')
            return

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
def pass_word_quiz(need_keypress, cap_story, press_select):
    def doit(words, prefix='', preload=None):
        if not preload:
            press_select()
            time.sleep(.01)

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
@pytest.mark.parametrize('seed_words, xfp', [
    ( 'abandon ' * 11 + 'about', 0x0adac573),
    ( 'abandon ' * 17 + 'agent', 0xc38a8be0),
    ( 'abandon ' * 23 + 'art', 0x24d73654 ),
    ( simulator_fixed_words, simulator_fixed_xfp),
    ])
def test_import_seed(goto_home, pick_menu_item, cap_story, need_keypress, unit_test,
                     cap_menu, word_menu_entry, seed_words, xfp, get_secrets, is_q1,
                     reset_seed_words, cap_screen_qr, qr_quality_check, expect_ftux,
                     is_headless):
    
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')

    sw = seed_words.split(' ')
    pick_menu_item('%d Words' % len(sw))

    word_menu_entry(sw)

    expect_ftux()

    pick_menu_item('Advanced/Tools')
    pick_menu_item('View Identity')

    title, body = cap_story()

    assert '  '+xfp2str(xfp) in body

    v = get_secrets()

    assert f'Press {KEY_QR if is_q1 else "(3)"} to show QR code' in body
    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '3')
        qr = cap_screen_qr().decode('ascii')
        assert qr == v['xpub']

    assert v['mnemonic'] == seed_words
    reset_seed_words()


@pytest.mark.veryslow           # 40 minutes realtime, skp with "-m not\ veryslow" on cmd line
@pytest.mark.parametrize('pos', range(0, 0x800, 23))
def test_all_bip39_words(pos, goto_home, pick_menu_item, cap_story, unit_test,
                         cap_menu, word_menu_entry, get_secrets, reset_seed_words,
                         expect_ftux, is_q1):
    from mnemonic import Mnemonic
    mnem = Mnemonic('english')
    wordlist = mnem.wordlist

    # try every single word! In 23-word batches (89 of them)
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
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

    if not is_q1:
        m = cap_menu()
        assert len(m) == 9, repr(m)
        sw.append(m[0])
        pick_menu_item(m[0])

    print("Words: %r" % sw)

    expect_ftux()

    v = get_secrets()
    if is_q1:
        assert v["mnemonic"].split(" ")[:-1] == sw
        mnem.check(v["mnemonic"])
    else:
        assert v['mnemonic'] == ' '.join(sw)

    reset_seed_words()

@pytest.mark.qrcode
@pytest.mark.parametrize('count', [20, 40, 51, 99, 104])
@pytest.mark.parametrize('nwords', [12, 24])
def test_import_from_dice(count, nwords, goto_home, pick_menu_item, cap_story, need_keypress,
                          unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words,
                          cap_screen, cap_screen_qr, qr_quality_check, expect_ftux, press_select,
                          press_cancel, is_q1, seed_story_to_words, is_headless):
    import random
    from hashlib import sha256
    
    unit_test('devtest/clear_seed.py')

    pick_menu_item('New Seed Words')
    pick_menu_item('Advanced')

    pick_menu_item(f'{nwords} Word Dice Roll')

    gave = ''
    for i in range(count):
        if count == 104:
            ch = chr(random.randint(0x30+1, 0x30+6))
        else:
            ch = chr(0x31 + (i % 6))
        time.sleep(0.01)
        need_keypress(ch)
        gave += ch
        
    time.sleep(0.1)
    press_select()

    time.sleep(0.1)
    title, body = cap_story()
    threshold = 99 if nwords == 24 else 50
    if count < threshold:
        assert 'Not enough dice rolls' in body
        assert str(len(gave)) in body

        time.sleep(0.1)
        press_select()  # add more dice rolls
        for i in range(threshold - count):
            ch = chr(0x31 + (i % 6))
            time.sleep(0.01)
            need_keypress(ch)
            gave += ch

        press_select()
        time.sleep(0.1)
        title, body = cap_story()

    assert f'Record these {nwords}' in body

    assert f'{KEY_QR if is_q1 else "(1)"} to view as QR Code' in body
    if is_q1:
        words = [i[:4].upper() for i in seed_story_to_words(body)]
    else:
        words = [i[4:4+4].upper() for i in re.findall(r'[ 0-9][0-9]: \w*', body)]

    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '1')

        qr = cap_screen_qr()
        assert qr.decode('ascii').split() == words
        press_cancel()      # close QR

    need_keypress('6')
    time.sleep(0.1)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    press_select()
    time.sleep(0.1)

    v = get_secrets()

    rs = v['raw_secret']
    if len(rs)%2 == 1:
        rs += '0'

    if nwords == 24:
        assert rs == '82' + sha256(gave.encode('ascii')).hexdigest()
    elif nwords == 12:
        assert rs == '80' + sha256(gave.encode('ascii')).hexdigest()[0:32]
    else:
        raise ValueError(nwords)

    expect_ftux()

@pytest.mark.parametrize('multiple_runs', range(3))
@pytest.mark.parametrize('nwords', [12, 24])
def test_new_wallet(nwords, goto_home, pick_menu_item, cap_story, expect_ftux,
                    cap_menu, get_secrets, unit_test, pass_word_quiz, multiple_runs,
                    reset_seed_words, is_q1, seed_story_to_words):
    # generate a random wallet, and check seeds are what's shown to user, etc
    
    unit_test('devtest/clear_seed.py')
    m = cap_menu()
    pick_menu_item('New Seed Words')
    pick_menu_item(f'{nwords} Words')

    title, body = cap_story()
    assert title == 'NO-TITLE'
    assert f'Record these {nwords} secret words!' in body

    if is_q1:
        words = seed_story_to_words(body)
    else:
        words = [w[3:].strip() for w in body.split('\n') if w and w[2] == ':']
    assert len(words) == nwords

    print("Words: %r" % words)

    count, _, _ = pass_word_quiz(words)
    assert count == nwords

    time.sleep(1)

    expect_ftux()

    v = get_secrets()
    assert v['mnemonic'].split(' ') == words

    reset_seed_words()


@pytest.mark.parametrize('multiple_runs', range(3))
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('testnet', [True, False])
def test_import_prv(way, testnet, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu,
                    word_menu_entry, get_secrets, microsd_path, multiple_runs, reset_seed_words,
                    nfc_write_text, settings_set, virtdisk_path, expect_ftux, press_select,
                    press_nfc, is_q1):
    if testnet:
        netcode = "XTN"
        settings_set('chain', 'XTN')
    else:
        netcode = "BTC"
        settings_set('chain', 'XTN')

    unit_test('devtest/clear_seed.py')

    node = BIP32Node.from_master_secret(os.urandom(32), netcode=netcode)
    prv = node.hwif(as_private=True)+'\n'
    if testnet:
        assert "tprv" in prv
    else:
        assert "xprv" in prv

    fname = 'test-%d.txt' % os.getpid()
    if way =="sd":
        fpath = microsd_path(fname)
    elif way == "vdisk":
        fpath = virtdisk_path(fname)
    if way != "nfc":
        with open(fpath, "w") as f:
            f.write(prv)

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')
    pick_menu_item('Import XPRV')
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import extended private key file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            press_nfc()
            time.sleep(0.2)
            nfc_write_text(prv)
            time.sleep(0.3)
    else:
        # virtual disk
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way != "nfc":
        time.sleep(0.1)
        pick_menu_item(fname)

    expect_ftux()

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

    reset_seed_words()


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('retry', range(3))
@pytest.mark.parametrize("testnet", [True, False])
def test_seed_import_tapsigner(way, retry, testnet, cap_menu, pick_menu_item, goto_home, cap_story,
                               need_keypress, reset_seed_words, dev, try_sign, enter_hex, unit_test,
                               settings_set, get_secrets, tapsigner_encrypted_backup, nfc_write_text,
                               press_nfc, press_select, is_q1):

    fname, backup_key_hex, node = tapsigner_encrypted_backup(way, testnet=testnet)
    if testnet:
        settings_set('chain', 'XTN')
    else:
        settings_set('chain', 'XTN')

    unit_test('devtest/clear_seed.py')
    m = cap_menu()
    assert m[0] == 'New Seed Words'
    pick_menu_item('Import Existing')
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            press_nfc()
            time.sleep(0.2)
            nfc_write_text(fname)
            time.sleep(0.3)
    else:
        # virtual disk
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way != "nfc":
        time.sleep(0.1)
        pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert "your TAPSIGNER" in story
    assert "back of the card" in story
    press_select()  # yes I have backup key
    enter_hex(backup_key_hex)
    unit_test('devtest/abort_ux.py')

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

    reset_seed_words()


@pytest.mark.parametrize('target', ['baby', 'struggle', 'youth'])
@pytest.mark.parametrize('version', range(8))
def test_bip39_pick_words(target, version, goto_home, pick_menu_item, cap_story,
                          cap_menu, word_menu_entry, get_pp_sofar, reset_seed_words,
                          press_select, only_mk4):
    # Check we can pick words
    reset_seed_words()

    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01)
    press_select()
    time.sleep(.01)      # skip warning
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
                        cap_menu, word_menu_entry, get_pp_sofar, need_keypress,
                        press_select, press_cancel, only_mk4):

    # Check we can pick numbers (appended)
    # - also the "clear all" menu item

    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01); press_select(); time.sleep(.01)      # skip warning
    pick_menu_item('Add Numbers')

    for d in target:
        time.sleep(.01)      # required
        need_keypress(d)

    if backspaces < len(target):
        for x in range(backspaces):
            time.sleep(.01)      # required
            press_cancel()

        if backspaces:
            for d in target[-backspaces:]:
                time.sleep(.01)      # required
                need_keypress(d)

    time.sleep(0.01)      # required
    press_select()

    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == target

    # And clear it

    pick_menu_item('Clear All')
    time.sleep(0.01)      # required

    press_select()
    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == ''

@pytest.fixture
def enter_complex(dev, is_q1):
    # full entry mode
    # - just left to right here
    # - not testing case swap, because might remove that
    f = functools.partial(_enter_complex, dev, is_q1)
    return f

@pytest.mark.parametrize('target', [
    'abc123', 'AbcZz1203', 'Test 123', 'Aa'*50,
    '&*!#^$*&@#^*&^$abcdABCD^%182736',
    'I be stacking sats!! Come at me bro....',
])
def test_bip39_complex(target, goto_home, pick_menu_item, cap_story,
                       press_select, enter_complex, restore_main_seed,
                       verify_ephemeral_secret_ui):
    goto_home()
    pick_menu_item('Passphrase')
    time.sleep(.01)
    press_select()
    time.sleep(.01)      # skip warning

    from mnemonic import Mnemonic

    seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=target)
    expect = BIP32Node.from_master_secret(seed, netcode="XTN")

    enter_complex(target, apply=True)
    press_select()
    # import pdb;pdb.set_trace()
    verify_ephemeral_secret_ui(xpub=expect.hwif(), is_b39pw=True)


@pytest.mark.qrcode
@pytest.mark.parametrize('mode', ['words', 'xprv', 'ms'])
@pytest.mark.parametrize('b39_word', ['', 'AbcZz1203'])
def test_show_seed(mode, b39_word, goto_home, pick_menu_item, cap_story, need_keypress,
                   sim_exec, cap_menu, get_secrets, cap_screen_qr, set_bip39_pw,
                   set_encoded_secret, qr_quality_check, reset_seed_words,
                   press_select, is_q1, seed_story_to_words, is_headless):

    reset_seed_words()
    if mode == 'words':
        set_bip39_pw(b39_word, reset=False)
        words = simulator_fixed_words.split(" ")

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
            if len(expect) % 2 == 1:
                expect += '0'
        

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('View Seed Words')
    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'can control all funds' in body
    press_select()      # skip warning
    time.sleep(0.01)

    title, body = cap_story()
    assert title == 'NO-TITLE'

    if mode == 'words':
        assert '24' in body

        lines = body.split('\n')
        if is_q1:
            assert seed_story_to_words(body) == words
        else:
            assert lines[1:25] == ['%2d: %s' % (n+1, w) for n,w in enumerate(words)]

        if b39_word:
            if is_q1:
                assert lines[11] == 'BIP-39 Passphrase:'
                assert "*" in lines[12]
                assert "Seed+Passphrase" in lines[14]
                ek = lines[15]
            else:
                assert lines[26] == 'BIP-39 Passphrase:'
                assert "*" in lines[27]
                assert "Seed+Passphrase" in lines[29]
                ek = lines[30]

            seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=b39_word)
            expect = BIP32Node.from_master_secret(seed, netcode="XTN")
            esk = expect.hwif(as_private=True)
            assert esk == ek
        else:
            assert "BIP-39 Passphrase" not in body

        qr_expect = ' '.join(w[0:4].upper() for w in words)

    else:
        assert expect in body
        qr_expect = expect

    if not is_q1:
        assert '(1) to view as QR Code' in body

    if not is_headless:
        need_keypress(KEY_QR if is_q1 else '1')
        qr = cap_screen_qr().decode('ascii')
        assert qr == qr_expect

    press_select()      # clear screen

@pytest.mark.qrcode
@pytest.mark.parametrize("data", [
    (simulator_fixed_words, [2007, 1585, 123, 131, 745, 43, 1506, 1930, 664, 749, 1200, 113, 1321, 330, 1764, 698, 1160, 656, 647, 1424, 135, 767, 987, 335]),
    ("task tube actor end cannon potato sign card occur donkey soup baby tooth bless barely pull gap priority", [1776, 1872, 21, 588, 267, 1350, 1602, 276, 1222, 521, 1663, 136, 1830, 189, 148, 1386, 762, 1367]),
    ("vacuum bridge buddy supreme exclude milk consider tail expand wasp pattern nuclear", [1924,222,235,1743,631,1124,378,1770,641,1980,1290,1210]),
    ("approve fruit lens brass ring actual stool coin doll boss strong rate", "008607501025021714880023171503630517020917211425"),
    ("good battle boil exact add seed angle hurry success glad carbon whisper", "080301540200062600251559007008931730078802752004"),
    ("forum undo fragile fade shy sign arrest garment culture tube off merit", "073318950739065415961602009907670428187212261116"),
    ("sound federal bonus bleak light raise false engage round stock update render quote truck quality fringe palace foot recipe labor glow tortoise potato still", "166206750203018810361417065805941507171219081456140818651401074412730727143709940798183613501710"),
    ("atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid meadow quick medal plate wisdom swap noble shallow", "011416550964188800731119157218870156061002561932122514430573003611011405110613292018175411971576"),
    ("attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire", "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643"),
])
def test_show_seed_qr(data, goto_home, pick_menu_item, cap_story, press_select,
                      sim_exec, cap_menu, get_secrets, cap_screen_qr,
                      set_encoded_secret, qr_quality_check, set_seed_words, is_q1):
    n = 4  # SeedQr 4 str chars for each index
    words, qr_expect = data
    if isinstance(qr_expect, str):
        qr_expect = [int(qr_expect[i:i+n]) for i in range(0, len(qr_expect), n)]
    set_seed_words(words)

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Export SeedQR')

    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'can control all funds' in body
    press_select()  # skip warning
    time.sleep(0.01)

    qr = cap_screen_qr().decode('ascii')
    qr = [int(qr[i:i+n]) for i in range(0, len(qr), n)]
    assert qr == qr_expect

    press_select()  # clear screen

def test_destroy_seed(goto_home, pick_menu_item, cap_story, press_select,
                      sim_exec, cap_menu, get_secrets, is_q1):
    # Check UX of destroying seeds, rarely used?

    #v = get_secrets()
    #words = v['mnemonic'].split(' ')

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Destroy Seed')
    time.sleep(.01)
    title, body = cap_story()
    where = title if is_q1 else body
    assert 'Are you SURE' in where
    assert 'All funds will be lost' in body
    press_select()
    time.sleep(0.01)

    title, body = cap_story()
    assert 'Are you REALLY sure though' in body
    assert 'certainly cause' in body
    assert 'accept all consequences' in body
    press_select()         # wants 4
    time.sleep(0.01)


def test_menu_wrapping(goto_home, pick_menu_item, cap_story, cap_menu,
                       press_select, press_up, press_down, press_cancel,
                       is_q1):
    goto_home()
    # first try that infinite scroll is turned off
    # home
    for i in range(10):  # settings on 5th in home (10 is way past that)
        press_down()

    # sitting at Logout
    # one up to get to settings
    if not is_q1:
        press_up()

    press_select()
    pick_menu_item("Menu Wrapping")
    press_select()
    pick_menu_item("Enable")
    time.sleep(1)
    press_cancel()  # back to home menu
    press_cancel()  # at Ready To Sign

    press_up()  # Settings as we just went over the top in home menu
    if not is_q1:
        press_up()
    press_select()

    pick_menu_item("Menu Wrapping")
    pick_menu_item("Default Off")
    time.sleep(1)
    press_cancel()  # back in home menu
    press_cancel()  # at Ready To Sign
    press_up()
    press_select()
    menu = cap_menu()
    assert "Menu Wrapping" not in menu
    goto_home()

def test_chain_changes_settings_xpub(pick_menu_item, goto_home, cap_story,
                                     press_select, press_cancel):
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("View Identity")
    _, story = cap_story()
    extended_key = story.split("\n\n")[5]
    assert extended_key.startswith("tpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    pick_menu_item("Bitcoin")
    press_cancel()  # go back to advanced
    time.sleep(0.1)
    pick_menu_item("View Identity")
    _, story = cap_story()
    extended_key = story.split("\n\n")[5]
    assert extended_key.startswith("xpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    time.sleep(0.1)
    _, story = cap_story()
    assert "Testnet must only be used by developers" in story
    press_select()
    pick_menu_item("Regtest")
    press_cancel()  # go back to advanced
    time.sleep(0.1)
    pick_menu_item("View Identity")
    _, story = cap_story()
    extended_key = story.split("\n\n")[5]
    assert extended_key.startswith("tpub")

@pytest.mark.parametrize("clear", [1, 0])
@pytest.mark.parametrize("f_len", [50, 500, 5000])
def test_sign_file_from_list_files(f_len, goto_home, cap_story, pick_menu_item, need_keypress,
                                   microsd_path, cap_menu, verify_detached_signature_file,
                                   press_select, clear, unit_test, reset_seed_words):
    if clear:
        unit_test('devtest/clear_seed.py')
    else:
        reset_seed_words()

    fname = "test_sign_listed.pdf"
    signame = "test_sign_listed.sig"
    fpath = microsd_path(fname)
    contents = os.urandom(f_len)
    digest = hashlib.sha256(contents).digest().hex()
    with open(fpath, "wb") as f:
        f.write(contents)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item('File Management')
    pick_menu_item('List Files')
    time.sleep(0.1)
    pick_menu_item(fname)
    time.sleep(0.1)
    _, story = cap_story()
    assert f"SHA256({fname})" in story
    assert digest in story
    if clear:
        assert "(4) to sign file digest and export detached signature" not in story
    else:
        assert "(4) to sign file digest and export detached signature" in story
        need_keypress("4")
        time.sleep(0.1)
        _, story = cap_story()
        assert f"Signature file {signame} written" in story
        need_keypress("y")
        verify_detached_signature_file([fname], signame, "sd", AF_CLASSIC)
        _, story = cap_story()
        assert "(4) to sign file digest and export detached signature" not in story

    assert "(6) to delete" in story

    need_keypress("6")
    menu = cap_menu()
    assert "List Files" in menu


def test_bip39_pw_signing_xfp_ux(goto_home, pick_menu_item, press_select, cap_story,
                                 enter_complex, reset_seed_words, cap_menu):
    goto_home()
    pick_menu_item("Passphrase")
    press_select()
    enter_complex("21coinkite21", apply=True)
    time.sleep(0.3)
    title, story = cap_story()
    assert title == "[0C9DC99D]"
    assert 'Above is the master key fingerprint of the new wallet' in story
    press_select()  # confirm passphrase
    m = cap_menu()
    assert m[0] == "[0C9DC99D]"
    pick_menu_item("Ready To Sign")
    time.sleep(0.1)
    title_sign, _ = cap_story()
    assert title_sign == title
    reset_seed_words()  # for subsequent tests


@pytest.mark.onetime
def test_dump_menutree(sim_execfile):
    # saves to ../unix/work/menudump.txt
    sim_execfile('devtest/menu_dump.py')

if 0:
    # show what the final word can be (debug only)
    def test_23_words(goto_home, pick_menu_item, cap_story, need_keypress, unit_test, cap_menu, word_menu_entry, get_secrets, reset_seed_words, cap_screen_qr, qr_quality_check):
        
        unit_test('devtest/clear_seed.py')

        m = cap_menu()
        assert m[0] == 'New Seed Words'    
        pick_menu_item('Import Existing')

        seed_words = 'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary'

        sw = seed_words.split(' ')
        pick_menu_item('24 Words')

        word_menu_entry(sw)

        print('\n'.join(cap_menu()))


# EOF
