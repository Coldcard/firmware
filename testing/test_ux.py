# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, re, hashlib, shutil
from helpers import xfp2str, prandom
from charcodes import KEY_DOWN, KEY_QR, KEY_NFC, KEY_DELETE, KEY_CANCEL
from constants import AF_CLASSIC, simulator_fixed_words, simulator_fixed_xfp
from mnemonic import Mnemonic
from bip32 import BIP32Node


@pytest.fixture
def enable_hw_ux(pick_menu_item, cap_story, press_select, goto_home):
    def doit(way, disable=False):
        pick_menu_item("Settings")
        pick_menu_item("Hardware On/Off")
        if way == "vdisk":
            pick_menu_item("Virtual Disk")
            _, story = cap_story()
            if "emulate a virtual disk drive" in story:
                press_select()
            if disable:
                pick_menu_item("Default Off")
            else:
                pick_menu_item("Enable")
        elif way == "nfc":
            pick_menu_item("NFC Sharing")
            _, story = cap_story()
            if "(Near Field Communications)" in story:
                press_select()
            if disable:
                pick_menu_item("Default Off")
            else:
                pick_menu_item("Enable NFC")
        else:
            raise RuntimeError("TODO")

        goto_home()

    return doit

def test_get_secrets(get_secrets, master_xpub):
    v = get_secrets()

    assert 'xpub' in v
    assert v['xpub'] == master_xpub

def test_home_menu(cap_menu, cap_story, cap_screen, need_keypress, reset_seed_words,
                   press_select, press_cancel, press_down, is_q1):
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
    if is_q1:
        assert scr == chk
    else:
        # does not fit to single screen on mk4
        assert scr in chk
        # go down to the bottom
        for i in range(6):
            press_down()

        scr = cap_screen().rstrip()
        assert scr in chk

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
    def doit(words, has_checksum=True, q_accept=True):
        if is_q1:
            # easier for us on Q, but have to anticipate the autocomplete
            for n, w in enumerate(words, start=1):
                do_keypresses(w[0:2])
                time.sleep(0.05)
                if 'Next key' in cap_screen():
                    do_keypresses(w[2])
                    time.sleep(.01)
                if 'Next key' in cap_screen():
                    if len(w) > 3:
                        do_keypresses(w[3])
                    else:
                        do_keypresses(KEY_DOWN)
                    time.sleep(.01)

                pat = rf'{n}:\s?{w}'
                for x in range(10):
                    if re.search(pat, cap_screen()):
                        break
                    time.sleep(0.02)
                else:
                    raise RuntimeError('timeout')

            if len(words) == 23:
                do_keypresses(KEY_DOWN)
                time.sleep(.03)
                cap_scr = cap_screen()
                while 'Next key' in cap_scr:
                    target = cap_scr.split("\n")[-1].replace("Next key: ", "")
                    # picks first choice!?
                    do_keypresses(target[0])
                    time.sleep(.03)
                    cap_scr = cap_screen()
            else:
                cap_scr = cap_screen()

            if has_checksum:
                assert 'Valid words' in cap_scr
            else:
                assert 'Press ENTER if all done' in cap_scr

            if q_accept:
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
                if '-' not in which:
                    break

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
                     is_headless, get_identity_story):
    
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')

    sw = seed_words.split(' ')
    pick_menu_item('%d Words' % len(sw))

    word_menu_entry(sw)

    expect_ftux()

    istory, parsed_ident = get_identity_story()

    assert xfp2str(xfp) == parsed_ident["xfp"]

    v = get_secrets()

    assert f'Press {KEY_QR if is_q1 else "(3)"} to show QR code' in istory
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

    target = f'Record these {nwords}'
    if is_q1:
        assert target in title
        words = [i[:4].upper() for i in seed_story_to_words(body)]
    else:
        assert target in body
        assert  "(1) to view as QR Code" in body
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
    target = f'Record these {nwords} secret words!'
    if is_q1:
        assert target in title
    else:
        assert title == 'NO-TITLE'
        assert target in body

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
                    press_nfc, is_q1, enable_hw_ux):

    unit_test('devtest/clear_seed.py')
    netcode = "XTN" if testnet else "BTC"
    settings_set('chain', netcode)

    if way != "sd":
        enable_hw_ux(way)

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
                               press_nfc, press_select, is_q1, enable_hw_ux):
    unit_test('devtest/clear_seed.py')
    netcode = "XTN" if testnet else "BTC"
    settings_set('chain', netcode)

    if way != "sd":
        enable_hw_ux(way)

    fname, backup_key_hex, node = tapsigner_encrypted_backup(way, testnet=testnet)

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
    if not is_q1:
        assert title == 'NO-TITLE'

    if mode == 'words':
        assert '24' in (title if is_q1 else body)

        lines = body.split('\n')
        if is_q1:
            assert seed_story_to_words(body) == words
        else:
            assert lines[1:25] == ['%2d: %s' % (n+1, w) for n,w in enumerate(words)]

        if b39_word:
            if is_q1:
                assert lines[9] == 'BIP-39 Passphrase:'
                assert "*" in lines[10]
                assert "Seed+Passphrase" in lines[12]
                ek = lines[13]
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
    assert 'Saved temporary seed settings and Seed Vault are lost' in body
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
                       is_q1, settings_remove):
    settings_remove("wa")  # disable
    goto_home()
    # first try that infinite scroll is turned off
    # home
    assert len(cap_menu()) < 10

    for i in range(10):
        press_down()

    # sitting at Logout
    # one up to get to settings
    if not is_q1:
        press_up()

    press_select()
    pick_menu_item("Menu Wrapping")
    press_select()
    pick_menu_item("Always Wrap")
    time.sleep(1)
    press_cancel()  # back to home menu
    press_cancel()  # at Ready To Sign

    press_up()  # Settings as we just went over the top in home menu
    if not is_q1:
        press_up()
    press_select()

    pick_menu_item("Menu Wrapping")
    pick_menu_item("Default")
    time.sleep(1)
    press_cancel()  # back in home menu
    press_cancel()  # at Ready To Sign
    press_up()
    press_select()
    menu = cap_menu()
    assert "Menu Wrapping" not in menu
    goto_home()

def test_chain_changes_settings_xpub(pick_menu_item, cap_story, press_select,
                                     get_identity_story):
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("tpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    pick_menu_item("Bitcoin")
    time.sleep(0.2)
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("xpub")
    press_select()
    pick_menu_item("Danger Zone")
    pick_menu_item("Testnet Mode")
    time.sleep(0.2)
    _, story = cap_story()
    assert "Testnet must only be used by developers" in story
    press_select()
    pick_menu_item("Regtest")
    time.sleep(0.2)
    _, parsed_ident = get_identity_story()
    assert parsed_ident["ek"].startswith("tpub")

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
        time.sleep(0.1)
        verify_detached_signature_file([fname], signame, "sd", AF_CLASSIC)
        time.sleep(0.1)
        _, story = cap_story()

    assert "(6) to delete" in story

    need_keypress("6")
    time.sleep(0.1)
    menu = cap_menu()
    assert "List Files" in menu


def test_rename_from_list_files(goto_home, cap_story, pick_menu_item, need_keypress, is_q1,
                                microsd_path, press_select, cap_screen, enter_complex):
    def clear(fname):
        for i in range(len(fname)):
            if not is_q1 and not i:
                # Mk4 different menu entry UX
                continue
            need_keypress(KEY_DELETE if is_q1 else "x")
            time.sleep(0.01)

    fname = "file_to_rename.pdf"
    fpath = microsd_path(fname)
    contents = os.urandom(64)
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
    assert "Press (1) to rename file" in story
    need_keypress("1")
    time.sleep(0.1)
    if is_q1:
        scr = cap_screen()
        assert fname in scr

    clear(fname)

    bad_fnames = ["renamed file.txt", "/sd/renamed_file.txt", "renamed\\file.txt"]
    for bad in bad_fnames:
        enter_complex(bad, b39pass=False)
        time.sleep(.1)
        title, story = cap_story()
        assert title == "Failure"
        assert "Failed to rename the file" in story
        assert "illegal char" in story
        press_select()
        time.sleep(.1)
        need_keypress("1")  # rename again
        time.sleep(.1)
        clear(fname)
        if not is_q1:
            need_keypress("1")  # toggle case back to upper (enter complex expect to start in that state)

    new_fname = "renamed_file.txt"
    enter_complex(new_fname, b39pass=False)
    time.sleep(.1)
    _, story = cap_story()
    assert f"SHA256({new_fname})" in story
    assert digest in story
    assert not os.path.exists(fpath)
    assert os.path.exists(microsd_path(new_fname))


def test_bip39_pw_signing_xfp_ux(pick_menu_item, press_select, cap_story, enter_complex,
                                 reset_seed_words, cap_menu, go_to_passphrase, microsd_wipe):
    microsd_wipe()  # need to wipe all PSBT on SD card so we do not proceed to signing
    go_to_passphrase()
    enter_complex("21coinkite21", apply=True)
    time.sleep(0.3)
    title, story = cap_story()
    assert title == "[0C9DC99D]"
    assert 'Above is the master key fingerprint of the new wallet' in story
    press_select()  # confirm passphrase
    time.sleep(0.1)
    m = cap_menu()
    assert m[0] == "[0C9DC99D]"
    pick_menu_item("Ready To Sign")
    time.sleep(0.1)
    title_sign, _ = cap_story()
    assert title_sign == title
    reset_seed_words()  # for subsequent tests


def test_q1_seed_word_entry_bug(word_menu_entry, unit_test, pick_menu_item,
                                is_q1, do_keypresses, press_select, expect_ftux):
    # internal/issues/750
    if not is_q1:
        raise pytest.skip("Q only")

    unit_test('devtest/clear_seed.py')
    pick_menu_item('Import Existing')
    pick_menu_item('24 Words')
    sw = ["abandon"] * 23
    sw += ["art"]
    word_menu_entry(sw, q_accept=False)
    do_keypresses("art")
    # now we are yikes if bug not fixed
    press_select()
    expect_ftux()


def test_custom_pushtx_url(goto_home, pick_menu_item, press_select, enter_complex,
                           cap_story, cap_menu, settings_remove, need_keypress,
                           press_cancel, is_q1, settings_get, OK):
    goto_home()
    settings_remove('ptxurl')  # empty slate

    pick_menu_item("Settings")
    pick_menu_item("NFC Push Tx")
    time.sleep(.1)
    title, story = cap_story()
    if title == "PUSH TX":
        assert "immediately broadcast" in story
        assert "tap any NFC-enabled phone on the COLDCARD" in story
        assert "choose a provider by URL here, or give your own URL" in story
        assert "transaction details could be linked by the service" in story
        press_select()

    time.sleep(.1)
    title, story = cap_story()
    if f"This feature requires NFC to be enabled. {OK} to enable" in story:
        press_select()

    time.sleep(.3)
    m = cap_menu()
    assert "coldcard.com" in m
    assert "mempool.space" in m
    assert "Custom URL..." in m
    assert "Disable" in m

    pick_menu_item("Custom URL...")
    time.sleep(.1)
    if not is_q1:
        # move to next char
        need_keypress("9")
        need_keypress("1")
    enter_complex("s://selfhosted.com/pushtx#", b39pass=False)
    time.sleep(.1)
    m = cap_menu()
    assert "selfhosted.com" in m
    assert settings_get('ptxurl') == "https://selfhosted.com/pushtx#"

    pick_menu_item("selfhosted.com")
    if is_q1:
        need_keypress(KEY_DELETE)
    else:
        need_keypress("1")  # get him to letters, so clean switch to symbols
    enter_complex("?", b39pass=False)
    time.sleep(.1)
    m = cap_menu()
    assert "selfhosted.com" in m
    assert settings_get('ptxurl') == "https://selfhosted.com/pushtx?"

    pick_menu_item("selfhosted.com")
    for _ in range(len("https://selfhosted.com/pushtx?") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("httphttps://a.com/pushtx#", b39pass=False)
    time.sleep(.1)
    title, story = cap_story()
    assert "Must start with http:// or https://." in story
    press_select()

    for _ in range(len("httphttps://a.com/pushtx#") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("http://sh.sk/ptx%", b39pass=False)

    time.sleep(.1)
    title, story = cap_story()
    assert "Final char must be # or ? or &." in story
    press_select()

    for _ in range(len("http://sh.sk/ptx%") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if not is_q1:
        need_keypress("1")

    enter_complex("http://s.s#", b39pass=False)

    time.sleep(.1)
    title, story = cap_story()
    assert "Too short." in story
    press_select()

    for _ in range(len("http://s.s#") - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    press_cancel()
    time.sleep(.1)
    press_select()
    time.sleep(.1)
    assert settings_get('ptxurl', None) is None


@pytest.mark.parametrize("fname,ftype", [
    ("ccbk-start.json", "J"),
    ("ckcc-backup.txt", "U"),
    ("devils-txn.txn", "T"),
    ("example-change.psbt", "P"),
    ("sim_conso5.psbt", "P"),  # binary psbt
    ("payjoin.psbt", "U"),  # base64 string in file
    ("worked-unsigned.psbt", "U"),  # hex string psbt
    ("coldcard-export.json", "J"),
    ("coldcard-export.sig", "U"),
])
def test_bbqr_share_files(fname, ftype, readback_bbqr, need_keypress, src_root_dir,
                          goto_home, pick_menu_item, is_q1, cap_menu, sim_root_dir):
    goto_home()
    if not is_q1:
        pick_menu_item("Advanced/Tools")
        pick_menu_item("File Management")
        assert "BBQr File Share" not in cap_menu()
        return

    fpath = f"{src_root_dir}/testing/data/" + fname
    shutil.copy2(fpath, f'{sim_root_dir}/MicroSD')
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("BBQr File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    file_type, rb = readback_bbqr()
    assert file_type == ftype
    with open(fpath, "rb") as f:
        res = f.read()

    assert res == rb
    os.remove(f'{sim_root_dir}/MicroSD/' + fname)

@pytest.mark.parametrize("fname", [
    "ccbk-start.json",
    "devils-txn.txn",
    "payjoin.psbt",  # base64 string in file
])
def test_qr_share_files(fname, pick_menu_item, goto_home, is_q1, cap_menu, cap_screen_qr,
                        src_root_dir, sim_root_dir):
    goto_home()
    if not is_q1:
        pick_menu_item("Advanced/Tools")
        pick_menu_item("File Management")
        assert "QR File Share" not in cap_menu()
        return

    fpath = f"{src_root_dir}/testing/data/" + fname
    shutil.copy2(fpath, f'{sim_root_dir}/MicroSD')
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("QR File Share")
    time.sleep(.1)
    pick_menu_item(fname)
    qr = cap_screen_qr()
    with open(fpath, "r") as f:
        res = f.read()

    assert res == qr.decode()
    os.remove(f'{sim_root_dir}/MicroSD/' + fname)

@pytest.mark.parametrize("word,cs_word", [
    # few combos with all words with length 8 + their longest possible checksum word
    ("acoustic", "decrease"),
    ("electric", "witness"),
    ("umbrella", "convince"),
    ("universe", "hamster"),
])
def test_q1_24_8char_words(set_seed_words, is_q1, goto_home, pick_menu_item, press_select,
                           cap_story, cap_screen, word, cs_word):
    # /issues/965
    # vectors calculated with `coldcard-mpy`:
    #
    #  w8 = [w for w in bip39.wordlist_en if len(w) >= 8]
    #  for w in w8:
    #      wl = ([w]*23)
    #      ds = list(bip39.a2b_words_guess(wl))
    #      print(w, max(ds, key=len))
    if not is_q1:
        raise pytest.skip("only Q")

    goto_home()
    # longest words in wordlist_en have 8 chars
    words = ([word] * 23) + [cs_word]
    set_seed_words(" ".join(words))

    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("Seed Functions")
    pick_menu_item('View Seed Words')
    time.sleep(.01)
    press_select()  # skip warning
    time.sleep(0.01)

    title, body = cap_story()
    assert '24' in title
    scr = cap_screen().split("\n")
    assert "Seed words (24)" in scr[0]
    assert scr[1] == ""
    # 8 rows
    assert len(scr[2:]) == 8

    x = 1
    y = 9
    z = 17
    for row in scr[2:]:
        # each row contains 3 colons (aka 3 words)
        srow = [r for r in row.split(" ") if r]  # filter empty strings
        assert len(srow) == 3  # three columns

        # 8 words for each column
        (tx, w0), (ty, w1), (tz, w2) = [pr.split(":") for pr in srow]
        assert x == int(tx) and y == int(ty) and z == int(tz)
        x += 1
        y += 1
        z += 1

        if int(tz) == 24:
            # last line with checksum word
            assert w2 == cs_word
            assert w0 == w1 == word
        else:
            assert w0 == w1 == w2 == word


def test_file_picker_suffixes(pick_menu_item, goto_home, cap_story, microsd_wipe, press_select,
                              microsd_path):
    # make sure no .txt, .7z & .pdf files are not on the SD card
    microsd_wipe()
    # create files that must not be recognized, because they're missing the dot
    for fn in ["backup7z", "backuptxt", "template:pdf"]:
        with open(microsd_path(fn), "w") as f:
            f.write("dummy")

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("I Am Developer.")
    pick_menu_item("Restore Bkup")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: *.7z,*.txt" in story
    press_select()

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Paper Wallets")
    press_select()
    pick_menu_item("Don't make PDF")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: *.pdf" in story

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("Sign Text File")
    time.sleep(.1)
    _, story = cap_story()
    assert "No suitable files found" in story
    assert "The filename must end in: *.txt,*.json" in story
    microsd_wipe()


@pytest.mark.onetime
def test_dump_menutree(sim_execfile):
    # saves to ../unix/work/menudump.txt
    sim_execfile('devtest/menu_dump.py')

if 0:
    # show what the final word can be (debug only) Mk4 only
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
