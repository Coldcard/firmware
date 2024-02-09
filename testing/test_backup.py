import pytest, time, json, os, shutil, re
from constants import simulator_fixed_words, simulator_fixed_tprv
from charcodes import KEY_QR
from pycoin.key.BIP32Node import BIP32Node
from mnemonic import Mnemonic


def decode_backup(txt):
    import json
    vals = dict()
    trimmed = dict()
    for ln in txt.split('\n'):
        if not ln: continue
        if ln[0] == '#': continue

        k, v = ln.split(' = ', 1)

        v = json.loads(v)

        if k.startswith('duress_') or k.startswith('fw_'):
            # no space in USB xfer for thesE!
            trimmed[k] = v
        else:
            vals[k] = v

    return vals, trimmed


@pytest.fixture
def backup_system(settings_set, settings_remove, goto_home, pick_menu_item,
                  cap_story, need_keypress, cap_screen_qr, pass_word_quiz,
                  get_setting, seed_story_to_words, press_cancel, is_q1,
                  press_select):
    def doit(reuse_pw=False, save_pw=False, st=None, ct=False):
        # st -> seed type
        # ct -> cleartext backup
        if reuse_pw:
            settings_set('bkpw', ' '.join('zoo' for _ in range(12)))
        else:
            settings_remove('bkpw')

        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Backup')
        pick_menu_item('Backup System')

        title, body = cap_story()
        if st:
            if st == "b39pass":
                assert "BIP39 passphrase is in effect" in body
                assert "ignores passphrases and produces backup of main seed" in body
                assert "(2) to back-up BIP39 passphrase wallet" in body
            if st == "eph":
                assert "A temporary seed is in effect" in body
                assert "so backup will be of that seed" in body

            press_select()
            time.sleep(.1)
            title, body = cap_story()

        if ct:
            # cleartext backup
            if ' 1: zoo' in body:
                press_cancel()

            need_keypress("6")
            time.sleep(.1)
            _, story = cap_story()
            assert "Are you SURE ?!?" in story
            assert "**NOT** be encrypted" in story
            press_select()
            return  # nothing more to be done

        if reuse_pw:
            assert ' 1: zoo' in body
            assert '12: zoo' in body
            press_select()
            words = ['zoo'] * 12

            time.sleep(0.1)
            title, body = cap_story()
        else:
            assert title == 'NO-TITLE'
            assert 'Record this' in body
            assert 'password:' in body

            words = seed_story_to_words(body)

            assert len(words) == 12

            print("Passphrase: %s" % ' '.join(words))

            if 'QR Code' in body:
                need_keypress(KEY_QR if is_q1 else '1')
                got_qr = cap_screen_qr().decode('ascii').lower().split()
                assert [w[0:4] for w in words] == got_qr
                press_select()

            # pass the quiz!
            count, title, body = pass_word_quiz(words)
            assert count >= 4
            assert "same words next time" in body
            assert "Press (1) to save" in body
            if save_pw:
                need_keypress('1')
                time.sleep(.1)

                assert get_setting('bkpw') == ' '.join(words)
            else:
                press_cancel()
                time.sleep(.01)
                assert get_setting('bkpw', 'xxx') == 'xxx'

        return words

    return doit


@pytest.mark.qrcode
@pytest.mark.parametrize('multisig', [False, 'multisig'])
@pytest.mark.parametrize('st', ["b39pass", "eph", None])
@pytest.mark.parametrize('reuse_pw', [False, True])
@pytest.mark.parametrize('save_pw', [False, True])
@pytest.mark.parametrize('seedvault', [False, True])
def test_make_backup(multisig, goto_home, pick_menu_item, cap_story, need_keypress, st,
                     open_microsd, microsd_path, unit_test, cap_menu, word_menu_entry,
                     pass_word_quiz, reset_seed_words, import_ms_wallet, get_setting,
                     cap_screen_qr, reuse_pw, save_pw, settings_set, settings_remove,
                     generate_ephemeral_words, set_bip39_pw, verify_backup_file,
                     check_and_decrypt_backup, restore_backup_cs, clear_ms, seedvault,
                     restore_main_seed, import_ephemeral_xprv, backup_system,
                     press_cancel, press_select):
    # Make an encrypted 7z backup, verify it, and even restore it!
    clear_ms()
    reset_seed_words()
    settings_set("seedvault", int(seedvault))
    settings_set("seeds", [] if seedvault else None)

    # need to make multisig in my main wallet
    if multisig and st != "eph":
        import_ms_wallet(15, 15)
        press_select()
        time.sleep(.1)
        assert len(get_setting('multisig')) == 1

    if st == "b39pass":
        xfp_pass = set_bip39_pw("coinkite", reset=False, seed_vault=seedvault)
        assert not get_setting('multisig', None)
    elif st == "eph":
        eph_seed = generate_ephemeral_words(num_words=24, dice=False, from_main=True,
                                            seed_vault=seedvault)
        if multisig:
            # make multisig in ephemeral wallet
            import_ms_wallet(15, 15, dev_key=True, common="605'/0'/0'")
            press_select()
            time.sleep(.1)
            assert len(get_setting('multisig')) == 1
    else:
        # create ephemeral seed - add to seed vault if necessary
        # and restore master (just so we have something in setting.seeds)
        node = import_ephemeral_xprv("sd", from_main=True, seed_vault=seedvault)
        restore_main_seed(seed_vault=seedvault, preserve_settings=True)

    words = backup_system(reuse_pw=reuse_pw, save_pw=save_pw, st=st)

    time.sleep(.1)
    title, body = cap_story()

    if st == "b39pass" and multisig:
        # correct settings switch back?
        # multisig is only in main wallet
        # must not be copied from main to b39pass
        # must not be available after backup done
        assert not get_setting('multisig', None)

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

    press_cancel()
    time.sleep(.01)

    verify_backup_file(fn)
    decrypted = check_and_decrypt_backup(fn, words)
    avail_settings = []
    if seedvault and (st in [None, "b39pass"]):
        assert "seedvault" in decrypted
        assert "seeds" in decrypted
        avail_settings.append("seeds")
        avail_settings.append("seedvault")
    else:
        assert "seedvault" not in decrypted
        assert "seeds" not in decrypted

    for i in range(10):
        press_cancel()
        time.sleep(.01)

    # test verify on device (CRC check)
    if multisig:
        avail_settings.append("multisig")

    restore_backup_cs(files[0], words, avail_settings=avail_settings)


@pytest.mark.parametrize("stype", ["words12", "words24", "xprv"])
def test_backup_ephemeral_wallet(stype, pick_menu_item, press_select, goto_home,
                                 cap_story, pass_word_quiz, get_setting,
                                 verify_backup_file, microsd_path, check_and_decrypt_backup,
                                 sim_execfile, unit_test, word_menu_entry, cap_menu,
                                 restore_backup_cs, generate_ephemeral_words, press_cancel,
                                 import_ephemeral_xprv, reset_seed_words, seed_story_to_words):
    reset_seed_words()
    goto_home()
    if "words" in stype:
        num_words = int(stype.replace("words", ""))
        sec = generate_ephemeral_words(num_words, from_main=True, seed_vault=False)
    else:
        sec = import_ephemeral_xprv("sd", from_main=True, seed_vault=False)

    target = sim_execfile('devtest/get-secrets.py')
    assert 'Error' not in target
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Backup")
    pick_menu_item("Backup System")
    time.sleep(.1)
    title, story = cap_story()
    assert "A temporary seed is in effect" in story
    assert "so backup will be of that seed" in story
    press_select()
    time.sleep(.1)
    title, story = cap_story()
    if "Use same backup file password as last time?" in story:
        press_cancel()
        time.sleep(.1)
        title, story = cap_story()
    assert title == 'NO-TITLE'
    assert 'Record this' in story
    assert 'password:' in story

    words = seed_story_to_words(story)

    assert len(words) == 12
    # pass the quiz!
    count, title, body = pass_word_quiz(words)
    assert count >= 4
    assert "same words next time" in body
    assert "Press (1) to save" in body
    press_cancel()
    time.sleep(.01)
    assert get_setting('bkpw', 'xxx') == 'xxx'
    title, story = cap_story()
    assert "Backup file written:" in story
    fn = story.split("\n\n")[1]
    assert fn.endswith(".7z")
    verify_backup_file(fn)
    contents = check_and_decrypt_backup(fn, words)
    if "words" in stype:
        assert "mnemonic" in contents
    else:
        assert "mnemonic" not in contents
    assert simulator_fixed_words not in contents
    assert simulator_fixed_tprv not in contents
    assert target == contents
    if "words" in stype:
        words_str = " ".join(sec)
        assert words_str in contents
        seed = Mnemonic.to_seed(words_str)
        expect = BIP32Node.from_master_secret(seed, netcode="XTN")
    else:
        expect = sec

    target_esk = None
    target_epk = None
    esk = expect.hwif(as_private=True)
    epk = expect.hwif(as_private=False)
    for line in contents.split("\n"):
        if line.startswith("xprv ="):
            target_esk = line.split("=")[-1].strip().replace('"', '')
        if line.startswith("xpub ="):
            target_epk = line.split("=")[-1].strip().replace('"', '')
    assert target_epk == epk
    assert target_esk == esk

    restore_backup_cs(fn, words)


@pytest.mark.parametrize('seedvault', [False, True])
@pytest.mark.parametrize("passphrase", ["@coinkite rulez!!", "!@#!@", "AAAAAAAAAAA"])
def test_backup_bip39_wallet(passphrase, set_bip39_pw, pick_menu_item, need_keypress,
                             goto_home, cap_story, pass_word_quiz, get_setting,
                             verify_backup_file, microsd_path, check_and_decrypt_backup,
                             sim_execfile, unit_test, word_menu_entry, cap_menu,
                             restore_backup_cs, seedvault, settings_set, reset_seed_words,
                             seed_story_to_words, press_cancel):
    reset_seed_words()
    goto_home()
    settings_set("seedvault", int(seedvault))
    settings_set("seeds", [] if seedvault else None)
    set_bip39_pw(passphrase, seed_vault=True)
    target = sim_execfile('devtest/get-secrets.py')
    assert 'Error' not in target
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Backup")
    pick_menu_item("Backup System")
    time.sleep(.1)
    title, story = cap_story()
    assert "BIP39 passphrase is in effect" in story
    assert "ignores passphrases and produces backup of main seed" in story
    assert "(2) to back-up BIP39 passphrase wallet" in story
    need_keypress("2")
    time.sleep(.1)
    title, story = cap_story()
    if "Use same backup file password as last time?" in story:
        press_cancel()
        time.sleep(.1)
        title, story = cap_story()
    assert title == 'NO-TITLE'
    assert 'Record this' in story
    assert 'password:' in story
    words = seed_story_to_words(story)
    assert len(words) == 12
    # pass the quiz!
    count, title, body = pass_word_quiz(words)
    assert count >= 4
    assert "same words next time" in body
    assert "Press (1) to save" in body
    press_cancel()
    time.sleep(.01)
    assert get_setting('bkpw', 'xxx') == 'xxx'
    title, story = cap_story()
    assert "Backup file written:" in story
    fn = story.split("\n\n")[1]
    assert fn.endswith(".7z")
    verify_backup_file(fn)
    contents = check_and_decrypt_backup(fn, words)
    assert "mnemonic" not in contents
    assert "seedvault" not in contents
    assert "seeds" not in contents
    assert simulator_fixed_words not in contents
    assert simulator_fixed_tprv not in contents
    assert target == contents
    seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=passphrase)
    expect = BIP32Node.from_master_secret(seed, netcode="XTN")
    esk = expect.hwif(as_private=True)
    epk = expect.hwif(as_private=False)
    target_esk = None
    target_epk = None
    for line in contents.split("\n"):
        if line.startswith("xprv ="):
            target_esk = line.split("=")[-1].strip().replace('"', '')
        if line.startswith("xpub ="):
            target_epk = line.split("=")[-1].strip().replace('"', '')
    assert target_epk == epk
    assert target_esk == esk

    restore_backup_cs(fn, words)


def test_trick_backups(goto_trick_menu, clear_all_tricks, repl, unit_test,
                       new_trick_pin, new_pin_confirmed, pick_menu_item,
                       press_select):

    from test_se2 import TC_REBOOT, TC_BLANK_WALLET

    clear_all_tricks()

    # - make wallets of all duress types (x2 each)
    # - plus a few simple ones
    # - perform a backup and check result

    for n in range(8):
        goto_trick_menu()
        pin = '123-%04d' % n
        new_trick_pin(pin, 'Duress Wallet', None)
        item = 'BIP-85 Wallet #%d' % (n % 4) if (n % 4 != 0) else 'Legacy Wallet'
        pick_menu_item(item)
        press_select()
        new_pin_confirmed(pin, item, None, None)

    for pin, op_mode, expect, _, xflags in [
        ('11-33', 'Just Reboot', 'Reboot when this PIN', False, TC_REBOOT),
        ('11-55', 'Look Blank', 'Look and act like a freshly', False, TC_BLANK_WALLET),
    ]:
        new_trick_pin(pin, op_mode, expect)
        new_pin_confirmed(pin, op_mode, xflags)

    # works, but not the best test
    # unit_test('devtest/backups.py')

    bk = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)

    assert 'Coldcard backup file' in bk

    # decode it
    vals, trimmed = decode_backup(bk)

    assert 'duress_xprv' in trimmed
    assert 'duress_1001_words' in trimmed
    assert 'duress_1002_words' in trimmed
    assert 'duress_1003_words' in trimmed

    unit_test('devtest/clear_seed.py')

    repl.exec(f'import backups; backups.restore_from_dict_ll({vals!r})')

    # recover from recovery
    repl.exec(f'import backups; pa.setup(pa.pin); pa.login(); from actions import goto_top_menu; goto_top_menu()')

    bk2 = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)
    assert 'Traceback' not in bk2

    vals2, tr2 = decode_backup(bk2)

    assert vals == vals2
    assert trimmed == tr2


def test_seed_vault_backup(settings_set, reset_seed_words, generate_ephemeral_words,
                           import_ephemeral_xprv, restore_main_seed, settings_get,
                           repl, pick_menu_item, press_cancel, cap_story, get_setting,
                           pass_word_quiz, verify_backup_file, check_and_decrypt_backup,
                           restore_backup_cs, cap_menu, verify_ephemeral_secret_ui,
                           seed_story_to_words):
    reset_seed_words()
    settings_set("seedvault", 1)
    settings_set("seeds", [])
    expect_count = 0
    ui_xfps = []
    for num_words in [12, 24]:
        mnemonic = generate_ephemeral_words(num_words=num_words, seed_vault=True)
        xfp = verify_ephemeral_secret_ui(mnemonic=mnemonic, seed_vault=True)
        ui_xfps.append(xfp)
        expect_count += 1

    # Ephemeral seeds - extended keys
    node = import_ephemeral_xprv("sd", seed_vault=True)
    xfp = verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=True)
    ui_xfps.append(xfp)
    expect_count += 1
    restore_main_seed(seed_vault=True)
    assert expect_count == 3
    assert len(ui_xfps) == expect_count
    # check all saved okay
    seeds = settings_get('seeds')
    assert len(seeds) == expect_count

    bk = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)
    assert 'Coldcard backup file' in bk

    pick_menu_item("Advanced/Tools")
    pick_menu_item("Backup")
    pick_menu_item("Backup System")

    time.sleep(.1)
    title, story = cap_story()
    if "Use same backup file password as last time?" in story:
        press_cancel()
        time.sleep(.1)
        title, story = cap_story()
    assert title == 'NO-TITLE'
    assert 'Record this' in story
    assert 'password:' in story
    words = seed_story_to_words(story)
    assert len(words) == 12
    # pass the quiz!
    count, title, body = pass_word_quiz(words)
    assert count >= 4
    assert "same words next time" in body
    assert "Press (1) to save" in body
    press_cancel()
    time.sleep(.01)
    assert get_setting('bkpw', 'xxx') == 'xxx'
    title, story = cap_story()
    assert "Backup file written:" in story
    fn = story.split("\n\n")[1]
    assert fn.endswith(".7z")
    verify_backup_file(fn)
    contents = check_and_decrypt_backup(fn, words)
    assert "mnemonic" in contents
    assert simulator_fixed_words in contents
    assert simulator_fixed_tprv in contents
    assert "setting.seedvault = 1" in contents
    assert "setting.seeds" in contents

    restore_backup_cs(fn, words)
    time.sleep(.2)
    m = cap_menu()
    assert "Seed Vault" in m
    pick_menu_item('Seed Vault')
    m = cap_menu()
    assert len(m) == expect_count
    sv_xfp_menu = [i.split(" ")[-1][1:-1] for i in m]
    for xfp_ui in ui_xfps:
        assert xfp_ui in sv_xfp_menu


def test_seed_vault_backup_frozen(reset_seed_words, settings_set, repl):
    from test_ephemeral import SEEDVAULT_TEST_DATA

    reset_seed_words()
    settings_set("seedvault", 1)

    sv = []
    for item in SEEDVAULT_TEST_DATA:
        xfp, entropy, mnemonic = item

        # build stashed encoded secret
        entropy_bytes = bytes.fromhex(entropy)
        if mnemonic:
            vlen = len(entropy_bytes)
            assert vlen in [16, 24, 32]
            marker = 0x80 | ((vlen // 8) - 2)
            stored_secret = bytes([marker]) + entropy_bytes
        else:
            stored_secret = entropy_bytes

        sv.append((xfp, stored_secret.hex(), f"[{xfp}]", "meta"))

    settings_set("seeds", sv)
    bk = repl.exec('import backups; RV.write(backups.render_backup_contents())', raw=1)
    assert 'Coldcard backup file' in bk
    target = json.dumps(sv)
    assert target in bk


def test_clone_start(reset_seed_words, pick_menu_item, cap_story, goto_home):
    sd_dir = "../unix/work/MicroSD"
    num_7z = len([i for i in os.listdir(sd_dir) if i.endswith(".7z")])
    fname = "ccbk-start.json"
    reset_seed_words()
    goto_home()
    shutil.copy(f"data/{fname}", sd_dir)
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Backup")
    pick_menu_item("Clone Coldcard")
    time.sleep(1)
    title, story = cap_story()
    assert "Done" in story
    assert "Take this MicroSD card back to other Coldcard" in story
    goto_home()
    assert len([i for i in os.listdir(sd_dir) if i.endswith(".7z")]) > num_7z
    os.remove(f"{sd_dir}/{fname}")