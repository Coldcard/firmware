# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Testing backups.
#
import pytest, time, json, os, shutil, re
from constants import simulator_fixed_words, simulator_fixed_tprv
from charcodes import KEY_QR
from bip32 import BIP32Node
from mnemonic import Mnemonic


@pytest.fixture
def override_bkpw(goto_home, pick_menu_item, cap_story, need_keypress, seed_story_to_words,
                  cap_menu, press_select, press_cancel, enter_complex, is_q1):

    def purge_current(exit=False):
        time.sleep(.1)
        title, story = cap_story()
        if "(1) to forget current" in story:
            need_keypress("1")
            time.sleep(.1)
            title, story = cap_story()
            assert "Delete current stored password?" in story
            press_select()
            time.sleep(.1)
            title, story = cap_story()
            assert "(1) to forget current" not in story
            if exit:
                press_cancel()

    def doit(password=None, old_password=None):
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("I Am Developer.")
        pick_menu_item("BKPW Override")
        time.sleep(.1)
        title, story = cap_story()
        current_bkpw = None
        if "(2) to show current active backup password" in story:
            need_keypress("2")
            time.sleep(.1)
            title, story = cap_story()
            assert 'Anyone with knowledge of the password will be able to decrypt your backups.' in story
            press_select()
            time.sleep(.1)
            title, current_bkpw = cap_story()
            current_bkpw = current_bkpw.strip()
            press_select()

        if old_password:
            assert current_bkpw == old_password, "old_password mismatch"

        if password is None:
            # purge current bkpw
            purge_current(exit=True)
            return

        # purge what was there from before
        purge_current()

        need_keypress("0")
        enter_complex(password, apply=False, b39pass=False)

        time.sleep(.1)
        title, story = cap_story()
        assert "(2) to show current active backup password" in story
        need_keypress("2")
        press_select()  # are you sure?
        time.sleep(.1)
        title, story = cap_story()
        new_current_bkpw = story.strip()
        press_select()

        time.sleep(.1)
        title, story = cap_story()
        if ((3*" ") in password) and not is_q1:
            assert password.replace("   ", "  ") == new_current_bkpw
        else:
            assert new_current_bkpw == password

        assert "(1) to forget current password" in story
        assert "(0) to change" in story

    return doit

@pytest.fixture
def backup_system(settings_set, settings_remove, goto_home, pick_menu_item,
                  cap_story, need_keypress, cap_screen_qr, pass_word_quiz,
                  get_setting, seed_story_to_words, press_cancel, is_q1,
                  press_select, is_headless):
    def doit(reuse_pw=None, save_pw=False, st=None, ct=False):
        # st -> seed type
        # ct -> cleartext backup
        if reuse_pw:
            if isinstance(reuse_pw, list):
                assert len(reuse_pw) == 12
            else:
                assert reuse_pw is True  # default
                reuse_pw = ['zoo' for _ in range(12)]

            settings_set('bkpw', ' '.join(reuse_pw))
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
            assert (' 1: %s' % reuse_pw[0]) in body
            assert ('12: %s' % reuse_pw[-1]) in body
            press_select()
            words = ['zoo'] * 12
        else:
            assert title == 'NO-TITLE'
            assert 'Record this' in body
            assert 'password:' in body

            words = seed_story_to_words(body)

            assert len(words) == 12

            print("Passphrase: %s" % ' '.join(words))

            if 'QR Code' in body and not is_headless:
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
@pytest.mark.parametrize('reuse_pw', [True, False])
@pytest.mark.parametrize('save_pw', [False, True])
@pytest.mark.parametrize('seedvault', [False, True])
@pytest.mark.parametrize('pass_way', ["qr", None])
def test_make_backup(multisig, goto_home, pick_menu_item, cap_story, need_keypress, st,
                     open_microsd, microsd_path, unit_test, cap_menu, word_menu_entry,
                     pass_word_quiz, reset_seed_words, import_ms_wallet, get_setting,
                     reuse_pw, save_pw, settings_set, settings_remove, press_select,
                     generate_ephemeral_words, set_bip39_pw, verify_backup_file,
                     check_and_decrypt_backup, restore_backup_cs, clear_ms, seedvault,
                     restore_main_seed, import_ephemeral_xprv, backup_system,
                     press_cancel, sim_exec, pass_way, garbage_collector):
    # Make an encrypted 7z backup, verify it, and even restore it!
    clear_ms()
    reset_seed_words()
    settings_set("seedvault", int(seedvault))
    settings_set("seeds", [] if seedvault else None)

    # test larger backup files > 10,000 bytes
    if multisig == False and st == None and not reuse_pw and not save_pw and not seedvault:
        # pick just one test case.
        # - to bypass USB msg limit, append as we go
        print(">>> Making huge backup file")
        notes = []
        settings_set('notes', [])
        for n in range(9):
            v = { fld:('a'*30) if fld != 'misc' else 'b'*1800
                    for fld in ['user', 'password', 'site', 'misc'] }
            v['title'] = f'Note {n+1}'
            notes.append(v)
            rv = sim_exec(cmd := f'settings.current["notes"].append({v!r})')
            print(rv)
            assert 'error' not in rv.lower()
        rv = sim_exec(cmd := f'settings.changed()')
        assert 'error' not in rv.lower()
    else:
        notes = None

    # need to make multisig in my main wallet
    if multisig and st != "eph":
        import_ms_wallet(15, 15)
        press_select()
        time.sleep(.1)
        assert len(get_setting('multisig')) == 1

    if not reuse_pw:
        # drop saved bkpw before we get to ephemeral settings
        settings_remove("bkpw")

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

    if notes:
        # verify large notes survived
        rb_notes = get_setting('notes')
        assert rb_notes == notes

    files = []
    for copy in range(2):
        if copy == 1:
            title, body = cap_story()
            assert 'written:' in body

        fn = [ln.strip() for ln in body.split('\n') if ln.endswith('.7z')][0]

        print("filename %d: %s" % (copy, fn))

        files.append(fn)
        garbage_collector.append(microsd_path(fn))

        # write extra copy.
        if not copy:
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

    restore_backup_cs(files[0], words, avail_settings=avail_settings,
                      pass_way=pass_way)


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
    # assert target == contents
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

    # TODO check file made is a good backup, with correct password


def test_bkpw_override(reset_seed_words, override_bkpw, goto_home, pick_menu_item,
                       cap_story, press_select, garbage_collector, microsd_path,
                       restore_backup_cs):
    reset_seed_words()  # clean slate
    old_pw = None
    test_cases = [
        "arm prob slot merc hub fiel wing aver tale undo diar boos army cabl mous teac drif risk frow achi poet ecol boss grit",
        " ".join(12 * ["elevator"]),
        " ".join(12 * ["fever"]),
        32 * "a",
        (16 * "0") + "   " + (16 *"1"),
        64 * "Q",
        (26 * "?") + "!@#$%^&*()",
    ]
    fnames = []
    for pw in test_cases:
        override_bkpw(pw, old_pw)

        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Backup")
        pick_menu_item("Backup System")
        time.sleep(1)
        title, story = cap_story()
        split_pw = pw.split(" ")
        if len(split_pw) == 12:
            assert (' 1: %s' % split_pw[0]) in story
            assert ('12: %s' % split_pw[-1]) in story
        else:
            # not words of len 12
            assert ("%s...%s" % (pw[0], pw[-1])) in story

        press_select()
        time.sleep(1)
        title, story = cap_story()
        assert "Backup file written" in story
        fname = story.split("\n\n")[1]
        garbage_collector.append(microsd_path(fname))
        fnames.append(fname)
        press_select()

    for pw, fn in zip(test_cases, fnames):
        restore_backup_cs(fn, pw, custom_bkpw=True)

# EOF
