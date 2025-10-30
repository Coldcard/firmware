# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Ephemeral Seeds tests
#

import pytest, time, re, os, shutil, pdb, hashlib
from constants import simulator_fixed_tpub, simulator_fixed_xfp, simulator_fixed_xpub
from constants import simulator_fixed_words, simulator_fixed_tprv
from ckcc.protocol import CCProtocolPacker
from txn import fake_txn
from bip32 import BIP32Node
from helpers import xfp2str, a2b_hex
from charcodes import KEY_CLEAR, KEY_NFC


WORDLISTS = {
    12: ('abandon ' * 11 + 'about', '73C5DA0A'),
    18: ('abandon ' * 17 + 'agent', 'E08B8AC3'),
    24: ('abandon ' * 23 + 'art', '5436D724'),
}

SEEDVAULT_TEST_DATA = [
    ["47649253", "344f9dc08e88b8a46d4b8f46c4e6bb6c",
     "crowd language ice brown merit fall release impose egg cheese put suit"],
    ["CC7BB706", "88f53ed897cc371ffe4b715c267206f3286ed2f655ba9d68",
     "material prepare renew convince sell morning weird hotel found crime like town manage harvest sun resemble output dolphin"],
    ["AC39935C", "956f484cc2136178fd1ad45faeb54972c829f65aad0d74eb2541b11984655893",
     "nice kid basket loud current round virtual fold garden interest false tortoise little will height payment insane float expire giraffe obscure crawl girl glare"],
    ['939B32C4',
     '017caa3142d48791f837b42fcd7a98662f9fb4101a15ae87cdbc1fecc96f33c11ffcefd8121daaba0625c918a335a0712b8c35c2da60e6fc6eef78b7028f4be02a',
     None],  # BIP-85 -> BIP-32 -> #23
]

@pytest.fixture
def seed_vault_enable(cap_story, pick_menu_item, press_select, goto_home,
                      settings_set):
    def doit(enable=True):
        
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("Seed Vault")
        time.sleep(.1)
        _, story = cap_story()
        if "Enable Seed Vault?" in story:
            press_select()

        if enable:
            pick_menu_item("Enable")
        else:
            pick_menu_item("Default Off")
            time.sleep(.2)
            _, story = cap_story()
            if "Please remove all seeds from the vault" in story:
                press_select()
                settings_set("seeds", [])
                pick_menu_item("Seed Vault")
                time.sleep(.1)
                pick_menu_item("Default Off")

        time.sleep(.1)

    return doit

def truncate_seed_words(words):
    if isinstance(words, str):
        words = words.split(" ")
    return ' '.join(w[0:4] for w in words)


@pytest.fixture
def ephemeral_seed_disabled(sim_exec):
    def doit():
        rv = sim_exec('from pincodes import pa; RV.write(repr(pa.tmp_value))')
        assert not eval(rv)
    return doit


@pytest.fixture
def ephemeral_seed_disabled_ui(cap_menu):
    def doit():
        # MUST be in ephemeral seed menu already
        time.sleep(0.1)
        menu = cap_menu()
        # no ephemeral seed chosen (yet)
        assert "[" not in menu[0]
    return doit


@pytest.fixture
def get_seed_value_ux(goto_home, pick_menu_item, need_keypress, cap_story,
                      nfc_read_text, seed_story_to_words, press_nfc, press_select):
    def doit(nfc=False):
        
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("Seed Functions")
        pick_menu_item('View Seed Words')
        time.sleep(.1)
        title, body = cap_story()
        assert ('Are you SURE' in body) or ('Are you SURE' in title)
        assert 'can control all funds' in body
        press_select()  # skip warning
        time.sleep(0.1)
        title, story = cap_story()

        if nfc:
            need_keypress("1")  # show QR code
            time.sleep(.2)
            press_nfc()  # any QR can be exported via NFC
            time.sleep(.2)
            str_words = nfc_read_text()
            time.sleep(.5)
            press_select()  # exit NFC animation
            return str_words.split(" ")  # always truncated

        return seed_story_to_words(story)
    return doit


@pytest.fixture
def get_identity_story(goto_home, pick_menu_item, cap_story):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("View Identity")
        time.sleep(0.1)
        title, story = cap_story()
        split_story = story.split("\n\n")
        parsed_story = {}
        if "is in effect" in split_story[0]:
            parsed_story["tmp"] = True
            if "BIP-39 passphrase" in split_story[0]:
                passphrase = True
            else:
                passphrase = False
                assert "Temporary seed" in split_story[0]
            parsed_story["pass"] = passphrase
            parsed_story["xfp"] = split_story[2].strip()
            parsed_story["ek"] = split_story[6].strip()
        else:
            assert "Master Key Fingerprint" in split_story[0]
            parsed_story["xfp"] = split_story[1].strip()
            parsed_story["ek"] = split_story[5].strip()
        return story, parsed_story
    return doit


@pytest.fixture
def goto_eph_seed_menu(goto_home, pick_menu_item, cap_story, need_keypress, is_q1):
    def _doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Temporary Seed")

        title, story = cap_story()
        if title == "WARNING":
            assert "Temporary seed is a secret completely separate from the master seed" in story
            assert "typically held in device RAM" in story
            assert "not persisted between reboots in the Secure Element." in story
            assert "Enable the Seed Vault feature to store these secrets longer-term." in story
            assert "Press (4) to prove you read to the end of this message and accept all consequences." in story
            need_keypress("4")  # understand consequences

    def doit():
        try:
            _doit()
        except:
            time.sleep(.1)
            _doit()

    return doit


@pytest.fixture
def restore_main_seed(goto_home, pick_menu_item, cap_story, cap_menu,
                      need_keypress, settings_slots, press_select, OK):

    def doit(preserve_settings=False, seed_vault=False):
        if seed_vault:
            preserve_settings = True

        prev = len(settings_slots())
        goto_home()
        menu = cap_menu()
        assert menu[-1] == "Restore Master"
        assert (menu[0][0] == "[") and (menu[0][-1] == "]")
        pick_menu_item("Restore Master")
        time.sleep(.1)
        title, story = cap_story()

        assert "Restore main wallet and its settings?" in story
        if seed_vault:
            assert f"Press {OK} to forget current temporary seed " not in story
            assert "settings, or press (1) to save & keep " not in story
        else:
            assert f"Press {OK} to forget current temporary seed " in story
            assert "settings, or press (1) to save & keep " in story
            assert "those settings if same seed is later restored." in story

        if preserve_settings and not seed_vault:
            need_keypress("1")
        else:
            press_select()

        time.sleep(.3)

        menu = cap_menu()
        assert menu[-1] != "Restore Master"
        assert (menu[0][0] != "[") and (menu[0][-1] != "]")

        after = len(settings_slots())
        if preserve_settings:
            assert prev <= after, "p%d == a%d" % (prev, after)
        else:
            assert prev > after, "p%d > a%d" % (prev, after)

    return doit


@pytest.fixture
def confirm_tmp_seed(need_keypress, cap_story, press_select):
    def doit(seedvault=False, expect_xfp=None, check_sv_not_offered=False):
        
        time.sleep(0.3)
        title, story = cap_story()

        if check_sv_not_offered:
            assert "to store temporary seed into Seed Vault" not in story

        if "Press (1) to store temporary seed into Seed Vault" in story:
            if seedvault:
                need_keypress("1")  # store it
                time.sleep(.1)
                title, story = cap_story()
                assert "Saved to Seed Vault" in story
                if expect_xfp is not None:
                    assert expect_xfp in story

                press_select()
            else:
                press_select()  # do not store

            time.sleep(.2)
            title, story = cap_story()

        if expect_xfp is not None:
            assert expect_xfp in title
        else:
            expect_xfp = title[1:-1]

        assert "New temporary master key is in effect now." in story
        press_select()
        return expect_xfp

    return doit


@pytest.fixture
def seed_vault_delete(pick_menu_item, need_keypress, cap_menu, cap_story,
                      goto_home, press_select, settings_get):
    def doit(xfp, wipe=True):
        # delete it from records
        goto_home()
        pick_menu_item("Seed Vault")
        time.sleep(.1)
        m = cap_menu()
        target_sv_mi = None
        for mi in m:
            if xfp in mi:
                pick_menu_item(mi)
                target_sv_mi = mi
                break
        else:
            assert False
        pick_menu_item("Delete")
        time.sleep(.1)
        title, story = cap_story()
        assert "Remove" in story
        assert xfp in title

        if wipe:
            press_select()
        else:
            if xfp2str(settings_get("xfp")) == xfp:
                assert "press (1)" not in story
                press_select()  # will NOT wipe settings
            else:
                assert "press (1)" in story
                # preserve settings - remove just from seed vaul
                need_keypress("1")

        time.sleep(.1)
        goto_home()
        pick_menu_item("Seed Vault")
        time.sleep(.1)
        m = cap_menu()
        assert target_sv_mi
        assert target_sv_mi not in m
    return doit


@pytest.fixture
def verify_ephemeral_secret_ui(cap_story, cap_menu, dev, fake_txn, goto_home,
                               get_identity_story, try_sign, get_seed_value_ux,
                               pick_menu_item):
    def doit(mnemonic=None, xpub=None, expected_xfp=None, seed_vault=False,
             testnet=True, is_b39pw=False):

        goto_home()
        menu = cap_menu()

        if expected_xfp:
            assert expected_xfp in menu[0]
        else:
            assert menu[0].startswith("[")  # ephemeral xfp

        in_effect_xfp = menu[0][1:-1]

        assert menu[1] == "Ready To Sign"  # returned to main menu
        assert menu[-1] == "Restore Master"  # restore main from ephemeral

        if seed_vault:
            pick_menu_item("Seed Vault")
            time.sleep(.1)
            sc_menu = cap_menu()
            assert "Restore Master" in sc_menu
            item = [i for i in sc_menu if in_effect_xfp in i][0]
            pick_menu_item(item)
            time.sleep(.1)
            m = cap_menu()
            assert "Delete" in m
            assert "Rename" in m
            assert len(m) == 4

            assert "Seed In Use" in m
            pick_menu_item("Seed In Use")  # noop
        elif seed_vault is False:
            # Seed Vault disabled
            m = cap_menu()
            assert "Seed Vault" not in m

        ident_story, parsed_ident = get_identity_story()
        ident_xfp = parsed_ident["xfp"]
        assert parsed_ident["tmp"]
        if is_b39pw:
            assert parsed_ident["pass"]

        assert ident_xfp == in_effect_xfp

        if mnemonic:
            seed_words = get_seed_value_ux()
            assert mnemonic == seed_words

        e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
        assert e_master_xpub != (simulator_fixed_tpub if testnet else simulator_fixed_xpub)
        if xpub:
            assert e_master_xpub == xpub
        psbt = fake_txn(2, 2, master_xpub=e_master_xpub, segwit_in=True)
        try_sign(psbt, accept=True, finalize=True)  # MUST NOT raise
        return in_effect_xfp

    return doit


@pytest.fixture
def generate_ephemeral_words(goto_eph_seed_menu, pick_menu_item, press_select,
                             need_keypress, cap_story, settings_set, seed_story_to_words,
                             ephemeral_seed_disabled_ui, confirm_tmp_seed, is_q1):
    def doit(num_words, dice=False, from_main=False, seed_vault=None, testnet=True):
        if testnet:
            netcode = "XTN"
        else:
            netcode = "BTC"

        settings_set("chain", netcode)

        goto_eph_seed_menu()
        if from_main:
            ephemeral_seed_disabled_ui()

        pick_menu_item("Generate Words")
        if not dice:
            pick_menu_item(f"{num_words} Words")
            time.sleep(0.1)
        else:
            pick_menu_item(f"{num_words} Word Dice Roll")
            for ch in '123456\r\r':
                need_keypress(ch)

        time.sleep(0.2)
        title, story = cap_story()
        assert f"Record these {num_words} secret words!" in (title if is_q1 else story)
        assert "Press (6) to skip word quiz" in story

        # filter those that starts with space, number and colon --> actual words
        e_seed_words = seed_story_to_words(story)
        assert len(e_seed_words) == num_words

        need_keypress("6")  # skip quiz
        time.sleep(.1)
        press_select()  # yes - I'm sure
        confirm_tmp_seed(seedvault=seed_vault)

        return e_seed_words

    return doit


@pytest.fixture
def import_ephemeral_xprv(microsd_path, virtdisk_path, goto_eph_seed_menu,
                          pick_menu_item, need_keypress, cap_story, settings_set,
                          nfc_write_text, ephemeral_seed_disabled_ui, confirm_tmp_seed,
                          press_nfc, press_select, is_q1):
    def doit(way, extended_key=None, testnet=True, seed_vault=False, from_main=False):
        if testnet:
            netcode = "XTN"
        else:
            netcode = "BTC"

        settings_set("chain", netcode)

        fname = "ek.txt"
        if extended_key is None:
            node = BIP32Node.from_master_secret(os.urandom(32), netcode=netcode)
            ek = node.hwif(as_private=True) + '\n'
        else:
            node = BIP32Node.from_wallet_key(extended_key)
            assert extended_key == node.hwif(as_private=True)
            ek = extended_key

        if way == "sd":
            fpath = microsd_path(fname)
        elif way == "vdisk":
            fpath = virtdisk_path(fname)
        if way != "nfc":
            with open(fpath, "w") as f:
                f.write(ek)

        if testnet:
            assert "tprv" in ek
        else:
            assert "xprv" in ek

        goto_eph_seed_menu()
        if from_main:
            ephemeral_seed_disabled_ui()

        pick_menu_item("Import XPRV")
        time.sleep(0.1)
        _, story = cap_story()
        if way == "sd":
            if "Press (1) to import extended private key file from SD Card" in story:
                need_keypress("1")
        elif way == "nfc":
            if f"press {KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
                pytest.xfail("NFC disabled")
            else:
                press_nfc()
                time.sleep(0.2)
                nfc_write_text(ek)
                time.sleep(0.3)
        else:
            # virtual disk
            if "press (2) to import from Virtual Disk" not in story:
                pytest.xfail("Vdisk disabled")
            else:
                need_keypress("2")

        if way != "nfc":
            time.sleep(0.1)
            pick_menu_item(fname)

        confirm_tmp_seed(expect_xfp=node.fingerprint().hex().upper(),
                         seedvault=seed_vault)

        return node

    return doit


@pytest.mark.parametrize("num_words", [12, 24])
@pytest.mark.parametrize("dice", [False, True])
@pytest.mark.parametrize("seed_vault", [False, True])
@pytest.mark.parametrize("preserve_settings", [False, True])
def test_ephemeral_seed_generate(num_words, generate_ephemeral_words, dice,
                                 reset_seed_words, goto_eph_seed_menu, seed_vault,
                                 ephemeral_seed_disabled, verify_ephemeral_secret_ui,
                                 preserve_settings, seed_vault_enable, seed_vault_delete,
                                 restore_main_seed):
    reset_seed_words()
    goto_eph_seed_menu()
    ephemeral_seed_disabled()
    seed_vault_enable(seed_vault)
    e_seed_words = generate_ephemeral_words(num_words=num_words, dice=dice,
                                            from_main=True, seed_vault=seed_vault)
    xfp = verify_ephemeral_secret_ui(mnemonic=e_seed_words, seed_vault=seed_vault)
    if seed_vault:
        seed_vault_delete(xfp, not preserve_settings)
    else:
        restore_main_seed(preserve_settings)


@pytest.mark.parametrize("num_words", [12, 18, 24])
@pytest.mark.parametrize("nfc", [False, True])
@pytest.mark.parametrize("truncated", [False, True])
@pytest.mark.parametrize("preserve_settings", [False, True])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_words(nfc, truncated, num_words, cap_menu, pick_menu_item,
                                     reset_seed_words, goto_eph_seed_menu,
                                     word_menu_entry, nfc_write_text, verify_ephemeral_secret_ui,
                                     ephemeral_seed_disabled, get_seed_value_ux, seed_vault,
                                     settings_set, cap_story, preserve_settings, seed_vault_enable,
                                     seed_vault_delete, restore_main_seed, confirm_tmp_seed):
    if truncated and not nfc: return

    words, expect_xfp = WORDLISTS[num_words]

    reset_seed_words()
    seed_vault_enable(seed_vault)
    goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Import Words")

    if not nfc:
        pick_menu_item(f"{num_words} Words")
        time.sleep(0.1)

        word_menu_entry(words.split())
    else:
        menu = cap_menu()
        if 'Import via NFC' not in menu:
            raise pytest.xfail("NFC not enabled")
        pick_menu_item('Import via NFC')

        if truncated:
            truncated_words = truncate_seed_words(words)
            nfc_write_text(truncated_words)
        else:
            nfc_write_text(words)
        time.sleep(.5)

    confirm_tmp_seed(seedvault=seed_vault)

    xfp = verify_ephemeral_secret_ui(mnemonic=words.split(" "), expected_xfp=expect_xfp,
                                     seed_vault=seed_vault)

    nfc_seed = get_seed_value_ux(nfc=True)  # export seed via NFC (always truncated)
    seed_words = get_seed_value_ux()
    assert " ".join(nfc_seed) == truncate_seed_words(seed_words)

    if seed_vault:
        seed_vault_delete(xfp, not preserve_settings)
    else:
        restore_main_seed(preserve_settings)


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize("testnet", [True, False])
@pytest.mark.parametrize("preserve_settings", [False, True])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_tapsigner(way, testnet, pick_menu_item, cap_story, enter_hex,
                                         need_keypress, reset_seed_words, goto_eph_seed_menu,
                                         verify_ephemeral_secret_ui, ephemeral_seed_disabled,
                                         nfc_write_text, tapsigner_encrypted_backup, seed_vault,
                                         preserve_settings, seed_vault_enable, settings_set,
                                         seed_vault_delete, restore_main_seed, confirm_tmp_seed,
                                         is_q1, press_select, press_nfc):
    
    reset_seed_words()
    if testnet:
        netcode = "XTN"
    else:
        netcode = "BTC"

    settings_set("chain", netcode)

    seed_vault_enable(seed_vault)

    fname, backup_key_hex, node = tapsigner_encrypted_backup(way, testnet=testnet)

    goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"press {KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.xfail("NFC disabled")
        else:
            press_nfc()
            time.sleep(0.2)
            nfc_write_text(fname)
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to import from Virtual Disk" not in story:
            pytest.xfail("Vdisk disabled")
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

    confirm_tmp_seed(expect_xfp=node.fingerprint().hex().upper(),
                     seedvault=seed_vault)

    xfp = verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=seed_vault,
                                     testnet=testnet)
    if seed_vault:
        seed_vault_delete(xfp, not preserve_settings)
    else:
        restore_main_seed(preserve_settings)


@pytest.mark.parametrize("fail", ["wrong_key", "key_len", "plaintext", "garbage"])
def test_ephemeral_seed_import_tapsigner_fail(pick_menu_item, cap_story, fail, cap_screen,
                                              need_keypress, reset_seed_words, enter_hex,
                                              tapsigner_encrypted_backup, goto_eph_seed_menu,
                                              microsd_path, ephemeral_seed_disabled, OK, X,
                                              settings_set, press_select, press_cancel):
    
    
    reset_seed_words()
    settings_set("seedvault", None)
    fail_msg = "Decryption failed - wrong key?"
    fname, backup_key_hex, node = tapsigner_encrypted_backup("sd", testnet=False)
    if fail == "plaintext":
        with open(microsd_path(fname), "w") as f:
            f.write(node.hwif(True) + "\n")
    if fail == "garbage":
        with open(microsd_path(fname), "wb") as f:
            f.write(os.urandom(152))

    goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
        need_keypress("1")

    time.sleep(0.1)
    pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert f"Press {OK} to continue {X} to cancel." in story
    press_select()  # yes I have backup key
    if fail == "wrong_key":
        backup_key_hex = os.urandom(16).hex()
    if fail == "key_len":
        backup_key_hex = os.urandom(15).hex()
        fail_msg = "'Backup Key' length != 32"

    enter_hex(backup_key_hex)
    time.sleep(0.3)

    if fail == "key_len":
        assert "Need 32" in cap_screen()
        press_cancel()
        return

    title, story = cap_story()
    assert title == "FAILURE"
    assert fail_msg in story
    press_cancel()
    press_cancel()


@pytest.mark.parametrize("data", [
    (
        "backup-4VMI3-2023-02-15T1645.aes",
        "cb5bec9ddea4e85558bb54f41dcb1d2e",
        "xpub661MyMwAqRbcFkTtUfByC6u46vJtdw6xFHUFhjc2AvA16BJCUPoeuwQcthN6yshHR34WZBT5gsHYVtha2QD9j9QozJf9ENeHS6TDgSAFBeX"
    ),
    (
        "backup-O4MZA-2023-02-15T2250.aes",
        "578efa5d6803e3c314a98a87d499ce97",
        "xpub661MyMwAqRbcGBeMu9h1B222hQmc4XkXasbN4F3mDGTWRJ11UQ5orWv41FPVK7stXsS9UtR5DBTArBvcsHPiCE2E1PAdqq1UQiQTYmrEEaa"
    ),
])
def test_ephemeral_seed_import_tapsigner_real(data, pick_menu_item, cap_story, microsd_path,
                                              need_keypress, reset_seed_words, enter_hex,
                                              goto_eph_seed_menu, verify_ephemeral_secret_ui,
                                              ephemeral_seed_disabled, settings_set, OK, X,
                                              confirm_tmp_seed, restore_main_seed, press_select):
    
    fname, backup_key_hex, pub = data
    fpath = microsd_path(fname)
    shutil.copy(f"data/{fname}", fpath)
    reset_seed_words()
    settings_set("seedvault", None)
    goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
        need_keypress("1")

    time.sleep(0.1)
    pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert f"Press {OK} to continue {X} to cancel." in story
    press_select()  # yes I have backup key
    enter_hex(backup_key_hex)
    confirm_tmp_seed(seedvault=False)
    verify_ephemeral_secret_ui(xpub=pub)
    os.unlink(fpath)
    restore_main_seed(False)


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize("testnet", [True, False])
@pytest.mark.parametrize("preserve_settings", [False, True])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_xprv(way, testnet, reset_seed_words,
                                    goto_eph_seed_menu, verify_ephemeral_secret_ui,
                                    ephemeral_seed_disabled, import_ephemeral_xprv,
                                    preserve_settings, seed_vault, seed_vault_enable,
                                    seed_vault_delete, restore_main_seed, confirm_tmp_seed):
    reset_seed_words()
    goto_eph_seed_menu()
    seed_vault_enable(seed_vault)
    ephemeral_seed_disabled()
    node = import_ephemeral_xprv(way=way, testnet=testnet, from_main=True,
                                 seed_vault=seed_vault)
    xfp = verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=seed_vault,
                                     testnet=testnet)
    if seed_vault:
        seed_vault_delete(xfp, not preserve_settings)
    else:
        restore_main_seed(preserve_settings)


@pytest.mark.parametrize("seed_vault", [True, False])
def test_activate_current_tmp_secret(reset_seed_words, goto_eph_seed_menu,
                                     ephemeral_seed_disabled, cap_story,
                                     pick_menu_item, press_select,
                                     word_menu_entry, settings_set,
                                     seed_vault, seed_vault_enable,
                                     confirm_tmp_seed, is_q1):
    reset_seed_words()
    seed_vault_enable(seed_vault)

    goto_eph_seed_menu()
    ephemeral_seed_disabled()
    words, expected_xfp = WORDLISTS[12]
    pick_menu_item("Import Words")
    pick_menu_item(f"12 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())

    in_effect_xfp = confirm_tmp_seed(seedvault=seed_vault)
    goto_eph_seed_menu()

    pick_menu_item("Import Words")
    pick_menu_item(f"12 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())
    time.sleep(0.2)
    title, story = cap_story()

    assert "Temporary master key already in use" in story
    assert title == "FAILED"
    assert in_effect_xfp == expected_xfp
    press_select()


@pytest.mark.parametrize('data', SEEDVAULT_TEST_DATA)
def test_seed_vault_menus(dev, data, settings_set, master_settings_get, pick_menu_item,
                          need_keypress, cap_story, cap_menu, reset_seed_words,
                          get_identity_story, get_seed_value_ux, fake_txn, try_sign,
                          sim_exec, goto_home, seed_vault_enable, is_q1, enter_text,
                          press_select, press_cancel, press_delete):
    # Verify "seed vault" feature works as intended
    reset_seed_words()
    xfp, entropy, mnemonic = data

    # build stashed encoded secret
    entropy_bytes = bytes.fromhex(entropy)
    if mnemonic:
        vlen = len(entropy_bytes)
        assert vlen in [16, 24, 32]
        marker = 0x80 | ((vlen // 8) - 2)
        stored_secret = bytes([marker]) + entropy_bytes
    else:
        stored_secret = entropy_bytes

    settings_set("seedvault", None)
    settings_set("seeds", [(xfp, stored_secret.hex(), f"[{xfp}]", "meta")])

    # enable Seed Vault
    goto_home()
    seed_vault_enable(True)
    time.sleep(.1)
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    m = cap_menu()
    assert len(m) == 1
    assert xfp in m[0]
    pick_menu_item(m[0])

    # Now in submenu for saved seed

    # view details.
    pick_menu_item('[%s]' % xfp)
    _, story = cap_story()
    assert xfp in story
    if mnemonic:
        assert ('%d words' % (6 * (vlen // 8))) in story
    else:
        assert 'xprv' in story
    press_cancel()

    # rename
    pick_menu_item("Rename")
    if not is_q1:
        for _ in range(len(xfp) + 1):  # [xfp]
            press_delete()

        # below should yield AAAA
        need_keypress("1")
        for _ in range(3):
            need_keypress("9")  # next char
            need_keypress("1")  # letters

        press_select()
    else:
        need_keypress(KEY_CLEAR)
        enter_text('AAAA')

    m = cap_menu()
    assert m[0] == "AAAA"

    pick_menu_item("AAAA")  # bug issues/920
    # would be yikes here, if not fixed
    time.sleep(.1)
    _, story = cap_story()
    assert "AAAA" in story
    assert xfp in story
    if mnemonic:
        assert ('%d words' % (6 * (vlen // 8))) in story
    else:
        assert 'xprv' in story
    press_cancel()

    # check parent menu - must be updated too
    press_cancel()
    m = cap_menu()
    for item in m:
        if "AAAA" in item:
            break
    else:
        assert False

    # go back
    press_select()
    pick_menu_item("Use This Seed")
    time.sleep(.1)
    title, story = cap_story()
    assert xfp in title
    assert 'temporary master key is in effect now' in story
    press_select()
    active = get_seed_value_ux()
    if mnemonic:
        assert active == mnemonic.split()
    else:
        assert active[1:4] == 'prv'
        node = BIP32Node.from_hwif(active)
        ch, pk = entropy_bytes[1:33], entropy_bytes[33:65]
        assert node.chain_code() == ch
        assert bytes(node.node.private_key) == pk

    istory, parsed_ident = get_identity_story()
    assert parsed_ident["tmp"] and not parsed_ident["pass"]

    ident_xfp = parsed_ident["xfp"]
    assert ident_xfp == xfp

    e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
    assert e_master_xpub != simulator_fixed_tpub
    psbt = fake_txn(2, 2, master_xpub=e_master_xpub, segwit_in=True)
    try_sign(psbt, accept=True, finalize=True)  # MUST NOT raise
    press_select()

    encoded = sim_exec('from pincodes import pa; RV.write(repr(pa.fetch()))')
    assert 'Error' not in encoded
    encoded = eval(encoded)
    assert len(encoded) == 72
    assert encoded[0:len(stored_secret)] == stored_secret

    # check rename worked
    seeds = master_settings_get("seeds")
    assert len(seeds) == 1
    entry = seeds[0]
    assert len(entry) == 4
    assert entry[0] == xfp
    assert entry[1] == stored_secret.hex()
    assert entry[2] == "AAAA"

    reset_seed_words()
    time.sleep(.2)
    goto_home()


def test_seed_vault_captures(request, dev, settings_set, settings_get, pick_menu_item,
                             cap_story, reset_seed_words, fake_txn, master_settings_get,
                             generate_ephemeral_words, goto_home, get_secrets,
                             import_ephemeral_xprv, set_bip39_pw, restore_main_seed,
                             restore_seed_xor, derive_bip85_secret, activate_bip85_ephemeral,
                             seed_vault_enable, is_q1, press_select, press_down):
    # Capture seeds by all the different paths and verify correct values are captured.
    # - BIP-85 -> 12, 24 words
    # - BIP-85 -> xprv (BIP-32)
    # - XOR seed restore
    # - Ephemeral keys menu: random and import
    # - Capture a BIP-39 passphrase into words
    # - Trick pin -> duress wallet * 4 options
    # Then, verify those can all co-exist and be recalled correctly.
    

    reset_seed_words()
    seed_vault_enable(True)
    settings_set("seeds", [])
    expect_count = 0

    if 1:
        # BIP39 Passphrase
        set_bip39_pw('dogsNcats', seed_vault=True, reset=False)
        expect_count += 1
        restore_main_seed(seed_vault=True)

    if 1:
        # Trick Pin -> duress wallet
        from test_se2 import build_duress_wallets
        expect_count += build_duress_wallets(request, seed_vault=True)

    if 1:
        # Seed XOR of 12words into 3 parts... not simple, kinda slow
        xor_parts, xor_expect = (
            ['become wool crumble brand camera cement gloom sell stand once connect stage',
             'save saddle indicate embrace detail weasel spread life staff mushroom bicycle light',
             'unlock damp injury tape enhance pause sheriff onion valley panic finger moon'],
            'drama jeans craft mixture filter lamp invest suggest vacant neutral history swim')

        restore_seed_xor(xor_parts, xor_expect, incl_self=None, save_to_vault=True)

        # check was saved
        expect_count += 1
        restore_main_seed(seed_vault=True)

    if 1:
        # Create via BIP-85
        for mode in ['12 words', '18 words', '24 words', 'XPRV (BIP-32)']:
            do_import, story = derive_bip85_secret(mode, index=74, chain="XTN")
            activate_bip85_ephemeral(do_import, reset=False, save_to_vault=True)

            expect_count += 1

        restore_main_seed(seed_vault=True)

    if 1:
        # Ephemeral seeds - generated words (behaves same as imported words)
        for num_words in [12, 24]:
            generate_ephemeral_words(num_words=num_words, seed_vault=True)
            expect_count += 1

        # Ephemeral seeds - extended keys
        import_ephemeral_xprv("sd", seed_vault=True)
        expect_count += 1
        restore_main_seed(seed_vault=True)

    # check all saved okay
    seeds = master_settings_get('seeds')
    n_seeds = len(seeds)
    assert n_seeds == expect_count

    # Switch to each one
    for i, obj in enumerate(seeds):
        xfp, encoded_sec, name, meta = obj
        pick_menu_item("Seed Vault")
        for _ in range(i):
            press_down()  # go down
        press_select()
        pick_menu_item('Use This Seed')
        time.sleep(0.1)

        title, story = cap_story()
        assert 'New temporary master key' in story
        assert 'power down' not in story
        assert xfp in title
        press_select()  # confirm activation of ephemeral secret

        assert xfp2str(settings_get('xfp')) == xfp

        raw = get_secrets()['raw_secret']
        if len(raw) % 2:
            raw += '0'

        assert raw == encoded_sec

    if 1:
        # cleanup
        reset_seed_words()
        settings_set("seedvault", None)
        settings_set("seeds", [])


def test_seed_vault_modifications(settings_set, reset_seed_words, pick_menu_item,
                                  generate_ephemeral_words, import_ephemeral_xprv,
                                  goto_home, cap_story, cap_menu, restore_main_seed,
                                  need_keypress, seed_vault_enable, is_q1, do_keypresses,
                                  press_select, press_cancel, press_down, press_delete):
    reset_seed_words()
    seed_vault_enable(True)
    settings_set("seeds", [])

    generate_ephemeral_words(num_words=24, seed_vault=True)
    generate_ephemeral_words(num_words=12, seed_vault=True)
    import_ephemeral_xprv("sd", seed_vault=True)
    import_ephemeral_xprv("sd", seed_vault=True)

    goto_home()
    pick_menu_item("Seed Vault")
    m = cap_menu()
    # 4 entries + Restore Master (as we are in ephemeral)
    assert len(m) == 5

    # restore to main seed
    restore_main_seed(seed_vault=True, preserve_settings=True)

    time.sleep(.1)
    m = cap_menu()
    # no ephemeral xfp at the top
    assert m[0] == "Ready To Sign"
    pick_menu_item("Seed Vault")
    # we are no longer in ephemral
    assert "Restore Master" not in m
    # first entry in menu
    press_select()
    m = cap_menu()
    assert "Rename" in m
    assert "Use This Seed" in m  # we are in master - so this must be there
    assert "Delete" in m

    # delete entry 0
    pick_menu_item("Delete")
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert len(m) == 3

    # first entry again
    press_select()
    pick_menu_item("Rename")
    for _ in range(10 if is_q1 else 9):
        press_delete()

    if is_q1:
        do_keypresses("AA")
    else:
        need_keypress("1")  # big letters
        need_keypress("9")
        need_keypress("1")
        # name changed to AA

    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert m[0] == "AA"
    assert "Rename" in m
    assert "Use This Seed" in m  # we are in master - so this must be there
    assert "Delete" in m

    # go back
    press_cancel()
    # second item
    press_down()
    press_select()
    time.sleep(.1)
    pick_menu_item("Use This Seed")
    title, _ = cap_story()
    press_select()  # confirm new eph
    time.sleep(.1)
    m = cap_menu()
    assert m[0] == title
    pick_menu_item("Seed Vault")
    press_down()
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert "Rename" in m
    assert "Seed In Use" in m
    assert "Delete" in m

    pick_menu_item("Rename")
    for _ in range(10 if is_q1 else 9):
        press_delete()

    if is_q1:
        do_keypresses("AAA")
    else:
        need_keypress("1")  # big letters
        need_keypress("9")
        need_keypress("1")
        need_keypress("9")
        need_keypress("1")
    # name changed to AAA
    press_select()

    time.sleep(.1)
    m = cap_menu()
    assert m[0] == "AAA"
    pick_menu_item("Delete")
    time.sleep(.1)
    title, story = cap_story()
    # current active does not offer to purge the slot, only to remove from Seed Vault
    assert "delete its settings?" not in story
    press_select()
    time.sleep(.1)
    goto_home()
    m = cap_menu()
    # still in tmp mode
    assert m[0] != "Ready To Sign"
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    m = cap_menu()
    # Ignore Add Current and Restore Master (only SV items are numbered with colon)
    assert len([mi for mi in m if ":" in mi]) == 2

    press_down()
    press_select()
    pick_menu_item("Use This Seed")
    title, _ = cap_story()
    press_select()  # confirm new eph
    time.sleep(.1)
    m = cap_menu()
    assert m[0] == title
    pick_menu_item("Seed Vault")
    press_down()
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert "Rename" in m
    assert "Seed In Use" in m
    assert "Delete" in m

    pick_menu_item("Delete")
    time.sleep(.1)
    _, story = cap_story()
    assert "delete its settings?" not in story
    press_select()  # only delete from seed vault, no other option provided
    time.sleep(.1)
    m = cap_menu()
    assert len(m) == 3
    assert "Add current tmp" in m
    press_select()
    # this is now different eph - modification not allowed
    time.sleep(.1)
    m = cap_menu()
    assert "Rename" not in m
    assert "Delete" not in m
    assert "Use This Seed" in m
    goto_home()
    time.sleep(.1)
    m = cap_menu()
    # still in ephemeral
    assert title == m[0]

    restore_main_seed()
    pick_menu_item("Seed Vault")
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert "Rename" in m
    assert "Use This Seed" in m
    assert "Delete" in m

    pick_menu_item("Delete")
    time.sleep(.1)
    _, story = cap_story()
    assert "delete its settings?" in story
    need_keypress("1")  # only remove from seed vault, keep settings
    time.sleep(.1)
    m = cap_menu()
    assert all([":" not in mi for mi in m])
    assert "(none saved yet)" in m


def test_xfp_collision(reset_seed_words, settings_set, import_ephemeral_xprv,
                       cap_story, press_cancel, pick_menu_item, cap_menu,
                       seed_vault_enable):

    node = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN")
    xfp = node.fingerprint().hex().upper()
    k0 = node.hwif(as_private=True)

    # change chain code but presevre public key
    node.node.chain_code = hashlib.sha256(node.node.chain_code).digest()
    k1 = node.hwif(as_private=True)
    assert k1 != k0

    reset_seed_words()
    seed_vault_enable(True)
    settings_set("seeds", [])

    import_ephemeral_xprv("sd", extended_key=k0, seed_vault=True, from_main=True)

    import_ephemeral_xprv("sd", extended_key=k1, seed_vault=True, from_main=False)

    pick_menu_item("Seed Vault")
    m = cap_menu()
    assert len(m) == 3  # two seeds and Restore Master
    # same master fingerprints
    assert xfp in m[0]
    assert xfp in m[1]
    # but only second is in use
    pick_menu_item(m[1])
    time.sleep(.1)
    sm = cap_menu()
    assert "Seed In Use" in sm
    assert "Use This Seed" not in sm
    press_cancel()  # go back
    pick_menu_item(m[0])
    time.sleep(.1)
    sm = cap_menu()
    assert "Seed In Use" not in sm
    assert "Use This Seed" in sm


@pytest.mark.parametrize("refuse", [False, True])
def test_add_current_active(reset_seed_words, settings_set, import_ephemeral_xprv,
                            goto_home, pick_menu_item, cap_story, cap_menu,
                            press_cancel, verify_ephemeral_secret_ui, is_q1,
                            seed_vault_enable, refuse, press_select, set_bip39_pw,
                            need_some_notes, need_some_passwords, import_ms_wallet,
                            restore_main_seed, settings_get, clear_ms):
    ADD_MI = "Add current tmp"

    reset_seed_words()
    goto_home()
    seed_vault_enable(True)
    # clear
    settings_set("seeds", [])
    clear_ms()
    settings_set("notes", [])

    if not refuse:
        # add something to seed vault
        sv_pass_xfp = set_bip39_pw('dogsNcats', seed_vault=True, reset=False)
        restore_main_seed(seed_vault=True)

        # add secure notes and passwords
        if is_q1:
            need_some_notes()
            need_some_passwords()

        # save multisig wallet to master settings
        ms_name = "aaa"
        import_ms_wallet(2,3,"p2wsh", name=ms_name, accept=True)

        time.sleep(.2)
        goto_home()

    # in master - do not offer
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    m = cap_menu()
    assert ADD_MI not in m
    goto_home()

    node = import_ephemeral_xprv("sd", seed_vault=False, from_main=True)
    xfp = node.fingerprint().hex().upper()
    pick_menu_item("Seed Vault")
    m = cap_menu()
    assert ADD_MI in m
    for mi in m:
        assert xfp not in mi

    pick_menu_item(ADD_MI)
    time.sleep(.1)
    title, story = cap_story()
    assert xfp in title
    assert "Add to Seed Vault?" in story
    if refuse:
        press_cancel()
        time.sleep(.1)
        m = cap_menu()
        assert ADD_MI in m
        for mi in m:
            assert xfp not in mi
    else:
        press_select()
        verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=True)
        restore_main_seed(seed_vault=True)
        time.sleep(.2)
        curr_xfp = settings_get("xfp", None)
        assert curr_xfp is not None
        assert curr_xfp != 0
        mss = settings_get("multisig")
        assert len(mss) == 1
        assert  mss[0][0] == ms_name
        if is_q1:
            assert len(settings_get("notes")) == 3
        sv = settings_get("seeds")
        assert len(sv) == 2
        assert sv[0][0] == xfp2str(sv_pass_xfp)  # added passphrase wallet
        assert sv[1][0] == xfp  # added via `Add current tmp`


@pytest.mark.parametrize('multisig', [True, False])
@pytest.mark.parametrize('seedvault', [False, True])
@pytest.mark.parametrize('data', SEEDVAULT_TEST_DATA)
def test_temporary_from_backup(multisig, backup_system, import_ms_wallet, get_setting,
                               data, press_select, cap_story, set_encoded_secret,
                               reset_seed_words, check_and_decrypt_backup, clear_ms,
                               goto_eph_seed_menu, pick_menu_item, word_menu_entry,
                               verify_ephemeral_secret_ui, seedvault, settings_set,
                               seed_vault_enable, confirm_tmp_seed, set_seed_words,
                               seed_vault_delete, restore_main_seed, settings_slots):

    xfp_str, encoded_str, mnemonic = data
    if mnemonic:
        set_seed_words(mnemonic)
    else:
        encoded = a2b_hex(encoded_str)
        set_encoded_secret(encoded)

    settings_set("chain", "XTN")
    clear_ms()

    if multisig:
        import_ms_wallet(15, 15, dev_key=True)
        press_select()
        time.sleep(.1)
        assert len(get_setting('multisig')) == 1
    else:
        assert get_setting('multisig') is None

    # ACTUAL BACKUP
    bk_pw = backup_system()
    time.sleep(.1)
    title, story = cap_story()
    fname = story.split("\n\n")[1]

    check_and_decrypt_backup(fname, bk_pw)

    # remove all saved slots, one of them will be the one where we just created backup
    # slot where backup was created needs to be removed - otherwise we will load back to it
    # and see multisig wallet there without the need for backup to actually copy it
    for s in settings_slots():
        try:
            os.remove(s)
        except: pass

    # restore fixed simulator
    reset_seed_words()
    seed_vault_enable(seedvault)

    goto_eph_seed_menu()
    pick_menu_item("Coldcard Backup")

    time.sleep(.1)
    pick_menu_item(fname)

    word_menu_entry(bk_pw, has_checksum=False)

    time.sleep(.5)
    title, story = cap_story()
    assert f"[{xfp_str}]" == title
    assert "Above is the master fingerprint of the seed stored in the backup." in story
    assert f"load backup as temporary seed" in story
    press_select()

    confirm_tmp_seed(seedvault)

    time.sleep(.1)
    if mnemonic:
        mnemonic = mnemonic.split(" ")

    xfp = verify_ephemeral_secret_ui(mnemonic=mnemonic, xpub=None, # XPUB verify ephemeral secret not tested here
                                     seed_vault=seedvault)

    # actual bug, multisig key copied with "setting." prefix -> therefore not visible in Multisig menu
    assert get_setting("setting.multisig") is None
    # correct multisig was copied during loading backup as tmp seed
    ms = get_setting('multisig')
    if multisig:
        assert len(ms) == 1
        assert ms[0][1] == [15,15]
    else:
        assert ms is None

    if seedvault:
        seed_vault_delete(xfp, True)
    else:
        restore_main_seed(False)

@pytest.mark.parametrize('btype', ["classic", "custom_bkpw", "plaintext"])
def test_temporary_from_backup_usb(backup_system, set_seed_words, cap_story, verify_ephemeral_secret_ui,
                                   settings_slots, reset_seed_words, word_menu_entry, confirm_tmp_seed,
                                   dev, microsd_path, press_select, btype, enter_complex):

    xfp_str, encoded_str, mnemonic = SEEDVAULT_TEST_DATA[0]
    set_seed_words(mnemonic)
    bkpw = 32*"X"
    plaintext = (btype == "plaintext")
    password = False

    # ACTUAL BACKUP
    if plaintext:
        bk_pw = backup_system(ct=True)
    elif btype == "custom_bkpw":
        # encrypted but with custom pwd
        password = True
        bk_pw = backup_system(reuse_pw=[bkpw])
    else:
        # classic word-based encrypted backup
        bk_pw = backup_system()

    time.sleep(.1)
    title, story = cap_story()
    fname = story.split("\n\n")[1]

    # remove all saved slots, one of them will be the one where we just created backup
    # slot where backup was created needs to be removed - otherwise we will load back to it
    # and see multisig wallet there without the need for backup to actually copy it
    for s in settings_slots():
        try:
            os.remove(s)
        except: pass

    # restore fixed simulator
    reset_seed_words()

    from ckcc_protocol.protocol import CCProtocolPacker
    with open(microsd_path(fname), "rb") as f:
        file_len, sha = dev.upload_file(f.read())

    dev.send_recv(CCProtocolPacker.restore_backup(file_len, sha, password, plaintext), timeout=None)
    time.sleep(.2)
    _, story = cap_story()
    assert "Restore uploaded backup as a temporary seed" in story
    press_select()

    time.sleep(.1)
    if btype == "classic":
        word_menu_entry(bk_pw, has_checksum=False)
    elif password:
        enter_complex(bkpw, apply=False, b39pass=False)

    time.sleep(.5)
    title, story = cap_story()
    assert f"[{xfp_str}]" == title
    assert "Above is the master fingerprint of the seed stored in the backup." in story
    assert f"load backup as temporary seed" in story
    press_select()

    time.sleep(.1)
    confirm_tmp_seed(seedvault=False)
    time.sleep(.1)
    mnemonic = mnemonic.split(" ")
    verify_ephemeral_secret_ui(mnemonic=mnemonic, xpub=None, seed_vault=False)


def test_tmp_upgrade_disabled(reset_seed_words, pick_menu_item, cap_story,
                              cap_menu, goto_home, unit_test,
                              import_ephemeral_xprv):
    reset_seed_words()
    goto_home()
    pick_menu_item("Advanced/Tools")
    time.sleep(.1)
    m = cap_menu()
    assert "Upgrade Firmware" in m
    node = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN")
    k0 = node.hwif(as_private=True)
    import_ephemeral_xprv("sd", extended_key=k0, seed_vault=True, from_main=True)
    goto_home()
    pick_menu_item("Advanced/Tools")
    time.sleep(.1)
    m = cap_menu()
    assert "Upgrade Firmware" not in m

    # Virgin CC
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'
    goto_home()
    pick_menu_item("Advanced/Tools")
    time.sleep(.1)
    m = cap_menu()
    assert "Upgrade Firmware" in m
    import_ephemeral_xprv("sd", extended_key=k0, seed_vault=True, from_main=True)
    goto_home()
    pick_menu_item("Advanced/Tools")
    time.sleep(.1)
    m = cap_menu()
    assert "Upgrade Firmware" not in m


def test_import_master_as_tmp(reset_seed_words, goto_eph_seed_menu, cap_story,
                              ephemeral_seed_disabled, pick_menu_item, goto_home,
                              need_keypress, word_menu_entry, settings_set,
                              confirm_tmp_seed, cap_menu, microsd_path,
                              restore_main_seed, get_identity_story, press_select,
                              press_cancel, settings_remove):
    
    
    reset_seed_words()
    # disable seed vault
    settings_remove("seedvault")
    settings_remove("seeds")

    goto_eph_seed_menu()
    ephemeral_seed_disabled()

    # try import same seed as current simulator master
    words, expected_xfp = simulator_fixed_words, simulator_fixed_xfp
    xfp_str = xfp2str(expected_xfp)
    pick_menu_item("Import Words")
    pick_menu_item(f"24 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())
    time.sleep(.1)
    title, story = cap_story()
    assert "FAILED" == title
    assert 'Cannot use master seed as temporary.' in story
    assert 'tested recovery of your master seed' in story
    press_cancel()

    # go to ephemeral seed and then try to create new ephemeral seed from master
    # when in different temporary seed whatsoever
    goto_eph_seed_menu()

    # random temporary seed
    pick_menu_item("Generate Words")
    pick_menu_item(f"12 Words")
    need_keypress("6")  # skip quiz
    press_select()  # yes - I'm sure
    confirm_tmp_seed(seedvault=False)

    goto_home()
    time.sleep(0.1)
    menu = cap_menu()
    # ephemeral seed chosen
    assert "[" in menu[0]
    goto_eph_seed_menu()
    pick_menu_item("Import Words")
    pick_menu_item(f"24 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())
    time.sleep(.1)
    title, story = cap_story()
    assert "FAILED" == title
    assert 'Cannot use master seed as temporary.' in story
    assert 'tested recovery of your master seed' in story
    press_cancel()

    # now import same seed but represented as master extended key
    # this works and does not delete master settings as encoded
    # secret is different and therefore nvram_key too
    fname = "ek_sim.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(simulator_fixed_tprv)

    goto_eph_seed_menu()
    pick_menu_item("Import XPRV")
    title, story = cap_story()
    if "Press (1)" in story:
        need_keypress("1")

    pick_menu_item(fname)
    confirm_tmp_seed(seedvault=False)  # allowed

    # verify we are in temporary seed
    goto_home()
    time.sleep(0.1)
    menu = cap_menu()
    # ephemeral seed chosen
    assert "[" in menu[0]
    assert xfp_str in menu[0]
    restore_main_seed(preserve_settings=False, seed_vault=False)
    story, parsed_ident = get_identity_story()
    assert xfp_str == parsed_ident["xfp"]

def test_home_menu_xfp(goto_home, pick_menu_item, press_select, cap_story, cap_menu,
                       settings_get, goto_eph_seed_menu, need_keypress):
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Home Menu XFP")
    time.sleep(.1)
    _, story = cap_story()
    if "Forces display of XFP" in story:
        press_select()
    pick_menu_item("Always Show")
    time.sleep(.3)
    m = cap_menu()
    assert m[0] == "<" + xfp2str(settings_get("xfp")) + ">"
    assert m[1] == "Ready To Sign"

    goto_eph_seed_menu()
    pick_menu_item("Generate Words")
    pick_menu_item(f"12 Words")
    time.sleep(0.1)
    need_keypress("6")  # skip quiz
    press_select()

    time.sleep(.1)
    _, story = cap_story()
    if "Press (1) to store temporary seed" in story:
        # seed vault enabled
        press_select()  # do not save
    press_select()  # new tmp seed

    time.sleep(.2)
    m = cap_menu()
    assert m[1] == "Ready To Sign"
    assert m[0] == "[" + xfp2str(settings_get("xfp")) + "]"
    pick_menu_item("Restore Master")
    press_select()

    time.sleep(.3)
    m = cap_menu()
    assert m[1] == "Ready To Sign"
    assert m[0] == "<" + xfp2str(settings_get("xfp")) + ">"
    # disable now
    pick_menu_item("Settings")
    pick_menu_item("Home Menu XFP")

    time.sleep(.1)
    _, story = cap_story()
    if "Forces display of XFP" in story:
        press_select()
    pick_menu_item("Only Tmp")

    time.sleep(.3)
    m = cap_menu()
    assert m[0] == "Ready To Sign"


def test_seed_vault_enable_on_tmp(generate_ephemeral_words, reset_seed_words,
                                  goto_eph_seed_menu, ephemeral_seed_disabled,
                                  verify_ephemeral_secret_ui, goto_home, cap_menu,
                                  restore_main_seed, pick_menu_item, settings_remove):
    reset_seed_words()
    # disable seed vault
    settings_remove("seedvault")
    settings_remove("seeds")
    goto_eph_seed_menu()
    ephemeral_seed_disabled()
    e_seed_words = generate_ephemeral_words(num_words=12, dice=False,
                                            from_main=True, seed_vault=False)
    verify_ephemeral_secret_ui(mnemonic=e_seed_words, seed_vault=False)
    goto_home()
    pick_menu_item("Advanced/Tools")
    m = cap_menu()
    assert "Seed Vault" not in m

# EOF
