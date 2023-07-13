# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Ephemeral Seeds tests
#
import pytest, time, re, os, shutil
from constants import simulator_fixed_tpub
from ckcc.protocol import CCProtocolPacker
from txn import fake_txn
from test_ux import word_menu_entry


WORDLISTS = {
    12: ('abandon ' * 11 + 'about', '73C5DA0A'),
    18: ('abandon ' * 17 + 'agent', 'E08B8AC3'),
    24: ('abandon ' * 23 + 'art', '5436D724'),
}


def truncate_seed_words(words):
    if isinstance(words, str):
        words = words.split(" ")
    return ' '.join(w[0:4] for w in words)


def seed_story_to_words(story: str):
    # filter those that starts with space, number and colon --> actual words
    words = [
        line.strip().split(":")[1].strip()
        for line in story.split("\n")
        if re.search(r"\s\d:", line) or re.search(r"\d{2}:", line)
    ]
    return words


@pytest.fixture
def ephemeral_seed_disabled(cap_menu):
    def doit():
        time.sleep(0.1)
        menu = cap_menu()
        # no ephemeral seed chosen (yet)
        assert "[" not in menu[0]
    return doit


@pytest.fixture
def get_seed_value_ux(goto_home, pick_menu_item, need_keypress, cap_story, nfc_read_text):
    def doit(nfc=False):
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("Seed Functions")
        pick_menu_item('View Seed Words')
        time.sleep(.01)
        title, body = cap_story()
        assert 'Are you SURE' in body
        assert 'can control all funds' in body
        need_keypress('y')  # skip warning
        time.sleep(0.01)
        title, story = cap_story()
        if nfc:
            need_keypress("1")  # show QR code
            time.sleep(.1)
            need_keypress("3")  # any QR can be exported via NFC
            time.sleep(.1)
            str_words = nfc_read_text()
            time.sleep(.1)
            need_keypress("y")  # exit NFC animation
            return str_words.split(" ")  # always truncated
        words = seed_story_to_words(story)
        return words
    return doit


@pytest.fixture
def get_identity_story(goto_home, pick_menu_item, cap_story):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("View Identity")
        time.sleep(0.1)
        title, story = cap_story()
        return story
    return doit


@pytest.fixture
def goto_eph_seed_menu(goto_home, pick_menu_item, cap_story, need_keypress):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Ephemeral Seed")

        title, story = cap_story()
        if title == "WARNING":
            assert "temporary secret stored solely in device RAM" in story
            assert "Press (4) to prove you read to the end of this message and accept all consequences." in story
            need_keypress("4")  # understand consequences
    return doit


@pytest.fixture
def verify_ephemeral_secret_ui(cap_story, need_keypress, cap_menu, dev, fake_txn, try_sign,
                               goto_eph_seed_menu, reset_seed_words, get_identity_story,
                               get_seed_value_ux):
    def doit(mnemonic=None, xpub=None, expected_xfp=None):
        time.sleep(0.3)
        _, story = cap_story()
        in_effect_xfp = story[1:9]
        if expected_xfp is not None:
            assert in_effect_xfp == expected_xfp
        assert "key in effect until next power down." in story
        need_keypress("y")  # just confirm new master key message

        menu = cap_menu()
        assert menu[0] == "Ready To Sign"  # returned to main menu

        ident_story = get_identity_story()
        assert "Ephemeral seed is in effect" in ident_story

        ident_xfp = ident_story.split("\n\n")[1].strip()
        assert ident_xfp == in_effect_xfp

        if mnemonic:
            seed_words = get_seed_value_ux()
            assert mnemonic == seed_words

        e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
        assert e_master_xpub != simulator_fixed_tpub
        if xpub:
            assert e_master_xpub == xpub
        psbt = fake_txn(2, 2, master_xpub=e_master_xpub, segwit_in=True)
        try_sign(psbt, accept=True, finalize=True)  # MUST NOT raise
        need_keypress("y")

        goto_eph_seed_menu()
        time.sleep(0.1)
        menu = cap_menu()
        # ephemeral seed chosen -> [xfp] will be visible
        assert menu[0] == f"[{ident_xfp}]"

        reset_seed_words()

        goto_eph_seed_menu()
        menu = cap_menu()
        assert menu[0] != f"[{ident_xfp}]"
    return doit


@pytest.mark.parametrize("num_words", [12, 24])
@pytest.mark.parametrize("dice", [False, True])
def test_ephemeral_seed_generate(num_words, pick_menu_item, cap_story, need_keypress,
                                 reset_seed_words, goto_eph_seed_menu, dice,
                                 ephemeral_seed_disabled, verify_ephemeral_secret_ui):

    reset_seed_words()
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Generate Words")
    if not dice:
        pick_menu_item(f"{num_words} Words")
        time.sleep(0.1)
    else:
        pick_menu_item(f"{num_words} Word Dice Roll")
        for ch in '123456yy':
            need_keypress(ch)

    time.sleep(0.2)
    title, story = cap_story()
    assert f"Record these {num_words} secret words!" in story
    assert "Press (6) to skip word quiz" in story

    # filter those that starts with space, number and colon --> actual words
    e_seed_words = seed_story_to_words(story)
    assert len(e_seed_words) == num_words

    need_keypress("6")  # skip quiz
    need_keypress("y")  # yes - I'm sure
    time.sleep(0.1)
    need_keypress("4")  # understand consequences
    verify_ephemeral_secret_ui(mnemonic=e_seed_words)


@pytest.mark.parametrize("num_words", [12, 18, 24])
@pytest.mark.parametrize("nfc", [False, True])
@pytest.mark.parametrize("truncated", [False, True])
def test_ephemeral_seed_import_words(nfc, truncated, num_words, cap_menu, pick_menu_item,
                                     need_keypress, reset_seed_words, goto_eph_seed_menu,
                                     word_menu_entry, nfc_write_text, verify_ephemeral_secret_ui,
                                     ephemeral_seed_disabled, get_seed_value_ux):
    if truncated and not nfc: return


    words, expect_xfp = WORDLISTS[num_words]

    reset_seed_words()
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
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

    need_keypress("4")  # understand consequences

    verify_ephemeral_secret_ui(mnemonic=words.split(" "), expected_xfp=expect_xfp)

    nfc_seed = get_seed_value_ux(nfc=True)  # export seed via NFC (always truncated)
    seed_words = get_seed_value_ux()
    assert " ".join(nfc_seed) == truncate_seed_words(seed_words)


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('retry', range(3))
@pytest.mark.parametrize("testnet", [True, False])
def test_ephemeral_seed_import_tapsigner(way, retry, testnet, pick_menu_item, cap_story, enter_hex,
                                         need_keypress, reset_seed_words, goto_eph_seed_menu,
                                         verify_ephemeral_secret_ui, ephemeral_seed_disabled,
                                         nfc_write_text, tapsigner_encrypted_backup):
    reset_seed_words()

    fname, backup_key_hex, node = tapsigner_encrypted_backup(way, testnet=testnet)

    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if "press (3) to import via NFC" not in story:
            pytest.xfail("NFC disabled")
        else:
            need_keypress("3")
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
        _, story = cap_story()
        assert "Pick TAPSIGNER encrypted backup file" in story
        need_keypress("y")
        pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert "your TAPSIGNER" in story
    assert "back of the card" in story
    need_keypress("y")  # yes I have backup key
    enter_hex(backup_key_hex)
    verify_ephemeral_secret_ui(xpub=node.hwif())


@pytest.mark.parametrize("fail", ["wrong_key", "key_len", "plaintext", "garbage"])
def test_ephemeral_seed_import_tapsigner_fail(pick_menu_item, cap_story, fail,
                                              need_keypress, reset_seed_words, enter_hex,
                                              tapsigner_encrypted_backup, goto_eph_seed_menu,
                                              microsd_path, ephemeral_seed_disabled):
    reset_seed_words()
    fail_msg = "Decryption failed - wrong key?"
    fname, backup_key_hex, node = tapsigner_encrypted_backup("sd", testnet=False)
    if fail == "plaintext":
        with open(microsd_path(fname), "w") as f:
            f.write(node.hwif(True) + "\n")
    if fail == "garbage":
        with open(microsd_path(fname), "wb") as f:
            f.write(os.urandom(152))
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
        need_keypress("1")

    time.sleep(0.1)
    _, story = cap_story()
    assert "Pick TAPSIGNER encrypted backup file" in story
    need_keypress("y")
    pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert "Press OK to continue X to cancel." in story
    need_keypress("y")  # yes I have backup key
    if fail == "wrong_key":
        backup_key_hex = os.urandom(16).hex()
    if fail == "key_len":
        backup_key_hex = os.urandom(15).hex()
        fail_msg = "'Backup Key' length != 32"
    enter_hex(backup_key_hex)
    time.sleep(0.3)
    title, story = cap_story()
    assert title == "FAILURE"
    assert fail_msg in story
    need_keypress("x")
    need_keypress("x")


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
                                              ephemeral_seed_disabled):
    fname, backup_key_hex, pub = data
    fpath = microsd_path(fname)
    shutil.copy(f"data/{fname}", fpath)
    reset_seed_words()
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Tapsigner Backup")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import TAPSIGNER encrypted backup file from SD Card" in story:
        need_keypress("1")

    time.sleep(0.1)
    _, story = cap_story()
    assert "Pick TAPSIGNER encrypted backup file" in story
    need_keypress("y")
    pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    assert "Press OK to continue X to cancel." in story
    need_keypress("y")  # yes I have backup key
    enter_hex(backup_key_hex)
    verify_ephemeral_secret_ui(xpub=pub)
    os.unlink(fpath)


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('retry', range(3))
@pytest.mark.parametrize("testnet", [True, False])
def test_ephemeral_seed_import_xprv(way, retry, testnet, pick_menu_item,
                                    cap_story, need_keypress, reset_seed_words,
                                    goto_eph_seed_menu, nfc_write_text, microsd_path,
                                    virtdisk_path, verify_ephemeral_secret_ui,
                                    ephemeral_seed_disabled):
    reset_seed_words()
    fname = "ek.txt"
    from pycoin.key.BIP32Node import BIP32Node
    node = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN" if testnet else "BTC")
    ek = node.hwif(as_private=True) + '\n'
    if way =="sd":
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

    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    pick_menu_item("Import XPRV")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import extended private key file from SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if "press (3) to import via NFC" not in story:
            pytest.xfail("NFC disabled")
        else:
            need_keypress("3")
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
        _, story = cap_story()
        assert "Select file containing the extended private key" in story
        need_keypress("y")
        pick_menu_item(fname)

    verify_ephemeral_secret_ui(xpub=node.hwif())


def test_activate_current_tmp_secret(reset_seed_words, goto_eph_seed_menu,
                                     ephemeral_seed_disabled, cap_story,
                                     pick_menu_item, need_keypress,
                                     word_menu_entry):
    reset_seed_words()
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    ephemeral_seed_disabled()
    words, expected_xfp = WORDLISTS[12]
    pick_menu_item("Import Words")
    pick_menu_item(f"12 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())
    time.sleep(0.3)
    _, story = cap_story()
    assert "key in effect until next power down." in story
    in_effect_xfp = story[1:9]
    need_keypress("y")
    try:
        goto_eph_seed_menu()
    except:
        time.sleep(.1)
        goto_eph_seed_menu()

    pick_menu_item("Import Words")
    pick_menu_item(f"12 Words")
    time.sleep(0.1)

    word_menu_entry(words.split())
    time.sleep(0.3)
    _, story = cap_story()
    assert "Ephemeral master key already in use" in story
    already_used_xfp = story[1:9]
    assert already_used_xfp == in_effect_xfp == expected_xfp
    need_keypress("y")

# EOF
