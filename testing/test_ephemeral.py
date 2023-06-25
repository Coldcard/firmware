# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Ephemeral Seeds tests
#
import pytest, time, re, os, shutil

from constants import simulator_fixed_xpub
from ckcc.protocol import CCProtocolPacker
from txn import fake_txn
from test_ux import word_menu_entry
from pycoin.key.BIP32Node import BIP32Node
from helpers import xfp2str


def truncate_seed_words(words):
    if isinstance(words, str):
        words = words.split(" ")
    return ' '.join(w[0:4] for w in words)


def seed_story_to_words(story: str):
    # filter those that starts with space, number and colon --> actual words
    # NOTE: will show xprv/tprv in full if we are not storing
    #       words (ie. BIP-32 loaded as master secret). So just return that string.
    if story[1:4] == 'prv':
        return story.split()[0]

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
def verify_ephemeral_secret_ui(cap_story, need_keypress, cap_menu, dev, goto_home, pick_menu_item,
                               fake_txn, try_sign, goto_eph_seed_menu, reset_seed_words,
                               get_identity_story, get_seed_value_ux):
    def doit(mnemonic=None, xpub=None, seed_vault=False):
        time.sleep(0.3)
        _, story = cap_story()
        in_effect_xfp = story[1:9]
        assert "key in effect until next power down." in story
        need_keypress("y")  # just confirm new master key message

        menu = cap_menu()
        assert menu[0] == "Ready To Sign"  # returned to main menu

        if seed_vault:
            # check exactly one seed is saved, then delete it
            pick_menu_item("Seed Vault")
            time.sleep(.1)
            sc_menu = cap_menu()
            assert len(sc_menu) == 1  # stored seed
            pick_menu_item(sc_menu[0])
            time.sleep(.1)
            m = cap_menu()
            assert "Use This Seed" in m
            assert "Delete" in m
            assert "Rename" in m
            assert len(m) == 4  # xfp is top item (works same as "Use this seed")
            # apply it - even if it is applied already
            pick_menu_item("Use This Seed")
            time.sleep(.1)
            _, story = cap_story()
            assert "Press (1)" not in story
            assert "key in effect until next power down." in story
            assert in_effect_xfp in story
            need_keypress("y")
            pick_menu_item("Seed Vault")
            pick_menu_item(sc_menu[0])
            time.sleep(.1)
            # delete it from records
            pick_menu_item("Delete")
            time.sleep(.1)
            _, story = cap_story()
            assert "Delete" in story
            assert in_effect_xfp in story
            need_keypress("y")
            time.sleep(.1)
            m = cap_menu()
            assert "(none saved yet)" in m
            assert len(m) == 1
        else:
            # Seed Vault disabled
            m = cap_menu()
            assert "Seed Vault" not in m

        ident_story = get_identity_story()
        assert "Ephemeral seed is in effect" in ident_story

        ident_xfp = ident_story.split("\n\n")[1].strip()
        assert ident_xfp == in_effect_xfp

        if mnemonic:
            seed_words = get_seed_value_ux()
            assert mnemonic == seed_words

        e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
        assert e_master_xpub != simulator_fixed_xpub
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
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_generate(num_words, pick_menu_item, goto_home, cap_story, need_keypress,
                                 reset_seed_words, goto_eph_seed_menu, dice, ephemeral_seed_disabled,
                                 verify_ephemeral_secret_ui, seed_vault, settings_set, settings_get):
    reset_seed_words()
    if seed_vault:
        settings_set("seedvault", True)
    else:
        settings_set("seedvault", None)
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

    if seed_vault:
        time.sleep(0.1)
        _, story = cap_story()
        assert "Press (1) to store ephemeral secret into Seed Vault" in story
        need_keypress("1")  # store it
        need_keypress("y")  # confirm saved to Seed Vault

    verify_ephemeral_secret_ui(mnemonic=e_seed_words, seed_vault=seed_vault)


@pytest.mark.parametrize("num_words", [12, 18, 24])
@pytest.mark.parametrize("nfc", [False, True])
@pytest.mark.parametrize("truncated", [False, True])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_words(nfc, truncated, num_words, cap_menu, pick_menu_item, goto_home,
                                     cap_story, need_keypress, reset_seed_words, goto_eph_seed_menu,
                                     word_menu_entry, nfc_write_text, verify_ephemeral_secret_ui,
                                     ephemeral_seed_disabled, get_seed_value_ux, seed_vault,
                                     settings_set, skip_nfc_check=False):
    if truncated and not nfc: return

    wordlists = {
        12: ( 'abandon ' * 11 + 'about', 0x0adac573),
        18: ( 'abandon ' * 17 + 'agent', 0xc38a8be0),
        24: ( 'abandon ' * 23 + 'art', 0x24d73654 ),
    }
    words, expect_xfp = wordlists[num_words]

    reset_seed_words()

    if seed_vault:
        settings_set("seedvault", True)
    else:
        settings_set("seedvault", None)

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
        time.sleep(.5)

    if seed_vault:
        time.sleep(.1)
        _, story = cap_story()
        assert "Press (1) to store ephemeral secret into Seed Vault" in story
        need_keypress("1")  # store it
        need_keypress("y")  # confirm saved to Seed Vault

    verify_ephemeral_secret_ui(mnemonic=words.split(" "), seed_vault=seed_vault)

    if not skip_nfc_check:
        nfc_seed = get_seed_value_ux(nfc=True)  # export seed via NFC (always truncated)
        seed_words = get_seed_value_ux()
        assert " ".join(nfc_seed) == truncate_seed_words(seed_words)


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('retry', range(3))
@pytest.mark.parametrize("testnet", [True, False])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_tapsigner(way, retry, testnet, pick_menu_item, cap_story, enter_hex,
                                         need_keypress, reset_seed_words, goto_eph_seed_menu,
                                         verify_ephemeral_secret_ui, ephemeral_seed_disabled,
                                         nfc_write_text, tapsigner_encrypted_backup, settings_set,
                                         seed_vault):
    reset_seed_words()
    if seed_vault:
        settings_set("seedvault", True)
    else:
        settings_set("seedvault", None)

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

    if seed_vault:
        time.sleep(.1)
        _, story = cap_story()
        assert "Press (1) to store ephemeral secret into Seed Vault" in story
        need_keypress("1")  # store it
        need_keypress("y")  # confirm saved to Seed Vault

    verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=seed_vault)


@pytest.mark.parametrize("fail", ["wrong_key", "key_len", "plaintext", "garbage"])
def test_ephemeral_seed_import_tapsigner_fail(cap_menu, pick_menu_item, goto_home, cap_story, fail,
                                              need_keypress, reset_seed_words, enter_hex,
                                              tapsigner_encrypted_backup, goto_eph_seed_menu,
                                              microsd_path, ephemeral_seed_disabled, settings_set):
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
def test_ephemeral_seed_import_tapsigner_real(data, cap_menu, pick_menu_item, goto_home, cap_story,
                                              need_keypress, reset_seed_words, enter_hex, microsd_path,
                                              goto_eph_seed_menu, verify_ephemeral_secret_ui,
                                              ephemeral_seed_disabled, settings_set):
    fname, backup_key_hex, pub = data
    fpath = microsd_path(fname)
    shutil.copy(f"data/{fname}", fpath)
    reset_seed_words()
    settings_set("seedvault", None)
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
@pytest.mark.parametrize('retry', range(2))
@pytest.mark.parametrize("testnet", [True, False])
@pytest.mark.parametrize("seed_vault", [False, True])
def test_ephemeral_seed_import_xprv(way, retry, testnet, cap_menu, pick_menu_item, goto_home,
                                    cap_story, need_keypress, reset_seed_words, goto_eph_seed_menu,
                                    nfc_write_text, enter_hex, microsd_path, virtdisk_path,
                                    verify_ephemeral_secret_ui, ephemeral_seed_disabled,
                                    seed_vault, settings_set):
    reset_seed_words()
    if seed_vault:
        settings_set("seedvault", True)
    else:
        settings_set("seedvault", None)

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

    if seed_vault:
        time.sleep(.1)
        _, story = cap_story()
        assert "Press (1) to store ephemeral secret into Seed Vault" in story
        need_keypress("1")  # store it
        need_keypress("y")  # confirm saved to Seed Vault

    verify_ephemeral_secret_ui(xpub=node.hwif(), seed_vault=seed_vault)


@pytest.mark.parametrize('data', [
    ("47649253", "344f9dc08e88b8a46d4b8f46c4e6bb6c", "crowd language ice brown merit fall release impose egg cheese put suit"),
    ("CC7BB706", "88f53ed897cc371ffe4b715c267206f3286ed2f655ba9d68", "material prepare renew convince sell morning weird hotel found crime like town manage harvest sun resemble output dolphin"),
    ("AC39935C", "956f484cc2136178fd1ad45faeb54972c829f65aad0d74eb2541b11984655893", "nice kid basket loud current round virtual fold garden interest false tortoise little will height payment insane float expire giraffe obscure crawl girl glare"),
    ('939B32C4', '017caa3142d48791f837b42fcd7a98662f9fb4101a15ae87cdbc1fecc96f33c11ffcefd8121daaba0625c918a335a0712b8c35c2da60e6fc6eef78b7028f4be02a', None),      # BIP-85 -> BIP-32 -> #23
])
def test_seed_vault_menus(dev, data, settings_set, settings_get, pick_menu_item, need_keypress, cap_story,
                    cap_menu, reset_seed_words, get_identity_story, get_seed_value_ux, fake_txn,
                    try_sign, sim_exec, goto_home, goto_eph_seed_menu):

    # Verify "seed vault" feature works as intended

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
    settings_set("seeds", [(xfp, stored_secret.hex(), f"[{xfp}]")])

    # enable Seed Vault
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Danger Zone")
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    _, story = cap_story()
    assert "Enable Seed Vault?" in story
    need_keypress("y")
    time.sleep(.1)
    pick_menu_item("Enable")
    time.sleep(.5)
    goto_home()
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
    need_keypress("x")

    # rename
    pick_menu_item("Rename")
    for _ in range(len(xfp) + 1):  # [xfp]
        need_keypress("x")

    # below should yield AAAA
    need_keypress("1")
    for _ in range(3):
        need_keypress("9")  # next char
        need_keypress("1")  # letters

    need_keypress("y")
    m = cap_menu()
    assert m[0] == "AAAA"
    need_keypress("x")  # go back
    m = cap_menu()
    assert "AAAA" in m[0]
    pick_menu_item(m[0])
    pick_menu_item("Use This Seed")
    time.sleep(.1)
    _, story = cap_story()
    assert xfp in story
    assert "key in effect until next power down." in story
    need_keypress("y")
    active = get_seed_value_ux()
    if mnemonic:
        assert active == mnemonic.split()
    else:
        assert active[1:4] == 'prv'
        node = BIP32Node.from_hwif(active)
        ch, pk = entropy_bytes[1:33], entropy_bytes[33:65]
        assert node.chain_code() == ch
        assert node.secret_exponent() == int(pk.hex(), 16)

    istory = get_identity_story()
    assert "Ephemeral seed is in effect" in istory

    ident_xfp = istory.split("\n\n")[1].strip()
    assert ident_xfp == xfp

    e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
    assert e_master_xpub != simulator_fixed_xpub
    psbt = fake_txn(2, 2, master_xpub=e_master_xpub, segwit_in=True)
    try_sign(psbt, accept=True, finalize=True)  # MUST NOT raise
    need_keypress("y")

    encoded = sim_exec('from pincodes import pa; RV.write(repr(pa.fetch()))')
    assert 'Error' not in encoded
    encoded = eval(encoded)
    assert len(encoded) == 72
    assert encoded[0:len(stored_secret)] == stored_secret

    # check rename worked
    seeds = settings_get("seeds")
    assert len(seeds) == 1
    entry = seeds[0]
    assert len(entry) == 3
    assert entry[0] == xfp
    assert entry[1] == stored_secret.hex()
    assert entry[2] == "AAAA"

    reset_seed_words()
    time.sleep(.2)
    need_keypress("x")

def test_seed_vault_captures(request, dev, settings_set, settings_get,
        pick_menu_item, need_keypress, cap_story,
        cap_menu, reset_seed_words, get_identity_story, get_seed_value_ux, fake_txn,
        try_sign, sim_exec, goto_home, goto_eph_seed_menu, get_secrets,
):
    # Capture seeds by all the different paths and verify correct values are captured.
    # - BIP-85 -> 12, 24 words
    # - BIP-85 -> xprv (BIP-32)
    # - XOR seed restore
    # - Ephemeral keys menu: random and import
    # - Capture a BIP-39 passphrase into words
    # Then, verify those can all co-exist and be recalled correctly.

    reset_seed_words()
    settings_set("seedvault", True)
    settings_set("seeds", [])
    expect_count = 0

    if 1:
        # BIP-39 passphrase, probably needs to be first
        import test_bip39pw
        set_bip39_pw = request.getfixturevalue('set_bip39_pw')
        set_bip39_pw('dogsNcats')
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("Seed Functions")
        pick_menu_item("Capture to Vault")

        _, story = cap_story()
        assert '(1) to store ephemeral secret' in story
        need_keypress('1')
        time.sleep(0.1)
        _, story = cap_story()
        assert 'Saved to Seed Vault' in story
        
        expect_count += 1

    if 1:
        # Seed XOR of 12words into 3 parts... not simple, kinda slow
        from test_seed_xor import test_import_xor

        xor_parts, xor_expect = (
             ['become wool crumble brand camera cement gloom sell stand once connect stage',
              'save saddle indicate embrace detail weasel spread life staff mushroom bicycle light',
              'unlock damp injury tape enhance pause sheriff onion valley panic finger moon'],
                 'drama jeans craft mixture filter lamp invest suggest vacant neutral history swim')

        args = {f: request.getfixturevalue(f)
                  for f in ['choose_by_word_length', 'goto_home', 'pick_menu_item', 'cap_story',
                            'need_keypress', 'cap_menu', 'word_menu_entry', 'get_secrets']}

        test_import_xor(incl_self=False, save_to_vault=True, parts=xor_parts, expect=xor_expect,
                reset_seed_words=lambda:None, set_seed_words=lambda x:None, **args)

        # check was saved
        expect_count += 1
        xor_xfp = xfp2str(settings_get('xfp'))
        assert settings_get("seeds")[expect_count-1][0] == xor_xfp

    if 1:
        # Create via BIP-85
        from test_drv_entro import test_path_index
        args = {f: request.getfixturevalue(f)
                    for f in ['dev', 'cap_menu', 'pick_menu_item', 'goto_home', 'cap_story',
                                'need_keypress', 'cap_screen_qr', 'qr_quality_check']}

        for mode, regex_pattern in [
            ('12 words', r'[a-f0-9]{32}'),
            ('18 words', r'[a-f0-9]{48}'),
            ('24 words', r'[a-f0-9]{64}'),
            ('XPRV (BIP-32)', r'[tx]prv[1-9A-HJ-NP-Za-km-z]{107}'),
        ]:
            test_path_index(index=72, mode=mode, pattern=regex_pattern, **args)
            _, story = cap_story()
            assert '(2) to switch to derived secret' in story
            need_keypress('2')
            time.sleep(0.1)

            _, story = cap_story()
            assert '(1) to store ephemeral secret' in story
            need_keypress('1')
            time.sleep(0.1)
            _, story = cap_story()
            assert 'Saved to Seed Vault' in story
            
            need_keypress('y')
            time.sleep(0.1)
            _, story = cap_story()
            assert 'master key in effect until next power down' in story

        expect_count += 4

    if 1:
        # Ephemeral seeds - generated and imported cases
        args = {f: request.getfixturevalue(f)
                    for f in ['pick_menu_item', 'goto_home', 'cap_story', 'need_keypress',
                     'reset_seed_words', 'goto_eph_seed_menu', 'ephemeral_seed_disabled',
                     'settings_set', 'settings_get']}

        args2 = {f: request.getfixturevalue(f)
                    for f in ['cap_menu', 'pick_menu_item', 'goto_home', 'cap_story',
                                'need_keypress', 'reset_seed_words', 'goto_eph_seed_menu',
                                'word_menu_entry', 'nfc_write_text', 
                                'ephemeral_seed_disabled', 'get_seed_value_ux', 'settings_set']}

        for num_words in [12, 24]:
            test_ephemeral_seed_generate(num_words=num_words, dice=False, seed_vault=True, 
                    verify_ephemeral_secret_ui=lambda **k:None, **args)

            test_ephemeral_seed_import_words(num_words=num_words, nfc=False,
                    truncated=False, seed_vault=True, skip_nfc_check=True,
                    verify_ephemeral_secret_ui=lambda **k:None, **args2)

        expect_count += 4


    # check all saved okay
    seeds = settings_get('seeds')
    n_seeds = len(seeds)
    assert n_seeds == expect_count

    # Switch to each one
    for n in list(range(n_seeds))+list(range(n_seeds-1, -1, -1)):
        goto_home()
        xfp, encoded_sec, name = seeds[n]
        pick_menu_item("Seed Vault")
        pick_menu_item('%d: %s' % (n+1, name))
        pick_menu_item('Use This Seed')
        time.sleep(0.1)

        _, story = cap_story()
        assert 'New ephemeral master key' in story
        assert 'power down' in story
        assert xfp in story

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

# EOF
