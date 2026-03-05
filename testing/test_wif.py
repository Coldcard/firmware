# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, re, hashlib, shutil
from helpers import prandom, addr_from_display_format
from charcodes import KEY_DOWN, KEY_QR, KEY_NFC, KEY_DELETE, KEY_UP
from bip32 import BIP32Node, PrivateKey
from base58 import encode_base58_checksum


def make_fake_wif(prefix=239):
    # generate a WIF
    return encode_base58_checksum(bytes([prefix]) + prandom(32) + b'\x01')

@pytest.mark.parametrize("num_wifs", [1, 11])
@pytest.mark.parametrize("separator", ["\n", ','])
@pytest.mark.parametrize("way", ["sd", "nfc", "qr", "vdisk"])
def test_wif_store_import(num_wifs, separator, way, import_wif_to_store, skip_if_useless_way,
                          settings_remove, goto_home):
    skip_if_useless_way(way)
    settings_remove("wifs")

    wif_list = [make_fake_wif() for _ in range(num_wifs)]

    import_wif_to_store(wif_list, way=way, sep=separator)
    goto_home()


def test_wif_store_import_manual(import_wif_to_store, settings_remove, goto_home):
    settings_remove("wifs")

    wif_list = [make_fake_wif()]

    import_wif_to_store(wif_list, way="input")
    goto_home()


def test_wif_store_import_paper_wallet(goto_home, pick_menu_item, press_select, cap_story,
                                       need_keypress, settings_remove, microsd_path, cap_menu):
    settings_remove("wifs")
    goto_home()
    pick_menu_item('Advanced/Tools')
    try:
        pick_menu_item('Paper Wallets')
    except:
        raise pytest.skip('Feature absent')

    press_select()
    pick_menu_item('GENERATE WALLET')

    time.sleep(0.1)
    title, story = cap_story()
    if "Press (1) to save paper wallet file to SD Card" in story:
        need_keypress("1")
    time.sleep(0.2)
    title, story = cap_story()
    assert 'Created file' in story

    story = [i for i in story.split('\n') if i]
    fname = story[-2]
    assert fname.endswith('.txt')

    with open(microsd_path(fname), "r") as f:
        const = f.read()

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item("WIF Store")
    time.sleep(.1)
    title, story = cap_story()
    if title == "WIF Store":
        press_select()
    pick_menu_item("Import WIF")
    need_keypress("1")  # SD
    try:
        pick_menu_item(fname)
    except:
        pass

    menu = cap_menu()
    assert "Import WIF" in menu
    pick_menu_item(menu[1])
    pick_menu_item("Detail")
    time.sleep(.1)
    title, story = cap_story()
    assert story.split("\n\n")[0] == const.split("\n\n")[4].strip()


@pytest.mark.parametrize("wif,err,way", [
    ("Ky2BtsR8qRN91PjktxaTQWMgJZUWSBJLjwip642vvoNyH1PeEpUP", "chain", "qr"),  # mainnet key on testnet
    ("91zb4oYGEvwEroihAbkdeoBpLSKnZYMdD1CPhfQD76fxrfNSp5J", "compressed only", "sd"),  # uncompressed pk
    ("cWALDjUu1tszsCBMjBjL4mhYj2wHUWYDR8Q8aSjLKzjkWaXMLRaY", None, "sd"),  # curve order
    ("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87J7g8rY9t", None, "nfc"),  # zero
    ("cPPBMnQzGV4QAqD2HNPamprjvnmv6dQ2oysHCUVSRv2yXkVvWVtX", None, "nfc"),  # wrong csum
    ("cPPBMnQzGV4QAqD2HNPamprjvnmv6dQ2oysHCUVSRv2yXkVvWVtX;cN7M6sNzn4LGBxAozsmphxjuxVNaHcLre7Nm163qM3DpY3BZog1v", None, "sd"),  # wrong separator
])
def test_wif_store_import_fail(way, wif, err, import_wif_to_store, skip_if_useless_way,
                               settings_remove, press_select, cap_story, use_testnet, settings_get):

    err = err or "no valid WIF found"
    skip_if_useless_way(way)
    use_testnet()
    settings_remove("wifs")

    import_wif_to_store([wif], way=way, early_exit=True)
    time.sleep(.1)
    title, story = cap_story()
    assert "Failed to import WIF" in story
    assert err in story
    press_select()
    assert not settings_get("wifs")


@pytest.mark.parametrize("netcode", ["XTN", "BTC"])
def test_wif_store_detail(netcode, import_wif_to_store, use_mainnet, cap_menu, pick_menu_item,
                          cap_story, need_keypress, settings_remove, cap_screen_qr, is_q1,
                          press_cancel, nfc_is_enabled, press_nfc, nfc_read_text, goto_home):
    goto_home()
    if netcode == "BTC":
        use_mainnet()

    settings_remove("wifs")

    prefix = bytes([128]) if netcode == "BTC" else bytes([239])
    privkeys = [PrivateKey.parse(prandom(32)) for _ in range(5)]
    wif_list = [encode_base58_checksum(prefix + bytes(sk) + b'\x01') for sk in privkeys]

    import_wif_to_store(wif_list)

    time.sleep(.1)
    menu = cap_menu()
    target_mi = []
    for mi in menu:
        if "⋯" in mi:
            target_mi.append(mi)

    assert len(target_mi) == len(wif_list)
    for mi, wif, sk in zip(target_mi, wif_list, privkeys):
        mi_split = mi.split(" ")[-1].split("⋯")
        assert len(mi_split) == 2
        assert mi_split[0] in wif
        assert mi_split[1] in wif
        pick_menu_item(mi)

        time.sleep(.1)
        menu = cap_menu()
        assert menu[0] == "Detail"
        assert menu[1] == "Addresses"
        assert menu[2] == "Sign MSG"
        assert menu[3] == "Delete"

        pick_menu_item("Detail")

        title, story = cap_story()
        assert title == "WIF"

        split_story = story.split("\n\n")
        story_wif = split_story[0]
        story_sk = split_story[1].split("\n")[-1]
        story_pk = split_story[2].split("\n")[-1]

        assert f'{KEY_QR if is_q1 else "(4)"} to show QR code' in story

        need_keypress(KEY_QR if is_q1 else "4")
        time.sleep(.1)
        wif_qr = cap_screen_qr().decode()
        press_cancel()

        if nfc_is_enabled():
            assert f"{KEY_NFC if is_q1 else '(3)'} to share via NFC" in story

            press_nfc()
            time.sleep(0.3)
            nfc_wif = nfc_read_text()
            time.sleep(0.3)
            press_cancel()
            assert nfc_wif == wif


        assert story_wif == wif == wif_qr
        assert story_sk == bytes(sk).hex()
        assert story_pk == sk.K.sec().hex()

        press_cancel()  # exit Detail
        press_cancel()  # exit WIF submenu


@pytest.mark.parametrize("netcode", ["XTN", "BTC"])
def test_wif_store_addresses(netcode, import_wif_to_store, use_mainnet, cap_menu, pick_menu_item,
                             cap_story, need_keypress, settings_remove, cap_screen_qr, is_q1,
                             nfc_is_enabled, press_nfc, nfc_read_text, goto_home, press_cancel):
    goto_home()
    if netcode == "BTC":
        use_mainnet()

    settings_remove("wifs")

    prefix = bytes([128]) if netcode == "BTC" else bytes([239])
    n = BIP32Node.from_master_secret(prandom(32))
    privkey = n.node.private_key

    wif_list = [ encode_base58_checksum(prefix + bytes(privkey) + b'\x01') ]

    import_wif_to_store(wif_list)

    time.sleep(.1)
    menu = cap_menu()
    assert len(menu) == 2
    pick_menu_item(menu[1])
    pick_menu_item("Addresses")

    for mi, af in [("P2SH-Segwit", "p2sh-p2wpkh"), ("Segwit P2WPKH", "p2wpkh"), ("Classic P2PKH", "p2pkh")]:
        pick_menu_item(mi)
        time.sleep(.1)
        title, story = cap_story()
        if is_q1:
            # Q has title as it needs hint keys
            assert title == mi

        target_addr = n.address(addr_fmt=af, netcode=netcode)
        addr = addr_from_display_format(story.split("\n\n")[0])
        assert addr == target_addr

        if not is_q1:
            assert "Press (1) to show address QR code." in story

        need_keypress(KEY_QR if is_q1 else "1")
        time.sleep(.1)
        qr_addr = cap_screen_qr().decode()
        if af == "p2wpkh":
            qr_addr = qr_addr.lower()
        press_cancel()
        assert qr_addr == target_addr

        if nfc_is_enabled():
            if not is_q1:
                assert "(3) to share via NFC." in story

            press_nfc()
            time.sleep(0.3)
            nfc_addr = nfc_read_text()
            time.sleep(0.3)
            press_cancel()
            assert nfc_addr == target_addr

        press_cancel()
    press_cancel()
    press_cancel()


def test_wif_store_clear_all(import_wif_to_store, press_select, cap_story, settings_get,
                             need_keypress, cap_menu, settings_remove, is_q1, goto_home):

    goto_home()
    settings_remove("wifs")
    wif_list = [make_fake_wif() for _ in range(30)]        # 30 is the max
    import_wif_to_store(wif_list)
    time.sleep(.1)

    menu = cap_menu()
    assert "Import WIF" not in menu  # WIF store is full
    assert "Clear All" in menu
    need_keypress(KEY_UP if is_q1 else "5")
    time.sleep(.1)
    press_select()  # on Clear All
    time.sleep(.1)
    title, story = cap_story()
    assert "Remove all saved WIF keys?" in story
    assert "(4)" in story
    press_select()  # does not work & gets you back to menu
    assert len(settings_get("wifs")) == 30

    press_select()  # on Clear All
    time.sleep(.1)
    need_keypress("4")
    time.sleep(.1)
    menu = cap_menu()
    assert len(menu) == 2
    assert "(none yet)" in menu
    assert "Import WIF" in menu
    assert not settings_get("wifs")


def test_wif_store_capacity(import_wif_to_store, settings_remove, press_select, cap_story,
                            settings_get, cap_menu, pick_menu_item, need_keypress):
    settings_remove("wifs")

    wif_list = [make_fake_wif() for _ in range(40)]  # MAX+1

    import_wif_to_store(wif_list[:31], early_exit=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Max 30 items allowed in WIF Store" in story
    assert "Attempted to import 31 keys" in story
    assert "remaining WIF store capacity is only 30"
    press_select()
    assert not settings_get("wifs")

    # import 29 keys
    import_wif_to_store(wif_list[:29])

    assert len(settings_get("wifs", [])) == 29

    import_wif_to_store(wif_list[-2:], early_exit=True)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Max 30 items allowed in WIF Store" in story
    assert "Attempted to import 2 keys" in story
    assert "remaining WIF store capacity is only 1"
    press_select()

    assert len(settings_get("wifs", [])) == 29

    import_wif_to_store(wif_list[-1:])
    assert len(settings_get("wifs", [])) == 30

    menu = cap_menu()
    assert "Import WIF" not in menu
    # remove random key to make space
    # pick key at current menu item position
    press_select()
    time.sleep(.1)
    pick_menu_item("Delete")
    time.sleep(.1)
    title, story = cap_story()
    assert "Delete WIF key?" in story
    press_select()
    time.sleep(.1)
    menu = cap_menu()
    assert "Import WIF" in menu


def test_wif_store_import_duplicate(settings_remove, import_wif_to_store, settings_get, cap_menu, cap_story,
                                    goto_home):
    goto_home()
    settings_remove("wifs")

    wif_list = [make_fake_wif() for _ in range(4)]

    import_wif_to_store(wif_list)
    b4 = cap_menu()
    assert len(settings_get("wifs")) == 4

    import_wif_to_store(wif_list, early_exit=True)
    assert len(settings_get("wifs")) == 4
    assert len(b4) == len(cap_menu())

    title, story = cap_story()
    assert 'duplicate WIF' in story


@pytest.mark.parametrize("way", ["qr", "sd", "nfc"])
def test_wif_store_export_all(way, goto_home, settings_remove, import_wif_to_store, pick_menu_item,
                              load_export):
    goto_home()
    settings_remove("wifs")

    wif_list = [make_fake_wif() for _ in range(6)]  # 6*52 chars so it can be shown on mk4 too

    import_wif_to_store(wif_list)
    time.sleep(.1)
    pick_menu_item("Export All")
    conts = load_export(way, "WIF Store", is_json=False, sig_check=False)

    assert wif_list == conts.split("\n")


