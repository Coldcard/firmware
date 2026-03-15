# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, json, base64
from helpers import prandom, addr_from_display_format
from charcodes import KEY_QR, KEY_NFC, KEY_UP
from constants import unmap_addr_fmt, AF_P2WSH, AF_P2SH
from bip32 import BIP32Node, PrivateKey
from base58 import encode_base58_checksum
from msg import verify_message, parse_signed_message
from psbt import BasicPSBT
from helpers import str_to_path


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
    assert len(menu) == 2  # only one WIF imported from paper wallet that contins 2x same WIF
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

        target_addr = n.address(addr_fmt=af, chain=netcode)
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
                              load_export, press_cancel):
    goto_home()
    settings_remove("wifs")

    wif_list = [make_fake_wif() for _ in range(6)]  # 6*52 chars so it can be shown on mk4 too

    import_wif_to_store(wif_list)
    time.sleep(.1)
    pick_menu_item("Export All")
    conts = load_export(way, "WIF Store", is_json=False, sig_check=False)

    assert wif_list == conts.split("\n")
    press_cancel()


@pytest.mark.parametrize('en_okeys', [ True, False])
def test_hobbled_wif_store(en_okeys, set_hobble, settings_remove, import_wif_to_store, goto_home,
                           cap_menu, pick_menu_item):
    goto_home()
    settings_remove("wifs")

    wif_list = [
        encode_base58_checksum(bytes([239]) + os.urandom(32) + b'\x01')
        for _ in range(3)
    ]

    import_wif_to_store(wif_list)
    goto_home()

    set_hobble(True, {'okeys'} if en_okeys else {})
    pick_menu_item("Advanced/Tools")

    if en_okeys:
        pick_menu_item("WIF Store")
        time.sleep(.1)
        menu = cap_menu()
        # check it is read-only
        assert "Import WIF" not in menu
        assert "Clear All" not in menu
        pick_menu_item(menu[0])
        time.sleep(.1)
        menu = cap_menu()
        assert "Delete" not in menu
    else:
        assert "WIF Store" not in cap_menu()


@pytest.mark.parametrize("way,af", [
    ("sd", "P2SH-Segwit"),
    ("input", "Segwit P2WPKH"),
    ("nfc", "Classic P2PKH")
])
def test_sign_msg_with_wif_store_key(way, af, settings_remove, import_wif_to_store, cap_menu,
                                     pick_menu_item, cap_story, need_keypress, press_nfc,
                                     enter_complex, garbage_collector, microsd_path, nfc_write_text,
                                     verify_msg_sign_story, msg_sign_export, press_select, goto_home):
    settings_remove("wifs")
    msg = "Coinkite"

    n = BIP32Node.from_master_secret(os.urandom(32))
    privkey = n.node.private_key
    import_wif_to_store([encode_base58_checksum(bytes([239]) + bytes(privkey) + b'\x01')])

    menu = cap_menu()
    assert len(menu) == 2
    pick_menu_item(menu[1])
    pick_menu_item("Sign MSG")
    pick_menu_item(af)

    if way == "input":
        need_keypress("0")
        enter_complex(msg, apply=False, b39pass=False)

    elif way == "sd":
        name = "msg_to_sign.txt"
        pth = microsd_path(name)
        with open(pth, "w") as f:
            f.write(msg)

        need_keypress("1")
        pick_menu_item(name)

    elif way == "nfc":
        press_nfc()
        time.sleep(0.2)
        nfc_write_text(msg)
        time.sleep(0.3)

    else:
        raise NotImplementedError

    time.sleep(.1)
    title, story = cap_story()
    addr_fmt = {"P2SH-Segwit": "p2sh-p2wpkh",
                "Segwit P2WPKH": "p2wpkh",
                "Classic P2PKH": "p2pkh"}[af]

    target_addr = n.address(addr_fmt=addr_fmt)
    verify_msg_sign_story(story, msg, "m", addr=target_addr)
    press_select()
    res = msg_sign_export(way if way != "input" else "sd")
    assert target_addr in res
    pmsg, addr, sig = parse_signed_message(res)
    assert pmsg == msg
    assert verify_message(addr, sig, msg) is True
    goto_home()


@pytest.mark.parametrize("oneshot", [True, False])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh", "p2sh"])
def test_multisig_wif_store(oneshot, addr_fmt, dev, fake_ms_txn, start_sign, settings_set,
                            clear_miniscript, cap_story, pytestconfig, import_ms_wallet, end_sign,
                            settings_remove):
    # TODO This test MUST be run with --psbt2 flag on and off
    clear_miniscript()
    settings_remove("wifs")
    M, N = 3, 5

    if addr_fmt == AF_P2SH:
        dd = "m/45h"
    elif addr_fmt == AF_P2WSH:
        dd = "m/48h/1h/0h/2h"
    else:
        dd = "m/48h/1h/0h/1h"

    def path_mapper(idx):
        kk = str_to_path(dd)
        return kk + [0,0]

    keys = import_ms_wallet(M, N, name='wif_store', accept=True, chain="XTN",
                            addr_fmt=addr_fmt, common=dd)

    psbt = fake_ms_txn(1, 1, M, keys, inp_addr_fmt=addr_fmt, path_mapper=path_mapper,
                       psbt_v2=pytestconfig.getoption('psbt2'))

    if not oneshot:
        # sign with master key first - nothing in WIF store
        # without warning
        # one signature from master added
        start_sign(psbt)
        title, story = cap_story()
        assert "warning" not in story
        psbt = end_sign()

        po = BasicPSBT().parse(psbt)
        assert len(po.inputs[0].part_sigs) == 1

    # add privkey from 0th & 1st node to WIF store
    der_node0 = keys[0][1].subkey_for_path(dd[2:] + "/0/0")
    sk0 = bytes(der_node0.node.private_key).hex()
    pk0 = der_node0.node.private_key.K.sec().hex()
    der_node1 = keys[1][1].subkey_for_path(dd[2:] + "/0/0")
    sk1 = bytes(der_node1.node.private_key).hex()
    pk1 = der_node1.node.private_key.K.sec().hex()
    settings_set("wifs", [(pk0,sk0), (pk1,sk1)])

    # sign with WIF keys
    start_sign(psbt, finalize=True)
    title, story = cap_story()
    assert "warning" in story
    assert "WIF store" in story
    end_sign(finalize=True)


@pytest.mark.parametrize("addr_fmt", ["p2wpkh", "p2sh-p2wpkh", "p2pkh"])
@pytest.mark.parametrize("idx", [1, 3])
def test_wif_store_ownership(addr_fmt, idx, is_q1, goto_home, pick_menu_item, scan_a_qr, cap_story,
                             need_keypress, src_root_dir, sim_root_dir, nfc_write, settings_remove,
                             import_wif_to_store, load_shared_mod, cap_screen_qr, press_cancel):

    settings_remove("wifs")

    n = BIP32Node.from_master_secret(os.urandom(32))
    privkey = n.node.private_key
    addr = n.address(addr_fmt=addr_fmt)
    wif = encode_base58_checksum(bytes([239]) + bytes(privkey) + b'\x01')
    wif1 = encode_base58_checksum(bytes([239]) + os.urandom(32) + b'\x01')
    wif2 = encode_base58_checksum(bytes([239]) + os.urandom(32) + b'\x01')

    if idx == 1:
        wif_list = [wif, wif1, wif2]
    else:
        wif_list = [wif1, wif2, wif]

    import_wif_to_store(wif_list)

    goto_home()

    if is_q1:
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr == addr_from_display_format(story.split("\n\n")[0])
        assert '(1) to verify ownership' in story
        need_keypress('1')

    else:
        cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
            f.write(ccfile)
        nfc_write(ccfile)

    time.sleep(1)
    title, story = cap_story()
    assert addr == addr_from_display_format(story.split("\n\n")[0])
    assert f"Found in WIF store at index {idx}" in story
    need_keypress(KEY_QR if is_q1 else '1')
    addr_qr = cap_screen_qr().decode()
    if addr_fmt == "p2wpkh":
        addr_qr = addr_qr.lower()

    assert addr == addr_qr
    press_cancel()


@pytest.mark.parametrize("num_ins", [1, 5])
@pytest.mark.parametrize("addr_fmt", ["p2tr", "p2pkh", "p2wpkh", "p2sh-p2wpkh"])
def test_wif_store_signing(num_ins, addr_fmt, fake_txn, goto_home, pick_menu_item, need_keypress,
                           start_sign, end_sign, cap_menu, cap_story, press_cancel, settings_remove,
                           press_select, import_wif_to_store):

    settings_remove("wifs")

    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(num_ins, 1, addr_fmt=addr_fmt, master_xpub=node.hwif())

    wifs = []
    for i in range(num_ins):
        n = node.subkey_for_path("0/%d" % i)
        wifs.append(n.node.private_key.wif(testnet=True))

    import_wif_to_store(wifs)

    menu = cap_menu()
    assert menu[0] == "Import WIF"

    start_sign(psbt, finalize=True)
    time.sleep(.1)
    title, story = cap_story()
    assert "warning" in story
    if num_ins == 1:
        assert "WIF store: 0" in story
    else:
        assert f"WIF store: {', '.join([str(i) for i in range(num_ins)])}" in story
    end_sign(finalize=True)


@pytest.mark.parametrize("der_paths", [True, False])
@pytest.mark.parametrize("complete", [True, False])
def test_wif_store_signing_multi(der_paths, complete, fake_txn, start_sign, end_sign, cap_story,
                                 settings_set):
    wifs = []

    hack = None
    if der_paths:
        def hack(psbt):
            new_paths = {}
            for k, v in psbt.inputs[0].bip32_paths.items():
                new_paths[k] = b"\x01" * 8  # garbage (do not use zero xfp here)

            psbt.inputs[0].bip32_paths = new_paths


    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(1, [["p2wpkh", 3*100_000_000]], addr_fmt="p2wpkh", master_xpub=node.hwif(),
                    psbt_v2=True, psbt_hacker=hack)
    po = BasicPSBT().parse(psbt)
    n = node.subkey_for_path("0/0")
    sk = bytes(n.node.private_key).hex()
    pk = n.node.private_key.K.sec().hex()
    wifs.append((pk, sk))

    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(1, 1, addr_fmt="p2pkh", master_xpub=node.hwif(), psbt_v2=True, psbt_hacker=hack)
    tmp = BasicPSBT().parse(psbt)
    po.inputs += tmp.inputs
    po.input_count += 1
    n = node.subkey_for_path("0/0")
    sk = bytes(n.node.private_key).hex()
    pk = n.node.private_key.K.sec().hex()
    wifs.append((pk, sk))

    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(1, 1, addr_fmt="p2sh-p2wpkh", master_xpub=node.hwif(), psbt_v2=True,
                    psbt_hacker=hack)
    tmp = BasicPSBT().parse(psbt)
    po.inputs += tmp.inputs
    po.input_count += 1
    n = node.subkey_for_path("0/0")
    sk = bytes(n.node.private_key).hex()
    pk = n.node.private_key.K.sec().hex()
    wifs.append((pk, sk))

    # pretend we have those imported
    if not complete:
        wifs = wifs[:-1]

    settings_set("wifs", wifs)

    start_sign(po.as_bytes(), finalize=complete)
    title, story = cap_story()
    assert "warning" in story
    if complete:
        assert "WIF store: 0, 1, 2" in story
    else:
        assert "WIF store: 0, 1" in story
        assert "Limited Signing" in story

    end_sign(finalize=complete)


def test_wif_store_signing_with_master(fake_txn, start_sign, end_sign, cap_story, settings_set):
    # signs both master key and keys from WIF store
    wifs = []

    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(1, [["p2wpkh", 3*100_000_000]], addr_fmt="p2wpkh", master_xpub=node.hwif(),
                    psbt_v2=True)
    po = BasicPSBT().parse(psbt)
    n = node.subkey_for_path("0/0")
    sk = bytes(n.node.private_key).hex()
    pk = n.node.private_key.K.sec().hex()
    wifs.append((pk, sk))

    node = BIP32Node.from_master_secret(os.urandom(32))
    psbt = fake_txn(1, 1, addr_fmt="p2tr", master_xpub=node.hwif(), psbt_v2=True)
    tmp = BasicPSBT().parse(psbt)
    po.inputs += tmp.inputs
    po.input_count += 1
    n = node.subkey_for_path("0/0")
    sk = bytes(n.node.private_key).hex()
    pk = n.node.private_key.K.sec().hex()
    wifs.append((pk, sk))

    # add simulator input
    psbt = fake_txn(1, 1, addr_fmt="p2wpkh", psbt_v2=True)
    tmp = BasicPSBT().parse(psbt)
    po.inputs += tmp.inputs
    po.input_count += 1


    settings_set("wifs", wifs)

    # convert to v0 PSBT just for fun
    start_sign(po.to_v0(), finalize=True)
    title, story = cap_story()
    assert "warning" in story
    assert "WIF store: 0, 1" in story

    end_sign(finalize=True)

@pytest.mark.parametrize("wif", [
    "KwYP78wzyiuShCqppuh1JZQCnKtFdAaY6HcDhRmhDy21vGSiF37N", # mainnet compressed
    "5JwcuSWKH4PqV1mU8JSK9BBUkLjuAUS3MFHfP1w1qy9HjnXpavk",  # mainnet uncompressed
    "91cLPdroy4CtRYxWBXxgggqNnZrTz2CoJrLDkjDjcnkMP74gX5S",  # testnet uncompressed
    "cUR6JLQCmdPPt3op4jEYmFhjHpWC2AoZaWmZqoDaBQYMXN4QeKuc", # testnet compressed
])
@pytest.mark.parametrize("testnet", [True, False])
def test_visualize_wif(wif, testnet, is_q1, goto_home, need_keypress, use_testnet, use_mainnet,
                       scan_a_qr, cap_story, settings_remove, press_select):
    if not is_q1:
        raise pytest.skip("need scanner")

    settings_remove("wifs")

    if testnet:
        use_testnet()
    else:
        use_mainnet()

    goto_home()
    need_keypress(KEY_QR)
    scan_a_qr(wif)
    time.sleep(1)
    title, story = cap_story()
    split_story = story.split("\n\n")
    pubkey = split_story[3].split("\n")[-1]
    if wif[0] in "59":
        # uncompressed
        assert pubkey[0:2] == "04"
        assert len(pubkey) == 130
    else:
        # compressed
        assert pubkey[0:2] in ["02", "03"]
        assert len(pubkey) == 66

    if testnet:
        # we are on testnet, mainnet keys are not importable
        if wif[0] in "K59":
            assert "Press (1) to import to WIF Store" not in story
            return
    else:
        # we are on mainnet, testnet keys are not importable
        if wif[0] in "c59":
            assert "Press (1) to import to WIF Store" not in story
            return

    assert "Press (1) to import to WIF Store" in story
    need_keypress("1")
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Success"
    assert "Saved to WIF Store" in story
    press_select()

    # try import same wif
    goto_home()
    need_keypress(KEY_QR)
    scan_a_qr(wif)
    time.sleep(1)
    need_keypress("1")
    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "Already saved in WIF Store" in story
    press_select()



@pytest.mark.bitcoind
@pytest.mark.parametrize("tmplt", [
    "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<0;1>/*)),older(10))))",
    "tr(unspend()/<0;1>/*,{and_v(v:multi_a(2,@0/<2;3>/*,@1/<2;3>/*,@2/<0;1>/*,@3/<0;1>/*),older(10)),multi_a(2,@0/<0;1>/*,@1/<0;1>/*)})",
])
def test_wif_store_signing_miniscript(tmplt, clear_miniscript, goto_home, cap_story, use_regtest,
                                      bitcoind, get_cc_key, offer_minsc_import, bitcoin_core_signer,
                                      press_select, start_sign, end_sign, create_core_wallet,
                                      settings_set):
    use_regtest()
    clear_miniscript()
    goto_home()
    af = "bech32m" if tmplt.startswith("tr(") else "bech32"
    tmplt = tmplt.replace("unspend()", "tpubD6NzVbkrYhZ4WbzhCs1gLUM8s8LAwTh68xVh1a3nRQyA3tbAJFSE2FEaH2CEGJTKmzcBagpyG35Kjv3UGpTEWbc7qSCX6mswrLQVVPgXECd")

    csigner0, ckey0 = bitcoin_core_signer(f"co-signer-0")
    ckey0 = ckey0.replace("/0/*", "")
    csigner1, ckey1 = bitcoin_core_signer(f"co-signer-1")
    ckey1 = ckey1.replace("/0/*", "")

    # cc device key
    cc_key = get_cc_key("86h/1h/0h").replace('/<0;1>/*', "")

    # fill policy
    desc = tmplt.replace("@0", cc_key)
    desc = desc.replace("@1", ckey0)
    desc = desc.replace("@2", ckey1)

    if "@3" in tmplt:
        csigner2, ckey2 = bitcoin_core_signer(f"co-signer-2")
        ckey2 = ckey2.replace("/0/*", "")
        desc = desc.replace("@3", ckey2)

    wname = "wif_msc"
    _, story = offer_minsc_import(json.dumps({"name": wname, "desc": desc}))
    assert "Create new miniscript wallet?" in story
    press_select()

    wo = create_core_wallet(wname, af, "sd", True)

    # use non-recovery path to split into 5 utxos + 1 going back to supply (not a conso)
    unspent = wo.listunspent()
    assert len(unspent) == 1
    psbt_resp = wo.walletcreatefundedpsbt(
        [],
        [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 2, "change_type": af},
    )
    psbt = psbt_resp.get("psbt")

    res = csigner0.listdescriptors(True)
    prv_ek = pth = None
    for obj in res["descriptors"]:
        if not obj["internal"] and obj["desc"].startswith("pkh("):
            prv_ek, pth = obj["desc"].replace("pkh(", "").split("/", 1)
            pth = pth.split(")")[0].replace("*", "0")

    c0sk = BIP32Node.from_wallet_key(prv_ek)
    subkey = c0sk.subkey_for_path(pth)
    sec = subkey.sec()
    sk = bytes(subkey.node.private_key)

    po = BasicPSBT().parse(base64.b64decode(psbt))
    if af == "bech32m":
        for pk, xfp_pth in po.inputs[0].taproot_bip32_paths.items():
            if pk == sec[1:]: break
        else:
            raise ValueError
    else:
        for pk, xfp_pth in po.inputs[0].bip32_paths.items():
            if pk == sec: break
        else:
            raise ValueError

    # add co-signer wif to wif_store
    settings_set("wifs", [(sec.hex(), sk.hex())])
    # now CC and WIF store sign in one sitting
    start_sign(po.as_bytes())
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    assert "warning" in story
    assert "WIF store" in story
    final_psbt = end_sign(True)
    # client software finalization
    res = wo.finalizepsbt(base64.b64encode(final_psbt).decode())
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

# EOF