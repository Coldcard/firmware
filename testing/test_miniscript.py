# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Miniscript-related tests.
#
import pytest, json, time, itertools, struct, random, os
from ckcc.protocol import CCProtocolPacker
from constants import AF_P2TR
from psbt import BasicPSBT
from charcodes import KEY_QR, KEY_RIGHT, KEY_CANCEL
from bbqr import split_qrs
from bip32 import BIP32Node


H = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"  # BIP-0341
TREE = {
    1: '%s',
    2: '{%s,%s}',
    3: random.choice(['{{%s,%s},%s}','{%s,{%s,%s}}']),
    4: '{{%s,%s},{%s,%s}}',
    5: random.choice(['{{%s,%s},{%s,{%s,%s}}}', '{{{%s,%s},%s},{%s,%s}}']),
    6: '{{%s,{%s,%s}},{{%s,%s},%s}}',
    7: '{{%s,{%s,%s}},{%s,{%s,{%s,%s}}}}',
    8: '{{{%s,%s},{%s,%s}},{{%s,%s},{%s,%s}}}',
    # more than MAX (4) for test purposes
    9: '{{{%s{%s,%s}},{%s,%s}},{{%s,%s},{%s,%s}}}'
}


def ranged_unspendable_internal_key(chain_code=32 * b"\x01", subderiv="/<0;1>/*"):
    # provide ranged provably unspendable key in serialized extended key format for core to understand it
    # core does NOT understand 'unspend('
    pk = b"\x02" + bytes.fromhex(H)
    node = BIP32Node.from_chaincode_pubkey(chain_code, pk)
    return node.hwif() + subderiv


@pytest.fixture
def offer_minsc_import(cap_story, dev):
    def doit(config, allow_non_ascii=False):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('utf-8' if allow_non_ascii else 'ascii'))

        open('debug/last-config-msc.txt', 'wt').write(config)
        dev.send_recv(CCProtocolPacker.miniscript_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        return title, story

    return doit


@pytest.fixture
def import_miniscript(goto_home, pick_menu_item, cap_story, need_keypress,
                      nfc_write_text, press_select, scan_a_qr, press_nfc):
    def doit(fname, way="sd", data=None):
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        pick_menu_item('Import')
        time.sleep(.3)
        _, story = cap_story()
        if way == "nfc":
            if "via NFC" not in story:
                pytest.skip("nfc disabled")

            press_nfc()
            time.sleep(.1)
            if isinstance(data, dict):
                data = json.dumps(data)
            nfc_write_text(data)
            time.sleep(1)
            return cap_story()
        elif way == "qr":
            if isinstance(data, dict):
                data = json.dumps(data)

            need_keypress(KEY_QR)
            try:
                scan_a_qr(data)
            except:
                # always as text - even if it is json
                actual_vers, parts = split_qrs(data, 'U', max_version=20)
                random.shuffle(parts)

                for p in parts:
                    scan_a_qr(p)
                    time.sleep(1)  # just so we can watch

            time.sleep(1)
            return cap_story()

        if "Press (1) to import miniscript wallet file from SD Card" in story:
            # in case Vdisk or NFC is enabled
            if way == "sd":
                need_keypress("1")

            elif way == "vdisk":
                if "ress (2)" not in story:
                    pytest.xfail(way)

                need_keypress("2")
        else:
            if way != "sd":
                pytest.xfail(way)

        time.sleep(.5)
        pick_menu_item(fname)
        time.sleep(.1)
        return cap_story()

    return doit

@pytest.fixture
def import_duplicate(import_miniscript, press_cancel, virtdisk_path, microsd_path):
    def doit(fname, way="sd", data=None):
        new_fpath = None
        new_fname = None
        path_f = microsd_path
        if way == "vdisk":
            path_f = virtdisk_path

        time.sleep(.2)
        title, story = import_miniscript(fname, way, data=data)
        if "unique names" in story:
            # trying to import duplicate with same name
            # cannot get over name uniqueness requirement
            # need to duplicate
            if way in ["qr", "nfc"]:
                data["name"] = data["name"] + "-new"
            else:
                with open(path_f(fname), "r") as f:
                    res = f.read()

                basename, ext = fname.split(".", 1)
                new_fname = basename + "-new" + "." + ext
                new_fpath = path_f(basename+"-new"+"."+ext)
                with open(new_fpath, "w") as f:
                    f.write(res)

            title, story = import_miniscript(new_fname, way, data=data)
            time.sleep(.2)

        assert "duplicate of already saved wallet" in story
        assert "OK to approve" not in story
        press_cancel()

        if new_fpath:
            os.remove(new_fpath)

    return doit

@pytest.fixture
def miniscript_descriptors(goto_home, pick_menu_item, need_keypress, cap_story,
                           microsd_path, is_q1, readback_bbqr, cap_screen_qr,
                           garbage_collector):

    def doit(minsc_name):
        qr_external = None
        goto_home()
        pick_menu_item("Settings")
        pick_menu_item("Miniscript")
        pick_menu_item(minsc_name)
        pick_menu_item("Descriptors")
        pick_menu_item("Export")
        need_keypress("1")  # internal and external separately
        time.sleep(.1)
        if is_q1:
            # check QR
            need_keypress(KEY_QR)
            try:
                file_type, data = readback_bbqr()
                assert file_type == "U"
                data = data.decode()
            except:
                data = cap_screen_qr().decode('ascii')

            qr_external, qr_internal = data.split("\n")
            need_keypress(KEY_CANCEL)

            pick_menu_item("Export")
            need_keypress("1")  # internal and external separately
            time.sleep(.2)

        title, story = cap_story()
        if "Press (1)" in story:
            need_keypress("1")
            time.sleep(.2)
            title, story = cap_story()

        assert "Miniscript file written" in story
        fname = story.split("\n\n")[-1]
        fpath = microsd_path(fname)
        garbage_collector.append(fpath)
        with open(fpath, "r") as f:
            cont = f.read()
        external, internal = cont.split("\n")
        if qr_external:
            assert qr_external == external
            assert qr_internal == internal
        return external, internal

    return doit


@pytest.fixture
def usb_miniscript_get(dev):
    def doit(name):
        dev.check_mitm()
        resp = dev.send_recv(CCProtocolPacker.miniscript_get(name))
        return json.loads(resp)

    return doit


@pytest.fixture
def usb_miniscript_delete(dev):
    def doit(name):
        dev.check_mitm()
        dev.send_recv(CCProtocolPacker.miniscript_delete(name))

    return doit


@pytest.fixture
def usb_miniscript_ls(dev):
    def doit():
        dev.check_mitm()
        resp = dev.send_recv(CCProtocolPacker.miniscript_ls())
        return json.loads(resp)

    return doit


@pytest.fixture
def usb_miniscript_addr(dev):
    def doit(name, index, change=False):
        dev.check_mitm()
        resp = dev.send_recv(CCProtocolPacker.miniscript_address(name, change, index))
        return resp

    return doit


@pytest.fixture
def get_cc_key(dev):
    def doit(path, subderiv=None):
        # cc device key
        master_xfp_str = struct.pack('<I', dev.master_fingerprint).hex()
        cc_key = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        return f"[{master_xfp_str}/{path}]{cc_key}{subderiv if subderiv else '/<0;1>/*'}"
    return doit


@pytest.fixture
def bitcoin_core_signer(bitcoind):
    def doit(name="core_signer"):
        # core signer
        signer = bitcoind.create_wallet(wallet_name=name, disable_private_keys=False,
                                        blank=False, passphrase=None, avoid_reuse=False,
                                        descriptors=True)
        target_desc = ""
        bitcoind_descriptors = signer.listdescriptors()["descriptors"]
        for d in bitcoind_descriptors:
            if d["desc"].startswith("pkh(") and d["internal"] is False:
                target_desc = d["desc"]
                break
        core_desc, checksum = target_desc.split("#")
        core_key = core_desc[4:-1]
        return signer, core_key
    return doit


@pytest.fixture
def address_explorer_check(goto_home, pick_menu_item, need_keypress, cap_menu,
                           cap_story, load_export, miniscript_descriptors,
                           usb_miniscript_addr, cap_screen_qr):
    def doit(way, addr_fmt, wallet, cc_minsc_name, export_check=True):
        goto_home()
        pick_menu_item("Address Explorer")
        need_keypress('4')  # warning
        m = cap_menu()
        wal_name = m[-1]
        pick_menu_item(wal_name)

        title, story = cap_story()
        assert "Taproot internal key" not in story

        if way == "qr":
            need_keypress(KEY_QR)
            cc_addrs = []
            for i in range(10):
                cc_addrs.append(cap_screen_qr().decode())
                need_keypress(KEY_RIGHT)
                time.sleep(.2)
            need_keypress(KEY_CANCEL)
        else:
            contents = load_export(way, label="Address summary", is_json=False, sig_check=False)
            addr_cont = contents.strip()

        time.sleep(.5)
        title, story = cap_story()
        assert "(0)" in story
        assert "change addresses." in story
        need_keypress("0")
        time.sleep(.5)
        title, story = cap_story()
        assert "(0)" not in story
        assert "change addresses." not in story

        if way == "qr":
            need_keypress(KEY_QR)
            cc_addrs_change = []
            for i in range(10):
                cc_addrs_change.append(cap_screen_qr().decode())
                need_keypress(KEY_RIGHT)
                time.sleep(.2)
            need_keypress(KEY_CANCEL)
        else:
            contents_change = load_export(way, label="Address summary", is_json=False,
                                          sig_check=False)
            addr_cont_change = contents_change.strip()

        if way == "nfc":
            addr_range = [0, 9]
            cc_addrs = addr_cont.split("\n")
            cc_addrs_change = addr_cont_change.split("\n")
            part_addr_index = 0
        elif way == 'qr':
            addr_range = [0, 9]
            part_addr_index = 0
        else:
            addr_range = [0, 249]
            cc_addrs_split = addr_cont.split("\n")
            cc_addrs_split_change = addr_cont_change.split("\n")
            # header is different for taproot
            if addr_fmt == "bech32m":
                try:
                    assert "Internal Key" in cc_addrs_split[0]
                except AssertionError:
                    assert "Unspendable Internal Key" in cc_addrs_split[0]
                assert "Taptree" in cc_addrs_split[0]
            else:
                assert "Internal Key" not in cc_addrs_split[0]
                assert "Taptree" not in cc_addrs_split[0]

            cc_addrs = cc_addrs_split[1:]
            cc_addrs_change = cc_addrs_split_change[1:]
            part_addr_index = 1

        time.sleep(2)

        internal_desc = None
        external_desc = None
        descriptors = wallet.listdescriptors()["descriptors"]
        for desc in descriptors:
            if desc["internal"]:
                internal_desc = desc["desc"]
            else:
                external_desc = desc["desc"]

        if export_check:
            cc_external, cc_internal = miniscript_descriptors(cc_minsc_name)

            unspend = "unspend("
            if unspend in cc_external:
                assert "unspend(" in cc_internal
                netcode = "XTN" if "tpub" in cc_external else "BTC"
                # bitcoin core does not recognize unspend( - needs hack
                # CC properly exports any imported unspend( for bitcoin core
                # as extended key serialization xpub/<0;1>/*
                start_idx = cc_external.find(unspend)
                assert start_idx != -1
                end_idx = start_idx + len(unspend) + 64 + 1
                uns = cc_external[start_idx: end_idx]
                chain_code = bytes.fromhex(uns[len(unspend):-1])
                node = BIP32Node.from_chaincode_pubkey(chain_code,
                                                       b"\x02" + bytes.fromhex(H),
                                                       netcode=netcode)
                ek = node.hwif()
                cc_external = cc_external.replace(uns, ek)
                cc_internal = cc_internal.replace(uns, ek)

            assert cc_external.split("#")[0] == external_desc.split("#")[0].replace("'", "h")
            assert cc_internal.split("#")[0] == internal_desc.split("#")[0].replace("'", "h")

        bitcoind_addrs = wallet.deriveaddresses(external_desc, addr_range)
        bitcoind_addrs_change = wallet.deriveaddresses(internal_desc, addr_range)

        for cc, core in [(cc_addrs, bitcoind_addrs), (cc_addrs_change, bitcoind_addrs_change)]:
            for idx, cc_item in enumerate(cc):
                if way == "nfc":
                    address = cc_item
                elif way == "qr":
                    if cc_item.startswith("BC"):
                        cc_item = cc_item.lower()
                    address = cc_item
                else:
                    cc_item = cc_item.split(",")
                    address = cc_item[part_addr_index]
                    address = address[1:-1]
                assert core[idx] == address

        # check few USB addresses
        for i in range(5):
            addr = usb_miniscript_addr(cc_minsc_name, i, change=False)
            time.sleep(.1)
            title, story = cap_story()
            assert addr in story
            assert addr == bitcoind_addrs[i]

        for i in range(5):
            addr = usb_miniscript_addr(cc_minsc_name, i, change=True)
            time.sleep(.1)
            title, story = cap_story()
            assert addr in story
            assert addr == bitcoind_addrs_change[i]

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["bech32", "p2sh-segwit"])
@pytest.mark.parametrize("lt_type", ["older", "after"])  # this is actually not generated by liana (liana is relative only)
@pytest.mark.parametrize("recovery", [True, False])
@pytest.mark.parametrize("way", ["qr", "nfc", "sd", "vdisk"])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",  # this is actually not generated by liana

    "or_d(multi(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi(2,@B,@C),locktime(N)))",
])
def test_liana_miniscripts_simple(addr_fmt, recovery, lt_type, minisc, clear_miniscript, goto_home,
                                  pick_menu_item, cap_menu, cap_story, microsd_path, way,
                                  use_regtest, bitcoind, microsd_wipe, load_export, dev,
                                  address_explorer_check, get_cc_key, import_miniscript,
                                  bitcoin_core_signer, import_duplicate, press_select,
                                  virtdisk_path, skip_if_useless_way, garbage_collector):
    skip_if_useless_way(way)
    normal_cosign_core = False
    recovery_cosign_core = False
    if "multi(" in minisc.split("),", 1)[0]:
        normal_cosign_core = True
    if "multi(" in minisc.split("),", 1)[-1]:
        recovery_cosign_core = True

    if lt_type == "older":
        sequence = 5
        locktime = 0
        # 101 blocks are mined by default
        to_replace = "older(5)"
    else:
        sequence = None
        locktime = 105
        to_replace = "after(105)"

    minisc = minisc.replace("locktime(N)", to_replace)

    if addr_fmt == "bech32":
        desc = f"wsh({minisc})"
    else:
        desc = f"sh(wsh({minisc}))"

    # core signer
    signer0, core_key0 = bitcoin_core_signer("s0")

    # cc device key
    cc_key = get_cc_key("84h/0h/0h")

    if recovery:
        # recevoery path is always B
        desc = desc.replace("@B", cc_key)
        desc = desc.replace("@A", core_key0)
    else:
        desc = desc.replace("@A", cc_key)
        desc = desc.replace("@B", core_key0)

    if "@C" in desc:
        signer1, core_key1 = bitcoin_core_signer("s1")
        desc = desc.replace("@C", core_key1)

    use_regtest()
    clear_miniscript()
    goto_home()
    name = "core-miniscript"
    fname = f"{name}.txt"
    if way in ["qr", "nfc"]:
        data = dict(name=name, desc=desc)
    else:
        path_f = microsd_path if way == "sd" else virtdisk_path
        data = None
        fpath = path_f(fname)
        garbage_collector.append(fpath)
        with open(fpath, "w") as f:
            f.write(desc)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname, way=way, data=data)
    try:
        assert "Create new miniscript wallet?" in story
    except:
        time.sleep(.2)
        _, story = cap_story()
        assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    import_duplicate(fname, way=way, data=data)
    menu = cap_menu()
    assert menu[0] == name
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export(way, label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]
    addr = wo.getnewaddress("", addr_fmt)
    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    if recovery and sequence:
        inp["sequence"] = sequence
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{addr_dest: all_of_it - 1}],
        locktime if recovery else 0,
        {"fee_rate": 20, "change_type": addr_fmt, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    if normal_cosign_core or recovery_cosign_core:
        psbt = signer1.walletprocesspsbt(psbt, True, "ALL")["psbt"]

    name = f"{name}.psbt"
    fpath = microsd_path(name)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    if recovery:
        assert not res[0]["allowed"]
        assert res[0]["reject-reason"] == 'non-BIP68-final' if sequence else "non-final"
        bitcoind.supply_wallet.generatetoaddress(6, bitcoind.supply_wallet.getnewaddress())
        res = wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
    else:
        assert res[0]["allowed"]

    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses
    address_explorer_check(way, addr_fmt, wo, "core-miniscript")


@pytest.mark.parametrize("addr_fmt", ["bech32", "p2sh-segwit"])
@pytest.mark.parametrize("way", ["qr", "sd"])
@pytest.mark.parametrize("minsc", [
    ("or_i(and_v(v:pkh($0),older(10)),or_d(multi(3,@A,@B,@C),and_v(v:thresh(2,pkh($1),a:pkh($2),a:pkh($3)),older(5))))", 0),
    ("or_i(and_v(v:pkh(@A),older(10)),or_d(multi(3,$0,$1,$2),and_v(v:thresh(2,pkh($3),a:pkh($4),a:pkh($5)),older(5))))", 10),
    ("or_i(and_v(v:pkh($0),older(10)),or_d(multi(3,$1,$2,$3),and_v(v:thresh(2,pkh(@A),a:pkh(@B),a:pkh($4)),older(5))))", 5),
])
def test_liana_miniscripts_complex(addr_fmt, minsc, bitcoind, use_regtest, clear_miniscript,
                                   microsd_path, pick_menu_item, cap_story,
                                   load_export, goto_home, address_explorer_check, cap_menu,
                                   get_cc_key, import_miniscript, bitcoin_core_signer,
                                   import_duplicate, press_select, way, skip_if_useless_way,
                                   garbage_collector):
    skip_if_useless_way(way)
    use_regtest()
    clear_miniscript()
    goto_home()

    minsc, to_gen = minsc
    signer_keys = minsc.count("@")
    bsigners = signer_keys - 1
    random_keys = minsc.count("$")
    bitcoind_signers = []
    for i in range(random_keys + bsigners):
        s, core_key = bitcoin_core_signer(f"co-signer-{i}")
        bitcoind_signers.append((s, core_key))

    cc_key = get_cc_key("m/84h/1h/0h")
    minsc = minsc.replace("@A", cc_key)

    use_signers = []
    if bsigners == 2:
        for ph, (s, key) in zip(["@B", "@C"], bitcoind_signers[:2]):
            use_signers.append(s)
            minsc = minsc.replace(ph, key)
        for i, (s, key) in enumerate(bitcoind_signers[2:]):
            ph = f"${i}"
            minsc = minsc.replace(ph, key)
    elif bsigners == 1:
        use_signers.append(bitcoind_signers[0][0])
        minsc = minsc.replace("@B", bitcoind_signers[0][1])
        for i, (s, key) in enumerate(bitcoind_signers[1:]):
            ph = f"${i}"
            minsc = minsc.replace(ph, key)
    elif bsigners == 0:
        for i, (s, key) in enumerate(bitcoind_signers):
            ph = f"${i}"
            minsc = minsc.replace(ph, key)
    else:
        assert False

    if addr_fmt == "bech32":
        desc = f"wsh({minsc})"
    else:
        desc = f"sh(wsh({minsc}))"

    name = "cmplx-miniscript"

    if way in ["qr", "nfc"]:
        fname = None
        data = dict(name=name, desc=desc)
    else:
        fname = f"{name}.txt"
        data = None
        fpath = microsd_path(fname)
        with open(fpath, "w") as f:
            f.write(desc)

        garbage_collector.append(fpath)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)
    _, story = import_miniscript(fname, way=way, data=data)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    import_duplicate(fname, way=way, data=data)
    menu = cap_menu()
    assert menu[0] == name
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export(way, label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]

    addr = wo.getnewaddress("", addr_fmt)
    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    if to_gen:
        inp["sequence"] = to_gen

    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{addr_dest: 1}],
        0,
        {"fee_rate": 20, "change_type": addr_fmt, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # cosingers signing first
    for s in use_signers:
        psbt = s.walletprocesspsbt(psbt, True, "ALL")["psbt"]

    pname = f"{name}.psbt"
    ppath = microsd_path(pname)
    with open(ppath, "w") as f:
        f.write(psbt)
    garbage_collector.append(ppath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(pname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    if to_gen:
        assert not res[0]["allowed"]
        assert res[0]["reject-reason"] == 'non-BIP68-final'
        bitcoind.supply_wallet.generatetoaddress(to_gen, bitcoind.supply_wallet.getnewaddress())
        res = wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
    else:
        assert res[0]["allowed"]

    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses
    address_explorer_check(way, addr_fmt, wo, name)


@pytest.fixture
def bitcoind_miniscript(bitcoind, need_keypress, cap_story, load_export,
                        pick_menu_item, goto_home, cap_menu, microsd_path,
                        use_regtest, get_cc_key, import_miniscript,
                        bitcoin_core_signer, import_duplicate, press_select,
                        virtdisk_path, garbage_collector):
    def doit(M, N, script_type, internal_key=None, cc_account=0, funded=True, r=None,
             tapscript_threshold=False, add_own_pk=False, same_account=False, way="sd"):

        use_regtest()
        bitcoind_signers = []
        bitcoind_signers_xpubs = []
        for i in range(N - 1):
            s, core_key = bitcoin_core_signer(f"bitcoind--signer{i}")
            s.keypoolrefill(10)
            bitcoind_signers.append(s)
            bitcoind_signers_xpubs.append(core_key)

        # watch only wallet where multisig descriptor will be imported
        ms = bitcoind.create_wallet(
            wallet_name=f"watch_only_{script_type}_{M}of{N}", disable_private_keys=True,
            blank=True, passphrase=None, avoid_reuse=False, descriptors=True
        )
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Export XPUB')
        time.sleep(0.5)
        title, story = cap_story()
        assert "extended public keys (XPUB) you would need to join a multisig wallet" in story
        press_select()
        need_keypress(str(cc_account))  # account
        press_select()
        xpub_obj = load_export(way, label="Multisig XPUB", is_json=True, sig_check=False)
        template = xpub_obj[script_type +"_desc"]
        acct_deriv = xpub_obj[script_type + '_deriv']

        if tapscript_threshold:
            me = f"[{xpub_obj['xfp']}/{acct_deriv.replace('m/','')}]{xpub_obj[script_type]}/<0;1>/*"
            signers_xp = [me] + bitcoind_signers_xpubs
            assert len(signers_xp) == N
            desc = f"tr({H},%s)"
            if internal_key:
                desc = desc.replace(H, internal_key)
            elif r:
                desc = desc.replace(H, f"r={r}")

            scripts = []
            for c in itertools.combinations(signers_xp, M):
                tmplt = f"sortedmulti_a({M},{','.join(c)})"
                scripts.append(tmplt)

            if len(scripts) > 8:
                while True:
                    # just some of them but at least one has to have my key
                    x = random.sample(scripts, 8)
                    if any(me in s for s in x):
                        scripts = x
                        break

            if add_own_pk:
                if len(scripts) < 8:
                    if same_account:
                        cc_key = get_cc_key("m/86h/1h/0h", subderiv="/<2;3>/*")
                    else:
                        cc_key = get_cc_key("m/86h/1h/1000h")
                    cc_pk_leaf = f"pk({cc_key})"
                    scripts.append(cc_pk_leaf)
                else:
                    pytest.skip("Scripts full")

            temp = TREE[len(scripts)]
            temp = temp % tuple(scripts)

            desc = desc % temp

        else:
            if add_own_pk:
                if same_account:
                    ss = [get_cc_key("m/86h/1h/0h", subderiv="/<4;5>/*")] + bitcoind_signers_xpubs
                    cc_key = get_cc_key("m/86h/1h/0h", subderiv="/<6;7>/*")
                else:
                    ss = [get_cc_key("m/86h/1h/0h")] + bitcoind_signers_xpubs
                    cc_key = get_cc_key("m/86h/1h/1000h")

                tmplt = f"sortedmulti_a({M},{','.join(ss)})"
                cc_pk_leaf = f"pk({cc_key})"
                desc = f"tr({H},{{{tmplt},{cc_pk_leaf}}})"
            else:
                desc = template.replace("M", str(M), 1).replace("...", ",".join(bitcoind_signers_xpubs))

            if internal_key:
                desc = desc.replace(H, internal_key)
            elif r:
                desc = desc.replace(H, f"r={r}")

        name = "minisc"
        fname = None
        if way in ["sd", "vdisk"]:
            data = None
            fname = f"{name}.txt"
            path_f = microsd_path if way == 'sd' else virtdisk_path
            fpath = path_f(fname)
            with open(fpath, "w") as f:
                f.write(desc + "\n")
            garbage_collector.append(fpath)
        else:
            data = dict(name=name, desc=desc)

        _, story = import_miniscript(fname, way=way, data=data)
        assert "Create new miniscript wallet?" in story
        assert name in story
        if script_type == "p2tr":
            assert "Taproot internal key" in story
            assert "Tapscript" in story
        assert "Press (1) to see extended public keys" in story
        if script_type == "p2wsh":
            assert "P2WSH" in story
        elif script_type == "p2sh":
            assert "P2SH" in story
        elif script_type == "p2tr":
            assert "P2TR" in story
        else:
            assert "P2SH-P2WSH" in story
        # assert "Derivation:\n  Varies (2)" in story
        press_select()  # approve multisig import
        if r == "@":
            # unspendable key is generated randomly
            # descriptors will differ
            with pytest.raises(AssertionError):
                import_duplicate(fname, way=way, data=data)
        else:
            import_duplicate(fname, way=way, data=data)
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        menu = cap_menu()
        pick_menu_item(menu[0])  # pick imported descriptor multisig wallet
        pick_menu_item("Descriptors")
        pick_menu_item("Bitcoin Core")
        text = load_export(way, label="Bitcoin Core miniscript", is_json=False, sig_check=False)
        text = text.replace("importdescriptors ", "").strip()
        # remove junk
        r1 = text.find("[")
        r2 = text.find("]", -1, 0)
        text = text[r1: r2]
        core_desc_object = json.loads(text)
        # import descriptors to watch only wallet
        res = ms.importdescriptors(core_desc_object)
        assert res[0]["success"]
        assert res[1]["success"]

        if r and r != "@":
            from pysecp256k1.extrakeys import keypair_create, keypair_xonly_pub, xonly_pubkey_parse
            from pysecp256k1.extrakeys import xonly_pubkey_tweak_add, xonly_pubkey_serialize, xonly_pubkey_from_pubkey
            H_xo = xonly_pubkey_parse(bytes.fromhex(H))
            r_bytes = bytes.fromhex(r)
            kp = keypair_create(r_bytes)
            kp_xo, kp_parity = keypair_xonly_pub(kp)
            pk = xonly_pubkey_tweak_add(H_xo, xonly_pubkey_serialize(kp_xo))
            xo, xo_parity = xonly_pubkey_from_pubkey(pk)
            internal_key_bytes = xonly_pubkey_serialize(xo)
            internal_key_hex = internal_key_bytes.hex()
            assert internal_key_hex in core_desc_object[0]["desc"]
            assert internal_key_hex in core_desc_object[1]["desc"]

        if funded:
            if script_type == "p2wsh":
                addr_type = "bech32"
            elif script_type == "p2tr":
                addr_type = "bech32m"
            elif script_type == "p2sh":
                addr_type = "legacy"
            else:
                addr_type = "p2sh-segwit"

            addr = ms.getnewaddress("", addr_type)
            if script_type == "p2wsh":
                sw = "bcrt1q"
            elif script_type == "p2tr":
                sw = "bcrt1p"
            else:
                sw = "2"
            assert addr.startswith(sw)
            # get some coins and fund above multisig address
            bitcoind.supply_wallet.sendtoaddress(addr, 49)
            bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

        return ms, bitcoind_signers

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("add_pk", [True, False])
@pytest.mark.parametrize("same_acct", [None, True, False])
@pytest.mark.parametrize("way", ["qr", "sd"])
@pytest.mark.parametrize("M_N", [(3,4),(4,5),(5,6)])
def test_tapscript(M_N, cc_first, clear_miniscript, goto_home, pick_menu_item,
                   cap_menu, cap_story, microsd_path, use_regtest, bitcoind, microsd_wipe,
                   load_export, bitcoind_miniscript, add_pk, same_acct, get_cc_key,
                   press_select, way, skip_if_useless_way, garbage_collector):
    skip_if_useless_way(way)
    M, N = M_N
    clear_miniscript()
    microsd_wipe()
    internal_key = None
    if same_acct is None:
        internal_key = ranged_unspendable_internal_key()
    elif same_acct:
        # provide internal key with same account derivation (change based derivation)
        internal_key = get_cc_key("m/86h/1h/0h", subderiv='/<10;11>/*')

    wo, signers = bitcoind_miniscript(M, N, "p2tr", tapscript_threshold=True,
                                      add_own_pk=add_pk, internal_key=internal_key,
                                      same_account=same_acct, way=way)
    addr = wo.getnewaddress("", "bech32m")
    bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    conso_addr = wo.getnewaddress("conso", "bech32m")
    psbt = wo.walletcreatefundedpsbt([], [{conso_addr:25}], 0, {"fee_rate": 2})["psbt"]
    if not cc_first:
        for s in signers[0:M-1]:
            psbt = s.walletprocesspsbt(psbt, True, "DEFAULT")["psbt"]

    psbt_fpath = microsd_path("ts_tree.psbt")
    with open(psbt_fpath, "w") as f:
        f.write(psbt)

    garbage_collector.append(psbt_fpath)
    time.sleep(2)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item("ts_tree.psbt")
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    press_select()
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "PSBT Signed"
    fname = [i for i in story.split("\n\n") if ".psbt" in i][0]
    fpath = microsd_path(fname)
    with open(fpath, "r") as f:
        psbt = f.read().strip()
    garbage_collector.append(fpath)
    if cc_first:
        # we MUST be able to finalize this without anyone else if add pk
        if not add_pk:
            for s in signers[0:M-1]:
                psbt = s.walletprocesspsbt(psbt, True, "DEFAULT")["psbt"]
    res = wo.finalizepsbt(psbt)
    assert res["complete"] is True
    accept_res = wo.testmempoolaccept([res["hex"]])[0]
    assert accept_res["allowed"] is True
    txid = wo.sendrawtransaction(res["hex"])
    assert len(txid) == 64


@pytest.mark.bitcoind
@pytest.mark.parametrize("csa", [True, False])
@pytest.mark.parametrize("add_pk", [True, False])
@pytest.mark.parametrize('M_N', [(3, 15), (2, 2), (3, 5)])
@pytest.mark.parametrize('way', ["qr", "sd", "vdisk", "nfc"])
@pytest.mark.parametrize('internal_type', ["unspend(", "xpub", "static"])
def test_bitcoind_tapscript_address(M_N, clear_miniscript, bitcoind_miniscript,
                                    use_regtest, way, csa, address_explorer_check,
                                    add_pk, internal_type, skip_if_useless_way):
    skip_if_useless_way(way)
    use_regtest()
    clear_miniscript()
    M, N = M_N

    ik = None  # default static
    if internal_type == "unspend(":
        ik = f"unspend({os.urandom(32).hex()})/<20;21>/*"
    elif internal_type == "xpub":
        ik = ranged_unspendable_internal_key(os.urandom(32))

    ms_wo, _ = bitcoind_miniscript(M, N, "p2tr", funded=False, tapscript_threshold=csa,
                                   add_own_pk=add_pk, way=way, internal_key=ik)
    address_explorer_check(way, "bech32m", ms_wo, "minisc")


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("m_n", [(2,2), (3, 5), (32, 32)])
@pytest.mark.parametrize("way", ["qr", "sd"])
@pytest.mark.parametrize("internal_key_spendable", [
    True,
    False,
    "77ec0c0fdb9733e6a3c753b1374c4a465cba80dff52fc196972640a26dd08b76",
    "@",
    "tpubD6NzVbkrYhZ4WhUnV3cPSoRWGf9AUdG2dvNpsXPiYzuTnxzAxemnbajrATDBWhaAVreZSzoGSe3YbbkY2K267tK3TrRmNiLH2pRBpo8yaWm/<2;3>/*",
    "unspend(c72231504cf8c1bbefa55974db4e0cdac781049a9a81a87e7ff5beeb45b34d3d)/<0;1>/*"
])
def test_tapscript_multisig(cc_first, m_n, internal_key_spendable, use_regtest, bitcoind, goto_home, cap_menu,
                            pick_menu_item, cap_story, microsd_path, load_export, microsd_wipe, dev, way,
                            bitcoind_miniscript, clear_miniscript, get_cc_key, press_cancel, press_select,
                            skip_if_useless_way, garbage_collector):
    skip_if_useless_way(way)
    M, N = m_n
    clear_miniscript()
    microsd_wipe()
    internal_key = None
    r = None
    if internal_key_spendable is True:
        internal_key = get_cc_key("86h/0h/3h")
    elif internal_key_spendable == "@":
        r = "@"
    elif isinstance(internal_key_spendable, str):
        if len(internal_key_spendable) == 64:
            r = internal_key_spendable
        else:
            internal_key = internal_key_spendable

    tapscript_wo, bitcoind_signers = bitcoind_miniscript(
        M, N, "p2tr", internal_key=internal_key, r=r,
        way=way
    )

    dest_addr = tapscript_wo.getnewaddress("", "bech32m")
    psbt = tapscript_wo.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 20})["psbt"]
    fname = "tapscript.psbt"
    if not cc_first:
        # bitcoind cosigner sigs first
        for i in range(M - 1):
            signer = bitcoind_signers[i]
            psbt = signer.walletprocesspsbt(psbt, True, "DEFAULT", True)["psbt"]

    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)

    garbage_collector.append(fpath)
    goto_home()
    # bug in goto_home ?
    press_cancel()
    time.sleep(0.1)
    # CC signing
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    press_select()
    time.sleep(0.1)
    title, story = cap_story()
    split_story = story.split("\n\n")
    cc_tx_id = None
    if "(ready for broadcast)" in story:
        signed_fname = split_story[1]
        signed_txn_fname = split_story[-2]
        cc_tx_id = split_story[-1].split("\n")[-1]
        txn_fpath = microsd_path(signed_txn_fname)
        with open(txn_fpath, "r") as f:
            signed_txn = f.read().strip()
        garbage_collector.append(txn_fpath)
    else:
        signed_fname = split_story[-1]

    fpath = microsd_path(signed_fname)
    with open(fpath, "r") as f:
        signed_psbt = f.read().strip()

    garbage_collector.append(fpath)
    if cc_first:
        for signer in bitcoind_signers:
            signed_psbt = signer.walletprocesspsbt(signed_psbt, True, "DEFAULT", True)["psbt"]
    res = tapscript_wo.finalizepsbt(signed_psbt, True)
    assert res['complete']
    tx_hex = res["hex"]
    res = bitcoind.supply_wallet.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    if cc_tx_id:
        assert tx_hex == signed_txn
        assert txn_id == cc_tx_id
    assert len(txn_id) == 64


@pytest.mark.parametrize("num_leafs", [1, 2, 5, 8])
@pytest.mark.parametrize("internal_key_spendable", [True, False])
def test_tapscript_pk(num_leafs, use_regtest, clear_miniscript, microsd_wipe, bitcoind,
                      internal_key_spendable, dev, microsd_path, get_cc_key,
                      pick_menu_item, cap_story, goto_home, cap_menu, load_export,
                      import_miniscript, bitcoin_core_signer, import_duplicate,
                      press_select, garbage_collector):
    use_regtest()
    clear_miniscript()
    microsd_wipe()
    tmplt = TREE[num_leafs]
    bitcoind_signers_xpubs = []
    bitcoind_signers = []
    for i in range(num_leafs):
        s, core_key = bitcoin_core_signer(f"bitcoind--signer{i}")
        bitcoind_signers.append(s)
        bitcoind_signers_xpubs.append(core_key)

    bitcoin_signer_leafs = [f"pk({k})" for k in bitcoind_signers_xpubs]

    cc_key = get_cc_key("86h/0h/100h")
    cc_leaf = f"pk({cc_key})"

    if internal_key_spendable:
        desc = f"tr({cc_key},{tmplt % (*bitcoin_signer_leafs,)})"
    else:
        internal_key = bitcoind_signers_xpubs[0]
        leafs = bitcoin_signer_leafs[1:] + [cc_leaf]
        random.shuffle(leafs)
        desc = f"tr({internal_key},{tmplt % (*leafs,)})"

    ts = bitcoind.create_wallet(
        wallet_name=f"watch_only_pk_ts", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )

    fname = "ts_pk.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc + "\n")

    garbage_collector.append(fpath)
    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Taproot internal key" in story
    assert "Tapscript" in story
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    press_select()
    import_duplicate(fname)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    menu = cap_menu()
    pick_menu_item(menu[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # import descriptors to watch only wallet
    res = ts.importdescriptors(core_desc_object)
    assert res[0]["success"]
    assert res[1]["success"]

    addr = ts.getnewaddress("", "bech32m")
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    dest_addr = ts.getnewaddress("", "bech32m")  # selfspend
    psbt = ts.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 2})["psbt"]
    fname = "ts_pk.psbt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)

    garbage_collector.append(fpath)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()

    garbage_collector.append(fpath_psbt)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = ts.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = ts.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    assert txn_id


@pytest.mark.parametrize("desc", [
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti_a(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*),sortedmulti_a(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)},sortedmulti_a(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)})#tpm3afjn",
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)}})",
    "tr(tpubD6NzVbkrYhZ4XB7hZjurMYsPsgNY32QYGZ8YFVU7cy1VBRNoYpKAVuUfqfUFss6BooXRrCeYAdK9av2yFnqWXZaUMJuZdpE9Kuh6gubCVHu/<0;1>/*,{sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)}})",
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)})",
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},or_d(pk([0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*),and_v(v:pkh([30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),older(500)))})",
    "tr(unspend(b320077905d0954b01a8a328ea08c0ac3b4b066d1240f47a1b2c58651dcda4eb)/<0;1>/*,{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},or_d(pk([0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*),and_v(v:pkh([30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),older(500)))})",
])
def test_tapscript_import_export(clear_miniscript, pick_menu_item, cap_story,
                                 import_miniscript, load_export, desc, microsd_path,
                                 press_select):
    clear_miniscript()
    fname = "imdesc.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    _, story = import_miniscript(fname)
    press_select()  # approve miniscript import
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Export")
    time.sleep(.1)
    title, story = cap_story()
    assert "(<0;1> notation) press OK" in story
    press_select()
    contents = load_export("sd", label="Miniscript", is_json=False, addr_fmt=AF_P2TR,
                           sig_check=False)
    descriptor = contents.strip()
    assert desc.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h") == descriptor.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h")


def test_duplicate_tapscript_leaves(use_regtest, clear_miniscript, microsd_wipe, bitcoind, dev,
                                    goto_home, pick_menu_item, microsd_path, import_miniscript,
                                    cap_story, load_export, get_cc_key, garbage_collector,
                                    bitcoin_core_signer, import_duplicate, press_select):
    # works in core - but some discussions are ongoing
    # https://github.com/bitcoin/bitcoin/issues/27104
    # CC also allows this for now... (experimental branch)
    use_regtest()
    clear_miniscript()
    microsd_wipe()
    ss, core_key = bitcoin_core_signer(f"dup_leafs")

    cc_key = get_cc_key("86h/0h/100h")
    cc_leaf = f"pk({cc_key})"

    tmplt = TREE[2]
    tmplt = tmplt % (cc_leaf, cc_leaf)
    desc = f"tr({core_key},{tmplt})"
    fname = "dup_leafs.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Taproot internal key" in story
    assert "Tapscript" in story
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    press_select()
    import_duplicate(fname)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # wo wallet
    ts = bitcoind.create_wallet(
        wallet_name=f"dup_leafs_wo", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    # import descriptors to watch only wallet
    res = ts.importdescriptors(core_desc_object)
    assert res[0]["success"]
    assert res[1]["success"]

    addr = ts.getnewaddress("", "bech32m")
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    dest_addr = ts.getnewaddress("", "bech32m")  # selfspend
    psbt = ts.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 2})["psbt"]
    fname = "ts_pk.psbt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = ts.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = ts.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    assert txn_id


def test_same_key_account_based_minisc(goto_home, pick_menu_item, cap_story,
                                       clear_miniscript, microsd_path, load_export, bitcoind,
                                       import_miniscript, use_regtest, import_duplicate,
                                       press_select, garbage_collector):
    clear_miniscript()
    use_regtest()

    desc = ("wsh("
            "or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),"
            "and_v("
            "v:pkh([0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*),"
            "older(5))))#qmwvph5c")

    name = "mini-accounts"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Press (1) to see extended public keys" in story

    press_select()
    import_duplicate(fname)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # wo wallet
    wo = bitcoind.create_wallet(
        wallet_name=f"multi-account", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    # import descriptors to watch only wallet
    res = wo.importdescriptors(core_desc_object)
    assert res[0]["success"]
    assert res[1]["success"]

    addr = wo.getnewaddress("", "bech32")
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    dest_addr = wo.getnewaddress("", "bech32")  # selfspend
    psbt = wo.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 2})["psbt"]
    fname = "multi-acct.psbt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)

    _psbt = BasicPSBT().parse(final_psbt.encode())
    assert len(_psbt.inputs[0].part_sigs) == 2
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    assert txn_id


CHANGE_BASED_DESCS = [
    (
        "wsh("
            "or_d("
                "pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),"
                "and_v("
                    "v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*),"
                    "older(5)"
                ")"
            ")"
        ")#aq0kpuae"
    ),
    (
        "wsh(or_i("
            "and_v("
                "v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2147483646;2147483647>/*),"
                "older(10)"
            "),"
            "or_d("
                "multi("
                    "3,"
                    "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<100;101>/*,"
                    "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<26;27>/*,"
                    "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<4;5>/*"
                "),"
                "and_v("
                    "v:thresh("
                        "2,"
                        "pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<20;21>/*),"
                        "a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<104;105>/*),"
                        "a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<22;23>/*)"
                    "),"
                    "older(5)"
                ")"
            ")"
        "))#a4nfkskx"
    ),
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*),older(5))),or_i(and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2147483646;2147483647>/*),older(10)),or_d(multi_a(3,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<100;101>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<26;27>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<4;5>/*),and_v(v:thresh(2,pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<20;21>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<104;105>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<22;23>/*)),older(5))))})#z5x7409w",
    "tr([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<66;67>/*,{or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*),older(5))),or_i(and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2147483646;2147483647>/*),older(10)),or_d(multi_a(3,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<100;101>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<26;27>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<4;5>/*),and_v(v:thresh(2,pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<20;21>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<104;105>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<22;23>/*)),older(5))))})#qqcy9jlr",
]

@pytest.mark.parametrize("desc", CHANGE_BASED_DESCS)
def test_same_key_change_based_minisc(goto_home, pick_menu_item, cap_story,
                                      clear_miniscript, microsd_path, load_export, bitcoind,
                                      import_miniscript, address_explorer_check, use_regtest,
                                      desc, press_select, garbage_collector):
    clear_miniscript()
    use_regtest()
    if desc.startswith("tr("):
        af = "bech32m"
    else:
        af = "bech32"

    name = "mini-change"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Press (1) to see extended public keys" in story

    press_select()
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # wo wallet
    wo = bitcoind.create_wallet(
        wallet_name=f"minsc-change", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    # import descriptors to watch only wallet
    res = wo.importdescriptors(core_desc_object)
    assert res[0]["success"]
    assert res[1]["success"]

    addr = wo.getnewaddress("", af)
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    dest_addr = wo.getnewaddress("", af)  # selfspend
    psbt = wo.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 2})["psbt"]
    fname = "msc-change-conso.psbt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    assert txn_id

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    dest_addr_0 = bitcoind.supply_wallet.getnewaddress()
    dest_addr_1 = bitcoind.supply_wallet.getnewaddress()
    dest_addr_2 = bitcoind.supply_wallet.getnewaddress()
    psbt = wo.walletcreatefundedpsbt(
        [],
        [{dest_addr_0: 1.0}, {dest_addr_1: 2.56}, {dest_addr_2: 12.99}],
        0, {"fee_rate": 2}
    )["psbt"]
    fname = "msc-change-send.psbt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(tx_hex)
    assert txn_id

    # check addresses
    address_explorer_check("sd", af, wo, "mini-change")


def test_same_key_account_based_multisig(goto_home, pick_menu_item, cap_story,
                                         clear_miniscript, microsd_path, load_export, bitcoind,
                                         import_miniscript, garbage_collector):
    clear_miniscript()
    desc = ("wsh(sortedmulti(2,"
            "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*,"
            "[0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*"
            "))")
    name = "multi-accounts"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "Use Settings -> Multisig Wallets" in story


@pytest.mark.parametrize("desc", [
    "wsh(or_d(pk(@A),and_v(v:pkh(@A),older(5))))",
    "tr(%s,multi_a(2,@A,@A))" % H,
    "tr(%s,{sortedmulti_a(2,@A,@A),pk(@A)})" % H,
    "tr(%s,or_d(pk(@A),and_v(v:pkh(@A),older(5))))" % H,
])
def test_insane_miniscript(get_cc_key, pick_menu_item, cap_story,
                           microsd_path, desc, import_miniscript,
                           garbage_collector):

    cc_key = get_cc_key("84h/0h/0h")
    desc = desc.replace("@A", cc_key)
    fname = "insane.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "Insane" in story

def test_tapscript_depth(get_cc_key, pick_menu_item, cap_story,
                         microsd_path, import_miniscript, garbage_collector):
    leaf_num = 9
    scripts = []
    for i in range(leaf_num):
        k = get_cc_key(f"84h/0h/{i}h")
        scripts.append(f"pk({k})")

    tree = TREE[leaf_num] % tuple(scripts)
    desc = f"tr({H},{tree})"
    fname = "9leafs.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)
    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "num_leafs > 8" in story

@pytest.mark.bitcoind
@pytest.mark.parametrize("lt_type", ["older", "after"])
@pytest.mark.parametrize("same_acct", [True, False])
@pytest.mark.parametrize("recovery", [True, False])
@pytest.mark.parametrize("leaf2_mine", [True, False])
@pytest.mark.parametrize("internal_type", ["unspend(", "xpub", "static"])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",

    "or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi_a(2,@B,@C),locktime(N)))",
])
def test_minitapscript(leaf2_mine, recovery, lt_type, minisc, clear_miniscript, goto_home,
                       pick_menu_item, cap_menu, cap_story, microsd_path, internal_type,
                       use_regtest, bitcoind, microsd_wipe, load_export, dev,
                       address_explorer_check, get_cc_key, import_miniscript,
                       bitcoin_core_signer, same_acct, import_duplicate, press_select,
                       garbage_collector):

    # needs bitcoind 26.0
    normal_cosign_core = False
    recovery_cosign_core = False
    if "multi_a(" in minisc.split("),", 1)[0]:
        normal_cosign_core = True
    if "multi_a(" in minisc.split("),", 1)[-1]:
        recovery_cosign_core = True

    if lt_type == "older":
        sequence = 5
        locktime = 0
        # 101 blocks are mined by default
        to_replace = "older(5)"
    else:
        sequence = None
        locktime = 105
        to_replace = "after(105)"

    minisc = minisc.replace("locktime(N)", to_replace)

    core_keys = []
    signers = []
    for i in range(3):
        # core signers
        signer, core_key = bitcoin_core_signer(f"co-signer{i}")
        core_keys.append(core_key)
        signers.append(signer)

    # cc device key
    if same_acct:
        cc_key = get_cc_key("86h/1h/0h", subderiv="/<4;5>/*")
        cc_key1 = get_cc_key("86h/1h/0h", subderiv="/<6;7>/*")
    else:
        cc_key = get_cc_key("86h/1h/0h")
        cc_key1 = get_cc_key("86h/1h/1h")

    if recovery:
        # recevoery path is always B
        minisc = minisc.replace("@B", cc_key)
        minisc = minisc.replace("@A", core_keys[0])
    else:
        minisc = minisc.replace("@A", cc_key)
        minisc = minisc.replace("@B", core_keys[0])

    if "@C" in minisc:
        minisc = minisc.replace("@C", core_keys[1])

    ik = H
    if internal_type == "unspend(":
        ik = f"unspend({os.urandom(32).hex()})/<2;3>/*"
    elif internal_type == "xpub":
        ik = ranged_unspendable_internal_key(os.urandom(32))

    if leaf2_mine:
        desc = f"tr({ik},{{{minisc},pk({cc_key1})}})"
    else:
        desc = f"tr({ik},{{pk({core_keys[2]}),{minisc}}})"

    use_regtest()
    clear_miniscript()
    name = "minitapscript"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    garbage_collector.append(fpath)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    import_duplicate(fname)
    menu = cap_menu()
    assert menu[0] == name
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]
    addr = wo.getnewaddress("", "bech32m")
    addr_dest = wo.getnewaddress("", "bech32m")  # self-spend
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    if recovery and sequence and not leaf2_mine:
        inp["sequence"] = sequence
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{addr_dest: all_of_it - 1}],
        locktime if (recovery and not leaf2_mine) else 0,
        {"fee_rate": 20, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    if (normal_cosign_core or recovery_cosign_core) and not leaf2_mine:
        psbt = signers[1].walletprocesspsbt(psbt, True, "ALL")["psbt"]

    name = f"{name}.psbt"
    fpath = microsd_path(name)
    with open(fpath, "w") as f:
        f.write(psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    if recovery and not leaf2_mine:
        assert not res[0]["allowed"]
        assert res[0]["reject-reason"] == 'non-BIP68-final' if sequence else "non-final"
        bitcoind.supply_wallet.generatetoaddress(6, bitcoind.supply_wallet.getnewaddress())
        res = wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
    else:
        assert res[0]["allowed"]

    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses
    address_explorer_check("sd", "bech32m", wo, "minitapscript")

@pytest.mark.parametrize("desc", [
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*),sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)},sortedmulti(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)})",
    "wsh(sortedmulti_a(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*))",
    "sh(wsh(or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:multi_a(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),older(500)))))",
])
def test_multi_mixin(desc, clear_miniscript, microsd_path, pick_menu_item,
                     cap_story, import_miniscript, garbage_collector):
    clear_miniscript()
    fname = "imdesc.txt"
    fpath = microsd_path(fname)
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    title, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "multi mixin" in story


def test_timelock_mixin():
    pass


@pytest.mark.parametrize("addr_fmt", ["bech32", "bech32m"])
@pytest.mark.parametrize("cc_first", [True, False])
def test_d_wrapper(addr_fmt, bitcoind, get_cc_key, goto_home, pick_menu_item, cap_story, cap_menu,
                   load_export, microsd_path, use_regtest, clear_miniscript, cc_first,
                   address_explorer_check, import_miniscript, bitcoin_core_signer, press_select,
                   garbage_collector):

    # check D wrapper u property for segwit v0 and v1
    # https://github.com/bitcoin/bitcoin/pull/24906/files
    minsc = "thresh(3,c:pk_k(@A),sc:pk_k(@B),sc:pk_k(@C),sdv:older(5))"

    core_keys = []
    signers = []
    for i in range(2):
        # core signers
        signer, core_key = bitcoin_core_signer(f"co-signer{i}")
        core_keys.append(core_key)
        signers.append(signer)

    cc_key = get_cc_key(f"{84 if addr_fmt == 'bech32' else 86}h/1h/0h")

    minsc = minsc.replace("@A", cc_key)
    minsc = minsc.replace("@B", core_keys[0])
    minsc = minsc.replace("@C", core_keys[1])

    if addr_fmt == "bech32":
        desc = f"wsh({minsc})"
    else:
        desc = f"tr({H},{minsc})"

    name = "d_wrapper"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    clear_miniscript()
    use_regtest()
    _, story = import_miniscript(fname)
    if addr_fmt == "bech32":
        assert "Failed to import" in story
        assert "thresh: X3 should be du" in story
        return

    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    menu = cap_menu()
    assert menu[0] == name
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]

    addr = wo.getnewaddress("", addr_fmt)  # self-spend
    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    inp["sequence"] = 5
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{addr_dest: all_of_it - 1}],
        0,
        {"fee_rate": 20, "change_type": addr_fmt},
    )
    psbt = psbt_resp.get("psbt")

    if not cc_first:
        to_sign_psbt_o = signers[0].walletprocesspsbt(psbt, True)
        to_sign_psbt = to_sign_psbt_o["psbt"]
        assert to_sign_psbt != psbt
    else:
        to_sign_psbt = psbt

    name = f"{name}.psbt"
    fpath = microsd_path(name)
    with open(fpath, "w") as f:
        f.write(to_sign_psbt)
    garbage_collector.append(fpath)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(fpath_psbt, "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath_psbt)
    assert final_psbt != to_sign_psbt
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()

    if cc_first:
        done_o = signers[0].walletprocesspsbt(final_psbt, True)
        done = done_o["psbt"]
    else:
        done = final_psbt

    res = wo.finalizepsbt(done)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    assert not res[0]["allowed"]
    assert res[0]["reject-reason"] == 'non-BIP68-final'
    bitcoind.supply_wallet.generatetoaddress(6, bitcoind.supply_wallet.getnewaddress())
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]

    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses
    address_explorer_check("sd", addr_fmt, wo, "d_wrapper")


def test_chain_switching(use_mainnet, use_regtest, settings_get, settings_set,
                         clear_miniscript, goto_home, cap_menu, pick_menu_item,
                         import_miniscript, microsd_path, press_select, garbage_collector):
    clear_miniscript()
    use_regtest()

    x = "wsh(or_d(pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),and_v(v:pkh([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),older(100))))"
    z = "wsh(or_d(pk([0f056943/48'/0'/0'/3']xpub6FQgdFZAHcAeDMVe9KxWoLMxziCjscCExzuKJhRSjM71CA9dUDZEGNgPe4S2SsRumCBXeaTBZ5nKz2cMDiK4UEbGkFXNipHLkm46inpjE9D/0/*),and_v(v:pkh([0f056943/48'/0'/0'/2']xpub6FQgdFZAHcAeAhQX2VvQ42CW2fDdKDhgwzhzXuUhWb4yfArmaZXkLbGS9W1UcgHwNxVESCS1b8BK8tgNYEF8cgmc9zkmsE45QSEvbwdp6Kr/0/*),older(100))))"
    y = f"tr({H},or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),after(800000))))"

    fname_btc = "BTC.txt"
    fname_xtn = "XTN.txt"
    fname_xtn0 = "XTN0.txt"

    for desc, fname in [(x, fname_xtn), (z, fname_btc), (y, fname_xtn0)]:
        fpath = microsd_path(fname)
        with open(fpath, "w") as f:
            f.write(desc)
        garbage_collector.append(fpath)

    # cannot import XPUBS when testnet/regtest enabled
    _, story = import_miniscript(fname_btc)
    assert "Failed to import" in story
    assert "wrong chain" in story

    import_miniscript(fname_xtn)
    press_select()
    # assert that wallets created at XRT always store XTN anywas (key_chain)
    res = settings_get("miniscript")
    assert len(res) == 1
    assert res[0][1] == "XTN"

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert "(none setup yet)" not in m
    assert fname_xtn.split(".")[0] in m[0]
    goto_home()
    settings_set("chain", "BTC")
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    # asterisk hints that some wallets are already stored
    # but not on current active chain
    assert "(none setup yet)*" in m
    import_miniscript(fname_btc)
    press_select()
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert fname_btc.split(".")[0] in m[0]
    for mi in m:
        assert fname_xtn.split(".")[0] not in mi

    _, story = import_miniscript(fname_xtn)
    assert "Failed to import" in story
    assert "wrong chain" in story

    settings_set("chain", "XTN")
    import_miniscript(fname_xtn0)
    press_select()
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert "(none setup yet)" not in m
    assert fname_xtn.split(".")[0] in m[0]
    assert fname_xtn0.split(".")[0] in m[1]
    for mi in m:
        assert fname_btc not in mi


@pytest.mark.parametrize("taproot_ikspendable", [
    (True, False), (True, True), (False, False)
])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),after(100)))",
    "or_d(multi(2,@A,@C),and_v(v:pkh(@B),after(100)))",
])
def test_import_same_policy_same_keys_diff_order(taproot_ikspendable, minisc,
                                                 clear_miniscript, use_regtest,
                                                 get_cc_key, bitcoin_core_signer,
                                                 offer_minsc_import, cap_menu,
                                                 bitcoind, pick_menu_item,
                                                 press_select):
    use_regtest()
    clear_miniscript()
    taproot, ik_spendable = taproot_ikspendable
    if taproot:
        minisc = minisc.replace("multi(", "multi_a(")
        if ik_spendable:
            ik = get_cc_key("84h/1h/100h", subderiv="/0/*")
            desc = f"tr({ik},{minisc})"
        else:
            desc = f"tr({H},{minisc})"
    else:
        desc = f"wsh({minisc})"

    cc_key0 = get_cc_key("84h/1h/0h", subderiv="/0/*")
    signer0, core_key0 = bitcoin_core_signer("s00")
    # recevoery path is always B
    desc0 = desc.replace("@A", cc_key0)
    desc0 = desc0.replace("@B", core_key0)

    if "@C" in desc:
        signer1, core_key1 = bitcoin_core_signer("s11")
        desc0 = desc0.replace("@C", core_key1)

    # now just change order of the keys (A,B), but same keys same policy
    desc1 = desc.replace("@B", cc_key0)
    desc1 = desc1.replace("@A", core_key0)

    if "@C" in desc:
        desc1 = desc1.replace("@C", core_key1)

    # checksum required if via USB
    desc_info = bitcoind.supply_wallet.getdescriptorinfo(desc0)
    desc0 = desc_info["descriptor"]  # with checksum
    desc_info = bitcoind.supply_wallet.getdescriptorinfo(desc1)
    desc1 = desc_info["descriptor"]  # with checksum

    title, story = offer_minsc_import(desc0)
    assert "Create new miniscript wallet?" in story
    press_select()
    time.sleep(.2)
    title, story = offer_minsc_import(desc1)
    assert "Create new miniscript wallet?" in story
    press_select()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    m = [i for i in m if not i.startswith("Import")]
    assert len(m) == 2


@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("way", ["usb", "nfc", "sd", "vdisk"])
def test_import_miniscript_usb_json(use_regtest, cs, way, cap_menu,
                                    clear_miniscript, pick_menu_item,
                                    get_cc_key, bitcoin_core_signer,
                                    offer_minsc_import, bitcoind, microsd_path,
                                    virtdisk_path, import_miniscript, goto_home,
                                    press_select):
    name = "my_minisc"
    minsc = f"tr({H},or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),after(100))))"
    use_regtest()
    clear_miniscript()

    cc_key = get_cc_key("84h/1h/0h", subderiv="/0/*")
    signer0, core_key0 = bitcoin_core_signer("s00")
    # recevoery path is always B
    desc = minsc.replace("@A", cc_key)
    desc = desc.replace("@B", core_key0)

    signer1, core_key1 = bitcoin_core_signer("s11")
    desc = desc.replace("@C", core_key1)

    if cs:
        desc_info = bitcoind.supply_wallet.getdescriptorinfo(desc)
        desc = desc_info["descriptor"]  # with checksum

    val = json.dumps({"name": name, "desc": desc})

    nfc_data = None
    fname = "diff_name.txt"  # will be ignored as name in the json has preference
    if way == "usb":
        title, story = offer_minsc_import(val)
    else:
        if way == "nfc":
            nfc_data = val
        else:
            if way == "sd":
                fpath = microsd_path(fname)
            else:
                fpath = virtdisk_path(fname)

            with open(fpath, "w") as f:
                f.write(val)

        title, story = import_miniscript(fname, way, nfc_data)

    assert "Create new miniscript wallet?" in story
    assert name in story
    press_select()
    time.sleep(.2)
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    m = [i for i in m if not i.startswith("Import")]
    assert len(m) == 1
    assert m[0] == name


@pytest.mark.parametrize("config", [
    # all dummy data there to satisfy badlen check in usb.py
    # missing 'desc' key
    {"name": "my_miniscript", "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    # name longer than 40 chars
    {"name": "a" * 41, "desc": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    # name too short
    {"name": "a", "desc": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    # desc key empty
    {"name": "ab", "desc": "", "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    # name type
    {"name": None, "desc": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    # desc type
    {"name": "ab", "desc": None, "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
])
def test_json_import_failures(config, offer_minsc_import):
    with pytest.raises(Exception):
        offer_minsc_import(json.dumps(config))


@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk"])
@pytest.mark.parametrize("is_json", [True, False])
def test_unique_name(clear_miniscript, use_regtest, offer_minsc_import,
                     pick_menu_item, cap_menu, way, goto_home,
                     microsd_path, virtdisk_path, is_json,
                     import_miniscript, press_select):
    clear_miniscript()
    use_regtest()

    name = "my_name"
    x = "wsh(or_d(pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),and_v(v:pkh([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),older(100))))"
    y = f"tr({H},or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),after(800000))))"

    xd = json.dumps({"name": name, "desc": x})
    title, story = offer_minsc_import(xd)
    assert "Create new miniscript wallet?" in story
    assert name in story
    press_select()
    time.sleep(.2)
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    m = [i for i in m if not i.startswith("Import")]
    assert len(m) == 1
    assert m[0] == name

    # completely different wallet but with the same name (USB)
    yd = json.dumps({"name": name, "desc": y})
    title, story = offer_minsc_import(yd)
    assert title == "FAILED"
    assert "MUST have unique names" in story
    press_select()
    # nothing imported
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    m = [i for i in m if not i.startswith("Import")]
    assert len(m) == 1
    assert m[0] == name

    goto_home()
    fname = f"{name}.txt"
    nfc_data = None
    if way == "nfc":
        if not is_json:
            pytest.xfail("impossible")

        nfc_data = yd
    else:
        if way == "sd":
            fpath = microsd_path(fname)
        elif way == "vdisk":
            fpath = virtdisk_path(fname)
        else:
            assert False

        with open(fpath, "w") as f:
            f.write(yd if is_json else y)

    title, story = import_miniscript(fname=fname, way=way, data=nfc_data)
    assert "FAILED" == title
    assert "MUST have unique names" in story


@pytest.mark.qrcode
def test_usb_workflow(usb_miniscript_get, usb_miniscript_ls, clear_miniscript,
                      usb_miniscript_addr, usb_miniscript_delete, use_regtest,
                      reset_seed_words, offer_minsc_import, need_keypress,
                      cap_story, cap_screen_qr, press_select):
    use_regtest()
    reset_seed_words()
    clear_miniscript()
    assert [] == usb_miniscript_ls()
    for i, desc in enumerate(CHANGE_BASED_DESCS):
        _, story = offer_minsc_import(json.dumps({"name": f"w{i}", "desc": desc}))
        assert "Create new miniscript wallet?" in story
        press_select()
        time.sleep(.2)

    msc_wallets = usb_miniscript_ls()
    assert len(msc_wallets) == 4
    assert sorted(msc_wallets) == ["w0", "w1", "w2", "w3"]

    # try to get/delete nonexistent wallet
    with pytest.raises(Exception) as err:
        usb_miniscript_get("w4")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"

    with pytest.raises(Exception) as err:
        usb_miniscript_delete("w4")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"

    for i, w in enumerate(msc_wallets):
        assert usb_miniscript_get(w)["desc"].split("#")[0] == CHANGE_BASED_DESCS[i].split("#")[0].replace("'", 'h')

    #check random address
    addr = usb_miniscript_addr("w0", 55, False)
    time.sleep(0.1)
    need_keypress('4')
    time.sleep(0.1)
    qr = cap_screen_qr().decode('ascii')
    assert qr == addr.upper()

    usb_miniscript_delete("w3")
    time.sleep(.2)
    _, story = cap_story()
    assert "Delete miniscript wallet" in story
    assert "'w3'" in story
    press_select()
    time.sleep(.2)
    assert len(usb_miniscript_ls()) == 3
    with pytest.raises(Exception) as err:
        usb_miniscript_get("w3")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"

    usb_miniscript_delete("w2")
    time.sleep(.2)
    _, story = cap_story()
    assert "Delete miniscript wallet" in story
    assert "'w2'" in story
    press_select()
    time.sleep(.2)
    assert len(usb_miniscript_ls()) == 2
    with pytest.raises(Exception) as err:
        usb_miniscript_get("w2")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"

    usb_miniscript_delete("w1")
    time.sleep(.2)
    _, story = cap_story()
    assert "Delete miniscript wallet" in story
    assert "'w1'" in story
    press_select()
    time.sleep(.2)
    assert len(usb_miniscript_ls()) == 1
    with pytest.raises(Exception) as err:
        usb_miniscript_get("w1")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"

    usb_miniscript_delete("w0")
    time.sleep(.2)
    _, story = cap_story()
    assert "Delete miniscript wallet" in story
    assert "'w0'" in story
    press_select()
    time.sleep(.2)
    assert len(usb_miniscript_ls()) == 0
    with pytest.raises(Exception) as err:
        usb_miniscript_get("w0")
    assert err.value.args[0] == "Coldcard Error: Miniscript wallet not found"


def test_miniscript_name_validation(microsd_path, offer_minsc_import):
    for tc in ["weê", "eee\teee"]:
        with pytest.raises(Exception) as e:
            offer_minsc_import(json.dumps({"name": tc, "desc": CHANGE_BASED_DESCS[0]}))
        assert "must be ascii" in e.value.args[0]