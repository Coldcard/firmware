# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Miniscript-related tests.
#
import pytest, json, time, itertools, struct, random, os, base64
from ckcc.protocol import CCProtocolPacker
from constants import AF_P2TR
from psbt import BasicPSBT
from charcodes import KEY_QR, KEY_RIGHT, KEY_CANCEL, KEY_DELETE
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
    9: '{{{%s,{%s,%s}},{%s,%s}},{{%s,%s},{%s,%s}}}',
    10: '{{{{%s,%s},{%s,%s}},{%s,%s}},{{%s,%s},{%s,%s}}}',
    11: '{{{{%s,%s},{%s,%s}},{%s,%s}},{{%s,%s},{%s,{%s,%s}}}}',
    12: '{{{{%s,%s},{%s,%s}},{%s,%s}},{{%s,%s},{{%s,%s},{%s,%s}}}}',
}


def ranged_unspendable_internal_key(chain_code=32 * b"\x01", subderiv="/<0;1>/*"):
    # provide ranged provably unspendable key in serialized extended key format for core to understand it
    # core does NOT understand 'unspend('
    pk = b"\x02" + bytes.fromhex(H)
    node = BIP32Node.from_chaincode_pubkey(chain_code, pk)
    return node.hwif() + subderiv


@pytest.fixture
def offer_minsc_import(cap_story, dev, sim_root_dir):
    def doit(config, allow_non_ascii=False):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('utf-8' if allow_non_ascii else 'ascii'))

        with open(f'{sim_root_dir}/debug/last-config-msc.txt', 'wt') as f:
            f.write(config)
        dev.send_recv(CCProtocolPacker.miniscript_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        return title, story

    return doit


@pytest.fixture
def import_miniscript(request, is_q1, need_keypress, offer_minsc_import, press_cancel):
    def doit(fname=None, way="sd", data=None, name=None):
        assert fname or data

        if fname:
            if way == "sd":
                microsd_path = request.getfixturevalue("microsd_path")
                fpath = microsd_path(fname)
            else:
                virtdisk_path = request.getfixturevalue("virtdisk_path")
                fpath = virtdisk_path(fname)
            with open(fpath, 'r') as f:
                config = f.read()
        else:
            config = data

        if way in ("usb", None):
            return offer_minsc_import(config)
        else:
            # only get those simulator related fixtures here, to be able to
            # use this with real HW
            cap_menu = request.getfixturevalue('cap_menu')
            cap_story = request.getfixturevalue('cap_story')
            goto_home = request.getfixturevalue('goto_home')
            press_nfc = request.getfixturevalue('press_nfc')
            pick_menu_item = request.getfixturevalue('pick_menu_item')

            goto_home()
            pick_menu_item("Settings")
            pick_menu_item("Miniscript")
            time.sleep(.1)

            pick_menu_item('Import')
            time.sleep(.2)
            _, story = cap_story()
            if way == "nfc":
                if "via NFC" not in story:
                    press_cancel()
                    pytest.skip("nfc disabled")

                press_nfc()
                time.sleep(.1)
                if isinstance(config, dict):
                    config = json.dumps(config)

                nfc_write_text = request.getfixturevalue('nfc_write_text')
                nfc_write_text(config)
                time.sleep(1)
                return cap_story()
            elif way == "qr":
                scan_a_qr = request.getfixturevalue('scan_a_qr')
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

            if not fname:
                microsd_path = request.getfixturevalue("microsd_path")
                virtdisk_path = request.getfixturevalue("virtdisk_path")
                path_f = microsd_path if way == "sd" else virtdisk_path
                fname = (name or "ms_wal") + ".txt"
                with open(path_f(fname), "w") as f:
                    f.write(config)

            if "Press (1) to import miniscript wallet file from SD Card" in story:
                # in case Vdisk or NFC is enabled
                if way == "sd":
                    need_keypress("1")

                elif way == "vdisk":
                    if "ress (2)" not in story:
                        press_cancel()
                        pytest.xfail(way)

                    need_keypress("2")
            else:
                if way != "sd":
                    pytest.xfail(way)

            time.sleep(.3)
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

            press_cancel()
            title, story = import_miniscript(new_fname, way, data=data)
            time.sleep(.2)

        assert "Duplicate wallet" in story
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
        qr_data = None
        goto_home()
        pick_menu_item("Settings")
        pick_menu_item("Miniscript")
        pick_menu_item(minsc_name)
        pick_menu_item("Descriptors")
        pick_menu_item("Export")
        time.sleep(.1)
        if is_q1:
            # check QR
            need_keypress(KEY_QR)
            try:
                file_type, data = readback_bbqr()
                assert file_type == "U"
                qr_data = data.decode().strip()
            except:
                qr_data = cap_screen_qr().decode('ascii').strip()

            need_keypress(KEY_CANCEL)

            pick_menu_item("Export")
            time.sleep(.2)

        title, story = cap_story()
        if "Press (1)" in story:
            need_keypress("1")
            time.sleep(.2)
            title, story = cap_story()

        assert "Miniscript file written" in story
        assert "signature file written" in story
        fname = story.split("\n\n")[1]
        fpath = microsd_path(fname)
        garbage_collector.append(fpath)
        with open(fpath, "r") as f:
            cont = f.read().strip()

        if qr_data:
            assert qr_data == cont
        return cont

    return doit


@pytest.fixture
def usb_miniscript_get(dev):
    def doit(name):
        dev.check_mitm()
        resp = dev.send_recv(CCProtocolPacker.miniscript_get(name))
        return json.loads(resp)

    return doit


@pytest.fixture
def usb_miniscript_policy(dev):
    def doit(name):
        dev.check_mitm()
        resp = dev.send_recv(CCProtocolPacker.miniscript_policy(name))
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
                           cap_story, miniscript_descriptors, load_export,
                           usb_miniscript_addr, cap_screen_qr, press_select):
    def doit(way, addr_fmt, wallet, cc_minsc_name, export_check=True):
        goto_home()
        pick_menu_item("Address Explorer")
        need_keypress('4')  # warning
        m = cap_menu()
        wal_name = m[-1]
        pick_menu_item(wal_name)

        time.sleep(1)
        if way == "qr":
            need_keypress(KEY_QR)
            cc_addrs = []
            for i in range(10):
                cc_addrs.append(cap_screen_qr().decode())
                need_keypress(KEY_RIGHT)
                time.sleep(.2)
            need_keypress(KEY_CANCEL)
        else:
            contents = load_export(way, label="Address summary", is_json=False)
            addr_cont = contents.strip()
            press_select()


        time.sleep(1)
        title, story = cap_story()

        assert "change addresses." in story and "(0)" in story
        need_keypress("0")

        time.sleep(1)
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
            contents_change = load_export(way, label="Address summary", is_json=False)
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

            cc_addrs = cc_addrs_split[1:]
            cc_addrs_change = cc_addrs_split_change[1:]
            part_addr_index = 1

        internal_desc = None
        external_desc = None
        descriptors = wallet.listdescriptors()["descriptors"]
        for desc in descriptors:
            if desc["internal"]:
                internal_desc = desc["desc"]
            else:
                external_desc = desc["desc"]

        time.sleep(1)

        if export_check:
            desc_export = miniscript_descriptors(cc_minsc_name)

            def remove_minisc_syntactic_sugar(descriptor, a, b):
                # syntactic sugar https://bitcoin.sipa.be/miniscript/
                target_len = len(a)
                idx = 0
                while idx != -1:
                    idx = descriptor.find(a, idx)
                    if idx == -1: break
                    # needs colon more identities than just 'c'
                    rep = f":{b}" if descriptor[idx-1] in "asctdvjnlu" else f"{b}"
                    descriptor = descriptor[:idx] + rep + descriptor[idx+target_len:]

                return descriptor

            desc_export = remove_minisc_syntactic_sugar(desc_export, "c:pk_k(", "pk(")
            desc_export = remove_minisc_syntactic_sugar(desc_export, "c:pk_h(", "pkh(")
            # TODO format with and without multipath expression
            # assert desc_export.split("#")[0] == external_desc.split("#")[0].replace("'", "h")

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


@pytest.fixture
def create_core_wallet(goto_home, pick_menu_item, load_export, bitcoind):
    def doit(name, addr_type, way="sd", funded=True):
        try:
            pick_menu_item(name)  # pick imported descriptor multisig wallet
        except:
            # probably not in Miniscript
            goto_home()
            pick_menu_item('Settings')
            pick_menu_item('Miniscript')
            pick_menu_item(name)

        pick_menu_item("Descriptors")
        pick_menu_item("Bitcoin Core")
        text = load_export(way, label="Bitcoin Core miniscript", is_json=False)
        text = text.replace("importdescriptors ", "").strip()
        # remove junk
        r1 = text.find("[")
        r2 = text.find("]", -1, 0)
        text = text[r1: r2]
        core_desc_object = json.loads(text)

        # watch only wallet where miniscript descriptor will be imported
        ms = bitcoind.create_wallet(
            wallet_name=name, disable_private_keys=True,
            blank=True, passphrase=None, avoid_reuse=False, descriptors=True
        )

        # import descriptors to watch only wallet
        res = ms.importdescriptors(core_desc_object)
        for obj in res:
            assert obj["success"]

        if funded:
            addr = ms.getnewaddress("", addr_type)
            if addr_type == "bech32":
                sw = "bcrt1q"
            elif addr_type == "bech32m":
                sw = "bcrt1p"
            else:
                sw = "2"
            assert addr.startswith(sw)
            # get some coins and fund above multisig address
            bitcoind.supply_wallet.sendtoaddress(addr, 49)
            bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

        return ms
    return doit


@pytest.fixture
def bitcoind_miniscript(bitcoind, need_keypress, cap_story, load_export,
                        pick_menu_item, goto_home, cap_menu, microsd_path,
                        use_regtest, get_cc_key, import_miniscript,
                        bitcoin_core_signer, import_duplicate, press_select,
                        virtdisk_path, garbage_collector, create_core_wallet):
    def doit(M, N, script_type, internal_key=None, cc_account=0, funded=True,
             tapscript_threshold=False, add_own_pk=False, same_account=False, way="sd"):

        use_regtest()
        bitcoind_signers = []
        bitcoind_signers_xpubs = []
        for i in range(N - 1):
            s, core_key = bitcoin_core_signer(f"bitcoind--signer{i}")
            s.keypoolrefill(10)
            bitcoind_signers.append(s)
            bitcoind_signers_xpubs.append(core_key)

        me_pth = f"m/48h/1h/{cc_account}h/3h"
        me = get_cc_key(me_pth)
        ik = internal_key or ranged_unspendable_internal_key()

        if tapscript_threshold:
            signers_xp = [me] + bitcoind_signers_xpubs
            assert len(signers_xp) == N
            desc = f"tr({ik},%s)"

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
                        cc_key = get_cc_key(me_pth, subderiv="/<2;3>/*")
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
                    ss = [get_cc_key(me_pth, subderiv="/<4;5>/*")] + bitcoind_signers_xpubs
                    cc_key = get_cc_key(me_pth, subderiv="/<6;7>/*")
                else:
                    ss = [get_cc_key("m/86h/1h/0h")] + bitcoind_signers_xpubs
                    cc_key = get_cc_key("m/86h/1h/1000h")

                tmplt = f"sortedmulti_a({M},{','.join(ss)})"
                cc_pk_leaf = f"pk({cc_key})"
                desc = f"tr({ik},{{{tmplt},{cc_pk_leaf}}})"
            else:
                desc = f"tr({ik},sortedmulti_a({M},{me},{','.join(bitcoind_signers_xpubs)}))"

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
        assert "Press (1) to see extended public keys" in story
        if script_type == "p2wsh":
            af = "bech32"
            assert "P2WSH" in story
        elif script_type == "p2sh":
            af = "legacy"
            assert "P2SH" in story
        elif script_type == "p2tr":
            af = "bech32m"
            assert "P2TR" in story
        else:
            af = "p2sh-segwit"
            assert "P2SH-P2WSH" in story
        # assert "Derivation:\n  Varies (2)" in story
        press_select()  # approve multisig import
        import_duplicate(fname, way=way, data=data)
        ms = create_core_wallet(name, af, way, funded)

        return ms, bitcoind_signers

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
def test_liana_miniscripts_simple(addr_fmt, recovery, lt_type, minisc, clear_miniscript,
                                  pick_menu_item, cap_story, microsd_path, way, dev,
                                  use_regtest, bitcoind, microsd_wipe, load_export,
                                  address_explorer_check, get_cc_key, import_miniscript,
                                  bitcoin_core_signer, import_duplicate, press_select,
                                  virtdisk_path, skip_if_useless_way, garbage_collector,
                                  create_core_wallet, goto_home):
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
        fname = None
    else:
        path_f = microsd_path if way == "sd" else virtdisk_path
        data = None
        fpath = path_f(fname)
        garbage_collector.append(fpath)
        with open(fpath, "w") as f:
            f.write(desc)

    _, story = import_miniscript(fname, way=way, data=data)
    time.sleep(.2)
    assert "Create new miniscript wallet?" in story
    press_select()
    # import_duplicate(fname, way=way, data=data)

    wo = create_core_wallet(name, addr_fmt, way, True)

    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
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
                                   garbage_collector, create_core_wallet):
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

    _, story = import_miniscript(fname, way=way, data=data)
    time.sleep(.2)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    import_duplicate(fname, way=way, data=data)

    wo = create_core_wallet(name, addr_fmt, way, True)

    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
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


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("add_pk", [True, False])
@pytest.mark.parametrize("same_acct", [None, True, False])
@pytest.mark.parametrize("way", ["qr", "sd"])
@pytest.mark.parametrize("M_N", [(3,4),(5,6)])
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
def test_bitcoind_tapscript_address(M_N, clear_miniscript, bitcoind_miniscript,
                                    use_regtest, way, csa, address_explorer_check,
                                    add_pk, skip_if_useless_way):
    skip_if_useless_way(way)
    use_regtest()
    clear_miniscript()
    M, N = M_N

    ik = ranged_unspendable_internal_key(os.urandom(32), subderiv=f"/<22;23>/*")

    ms_wo, _ = bitcoind_miniscript(M, N, "p2tr", funded=False, tapscript_threshold=csa,
                                   add_own_pk=add_pk, way=way, internal_key=ik)
    address_explorer_check(way, "bech32m", ms_wo, "minisc")


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("m_n", [(2,3), (32, 32)])
@pytest.mark.parametrize("way", ["qr", "sd"])
@pytest.mark.parametrize("internal_key_spendable", [
    True,
    False,
    "tpubD6NzVbkrYhZ4WhUnV3cPSoRWGf9AUdG2dvNpsXPiYzuTnxzAxemnbajrATDBWhaAVreZSzoGSe3YbbkY2K267tK3TrRmNiLH2pRBpo8yaWm/<2;3>/*",
])
def test_tapscript_multisig(cc_first, m_n, internal_key_spendable, use_regtest, bitcoind, goto_home, cap_menu,
                            pick_menu_item, cap_story, microsd_path, load_export, microsd_wipe, dev, way,
                            bitcoind_miniscript, clear_miniscript, get_cc_key, press_cancel, press_select,
                            skip_if_useless_way, garbage_collector, file_tx_signing_done):
    skip_if_useless_way(way)
    M, N = m_n
    clear_miniscript()
    microsd_wipe()
    internal_key = None
    if internal_key_spendable is True:
        internal_key = get_cc_key("86h/0h/3h")

    elif isinstance(internal_key_spendable, str):
        internal_key = internal_key_spendable

    tapscript_wo, bitcoind_signers = bitcoind_miniscript(
        M, N, "p2tr", internal_key=internal_key,
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

    signed_psbt, signed_txn, cc_tx_id = file_tx_signing_done(story)

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
                      press_select, garbage_collector, create_core_wallet):
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

    fname = "ts_pk.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc + "\n")

    garbage_collector.append(fpath)
    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    press_select()
    import_duplicate(fname)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    menu = cap_menu()

    ts = create_core_wallet(menu[0], "bech32m", "sd", True)

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
    "tr(unspend(),{{sortedmulti_a(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*),sortedmulti_a(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)},sortedmulti_a(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)})",
    "tr(unspend(),{sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)}})",
    "tr(unspend(),{sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)}})",
    "tr(unspend(),{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)})",
    "tr(unspend(),{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},or_d(pk([0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*),and_v(v:pkh([30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),older(500)))})",
    "tr(unspend(),{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},or_d(pk([0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*),and_v(v:pkh([30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),older(500)))})",
])
def test_tapscript_import_export(clear_miniscript, pick_menu_item, cap_story,
                                 import_miniscript, load_export, desc, microsd_path,
                                 press_select):
    i = random.randint(2, 10)  # needs to be disjoint
    unspend = ranged_unspendable_internal_key(os.urandom(32), subderiv=f"/<{i};{i+1}>/*")
    desc = desc.replace("unspend()", unspend)
    clear_miniscript()
    fname = "imdesc.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    _, story = import_miniscript(fname)
    press_select()  # approve miniscript import
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Export")
    contents = load_export("sd", label="Miniscript", is_json=False, addr_fmt=AF_P2TR)
    descriptor = contents.strip()
    assert desc.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h") == descriptor.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h")


def test_duplicate_tapscript_leaves(use_regtest, clear_miniscript, microsd_wipe, bitcoind, dev,
                                    goto_home, pick_menu_item, microsd_path, import_miniscript,
                                    cap_story, load_export, get_cc_key, garbage_collector,
                                    bitcoin_core_signer, import_duplicate, press_select,
                                    create_core_wallet):
    # works in core - but some discussions are ongoing
    # https://github.com/bitcoin/bitcoin/issues/27104
    # CC also allows this for now... (experimental branch)
    use_regtest()
    clear_miniscript()
    microsd_wipe()
    ss, core_key = bitcoin_core_signer(f"s1_dup_leafs")

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
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    press_select()
    import_duplicate(fname)

    ts = create_core_wallet(fname.split(".")[0], "bech32m", "sd", True)

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
                                       press_select, garbage_collector, create_core_wallet):
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

    wo = create_core_wallet(fname.split(".")[0], "bech32", "sd", True)

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
    "tr(tpubD6NzVbkrYhZ4WhUnV3cPSoRWGf9AUdG2dvNpsXPiYzuTnxzAxemnbajrATDBWhaAVreZSzoGSe3YbbkY2K267tK3TrRmNiLH2pRBpo8yaWm/<2;3>/*,{or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*),older(5))),or_i(and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2147483646;2147483647>/*),older(10)),or_d(multi_a(3,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<100;101>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<26;27>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<4;5>/*),and_v(v:thresh(2,pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<20;21>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<104;105>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<22;23>/*)),older(5))))})",
    "tr([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<66;67>/*,{or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*),older(5))),or_i(and_v(v:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2147483646;2147483647>/*),older(10)),or_d(multi_a(3,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<100;101>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<26;27>/*,[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<4;5>/*),and_v(v:thresh(2,pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<20;21>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<104;105>/*),a:pkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<22;23>/*)),older(5))))})#qqcy9jlr",
]

@pytest.mark.parametrize("desc", CHANGE_BASED_DESCS)
def test_same_key_change_based_minisc(goto_home, pick_menu_item, cap_story,
                                      clear_miniscript, microsd_path, load_export, bitcoind,
                                      import_miniscript, address_explorer_check, use_regtest,
                                      desc, press_select, garbage_collector, create_core_wallet):
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

    wo = create_core_wallet(name, af, "sd", True)

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


@pytest.mark.parametrize("desc", [
    "wsh(or_d(pk(@A),and_v(v:pkh(@A),older(5))))",
    "tr(@ik,multi_a(2,@A,@A))",
    "tr(@ik,{sortedmulti_a(2,@A,@A),pk(@A)})",
    "tr(@ik,or_d(pk(@A),and_v(v:pkh(@A),older(5))))",
])
def test_insane_miniscript(get_cc_key, pick_menu_item, cap_story,
                           microsd_path, desc, import_miniscript,
                           garbage_collector):

    cc_key = get_cc_key("84h/0h/0h")
    desc = desc.replace("@A", cc_key)
    desc = desc.replace("@ik", ranged_unspendable_internal_key())
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
    desc = f"tr({ranged_unspendable_internal_key()},{tree})"
    fname = "9leafs.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)
    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "num_leafs > 8" in story

@pytest.mark.bitcoind
# @pytest.mark.parametrize("lt_type", ["older", "after"])
@pytest.mark.parametrize("same_acct", [True, False])
@pytest.mark.parametrize("recovery", [True, False])
@pytest.mark.parametrize("leaf2_mine", [True, False])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",

    "or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi_a(2,@B,@C),locktime(N)))",
])
def test_minitapscript(leaf2_mine, recovery, minisc, clear_miniscript, goto_home,
                       pick_menu_item, cap_menu, cap_story, microsd_path,
                       use_regtest, bitcoind, microsd_wipe, load_export, dev,
                       address_explorer_check, get_cc_key, import_miniscript,
                       bitcoin_core_signer, same_acct, import_duplicate, press_select,
                       garbage_collector, start_sign, end_sign, create_core_wallet):
    lt_type = "older"
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
        signer.keypoolrefill(25)
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
    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    import_duplicate(fname)

    wo = create_core_wallet(name, "bech32m", "sd", True)

    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}

    if recovery and sequence and not leaf2_mine:
        inp["sequence"] = sequence

    # split to
    num_outs = 20
    nVal = all_of_it / num_outs
    conso_addrs = [{wo.getnewaddress("", "bech32m"): nVal} for _ in range(num_outs)]  # self-spend
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        conso_addrs,
        locktime if (recovery and not leaf2_mine) else 0,
        {"fee_rate": 2, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    if (normal_cosign_core or recovery_cosign_core) and not leaf2_mine:
        psbt_res = signers[1].walletprocesspsbt(psbt, True, "DEFAULT")
        assert psbt_res["psbt"] != psbt
        psbt = psbt_res.get("psbt")

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
    assert "warning" not in story
    assert "1 input" in story
    assert "20 outputs" in story
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

    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    unspent = wo.listunspent()
    assert len(unspent) == 20
    ins = [{"txid": u["txid"], "vout": u["vout"]} for u in unspent]

    if recovery and sequence and not leaf2_mine:
        for i in ins:
            i["sequence"] = sequence

    # consolidate multiple inputs to one for us
    # BUT also send 1 corn back to supply (so not a consolidation)
    outs = [
        {wo.getnewaddress("", "bech32m"): wo.getbalance() - 1},
        {bitcoind.supply_wallet.getnewaddress("", "bech32"): 1},
    ]
    psbt_resp = wo.walletcreatefundedpsbt(
        ins,
        outs,
        locktime if (recovery and not leaf2_mine) else 0,
        {"fee_rate": 2, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # now CC first
    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "warning" not in story
    assert "Consolidating" not in story
    assert "20 inputs" in story
    assert "2 outputs" in story
    final_psbt = end_sign(True)
    psbt = base64.b64encode(final_psbt).decode()

    if (normal_cosign_core or recovery_cosign_core) and not leaf2_mine:
        # core co-signer second after CC (if needed)
        psbt_res = signers[1].walletprocesspsbt(psbt, True, "DEFAULT")
        assert psbt_res["psbt"] != psbt
        psbt = psbt_res.get("psbt")

    res = wo.finalizepsbt(psbt)
    assert res["complete"]
    tx_hex = res["hex"]
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
    "tr(tpubD6NzVbkrYhZ4WhUnV3cPSoRWGf9AUdG2dvNpsXPiYzuTnxzAxemnbajrATDBWhaAVreZSzoGSe3YbbkY2K267tK3TrRmNiLH2pRBpo8yaWm/<2;3>/*,{{sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*),sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)},sortedmulti(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)})",
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
                   garbage_collector, create_core_wallet):

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
        desc = f"tr({ranged_unspendable_internal_key()},{minsc})"

    name = "d_wrapper"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

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

    wo = create_core_wallet(name, addr_fmt, "sd", True)

    addr_dest = wo.getnewaddress("", addr_fmt)  # self-spend
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
    y = f"tr({ranged_unspendable_internal_key()},or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),after(800000))))"

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
    time.sleep(.1)
    res = settings_get("miniscript", [])
    assert len(res) == 1
    assert res[0][-1]["ct"] == "XRT"

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
    # but not on current active chain
    assert "(none setup yet)" in m
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
def test_import_same_policy_same_keys_diff_order(taproot_ikspendable, minisc, use_regtest,
                                                 clear_miniscript, bitcoin_core_signer,
                                                 get_cc_key, settings_get, cap_menu,
                                                 offer_minsc_import, bitcoind, press_select):
    use_regtest()
    clear_miniscript()
    taproot, ik_spendable = taproot_ikspendable
    if taproot:
        minisc = minisc.replace("multi(", "multi_a(")
        if ik_spendable:
            ik = get_cc_key("84h/1h/100h", subderiv="/0/*")
            desc = f"tr({ik},{minisc})"
        else:
            desc = f"tr({ranged_unspendable_internal_key()},{minisc})"
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
    time.sleep(.2)
    assert len(settings_get("miniscript", [])) == 2


@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("way", ["usb", "nfc", "sd", "vdisk"])
def test_import_miniscript_usb_json(use_regtest, cs, way, cap_menu, clear_miniscript, get_cc_key,
                                    bitcoin_core_signer, offer_minsc_import, bitcoind, microsd_path,
                                    virtdisk_path, import_miniscript, goto_home, press_select,
                                    settings_get):
    name = "my_minisc"
    minsc = f"tr({ranged_unspendable_internal_key()},or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),after(100))))"
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
    msc = settings_get("miniscript", [])
    assert len(msc) == 1
    assert msc[0][0] == name


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
    y = f"tr({ranged_unspendable_internal_key()},or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),after(800000))))"

    xd = json.dumps({"name": name, "desc": x})
    title, story = offer_minsc_import(xd)
    assert "Create new miniscript wallet?" in story
    assert name in story
    press_select()
    time.sleep(.2)
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    assert m[0] == name
    assert m[1] == "Import"

    # completely different wallet but with the same name (USB)
    yd = json.dumps({"name": name, "desc": y})
    title, story = offer_minsc_import(yd)
    assert ("'%s' already exists" % name) in story
    assert "MUST have unique names" in story
    press_select()
    # nothing imported
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    assert m[0] == name
    assert m[1] == "Import"

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
    assert ("'%s' already exists" % name) in story
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


def test_bug_fill_policy(set_seed_words, goto_home, pick_menu_item, need_keypress,
                         microsd_path, cap_story, press_select, clear_miniscript,
                         cap_menu, bitcoind, start_sign, end_sign):
    clear_miniscript()
    mnemonic = "normal useless alpha sphere grid defense feed era farm law hair region"
    set_seed_words(mnemonic)

    desc = """tr(tpubD6NzVbkrYhZ4Xjg1aU3fkQSj6yp8d7XNpnpVvjUBqDzMJt7J6QafSCBF5RLY2wwi
Vuhu79MKCKbUxjCxvicdATdc7hMPEejgCkQy3B28MiP/<0;1>/*,{and_v(v:multi_a(1,
[61cd4eb6/48'/1'/0'/2']tpubDE4RRPsyHN6GUsic4hrniYUhTsQ7h1bRQYyDPcWDFjKZ
vhms2nUNwo2j4oRwtuDZNJwwXzeoZ22RjGrueJ3zgAbbSTEM8kZQ8EnyDE79sGK/<2;3>/*
,[c658b283/48'/1'/0'/2']tpubDFL5wzgPBYK5pZ2Kh1T8qrxnp43kjE5CXfguZHHBrZS
WpkfASy5rVfj7prh11XdqkC1P3kRwUPBeX7AHN8XBNx8UwiprnFnEm5jyswiRD4p/<2;3>/
*),older(65535)),multi_a(2,[c658b283/48'/1'/0'/2']tpubDFL5wzgPBYK5pZ2Kh
1T8qrxnp43kjE5CXfguZHHBrZSWpkfASy5rVfj7prh11XdqkC1P3kRwUPBeX7AHN8XBNx8U
wiprnFnEm5jyswiRD4p/<0;1>/*,[61cd4eb6/48'/1'/0'/2']tpubDE4RRPsyHN6GUsic
4hrniYUhTsQ7h1bRQYyDPcWDFjKZvhms2nUNwo2j4oRwtuDZNJwwXzeoZ22RjGrueJ3zgAb
bSTEM8kZQ8EnyDE79sGK/<0;1>/*,[25f48f59/48'/1'/0'/2']tpubDFRnTG8pxuoQ67w
aXsh1vNLD9c88JcRwEFxKCUsXzR11RkuV4pqFU6ccCZdwnjGY4yw25uCRHh4wCKNquvfgQ3
zUvcND8MhRQFv8dCFzjNu/<0;1>/*)})#vh0vvyyn"""

    psbt = """cHNidP8BAIkCAAAAAeqLNNQht+6fI8FkMNHKGAvQGxbT13MnWFy4E+bjjLgCAQAAAAD9///
/AqCGAQAAAAAAIlEgucVAj4RPepF0/SyzmhPtCRuKI9xAQd2ScMQhRo9QxS5DCAMAAAAAAC
JRIAS4JaU4120D1sK/uwi3pX/d44riN1ZL7/8gihqjovNiAAAAAAABASs2kgQAAAAAACJRI
HWNphYJKzPZvktvz5R8JcN2jyq3X037IdsYEIDkyJk7QhXB5HKqDFDM67yjCq7Se80ncwja
RKN9sUObTyvZmbUObbeSJsFccViS0oZLC6gQ/8Qmufbj1s4NQa3LIWyvMivI3mkgM/TcQjN
Yw24uBt3x3dPWB1zB6JE2XXpQ1SZxj8o/A42sIHQi+N5Ks8V63jBweYeXAHfYdbbK8i8g+K
nAk87zPU+4uiBcgNyWXXed03Q77nXydquU/r3OGKaNmfgKZEaReol/GbpSnMBCFcHkcqoMU
MzrvKMKrtJ7zSdzCNpEo32xQ5tPK9mZtQ5tt+YJ/0OcHr4oEr0kYvDKBTQQmmLvIQOcvrLs
WIK71wAuTCDt0of0dokHgcFnysYqBSMq0n/q8BXbdtc6FN45FDFJ5qwg2jHHFnREqivJDEd
6OP6MVGPTh+VKFGcVw5069IYoHu26UZ0D//8AssAhFjP03EIzWMNuLgbd8d3T1gdcweiRNl
16UNUmcY/KPwONPQHmCf9DnB6+KBK9JGLwygU0EJpi7yEDnL6y7FiCu9cALsZYsoMwAACAA
QAAgAAAAIACAACAAQAAAAEAAAAhFlyA3JZdd53TdDvudfJ2q5T+vc4Ypo2Z+ApkRpF6iX8Z
PQHmCf9DnB6+KBK9JGLwygU0EJpi7yEDnL6y7FiCu9cALiX0j1kwAACAAQAAgAAAAIACAAC
AAQAAAAEAAAAhFnQi+N5Ks8V63jBweYeXAHfYdbbK8i8g+KnAk87zPU+4PQHmCf9DnB6+KB
K9JGLwygU0EJpi7yEDnL6y7FiCu9cALmHNTrYwAACAAQAAgAAAAIACAACAAQAAAAEAAAAhF
toxxxZ0RKoryQxHejj+jFRj04flShRnFcOdOvSGKB7tPQGSJsFccViS0oZLC6gQ/8Qmufbj
1s4NQa3LIWyvMivI3sZYsoMwAACAAQAAgAAAAIACAACAAwAAAAEAAAAhFuRyqgxQzOu8owq
u0nvNJ3MI2kSjfbFDm08r2Zm1Dm23DQB8Rh5dAQAAAAEAAAAhFu3Sh/R2iQeBwWfKxioFIy
rSf+rwFdt21zoU3jkUMUnmPQGSJsFccViS0oZLC6gQ/8Qmufbj1s4NQa3LIWyvMivI3mHNT
rYwAACAAQAAgAAAAIACAACAAwAAAAEAAAABFyDkcqoMUMzrvKMKrtJ7zSdzCNpEo32xQ5tP
K9mZtQ5ttwEYIM5NkFnDQB89FHqGhszz+s+W7dqU367i55HGAojV3UIeAAABBSBbkkOJTQO
GaVlOrV3dhuuoJ+mExi5yco1KgXreMLenRAEGuQHAaCDmAYkOelpDlG83jdRpTPCCRnycqv
57ZqHfHdVKmDEPN6wgPuunxNxW0oPW2ZejdP8jfaaB5k+tCfWK2OFY0b4qVJe6IG5O5Uawc
tSgkNBrJ/pX/Fxfg33+67rTirW8sUmhiiNQulKcAcBLIJAD9nceZ+8HESN1pKN/mC4PD+52
KlrvkLEbnlY90unxrCAh9E3FtPjeBG5Rt8tFIVn2mCgcsefMY+oLB85YQYNX3LpRnQP//wC
yIQch9E3FtPjeBG5Rt8tFIVn2mCgcsefMY+oLB85YQYNX3D0B7rC0ojXeM3TXglbOnszIeY
YXUZmryJkcTjQlleT5XnPGWLKDMAAAgAEAAIAAAACAAgAAgAMAAAADAAAAIQc+66fE3FbSg
9bZl6N0/yN9poHmT60J9YrY4VjRvipUlz0BY9TGKw5dxhZn81aA+bduIqWCMpBW2K5F0Fux
fY4ofjdhzU62MAAAgAEAAIAAAACAAgAAgAEAAAADAAAAIQdbkkOJTQOGaVlOrV3dhuuoJ+m
Exi5yco1KgXreMLenRA0AfEYeXQEAAAADAAAAIQduTuVGsHLUoJDQayf6V/xcX4N9/uu604
q1vLFJoYojUD0BY9TGKw5dxhZn81aA+bduIqWCMpBW2K5F0FuxfY4ofjcl9I9ZMAAAgAEAA
IAAAACAAgAAgAEAAAADAAAAIQeQA/Z3HmfvBxEjdaSjf5guDw/udipa75CxG55WPdLp8T0B
7rC0ojXeM3TXglbOnszIeYYXUZmryJkcTjQlleT5XnNhzU62MAAAgAEAAIAAAACAAgAAgAM
AAAADAAAAIQfmAYkOelpDlG83jdRpTPCCRnycqv57ZqHfHdVKmDEPNz0BY9TGKw5dxhZn81
aA+bduIqWCMpBW2K5F0FuxfY4ofjfGWLKDMAAAgAEAAIAAAACAAgAAgAEAAAADAAAAAA=="""

    desc_fname = "minib.txt"
    with open(microsd_path(desc_fname), "w") as f:
        f.write(desc)

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item("Import")
    need_keypress("1")
    pick_menu_item(desc_fname)
    time.sleep(.1)
    _, story = cap_story()
    assert "Create new miniscript wallet?" in story
    assert "minib" in story  # name
    press_select()

    goto_home()
    start_sign(base64.b64decode(psbt))
    signed = end_sign(accept=True)
    assert signed != base64.b64decode(psbt)


@pytest.mark.bitcoind
@pytest.mark.parametrize("tmplt", [
    "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<0;1>/*)),older(10))))",
    # below is same as above with just first two keys swapped in thresh
    "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@1/<2;3>/*),a:pkh(@0/<2;3>/*),a:pkh(@2/<0;1>/*)),older(10))))",
    "tr(unspend()/<0;1>/*,{and_v(v:multi_a(2,@0/<2;3>/*,@1/<2;3>/*,@2/<0;1>/*,@3/<0;1>/*),older(10)),multi_a(2,@0/<0;1>/*,@1/<0;1>/*)})",
    # below is same as above with just first two keys swapped in last multi_a
    "tr(unspend()/<0;1>/*,{and_v(v:multi_a(2,@0/<2;3>/*,@1/<2;3>/*,@2/<0;1>/*,@3/<0;1>/*),older(10)),multi_a(2,@1/<0;1>/*,@0/<0;1>/*)})",
    # internal key is ours
    "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@0/<2;3>/*,@1/<2;3>/*,@2/<2;3>/*,@3/<0;1>/*),older(10)),multi_a(2,@1/<0;1>/*,@2/<0;1>/*)})",
])
def test_expanding_multisig(tmplt, clear_miniscript, goto_home, pick_menu_item, garbage_collector,
                            cap_menu, cap_story, microsd_path, use_regtest, bitcoind, microsd_wipe,
                            load_export, dev, address_explorer_check, get_cc_key, import_miniscript,
                            bitcoin_core_signer, import_duplicate, press_select, start_sign, end_sign,
                            create_core_wallet):
    use_regtest()
    clear_miniscript()
    sequence = 10
    af = "bech32m" if tmplt.startswith("tr(") else "bech32"
    unspend = "tpubD6NzVbkrYhZ4WbzhCs1gLUM8s8LAwTh68xVh1a3nRQyA3tbAJFSE2FEaH2CEGJTKmzcBagpyG35Kjv3UGpTEWbc7qSCX6mswrLQVVPgXECd"
    tmplt = tmplt.replace("unspend()", unspend)

    csigner0, ckey0 = bitcoin_core_signer(f"co-signer-0")
    ckey0 = ckey0.replace("/0/*", "")
    csigner0.keypoolrefill(20)
    csigner1, ckey1 = bitcoin_core_signer(f"co-signer-1")
    ckey1 = ckey1.replace("/0/*", "")
    csigner1.keypoolrefill(20)
    csigner2, ckey2 = None, None

    # cc device key
    cc_key = get_cc_key("86h/1h/0h").replace('/<0;1>/*', "")

    # fill policy
    desc = tmplt.replace("@0", cc_key)
    desc = desc.replace("@1", ckey0)
    desc = desc.replace("@2", ckey1)

    if "@3" in tmplt:
        csigner2, ckey2 = bitcoin_core_signer(f"co-signer-2")
        ckey2 = ckey2.replace("/0/*", "")
        csigner2.keypoolrefill(20)
        desc = desc.replace("@3", ckey2)

    wname = "expand_msc"
    fname = f"{wname}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(wname, af, "sd", True)

    # use non-recovery path to split into 5 utxos + 1 going back to supply (not a conso)
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    dest_addrs = [wo.getnewaddress(f"a{i}", af) for i in range(5)]
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{a: 5} for a in dest_addrs] + [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 20, "change_type": af},
    )
    psbt = psbt_resp.get("psbt")

    # if we have internal key we just spend with it, singlesig on chain
    have_internal = "tr(@0," in tmplt

    if not have_internal:
        # first sign with cosigner in gucci path (non-recovery)
        psbt = csigner0.walletprocesspsbt(psbt, True)["psbt"]

    # now CC
    start_sign(base64.b64decode(psbt), finalize=have_internal)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    final_psbt = end_sign(True, finalize=have_internal)

    if have_internal:
        tx_hex = final_psbt.hex()  # it is final tx actually
    else:
        # client software finalization
        res = wo.finalizepsbt(base64.b64encode(final_psbt).decode())
        assert res["complete"]
        tx_hex = res["hex"]

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    unspent = wo.listunspent()
    assert len(unspent) == 6  # created 5 txos of 5 btc, one to supply & change back is 6th utxo

    # consolidation - consolidate 3 utxo into one bigger
    to_spend = [{"txid": o["txid"], "vout": o["vout"]} for o in unspent if float(o["amount"]) == 5.0][:3]
    psbt_resp = wo.walletcreatefundedpsbt(
        to_spend,
        [{wo.getnewaddress("conso", af): 15}],
        0,
        {"fee_rate": 20, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # now CC signing first
    start_sign(base64.b64decode(psbt), finalize=have_internal)
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    updated_psbt = end_sign(True, finalize=have_internal)

    if not have_internal:
        # now cosigner (still on non-recovery path)
        updated_psbt = base64.b64encode(updated_psbt).decode()
        final_psbt = csigner0.walletprocesspsbt(updated_psbt, True,
                                                "DEFAULT"if "tr(" == tmplt[:3] else "ALL")["psbt"]

        # client software finalization
        res = wo.finalizepsbt(final_psbt)
        assert res["complete"]
        tx_hex = res["hex"]
    else:
        # actually a final tx
        tx_hex = updated_psbt.hex()

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    unspent = wo.listunspent()
    assert len(unspent) == 4

    # now we lost our non-recovey path cosigner
    del csigner0
    # use recovery key to consolidate all our outputs and send them to other wallet
    dest = bitcoind.supply_wallet.getnewaddress()
    all_of_it = wo.getbalance()
    # need to bump sequence here
    psbt_resp = wo.walletcreatefundedpsbt(
        [ {"txid": o["txid"], "vout": o["vout"], "sequence": sequence} for o in unspent],
        [{dest: all_of_it}],
        0,
        {"fee_rate": 10, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # now cosigner (on recovery path)
    psbt = csigner1.walletprocesspsbt(psbt, True)["psbt"]

    if have_internal:
        final_psbt = csigner2.walletprocesspsbt(psbt, True)["psbt"]
    else:
        # CC
        start_sign(base64.b64decode(psbt))
        time.sleep(.1)
        title, story = cap_story()
        assert title == "OK TO SEND?"
        assert "Consolidating" not in story
        final_psbt = end_sign(True)
        final_psbt = base64.b64encode(final_psbt).decode()

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    # timelocked
    assert not res[0]["allowed"]
    assert res[0]["reject-reason"] == 'non-BIP68-final'

    # mines some blocks to release the lock
    bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    assert len(wo.listunspent()) == 0

    # check addresses
    address_explorer_check("sd", af, wo, wname)


@pytest.mark.parametrize("blinded", [True, False])
def test_big_boy(use_regtest, clear_miniscript, bitcoin_core_signer, get_cc_key, microsd_path,
                 garbage_collector, pick_menu_item, bitcoind, import_miniscript, press_select,
                 cap_story, cap_menu, load_export, start_sign, end_sign, blinded,
                 create_core_wallet):
    # keys (@0,@4,@5) are more important (primary) than keys (@1,@2,@3) (secondary)
    # currently requires to tweak MAX_TR_SIGNERS = 33
    # with blinded=True, all co-signer keys are blinded (have no key origin info)
    tmplt = (
        "tr("
        "tpubD6NzVbkrYhZ4XgXS51CV3bhoP5dJeQqPhEyhKPDXBgEs64VdSyAfku99gtDXQzY6HEXY5Dqdw8Qud1fYiyewDmYjKe9gGJeDx7x936ur4Ju/<0;1>/*,"  # unspendable
        "{{{and_v(v:multi_a(3,@5/<8;9>/*,@1/<8;9>/*,@2/<8;9>/*,@3/<8;9>/*),older(1000)),"  # after 1000 blocks one of primary keys can sign with 2 secondary
        "and_v(v:multi_a(3,@0/<8;9>/*,@1/<10;11>/*,@2/<10;11>/*,@3/<10;11>/*),older(1000))},"  # after 1000 blocks one of primary keys can sign with 2 secondary
        "{{and_v(v:multi_a(5,@4/<2;3>/*,@5/<2;3>/*,@0/<2;3>/*,@1/<2;3>/*,@2/<2;3>/*,@3/<2;3>/*),older(20)),"  # 5of6 after 20 blocks
        "and_v(v:multi_a(4,@4/<4;5>/*,@5/<4;5>/*,@0/<4;5>/*,@1/<4;5>/*,@2/<4;5>/*,@3/<4;5>/*),older(60))},"  # 4of6 after 60 blocks
        "{and_v(v:multi_a(2,@4/<6;7>/*,@5/<6;7>/*,@0/<6;7>/*),older(120)),"  # after 120 blocks it is enough to have 2 of (@0,@4,@5)
        "and_v(v:multi_a(3,@4/<8;9>/*,@1/<6;7>/*,@2/<6;7>/*,@3/<6;7>/*),older(1000))}}},"  # after 1000 blocks one of primary keys can sign with 2 secondary
        "multi_a(6,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*,@4/<0;1>/*,@5/<0;1>/*,@0/<0;1>/*)})"  # 6of6 primary path
    )

    use_regtest()
    clear_miniscript()
    af = "bech32m"

    cc_key = get_cc_key("86h/1h/0h").replace('/<0;1>/*', "")
    desc = tmplt.replace("@0", cc_key)

    cosigners = []
    for i in range(1, 6):
        csigner, ckey = bitcoin_core_signer(f"co-signer-{i}")
        ckey = ckey.replace("/0/*", "")

        if blinded:
            ckey = ckey.split("]")[-1]

        csigner.keypoolrefill(20)
        cosigners.append(csigner)
        desc = desc.replace(f"@{i}", ckey)

    wname = "bigboy"
    fname = f"{wname}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(wname, af, "sd", True)

    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    # split to 10 utxos
    dest_addrs = [wo.getnewaddress(f"a{i}", af) for i in range(10)]
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{a: 4} for a in dest_addrs] + [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 3, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # sign with all cosigners
    for s in cosigners:
        psbt = s.walletprocesspsbt(psbt, True)["psbt"]

    # now CC
    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    final_psbt = end_sign(True)
    final_psbt = base64.b64encode(final_psbt).decode()

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    unspent = wo.listunspent()
    assert len(unspent) == 11


@pytest.mark.parametrize("af", ["bech32", "bech32m"])
def test_single_key_miniscript(af, settings_set, clear_miniscript, goto_home, get_cc_key,
                               garbage_collector, microsd_path, bitcoind, import_miniscript,
                               press_select, cap_menu, pick_menu_item, load_export, cap_story,
                               start_sign, end_sign, create_core_wallet):
    sequence = 10
    goto_home()
    clear_miniscript()
    settings_set("chain", "XRT")
    policy = "and_v(v:pk(@0/<0;1>/*),older(10))"

    if af == "bech32m":
        tmplt = f"tr(tpubD6NzVbkrYhZ4XgXS51CV3bhoP5dJeQqPhEyhKPDXBgEs64VdSyAfku99gtDXQzY6HEXY5Dqdw8Qud1fYiyewDmYjKe9gGJeDx7x936ur4Ju/<0;1>/*,{policy})"
    else:
        tmplt = f"wsh({policy})"

    cc_key = get_cc_key("m/99h/0h/0h").replace('/<0;1>/*', '')
    tmplt = tmplt.replace("@0", cc_key)

    wname = "single_key_mini"
    fname = f"{wname}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(tmplt)

    garbage_collector.append(fpath)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(wname, af, "sd", True)

    unspent = wo.listunspent()
    assert len(unspent) == 1

    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "sequence": sequence}
    # split to 10 utxos
    dest_addrs = [wo.getnewaddress(f"a{i}", af) for i in range(10)]
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{a: 4} for a in dest_addrs] + [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 3, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    final_psbt = end_sign(True)
    final_psbt = base64.b64encode(final_psbt).decode()

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    # timelocked
    assert not res[0]["allowed"]
    assert res[0]["reject-reason"] == 'non-BIP68-final'

    # mines some blocks to release the lock
    bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    unspent = wo.listunspent()
    assert len(unspent) == 11

    # now consolidate to one output
    psbt_resp = wo.walletcreatefundedpsbt(
        [{"txid": o["txid"], "vout": o["vout"], "sequence": sequence} for o in unspent],
        [{wo.getnewaddress("", af): wo.getbalance()}],
        0,
        {"fee_rate": 3, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    final_psbt = end_sign(True)
    final_psbt = base64.b64encode(final_psbt).decode()

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    # timelocked
    assert not res[0]["allowed"]
    assert res[0]["reject-reason"] == 'non-BIP68-final'

    # mines some blocks to release the lock
    bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

    unspent = wo.listunspent()
    assert len(unspent) == 1


@pytest.mark.parametrize("tmplt", [
    "wsh(or_d(pk(@0),and_v(v:pkh(@1),older(100))))",
    f"tr({ranged_unspendable_internal_key()},or_d(pk(@0),and_v(v:pk(@1),older(100))))"
])
@pytest.mark.parametrize("cc_sign", [False, True])
@pytest.mark.parametrize("has_orig", [False, True])
def test_originless_keys(tmplt, offer_minsc_import, get_cc_key, bitcoin_core_signer, bitcoind,
                         pick_menu_item, load_export, goto_home, cap_menu, clear_miniscript,
                         use_regtest, press_select, start_sign, end_sign, cap_story, cc_sign,
                         has_orig, address_explorer_check, create_core_wallet):
    # can be both:
    #   a.) just ranged xpub without origin info -> xpub1/<0;1>/*
    #   b.) ranged xpub with its fp -> [xpub1_fp]xpub1/<0;1>/*
    sequence = 100
    use_regtest()
    clear_miniscript()
    af = "bech32m" if "tr(" in tmplt else "bech32"
    name = "originless"

    cc_key = get_cc_key("m/84h/1h/0h")
    cs, ck = bitcoin_core_signer(name+"_signer")
    originless_ck = ck.split("]")[-1]

    n = BIP32Node.from_hwif(originless_ck.split("/")[0])  # just extended key
    fp_str = "[" + n.fingerprint().hex() + "]"
    if has_orig:
        originless_ck = fp_str + originless_ck

    desc = tmplt.replace("@0", cc_key)
    desc = desc.replace("@1", originless_ck)
    to_import = {"desc": desc, "name": name}
    offer_minsc_import(json.dumps(to_import))
    press_select()

    wo = create_core_wallet(name, af, "sd", True)

    unspent = wo.listunspent()
    assert len(unspent) == 1

    if cc_sign:
        inputs = []
    else:
        inputs = [{"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "sequence": sequence}]

    # split to 10 utxos
    dest_addrs = [wo.getnewaddress(f"a{i}", af) for i in range(10)]
    psbt_resp = wo.walletcreatefundedpsbt(
        inputs,
        [{a: 4} for a in dest_addrs] + [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 3, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    if cc_sign:
        start_sign(base64.b64decode(psbt))
        time.sleep(.1)
        title, story = cap_story()
        assert title == "OK TO SEND?"
        assert "Consolidating" not in story
        final_psbt = end_sign(True)
        final_psbt = base64.b64encode(final_psbt).decode()
    else:
        final_psbt_o = cs.walletprocesspsbt(psbt, True, "DEFAULT" if af == "bech32m" else "ALL")
        final_psbt = final_psbt_o["psbt"]
        assert psbt != final_psbt

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    if not cc_sign:
        # timelocked
        assert not res[0]["allowed"]
        assert res[0]["reject-reason"] == 'non-BIP68-final'

        # mines some blocks to release the lock
        bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

        res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses
    address_explorer_check("sd", af, wo, name)


@pytest.mark.parametrize("internal_key", [
    H,
    "r=@",
    "r=dfed64ff493dca2ab09eadefaa0c88be8404908fa6eff869ff71c0d359d086b9",
    "f19573a10866ee9881769e24464f9a0e989c2cb8e585db385934130462abed90"
])
def test_static_internal_key(internal_key, clear_miniscript, microsd_path, pick_menu_item,
                             cap_story, import_miniscript, garbage_collector):
    clear_miniscript()
    desc = "tr(@ik,{{sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*),sortedmulti(2,[0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)},sortedmulti(2,[b7fe820c/48h/1h/0h/3h]tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/<0;1>/*,[30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*)})"
    desc = desc.replace("@ik", internal_key)
    fname = "imdesc.txt"
    fpath = microsd_path(fname)
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    garbage_collector.append(fpath)

    title, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "only extended pubkeys allowed" in story


# @pytest.mark.bitcoind
# def test_csa_tapscript(clear_miniscript, bitcoin_core_signer, get_cc_key,
#                        use_regtest, address_explorer_check, bitcoind,
#                        offer_minsc_import, create_core_wallet, press_select):
#     use_regtest()
#     clear_miniscript()
#     M, N = 11, 12
#
#     bitcoind_signers = []
#     bitcoind_signers_xpubs = []
#     for i in range(N - 1):
#         s, core_key = bitcoin_core_signer(f"bitcoind--signer{i}")
#         s.keypoolrefill(10)
#         bitcoind_signers.append(s)
#         bitcoind_signers_xpubs.append(core_key)
#
#     me = get_cc_key(f"m/48h/1h/0h/3h")
#     ik = ranged_unspendable_internal_key()
#
#     signers_xp = [me] + bitcoind_signers_xpubs
#     assert len(signers_xp) == N
#     desc = f"tr({ik},%s)"
#
#     scripts = []
#     for c in itertools.combinations(signers_xp, M):
#         tmplt = f"multi_a({M},{','.join(c)})"
#         scripts.append(tmplt)
#
#     assert len(scripts) == 12
#     temp = TREE[len(scripts)]
#     temp = temp % tuple(scripts)
#
#     desc = desc % temp
#
#     title, story = offer_minsc_import(desc)
#     name = story.split("\n")[3].strip()
#     assert "Create new miniscript wallet?" in story
#     press_select()
#     ms_wo = create_core_wallet(name, "bech32m", "sd", False)
#     address_explorer_check("sd", "bech32m", ms_wo, "minisc")


# @pytest.mark.parametrize("desc", [
#
#     # "wsh(or_i(and_v(v:pkh(@A),older(100)),or_d(multi(3,@A,@B,@C),and_v(v:thresh(2,pkh(@A),a:pkh(@B),a:pkh(@C)),older(500)))))"
# ])
def test_tapscript_disjoint_derivation(cap_story, offer_minsc_import, microsd_path,
                                       get_cc_key, bitcoin_core_signer):
    desc = "tr(unspend(),{{sortedmulti_a(2,@A,@B),sortedmulti_a(2,@AA,@C)},sortedmulti_a(2,@AAA,@BB,@CC)})"

    # internal key is OK
    unspend = ranged_unspendable_internal_key(os.urandom(32), subderiv=f"/<0;1>/*")
    desc = desc.replace("unspend()", unspend)

    # @A, @AA & @AAA is us - all OK
    kA = get_cc_key("m/999h/1h/66h")
    kAA = kA.replace("/<0;1>/*", "/<2;3>/*")
    kAAA = kA.replace("/<0;1>/*", "/<4;5>/*")

    desc = desc.replace("@AAA", kAAA)
    desc = desc.replace("@AA", kAA)
    desc = desc.replace("@A", kA)

    s0, kB = bitcoin_core_signer("B")
    # this is problematic - as it is nto disjoint
    kB = kB.replace("/0/*", "/<1;2>/*")
    kBB = kB.replace("/<1;2>/*", "/<0;1>/*")

    s1, kC = bitcoin_core_signer("C")
    kC = kC.replace("/0/*", "/<0;1>/*")
    kCC = kC.replace("/<0;1>/*", "/<2;3>/*")

    desc = desc.replace("@BB", kBB)
    desc = desc.replace("@B", kB)
    desc = desc.replace("@CC", kCC)
    desc = desc.replace("@C", kC)

    with pytest.raises(Exception) as e:
        offer_minsc_import(desc)
    assert "Non-disjoint multipath" in e.value.args[0]

    # now make internal key non-disjoint
    desc = desc.replace(unspend, ranged_unspendable_internal_key(os.urandom(32), subderiv=f"/<3;4>/*"))
    # previously invalid key
    desc = desc.replace(kB, kB.replace("/<1;2>/*", "/<2;3>/*"))

    with pytest.raises(Exception) as e:
        offer_minsc_import(desc)
    assert "Non-disjoint multipath" in e.value.args[0]


@pytest.mark.bitcoind
@pytest.mark.parametrize("way", ["usb", "nfc", "sd", "vdisk", "qr"])
def test_same_key_set_miniscript(get_cc_key, bitcoin_core_signer, create_core_wallet, way,
                                 offer_minsc_import, press_select, bitcoind, start_sign,
                                 cap_story, end_sign, clear_miniscript, goto_home, scan_a_qr,
                                 pick_menu_item, microsd_path, garbage_collector, press_cancel,
                                 need_keypress, press_nfc, nfc_write_text, nfc_read,
                                 readback_bbqr, virtdisk_path, skip_if_useless_way):
    # same keys in miniscript, impossible to match correct wallet with auto-match
    skip_if_useless_way(way)
    goto_home()
    clear_miniscript()

    msc1 = "wsh(andor(pk(@D),after(1767225600),multi(2,@A,@B,@C)))"
    msc2 = "wsh(or_d(pk(@D),and_v(v:multi(2,@A,@B,@C),older(65535))))"

    ak = get_cc_key("m/48h/1h/0h/2h")
    bs, bk = bitcoin_core_signer("bb")
    cs, ck = bitcoin_core_signer("cc")
    ds, dk = bitcoin_core_signer("dd")

    bk = bk.replace("/0/*", "/<0;1>/*")
    ck = ck.replace("/0/*", "/<0;1>/*")
    dk = dk.replace("/0/*", "/<0;1>/*")

    msc1 = msc1.replace("@A", ak)
    msc1 = msc1.replace("@B", bk)
    msc1 = msc1.replace("@C", ck)
    msc1 = msc1.replace("@D", dk)

    msc2 = msc2.replace("@A", ak)
    msc2 = msc2.replace("@B", bk)
    msc2 = msc2.replace("@C", ck)
    msc2 = msc2.replace("@D", dk)

    title, story = offer_minsc_import(json.dumps(dict(name="msc1", desc=msc1)))
    assert "msc1" in story
    assert "Create new miniscript wallet?" in story
    press_select()

    title, story = offer_minsc_import(json.dumps(dict(name="msc2", desc=msc2)))
    assert "msc2" in story
    assert "Create new miniscript wallet?" in story
    press_select()

    m1 = create_core_wallet("msc1", "bech32")
    m2 = create_core_wallet("msc2", "bech32")

    # now try to sign (via Ready To Sign) PSBT from msc2
    # this will not work, as msc1 has same key set and was imported first
    # so we match msc1
    psbt = m2.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1.0}],
                                     0, {"fee_rate": 2})["psbt"]

    if way == "usb":
        # first try classic way without specifying wallet name
        # will fail with scriptPubKey mismatch
        start_sign(base64.b64decode(psbt))
        time.sleep(.1)
        title, story = cap_story()
        assert "spk mismatch" in story

        # now with name specified via USB
        start_sign(base64.b64decode(psbt), miniscript="msc2")
        time.sleep(.1)
        title, story = cap_story()
        assert title == "OK TO SEND?"
        assert "msc2" in story
        end_sign(accept=True)

    else:
        fname = "the_txn.psbt"
        fpath = microsd_path(fname)
        garbage_collector.append(fpath)
        with open(fpath, "w") as f:
            f.write(psbt)

        goto_home()
        # just try SD for normal matching without name
        pick_menu_item("Ready To Sign")
        title, story = cap_story()
        if 'OK TO SEND' not in title:
            try:
                pick_menu_item(fname)
                time.sleep(0.1)
                title, story = cap_story()
            except: pass

        assert "spk mismatch" in story
        press_select()  # exit

        # now correct way via miniscript wallet
        pick_menu_item("Settings")
        pick_menu_item("Miniscript")
        pick_menu_item("msc2")
        pick_menu_item("Sign PSBT")
        title, story = cap_story()
        if way == "nfc":
            if "import via NFC" not in story:
                raise pytest.skip("NFC disabled")

            press_nfc()
            nfc_write_text(psbt)
            time.sleep(1)
            title, story = cap_story()
            assert title == "OK TO SEND?"
            assert "msc2" in story
            press_select()  # confirm signing
            time.sleep(0.1)
            got = nfc_read()
            time.sleep(1)
            assert got
            press_cancel()  # exit NFC loop

        elif way == "qr":
            if "scan QR code" not in story:
                raise pytest.skip("Mk4 no QR")

            need_keypress(KEY_QR)
            # base64 PSBT as text
            actual_vers, parts = split_qrs(psbt, 'U', max_version=20)
            random.shuffle(parts)

            for p in parts:
                scan_a_qr(p)
                time.sleep(1)  # just so we can watch

            title, story = cap_story()
            assert title == "OK TO SEND?"
            assert "msc2" in story
            press_select()  # confirm signing
            time.sleep(.2)
            file_type, rb = readback_bbqr()
            assert file_type == 'P'
            press_cancel()
        else:
            if way == "sd":
                assert "Press (1)" in story
                need_keypress("1")
            else:
                assert way == "vdisk"
                if "import from Virtual Disk" not in story:
                    raise pytest.skip("Virtual Disk disabled")

                fpath = virtdisk_path(fname)
                garbage_collector.append(fpath)
                with open(fpath, "w") as f:
                    f.write(psbt)

                need_keypress("2")

            title, story = cap_story()
            if 'OK TO SEND' not in title:
                pick_menu_item(fname)
                time.sleep(0.1)
                title, story = cap_story()

            assert title == "OK TO SEND?"
            assert "msc2" in story
            press_select()  # confirm signing
            time.sleep(0.1)
            title, story = cap_story()
            assert title == 'PSBT Signed'


@pytest.mark.parametrize("desc", CHANGE_BASED_DESCS)
@pytest.mark.parametrize("way", ["usb", "sd", "vdisk", "nfc", "qr"])
def test_bip388_policies(desc, way, offer_minsc_import, press_select, pick_menu_item, goto_home,
                         clear_miniscript, microsd_path, virtdisk_path, garbage_collector,
                         need_keypress, cap_story, load_export, press_cancel, usb_miniscript_get,
                         skip_if_useless_way, scan_a_qr, press_nfc, nfc_write_text,
                         usb_miniscript_policy):

    skip_if_useless_way(way)
    clear_miniscript()
    title, story = offer_minsc_import(json.dumps(dict(name="msc1", desc=desc)))
    assert "msc1" in story
    assert "Create new miniscript wallet?" in story
    press_select()

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item("msc1")
    pick_menu_item("Descriptors")
    pick_menu_item("BIP-388 Policy")

    if way == "usb":
        contents = usb_miniscript_policy("msc1")
    else:
        contents = load_export(way, "BIP-388 Wallet Policy", is_json=True)
        press_cancel()
        press_cancel()
        if way != "nfc":
            press_cancel()

        pick_menu_item("Import")

    # try import - must raise duplicate
    new_name = "b388_reimport"
    # change name - make it harder
    contents["name"] = new_name
    to_import = json.dumps(contents)

    if way == "nfc":
        press_nfc()
        nfc_write_text(to_import)
        time.sleep(1)
        title, story = cap_story()
        assert "Duplicate wallet. Wallet 'msc1' is the same." in story
        assert "b388_reimport" in story
        press_cancel()

        clear_miniscript()
        pick_menu_item("Import")
        press_nfc()

        nfc_write_text(to_import)
        time.sleep(1)

    elif way == "qr":
        need_keypress(KEY_QR)
        # base64 PSBT as text
        actual_vers, parts = split_qrs(to_import, 'U', max_version=20)
        random.shuffle(parts)

        for p in parts:
            scan_a_qr(p)
            time.sleep(1)  # just so we can watch

        title, story = cap_story()
        assert "Duplicate wallet. Wallet 'msc1' is the same." in story
        assert "b388_reimport" in story
        press_cancel()

        clear_miniscript()
        pick_menu_item("Import")
        need_keypress(KEY_QR)

        for p in parts:
            scan_a_qr(p)
            time.sleep(1)  # just so we can watch

    elif way == "usb":
        goto_home()
        title, story = offer_minsc_import(to_import)
        assert "Duplicate wallet. Wallet 'msc1' is the same." in story
        assert "b388_reimport" in story
        press_cancel()

        clear_miniscript()
        offer_minsc_import(to_import)

    else:
        path_f = microsd_path if way == "sd" else virtdisk_path
        fname = "b388_reimport.json"
        fpath = path_f(fname)
        garbage_collector.append(fpath)
        with open(path_f(fname), "w") as f:
            f.write(to_import)

        if way == "sd":
            assert "Press (1)" in story
            need_keypress("1")
        else:
            assert way == "vdisk"
            if "import from Virtual Disk" not in story:
                raise pytest.skip("Virtual Disk disabled")

            need_keypress("2")

        # try to import duplicate
        time.sleep(.1)
        pick_menu_item(fname)
        time.sleep(.1)
        title, story = cap_story()
        assert "Duplicate wallet. Wallet 'msc1' is the same." in story
        assert "b388_reimport" in story

        press_cancel()
        # now clear imported miniscript and import
        clear_miniscript()
        pick_menu_item("Import")
        need_keypress("1" if way == "sd" else "2")
        time.sleep(.1)
        pick_menu_item(fname)


    time.sleep(.1)
    title, story = cap_story()
    assert "Duplicate wallet" not in story
    assert "Create new miniscript wallet?" in story
    assert "b388_reimport" in story
    press_select()

    # verify that the descriptor matches
    assert usb_miniscript_get(new_name)["desc"].split("#")[0] == desc.split("#")[0].replace("'", 'h')


def test_miniscript_rename(offer_minsc_import, clear_miniscript, press_select, goto_home,
                           pick_menu_item, enter_complex, cap_menu, cap_screen, is_q1,
                           need_keypress, press_cancel):
    clear_miniscript()
    name = "old_name"
    title, story = offer_minsc_import(json.dumps(dict(name=name, desc=CHANGE_BASED_DESCS[0])))
    assert "old_name" in story
    assert "Create new miniscript wallet?" in story
    press_select()

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item(name)
    pick_menu_item("Rename")
    if is_q1:
        # old name is filled in input field
        # same for Mk4, just not possible with cap_screen, or cap_story
        time.sleep(.1)
        scr = cap_screen()
        assert name in scr

    new_name = 35 * "0"
    # first delete old one
    for _ in range(len(name) - (0 if is_q1 else 1)):
        need_keypress(KEY_DELETE if is_q1 else "x")

    if is_q1:
        # attempt to use empty string as a name
        # on Mk4 it is not possible to not have at least one char
        press_select()
        time.sleep(.1)
        scr = cap_screen()
        assert "Need 1" in scr

    # it is not possible to input more than 30 characters
    enter_complex(new_name, apply=False, b39pass=False)

    real_name = new_name[:30]

    # specific wallet menu has changed
    time.sleep(.1)
    m = cap_menu()
    assert name not in m
    assert real_name == m[0]

    # miniscript wallets menu has changed
    press_cancel()  # one back

    time.sleep(.1)
    m = cap_menu()
    assert name not in m
    assert real_name == m[0]


def test_legacy_sh_miniscript(offer_minsc_import, press_select, create_core_wallet, clear_miniscript):
    clear_miniscript()
    desc = ("sh("
            "or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),"
            "and_v("
            "v:pkh([0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*),"
            "older(5))))")

    name = "legacy_sh_msc"
    with pytest.raises(Exception) as e:
        offer_minsc_import(json.dumps(dict(name=name, desc=desc)))

    assert "Miniscript in legacy P2SH not allowed" in str(e)


@pytest.mark.parametrize("lock", [
    ("older", 0),
    ("after", 0),
    ("older", 65536),
    ("after", 2147483648),
    # time-based relative locks
    ("older", 4194304),
    ("older", 4259840),
])
def test_timelocks_without_consesnsus_meaning(lock, clear_miniscript, goto_home, get_cc_key,
                                              offer_minsc_import, press_select):
    goto_home()
    clear_miniscript()
    policy = "and_v(v:pk(@0/<0;1>/*),locktime())"

    # not allowed to import on CC
    _type, val = lock
    to_replace = f"{_type}({val})"

    policy = policy.replace("locktime()", to_replace)

    tmplt = f"wsh({policy})"

    cc_key = get_cc_key("m/88h/0h/0h",).replace('/<0;1>/*', '')
    desc = tmplt.replace("@0", cc_key)

    wname = "locks_oob"

    with pytest.raises(Exception) as e:
        offer_minsc_import(json.dumps(dict(name=wname, desc=desc)))

    if _type == "older":
        if val & (1 << 22):
            what = "Time-based "
            x = 4194305
            y = 4259839
        else:
            what = "Block-based "
            x = 1
            y = (2**16)-1
    else:
        what = ""
        x = 1
        y = (2**31)-1

    assert f"{what}{lock[0]} out of range [{x}, {y}]" in e.value.args[0]
    press_select()

# EOF