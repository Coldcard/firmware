# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Miniscript-related tests.
#
import pytest, json, time, itertools, struct, random
from ckcc.protocol import CCProtocolPacker
from constants import AF_P2TR
from psbt import BasicPSBT


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


@pytest.fixture
def offer_minsc_import(cap_story, dev, need_keypress):
    def doit(config):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode())

        open('debug/last-config-msc.txt', 'wt').write(config)
        dev.send_recv(CCProtocolPacker.miniscript_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        return title, story

    return doit


@pytest.fixture
def import_miniscript(goto_home, pick_menu_item, cap_story, need_keypress):
    def doit(fname, way="sd"):
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        pick_menu_item('Import from File')
        time.sleep(.3)
        _, story = cap_story()
        if "Press (1) to import miniscript wallet file from SD Card" in story:
            # in case Vdisk or NFC is enabled
            if way == "sd":
                need_keypress("1")
            elif way == "nfc":
                pass
            elif way == "vdisk":
                pass
        time.sleep(.3)
        need_keypress("y")
        pick_menu_item(fname)
        time.sleep(.1)
        return cap_story()

    return doit

@pytest.fixture
def import_duplicate(import_miniscript, need_keypress):
    def doit(fname, way="sd"):
        _, story = import_miniscript(fname, way)
        assert "duplicate of already saved wallet" in story
        assert "OK to approve" not in story
        need_keypress("x")

    return doit

@pytest.fixture
def miniscript_descriptors(goto_home, pick_menu_item, need_keypress, cap_story,
                           microsd_path):
    def doit(minsc_name):
        goto_home()
        pick_menu_item("Settings")
        pick_menu_item("Miniscript")
        pick_menu_item(minsc_name)
        pick_menu_item("Descriptors")
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
        with open(microsd_path(fname), "r") as f:
            cont = f.read()
        external, internal = cont.split("\n")
        return external, internal
    return doit


@pytest.fixture
def get_cc_key(dev):
    def doit(path, int_ext=False):
        # cc device key
        master_xfp_str = struct.pack('<I', dev.master_fingerprint).hex()
        cc_key = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        return f"[{master_xfp_str}/{path}]{cc_key}{'/<0;1>/*' if int_ext else '/0/*'}"
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
                           cap_story, load_export, miniscript_descriptors):
    def doit(way, addr_fmt, wallet, cc_minsc_name, export_check=True):
        goto_home()
        pick_menu_item("Address Explorer")
        need_keypress('4')  # warning
        m = cap_menu()
        wal_name = m[-1]
        pick_menu_item(wal_name)

        title, story = cap_story()
        if addr_fmt == "bech32m":
            assert "Taproot internal key" in story
        else:
            assert "Taproot internal key" not in story

        contents = load_export(way, label="Address summary", is_json=False, sig_check=False, vdisk_key="4")
        addr_cont = contents.strip()

        time.sleep(5)
        title, story = cap_story()
        assert "Press (6)" in story
        assert "change addresses." in story
        need_keypress("6")
        time.sleep(5)
        title, story = cap_story()
        assert "Press (6)" not in story
        assert "change addresses." not in story

        contents_change = load_export(way, label="Address summary", is_json=False, sig_check=False, vdisk_key="4")
        addr_cont_change = contents_change.strip()

        if way == "nfc":
            addr_range = [0, 9]
            cc_addrs = addr_cont.split("\n")
            cc_addrs_change = addr_cont_change.split("\n")
            part_addr_index = 0
        else:
            addr_range = [0, 249]
            cc_addrs_split = addr_cont.split("\n")
            cc_addrs_split_change = addr_cont_change.split("\n")
            # header is different for taproot
            if addr_fmt == "bech32m":
                assert "Internal Key" in cc_addrs_split[0]
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
            assert cc_external.split("#")[0] == external_desc.split("#")[0].replace("'", "h")
            assert cc_internal.split("#")[0] == internal_desc.split("#")[0].replace("'", "h")

        bitcoind_addrs = wallet.deriveaddresses(external_desc, addr_range)
        bitcoind_addrs_change = wallet.deriveaddresses(internal_desc, addr_range)

        for cc, core in [(cc_addrs, bitcoind_addrs), (cc_addrs_change, bitcoind_addrs_change)]:
            for idx, cc_item in enumerate(cc):
                cc_item = cc_item.split(",")
                partial_address = cc_item[part_addr_index]
                _start, _end = partial_address.split("___")
                if way != "nfc":
                    _start, _end = _start[1:], _end[:-1]
                assert core[idx].startswith(_start)
                assert core[idx].endswith(_end)

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", ["bech32", "p2sh-segwit"])
@pytest.mark.parametrize("lt_type", ["older", "after"])  # this is actually not generated by liana (liana is relative only)
@pytest.mark.parametrize("recovery", [True, False])
# @pytest.mark.parametrize("lt_val", ["time", "block"]) TODO hard to test timebased
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",  # this is actually not generated by liana

    "or_d(multi(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi(2,@B,@C),locktime(N)))",
])
def test_liana_miniscripts_simple(addr_fmt, recovery, lt_type, minisc, clear_miniscript, goto_home,
                                  need_keypress, pick_menu_item, cap_menu, cap_story, microsd_path,
                                  use_regtest, bitcoind, microsd_wipe, load_export, dev,
                                  address_explorer_check, get_cc_key, import_miniscript,
                                  bitcoin_core_signer, import_duplicate):
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
    name = "core-miniscript"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    need_keypress("y")
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
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
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
    address_explorer_check("sd", addr_fmt, wo, "core-miniscript")


@pytest.mark.parametrize("addr_fmt", ["bech32", "p2sh-segwit"])
@pytest.mark.parametrize("minsc", [
    ("or_i(and_v(v:pkh($0),older(10)),or_d(multi(3,@A,@B,@C),and_v(v:thresh(2,pkh($1),a:pkh($2),a:pkh($3)),older(5))))", 0),
    ("or_i(and_v(v:pkh(@A),older(10)),or_d(multi(3,$0,$1,$2),and_v(v:thresh(2,pkh($3),a:pkh($4),a:pkh($5)),older(5))))", 10),
    ("or_i(and_v(v:pkh($0),older(10)),or_d(multi(3,$1,$2,$3),and_v(v:thresh(2,pkh(@A),a:pkh(@B),a:pkh($4)),older(5))))", 5),
])
def test_liana_miniscripts_complex(addr_fmt, minsc, bitcoind, use_regtest, clear_miniscript,
                                   microsd_path, pick_menu_item, need_keypress, cap_story,
                                   load_export, goto_home, address_explorer_check, cap_menu,
                                   get_cc_key, import_miniscript, bitcoin_core_signer,
                                   import_duplicate):
    use_regtest()
    clear_miniscript()

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
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    need_keypress("y")
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
    with open(microsd_path(pname), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(pname)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
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
    address_explorer_check("sd", addr_fmt, wo, name)


@pytest.fixture
def bitcoind_miniscript(bitcoind, need_keypress, cap_story, load_export, get_cc_key,
                        pick_menu_item, goto_home, cap_menu, microsd_path, use_regtest,
                        import_miniscript, bitcoin_core_signer, import_duplicate):
    def doit(M, N, script_type, internal_key=None, cc_account=0, funded=True, r=None,
             tapscript_threshold=False, add_own_pk=False):

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
        need_keypress("y")
        need_keypress(str(cc_account))  # account
        need_keypress("y")
        xpub_obj = load_export("sd", label="Multisig XPUB", is_json=True, sig_check=False)
        template = xpub_obj[script_type +"_desc"]

        if tapscript_threshold:
            me = f"[{xpub_obj['xfp']}/{xpub_obj[script_type + '_deriv'].replace('m/','')}]{xpub_obj[script_type]}/0/*"
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
                ss = [get_cc_key("m/86h/1h/0h")] + bitcoind_signers_xpubs
                tmplt = f"sortedmulti_a({M},{','.join(ss)})"
                cc_key = get_cc_key("m/86h/1h/1000h")
                cc_pk_leaf = f"pk({cc_key})"
                desc = f"tr({H},{{{tmplt},{cc_pk_leaf}}})"
            else:
                desc = template.replace("M", str(M), 1).replace("...", ",".join(bitcoind_signers_xpubs))

            if internal_key:
                desc = desc.replace(H, internal_key)
            elif r:
                desc = desc.replace(H, f"r={r}")

        name = "minisc.txt"
        with open(microsd_path(name), "w") as f:
            f.write(desc + "\n")
        _, story = import_miniscript(name)
        assert "Create new miniscript wallet?" in story
        assert name.split(".")[0] in story
        if script_type == "p2tr":
            assert "Taproot internal key" in story
            assert "Taproot tree keys" in story
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
        need_keypress("y")  # approve multisig import
        if r:
            # unspendable key is generated randomly
            # descriptors will differ
            with pytest.raises(AssertionError):
                import_duplicate(name)
        else:
            import_duplicate(name)
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        menu = cap_menu()
        pick_menu_item(menu[0])  # pick imported descriptor multisig wallet
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
@pytest.mark.parametrize("M_N", [(3,4),(4,5),(5,6)])
def test_tapscript(M_N, cc_first, clear_miniscript, goto_home, need_keypress, pick_menu_item,
                   cap_menu, cap_story, microsd_path, use_regtest, bitcoind, microsd_wipe,
                   load_export, bitcoind_miniscript, add_pk):
    M, N = M_N
    clear_miniscript()
    microsd_wipe()
    wo, signers = bitcoind_miniscript(M, N, "p2tr", tapscript_threshold=True, add_own_pk=add_pk)
    addr = wo.getnewaddress("", "bech32m")
    bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    conso_addr = wo.getnewaddress("conso", "bech32m")
    psbt = wo.walletcreatefundedpsbt([], [{conso_addr:25}], 0, {"fee_rate": 2})["psbt"]
    if not cc_first:
        for s in signers[0:M-1]:
            psbt = s.walletprocesspsbt(psbt, True, "DEFAULT")["psbt"]
    with open(microsd_path("ts_tree.psbt"), "w") as f:
        f.write(psbt)
    time.sleep(2)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.2)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    need_keypress("y")
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "PSBT Signed"
    fname = story.split("\n\n")[-1]
    with open(microsd_path(fname), "r") as f:
        psbt = f.read().strip()
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
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_bitcoind_tapscript_address(M_N, clear_miniscript, goto_home, need_keypress,
                                    pick_menu_item, cap_menu, cap_story, make_multisig,
                                    import_ms_wallet, microsd_path, bitcoind_miniscript,
                                    use_regtest, load_export, way, csa, address_explorer_check,
                                    add_pk):
    use_regtest()
    clear_miniscript()
    M, N = M_N
    ms_wo, _ = bitcoind_miniscript(M, N, "p2tr", funded=False, tapscript_threshold=csa,
                                   add_own_pk=add_pk)
    address_explorer_check(way, "bech32m", ms_wo, "minisc", export_check=False)


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("m_n", [(2,2), (3, 5), (32, 32)])
@pytest.mark.parametrize("internal_key_spendable", [True, False, "77ec0c0fdb9733e6a3c753b1374c4a465cba80dff52fc196972640a26dd08b76", "@"])
def test_tapscript_multisig(cc_first, m_n, internal_key_spendable, use_regtest, bitcoind, goto_home, cap_menu,
                            need_keypress, pick_menu_item, cap_story, microsd_path, load_export, microsd_wipe, dev,
                            bitcoind_miniscript, clear_miniscript, get_cc_key):
    M, N = m_n
    clear_miniscript()
    microsd_wipe()
    internal_key = None
    r = None
    if internal_key_spendable is True:
        internal_key = get_cc_key("86h/0h/3h")
    elif isinstance(internal_key_spendable, str) and len(internal_key_spendable) == 64:
        r = internal_key_spendable
    elif internal_key_spendable == "@":
        r = "@"

    tapscript_wo, bitcoind_signers = bitcoind_miniscript(M, N, "p2tr", internal_key=internal_key, r=r)

    dest_addr = tapscript_wo.getnewaddress("", "bech32m")
    psbt = tapscript_wo.walletcreatefundedpsbt([], [{dest_addr: 1.0}], 0, {"fee_rate": 20})["psbt"]
    fname = "tapscript.psbt"
    if not cc_first:
        # bitcoind cosigner sigs first
        for i in range(M - 1):
            signer = bitcoind_signers[i]
            psbt = signer.walletprocesspsbt(psbt, True, "DEFAULT", True)["psbt"]
    with open(microsd_path(fname), "w") as f:
        f.write(psbt)
    goto_home()
    # bug in goto_home ?
    need_keypress("x")
    time.sleep(0.1)
    # CC signing
    need_keypress("y")
    time.sleep(0.1)
    title, story = cap_story()
    if "Choose" in story:
        need_keypress("y")
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    need_keypress("y")
    time.sleep(0.1)
    title, story = cap_story()
    split_story = story.split("\n\n")
    cc_tx_id = None
    if "(ready for broadcast)" in story:
        signed_fname = split_story[1]
        signed_txn_fname = split_story[-2]
        cc_tx_id = split_story[-1].split("\n")[-1]
        with open(microsd_path(signed_txn_fname), "r") as f:
            signed_txn = f.read().strip()
    else:
        signed_fname = split_story[-1]

    with open(microsd_path(signed_fname), "r") as f:
        signed_psbt = f.read().strip()

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
                      internal_key_spendable, dev, microsd_path, need_keypress, get_cc_key,
                      pick_menu_item, cap_story, goto_home, cap_menu, load_export,
                      import_miniscript, bitcoin_core_signer, import_duplicate):
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
    with open(microsd_path(fname), "w") as f:
        f.write(desc + "\n")
    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Taproot internal key" in story
    assert "Taproot tree keys" in story
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    need_keypress("y")
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
    with open(microsd_path(fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
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
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},sortedmulti_a(2,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)})",
    "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{{sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[b7fe820c/48'/1'/0'/3']tpubDFdQ1sNV53TbogAMPEd2egY5NXfbdKD1Mnr2iBrJrcwRHJbKC7tuuUMHT8SSHJ2VEKdCf5WYBMfevvWCnyJV53gYUT2wFyxEV8SuUTedBp7/0/*),sortedmulti_a(2,[0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*,[30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*)},or_d(pk([0f056943/48'/1'/0'/3']tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/0/*),and_v(v:pkh([30afbe54/48'/1'/0'/3']tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/0/*),older(500)))})",
])
def test_tapscript_import_export(clear_miniscript, pick_menu_item, cap_story, need_keypress,
                                 import_miniscript, load_export, desc, microsd_path):
    clear_miniscript()
    fname = "imdesc.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    _, story = import_miniscript(fname)
    need_keypress("y")  # approve miniscript import
    pick_menu_item(fname.split(".")[0])
    pick_menu_item("Descriptors")
    pick_menu_item("Export")
    time.sleep(.1)
    title, story = cap_story()
    assert "(<0;1> notation) press OK" in story
    need_keypress("y")
    contents = load_export("sd", label="Miniscript", is_json=False, addr_fmt=AF_P2TR,
                           sig_check=False)
    descriptor = contents.strip()
    assert desc.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h") == descriptor.split("#")[0].replace("<0;1>/*", "0/*").replace("'", "h")


def test_duplicate_tapscript_leaves(use_regtest, clear_miniscript, microsd_wipe, bitcoind, dev,
                                    goto_home, pick_menu_item, need_keypress, microsd_path,
                                    cap_story, load_export, get_cc_key, import_miniscript,
                                    bitcoin_core_signer, import_duplicate):
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
    with open(microsd_path(fname), "w") as f:
        f.write(desc)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Taproot internal key" in story
    assert "Taproot tree keys" in story
    assert "Press (1) to see extended public keys" in story
    assert "P2TR" in story

    need_keypress("y")
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
    with open(microsd_path(fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
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


def test_same_key_account_based_minisc(goto_home, need_keypress, pick_menu_item, cap_story,
                                       clear_miniscript, microsd_path, load_export, bitcoind,
                                       import_miniscript, import_duplicate):
    clear_miniscript()
    desc = ("wsh("
            "or_d(pk([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*),"
            "and_v("
            "v:pkh([0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*),"
            "older(5))))#qmwvph5c")
    name = "mini-accounts"
    fname = f"{name}.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    assert fname.split(".")[0] in story
    assert "Press (1) to see extended public keys" in story

    need_keypress("y")
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
    with open(microsd_path(fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(fname)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()

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


def test_same_key_account_based_multisig(goto_home, need_keypress, pick_menu_item, cap_story,
                                         clear_miniscript, microsd_path, load_export, bitcoind,
                                         import_miniscript):
    # but still imported as miniscript - even tho it is basic multisig that can be imported legacy path
    clear_miniscript()
    desc = ("wsh(sortedmulti(2,"
            "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*,"
            "[0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*"
            "))")
    name = "multi-accounts"
    fname = f"{name}.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)

    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "Use Settings -> Multisig Wallets" in story


@pytest.mark.parametrize("desc", [
    "wsh(or_d(pk(@A),and_v(v:pkh(@A),older(5))))",
    "tr(%s,multi_a(2,@A,@A))" % H,
    "tr(%s,{sortedmulti_a(2,@A,@A),pk(@A)})" % H,
    "tr(%s,or_d(pk(@A),and_v(v:pkh(@A),older(5))))" % H,
])
def test_insane_miniscript(get_cc_key, pick_menu_item, need_keypress, cap_story,
                           microsd_path, desc, import_miniscript):

    cc_key = get_cc_key("84h/0h/0h")
    desc = desc.replace("@A", cc_key)
    fname = "insane.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)

    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "Insane" in story

def test_tapscript_depth(get_cc_key, pick_menu_item, need_keypress, cap_story,
                         microsd_path, import_miniscript):
    leaf_num = 9
    scripts = []
    for i in range(leaf_num):
        k = get_cc_key(f"84h/0h/{i}h")
        scripts.append(f"pk({k})")

    tree = TREE[leaf_num] % tuple(scripts)
    desc = f"tr({H},{tree})"
    fname = "9leafs.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)
    _, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "num_leafs > 8" in story

@pytest.mark.bitcoind
@pytest.mark.parametrize("lt_type", ["older", "after"])
@pytest.mark.parametrize("recovery", [True, False])
@pytest.mark.parametrize("leaf2_mine", [True, False])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",

    "or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi_a(2,@B,@C),locktime(N)))",
])
def test_minitapscript(leaf2_mine, recovery, lt_type, minisc, clear_miniscript, goto_home,
                       need_keypress, pick_menu_item, cap_menu, cap_story, microsd_path,
                       use_regtest, bitcoind, microsd_wipe, load_export, dev,
                       address_explorer_check, get_cc_key, import_miniscript,
                       bitcoin_core_signer, import_duplicate):

    # needs this bitcoind branch https://github.com/bitcoin/bitcoin/pull/27255
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

    if leaf2_mine:
        desc = f"tr({H},{{{minisc},pk({cc_key1})}})"
    else:
        desc = f"tr({H},{{pk({core_keys[2]}),{minisc}}})"

    use_regtest()
    clear_miniscript()
    name = "minitapscript"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    need_keypress("y")
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
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
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
                     cap_story, need_keypress, import_miniscript):
    clear_miniscript()
    fname = "imdesc.txt"
    with open(microsd_path(fname), "w") as f:
        f.write(desc)

    title, story = import_miniscript(fname)
    assert "Failed to import" in story
    assert "multi mixin" in story


def test_timelock_mixin():
    pass


@pytest.mark.parametrize("addr_fmt", ["bech32", "bech32m"])
@pytest.mark.parametrize("cc_first", [True, False])
def test_d_wrapper(addr_fmt, bitcoind, get_cc_key, goto_home, pick_menu_item, cap_story, cap_menu,
                   need_keypress, load_export, microsd_path, use_regtest, clear_miniscript, cc_first,
                   address_explorer_check, import_miniscript, bitcoin_core_signer):

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
    need_keypress("y")
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
    with open(microsd_path(name), "w") as f:
        f.write(to_sign_psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "Choose PSBT file to be signed" in story:
        need_keypress("y")
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert "OK TO SEND?" in title
    assert "Consolidating" in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()

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
                         need_keypress, import_miniscript, microsd_path):
    clear_miniscript()
    use_regtest()

    x = "wsh(or_d(pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),and_v(v:pkh([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),older(100))))"
    z = "wsh(or_d(pk([0f056943/48'/0'/0'/3']xpub6FQgdFZAHcAeDMVe9KxWoLMxziCjscCExzuKJhRSjM71CA9dUDZEGNgPe4S2SsRumCBXeaTBZ5nKz2cMDiK4UEbGkFXNipHLkm46inpjE9D/0/*),and_v(v:pkh([0f056943/48'/0'/0'/2']xpub6FQgdFZAHcAeAhQX2VvQ42CW2fDdKDhgwzhzXuUhWb4yfArmaZXkLbGS9W1UcgHwNxVESCS1b8BK8tgNYEF8cgmc9zkmsE45QSEvbwdp6Kr/0/*),older(100))))"
    y = f"tr({H},or_d(pk([30afbe54/48h/1h/0h/3h]tpubDFLVv7cuiLjn3QcsCend5kn3yw5sx6Czazy7hZvdGX61v8pkU95k2Byz9M5jnabzeUg7qWtHYLeKQyCWWAHhUmQQMeZ4Dee2CfGR2TsZqrN/<0;1>/*),and_v(v:pk([0f056943/48h/1h/0h/3h]tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez/<0;1>/*),after(800000))))"

    fname_btc = "BTC.txt"
    fname_xtn = "XTN.txt"
    fname_xtn0 = "XTN0.txt"

    for desc, fname in [(x, fname_xtn), (z, fname_btc), (y, fname_xtn0)]:
        with open(microsd_path(fname), "w") as f:
            f.write(desc)

    # cannot import XPUBS when testnet/regtest enabled
    _, story = import_miniscript(fname_btc)
    assert "Failed to import" in story
    assert "wrong chain" in story

    import_miniscript(fname_xtn)
    need_keypress("y")
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
    need_keypress("y")
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
    need_keypress("y")
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
                                                 offer_minsc_import, need_keypress,
                                                 cap_menu, bitcoind, pick_menu_item):
    use_regtest()
    clear_miniscript()
    taproot, ik_spendable = taproot_ikspendable
    if taproot:
        minisc = minisc.replace("multi(", "multi_a(")
        if ik_spendable:
            ik = get_cc_key("84h/1h/100h")
            desc = f"tr({ik},{minisc})"
        else:
            desc = f"tr({H},{minisc})"
    else:
        desc = f"wsh({minisc})"

    cc_key0 = get_cc_key("84h/1h/0h")
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
    need_keypress("y")
    time.sleep(.2)
    title, story = offer_minsc_import(desc1)
    assert "Create new miniscript wallet?" in story
    need_keypress("y")
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    m = cap_menu()
    assert len(m) == 3
