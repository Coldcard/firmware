# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# MuSig2 tests.
#
import pytest, base64, itertools, time, json, copy, random, os
from txn import BasicPSBT
from constants import SIGHASH_MAP
from bip32 import random_keys, ranged_unspendable_internal_key, BIP32Node
from helpers import generate_binary_tree_template
from mnemonic import Mnemonic


def sighash_check(psbt, sighash):
    po = BasicPSBT().parse(psbt)
    for inp in po.inputs:
        if sighash != "DEFAULT":
            assert inp.sighash == SIGHASH_MAP[sighash]
        else:
            assert inp.sighash is None


@pytest.fixture
def build_musig_wallet(bitcoin_core_signer, microsd_path, garbage_collector, press_select, get_cc_key,
                       import_duplicate, create_core_wallet, import_miniscript, offer_minsc_import):

    def doit(wal_name, num_signers, cc_key_orig_der="86h/1h/0h", import_way="usb",
             musig_subder=None, tapscript=False, tapscript_musig_threshold=0, wallet_type=0,
             tree_design="balanced", num_utxo_available=1):

        # wallet type 0 -> musig with all participant keys in taproot internal, N-1 signer leaves in tapscript
        # wallet type 1 -> N-1 across both internal key and tapscript leaves + one fallback sortedmulti

        # derivation not allowed inside musig
        core_pubkeys = []
        core_privkeys = []
        signers = []

        # first signer is CC
        cc_key = get_cc_key(cc_key_orig_der).replace("/<0;1>/*", "")

        for i in range(num_signers-1):
            # core signers
            signer, core_pk, core_sk = bitcoin_core_signer(f"{wal_name}_cosigner{i}", privkey=True)
            signer.keypoolrefill(25)
            core_pubkeys.append(core_pk.replace("/0/*", ""))
            core_privkeys.append(core_sk.replace("/0/*", ""))
            signers.append(signer)

        all_pks = [cc_key] + core_pubkeys
        if isinstance(tapscript, str):
            # custom descriptor - fill keys
            desc = tapscript.replace("$H", ranged_unspendable_internal_key())
            for i in range(len(all_pks) -1, -1, -1):
                desc = desc.replace(f"${i}", all_pks[i])

        else:
            random.shuffle(all_pks)
            inner = "musig(%s)" % ",".join(all_pks)
            if musig_subder:
                inner += musig_subder

            if tapscript:
                if wallet_type == 0:
                    scripts = []
                    for c in itertools.combinations(all_pks, tapscript_musig_threshold):
                        msig = f"pk(musig({','.join(c)}){musig_subder or ''})"
                        scripts.append(msig)

                    tmplt = generate_binary_tree_template(len(scripts), strategy=tree_design)
                    tapscript = tmplt % tuple(scripts)

                    inner += ","
                    inner += tapscript

                elif wallet_type == 1:
                    scripts = []
                    for c in itertools.combinations(all_pks, tapscript_musig_threshold):
                        msig = f"musig({','.join(c)}){musig_subder or ''}"
                        scripts.append(msig)

                    # internal key is just one of the musigs with N-1 keys
                    inner = scripts.pop(0)
                    scripts = [f"pk({sc})" for sc in scripts]
                    # add fallback sortedmulti classic multisig
                    scripts.append(f"sortedmulti_a({tapscript_musig_threshold},{','.join(all_pks)})")
                    # as one musig was removed from scripts & one fallback added, len is correct
                    tmplt = generate_binary_tree_template(len(scripts), strategy=tree_design)
                    tapscript = tmplt % tuple(scripts)

                    inner += ","
                    inner += tapscript

            desc = f"tr({inner})"

        if import_way == "usb":
            _, story = offer_minsc_import(json.dumps(dict(name=wal_name, desc=desc)))
        elif import_way == "sd":
            fname = f"{wal_name}.txt"
            fpath = microsd_path(fname)
            with open(fpath, "w") as f:
                f.write(desc)

            garbage_collector.append(fpath)
            _, story = import_miniscript(fname)
        else:
            raise ValueError  # not implemented (yet)

        assert "Create new miniscript wallet?" in story
        assert wal_name in story
        # do some checks on policy --> helper function to replace keys with letters
        press_select()

        wo = create_core_wallet(wal_name, "bech32m", "sd", num_utxo_available)

        desc_lst = []
        for obj in wo.listdescriptors()["descriptors"]:
            del obj["next"]
            del obj["next_index"]
            desc_lst.append(obj)

        # import musig descriptor to signers
        # each signer has it's own privkey loaded
        for s, spk, ssk in zip(signers, core_pubkeys, core_privkeys):
            to_import = copy.deepcopy(desc_lst)
            for dobj in to_import:
                dobj["desc"] = dobj["desc"].split("#")[0].replace(spk, ssk)
                csum = wo.getdescriptorinfo(dobj["desc"])["checksum"]
                dobj["desc"] = dobj["desc"] + "#" + csum

            res = s.importdescriptors(to_import)
            for o in res:
                assert o["success"]

        # return watch only wallet with musig imported
        # & core signers with musig wallet imported
        # & descriptor that was imported into CC and watch onyl wallet
        return wo, signers, desc

    return doit


@pytest.fixture
def musig_signing(start_sign, end_sign, microsd_path, garbage_collector, cap_story, goto_home,
                  pick_menu_item, press_select, bitcoind, need_keypress, press_cancel):

    def doit(wallet_name, watch_only, core_signers, coldcard_first, signers_start, signers_end,
             finalized, split_to=10, sequence=None, locktime=0, cc_first_no_sigs_added=True):

        all_of_it = watch_only.getbalance()
        unspent = watch_only.listunspent()
        assert len(unspent) == 1

        if sequence:
            inp = [{"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "sequence": sequence}]
        else:
            inp = []  # auto-selection

        # split to
        nVal = all_of_it / split_to
        conso_addrs = [{watch_only.getnewaddress("", "bech32m"): nVal} for _ in range(split_to)]  # self-spend
        psbt_resp = watch_only.walletcreatefundedpsbt(
            inp,
            conso_addrs,
            locktime,
            {"fee_rate": 2, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
        )
        psbt = psbt_resp.get("psbt")

        if not coldcard_first:
            # cosigners adding nonces
            for s in core_signers:
                psbt_resp = s.walletprocesspsbt(psbt, True, "DEFAULT", True, False)
                psbt = psbt_resp.get("psbt")

        # CC add nonce
        # even if all nonces from co-signers are already present we do not add signatures
        # 1st & 2nd round are strictly separated
        # if CC adds nonce, no signatures are added and vice-versa
        start_sign(base64.b64decode(psbt))
        title, story = cap_story()
        assert "Consolidating" in story
        assert f"Wallet: {wallet_name}" in story
        need_keypress("2")
        pick_menu_item("Inputs")
        title, story = cap_story()
        assert "MuSig2" in story
        press_cancel()
        press_cancel()
        res_psbt = end_sign(exit_export_loop=False)
        time.sleep(.1)
        title, story = cap_story()
        if not cc_first_no_sigs_added:
            assert "PSBT Signed" == title
        else:
            assert "PSBT Updated" == title

        press_cancel()  # exit export loop

        b64_res_psbt = base64.b64encode(res_psbt).decode()

        if coldcard_first:
            # if cc was first to add pubnonce - now core cosigners will add
            for s in core_signers:
                psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "DEFAULT", True, False)
                b64_res_psbt = psbt_resp.get("psbt")

        # cosigners adding signatures - core also strictly separates 1st & 2nd round (cannot add both nonce and sigs in one sitting)
        for s in core_signers[signers_start: signers_end]:
            psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "DEFAULT", True, False)
            b64_res_psbt = psbt_resp.get("psbt")

        final_txn = None
        cc_txid = None
        # now CC adds signatures
        # go via SD, as we want to see both PSBT and finalized tx
        fname = f"{wallet_name}.psbt"
        fpath = microsd_path(fname)
        with open(fpath, "w") as f:
            f.write(b64_res_psbt)

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
        split_story = story.split("\n\n")
        fname_psbt = split_story[1]

        fpath_psbt = microsd_path(fname_psbt)
        with open(fpath_psbt, "r") as f:
            b64_res_psbt = f.read().strip()
        garbage_collector.append(fpath_psbt)

        if finalized:
            fname_txn = split_story[3]
            cc_txid = split_story[4].split("\n")[-1]
            fpath_txn = microsd_path(fname_txn)
            with open(fpath_txn, "r") as f:
                final_txn = f.read().strip()
            garbage_collector.append(fpath_txn)

        res = watch_only.finalizepsbt(b64_res_psbt)
        assert res["complete"]
        tx_hex = res["hex"]
        if finalized:
            assert tx_hex == final_txn

        if (sequence or locktime) and not finalized:
            # we are signing for timelocked tapscript
            res = watch_only.testmempoolaccept([tx_hex])
            assert res[0]["allowed"] is False
            assert res[0]['reject-reason'] == 'non-BIP68-final' if sequence else "non-final"
            if sequence:
                bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())
            else:
                block_h = watch_only.getblockchaininfo()["blocks"]
                bitcoind.supply_wallet.generatetoaddress(locktime - block_h, bitcoind.supply_wallet.getnewaddress())


        res = watch_only.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
        res = watch_only.sendrawtransaction(tx_hex)
        assert len(res) == 64  # tx id
        if finalized:
            assert res == cc_txid

        #
        # now consolidate multiple inputs to send out
        bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above
        all_of_it = watch_only.getbalance()
        unspent = watch_only.listunspent()
        assert len(unspent) == split_to

        ins = [{"txid": u["txid"], "vout": u["vout"]} for u in unspent]
        if sequence:
            for i in ins:
                i["sequence"] = sequence

        psbt_resp = watch_only.walletcreatefundedpsbt(
            ins,
            [{bitcoind.supply_wallet.getnewaddress(): all_of_it - 2}],  # slightly less so we still have some change
            locktime,
            {"fee_rate": 2, "change_type": "bech32m"},
        )
        psbt1 = psbt_resp.get("psbt")

        if not coldcard_first:
            # cosigners adding nonces
            for s in core_signers:
                psbt_resp = s.walletprocesspsbt(psbt1, True, "DEFAULT", True, False)
                psbt1 = psbt_resp.get("psbt")

        # CC adds nonces
        start_sign(base64.b64decode(psbt1))
        title, story = cap_story()
        assert "Consolidating" not in story
        assert "Change back:" in story  # has one change address
        assert f"Wallet: {wallet_name}" in story
        res_psbt1 = end_sign(exit_export_loop=False)
        time.sleep(.1)
        title, story = cap_story()
        if not cc_first_no_sigs_added:
            assert "PSBT Signed" == title
        else:
            assert "PSBT Updated" == title

        press_cancel()  # exit export loop

        b64_res_psbt1 = base64.b64encode(res_psbt1).decode()

        if coldcard_first:
            # if cc was first to add pubnonce - now core cosigners will add nonces
            for s in core_signers:
                psbt_resp = s.walletprocesspsbt(b64_res_psbt1, True, "DEFAULT", True, False)
                b64_res_psbt1 = psbt_resp.get("psbt")

        # cosigners adding signatures
        for s in core_signers[signers_start: signers_end]:
            psbt_resp = s.walletprocesspsbt(b64_res_psbt1, True, "DEFAULT", True, False)
            b64_res_psbt1 = psbt_resp.get("psbt")

        final_txn1 = None
        cc_txid1 = None
        # CC adds signatures
        # go via SD, as we want to see both PSBT and finalized tx
        fname = f"{wallet_name}.psbt"
        fpath = microsd_path(fname)
        with open(fpath, "w") as f:
            f.write(b64_res_psbt1)

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
        assert "Change back:" in story  # has one change address
        press_select()  # confirm signing
        time.sleep(0.5)
        title, story = cap_story()
        assert "PSBT Signed" == title
        assert "Updated PSBT is:" in story
        press_select()
        split_story = story.split("\n\n")
        fname_psbt = split_story[1]

        fpath_psbt = microsd_path(fname_psbt)
        with open(fpath_psbt, "r") as f:
            b64_res_psbt1 = f.read().strip()
        garbage_collector.append(fpath_psbt)

        if finalized:
            fname_txn = split_story[3]
            cc_txid1 = split_story[4].split("\n")[-1]
            fpath_txn = microsd_path(fname_txn)
            with open(fpath_txn, "r") as f:
                final_txn1 = f.read().strip()
            garbage_collector.append(fpath_txn)

        res1 = watch_only.finalizepsbt(b64_res_psbt1)
        assert res1["complete"]
        tx_hex1 = res1["hex"]
        if coldcard_first and finalized:
            assert tx_hex1 == final_txn1

        if sequence and not finalized:
            # we are signing for timelocked tapscript
            res = watch_only.testmempoolaccept([tx_hex1])
            assert res[0]["allowed"] is False
            assert res[0]['reject-reason'] == 'non-BIP68-final'
            bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

        res = watch_only.testmempoolaccept([tx_hex1])
        assert res[0]["allowed"]
        res = watch_only.sendrawtransaction(tx_hex1)
        assert len(res) == 64  # tx id
        if coldcard_first and finalized:
            assert res == cc_txid1

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("tapscript", [1, False, 2, 3])
@pytest.mark.parametrize("ts_level", [0, 1])
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("originless", [True, False])  # co-signer keys do not include origin derivation
def test_musig(tapscript, ts_level, cc_first, clear_miniscript, microsd_path, use_regtest,
               address_explorer_check, get_cc_key, import_miniscript, bitcoin_core_signer,
               import_duplicate, press_select, create_core_wallet, garbage_collector,
               musig_signing, originless):

    use_regtest()

    # derivation not allowed inside musig
    core_pubkeys = []
    core_privkeys = []
    signers = []
    for i in range(2):
        # core signers
        signer, core_pk, core_sk = bitcoin_core_signer(f"musig-co-signer{i}", privkey=True)
        signer.keypoolrefill(25)
        core_pk = core_pk.replace("/0/*", "")
        if originless:
            core_pk = core_pk.split("]")[-1]
        core_sk = core_sk.replace("/0/*", "")
        core_pubkeys.append(core_pk)
        core_privkeys.append(core_sk)
        signers.append(signer)

    cc_key = get_cc_key("86h/1h/0h").replace("/<0;1>/*", "")

    inner = "musig(%s)/<2;3>/*" % ",".join([cc_key] + core_pubkeys)

    sequence = None
    cc_first_no_sigs_added = True
    if tapscript:
        if tapscript == 1:
            # musig in tapscript
            s0 = f"pk(musig({cc_key},{core_pubkeys[1]})/<2;3>/*)"
            s1 = f"pk(musig({cc_key},{core_pubkeys[0]})/<2;3>/*)"
            s2 = f"pk(musig({core_pubkeys[0]},{core_pubkeys[1]})/<2;3>/*)"
        elif tapscript == 2:
            # classic multisig in tapscript
            s0 = f"sortedmulti_a(2,{cc_key}/<2;3>/*,{core_pubkeys[1]}/<2;3>/*)"
            s1 = f"sortedmulti_a(2,{cc_key}/<2;3>/*,{core_pubkeys[0]}/<2;3>/*)"
            s2 = f"sortedmulti_a(2,{core_pubkeys[0]}/<2;3>/*,{core_pubkeys[1]}/<2;3>/*)"
            # we will add signatures for classic multisig leafs, so title will be PSBT Signed (not PSBT Updated)
            cc_first_no_sigs_added = False
        elif tapscript == 3:
            # time-locked musig in tapscript
            sequence = 10
            s0 = f"and_v(v:pk(musig({cc_key},{core_pubkeys[1]})/<2;3>/*),older(10))"
            s1 = f"and_v(v:pk(musig({cc_key},{core_pubkeys[0]})/<2;3>/*),older(10))"
            s2 = f"and_v(v:pk(musig({core_pubkeys[0]},{core_pubkeys[1]})/<2;3>/*),older(10))"
        else:
            raise NotImplementedError

        inner += ","

        # in tapscript we're always signing only with signer[1]
        # only one core signer to not satisfy musig in internal key & actually test tapscript
        # ts_level decides whether "signable leaf" is at depth 0 or 1
        if ts_level:
            # signable tapscript leaf (s0) at level 1
            inner += "{%s,{%s,%s}}" % (s2,s1,s0)
        else:
            # signable tapscript leaf (s0) at level 0
            inner += "{%s,{%s,%s}}" % (s0,s1,s2)

    desc = f"tr({inner})"

    clear_miniscript()
    name = "musig"
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

    desc_lst = []
    for obj in wo.listdescriptors()["descriptors"]:
        del obj["next"]
        del obj["next_index"]
        desc_lst.append(obj)

    # import musig descriptor to signers
    # each signer has it's own privkey loaded
    for s, spk, ssk in zip(signers, core_pubkeys, core_privkeys):
        to_import = copy.deepcopy(desc_lst)
        for dobj in to_import:
            dobj["desc"] = dobj["desc"].split("#")[0].replace(spk, ssk)
            csum = wo.getdescriptorinfo(dobj["desc"])["checksum"]
            dobj["desc"] = dobj["desc"] + "#" + csum

        res = s.importdescriptors(to_import)
        for o in res:
            assert o["success"]

    if tapscript:
        # sign with just one core signer + CC
        # all the leafs have 2of2, only internal key has 3of3, so enough to produce finalizable tx
        _from, _to = 1, 2
    else:
        # signing with internal key - needs all signatures
        _from, _to = 0, 2

    musig_signing(name, wo, signers, cc_first, _from, _to, finalized=not tapscript, split_to=10,
                  sequence=sequence, cc_first_no_sigs_added=cc_first_no_sigs_added)

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


@pytest.mark.bitcoind
@pytest.mark.parametrize("N_K", [(5,3),(6,4), (10,9)])
@pytest.mark.parametrize("tapscript", [True, False])
@pytest.mark.parametrize("cc_first", [True, False])
def test_musig_big(N_K, cc_first, tapscript, clear_miniscript, use_regtest, address_explorer_check,
                   build_musig_wallet, musig_signing):

    num_signers, threshold = N_K
    use_regtest()
    clear_miniscript()

    # how many signers need to sing in different situations
    # if only internal key musig, all must sign so from will be 0 and to len(signers)
    if tapscript:
        _from, _to = 1, threshold
    else:
        _from, _to = 0, num_signers

    name = "big_musig"
    wo, signers, desc = build_musig_wallet(name, num_signers, tapscript=tapscript,
                                           tree_design=random.choice(["left_heavy", "right_heavy"]),  # not balanced tree
                                           tapscript_musig_threshold=threshold)

    musig_signing(name, wo, signers, cc_first, _from, _to, finalized=not tapscript, split_to=20)

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


@pytest.mark.bitcoind
@pytest.mark.parametrize("N_K", [(3,2),(4,3)])
@pytest.mark.parametrize("cc_first", [True, False])
def test_musig_alt(N_K, cc_first, clear_miniscript, use_regtest, address_explorer_check,
                   build_musig_wallet, musig_signing):

    num_signers, threshold = N_K
    use_regtest()
    clear_miniscript()

    name = "alt_musig"
    wo, signers, desc = build_musig_wallet(name, num_signers, tapscript=True, wallet_type=1,
                                           tapscript_musig_threshold=threshold)

    # we may finalize, but only randomly as we have no idea whether our key will be in the internal key
    # key order is randomized in build musig wallet
    musig_signing(name, wo, signers, cc_first, 1, threshold, finalized=False, split_to=5,
                  cc_first_no_sigs_added=False)

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


@pytest.mark.parametrize("tapscript", [
    "tr($H,and_v(v:pk(musig($0,$1,$2)/<0;1>/*),after(120)))",
    "tr($H,and_v(vc:pk_k(musig($0,$1,$2)/<0;1>/*),after(120)))",
    "tr($H,and_v(v:pkh(musig($0,$1,$2)/<0;1>/*),after(120)))",
    "tr($H,and_v(vc:pk_h(musig($0,$1,$2)/<0;1>/*),after(120)))",
    "tr($H,{and_v(v:pk(musig($0,$2)/0/*),after(120)),and_v(v:pk(musig($1,$2)/0/*),after(120))})",
])
def test_miniscript_musig_variations(tapscript, clear_miniscript, use_regtest, address_explorer_check,
                       build_musig_wallet, musig_signing):

    num_signers = 3
    use_regtest()
    clear_miniscript()

    name = "mini_tap"
    wo, signers, desc = build_musig_wallet(name, num_signers, tapscript=tapscript)

    musig_signing(name, wo, signers, False, 0, num_signers, finalized=False,
                  split_to=4, locktime=120)

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


def test_resign_musig_psbt_nonce(use_regtest, clear_miniscript, build_musig_wallet, start_sign,
                                 cap_story, end_sign, press_cancel):
    use_regtest()
    clear_miniscript()
    name = "musig_resign_nonce"
    wo, signers, desc = build_musig_wallet(name, 3, tapscript=True,
                                           tapscript_musig_threshold=2)

    psbt_resp = wo.walletcreatefundedpsbt([], [{wo.getnewaddress("", "bech32m"): 5}], 0,
                                          {"fee_rate": 2, "change_type": "bech32m"})
    # nothing added yet
    empty_psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(empty_psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    # resign empty PSBT - even thou CC already has session rand stored for this TX
    # FAIL
    start_sign(base64.b64decode(empty_psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    with pytest.raises(Exception) as err:
        end_sign()
    assert err.value.args[0] == "Coldcard Error: Signing failed late"
    time.sleep(.1)
    title, story = cap_story()
    assert "resign" in story

    po = BasicPSBT().parse(res_psbt)
    # we added nonce for all the leafs we're part of
    assert len(po.inputs[0].musig_pubnonces) == 3
    # no signature was added
    assert len(po.inputs[0].musig_part_sigs) == 0
    my_nonce_psbt = po.as_b64_str()

    # provide same PSBT to coldcard - one where it already provided pubnonces
    # this causes - session rand to be dropped from cache, so even if this works
    # subsequent signature providing will fail
    start_sign(base64.b64decode(my_nonce_psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    with pytest.raises(Exception) as err:
        end_sign()
    assert err.value.args[0] == "Coldcard Error: Signing failed late"
    time.sleep(.1)
    title, story = cap_story()
    assert "musig needs restart" in story
    press_cancel()

def test_resign_musig_psbt_sig(use_regtest, clear_miniscript, build_musig_wallet, start_sign,
                                 cap_story, end_sign, press_cancel):

    use_regtest()
    clear_miniscript()
    name = "musig_resign_sig"
    wo, signers, desc = build_musig_wallet(name, 3, tapscript=True,
                                           tapscript_musig_threshold=2)

    psbt_resp = wo.walletcreatefundedpsbt([], [{wo.getnewaddress("", "bech32m"): 3}], 0,
                                          {"fee_rate": 3, "change_type": "bech32m"})
    # nothing added yet
    empty_psbt = psbt_resp.get("psbt")

    # add our nonces
    start_sign(base64.b64decode(empty_psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    po = BasicPSBT().parse(res_psbt)
    # nothing was added - still just 3 nonce from first run
    assert len(po.inputs[0].musig_pubnonces) == 3
    # still no signature was added
    assert len(po.inputs[0].musig_part_sigs) == 0

    # cosigners adding nonces
    full_nonce_psbt = po.as_b64_str()
    for s in signers:
        psbt_resp = s.walletprocesspsbt(full_nonce_psbt, True, "DEFAULT", True, False)
        full_nonce_psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(full_nonce_psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()
    po = BasicPSBT().parse(res_psbt)
    # all nonces added at this point
    assert len(po.inputs[0].musig_pubnonces) == 9
    # coldcard also added partial signatures - as all pubnonces were already available
    assert len(po.inputs[0].musig_part_sigs) == 3

    # resign PSBT that we have already signed
    start_sign(base64.b64decode(po.as_b64_str()))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    # nothing changed
    po = BasicPSBT().parse(res_psbt)
    assert len(po.inputs[0].musig_pubnonces) == 9
    assert len(po.inputs[0].musig_part_sigs) == 3

    final_psbt = po.as_b64_str()
    for s in signers:
        psbt_resp = s.walletprocesspsbt(final_psbt, True, "DEFAULT", True, False)  # do not finalize
        final_psbt = psbt_resp.get("psbt")

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id


def test_identical_musig_fragments(use_regtest, bitcoin_core_signer, get_cc_key, clear_miniscript,
                                   offer_minsc_import, press_select, create_core_wallet, start_sign,
                                   end_sign, cap_story, bitcoind):
    # three identical musig in descriptor - one in internal key, other two in tapscript leaves
    # CC provides signature for internal key & one ONLY one tapleaf as tapleafs are completely same (even sighash is the same)
    use_regtest()

    core_pubkeys = []
    core_privkeys = []
    signers = []
    for i in range(2):
        # core signers
        signer, core_pk, core_sk = bitcoin_core_signer(f"musig-co-signer{i}", privkey=True)
        signer.keypoolrefill(25)
        core_pubkeys.append(core_pk.replace("/0/*", ""))
        core_privkeys.append(core_sk.replace("/0/*", ""))
        signers.append(signer)

    cc_key = get_cc_key("86h/1h/0h").replace("/<0;1>/*", "")
    msig = "musig(%s)" % ",".join([cc_key] + core_pubkeys)
    desc = f"tr({msig}/<0;1>/*,{{pk({msig}/<0;1>/*),pk({msig}/<0;1>/*)}})"

    clear_miniscript()
    name = "ident_musig"
    _, story = offer_minsc_import(json.dumps(dict(name=name, desc=desc)))
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(name, "bech32m", funded=True)

    desc_lst = []
    for obj in wo.listdescriptors()["descriptors"]:
        del obj["next"]
        del obj["next_index"]
        desc_lst.append(obj)

    # import musig descriptor to signers
    # each signer has it's own privkey loaded
    for s, spk, ssk in zip(signers, core_pubkeys, core_privkeys):
        to_import = copy.deepcopy(desc_lst)
        for dobj in to_import:
            dobj["desc"] = dobj["desc"].split("#")[0].replace(spk, ssk)
            csum = wo.getdescriptorinfo(dobj["desc"])["checksum"]
            dobj["desc"] = dobj["desc"] + "#" + csum

        res = s.importdescriptors(to_import)
        for o in res:
            assert o["success"]

    psbt_resp = wo.walletcreatefundedpsbt([], [{wo.getnewaddress("", "bech32m"): 5}], 0,
                                          {"fee_rate": 2, "change_type": "bech32m"})
    # nothing added yet
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    po = BasicPSBT().parse(res_psbt)
    assert len(po.inputs[0].musig_pubnonces) == 2
    assert len(po.inputs[0].musig_part_sigs) == 0

    full_nonce_psbt = po.as_b64_str()
    for s in signers:
        psbt_resp = s.walletprocesspsbt(full_nonce_psbt, True, "DEFAULT", True, False)
        full_nonce_psbt = psbt_resp.get("psbt")

    po = BasicPSBT().parse(base64.b64decode(full_nonce_psbt))
    assert len(po.inputs[0].musig_pubnonces) == 6
    assert len(po.inputs[0].musig_part_sigs) == 0

    start_sign(po.as_bytes())
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    po = BasicPSBT().parse(res_psbt)
    assert len(po.inputs[0].musig_pubnonces) == 6
    assert len(po.inputs[0].musig_part_sigs) == 2

    final_psbt = po.as_b64_str()
    for s in signers:
        psbt_resp = s.walletprocesspsbt(final_psbt, True, "DEFAULT", True, False)
        final_psbt = psbt_resp.get("psbt")

    po = BasicPSBT().parse(base64.b64decode(final_psbt))
    assert len(po.inputs[0].musig_pubnonces) == 6
    assert len(po.inputs[0].musig_part_sigs) == 6

    res = wo.finalizepsbt(po.as_b64_str())
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id


def test_identical_musig_subder(use_regtest, bitcoin_core_signer, get_cc_key, clear_miniscript,
                                offer_minsc_import, press_select, create_core_wallet,
                                musig_signing, address_explorer_check):
    # TODO bitcoin-core bitching that this descriptor is not sane because it contains duplicate public keys
    # needs https://github.com/bitcoin/bitcoin/pull/34697 (or something less buggy)
    # identical musig in one tapleaf, but musig subderivation differs, i.e. different key
    raise pytest.skip("needs updated bitcoind")
    use_regtest()

    core_pubkeys = []
    core_privkeys = []
    signers = []
    for i in range(2):
        # core signers
        signer, core_pk, core_sk = bitcoin_core_signer(f"musig-co-signer{i}", privkey=True)
        signer.keypoolrefill(25)
        core_pubkeys.append(core_pk.replace("/0/*", ""))
        core_privkeys.append(core_sk.replace("/0/*", ""))
        signers.append(signer)

    cc_key = get_cc_key("86h/1h/0h").replace("/<0;1>/*", "")
    msig = "musig(%s)" % ",".join([cc_key] + core_pubkeys)
    desc = f"tr({ranged_unspendable_internal_key()},and_v(v:pk({msig}/<0;1>/*),pk({msig}/<2;3>/*)))"

    clear_miniscript()
    name = "ident_musig_subder"
    _, story = offer_minsc_import(json.dumps(dict(name=name, desc=desc)))
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(name, "bech32m", funded=True)

    desc_lst = []
    for obj in wo.listdescriptors()["descriptors"]:
        del obj["next"]
        del obj["next_index"]
        desc_lst.append(obj)

    # import musig descriptor to signers
    # each signer has it's own privkey loaded
    for s, spk, ssk in zip(signers, core_pubkeys, core_privkeys):
        to_import = copy.deepcopy(desc_lst)
        for dobj in to_import:
            dobj["desc"] = dobj["desc"].split("#")[0].replace(spk, ssk)
            csum = wo.getdescriptorinfo(dobj["desc"])["checksum"]
            dobj["desc"] = dobj["desc"] + "#" + csum

        res = s.importdescriptors(to_import)
        for o in res:
            assert o["success"]


    musig_signing(name, wo, signers, True, 0, 3, finalized=False,
                  split_to=2)

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


def test_multiple_musig_sessions_simple(use_regtest, clear_miniscript, build_musig_wallet,
                                        start_sign, end_sign, cap_story, garbage_collector,
                                        goto_home, microsd_path, pick_menu_item, press_select):
    use_regtest()
    clear_miniscript()
    # below wallets have identical structure, but the keys differ
    # testing our session cache logic
    wo0, signers0, desc0 = build_musig_wallet("wal0", 4, tapscript=True,
                                              tapscript_musig_threshold=3)

    wo1, signers1, desc1 = build_musig_wallet("wal1", 4, tapscript=True,
                                              tapscript_musig_threshold=3)

    wo2, signers2, desc2 = build_musig_wallet("wal2", 4, tapscript=True,
                                              tapscript_musig_threshold=3)

    psbts = []  # ordered 0,1,2
    for wal in [wo0, wo1, wo2]:
        psbt_resp = wal.walletcreatefundedpsbt([], [{wal.getnewaddress("", "bech32m"): 5}], 0,
                                              {"fee_rate": 2, "change_type": "bech32m"})
        psbts.append(psbt_resp.get("psbt"))

    # initialize musig sessions for all three PSBTs
    for i in range(3):
        start_sign(base64.b64decode(psbts[i]))
        title, story = cap_story()
        assert "Consolidating" in story
        assert f"Wallet: wal{i}" in story
        res_psbt = end_sign()

        po = BasicPSBT().parse(res_psbt)
        assert len(po.inputs[0].musig_pubnonces) == 4  # internal key + 3 leafs out of 4
        assert len(po.inputs[0].musig_part_sigs) == 0

        psbts[i] = po.as_b64_str()  # replace with updated PSBT


    # add pubnonce from co-signers
    for i, signers in enumerate([signers0, signers1, signers2]):
        the_psbt = psbts[i]
        for s in signers:
            psbt_resp = s.walletprocesspsbt(the_psbt, True, "DEFAULT", True, False)  # do not finalize
            the_psbt = psbt_resp.get("psbt")

        psbts[i] = the_psbt  # update

    for psbt in psbts:
        po = BasicPSBT().parse(base64.b64decode(psbt))
        assert len(po.inputs[0].musig_pubnonces) == (4*4)  # each cosigner added 4 nonces (internal key + 3 leafs)
        assert len(po.inputs[0].musig_part_sigs) == 0

    # add signatures from co-signers
    for i, signers in enumerate([signers0, signers1, signers2]):
        the_psbt = psbts[i]
        for s in signers:
            psbt_resp = s.walletprocesspsbt(the_psbt, True, "DEFAULT", True, False)  # do not finalize
            the_psbt = psbt_resp.get("psbt")

        psbts[i] = the_psbt  # update

    for i in range(2,-1,-1):  # reverse order
        fname = f"{i}.psbt"
        fpath = microsd_path(fname)
        with open(fpath, "w") as f:
            f.write(psbts[i])

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
        assert "Change back:" in story
        press_select()  # confirm signing
        time.sleep(0.5)
        title, story = cap_story()
        assert "PSBT Signed" == title
        assert "Updated PSBT is:" in story
        press_select()
        split_story = story.split("\n\n")
        fname_psbt = split_story[1]

        fpath_psbt = microsd_path(fname_psbt)
        with open(fpath_psbt, "r") as f:
            res_psbt = f.read().strip()
        garbage_collector.append(fpath_psbt)

        # finalize txn will be provided as internal key signing is done
        fname_txn = split_story[3]
        cc_txid = split_story[4].split("\n")[-1]
        fpath_txn = microsd_path(fname_txn)
        with open(fpath_txn, "r") as f:
            final_txn = f.read().strip()
        garbage_collector.append(fpath_txn)

        # does not matter which wallet is used for finalization
        res = wo0.finalizepsbt(res_psbt)
        assert res["complete"]
        tx_hex = res["hex"]
        assert tx_hex == final_txn
        res = wo0.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
        res = wo0.sendrawtransaction(tx_hex)
        assert len(res) == 64  # tx id
        assert res == cc_txid


def test_multiple_musig_sessions_identical_leave(use_regtest, clear_miniscript, build_musig_wallet,
                                                 start_sign, end_sign, cap_story, garbage_collector,
                                                 create_core_wallet, press_select, offer_minsc_import):
    use_regtest()
    clear_miniscript()
    # below wallets have identical structure, but the keys differ
    wo, signers, desc = build_musig_wallet("ww", 3, tapscript=True,
                                           tapscript_musig_threshold=2, musig_subder="/<0;1>/*")

    # replace musig internal key with unspendable
    ik = ranged_unspendable_internal_key()
    new_start = f"tr({ik}"
    end_idx = desc.find("*")
    desc = new_start + desc[end_idx+1:]

    wal_name = "qqq"
    _, story = offer_minsc_import(json.dumps(dict(name=wal_name, desc=desc)))
    assert "Create new miniscript wallet?" in story
    assert wal_name in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo0 = create_core_wallet(wal_name, "bech32m", "sd", True)

    psbts = []
    for wal in [wo, wo0]:
        psbt_resp = wal.walletcreatefundedpsbt([], [{wal.getnewaddress("", "bech32m"): 1.256}], 0,
                                               {"fee_rate": 2, "change_type": "bech32m"})
        psbts.append(psbt_resp.get("psbt"))

    for i in range(2):
        start_sign(base64.b64decode(psbts[i]))
        title, story = cap_story()
        assert "Consolidating" in story
        res_psbt = end_sign()

        po = BasicPSBT().parse(res_psbt)
        psbts[i] = po.as_b64_str()  # replace with updated PSBT

    # add pubnonces from co-signers
    for i in range(2):
        the_psbt = psbts[i]
        for s in signers:
            psbt_resp = s.walletprocesspsbt(the_psbt, True, "DEFAULT", True, False)  # do not finalize
            the_psbt = psbt_resp.get("psbt")

        psbts[i] = the_psbt  # update

    # add signatures from co-signers
    for i in range(2):
        the_psbt = psbts[i]
        for s in signers:
            psbt_resp = s.walletprocesspsbt(the_psbt, True, "DEFAULT", True, False)  # do not finalize
            the_psbt = psbt_resp.get("psbt")

        psbts[i] = the_psbt  # update

    # finalize on CC
    for i in range(2):
        start_sign(base64.b64decode(psbts[i]))
        title, story = cap_story()
        assert "Consolidating" in story
        res_psbt = end_sign()

        res = wo0.finalizepsbt(base64.b64encode(res_psbt).decode())
        assert res["complete"]
        tx_hex = res["hex"]
        res = wo0.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
        res = wo0.sendrawtransaction(tx_hex)
        assert len(res) == 64  # tx id


@pytest.mark.parametrize("tapscript", [
    False,
    "tr($H,{and_v(v:pk(musig($0,$2)/0/*),after(120)),and_v(v:pk(musig($1,$2)/0/*),after(120))})",
])
@pytest.mark.parametrize("cc_first", [True, False])
@pytest.mark.parametrize("sighash", ["NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"])
def test_exotic_sighash_musig(tapscript, clear_miniscript, use_regtest, address_explorer_check,
                              build_musig_wallet, start_sign, end_sign, cc_first, sighash,
                              cap_story, bitcoind, settings_set):

    num_signers = 3
    locktime = 120
    use_regtest()
    clear_miniscript()
    settings_set("sighshchk", 1)  # disable checks

    name = "sighash_musig"
    wo, signers, desc = build_musig_wallet(name, num_signers, tapscript=tapscript)

    if tapscript:
        _from, _to = 1, 2
    else:
        _from, _to = 0, num_signers

    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1

    # split to
    # use sighash ALL for consolidation
    nVal = all_of_it / 4
    conso_addrs = [{wo.getnewaddress("", "bech32m"): nVal} for _ in range(4)]  # self-spend
    psbt_resp = wo.walletcreatefundedpsbt(
        [],
        conso_addrs,
        120 if tapscript else 0,
        {"fee_rate": 2, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    if not cc_first:
        # cosigners adding nonces
        for s in signers:
            psbt_resp = s.walletprocesspsbt(psbt, True, "ALL", True, False)
            psbt = psbt_resp.get("psbt")

    else:
        # CC is going first, tweak sighash to ALL (only one working besides DEFAULT for conso tx)
        po = BasicPSBT().parse(base64.b64decode(psbt))
        for inp in po.inputs:
            inp.sighash = SIGHASH_MAP["ALL"]

        psbt = po.as_b64_str()

    # CC add nonce
    start_sign(base64.b64decode(psbt))
    title, story = cap_story()
    assert "warning" not in story
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    sighash_check(res_psbt, "ALL")

    b64_res_psbt = base64.b64encode(res_psbt).decode()

    if cc_first:
        # if cc was first to add pubnonce - now core cosigners will add
        for s in signers:
            psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "ALL", True, False)
            b64_res_psbt = psbt_resp.get("psbt")

    # cosigners adding signatures - seems core is unable to add both nonce and signature in one iteration
    for s in signers[_from: _to]:
        psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "ALL", True, False)
        b64_res_psbt = psbt_resp.get("psbt")

    # CC add sig
    start_sign(base64.b64decode(b64_res_psbt))
    title, story = cap_story()
    assert "warning" not in story
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()
    sighash_check(res_psbt, "ALL")
    b64_res_psbt = base64.b64encode(res_psbt).decode()

    res = wo.finalizepsbt(b64_res_psbt)
    assert res["complete"]
    tx_hex = res["hex"]

    if tapscript:
        # we are signing for timelocked tapscript
        res = wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"] is False
        assert res[0]['reject-reason'] == "non-final"
        block_h = wo.getblockchaininfo()["blocks"]
        bitcoind.supply_wallet.generatetoaddress(locktime - block_h, bitcoind.supply_wallet.getnewaddress())

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    #
    # now consolidate multiple inputs to send out
    # we can check all sighash flags here as this is not pure consolidation
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above
    unspent = wo.listunspent()
    assert len(unspent) == 4

    psbt_resp = wo.walletcreatefundedpsbt(
        [],
        [
            {bitcoind.supply_wallet.getnewaddress(): 2},
            {bitcoind.supply_wallet.getnewaddress(): 2},
            {bitcoind.supply_wallet.getnewaddress(): 2},
            {bitcoind.supply_wallet.getnewaddress(): 2},
        ],
        locktime if tapscript else 0,
        {"fee_rate": 2, "change_type": "bech32m"},
    )
    psbt1 = psbt_resp.get("psbt")

    if not cc_first:
        # cosigners adding nonces
        for s in signers:
            psbt_resp = s.walletprocesspsbt(psbt1, True, sighash, True, False)
            psbt1 = psbt_resp.get("psbt")

    else:
        # CC is going first, tweak sighash
        po = BasicPSBT().parse(base64.b64decode(psbt1))
        for inp in po.inputs:
            inp.sighash = SIGHASH_MAP[sighash]

        psbt1 = po.as_b64_str()

    # CC adds nonce only
    start_sign(base64.b64decode(psbt1))
    title, story = cap_story()
    assert "Consolidating" not in story
    assert "Change back:" in story  # has one change address
    assert "warning" in story
    assert "sighash" in story
    if sighash == "NONE":
        assert sighash in story
    else:
        assert "Some inputs have unusual SIGHASH values"
    assert f"Wallet: {name}" in story
    res_psbt1 = end_sign()
    sighash_check(res_psbt1, sighash)
    b64_res_psbt1 = base64.b64encode(res_psbt1).decode()

    if cc_first:
        # if cc was first to add pubnonce - now core cosigners will add
        for s in signers:
            psbt_resp = s.walletprocesspsbt(b64_res_psbt1, True, sighash, True, False)
            b64_res_psbt1 = psbt_resp.get("psbt")

    # cosigners adding signatures
    for s in signers[_from: _to]:
        psbt_resp = s.walletprocesspsbt(b64_res_psbt1, True, sighash, True, False)
        b64_res_psbt1 = psbt_resp.get("psbt")

    # CC adds sig
    start_sign(base64.b64decode(b64_res_psbt1))
    title, story = cap_story()
    assert "warning" in story
    assert "sighash" in story
    if sighash == "NONE":
        assert sighash in story
    else:
        assert "Some inputs have unusual SIGHASH values"
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()
    sighash_check(res_psbt, sighash)
    b64_res_psbt1 = base64.b64encode(res_psbt).decode()

    res1 = wo.finalizepsbt(b64_res_psbt1)
    assert res1["complete"]
    tx_hex1 = res1["hex"]
    res = wo.testmempoolaccept([tx_hex1])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex1)
    assert len(res) == 64  # tx id

    # now try forbidden consolidation tx with exotic sighash - must fail
    settings_set("sighshchk", 0)  # enable checks
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above
    al_of_it = wo.getbalance()
    psbt_resp = wo.walletcreatefundedpsbt(
        [],
        [{wo.getnewaddress("", "bech32m"): al_of_it}],
        120 if tapscript else 0,
        {"fee_rate": 2, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    po = BasicPSBT().parse(base64.b64decode(psbt))
    for inp in po.inputs:
        inp.sighash = SIGHASH_MAP[sighash]

    psbt = po.as_bytes()
    start_sign(psbt)
    title, story = cap_story()
    assert "Failure" == title
    assert "Only sighash ALL/DEFAULT is allowed for pure consolidation transactions." in story


def test_duplicate_musig_in_tapleaf(get_cc_key, offer_minsc_import):
    path = "99h/1h/0h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)

    # duplicate musig in tapscript leaf
    musig = f"musig({cc_key},{keys[0]},{keys[1]})"
    desc = f"tr({ranged_unspendable_internal_key()},and_v(v:pk({musig}),pk({musig})))"
    with pytest.raises(Exception) as e:
        offer_minsc_import(desc)
    assert e.value.args[0] == "Coldcard Error: Insane"


def test_unspendable_key_in_musig(get_cc_key, offer_minsc_import):
    path = "199h/1h/3h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)
    unspend = ranged_unspendable_internal_key(subderiv="")

    # duplicate musig in tapscript leaf
    musig = f"musig({cc_key},{keys[0]},{unspend})"
    data = [
        f"tr({musig})",
        f"tr({keys[1]},pk({musig}))",
    ]
    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: unspendable key inside musig"


def test_musig_outside_taproot_context(get_cc_key, offer_minsc_import):
    # musig only allowed in taproot - whether internal key or tapscript
    path = "1001h/1h/99h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)

    inner = f"musig({cc_key},{keys[0]},{keys[1]}"
    data = [
        f"wsh(pk({inner}))",
        f"sh(wsh(pk({inner})))",
        f"sh(pk({inner}))",
    ]

    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: musig in non-taproot context"


def test_nested_musig(get_cc_key, offer_minsc_import):
    # musig key expression nested in another key expression is not allowed
    path = "99h/1h/0h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)

    data = [
        f"tr(musig({cc_key},{keys[0]},musig({cc_key},{keys[0]},{keys[1]})))",
        f"tr({cc_key},pk(musig({cc_key},{keys[0]},musig({cc_key},{keys[0]},{keys[1]}))))",
    ]

    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: nested musig not allowed"


def test_key_derivation_not_allowed_inside_musig(get_cc_key, offer_minsc_import):
    # only whole musig key expression can have key derivation, not single keys
    path = "86h/1h/3h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)

    data = [
        f"tr(musig({cc_key}/<0;1>/*,{keys[0]},{keys[1]}))", # internal key
        f"tr({cc_key},pk(musig({cc_key}/<0;1>/*,{keys[0]}/<0;1>/*,{keys[1]}/<0;1>/*)))", # nested musig in tapscript
    ]

    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: key derivation not allowed inside musig"


def test_hardened_musig_derivation(get_cc_key, offer_minsc_import):
    # only whole musig key expression can have key derivation, not single keys
    path = "88h/0h/0h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(2, path=path)

    data = [
        f"tr(musig({cc_key},{keys[0]},{keys[1]})/1h/*)",
        f"tr({cc_key},pk(musig({cc_key},{keys[0]},{keys[0]})/3h/*))",
    ]

    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: Cannot use hardened sub derivation path"


def test_only_unique_keys_in_musig(get_cc_key, offer_minsc_import):
    path = "88h/0h/0h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(1, path=path)

    data = [
        f"tr(musig({cc_key},{keys[0]},{keys[0]}))", # internal key non-unique foreign keys
        f"tr(musig({cc_key},{cc_key},{keys[0]}))", # internal key non-unique own keys
        f"tr({cc_key},pk(musig({cc_key},{keys[0]},{keys[0]})))", # tapscript key non-unique foreign keys
        f"tr({cc_key},pk(musig({cc_key},{cc_key},{keys[0]})))", # tapscript key non-unique own keys
    ]

    for desc in data:
        with pytest.raises(Exception) as e:
            offer_minsc_import(desc)
        assert e.value.args[0] == "Coldcard Error: musig keys not unique"


@pytest.mark.bitcoind
def test_tmp_seed_cosign(bitcoind, settings_set, end_sign, start_sign, restore_main_seed, use_regtest,
                         cap_story, goto_eph_seed_menu, pick_menu_item, word_menu_entry,
                         confirm_tmp_seed, usb_miniscript_get, offer_minsc_import, press_select,
                         clear_miniscript, get_cc_key, create_core_wallet):

    # proves that we can hold secnonce for multiple seed types on one device (even for same txn where respective keys are co-signers)
    b_words = "sight will strike aspect nerve saddle young special dragon fence chest tattoo"

    use_regtest()
    clear_miniscript()

    name = "tmp_musig_cosign"
    der_pth = "86h/1h/0h"

    # it is string mnemonic
    b39_seed = Mnemonic.to_seed(b_words)
    b_node = BIP32Node.from_master_secret(b39_seed)
    b_xfp = b_node.fingerprint().hex()
    b_key = b_node.subkey_for_path(der_pth).hwif()
    b_key_exp = f"[{b_xfp}/{der_pth}]{b_key}"

    # C is just random key we won't use
    c_node = BIP32Node.from_master_secret(os.urandom(32))
    c_xfp = c_node.fingerprint().hex()
    c_key = c_node.subkey_for_path(der_pth).hwif()
    c_key_exp = f"[{c_xfp}/{der_pth}]{c_key}"

    cc_key = get_cc_key("86h/1h/0h").replace("/<0;1>/*", "")

    inner = "musig(%s)" % ",".join([cc_key, b_key_exp, c_key_exp])

    s0 = f"pk(musig({cc_key},{b_key_exp}))"
    s1 = f"pk(musig({cc_key},{c_key_exp}))"
    s2 = f"pk(musig({c_key_exp},{b_key_exp}))"


    inner += ","
    inner += "{%s,{%s,%s}}" % (s0,s1,s2)
    desc = f"tr({inner})"

    title, story = offer_minsc_import(json.dumps(dict(name=name, desc=desc)))
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    bitcoind_wo = create_core_wallet(name, "bech32m", "sd", True)

    psbt = bitcoind_wo.walletcreatefundedpsbt(
        [], [{bitcoind.supply_wallet.getnewaddress(): 0.2},
             {bitcoind.supply_wallet.getnewaddress(): 0.255}],
        0, {"fee_rate": 20, "change_type": "bech32m"}
    )['psbt']

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title

    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)
    assert not po.inputs[0].musig_part_sigs
    assert po.inputs[0].musig_pubnonces

    goto_eph_seed_menu()
    pick_menu_item("Import Words")
    pick_menu_item("12 Words")
    time.sleep(0.1)
    word_menu_entry(b_words.split())
    confirm_tmp_seed(seedvault=False)
    title, story = offer_minsc_import(desc)
    assert "Create new miniscript wallet?" in story
    press_select()

    start_sign(signed)
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title
    assert "warning" not in story
    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)
    # now we should have all pubnonces that we need
    assert len(po.inputs[0].musig_part_sigs) == 0
    assert po.inputs[0].musig_pubnonces

    # 2nd round - get signature
    start_sign(signed)
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title
    assert "warning" not in story
    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)
    # now we should have signature one signature
    assert len(po.inputs[0].musig_part_sigs) == 1

    try:
        # this is run with --eff so number of settings may be incorrect - no prob
        restore_main_seed()
    except: pass

    start_sign(signed)
    time.sleep(.1)
    title, story = cap_story()
    assert 'OK TO SEND?' == title

    signed = end_sign(accept=True)
    po = BasicPSBT().parse(signed)
    assert len(po.inputs[0].musig_part_sigs) == 2
    assert po.inputs[0].musig_pubnonces
    # 1 aggregate sig for aggregated musig leaf
    assert len(po.inputs[0].taproot_script_sigs) == 1

    res = bitcoind_wo.finalizepsbt(base64.b64encode(signed).decode())
    assert res["complete"]
    tx_hex = res["hex"]
    res = bitcoind_wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

# EOF