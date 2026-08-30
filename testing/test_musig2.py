# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# MuSig2 tests.
#
import pytest, base64, itertools, time, json, copy, random, struct
from txn import BasicPSBT
from constants import SIGHASH_MAP
from bip32 import random_keys, ranged_unspendable_internal_key, BIP32Node
from helpers import generate_binary_tree_template
from mnemonic import Mnemonic
from psbt import (PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, PSBT_IN_MUSIG2_PUB_NONCE,
                  PSBT_IN_MUSIG2_PARTIAL_SIG, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS)


def sighash_check(psbt, sighash):
    po = BasicPSBT().parse(psbt)
    for inp in po.inputs:
        if sighash != "DEFAULT":
            assert inp.sighash == SIGHASH_MAP[sighash]
        else:
            assert inp.sighash is None


@pytest.fixture
def reset_musig_session_cache(sim_exec):
    sim_exec("import psbt; psbt.MUSIG_SESSION_CACHE.clear()")
    yield
    sim_exec("import psbt; psbt.MUSIG_SESSION_CACHE.clear()")


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

        return res_psbt

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


@pytest.mark.veryslow
@pytest.mark.bitcoind
@pytest.mark.parametrize("N_K", [(5,3),(6,4), (32,31)])
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


@pytest.mark.bitcoind
def test_musig_incomplete_rounds(use_regtest, clear_miniscript, build_musig_wallet,
                                  start_sign, end_sign, reset_musig_session_cache):
    use_regtest()
    clear_miniscript()
    wo, signers, _ = build_musig_wallet("musig_incomplete", 3)
    empty_psbt = wo.walletcreatefundedpsbt(
        [], [{wo.getnewaddress("", "bech32m"): 5}], 0,
        {"fee_rate": 2, "change_type": "bech32m"})["psbt"]

    # One participant nonce is missing: do not produce our partial signature.
    start_sign(base64.b64decode(empty_psbt))
    cc_nonce_psbt = BasicPSBT().parse(end_sign()).as_b64_str()
    one_cosigner_nonce = signers[0].walletprocesspsbt(
        cc_nonce_psbt, True, "DEFAULT", True, False)["psbt"]
    start_sign(base64.b64decode(one_cosigner_nonce))
    po = BasicPSBT().parse(end_sign())
    assert len(po.inputs[0].musig_pubnonces) == 2
    assert not po.inputs[0].musig_part_sigs
    assert po.inputs[0].taproot_key_sig is None

    # Supplying the withheld nonce must resume the same signing round.
    full_nonce_psbt = signers[1].walletprocesspsbt(
        po.as_b64_str(), True, "DEFAULT", True, False)["psbt"]
    start_sign(base64.b64decode(full_nonce_psbt))
    po = BasicPSBT().parse(end_sign())
    assert len(po.inputs[0].musig_pubnonces) == 3
    assert len(po.inputs[0].musig_part_sigs) == 1
    assert po.inputs[0].taproot_key_sig is None
    assert not wo.finalizepsbt(po.as_b64_str())["complete"]

    # With one participant partial missing, an aggregate signature still
    # must not appear.
    one_cosigner_partial = signers[0].walletprocesspsbt(
        po.as_b64_str(), True, "DEFAULT", True, False)["psbt"]
    start_sign(base64.b64decode(one_cosigner_partial))
    po = BasicPSBT().parse(end_sign())
    assert len(po.inputs[0].musig_part_sigs) == 2
    assert po.inputs[0].taproot_key_sig is None
    assert not wo.finalizepsbt(po.as_b64_str())["complete"]


@pytest.mark.bitcoind
def test_musig_metadata_scoping(use_regtest, clear_miniscript, build_musig_wallet,
                                start_sign, end_sign, reset_musig_session_cache):
    use_regtest()
    clear_miniscript()
    wo, signers, _ = build_musig_wallet("musig_scoping", 3)
    empty_psbt = wo.walletcreatefundedpsbt(
        [], [{wo.getnewaddress("", "bech32m"): 5}], 0,
        {"fee_rate": 2, "change_type": "bech32m"})["psbt"]
    invalid_pubkey = b"\x04" + b"\x11" * 32

    # Foreign participant, aggregate and leaf contexts cannot fill the nonce set.
    start_sign(base64.b64decode(empty_psbt))
    po = BasicPSBT().parse(end_sign())
    own_key, own_nonce = next(iter(po.inputs[0].musig_pubnonces.items()))
    _, participants = next(iter(po.inputs[0].musig_pubkeys.items()))
    others = [pk for pk in participants if pk != own_key[0]]
    assert len(others) == 2
    foreign_keys = [
        (invalid_pubkey, own_key[1], b""),
        (others[0], invalid_pubkey, b""),
        (others[1], own_key[1], b"\x22" * 32),
    ]
    po.inputs[0].musig_pubkeys[invalid_pubkey] = [invalid_pubkey]
    next(o for o in po.outputs if o.musig_pubkeys).musig_pubkeys[invalid_pubkey] = [invalid_pubkey]
    po.inputs[0].musig_pubnonces.update((key, own_nonce) for key in foreign_keys)
    start_sign(po.as_bytes())
    po = BasicPSBT().parse(end_sign())
    matching = {k: v for k, v in po.inputs[0].musig_pubnonces.items()
                if k[0] in participants and k[1:] == own_key[1:]}
    assert len(matching) == 1
    assert not po.inputs[0].musig_part_sigs
    assert po.inputs[0].taproot_key_sig is None

    # The same context checks apply to partial signatures.
    start_sign(base64.b64decode(empty_psbt))
    full_nonce_psbt = BasicPSBT().parse(end_sign()).as_b64_str()
    for signer in signers:
        full_nonce_psbt = signer.walletprocesspsbt(
            full_nonce_psbt, True, "DEFAULT", True, False)["psbt"]
    po = BasicPSBT().parse(base64.b64decode(full_nonce_psbt))
    own_key = next(k for k in po.inputs[0].musig_pubnonces if k[0] not in others)
    po.inputs[0].musig_part_sigs.update(
        (key, bytes([num]) * 32) for num, key in enumerate(foreign_keys, 1))
    start_sign(po.as_bytes())
    po = BasicPSBT().parse(end_sign())
    matching = {k: v for k, v in po.inputs[0].musig_part_sigs.items()
                if k[0] in participants and k[1:] == own_key[1:]}
    assert len(matching) == 1
    assert po.inputs[0].taproot_key_sig is None


@pytest.mark.bitcoind
def test_musig_nonce_fresh_after_restart(use_regtest, clear_miniscript, build_musig_wallet,
                                         start_sign, end_sign, cap_story, press_cancel,
                                         sim_exec, reset_musig_session_cache):
    use_regtest()
    clear_miniscript()
    wo, _, _ = build_musig_wallet("musig_fresh_nonce", 2)
    empty_psbt = wo.walletcreatefundedpsbt(
        [], [{wo.getnewaddress("", "bech32m"): 5}], 0,
        {"fee_rate": 2, "change_type": "bech32m"})["psbt"]

    start_sign(base64.b64decode(empty_psbt))
    first = BasicPSBT().parse(end_sign())
    sim_exec("import psbt; psbt.MUSIG_SESSION_CACHE.clear()")
    start_sign(base64.b64decode(empty_psbt))
    second = BasicPSBT().parse(end_sign())
    assert first.inputs[0].musig_pubnonces.keys() == second.inputs[0].musig_pubnonces.keys()
    assert first.inputs[0].musig_pubnonces != second.inputs[0].musig_pubnonces

    # The cache belongs to the second nonce. Substituting another valid nonce
    # from a fresh session must fail before any partial signature is returned.
    second.inputs[0].musig_pubnonces = first.inputs[0].musig_pubnonces.copy()
    start_sign(second.as_bytes())
    with pytest.raises(Exception):
        end_sign()
    time.sleep(.1)
    title, _ = cap_story()
    assert title == "Failure"
    press_cancel()


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
    # identical musig in one tapleaf, but musig subderivation differs, i.e. different key
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

    res_psbt = musig_signing(name, wo, signers, True, 0, 3, finalized=False,
                             split_to=2)

    pubnonces = BasicPSBT().parse(res_psbt).inputs[0].musig_pubnonces
    assert len(pubnonces) == 2
    assert len(set(pubnonces.values())) == 2

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


def test_musig_participant_limit(get_cc_key, offer_minsc_import):
    path = "88h/0h/0h"
    cc_key = get_cc_key(path).replace("/<0;1>/*", "")
    keys = random_keys(32, path=path)
    desc = "tr(musig(%s))" % ",".join([cc_key] + keys)

    with pytest.raises(Exception) as e:
        offer_minsc_import(desc)
    assert e.value.args[0] == "Coldcard Error: too many musig keys"


@pytest.mark.bitcoind
def test_musig_psbt_participant_limit(use_regtest, clear_miniscript, build_musig_wallet,
                                       start_sign, cap_story, press_cancel):
    use_regtest()
    clear_miniscript()
    wo, _, _ = build_musig_wallet("musig_limit", 2)
    resp = wo.walletcreatefundedpsbt([], [{wo.getnewaddress("", "bech32m"): 5}], 0,
                                     {"fee_rate": 2, "change_type": "bech32m"})
    raw = base64.b64decode(resp["psbt"])
    for section in ("input", "output"):
        po = BasicPSBT().parse(raw)
        obj = po.inputs[0] if section == "input" else next(o for o in po.outputs if o.musig_pubkeys)
        participants = next(iter(obj.musig_pubkeys.values()))
        assert len(participants) == 2
        participants += [participants[0]] * 31

        start_sign(po.as_bytes())
        title, story = cap_story()
        assert title == "Failure", section
        assert "Invalid PSBT" in story, section
        assert "too many musig keys" in story, section
        press_cancel()


@pytest.mark.bitcoind
def test_musig_psbt_field_lengths(use_regtest, clear_miniscript, build_musig_wallet,
                                   start_sign, cap_story, press_cancel):
    use_regtest()
    clear_miniscript()
    wo, _, _ = build_musig_wallet("musig_field_lengths", 2)
    resp = wo.walletcreatefundedpsbt([], [{wo.getnewaddress("", "bech32m"): 5}], 0,
                                     {"fee_rate": 2, "change_type": "bech32m"})
    raw = base64.b64decode(resp["psbt"])
    pk = b"\x02" + b"\x33" * 32
    composite = pk * 2
    cases = [
        ("input participant key", "input", PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, pk[:-1], pk),
        ("input participant long key", "input", PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, pk + b"x", pk),
        ("input empty participants", "input", PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, pk, b""),
        ("input participant value", "input", PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, pk, pk[:-1]),
        ("output participant key", "output", PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, pk[:-1], pk),
        ("output participant long key", "output", PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, pk + b"x", pk),
        ("output empty participants", "output", PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, pk, b""),
        ("output participant value", "output", PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, pk, pk[:-1]),
        ("pubnonce key", "input", PSBT_IN_MUSIG2_PUB_NONCE, composite[:-1], b"\x44" * 66),
        ("pubnonce long key", "input", PSBT_IN_MUSIG2_PUB_NONCE, composite + b"x", b"\x44" * 66),
        ("pubnonce value", "input", PSBT_IN_MUSIG2_PUB_NONCE, composite, b"\x44" * 65),
        ("pubnonce long value", "input", PSBT_IN_MUSIG2_PUB_NONCE, composite, b"\x44" * 67),
        ("partial key", "input", PSBT_IN_MUSIG2_PARTIAL_SIG, composite[:-1], b"\x55" * 32),
        ("partial long key", "input", PSBT_IN_MUSIG2_PARTIAL_SIG, composite + b"x", b"\x55" * 32),
        ("partial value", "input", PSBT_IN_MUSIG2_PARTIAL_SIG, composite, b"\x55" * 31),
        ("partial long value", "input", PSBT_IN_MUSIG2_PARTIAL_SIG, composite, b"\x55" * 33),
    ]
    for label, section, field_type, key, value in cases:
        po = BasicPSBT().parse(raw)
        obj = po.inputs[0] if section == "input" else po.outputs[0]
        obj.unknown = [(bytes([field_type]) + key, value)]
        start_sign(po.as_bytes())
        title, story = cap_story()
        assert title == "Failure", label
        assert "Invalid PSBT" in story, label
        press_cancel()


@pytest.mark.bitcoind
def test_musig_untrusted_aggregate_metadata(use_regtest, clear_miniscript, build_musig_wallet,
                                             start_sign, end_sign, cap_story, press_cancel,
                                             sim_exec, reset_musig_session_cache):
    use_regtest()
    clear_miniscript()
    wo, _, _ = build_musig_wallet("musig_untrusted", 2)
    empty_psbt = wo.walletcreatefundedpsbt(
        [], [{wo.getnewaddress("", "bech32m"): 5}], 0,
        {"fee_rate": 2, "change_type": "bech32m"})["psbt"]
    raw = base64.b64decode(empty_psbt)

    # Learn which base participant is ours, then deliberately discard that session.
    start_sign(raw)
    nonce_psbt = BasicPSBT().parse(end_sign())
    own_pubkey = next(iter(nonce_psbt.inputs[0].musig_pubnonces))[0]
    sim_exec("import psbt; psbt.MUSIG_SESSION_CACHE.clear()")
    outsider = BIP32Node.from_master_secret(b"\x66" * 32).sec()
    invalid_pubkey = b"\x04" + b"\x77" * 32

    mutations = []
    for label, hardened in (("different aggregate path", False), ("hardened aggregate path", True)):
        po = BasicPSBT().parse(raw)
        inp = po.inputs[0]
        path = bytearray(inp.taproot_bip32_paths[inp.taproot_internal_key])
        index = struct.unpack("<I", path[-4:])[0]
        index = index | 0x80000000 if hardened else index ^ 1
        path[-4:] = struct.pack("<I", index)
        inp.taproot_bip32_paths[inp.taproot_internal_key] = bytes(path)
        mutations.append((label, po))

    po = BasicPSBT().parse(raw)
    inp = po.inputs[0]
    path = bytearray(inp.taproot_bip32_paths[inp.taproot_internal_key])
    path[1:5] = b"\xff" * 4
    inp.taproot_bip32_paths[inp.taproot_internal_key] = bytes(path)
    mutations.append(("foreign aggregate fingerprint", po))

    for label, replacement in (("different participant aggregation", outsider),
                               ("invalid participant pubkey", invalid_pubkey)):
        po = BasicPSBT().parse(raw)
        participants = next(iter(po.inputs[0].musig_pubkeys.values()))
        participants[next(i for i, pk in enumerate(participants) if pk != own_pubkey)] = replacement
        mutations.append((label, po))

    po = BasicPSBT().parse(raw)
    inp = po.inputs[0]
    derivation = inp.taproot_bip32_paths.pop(inp.taproot_internal_key)
    inp.taproot_bip32_paths[outsider[1:]] = derivation
    mutations.append(("derived aggregate key mismatch", po))

    for label, po in mutations:
        sim_exec("import psbt; psbt.MUSIG_SESSION_CACHE.clear()")
        start_sign(po.as_bytes())
        title, _ = cap_story()
        if title == "Failure":
            press_cancel()
            continue
        try:
            result = end_sign()
        except Exception:
            time.sleep(.1)
            title, _ = cap_story()
            assert title == "Failure", label
            press_cancel()
        else:
            inp = BasicPSBT().parse(result).inputs[0]
            assert not inp.musig_pubnonces, label
            assert not inp.musig_part_sigs, label
            assert inp.taproot_key_sig is None, label


@pytest.mark.bitcoind
def test_tmp_seed_cosign(bitcoind, restore_main_seed, use_regtest, cap_story,
                         goto_eph_seed_menu, pick_menu_item, word_menu_entry,
                         confirm_tmp_seed, offer_minsc_import, press_select,
                         clear_miniscript, get_cc_key, create_core_wallet,
                         microsd_path, goto_home, microsd_wipe):

    # Proves that we can hold secnonce for multiple seed types on one device
    # (even for the same txn where respective keys are co-signers), and that
    # repeated SD-card passes keep a stable, incrementing filename.
    b_words = "sight will strike aspect nerve saddle young special dragon fence chest tattoo"
    c_words = "able december recipe saddle cheese squirrel almost planet family cannon sight tattoo"

    use_regtest()
    clear_miniscript()
    microsd_wipe()

    name = "tmp_musig_cosign"
    der_pth = "86h/1h/0h"

    b_node = BIP32Node.from_master_secret(Mnemonic.to_seed(b_words))
    b_xfp = b_node.fingerprint().hex()
    b_key = b_node.subkey_for_path(der_pth).hwif()
    b_key_exp = f"[{b_xfp}/{der_pth}]{b_key}"

    c_node = BIP32Node.from_master_secret(Mnemonic.to_seed(c_words))
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
    press_select()

    bitcoind_wo = create_core_wallet(name, "bech32m", "sd", True)

    psbt = bitcoind_wo.walletcreatefundedpsbt(
        [], [{bitcoind.supply_wallet.getnewaddress(): 0.2}],
        0, {"fee_rate": 20, "change_type": "bech32m"}
    )['psbt']

    fname = "the.psbt"
    with open(microsd_path(fname), "w") as f:
        f.write(psbt)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(.1)
        pick_menu_item(fname)
        time.sleep(.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "warning" not in story
    press_select()
    time.sleep(.1)
    title, story = cap_story()
    assert title == "PSBT Updated"

    fname = story.split("\n\n")[1]
    assert fname == "the-part.psbt"

    for i, words in [(2, b_words), (3, c_words)]:
        goto_eph_seed_menu()
        pick_menu_item("Import Words")
        pick_menu_item("12 Words")
        time.sleep(.1)
        word_menu_entry(words.split())
        confirm_tmp_seed(seedvault=False)
        title, story = offer_minsc_import(desc)
        assert "Create new miniscript wallet?" in story
        press_select()

        goto_home()
        pick_menu_item("Ready To Sign")
        time.sleep(.1)
        title, story = cap_story()
        if "OK TO SEND?" not in title:
            time.sleep(.1)
            pick_menu_item(fname)
            time.sleep(.1)
            title, story = cap_story()
        assert title == "OK TO SEND?"
        assert "warning" not in story
        press_select()
        time.sleep(.1)
        title, story = cap_story()
        assert title == "PSBT Updated"

        fname = story.split("\n\n")[1]
        assert fname == f"the-part-{i}.psbt"

    # Still at C words: perform its second MuSig round.
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(.1)
        pick_menu_item(fname)
        time.sleep(.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "warning" not in story
    press_select()
    time.sleep(.1)
    title, story = cap_story()
    assert title == "PSBT Signed"

    fname = story.split("\n\n")[1]
    assert fname == "the-part-4.psbt"

    # Back to B words; the miniscript wallet is already imported.
    goto_eph_seed_menu()
    pick_menu_item("Import Words")
    pick_menu_item("12 Words")
    time.sleep(.1)
    word_menu_entry(b_words.split())
    confirm_tmp_seed(seedvault=False)

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(.1)
        pick_menu_item(fname)
        time.sleep(.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "warning" not in story
    press_select()
    time.sleep(.1)
    title, story = cap_story()
    assert title == "PSBT Signed"

    fname = story.split("\n\n")[1]
    assert fname == "the-part-5.psbt"

    try:
        # This is run with --eff, so the number of settings may be incorrect.
        restore_main_seed()
    except Exception:
        pass

    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(.1)
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(.1)
        pick_menu_item(fname)
        time.sleep(.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "warning" not in story
    press_select()
    time.sleep(.1)
    title, story = cap_story()
    assert title == "PSBT Signed"
    split_story = story.split("\n\n")
    fname_psbt = split_story[1]
    assert fname_psbt == "the-signed.psbt"
    fname_txn = split_story[3]
    cc_txid = split_story[4].split("\n")[-1]

    with open(microsd_path(fname_psbt), "r") as f:
        psbt = f.read().strip()

    with open(microsd_path(fname_txn), "r") as f:
        txn = f.read().strip()

    res = bitcoind_wo.finalizepsbt(psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    assert tx_hex == txn
    res = bitcoind_wo.testmempoolaccept([txn])
    assert res[0]["allowed"]
    res = bitcoind_wo.sendrawtransaction(txn)
    assert res == cc_txid


@pytest.mark.bitcoind
@pytest.mark.parametrize("cc_in_musig", [True, False])
def test_musig_in_thresh(cc_in_musig, clear_miniscript, offer_minsc_import, use_regtest, bitcoind,
                         address_explorer_check, get_cc_key, bitcoin_core_signer, import_duplicate,
                         press_select, end_sign, create_core_wallet, start_sign, cap_story,
                         press_cancel):
    use_regtest()
    sequence = 25

    core_musig_pubkeys = []
    core_musig_privkeys = []
    musig_signers = []
    for i in range(2):
        signer, core_pk, core_sk = bitcoin_core_signer(f"musig-co-signer{i}", privkey=True)
        signer.keypoolrefill(25)
        core_pk = core_pk.replace("/0/*", "")
        core_sk = core_sk.replace("/0/*", "")
        core_musig_pubkeys.append(core_pk)
        core_musig_privkeys.append(core_sk)
        musig_signers.append(signer)

    core_pubkeys = []
    core_privkeys = []
    signers = []
    for i in range(2):
        signer, core_pk, core_sk = bitcoin_core_signer(f"co-signer{i}", privkey=True)
        signer.keypoolrefill(25)
        core_pk = core_pk.replace("/0/*", "/<0;1>/*")
        core_pubkeys.append(core_pk)
        core_privkeys.append(core_sk)
        signers.append(signer)

    cc_key = get_cc_key("86h/1h/0h")

    if cc_in_musig:
        cc_key = cc_key.replace("/<0;1>/*", "")
        musig = "musig(%s)/<0;1>/*" % ",".join([cc_key] + core_musig_pubkeys)
        tapscript = f"thresh(3,pk({core_pubkeys[0]}),s:pk({core_pubkeys[1]}),s:pk({musig}),sln:older({sequence}))"
    else:
        musig = "musig(%s)/<0;1>/*" % ",".join(core_musig_pubkeys)
        tapscript = f"thresh(3,pk({core_pubkeys[0]}),s:pk({cc_key}),s:pk({musig}),sln:older({sequence}))"

    desc = f"tr({ranged_unspendable_internal_key()},{tapscript})"

    clear_miniscript()
    name = "musig_var"

    _, story = offer_minsc_import(json.dumps(dict(name=name, desc=desc)))
    assert "Create new miniscript wallet?" in story
    press_select()

    wo = create_core_wallet(name, "bech32m", "sd", 1)

    desc_lst = []
    for obj in wo.listdescriptors()["descriptors"]:
        del obj["next"]
        del obj["next_index"]
        desc_lst.append(obj)

    if cc_in_musig:
        # import musig descriptor to signers
        # each signer has it's own privkey loaded
        for s, spk, ssk in zip(musig_signers, core_musig_pubkeys, core_musig_privkeys):
            to_import = copy.deepcopy(desc_lst)
            for dobj in to_import:
                dobj["desc"] = dobj["desc"].split("#")[0].replace(spk, ssk)
                csum = wo.getdescriptorinfo(dobj["desc"])["checksum"]
                dobj["desc"] = dobj["desc"] + "#" + csum

            res = s.importdescriptors(to_import)
            for o in res:
                assert o["success"]

    unspent = wo.listunspent()

    inp = [{"txid": u["txid"], "vout": u["vout"], "sequence": sequence} for u in unspent]

    conso_addr = [{wo.getnewaddress("", "bech32m"): wo.getbalance()}]  # self-spend
    psbt_resp = wo.walletcreatefundedpsbt(inp, conso_addr, 0, {"fee_rate": 2,
                                                               "change_type": "bech32m",
                                                               "subtractFeeFromOutputs": [0]})
    psbt = psbt_resp.get("psbt")
    res_psbt = base64.b64decode(psbt)

    if cc_in_musig:
        # musig co-signers adding nonces
        for s in musig_signers:
            psbt_resp = s.walletprocesspsbt(psbt, True, "DEFAULT", True, False)
            psbt = psbt_resp.get("psbt")

        # CC add nonce
        start_sign(base64.b64decode(psbt))
        title, story = cap_story()
        assert "Consolidating" in story
        assert f"Wallet: {name}" in story
        res_psbt = end_sign(exit_export_loop=False)
        time.sleep(.1)
        title, story = cap_story()
        assert "PSBT Updated" == title
        press_cancel()  # exit export loop

        po = BasicPSBT().parse(res_psbt)
        for inp in po.inputs:
            # all co-signers added nonces
            assert len(inp.musig_pubnonces) == 3
            # no signature was added
            assert len(inp.musig_part_sigs) == 0

    # CC add signature
    start_sign(res_psbt)
    title, story = cap_story()
    assert "Consolidating" in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign(exit_export_loop=False)
    time.sleep(.1)
    title, story = cap_story()
    assert "PSBT Signed" == title
    press_cancel()  # exit export loop

    b64_res_psbt = base64.b64encode(res_psbt).decode()

    if cc_in_musig:
        # musig co-signers add signatures
        for s in musig_signers:
            psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "DEFAULT", True, False)
            b64_res_psbt = psbt_resp.get("psbt")

        po = BasicPSBT().parse(base64.b64decode(b64_res_psbt))
        for inp in po.inputs:
            # nonces from 1st round
            assert len(inp.musig_pubnonces) == 3
            # all co-signers added signatures
            assert len(inp.musig_part_sigs) == 3

    # now sign with one of the normal core signers that are not part of the musig
    b64_res_psbt = signers[0].walletprocesspsbt(b64_res_psbt, True, "DEFAULT", True, False)["psbt"]

    res = wo.finalizepsbt(b64_res_psbt)
    assert res["complete"]
    tx_hex = res["hex"]

    # we are signing for timelocked tapscript
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"] is False
    assert res[0]['reject-reason'] == 'non-BIP68-final'
    bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    # check addresses are correct
    address_explorer_check("sd", "bech32m", wo, name)


@pytest.mark.parametrize("tapscript", [True, False])
def test_inputs_in_different_musig_rounds(tapscript, use_regtest, clear_miniscript, bitcoind,
                                          build_musig_wallet, start_sign, end_sign, cap_story,
                                          press_cancel):
    use_regtest()
    clear_miniscript()
    name = "diff_round_musig"
    wo, signers, desc = build_musig_wallet(name, 3, tapscript=tapscript,
                                           tree_design="left_heavy",  # not balanced tree
                                           tapscript_musig_threshold=2, num_utxo_available=2)
    unspent = wo.listunspent()
    assert len(unspent) == 2

    psbt_resp = wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 43.4389}],
                                          0, {"fee_rate": 2, "change_type": "bech32m"})
    psbt = psbt_resp.get("psbt")

    # cosigners adding nonces
    for s in signers:
        psbt_resp = s.walletprocesspsbt(psbt, True, "DEFAULT", True, False)
        psbt = psbt_resp.get("psbt")

    # CC add nonce
    start_sign(base64.b64decode(psbt))
    title, story = cap_story()
    assert "Consolidating" not in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign(exit_export_loop=False)
    time.sleep(.1)
    title, story = cap_story()
    assert "PSBT Updated" == title

    press_cancel()  # exit export loop

    po = BasicPSBT().parse(res_psbt)
    for inp in po.inputs:
        assert len(inp.musig_pubnonces) == (9 if tapscript else 3)
        assert len(inp.musig_part_sigs) == 0

    b64_res_psbt = po.as_b64_str()

    for s in signers:
        psbt_resp = s.walletprocesspsbt(b64_res_psbt, True, "DEFAULT", True, False)
        b64_res_psbt = psbt_resp.get("psbt")

    po = BasicPSBT().parse(base64.b64decode(b64_res_psbt))
    for inp in po.inputs:
        assert len(inp.musig_pubnonces) == (9 if tapscript else 3)
        assert len(inp.musig_part_sigs) == (6 if tapscript else 2)

    # remove nonces and signatures from 0th input, keep them with 1st input
    # causing this PSBT to have inputs in both 1st & 2nd round (not allowed)
    po.inputs[0].musig_pubnonces = {}
    po.inputs[0].musig_part_sigs = {}

    # CC add nonce
    start_sign(po.as_bytes())
    time.sleep(.1)
    title, story = cap_story()
    assert "Consolidating" not in story
    assert f"Wallet: {name}" in story
    with pytest.raises(Exception):
        end_sign(exit_export_loop=False)

    time.sleep(.1)
    title, story = cap_story()
    assert title == "Failure"
    assert "resign" in story


@pytest.mark.parametrize("tapscript", [True, False])
def test_modify_PSBT_during_musig_signing(tapscript, use_regtest, clear_miniscript, bitcoind,
                                          build_musig_wallet, start_sign, end_sign, cap_story):
    use_regtest()
    clear_miniscript()
    name = "mod_musig"
    wo, signers, desc = build_musig_wallet(name, 3, tapscript=tapscript,
                                           tree_design="right_heavy",  # not balanced tree
                                           tapscript_musig_threshold=2, num_utxo_available=2)
    unspent = wo.listunspent()
    assert len(unspent) == 2

    # spend first UTXO
    inps = [{"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}]

    psbt_resp = wo.walletcreatefundedpsbt(inps, [{bitcoind.supply_wallet.getnewaddress(): 5.12345}],
                                          0, {"fee_rate": 2, "change_type": "bech32m"})
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    title, story = cap_story()
    assert "Consolidating" not in story
    assert f"Wallet: {name}" in story
    res_psbt = end_sign()

    po = BasicPSBT().parse(res_psbt)

    # spend second UTXO
    inps = [{"txid": unspent[1]["txid"], "vout": unspent[1]["vout"]}]

    psbt_resp = wo.walletcreatefundedpsbt(inps, [{bitcoind.supply_wallet.getnewaddress(): 3.54321}],
                                          0, {"fee_rate": 3, "change_type": "bech32m"})
    psbt = psbt_resp.get("psbt")
    po1 = BasicPSBT().parse(base64.b64decode(psbt))

    # change to PSBT v2 to not need handle txn
    x = BasicPSBT().parse(po.to_v2())
    y = BasicPSBT().parse(po1.to_v2())

    combined = BasicPSBT()
    combined.version = 2
    combined.txn_version = 2

    combined.input_count = x.input_count + y.input_count
    combined.output_count = x.output_count + y.output_count
    combined.fallback_locktime = 0
    combined.inputs = x.inputs + y.inputs
    combined.outputs = x.outputs + y.outputs

    start_sign(combined.as_bytes())
    time.sleep(.1)
    title, story = cap_story()
    assert "Consolidating" not in story
    assert f"Wallet: {name}" in story
    with pytest.raises(Exception):
        end_sign()

    time.sleep(.1)
    title, story = cap_story()
    assert "musig needs restart" in story


@pytest.mark.parametrize("der", ["/**", "/<0;1>/*"])
def test_import_musig_from_b388_policy(der, microsd_path, garbage_collector, clear_miniscript,
                                       pick_menu_item, need_keypress, cap_story, use_mainnet,
                                       press_select, usb_miniscript_policy, goto_home,
                                       usb_miniscript_get):
    policy = """{
"name":"MuSig2",
"desc_template":"tr(musig(@0,@1,@2)%s,{{pk(musig(@0,@1)%s),pk(musig(@1,@2)%s)},pk(musig(@0,@2)%s)})",
"keys_info":[
  "[a0d3c79c/48h/0h/0h/3h]xpub6DyCgL3TMMS3trskRyxP6M6iCqSUYPgC4QECKYkubC1L27aYUnPZJwvw57vK56G1t42KQHhX8MrU5zkt9nispkAMXYDLfiiSyrQ9HT1aQoy",
  "[9a1c8a27/48h/0h/0h/3h]xpub6DmrCyYSAz65fVFRAPEsvLZ5jHZYeF6DvprfYp7754XD2srXQr8kAcayGKhakmWiNe7iVEpjmC9JuqicHAQZk1rpWijrvh2AEwL7WaietUN",
  "[0f056943/48h/0h/0h/3h]xpub6FQgdFZAHcAeDMVe9KxWoLMxziCjscCExzuKJhRSjM71CA9dUDZEGNgPe4S2SsRumCBXeaTBZ5nKz2cMDiK4UEbGkFXNipHLkm46inpjE9D"]
}
"""
    policy = policy % (der, der, der, der)
    fname = "musig_b388.json"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(policy)

    clear_miniscript()
    use_mainnet()
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")
    pick_menu_item("Import")
    need_keypress("1")
    try:
        pick_menu_item(fname)
    except: pass

    time.sleep(.1)
    title, story = cap_story()
    assert "Create new miniscript wallet" in story
    assert "/**" in story
    assert "/<0;1>/*" not in story
    press_select()
    pick_menu_item("MuSig2")
    pick_menu_item("Descriptors")
    pick_menu_item("BIP-388 Policy")

    contents = usb_miniscript_policy("MuSig2")
    assert "/**" in contents["desc_template"]
    assert "/<0;1>/*" not in contents["desc_template"]
    if der == "/<0;1>/*":
        policy = policy.replace(der, "/**")
    assert json.loads(policy) == contents

    contents = usb_miniscript_get("MuSig2")
    assert "/**" not in contents["desc"]
    assert "/<0;1>/*" in contents["desc"]

# EOF
