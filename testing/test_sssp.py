# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests related to Single Signer Spending Policy feature (SSSP)
#
# run simulator without --eff
#
#
import pytest, time, base64, random, json
from psbt import BasicPSBT
from ckcc.protocol import CCProtocolPacker


@pytest.fixture
def goto_sssp_menu(goto_home, pick_menu_item, is_mark4):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Spending Policy")
        pick_menu_item("Single-Signer")

    return doit


@pytest.fixture
def setup_sssp(goto_sssp_menu, pick_menu_item, cap_story, press_select, pass_word_quiz, is_q1,
                seed_story_to_words, cap_menu, OK, word_menu_entry, press_cancel, press_delete,
                enter_number, scan_a_qr, cap_screen, settings_get, need_keypress, microsd_path,
                master_settings_get, enter_pin, settings_remove, sim_exec):

    def doit(pin=None, mag=None, vel=None, whitelist=None, w2fa=None, has_violation=None,
             word_check=None, notes_and_pws=None, rel_keys=None):

        goto_sssp_menu()
        time.sleep(.1)
        title, story = cap_story()

        # it is possible that PIN was set beforehand
        if title == "Spending Policy":
            assert "stops you from signing transactions unless conditions are met" in story
            assert "locked into a special mode" in story
            assert "First step is to define a new PIN" in story
            press_select()
            time.sleep(.1)
            scr = cap_screen()
            if "Spending Policy" in scr:
                what = "Enter first part of PIN" if is_q1 else "Enter PIN Prefix"
                assert what in scr

                enter_pin(pin)
                time.sleep(.1)
                scr = cap_screen()
                what = "Confirm PIN value"if is_q1 else "CONFIRM PIN VALUE"
                assert what in scr
                enter_pin(pin)
                time.sleep(.1)

        m = cap_menu()

        assert "Edit Policy..." in m
        if has_violation is not None:
            if has_violation:
                assert "Last Violation" in m
            else:
                assert "last Violation" not in m

        assert "Word Check" in m
        assert ("Allow Notes" in m) or not is_q1
        assert "Related Keys" in m
        assert "Remove Policy" in m
        assert "Test Drive" in m
        assert "ACTIVATE" in m

        pick_menu_item("Edit Policy...")

        whitelist_mi = "Whitelist Addresses" if is_q1 else "Whitelist"
        mag_mi = "Max Magnitude"
        vel_mi = "Limit Velocity"
        mi_2fa = "Web 2FA"

        time.sleep(.1)
        m = cap_menu()
        assert mag_mi in m
        assert vel_mi in m
        assert whitelist_mi in m
        assert mi_2fa in m

        # setting above values here
        if mag:
            pick_menu_item(mag_mi)
            enter_number(mag)
            time.sleep(.1)
            title, story = cap_story()
            assert f"{mag} {'BTC' if int(mag) < 1000 else 'SATS'}" in story
            press_select()

            time.sleep(.1)
            assert settings_get("sssp")["pol"]["mag"] == mag

        if vel:
            if not settings_get("sssp")["pol"].get("mag", None):
                pick_menu_item(vel_mi)
                title, story = cap_story()
                assert 'Velocity limit requires' in story
                assert 'starting value' in story
                press_select()
            else:
                pick_menu_item(vel_mi)

            if vel == "Unlimited":
                target = 0
            else:
                target = int(vel.split()[0])

            pick_menu_item(vel)  # actually a full menu item
            time.sleep(.3)
            assert settings_get("sssp")["pol"]["vel"] == target

        if whitelist:
            pick_menu_item(whitelist_mi)
            time.sleep(.1)
            m = cap_menu()
            assert "(none yet)" in m
            assert "Import from File" in m
            if is_q1:
                assert "Scan QR" in m
                pick_menu_item("Scan QR")
                for i, addr in enumerate(whitelist, start=1):
                    scan_a_qr(addr)

                    for _ in range(10):
                        scr = cap_screen()
                        if (f"Got {i} so far" in scr) and ("ENTER to apply" in scr):
                            break
                        time.sleep(.2)
                    else:
                        assert False, "updating whitelist failed"

                press_select()
            else:
                assert "Scan QR" not in m
                fname = "ccc_addrs.txt"
                with open(microsd_path(fname), "w") as f:
                    for a in whitelist:
                        f.write(f"{a}\n")

                pick_menu_item("Import from File")
                time.sleep(.1)
                _, story = cap_story()
                if "Press (1)" in story:
                    need_keypress("1")
                pick_menu_item(fname)

            time.sleep(.1)
            _, story = cap_story()
            if len(whitelist) == 1:
                assert "Added new address to whitelist" in story
            else:
                assert f"Added {len(whitelist)} new addresses to whitelist" in story

            for addr in whitelist:
                assert addr in story

            # check menu correct
            press_select()
            time.sleep(.1)
            m = cap_menu()
            mi_addrs = [a for a in m if '⋯' in a]
            for mia, addr in zip(mi_addrs, reversed(whitelist)):
                _start, _end = mia.split('⋯')
                assert addr.startswith(_start)
                assert addr.endswith(_end)

            press_cancel()

            assert settings_get("sssp")["pol"]["addrs"] == whitelist

        if w2fa:
            pick_menu_item(mi_2fa)

        press_cancel()  # leave Edit Policy... (shared settings with CCC)

        # now rest of sssp specific settings
        if word_check is not None:
            pick_menu_item("Word Check")
            time.sleep(.1)
            title, story = cap_story()
            assert "addition to special PIN" in story
            assert "provide the first and last seed words" in story
            if word_check:
                assert "Enable?" in story
                press_select()  # confirm action
                time.sleep(.1)
                assert settings_get("sssp")["words"]
            else:
                assert "Disable?" in story
                pol = settings_get("sssp")
                if "words" in pol:
                    assert not pol["words"]

        if notes_and_pws is not None:
            assert is_q1
            pick_menu_item("Allow Notes")
            time.sleep(.1)
            title, story = cap_story()
            assert "Allow (read-only) access to secure notes and passwords?" in story
            if notes_and_pws:
                assert "Enable?" in story
                press_select()  # confirm action
                time.sleep(.1)
                assert settings_get("sssp")["notes"]
            else:
                assert "Disable?" in story
                pol = settings_get("sssp")
                if "notes" in pol:
                    assert not pol["notes"]

        if rel_keys is not None:
            pick_menu_item("Related Keys")
            time.sleep(.1)
            title, story = cap_story()
            assert "Allow access to BIP-39 passphrase wallets" in story
            assert "and Seed Vault (read-only)" in story
            if rel_keys:
                assert "Enable?" in story
                press_select()  # confirm action
                time.sleep(.1)
                assert settings_get("sssp")["okeys"]
            else:
                assert "Disable?" in story
                pol = settings_get("sssp")
                if "okeys" in pol:
                    assert not pol["okeys"]

    yield doit

    # cleanup code -- all users of this fixture will get this code

    settings_remove("sssp")
    sim_exec('from pincodes import pa;pa.hobbled_mode = False; from actions import goto_top_menu; goto_top_menu()')
    


@pytest.fixture
def policy_sign(start_sign, end_sign, cap_story, get_last_violation):
    def doit(wallet, psbt, violation=None):
        start_sign(base64.b64decode(psbt))
        time.sleep(.1)
        title, story = cap_story()

        if violation:
            # assume SSSP cases
            assert title == "Failure"
            assert 'warning' not in story
            assert "Spending Policy violation." in story
            assert violation in get_last_violation()
            return

        assert 'OK TO SEND?' == title
        assert "warning" not in story

        signed = end_sign(accept=True)
        po = BasicPSBT().parse(signed)

        tx_hex = None
        if violation is None:
            assert not get_last_violation()
            assert len(po.inputs[0].part_sigs) or po.inputs[0].taproot_key_sig or len(po.inputs[0].taproot_script_sigs)
            res = wallet.finalizepsbt(base64.b64encode(signed).decode())
            assert res["complete"]
            tx_hex = res["hex"]
            res = wallet.testmempoolaccept([tx_hex])
            assert res[0]["allowed"]
            res = wallet.sendrawtransaction(tx_hex)
            assert len(res) == 64  # tx id

        return signed, tx_hex

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("mag_ok", [True, False])
@pytest.mark.parametrize("mag", [1000000, 2])
def test_magnitude(mag_ok, mag, setup_sssp, bitcoind, settings_set, pick_menu_item,
                   bitcoind_d_sim_watch, policy_sign, press_select,
                   reset_seed_words, settings_path):

    wo = bitcoind_d_sim_watch

    settings_set("chain", "XRT")

    if mag_ok:
        # always try limit/border value
        if mag is None:
            to_send = 1
        else:
            to_send = mag / 100000000 if mag > 1000 else mag
    else:
        if mag is None:
            to_send = 1.1
        else:
            to_send = ((mag / 100000000)+1) if mag > 1000 else (mag+0.001)

    setup_sssp("11-11", mag=mag)

    pick_menu_item("ACTIVATE")
    press_select()

    addr = wo.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(address=addr, amount=5.0)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT
    psbt_resp = wo.walletcreatefundedpsbt(
        [], [{bitcoind.supply_wallet.getnewaddress(): to_send}], 0, {"fee_rate": 2}
    )
    psbt = psbt_resp.get("psbt")

    policy_sign(wo, psbt, violation=None if mag_ok else "magnitude")


@pytest.mark.bitcoind
@pytest.mark.parametrize("whitelist_ok", [True, False])
def test_whitelist(whitelist_ok, setup_sssp, bitcoind, settings_set, policy_sign,
                   bitcoind_d_sim_watch, pick_menu_item, press_select):

    wo = bitcoind_d_sim_watch

    settings_set("chain", "XRT")

    whitelist = [
        "bcrt1qqca9eefwz8tzn7rk6aumhwhapyf5vsrtrddxxp",
        "bcrt1q7nck280nje50gzjja3gyguhp2ds6astu5ndhkj",
        "bcrt1qhexpvdhwuerqq0h24j06g8y5eumjjdr28ng4vv",
        "bcrt1q3ylr55pk7rl0rc06d8th7h25zmcuvvg8wt0yl3",
    ]

    if whitelist_ok:
        send_to = whitelist[0]
    else:
        send_to = bitcoind.supply_wallet.getnewaddress()

    setup_sssp("11-11", whitelist=whitelist)
    pick_menu_item("ACTIVATE")
    press_select()

    multi_addr = wo.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=5.0)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT
    psbt_resp = wo.walletcreatefundedpsbt(
        [], [{send_to: 1}], 0, {"fee_rate": 2}
    )
    psbt = psbt_resp.get("psbt")
    policy_sign(wo, psbt, violation=None if whitelist_ok else "whitelist")


@pytest.mark.bitcoind
@pytest.mark.parametrize("velocity_mi", ['6 blocks (hour)', '48 blocks (8h)'])
def test_velocity(velocity_mi, setup_sssp, bitcoind, settings_set, pick_menu_item,
                      policy_sign, settings_get, bitcoind_d_sim_watch, press_select):

    wo = bitcoind_d_sim_watch
    wo.keypoolrefill(20)
    settings_set("chain", "XRT")

    blocks = int(velocity_mi.split()[0])

    setup_sssp("11-11", vel=velocity_mi)
    pick_menu_item("ACTIVATE")
    press_select()

    assert "block_h" not in settings_get("sssp")["pol"]

    multi_addr = wo.getnewaddress()
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT, first tx
    init_block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]  # block height
    psbt_resp = wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                          init_block_height)  # nLockTime set to current block height
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == init_block_height
    policy_sign(wo, psbt)  # success as this is first tx that sets block height from 0

    assert settings_get("sssp")["pol"]["block_h"] == init_block_height

    # mine some, BUT not enough to satisfy velocity policy
    # - check velocity is exactly right to block number vs. required gap
    bitcoind.supply_wallet.generatetoaddress(blocks - 1, bitcoind.supply_wallet.getnewaddress())
    block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]
    psbt_resp = wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                          block_height)
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == block_height
    policy_sign(wo, psbt, violation="velocity")

    assert settings_get("sssp")["pol"]["block_h"] == init_block_height  # still initial block height as above failed

    # mine the remaining one block to satisfy velocity policy
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]
    psbt_resp = wo.walletcreatefundedpsbt([], [{bitcoind.supply_wallet.getnewaddress(): 1}],
                                                   block_height)
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == block_height
    policy_sign(wo, psbt)  # success

    assert settings_get("sssp")["pol"]["block_h"] == block_height  # updated block height

    # check txn re-sign fails (if velocity in effect)
    policy_sign(wo, psbt, violation="rewound")
    # check decreasing nLockTime
    policy_sign(
        wo,
        wo.walletcreatefundedpsbt(
            [], [{bitcoind.supply_wallet.getnewaddress(): 1}], block_height - 1
        )["psbt"],
        violation="rewound"
    )
    # check nLockTime disabled when velocity enabled - fail
    policy_sign(
        wo,
        wo.walletcreatefundedpsbt(
            [], [{bitcoind.supply_wallet.getnewaddress(): 1}], 0
        )["psbt"],
        violation="no nLockTime"
    )
    # unix timestamp
    policy_sign(
        wo,
        wo.walletcreatefundedpsbt(
            [], [{bitcoind.supply_wallet.getnewaddress(): 1}], 500000000
        )["psbt"],
        violation="nLockTime not height"
    )


@pytest.mark.bitcoind
@pytest.mark.parametrize("active", [True, False])
def test_warnings(setup_sssp, bitcoind, settings_set, policy_sign, pick_menu_item,
                  bitcoind_d_sim_watch, settings_get, press_select, active):

    wo = bitcoind_d_sim_watch
    wo.keypoolrefill(20)

    settings_set("chain", "XRT")

    whitelist = ["bcrt1qlk39jrclgnawa42tvhu2n7se987qm96qg8v76e",
                 "2Mxp1Dy2MyR4w36J2VaZhrFugNNFgh6LC1j",
                 "mjR14oKxYzRg9RAZdpu3hrw8zXfFgGzLKm"]

    setup_sssp("11-11", mag=10000000, vel='6 blocks (hour)', whitelist=whitelist)
    if active:
        pick_menu_item("ACTIVATE")
        press_select()
    else:
        # demonstration that policy is in effect from configuration
        # user does not need to activate (or test-drive) and policy in effect already
        pass

    bitcoind.supply_wallet.sendtoaddress(address=wo.getnewaddress(), amount=2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    # create funded PSBT, first tx
    # whitelist OK, velocity OK, & magnitude OK - but fee high
    init_block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]  # block height
    psbt_resp = wo.walletcreatefundedpsbt([], [{whitelist[0]: 0.06},{whitelist[1]: 0.01},{whitelist[2]: 0.03}],
                                          init_block_height, {"fee_rate":48000})
    psbt = psbt_resp.get("psbt")
    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == init_block_height
    policy_sign(wo, psbt, violation="has warnings")

    # invalidate nLockTime with use of nSequence max values
    utxos = wo.listunspent()
    ins = []
    for i, utxo in enumerate(utxos):
        # block height based RTL
        inp = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "sequence": 0xffffffff,
        }
        ins.append(inp)

    psbt_resp = wo.walletcreatefundedpsbt(ins, [{whitelist[0]: 0.06},{whitelist[1]: 0.01},{whitelist[2]: 0.03}],
                                          0, {"fee_rate":2, "replaceable": False})  # locktime needs to be zero, otherwise exception from core (contradicting parameters)
    po = BasicPSBT().parse(base64.b64decode(psbt_resp.get("psbt")))
    assert po.parsed_txn.nLockTime == 0
    po.parsed_txn.nLockTime = init_block_height  # add locktime
    po.txn = po.parsed_txn.serialize_with_witness()
    # num_warn=2, warn_list=["Bad Locktime"]
    policy_sign(wo, po.as_b64_str(), violation="has warnings")

    # exotic sighash warning
    settings_set("sighshchk", 1)  # needed to only get warning instead of failure
    psbt_resp = wo.walletcreatefundedpsbt([], [{whitelist[0]: 0.06},{whitelist[1]: 0.01},{whitelist[2]: 0.03}],
                                                   init_block_height, {"fee_rate":2, "replaceable": True})
    po = BasicPSBT().parse(base64.b64decode(psbt_resp.get("psbt")))
    for idx, i in enumerate(po.inputs):
        i.sighash = 2  # NONE

    # num_warn=2, warn_list=["sighash NONE"]
    policy_sign(wo, po.as_b64_str(), violation="has warnings")


def test_remove_sssp(setup_sssp, pick_menu_item, press_select, cap_story, cap_menu, settings_get):
    setup_sssp("11-11", mag=10000000, vel='6 blocks (hour)')

    # check test drive
    pick_menu_item("Test Drive")
    time.sleep(.1)
    _, story = cap_story()
    assert "COLDCARD operation will look like with Spending Policy" in story
    press_select()

    time.sleep(.1)
    m = cap_menu()
    assert "EXIT TEST DRIVE" in m
    assert "Settings" not in m

    pick_menu_item("EXIT TEST DRIVE")
    time.sleep(.1)
    m = cap_menu()
    assert "Edit Policy..." in m  # back in policy settings

    pick_menu_item("Remove Policy")
    time.sleep(.1)
    _, story = cap_story()
    assert "Bypass PIN will be removed" in story
    assert "spending policy settings forgotten" in story
    press_select()

    time.sleep(.1)
    assert not settings_get("sssp")

    tps = settings_get("tp")
    if tps:
        assert "11-11" not in tps

    assert not settings_get("sssp")


def test_use_main_pin_as_unlock(setup_sssp, cap_story):
    # not allowed
    # simulator PIN
    with pytest.raises(Exception):
        setup_sssp("12-12")

    _, story = cap_story()
    assert "already in use" in story
    assert "PIN codes must be unique" in story


@pytest.mark.parametrize("hide", [True, False])
def test_use_trick_pin_as_unlock(hide, setup_sssp, cap_story, new_trick_pin, pick_menu_item,
                                 press_select, clear_all_tricks):
    clear_all_tricks()
    pin = "11-11"
    new_trick_pin(pin, 'Wipe Seed', 'Wipe the seed and maybe do more')
    pick_menu_item('Wipe & Reboot')
    press_select()
    press_select()
    if hide:
        pick_menu_item(f"↳{pin}")
        pick_menu_item("Hide Trick")
        press_select()  # confirm

    with pytest.raises(Exception):
        setup_sssp(pin)

    _, story = cap_story()
    assert "already in use" in story
    assert "PIN codes must be unique" in story



@pytest.mark.parametrize("active_policy", [False, True])
def test_deltamode_signature(active_policy, setup_sssp, bitcoind, settings_set,
                             start_sign, end_sign, pick_menu_item, press_select,
                             set_deltamode, bitcoind_d_sim_watch, settings_get):

    # verify that "deltamode" trick pins will work in SSSP mode
    # - and that resulting signature is bad
    # - device should **not** wipe itself

    dest = "bcrt1qlk39jrclgnawa42tvhu2n7se987qm96qg8v76e"
    wo = bitcoind_d_sim_watch
    wo.keypoolrefill(20)

    settings_set("chain", "XRT")

    if active_policy:
        setup_sssp(f"{random.randint(0,99)}-11", mag=100)
        pick_menu_item("ACTIVATE")
        press_select()

    bitcoind.supply_wallet.sendtoaddress(address=wo.getnewaddress(), amount=2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    # create funded PSBT, first tx
    # - within active policy.
    init_block_height = bitcoind.supply_wallet.getblockchaininfo()["blocks"]  # block height
    psbt_resp = wo.walletcreatefundedpsbt([], [{dest: 0.06}],
                                          init_block_height, {"fee_rate":2, "replaceable": False})
    psbt = psbt_resp.get("psbt")

    po = BasicPSBT().parse(base64.b64decode(psbt))
    assert po.parsed_txn.nLockTime == init_block_height

    start_sign(base64.b64decode(psbt), finalize=True)
    signed = end_sign(accept=True, finalize=True)

    set_deltamode(True)

    start_sign(base64.b64decode(psbt), finalize=True)
    signed2 = end_sign(accept=True, finalize=True)

    # check wrong signature happened
    assert signed != signed2
    probs = wo.testmempoolaccept([signed2.hex()])[0]
    try:
        # old bitcoind
        assert 'Signature must be zero' in probs['reject-reason'], probs
    except AssertionError:
        assert 'mandatory-script-verify-flag-failed' in probs['reject-reason'], probs
    assert not probs['allowed']

    # check right signature
    no_probs = wo.testmempoolaccept([signed.hex()])[0]
    assert no_probs['allowed']


@pytest.mark.bitcoind
def test_sssp_enforce_tmp_seed(setup_sssp, bitcoind, settings_set, settings_get, press_select,
                               pick_menu_item, cap_menu, go_to_passphrase, enter_complex,
                               need_keypress, word_menu_entry, fake_txn, start_sign, dev,
                               cap_story):
    tmp_words = "style car win bomb plug raccoon predict warm wrap flush usual seminar"
    blocks = 6  # ~1 hour
    settings_set("chain", "XRT")
    setup_sssp("11-11", mag=2, vel='6 blocks (hour)', rel_keys=True)
    assert "block_h" not in settings_get("sssp")["pol"]
    pick_menu_item("ACTIVATE")
    press_select()
    time.sleep(.1)
    m = cap_menu()
    # check we are in hobbled mode & okeys is respected
    assert "Passphrase" in m
    assert "Settings" not in m

    # import word-based seed as tmp and check that sssp is enforced
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Temporary Seed")
    need_keypress("4")
    pick_menu_item("Import Words")
    pick_menu_item("12 Words")
    word_menu_entry(tmp_words.split())
    press_select()
    time.sleep(.1)
    m = cap_menu()
    assert "Passphrase" in m  # word based + okeys
    assert "Settings" not in m

    xpub = dev.send_recv(CCProtocolPacker.get_xpub("m"), timeout=None)
    psbt = fake_txn(2,2, input_amount=200000000, master_xpub=xpub)
    start_sign(psbt)
    time.sleep(.1)
    _, story = cap_story()
    assert "Spending Policy violation" in story
    press_select()

    # recurse deeper, to passphrase wallet, on top of word-based tmp seed
    go_to_passphrase()
    enter_complex("AAA", apply=True)

    press_select()
    m = cap_menu()
    assert "Passphrase" not in m  # xprv based
    assert "Settings" not in m  # still in hobbled

    xpub = dev.send_recv(CCProtocolPacker.get_xpub("m"), timeout=None)
    psbt = fake_txn(2, 2, input_amount=200000000, master_xpub=xpub)
    start_sign(psbt)
    time.sleep(.1)
    _, story = cap_story()
    assert "Spending Policy violation" in story
    press_select()
    time.sleep(.1)

    pick_menu_item("Restore Master")
    press_select()

    time.sleep(.1)
    m = cap_menu()
    assert "Passphrase" in m
    assert "Settings" not in m  # still in hobbled
    psbt = fake_txn(2, 2, input_amount=200000000)
    start_sign(psbt)
    time.sleep(.1)
    _, story = cap_story()
    assert "Spending Policy violation" in story
    press_select()

def test_sssp_notes_enable(only_q1, setup_sssp):
    # just test menu item works
    setup_sssp("11-11", mag=2, vel='6 blocks (hour)', notes_and_pws=True)
    
def test_sssp_word_check(setup_sssp):
    # just test menu item works
    setup_sssp("11-11", mag=2, vel='6 blocks (hour)', word_check=True)

@pytest.mark.parametrize("af", ["bech32", "bech32m"])
def test_miniscript_enforce(af, settings_set, clear_miniscript, goto_home, get_cc_key, bitcoind,
                            offer_minsc_import, press_select, cap_menu, pick_menu_item, cap_story,
                            start_sign, end_sign, create_core_wallet, policy_sign, setup_sssp):
    sequence = 10
    goto_home()
    clear_miniscript()

    settings_set("chain", "XRT")
    policy = "and_v(v:pk(@0/<0;1>/*),older(10))"

    if af == "bech32m":
        tmplt = f"tr(tpubD6NzVbkrYhZ4XgXS51CV3bhoP5dJeQqPhEyhKPDXBgEs64VdSyAfku99gtDXQzY6HEXY5Dqdw8Qud1fYiyewDmYjKe9gGJeDx7x936ur4Ju/<0;1>/*,{policy})"
    else:
        tmplt = f"wsh({policy})"

    cc_key = get_cc_key("m/666h/1h/0h").replace('/<0;1>/*', '')
    desc = tmplt.replace("@0", cc_key)

    wname = "single_k_mini"

    _, story = offer_minsc_import(json.dumps(dict(name=wname, desc=desc)))
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()

    wo = create_core_wallet(wname, af, "sd", True)

    whitelisted_addr = bitcoind.supply_wallet.getnewaddress()
    setup_sssp("11-11", mag=10000000, vel='6 blocks (hour)', whitelist=[whitelisted_addr])
    pick_menu_item("ACTIVATE")
    press_select()

    unspent = wo.listunspent()
    assert len(unspent) == 1

    # mines 10 blocks to release script lock (not related to SSSP)
    bitcoind.supply_wallet.generatetoaddress(sequence, bitcoind.supply_wallet.getnewaddress())

    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "sequence": sequence}
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{bitcoind.supply_wallet.getnewaddress(): 5}],  # magnitude violation
        wo.getblockchaininfo()["blocks"],
        {"fee_rate": 3, "change_type": af},
    )
    psbt = psbt_resp.get("psbt")

    policy_sign(wo, psbt, violation="magnitude")

    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{bitcoind.supply_wallet.getnewaddress(): 0.09}],  # whitelist violation
        wo.getblockchaininfo()["blocks"],
        {"fee_rate": 3, "change_type": af},
    )
    psbt = psbt_resp.get("psbt")
    policy_sign(wo, psbt, violation="whitelist")

    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{whitelisted_addr: 0.09}],
        wo.getblockchaininfo()["blocks"],
        {"fee_rate": 3, "change_type": af},
    )
    psbt = psbt_resp.get("psbt")
    policy_sign(wo, psbt)  # good - in accordance with policy

# EOF
