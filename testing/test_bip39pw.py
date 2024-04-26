# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-39 seed word encryption
#

import pytest, time, struct, pdb
from pycoin.key.BIP32Node import BIP32Node
from binascii import a2b_hex
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
import json
from mnemonic import Mnemonic
from constants import simulator_fixed_xfp, simulator_fixed_words, simulator_fixed_tprv
from helpers import xfp2str


# add the BIP39 test vectors
vectors = json.load(open('bip39-vectors.json'))['english']

@pytest.mark.parametrize('vector', vectors)
def test_b9p_vectors(dev, set_seed_words, press_select, vector, pw='RoZert'[::-1].upper()):
    # Test all BIP-39 vectors. Slow.
    _, words, cooked, xprv = vector

    seed = Mnemonic.to_seed(words, passphrase=pw)
    assert seed == a2b_hex(cooked)

    set_seed_words(words)

    dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

    press_select()

    xpub = None
    while xpub == None:
        time.sleep(0.050)
        xpub = dev.send_recv(CCProtocolPacker.get_passphrase_done(), timeout=None)

    # check our math (ignore testnet vs. mainnet)
    got = BIP32Node.from_wallet_key(xpub)
    exp = BIP32Node.from_wallet_key(xprv)

    assert got.public_pair() == exp.public_pair()

@pytest.mark.parametrize('pw', ['test 2', 'with some spaces',
                                '123 12l3kj1l2k3j 1l2k3j 1l2k3j ',
                                'a'*99,
                                ''      # keep last, resets state
                ])
def test_b9p_basic(pw, set_bip39_pw):
    set_bip39_pw(pw)


@pytest.fixture()
def set_bip39_pw(dev, need_keypress, reset_seed_words, cap_story,
                 sim_execfile, press_select):

    def doit(pw, reset=True, seed_vault=False, on_tmp=False):
        # reset from previous runs
        if reset:
            words = reset_seed_words()
        else:
            conts = sim_execfile('devtest/get-secrets.py')
            if 'mnemonic' in conts:
                for l in conts.split("\n"):
                    if l.startswith("mnemonic ="):
                        words = l.split("=")[-1].strip().replace('"', '')
                        break
            else:
                words = simulator_fixed_words

        # optimization
        if pw == '':
            return simulator_fixed_xfp

        print(f"Setting BIP-39 pw: {pw}")
        dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

        if pw:
            time.sleep(0.050)
            title, body = cap_story()

            assert pw not in body

            # verify display of passphrase
            need_keypress('2')
            time.sleep(0.050)
            title, body = cap_story()
            assert pw in body
            press_select()  # go back

        time.sleep(.1)
        title, body = cap_story()
        if on_tmp:
            assert "to current active temporary seed" in body
        else:
            assert "to master seed" in body

        press_select()

        time.sleep(.3)
        title, story = cap_story()
        if "Press (1) to store temporary seed into Seed Vault" in story:
            if seed_vault:
                need_keypress("1")  # store it
                time.sleep(.1)
                title, story = cap_story()
                assert "Saved to Seed Vault" in story

                press_select()
            else:
                press_select()  # do not store

            time.sleep(.2)
            title, story = cap_story()

        assert "Above is the master key fingerprint" in story
        press_select()

        done = None
        while done is None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_passphrase_done(), timeout=None)

        xpub = done
        assert xpub[1:4] == 'pub'
        got = BIP32Node.from_wallet_key(xpub)

        # what it should be
        seed = Mnemonic.to_seed(words, passphrase=pw)
        expect = BIP32Node.from_master_secret(seed)

        assert got.public_pair() == expect.public_pair()

        xfp, = struct.unpack('I', expect.fingerprint())

        return xfp

    return doit


@pytest.mark.parametrize('pw', [ 
    'a'*1000,   # way too big
    'a'*100,    # just too big
    ])
def test_b39_fails(dev, pw):

    with pytest.raises(CCProtoError):
        dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

def test_b39p_refused(dev, press_cancel, pw='testing 123'):
    # user can refuse the passphrase (cancel)

    dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

    press_cancel()

    with pytest.raises(CCUserRefused):
        done = None
        while done == None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_passphrase_done(), timeout=None)


@pytest.mark.parametrize('target', ['baby', 'struggle', 'youth'])
@pytest.mark.parametrize('version', range(8))
def test_bip39_pick_words(target, version, cap_menu, pick_menu_item, cap_story,
                          word_menu_entry, get_pp_sofar, reset_seed_words,
                          press_select, only_mk4, go_to_passphrase):
    # Check we can pick words
    reset_seed_words()

    go_to_passphrase()
    pick_menu_item('Add Word')

    word_menu_entry([target])
    if version%4 == 0:
        mw = target
    if version%4 == 1:
        mw = target.upper()
    if version%4 == 2:
        mw = target.lower()
    if version%4 == 3:
        mw = target.title()
    if version >= 4:
        mw = ' ' + mw

    pick_menu_item(mw)

    chk = get_pp_sofar()

    assert chk == mw

@pytest.mark.parametrize('target', ['123', '1', '4'*32, '12'*8])
@pytest.mark.parametrize('backspaces', [1, 0, 12])
def test_bip39_add_nums(target, backspaces, pick_menu_item, cap_story, only_mk4,
                        cap_menu, word_menu_entry, get_pp_sofar, need_keypress,
                        press_select, press_cancel, go_to_passphrase):

    # Check we can pick numbers (appended)
    # - also the "clear all" menu item

    go_to_passphrase()
    pick_menu_item('Add Numbers')

    for d in target:
        time.sleep(.01)      # required
        need_keypress(d)

    if backspaces < len(target):
        for x in range(backspaces):
            time.sleep(.01)      # required
            press_cancel()

        if backspaces:
            for d in target[-backspaces:]:
                time.sleep(.01)      # required
                need_keypress(d)

    time.sleep(0.01)      # required
    press_select()

    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == target

    # And clear it

    pick_menu_item('Clear All')
    time.sleep(0.01)      # required

    press_select()
    time.sleep(0.01)      # required
    chk = get_pp_sofar()
    assert chk == ''

@pytest.mark.parametrize('target', [
    'abc123', 'AbcZz1203', 'Test 123', 'Aa'*50,
    '&*!#^$*&@#^*&^$abcdABCD^%182736',
    'I be stacking sats!! Come at me bro....',
])
def test_bip39_complex(target, pick_menu_item, cap_story, goto_home,
                       press_select, enter_complex, restore_main_seed,
                       verify_ephemeral_secret_ui, go_to_passphrase):
    go_to_passphrase()

    from mnemonic import Mnemonic

    seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=target)
    expect = BIP32Node.from_master_secret(seed, netcode="XTN")

    enter_complex(target, apply=True)
    press_select()
    time.sleep(.1)
    verify_ephemeral_secret_ui(xpub=expect.hwif(), is_b39pw=True)
    goto_home()
    time.sleep(.1)
    pick_menu_item("Restore Master")
    press_select()


def test_cancel_on_empty_added_numbers(pick_menu_item, is_q1, cap_menu,
                                       press_cancel, go_to_passphrase):
    if is_q1:
        # there is no Enter Number dialog on Q1
        pytest.skip("'Enter Number' not available on Q1")

    go_to_passphrase()
    pick_menu_item('Add Numbers')
    press_cancel()  # do not add any numbers and cancel with x
    pick_menu_item('CANCEL')
    time.sleep(0.1)
    m = cap_menu()
    assert "Ready To Sign" in m[:3]


@pytest.mark.parametrize("has_duress", [True, False])
@pytest.mark.parametrize('stype', ["bip39pw", "words", "xprv", None])
def test_lockdown_ux(stype, pick_menu_item, set_bip39_pw, goto_home,
                     press_cancel, get_setting, reset_seed_words,
                     generate_ephemeral_words, import_ephemeral_xprv,
                     press_select, is_q1, cap_story, has_duress,
                     goto_trick_menu, new_trick_pin, new_pin_confirmed,
                     clear_all_tricks):
    # test UX and operation of the 'seed lockdown' option
    if has_duress:
        goto_trick_menu()
        pin = '123-254'
        new_trick_pin(pin, 'Duress Wallet', None)
        item = 'BIP-85 Wallet #1'
        pick_menu_item(item)
        press_select()
        new_pin_confirmed(pin, item, None, None)
        goto_home()

    if stype:
        if stype == "bip39pw":
            set_bip39_pw('test')
        elif stype == "words":
            generate_ephemeral_words(24)
        elif stype == "xprv":
            import_ephemeral_xprv("sd")

        xfp = get_setting("xfp")
        assert xfp != simulator_fixed_xfp

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Lock Down Seed')

    time.sleep(0.1)
    title, story = cap_story()

    if stype:
        where = title if is_q1 else story
        assert 'Are you SURE' in where
        assert "erased forever" in story
        assert "Saved temporary seed settings and Seed Vault are lost" in story
        if stype == "bip39pw":
            assert "Convert currently used BIP-39 passphrase to master seed" in story
            assert "but the passphrase itself is erased" in story
    else:
        assert 'do not have an active temporary seed' in story

    if has_duress and stype:
        press_select() # confirm to get error
        time.sleep(.1)
        title, story = cap_story()
        assert "You have one or more duress wallets defined" in story
        assert "Please empty them" in story
        press_select()

        if stype:
            # need to restore master to be able to see trick pin menu
            goto_home()
            pick_menu_item("Restore Master")
            press_select()
            time.sleep(.1)

        clear_all_tricks()
    else:
        press_cancel()

    reset_seed_words()
    # real code does reboot, which is poorly simulated; avoid that
    # this needs to be tested with real HW !!!


@pytest.mark.parametrize("stype", ["words", "xprv"])
@pytest.mark.parametrize("seed_vault", [True, False])
def test_bip39pass_on_ephemeral_seed(generate_ephemeral_words, import_ephemeral_xprv,
                                     need_keypress, pick_menu_item, goto_home,
                                     reset_seed_words, goto_eph_seed_menu, stype,
                                     enter_complex, cap_story, cap_menu,
                                     settings_set, seed_vault, press_select,
                                     go_to_passphrase):
    passphrase = "@coinkite rulez!!"
    reset_seed_words()
    settings_set("seedvault", 1)
    settings_set("seeds", [])

    goto_eph_seed_menu()

    if stype == "words":
        # words
        sec = generate_ephemeral_words(24, from_main=True, seed_vault=seed_vault)
        parent = Mnemonic.to_seed(" ".join(sec))
        parent_node = BIP32Node.from_master_secret(parent)
        parent_fp = parent_node.fingerprint().hex().upper()
    else:
        # node
        sec = import_ephemeral_xprv("sd", from_main=True, seed_vault=seed_vault)

    goto_home()
    if stype == "xprv":
        # cannot add passphrase on top of extended key - only words
        m = cap_menu()
        assert "Passphrase" not in m
        return

    go_to_passphrase()
    enter_complex(passphrase, apply=True)

    tmp_seed = Mnemonic.to_seed(" ".join(sec), passphrase=passphrase)
    tmp_node = BIP32Node.from_master_secret(tmp_seed)
    tmp_fp = tmp_node.fingerprint().hex().upper()

    time.sleep(.2)
    title, story = cap_story()
    title_xfp = title[1:-1]

    assert "created by adding passphrase to" in story
    assert tmp_fp == title_xfp
    assert f"current active temporary seed [{parent_fp}]" in story

    press_select()

    time.sleep(.3)
    title, story = cap_story()
    if "Press (1) to store temporary seed into Seed Vault" in story:
        if seed_vault:
            need_keypress("1")  # store it
            time.sleep(.1)
            title, story = cap_story()
            assert "Saved to Seed Vault" in story
            assert title_xfp in story

            press_select()
        else:
            press_select()  # do not store

    if seed_vault:
        # check correct meta in seed vault
        pick_menu_item("Seed Vault")
        m = cap_menu()
        for i in m:
            if title_xfp in i:
                pick_menu_item(i)
                break
        else:
            pytest.fail("not in menu")

        # choose first info item in submenu
        press_select()
        time.sleep(.1)
        _, story = cap_story()
        assert title_xfp in story
        assert ("BIP-39 Passphrase on [%s]" % parent_fp) in story


@pytest.mark.parametrize("stype", ["words", "xprv", "b39pw"])
def test_bip39pass_on_ephemeral_seed_usb(generate_ephemeral_words, import_ephemeral_xprv,
                                         pick_menu_item, goto_home,
                                         reset_seed_words, goto_eph_seed_menu, stype,
                                         cap_story, cap_menu, set_bip39_pw,
                                         get_identity_story, settings_set):
    passphrase = "@coinkite rulez!!"
    reset_seed_words()
    settings_set("seedvault", 0)

    goto_eph_seed_menu()

    if stype == "words":
        # words
        sec = generate_ephemeral_words(24, from_main=True, seed_vault=False)
        parent_words = " ".join(sec)
    elif stype == "b39pw":
        base_pw = "random_pw"
        parent_words = simulator_fixed_words
        set_bip39_pw(base_pw, reset=False, on_tmp=False)
    else:
        # node
        import_ephemeral_xprv("sd", from_main=True, seed_vault=False)

    goto_home()
    if stype in ("xprv", "b39pw"):
        with pytest.raises(Exception) as e:
            set_bip39_pw(passphrase, reset=False)
        assert "no seed" in e.value.args[0]
        return

    parent = Mnemonic.to_seed(parent_words, passphrase=passphrase)
    parent_node = BIP32Node.from_master_secret(parent, netcode="XTN")
    xpub = parent_node.hwif()
    set_bip39_pw(passphrase, reset=False, on_tmp=True if stype == "words" else False)
    ident_story, parsed_ident = get_identity_story()
    assert xpub == parsed_ident["ek"]


@pytest.mark.parametrize("usb", [True, False])
def test_tmp_on_xprv_master(generate_ephemeral_words, cap_menu, go_to_passphrase,
                            pick_menu_item, need_keypress, enter_complex,
                            cap_story, unit_test, microsd_path, expect_ftux,
                            set_bip39_pw, usb, press_select):
    passphrase = "jfkdsfdks"
    fname = "ek.txt"
    fpath = microsd_path("ek.txt")
    with open(fpath, "w") as f:
        f.write(simulator_fixed_tprv)
    unit_test('devtest/clear_seed.py')
    time.sleep(.2)
    pick_menu_item('Import Existing')
    pick_menu_item("Import XPRV")
    time.sleep(.2)
    title, story = cap_story()
    if "Press (1)" in story:
        need_keypress("1")

    pick_menu_item(fname)
    time.sleep(.2)
    expect_ftux()
    m = cap_menu()
    assert "Passphrase" not in m
    sec = generate_ephemeral_words(24, from_main=True, seed_vault=False)
    parent = Mnemonic.to_seed(" ".join(sec), passphrase=passphrase)
    parent_node = BIP32Node.from_master_secret(parent, netcode="XTN")
    parent_fp = parent_node.fingerprint().hex().upper()
    m = cap_menu()
    # temporary seed is word-based - offer passphrase
    assert "Passphrase" in m
    if usb:
        res_fp = set_bip39_pw(passphrase, reset=False, seed_vault=False, on_tmp=True)
        assert xfp2str(res_fp) == parent_fp
        with pytest.raises(Exception):
            set_bip39_pw(passphrase, reset=False, seed_vault=False, on_tmp=True)

        return

    go_to_passphrase()
    enter_complex(passphrase, apply=True)
    time.sleep(.1)
    title, story = cap_story()


    assert parent_fp in title  # no choice story
    assert "current active temporary seed" in story
    press_select()
    time.sleep(.2)
    title, story = cap_story()
    if "Press (1)" in story:
        press_select()

    m = cap_menu()
    assert "Passphrase" not in m

# EOF
