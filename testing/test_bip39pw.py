# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-39 seed word encryption
#
import pdb

import pytest, time, struct
from pycoin.key.BIP32Node import BIP32Node
from binascii import a2b_hex
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
import json
from mnemonic import Mnemonic
from constants import simulator_fixed_xfp, simulator_fixed_words

# add the BIP39 test vectors
vectors = json.load(open('bip39-vectors.json'))['english']

@pytest.mark.parametrize('vector', vectors)
def test_b9p_vectors(dev, set_seed_words, need_keypress, vector, pw='RoZert'[::-1].upper()):
    # Test all BIP-39 vectors. Slow.
    _, words, cooked, xprv = vector

    seed = Mnemonic.to_seed(words, passphrase=pw)
    assert seed == a2b_hex(cooked)

    set_seed_words(words)

    dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

    need_keypress('y')

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
                 sim_execfile):

    def doit(pw, reset=True, seed_vault=False):
        # reset from previous runs
        if reset:
            words = reset_seed_words()
        else:
            conts = sim_execfile('devtest/get-secrets.py')
            assert 'mnemonic' in conts
            for l in conts.split("\n"):
                if l.startswith("mnemonic ="):
                    words = l.split("=")[-1].strip().replace('"', '')
                    break

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

        need_keypress('y')

        time.sleep(.3)
        title, story = cap_story()
        if "Press (1) to store temporary seed into Seed Vault" in story:
            if seed_vault:
                need_keypress("1")  # store it
                time.sleep(.1)
                title, story = cap_story()
                assert "Saved to Seed Vault" in story

                need_keypress("y")
            else:
                need_keypress("y")  # do not store

            title, story = cap_story()

        assert "Above is the master key fingerprint" in story
        need_keypress("y")

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

def test_b39p_refused(dev, need_keypress, pw='testing 123'):
    # user can refuse the passphrase (cancel)

    dev.send_recv(CCProtocolPacker.bip39_passphrase(pw), timeout=None)

    need_keypress('x')

    with pytest.raises(CCUserRefused):
        done = None
        while done == None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_passphrase_done(), timeout=None)


def test_cancel_on_empty_added_numbers(pick_menu_item, goto_home, need_keypress, cap_menu):
    goto_home()
    pick_menu_item('Passphrase')
    need_keypress("y")  # intro story
    pick_menu_item('Add Numbers')
    need_keypress("x")  # do not add any numbers and cancel with x
    pick_menu_item('CANCEL')
    time.sleep(0.1)
    m = cap_menu()
    assert "Ready To Sign" in m[:3]


@pytest.mark.parametrize('stype', ["bip39pw", "words", "xprv", None])
def test_lockdown(stype, pick_menu_item, set_bip39_pw, goto_home, cap_story,
                  need_keypress, sim_exec, get_settings, reset_seed_words,
                  get_setting, generate_ephemeral_words, import_ephemeral_xprv):
    # test UX and operation of the 'seed lockdown' option
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
        assert 'Are you SURE' in story
    else:
        assert 'do not have an active temporary seed' in story
        need_keypress('x')
        return

    # real code does reboot, which is poorly simulated; avoid that
    sim_exec('import callgate; callgate.show_logout = lambda x:0')
    # commit change
    need_keypress('y')

    time.sleep(0.25)

    # verify effect
    nv = get_settings()
    mem_xfp = get_setting('xfp')
    assert hex(mem_xfp) == hex(xfp), "XFP or key correct after save"
    assert nv['xfp'] == mem_xfp, "in-memory xfp different from saved value"

    # not 100% sure this reset is complete enough
    # goto_home()
    reset_seed_words()


@pytest.mark.parametrize("stype", ["words", "xprv"])
@pytest.mark.parametrize("on_eph", [True, False])
@pytest.mark.parametrize("seed_vault", [True, False])
def test_bip39pass_on_ephemeral_seed(generate_ephemeral_words, import_ephemeral_xprv,
                                     need_keypress, pick_menu_item, goto_home,
                                     reset_seed_words, goto_eph_seed_menu, stype,
                                     enter_complex, cap_story, cap_menu, on_eph,
                                     settings_set, seed_vault):
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

    pick_menu_item("Passphrase")
    need_keypress("y")
    enter_complex(passphrase)
    pick_menu_item("APPLY")
    time.sleep(.1)
    title, story = cap_story()
    # title is xfp = simulator fixed words + pass (as first iteration is always from main seed)
    xfp0 = title[1:-1]
    seed0 = Mnemonic.to_seed(simulator_fixed_words, passphrase=passphrase)
    expect0 = BIP32Node.from_master_secret(seed0)
    assert expect0.fingerprint().hex().upper() == xfp0
    assert "press (2) to add passphrase to the current active temporary seed" in story

    if on_eph:
        need_keypress("2")
        time.sleep(.5)
        title, story = cap_story()
        xfp1 = title[1:-1]
        seed1 = Mnemonic.to_seed(" ".join(sec), passphrase=passphrase)
        expect1 = BIP32Node.from_master_secret(seed1)
        assert expect1.fingerprint().hex().upper() == xfp1
        assert "press (2)" not in story
        need_keypress("y")
    else:
        need_keypress("y")

    if on_eph:
        to_check = xfp1
    else:
        to_check = xfp0

    time.sleep(.3)
    title, story = cap_story()
    if "Press (1) to store temporary seed into Seed Vault" in story:
        if seed_vault:
            need_keypress("1")  # store it
            time.sleep(.1)
            title, story = cap_story()
            assert "Saved to Seed Vault" in story
            assert to_check in story

            need_keypress("y")
        else:
            need_keypress("y")  # do not store

    if seed_vault:
        # check correct meta in seed vault
        pick_menu_item("Seed Vault")
        m = cap_menu()
        for i in m:
            if to_check in i:
                pick_menu_item(i)
                break
        else:
            pytest.fail("not in menu")

        # choose first info item in submenu
        need_keypress("y")
        time.sleep(.1)
        _, story = cap_story()
        assert to_check in story
        if on_eph:
            assert ("BIP-39 Passphrase on [%s]" % parent_fp) in story
        else:
            assert "BIP-39 Passphrase on [0F056943]"  in story

# EOF
