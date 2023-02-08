# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-39 seed word encryption
#
import pytest, time, struct
from pycoin.key.BIP32Node import BIP32Node
from base64 import b64encode
from binascii import b2a_hex, a2b_hex
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
import json
from mnemonic import Mnemonic
from conftest import simulator_fixed_xfp

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
def clear_bip39_pw(sim_exec, reset_seed_words):
    # faster?
    reset_seed_words()

@pytest.fixture()
def set_bip39_pw(dev, need_keypress, reset_seed_words, cap_story):

    def doit(pw):
        # reset from previous runs
        words = reset_seed_words()
    
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

        done = None
        while done == None:
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


@pytest.mark.parametrize('haz', [ False, True ])
def test_lockdown(dev, haz, cap_menu, pick_menu_item, set_bip39_pw, goto_home, cap_story, need_keypress, sim_exec, sim_eval, get_settings, reset_seed_words, get_setting):
    # test UX and operation of the 'seed lockdown' option
    
    if haz:
        xfp = set_bip39_pw('test')
        assert xfp != simulator_fixed_xfp

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Lock Down Seed')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Are you SURE' in story
    assert 'computes' in story

    if not haz:
        need_keypress('y')

        time.sleep(0.1)
        title, story = cap_story()
        assert 'Are you SURE' in story
        assert 'do not have a BIP-39 passphrase' in story
        
        need_keypress('x')
        return

    # before saving, xfp should be in-memory only
    nv = get_settings()
    mem_xfp = get_setting('xfp')
    assert hex(mem_xfp) == hex(xfp), "XFP or key correct b4 save"
    assert nv['xfp'] != mem_xfp, "in-memory xfp not different from saved value"

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
    goto_home()
    reset_seed_words()

# EOF
