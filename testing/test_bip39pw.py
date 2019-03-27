# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# BIP39 seed word encryption
#
import pytest, time
from pycoin.key.BIP32Node import BIP32Node
from pycoin.contrib.msg_signing import verify_message
from base64 import b64encode
from binascii import b2a_hex, a2b_hex
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
import json
from mnemonic import Mnemonic

# add the BIP39 test vectors
vectors = json.load(open('bip39-vectors.json'))['english']

@pytest.mark.parametrize('vector', vectors)
def test_b9p_vectors(dev, set_seed_words, need_keypress, vector, pw='RoZert'[::-1].upper()):
    # Test all BIP39 vectors. Slow.
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
def test_b9p_basic(dev, need_keypress, pw, reset_seed_words, cap_story):

    # reset from previous runs
    words = reset_seed_words()

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


# EOF
