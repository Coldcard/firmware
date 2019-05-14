# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Exporting of wallet files and similar things.
#
import pytest, time, struct, os
from pycoin.key.BIP32Node import BIP32Node
from base64 import b64encode
from binascii import b2a_hex, a2b_hex
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
import json
from conftest import simulator_fixed_xfp, simulator_fixed_xprv


def test_export_wasbi(dev, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path):
    # test UX and operation of the 'wasabi wallet export'

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('MicroSD Card')
    pick_menu_item('Wasabi Wallet')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves a skeleton Wasabi' in story

    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'wallet file written' in story
    fname = story.split('\n')[-1]

    need_keypress('y')

    path = microsd_path(fname)
    with open(path, 'rt') as fp:
        obj = json.load(fp)

        assert 'MasterFingerprint' in obj
        assert 'ExtPubKey' in obj
        assert 'BlockchainState' in obj
        assert obj['BlockchainState']['Network']
        
        xpub = obj['ExtPubKey']
        assert xpub.startswith('xpub')      # even for testnet

        assert int(obj['MasterFingerprint'], 16) == simulator_fixed_xfp

        got = BIP32Node.from_wallet_key(xpub)
        expect = BIP32Node.from_wallet_key(simulator_fixed_xprv).subkey_for_path("84'/0'/0'.pub")

        assert got.sec() == expect.sec()

    os.unlink(path)

        
@pytest.mark.parametrize('mode', [ "Legacy (P2PKH)", "P2SH-Segwit", "Native Segwit"])
def test_export_electrum(mode, dev, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path):
    # lightly test electrum wallet export

    goto_home()
    pick_menu_item('Advanced')
    pick_menu_item('MicroSD Card')
    pick_menu_item('Electrum Wallet')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves a skeleton Electrum wallet' in story

    need_keypress('y')

    time.sleep(0.1)
    pick_menu_item(mode)

    time.sleep(0.1)
    title, story = cap_story()

    assert 'wallet file written' in story
    fname = story.split('\n')[-1]

    need_keypress('y')

    path = microsd_path(fname)
    with open(path, 'rt') as fp:
        obj = json.load(fp)

        ks = obj['keystore']
        assert ks['ckcc_xfp'] == simulator_fixed_xfp

        assert ks['hw_type'] == 'coldcard'
        assert ks['type'] == 'hardware'

        deriv = ks['derivation']
        assert deriv.startswith('m/')
        assert int(deriv.split("/")[1][:-1]) in {44, 84, 49}        # weak

        xpub = ks['xpub']
        assert xpub[1:4] == 'pub'

        if xpub[0] in 'tx': 
            # no slip132 here

            got = BIP32Node.from_wallet_key(xpub)
            expect = BIP32Node.from_wallet_key(simulator_fixed_xprv).subkey_for_path(deriv[2:])

            assert got.sec() == expect.sec()

    os.unlink(path)

# EOF
