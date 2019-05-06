# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Multisig-related tests.
#
import time, pytest, os
#from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from ckcc.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from binascii import b2a_hex, a2b_hex
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from io import BytesIO
from pprint import pprint, pformat
from decimal import Decimal
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom
import struct

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    return b2a_hex(struct.pack('>I', xfp)).decode('ascii').upper()

@pytest.fixture
def clear_ms(unit_test):
    def doit():
        unit_test('devtest/wipe_ms.py')
    return doit

@pytest.fixture()
def make_multisig():
    # make a multsig wallet, always with simulator as an element
    from pycoin.key.BIP32Node import BIP32Node
    from struct import unpack
    from conftest import simulator_fixed_xprv, simulator_fixed_xfp

    # always BIP45:   m/45'/...

    def doit(M, N):
        keys = {}

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d' % i, 'XTN')

            xfp = unpack(">I", pk.fingerprint())[0]

            sub = pk.subkey(45, is_hardened=True, as_private=True)
            keys[xfp] = pk, sub

        pk = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        keys[simulator_fixed_xfp] = pk, pk.subkey(45, is_hardened=True, as_private=True)

        return keys

    return doit

@pytest.fixture
def import_ms_wallet(dev, make_multisig, cap_story):

    def doit(M, N):
        keys = make_multisig(M, N)

        # render as a file for import
        name = f'test-{M}-{N}'
        config = f"name: {name}\npolicy: {M} / {N}\n\n"

        config += '\n'.join('%s: %s' % (xfp2str(k), dd.hwif()) 
                                            for k, (m, dd) in keys.items())
        #print(config)

        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('ascii'))

        dev.send_recv(CCProtocolPacker.multisig_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        #print(repr(story))

        assert 'Create new multisig' in story
        assert name in story
        assert f'Policy: {M} of {N}\n' in story

        return keys

    return doit

@pytest.mark.parametrize('m_of_n', [ (1,3), (2,3), (3,3), (10, 15), (16,16),
                                        (1, 20), (17, 20), (20,20) ])
@pytest.mark.parametrize('segwit', [True, False])
def test_import_ranges(m_of_n, segwit, clear_ms, import_ms_wallet, need_keypress):

    M, N = m_of_n

    # TODO: segwit

    import_ms_wallet(M, N)

    time.sleep(.1)
    need_keypress('y')

    # test an address that should be in that wallet.

    # cleanup
    clear_ms()

def test_import_detail(clear_ms, import_ms_wallet, need_keypress, cap_story):
    # check all details are shown right

    M,N = 19, 20

    keys = import_ms_wallet(M, N)

    time.sleep(.1)
    need_keypress('2')

    time.sleep(.1)
    title, story = cap_story()

    assert title == f'{M} of {N}'
    xpubs = [b.hwif() for a,b in keys.values()]
    for xp in xpubs:
        assert xp in story

    need_keypress('x')

    time.sleep(.1)
    need_keypress('x')


# TODO
# - test overflow during import
# - duplicate imports

# EOF
