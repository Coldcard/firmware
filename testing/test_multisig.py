# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Multisig-related tests.
#
import time, pytest, os
#from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from ckcc.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from pprint import pprint, pformat
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom
from ckcc_protocol.constants import AF_P2WSH, AFC_SCRIPT, AF_P2SH, AF_P2WSH_P2SH
from struct import unpack, pack
from conftest import simulator_fixed_xprv, simulator_fixed_xfp

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    from binascii import b2a_hex
    return b2a_hex(pack('>I', xfp)).decode('ascii').upper()

def HARD(n=0):
    return 0x80000000 | n

unmap_addr_fmt = {
    'p2sh': AF_P2SH,
    'p2wsh': AF_P2WSH,
    'p2wsh-p2sh': AF_P2WSH_P2SH,
}

@pytest.fixture()
def bitcoind_p2sh(bitcoind):
    # Use bitcoind to generate a p2sh addres based on public keys.

    def doit(M, pubkeys, fmt):

        fmt = {
            AF_P2SH: 'legacy',
            AF_P2WSH: 'bech32',
            AF_P2WSH_P2SH: 'p2sh-segwit'
        }[fmt]

        try:
            rv = bitcoind.createmultisig(M, [B2A(i) for i in pubkeys], fmt)
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            rv = bitcoind.createmultisig(M, [B2A(i) for i in pubkeys], fmt)

        return rv['address'], rv['redeemScript']

    return doit

@pytest.fixture
def clear_ms(unit_test):
    def doit():
        unit_test('devtest/wipe_ms.py')
    return doit

@pytest.fixture()
def make_multisig():
    # make a multsig wallet, always with simulator as an element
    from pycoin.key.BIP32Node import BIP32Node

    # always BIP45:   m/45'/...

    def doit(M, N):
        keys = {}

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d' % i, 'XTN')

            xfp = unpack("<I", pk.fingerprint())[0]

            sub = pk.subkey(45, is_hardened=True, as_private=True)
            keys[xfp] = pk, sub

        pk = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        keys[simulator_fixed_xfp] = pk, pk.subkey(45, is_hardened=True, as_private=True)

        return keys

    return doit

@pytest.fixture
def offer_import(cap_story, dev):
    def doit(config):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('ascii'))

        dev.send_recv(CCProtocolPacker.multisig_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        #print(repr(story))

        return title, story

    return doit

@pytest.fixture
def import_ms_wallet(dev, make_multisig, offer_import):

    def doit(M, N, addr_fmt=None):
        keys = make_multisig(M, N)

        # render as a file for import
        name = f'test-{M}-{N}'
        config = f"name: {name}\npolicy: {M} / {N}\n\n"

        if addr_fmt:
            config += f'format: {addr_fmt.upper()}\n'

        config += '\n'.join('%s: %s' % (xfp2str(k), dd.hwif(as_private=False)) 
                                            for k, (m, dd) in keys.items())
        #print(config)

        title, story = offer_import(config)

        assert 'Create new multisig' in story
        assert name in story
        assert f'Policy: {M} of {N}\n' in story

        return keys

    return doit


@pytest.mark.parametrize('N', [ 3, 15])
def test_ms_import_variations(N, make_multisig, clear_ms, offer_import, need_keypress):
    # all the different ways...
    keys = make_multisig(N, N)

    # bare, no fingerprints
    # - no xfps
    # - no meta data
    config = '\n'.join(sk.hwif(as_private=False) for m,sk in keys.values())
    title, story = offer_import(config)
    assert f'Policy: {N} of {N}\n' in story
    need_keypress('x')

    # exclude myself (expect fail)
    config = '\n'.join(sk.hwif(as_private=False) 
                            for xfp,(m,sk) in keys.items() if xfp != simulator_fixed_xfp)

    with pytest.raises(BaseException) as ee:
        title, story = offer_import(config)
    assert 'my key not included' in str(ee.value)


    # normal names
    for name in [ 'Zy', 'Z'*20 ]:
        config = f'name: {name}\n'
        config += '\n'.join(sk.hwif(as_private=False) for m,sk in keys.values())
        title, story = offer_import(config)
        need_keypress('x')
        assert name in story

    # too long name
    config = 'name: ' + ('A'*21) + '\n'
    config += '\n'.join(sk.hwif(as_private=False) for m,sk in keys.values())
    with pytest.raises(BaseException) as ee:
        title, story = offer_import(config)
    assert '20 long' in str(ee.value)

    # comments, blank lines
    config = [sk.hwif(as_private=False) for m,sk in keys.values()]
    for i in range(len(config)):
        config.insert(i, '# comment')
        config.insert(i, '')
    title, story = offer_import('\n'.join(config))
    assert f'Policy: {N} of {N}\n' in story
    need_keypress('x')

    # the different addr formats
    for af in unmap_addr_fmt.keys():
        config = f'format: {af}\n'
        config += '\n'.join(sk.hwif(as_private=False) for m,sk in keys.values())
        title, story = offer_import(config)
        need_keypress('x')
        assert f'Policy: {N} of {N}\n' in story

def make_redeem(M, keys, paths):
    N = len(keys)

    # see BIP 67: <https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki>

    pubkeys = []
    for xfp in keys:
        node = keys[xfp][0]     # master root key
        path = paths[xfp]

        print(xfp2str(xfp),end=': ')

        for p in path:
            node = node.subkey(p & ~0x80000000, is_hardened=bool(p & 0x80000000))
            if p == 2147483693:
                assert node == keys[xfp][1]

        pk = node.sec(use_uncompressed=False)
        pubkeys.append(pk)
        #print(f"{xfp2str(xfp)} {path} => {B2A(pk)}")

    pubkeys.sort()

    mm = [80 + M] if M <= 16 else [1, M]
    nn = [80 + N] if N <= 16 else [1, N]

    rv = bytes(mm)

    for pk in pubkeys:
        rv += bytes([len(pk)]) + pk

    rv += bytes(nn + [0xAE])

    print("redeem script: " + B2A(rv))

    return rv, pubkeys
        
    

@pytest.fixture
def test_ms_show_addr(dev, cap_story, need_keypress, addr_vs_path, bitcoind_p2sh):
    def doit(M, keys, subpath=[1,2,3], addr_fmt=AF_P2SH):
        # test we are showing addresses correctly
        addr_fmt = unmap_addr_fmt.get(addr_fmt, addr_fmt)

        # limitation: assume BIP45 here, but don't do cosigner index
        paths = [[xfp, HARD(45)] + subpath for xfp in keys]

        got_addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                                        M, paths, addr_fmt), timeout=None)

        title, story = cap_story()

        #print(story)

        assert got_addr in story
        assert all((xfp2str(i) in story) for i in keys)
        assert '/?/'+'/'.join(str(i) for i in subpath) in story

        need_keypress('y')

        # re-calc redeem script
        print(repr(paths))
        scr, pubkeys = make_redeem(M, keys, dict((a,b) for a,*b in paths))
        assert len(scr) <= 520, "script too long for standard!"

        # check expected addr was generated based on my math
        addr_vs_path(got_addr, addr_fmt=addr_fmt, script=scr)

        # also check against bitcoind
        core_addr, core_scr = bitcoind_p2sh(M, pubkeys, addr_fmt)
        assert B2A(scr) == core_scr
        assert core_addr == got_addr


    return doit
    

@pytest.mark.parametrize('m_of_n', [(1,3), (2,3), (3,3), (3,6), (10, 15), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2wsh-p2sh', 'p2sh', 'p2wsh' ])
def test_import_ranges(m_of_n, addr_fmt, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr):

    M, N = m_of_n

    #if addr_fmt == 'p2wsh-p2sh':
        #raise pytest.xfail('not done')

    keys = import_ms_wallet(M, N, addr_fmt)

    time.sleep(.1)
    need_keypress('y')

    # test an address that should be in that wallet.
    time.sleep(.1)
    test_ms_show_addr(M, keys, addr_fmt=addr_fmt)

    # cleanup
    clear_ms()

def test_import_detail(clear_ms, import_ms_wallet, need_keypress, cap_story):
    # check all details are shown right

    M,N = 14, 15

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


def test_export_bip45_multisig(goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path):
    # test UX and math for bip45 export
    from pycoin.key.BIP32Node import BIP32Node

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BIP45 Export')

    time.sleep(.1)
    title, story = cap_story()
    assert 'BIP45' in title
    assert 'BIP45' in story
    assert "m/45'" in story
    
    need_keypress('y')

    time.sleep(.1)
    title, story = cap_story()
    fname = story.split('\n')[-1]

    with open(microsd_path(fname), 'rt') as fp:
        xpub = fp.read().strip()

        n = BIP32Node.from_wallet_key(xpub)

    assert n.tree_depth() == 1
    assert n.child_index() == 45 | (1<<31)
    mxfp = unpack("<I", n.parent_fingerprint())[0]
    assert hex(mxfp) == hex(simulator_fixed_xfp)

    e = BIP32Node.from_wallet_key(simulator_fixed_xprv)
    expect = e.subkey_for_path("45'.pub") 
    assert expect.hwif() == n.hwif()



# TODO
# - test nvram overflow during import
# - duplicate imports

# EOF
