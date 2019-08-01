# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Multisig-related tests.
#
import time, pytest, os, random
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from ckcc.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from pprint import pprint, pformat
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom, fake_dest_addr, swab32, xfp2str
from struct import unpack, pack
from constants import *
from pycoin.key.BIP32Node import BIP32Node
from pycoin.encoding import a2b_hashed_base58
from io import BytesIO

def HARD(n=0):
    return 0x80000000 | n

def str2ipath(s):
    # convert text to numeric path for BIP174
    for i in s.split('/'):
        if i == 'm': continue
        if not i: continue      # trailing or duplicated slashes

        if i[-1] in "'ph":
            assert len(i) >= 2, i
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)
            assert 0 <= here < 0x80000000, here

        yield here


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

    # always BIP45:   m/45'/... (but no co-signer idx)

    def doit(M, N, unique=0):
        keys = []

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d - %d' % (i, unique), 'XTN')

            xfp = unpack("<I", pk.fingerprint())[0]

            sub = pk.subkey(45, is_hardened=True, as_private=True)
            keys.append((xfp, pk, sub))

        pk = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        keys.append((simulator_fixed_xfp, pk, pk.subkey(45, is_hardened=True, as_private=True)))

        return keys

    return doit

@pytest.fixture
def offer_ms_import(cap_story, dev, need_keypress):
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
def import_ms_wallet(dev, make_multisig, offer_ms_import, need_keypress):

    def doit(M, N, addr_fmt=None, name=None, unique=0, accept=False, common=None, keys=None):
        keys = keys or make_multisig(M, N, unique=unique)

        # render as a file for import
        name = name or f'test-{M}-{N}'
        config = f"name: {name}\npolicy: {M} / {N}\n\n"

        if addr_fmt:
            config += f'format: {addr_fmt.title()}\n'

        if common:
            config += f'derivation: {common}\n'

        config += '\n'.join('%s: %s' % (xfp2str(xfp), dd.hwif(as_private=False)) 
                                            for xfp, m, dd in keys)
        print(config)

        title, story = offer_ms_import(config)

        assert 'Create new multisig' in story
        assert name in story
        assert f'Policy: {M} of {N}\n' in story

        if accept:
            time.sleep(.1)
            need_keypress('y')

            # Test it worked.
            time.sleep(.1)      # required
            xor = 0
            for xfp, _, _ in keys:
                xor ^= xfp
            assert dev.send_recv(CCProtocolPacker.multisig_check(M, N, xor)) == 1

        return keys

    return doit


@pytest.mark.parametrize('N', [ 3, 15])
def test_ms_import_variations(N, make_multisig, clear_ms, offer_ms_import, need_keypress):
    # all the different ways...
    keys = make_multisig(N, N)

    # bare, no fingerprints
    # - no xfps
    # - no meta data
    config = '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
    title, story = offer_ms_import(config)
    assert f'Policy: {N} of {N}\n' in story
    need_keypress('x')

    # exclude myself (expect fail)
    config = '\n'.join(sk.hwif(as_private=False) 
                            for xfp,m,sk in keys if xfp != simulator_fixed_xfp)

    with pytest.raises(BaseException) as ee:
        title, story = offer_ms_import(config)
    assert 'my key not included' in str(ee.value)


    # normal names
    for name in [ 'Zy', 'Z'*20 ]:
        config = f'name: {name}\n'
        config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
        title, story = offer_ms_import(config)
        need_keypress('x')
        assert name in story

    # too long name
    config = 'name: ' + ('A'*21) + '\n'
    config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
    with pytest.raises(BaseException) as ee:
        title, story = offer_ms_import(config)
    assert '20 long' in str(ee.value)

    # comments, blank lines
    config = [sk.hwif(as_private=False) for xfp,m,sk in keys]
    for i in range(len(config)):
        config.insert(i, '# comment')
        config.insert(i, '')
    title, story = offer_ms_import('\n'.join(config))
    assert f'Policy: {N} of {N}\n' in story
    need_keypress('x')

    # the different addr formats
    for af in unmap_addr_fmt.keys():
        config = f'format: {af}\n'
        config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
        title, story = offer_ms_import(config)
        need_keypress('x')
        assert f'Policy: {N} of {N}\n' in story

def make_redeem(M, keys, path_mapper=None, violate_bip67=False, tweak_redeem=None):
    # Construct a redeem script, and ordered list of xfp+path to match.
    N = len(keys)

    assert path_mapper

    # see BIP 67: <https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki>

    data = []
    for cosigner_idx, (xfp, node, sk) in enumerate(keys):
        path = path_mapper(cosigner_idx)
        print("path: " + ' / '.join(hex(i) for i in path))

        if not node:
            # use xpubkey, otherwise master
            dpath = path[sk.tree_depth():]
            assert not dpath or max(dpath) < 1000
            node = sk
        else:
            dpath = path

        for p in dpath:
            node = node.subkey(p & ~0x80000000, is_hardened=bool(p & 0x80000000))

        pk = node.sec(use_uncompressed=False)
        data.append( (pk, xfp, path))

    data.sort(key=lambda i:i[0])

    if violate_bip67:
        # move them out of order
        data[0], data[1] = data[1], data[0]
    

    mm = [80 + M] if M <= 16 else [1, M]
    nn = [80 + N] if N <= 16 else [1, N]

    rv = bytes(mm)

    for pk,_,_ in data:
        rv += bytes([len(pk)]) + pk

    rv += bytes(nn + [0xAE])

    if tweak_redeem:
        rv = tweak_redeem(rv)

    #print("redeem script: " + B2A(rv))

    xfp_paths = [[xfp]+xpath for _,xfp,xpath in data]
    #print("xfp_paths: " + repr(xfp_paths))

    return rv, [pk for pk,_,_ in data], xfp_paths

def make_ms_address(M, keys, idx=0, is_change=0, addr_fmt=AF_P2SH, testnet=1, **make_redeem_args):
    # Construct addr and script need to represent a p2sh address
    import bech32
    from pycoin.encoding import b2a_hashed_base58, hash160
    from hashlib import sha256

    if 'path_mapper' not in make_redeem_args:
        make_redeem_args['path_mapper'] = lambda cosigner: [HARD(45), cosigner, is_change, idx]

    script, pubkeys, xfp_paths = make_redeem(M, keys, **make_redeem_args)

    if addr_fmt == AF_P2WSH:
        hrp = ['bc', 'tb'][testnet]
        data = sha256(script).digest()
        addr = bech32.encode(hrp, 0, data)
    else:
        if addr_fmt == AF_P2SH:
            digest = hash160(script)
        elif addr_fmt == AF_P2WSH_P2SH:
            digest = hash160(b'\x00\x20' + sha256(script).digest())
        else:
            assert 0

        prefix = bytes([196]) if testnet else bytes([5])
        addr = b2a_hashed_base58(prefix + digest)

    return addr, script, zip(pubkeys, xfp_paths)
    

@pytest.fixture
def test_ms_show_addr(dev, cap_story, need_keypress, addr_vs_path, bitcoind_p2sh):
    def doit(M, keys, addr_fmt=AF_P2SH, bip45=True, **make_redeem_args):
        # test we are showing addresses correctly
        # - verifies against bitcoind as well
        addr_fmt = unmap_addr_fmt.get(addr_fmt, addr_fmt)

        # make a redeem script, using provided keys/pubkeys
        if bip45:
            make_redeem_args['path_mapper'] = lambda i: [HARD(45), i, 0,0]

        scr, pubkeys, xfp_paths = make_redeem(M, keys, **make_redeem_args)
        assert len(scr) <= 520, "script too long for standard!"

        got_addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                                    M, xfp_paths, scr, addr_fmt=addr_fmt),
                                    timeout=None)

        title, story = cap_story()

        #print(story)

        assert got_addr in story
        assert all((xfp2str(xfp) in story) for xfp,_,_ in keys)
        if bip45:
            for i in range(len(keys)):
                assert ('/?/%d/0/0' % i) in story

        need_keypress('y')
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

    keys = import_ms_wallet(M, N, addr_fmt, accept=1)

    #print("imported: %r" % [x for x,_,_ in keys])

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        test_ms_show_addr(M, keys, addr_fmt=addr_fmt)

    finally:
        clear_ms()

def test_violate_bip67(clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr):
    # detect when pubkeys are not in order in the redeem script
    M, N = 1, 15

    keys = import_ms_wallet(M, N, accept=1)

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        with pytest.raises(BaseException) as ee:
            test_ms_show_addr(M, keys, violate_bip67=1)
        assert 'BIP67' in str(ee.value)
    finally:
        clear_ms()


@pytest.mark.parametrize('which_pubkey', [0, 1, 14])
def test_bad_pubkey(clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr, which_pubkey):
    # give incorrect pubkey inside redeem script
    M, N = 1, 15

    keys = import_ms_wallet(M, N, accept=1)

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        def tweaker(scr):
            return bytes((s if i != (5 + (34*which_pubkey)) else s^0x1) for i,s in enumerate(scr))

        with pytest.raises(BaseException) as ee:
            test_ms_show_addr(M, keys, tweak_redeem=tweaker)
        assert ('pk#%d wrong' % (which_pubkey+1)) in str(ee.value)
    finally:
        clear_ms()

def test_import_detail(clear_ms, import_ms_wallet, need_keypress, cap_story):
    # check all details are shown right

    M,N = 14, 15

    keys = import_ms_wallet(M, N)

    time.sleep(.2)
    need_keypress('1')

    time.sleep(.1)
    title, story = cap_story()

    assert title == f'{M} of {N}'
    xpubs = [sk.hwif() for _,_,sk in keys]
    for xp in xpubs:
        assert xp in story

    need_keypress('x')

    time.sleep(.1)
    need_keypress('x')


def test_export_airgap(goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path):
    # test UX and math for bip45 export
    import json

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')

    time.sleep(.1)
    title, story = cap_story()
    assert 'BIP45' in story
    assert "m/45'" in story
    assert "m/48'/" in story
    
    need_keypress('y')

    time.sleep(.1)
    title, story = cap_story()
    fname = story.split('\n')[-1]

    assert fname.startswith('ccxp-')
    assert fname.endswith('.json')

    with open(microsd_path(fname), 'rt') as fp:
        rv = json.load(fp)

    assert 'xfp' in rv
    assert len(rv) >= 7

    n = BIP32Node.from_wallet_key(rv['p2sh'])

    assert n.tree_depth() == 1
    assert n.child_index() == 45 | (1<<31)
    mxfp = unpack("<I", n.parent_fingerprint())[0]
    assert hex(mxfp) == hex(simulator_fixed_xfp)

    e = BIP32Node.from_wallet_key(simulator_fixed_xprv)
    expect = e.subkey_for_path("45'.pub") 
    assert expect.hwif() == n.hwif()

@pytest.mark.parametrize('N', [ 3, 15])
def test_import_ux(N, goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path, make_multisig):
    # test menu-based UX for importing wallet file from SD
    M = N-1

    keys = make_multisig(M, N)
    name = 'named-%d' % random.randint(10000,99999)
    config = f'policy: {M} of {N}\n'
    config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)

    fname = microsd_path(f'ms-{name}.txt')
    with open(fname, 'wt') as fp:
        fp.write(config)

    try:
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Import from SD')

        time.sleep(.1)
        _, story = cap_story()
        assert "Pick multisig wallet" in story
        need_keypress('y')

        time.sleep(.1)
        pick_menu_item(fname.rsplit('/', 1)[1])

        time.sleep(.1)
        _, story = cap_story()

        assert 'Create new multisig' in story
        assert name in story, 'didnt infer wallet name from filename'
        assert f'Policy: {M} of {N}\n' in story

        # abort install
        need_keypress('x')

    finally:
        # cleanup
        try: os.unlink(fname)
        except: pass
    
@pytest.mark.parametrize('addr_fmt', ['p2wsh-p2sh', 'p2sh', 'p2wsh' ])
def test_export_single_ux(goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path, import_ms_wallet, addr_fmt, clear_ms):

    # create a wallet, export to SD card, check file created.

    clear_ms()

    name = 'ex-test-%d' % random.randint(10000,99999)
    M,N = 3, 15
    keys = import_ms_wallet(M, N, name=name, addr_fmt=addr_fmt, accept=1)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')

    menu = cap_menu()
    item = [i for i in menu if name in i][0]
    pick_menu_item(item)

    pick_menu_item('Coldcard Export')

    time.sleep(.1)
    title, story = cap_story()
    fname = story.split('\n')[-1]
    assert fname, story
    fname = microsd_path(fname)

    try:
        got = set()
        with open(fname, 'rt') as fp:
            for ln in fp.readlines():
                ln = ln.strip()
                if '#' in ln:
                    assert ln[0] == '#'
                    continue
                if not ln:
                    continue

                assert ':' in ln
                label, value = ln.split(': ')

                if label == 'Name':
                    assert value == name
                    got.add(label)
                elif label == 'Policy':
                    assert value == f'{M} of {N}'
                    got.add(label)
                elif label == 'Derivation':
                    assert value == "m/45'"
                    got.add(label)
                elif label == 'Format':
                    assert value == addr_fmt.upper()
                    assert addr_fmt != 'p2sh'
                    got.add(label)
                else:
                    assert len(label) == 8, label
                    xfp = swab32(int(label, 16))
                    got.add(xfp)
                    assert xfp in [x for x,_,_ in keys]
                    n = BIP32Node.from_wallet_key(value)

        if 'Format' not in got:
            assert addr_fmt == 'p2sh'
            got.add('Format')

        assert len(got) == 4 + N

        time.sleep(.1)
        need_keypress('y')
    finally:
        os.unlink(fname)

    # test delete while we're here
    pick_menu_item('Delete')

    time.sleep(.2)
    _, story = cap_story()
    assert 'you SURE' in story
    assert name in story

    need_keypress('y')
    time.sleep(.1)
    menu = cap_menu()
    assert not [i for i in menu if name in i]
    assert '(none setup yet)' in menu


@pytest.mark.parametrize('N', [ 3, 15])
def test_overflow(N, import_ms_wallet, clear_ms, need_keypress, cap_story):
    clear_ms()
    M = N
    name = 'a'*20       # longest possible
    for count in range(1, 10):
        keys = import_ms_wallet(M, N, name=name, addr_fmt='p2wsh', unique=count, accept=0)

        time.sleep(.1)
        need_keypress('y')

        time.sleep(.2)
        title, story = cap_story()
        if title or story:
            print(f'Failed with {count} @ {N} keys each')
            assert 'No space left' in story
            break

    if N == 3:
        assert count == 9, "Expect fail at 9"
    if N == 15:
        assert count == 2, "Expect fail at 2"

    need_keypress('y')
    clear_ms()

@pytest.mark.parametrize('N', [ 3, 15])
def test_make_example_file(N, microsd_path, make_multisig, addr_fmt=None):
    M=3
    keys = make_multisig(M, N)

    # render as a file for import
    name = f'sample-{M}-{N}'
    config = f"name: {name}\npolicy: {M} / {N}\n\n"

    if addr_fmt:
        config += f'format: {addr_fmt.upper()}\n'

    config += '\n'.join('%s: %s' % (xfp2str(xfp), sk.hwif(as_private=False)) 
                                        for xfp,m,sk in keys)

    fname = microsd_path(f'{name}.txt')
    with open(fname, 'wt') as fp:
        fp.write(config+'\n')

    print(f"Created: {fname}")

@pytest.mark.parametrize('num_diff', [ 1, 5])
@pytest.mark.parametrize('N', [ 5, 15])
def test_import_dup_safe(N, clear_ms, make_multisig, offer_ms_import, need_keypress, cap_story, goto_home, pick_menu_item, cap_menu, num_diff):
    M = N

    clear_ms()

    keys = make_multisig(M, N)

    # render as a file for import
    def make_named(name):
        config = f"name: {name}\npolicy: {M} / {N}\n\n"
        config += '\n'.join('%s: %s' % (xfp2str(xfp), sk.hwif(as_private=False)) 
                                        for xfp,m,sk in keys)
        return config

    def check_named(name):
        # check worked: look in menu for name
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')

        menu = cap_menu()
        assert menu[0] == f'{M}/{N}: {name}'
        assert len(menu) == 5

    title, story = offer_ms_import(make_named('xxx-orig'))
    assert 'xxx-orig' in story
    need_keypress('y')
    check_named('xxx-orig')

    # just simple rename
    title, story = offer_ms_import(make_named('xxx-new'))
    assert 'Update' in story
    assert 'xxx-new' in story

    need_keypress('y')
    check_named('xxx-new')

    # hack up a bogus import
    for count, (xfp,_,_) in enumerate(keys):
        if count == num_diff: break
        keys[count][2]._chain_code = bytes(i^0xa5 for i in keys[count][2]._chain_code)

    title, story = offer_ms_import(make_named('xxx-hacked'))
    assert f'{num_diff} different' in story
    assert 'caution' in story.lower()
    assert 'danger' in story.lower()
    assert 'xxx-hacked' in story

    need_keypress('y')
    check_named('xxx-hacked')

    clear_ms()

@pytest.mark.parametrize('N', [ 3, 15])
def test_duplicate_xfp(N, offer_ms_import, need_keypress, test_ms_show_addr):
    # it's legit to have duplicate XFP values! Not hard to make either!

    # new wallet will all having same XFP, but different xpubs
    pk = BIP32Node.from_wallet_key(simulator_fixed_xprv)

    keys = [(simulator_fixed_xfp, pk, pk.subkey(45, is_hardened=True, as_private=False))]
    lst = [keys[0][-1]]
    for idx in range(N-1):
        h = BIP32Node.from_hwif(pk.hwif(as_private=True))        # deepcopy
        h._chain_code = b'chain code is 32 bytes: %08d' % idx
        subkey = h.subkey(45, is_hardened=True, as_private=False)
        lst.append(subkey)

        xfp = unpack("<I", pk.fingerprint())[0]
        keys.append( (xfp, h, subkey) )

    #print(lst)

    # bare, no fingerprints
    # - no xfps
    # - no meta data
    config = '\n'.join(sk.hwif(as_private=False) for sk in lst)
    title, story = offer_ms_import(config)
    assert f'Policy: {N} of {N}\n' in story
    need_keypress('y')

    test_ms_show_addr(N, keys)

@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH] )
def test_ms_cli(dev, addr_fmt, clear_ms, import_ms_wallet, addr_vs_path, M=1, N=3):
    # exercise the p2sh command of ckcc:cli ... hard to do manually.

    from subprocess import check_output

    clear_ms()
    keys = import_ms_wallet(M, N, name='cli-test', accept=1)

    pmapper = lambda i: [HARD(45), i, 0,0]

    scr, pubkeys, xfp_paths = make_redeem(M, keys, pmapper)

    def decode_path(p):
        return '/'.join(str(i) if i < 0x80000000 else "%d'"%(i& 0x7fffffff) for i in p)

    if 1:
        args = ['ckcc']
        if dev.is_simulator:
            args += ['-x']

        args += ['p2sh', '-q']

        if addr_fmt == AF_P2WSH:
            args += ['-s']
        elif addr_fmt == AF_P2WSH_P2SH:
            args += ['-s', '-w']

        args += [B2A(scr)]
        args += [xfp2str(x)+'/'+decode_path(path) for x,*path in xfp_paths]

        import shlex
        print('CMD: ' + (' '.join(shlex.quote(i) for i in args)))

        addr = check_output(args, encoding='ascii').strip()

        print(addr)
        addr_vs_path(addr, addr_fmt=addr_fmt, script=scr)

        # test case for make_ms_address really.
        expect_addr, scr2, _ = make_ms_address(M, keys, path_mapper=pmapper, addr_fmt=addr_fmt)
        assert expect_addr == addr
        assert scr2 == scr
        

    # need to re-start our connection once ckcc has talked to simulator
    dev.start_encryption()
    dev.check_mitm()

    clear_ms()

from test_bip39pw import set_bip39_pw

@pytest.fixture()
def make_myself_wallet(dev, set_bip39_pw, offer_ms_import, need_keypress, clear_ms):

    # construct a wallet (M of 4) using different bip39 passwords, and default sim
    def doit(M, addr_fmt=None, do_import=True):
        passwords = ['Me', 'Myself', 'And I', '']

        if 0:
            # WORKING, but slow .. and it's constant data
            keys = []
            for pw in passwords:
                xfp = set_bip39_pw(pw)

                sk = dev.send_recv(CCProtocolPacker.get_xpub("m/45'"))
                node = BIP32Node.from_wallet_key(sk)

                keys.append((xfp, None, node))

            assert len(set(x for x,_,_ in keys)) == 4, keys
            pprint(keys)
        else:
            # Much, FASTER!
            assert dev.is_simulator
            keys = [(3503269483, None,
                        BIP32Node.from_hwif('tpubD9429UXFGCTKJ9NdiNK4rC5ygqSUkginycYHccqSg5gkmyQ7PZRHNjk99M6a6Y3NY8ctEUUJvCu6iCCui8Ju3xrHRu3Ez1CKB4ZFoRZDdP9')),
                     (2389277556, None,
                        BIP32Node.from_hwif('tpubD97nVL37v5tWyMf9ofh5rznwhh1593WMRg6FT4o6MRJkKWANtwAMHYLrcJFsFmPfYbY1TE1LLQ4KBb84LBPt1ubvFwoosvMkcWJtMwvXgSc')),
                 (3190206587, None,
                        BIP32Node.from_hwif('tpubD9ArfXowvGHnuECKdGXVKDMfZVGdephVWg8fWGWStH3VKHzT4ph3A4ZcgXWqFu1F5xGTfxncmrnf3sLC86dup2a8Kx7z3xQ3AgeNTQeFxPa')),
                (1130956047, None,
                        BIP32Node.from_hwif('tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n')),
            ]

        if do_import:
            # render as a file for import
            config = f"name: Myself-{M}\npolicy: {M} / 4\n\n"

            if addr_fmt:
                config += f'format: {addr_fmt.upper()}\n'

            config += '\n'.join('%s: %s' % (xfp2str(xfp), sk.hwif()) for xfp, _, sk in keys)
            #print(config)

            title, story = offer_ms_import(config)
            #print(story)

            # dont care if update or create; accept it.
            time.sleep(.1)
            need_keypress('y')

        def select_wallet(idx):
            # select to specific pw
            xfp = set_bip39_pw(passwords[idx])
            assert xfp == keys[idx][0]

        return (keys, select_wallet)

    yield  doit

    set_bip39_pw('')


@pytest.fixture()
def fake_ms_txn():
    # make various size MULTISIG txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    from pycoin.tx.Tx import Tx
    from pycoin.tx.TxIn import TxIn
    from pycoin.tx.TxOut import TxOut
    from pycoin.serialize import h2b_rev
    from pycoin.encoding import hash160
    from struct import pack

    def doit(num_ins, num_outs, M, keys, fee=10000,
                outvals=None, segwit_in=False, outstyles=['p2pkh'], change_outputs=[],
                incl_xpubs=False):
        psbt = BasicPSBT()
        txn = Tx(2,[],[])

        if incl_xpubs:
            # add global header with XPUB's
            # - assumes BIP45
            for xfp, m, sk in keys:
                kk = pack('<II', xfp, 45|0x80000000)
                psbt.xpubs.append( (sk.serialize(as_private=False), kk) )

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        for i in range(num_ins):
            # make a fake txn to supply each of the inputs
            # - each input is 1BTC

            # addr where the fake money will be stored.
            addr, script, details = make_ms_address(M, keys, idx=i)

            # lots of supporting details needed for p2sh inputs
            if segwit_in:
                psbt.inputs[i].witness_script = script
            else:
                psbt.inputs[i].redeem_script = script

            for pubkey, xfp_path in details:
                psbt.inputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)

            # UTXO that provides the funding for to-be-signed txn
            supply = Tx(2,[TxIn(pack('4Q', 0xdead, 0xbeef, 0, 0), 73)],[])

            # sciptPubKey for input's output
            pks = bytes([0xa9, 0x14]) + hash160(script) + bytes([0x87])

            supply.txs_out.append(TxOut(1E8, pks))

            with BytesIO() as fd:
                if not segwit_in:
                    supply.stream(fd)
                    psbt.inputs[i].utxo = fd.getvalue()
                else:
                    supply.txs_out[-1].stream(fd)
                    psbt.inputs[i].witness_utxo = fd.getvalue()

            spendable = TxIn(supply.hash(), 0)
            txn.txs_in.append(spendable)


        for i in range(num_outs):
            # random P2PKH
            if not outstyles:
                style = ADDR_STYLES[i % len(ADDR_STYLES)]
            else:
                style = outstyles[i % len(outstyles)]

            if i in change_outputs:
                addr, scr, details = make_ms_address(M, keys, idx=i)

                for pubkey, xfp_path in details:
                    psbt.outputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)
            else:
                scr = fake_dest_addr(style)

            assert scr

            if 'w' in style:
                psbt.outputs[i].witness_script = scr
            elif style.endswith('sh'):
                psbt.outputs[i].redeem_script = scr

            if not outvals:
                h = TxOut(round(((1E8*num_ins)-fee) / num_outs, 4), scr)
            else:
                h = TxOut(outvals[i], scr)

            txn.txs_out.append(h)

        with BytesIO() as b:
            txn.stream(b)
            psbt.txn = b.getvalue()

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH] )
@pytest.mark.parametrize('num_ins', [ 2, 7, 15 ])
@pytest.mark.parametrize('incl_xpubs', [ False, True ])
def test_ms_sign_simple(num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet, addr_vs_path, fake_ms_txn, try_sign, M=1, N=3):
    
    num_outs = num_ins-1

    clear_ms()
    keys = import_ms_wallet(M, N, name='cli-test', accept=1)

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, incl_xpubs=incl_xpubs)

    open('debug/last.psbt', 'wb').write(psbt)

    try_sign(psbt)

@pytest.mark.parametrize('num_ins', [ 15 ])
@pytest.mark.parametrize('M', [ 2, 4, 1 ])
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('incl_xpubs', [ True, False ])
def test_ms_sign_myself(M, make_myself_wallet, segwit, num_ins, dev, clear_ms, 
        fake_ms_txn, try_sign, bitcoind_finalizer, incl_xpubs, bitcoind_analyze, bitcoind_decode):

    # IMPORTANT: wont work if you start simulator with -m flag. Use no args

    num_outs = 2

    clear_ms()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, do_import=(not incl_xpubs))
    N = len(keys)

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, segwit_in=segwit, incl_xpubs=incl_xpubs)

    open(f'debug/myself-before.psbt', 'wb').write(psbt)
    for idx in range(M):
        select_wallet(idx)
        _, updated = try_sign(psbt, accept_ms_import=(incl_xpubs and (idx==0)))
        open(f'debug/myself-after.psbt', 'wb').write(updated)
        assert updated != psbt

        aft = BasicPSBT().parse(updated)

        # check all inputs gained a signature
        assert all(len(i.part_sigs)==(idx+1) for i in aft.inputs)

        psbt = updated

    # should be fully signed now.
    anal = bitcoind_analyze(aft.as_bytes())

    try:
        assert not any(inp.get('missing') for inp in anal['inputs']), "missing sigs: %r" % anal
        assert all(inp['next'] in {'finalizer','updater'} for inp in anal['inputs']), "other issue: %r" % anal
    except:
        # XXX seems to be a bug in analyzepsbt function ... not fully studied
        pprint(anal, stream=open('debug/analyzed.txt', 'wt'))
        decode = bitcoind_decode(aft.as_bytes())
        pprint(decode, stream=open('debug/decoded.txt', 'wt'))
    
        if M==N or segwit:
            # as observed, bug not trigged, so raise if it *does* happen
            raise
        else:
            print("ignoring bug in bitcoind")

    if 0:
        # why doesn't this work?
        extracted_psbt, txn, is_complete = bitcoind_finalizer(aft.as_bytes(), extract=True)

        ex = BasicPSBT().parse(extracted_psbt)
        assert is_complete
        assert ex != aft

@pytest.mark.parametrize('addr_fmt', ['p2wsh', 'p2wsh-p2sh', 'p2sh'])
#@pytest.mark.parametrize('N', [3, 4, 14])
def test_make_airgapped(addr_fmt, goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path, set_bip39_pw, clear_ms, N=4):
    # test UX and math for bip45 export

    # cleanup
    from glob import glob
    for fn in glob(microsd_path('ccxp-*.json')):
        assert fn
        os.unlink(fn)
    clear_ms()

    for idx in range(N):
        if N == 4:
            set_bip39_pw(['Me', 'Myself', 'And I', ''][idx])
        else:
            set_bip39_pw(f'test {idx}' if idx else '')

        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Export XPUB')
        time.sleep(.05)
        need_keypress('y')
        need_keypress('y')

    set_bip39_pw('')

    assert len(glob(microsd_path('ccxp-*.json'))) == N

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Create Airgapped')
    time.sleep(.05)
    title, story = cap_story()
    assert 'XPUB' in story

    if addr_fmt == 'p2wsh':
        need_keypress('y')
    elif addr_fmt == 'p2wsh-p2sh':
        need_keypress('1')
    elif addr_fmt == 'p2sh':
        need_keypress('2')
    else:
        assert 0, addr_fmt

    time.sleep(.1)
    title, story = cap_story()

    assert ('(N=%d #files=%d' % (N, N)) in story

    if N == 3:
        assert '2 of 3' in story
        M = 2
    elif N == 14:
        assert '8 of 14' in story
        M = 8
    elif N == 4:
        assert '3 of 4' in story
        need_keypress('7')
        time.sleep(.05)
        title, story = cap_story()
        assert '2 of 4' in story
        M = 2
    else:
        assert 0, N

    need_keypress('y')

    time.sleep(.1)
    title, story = cap_story()

    assert "Create new multisig" in story
    need_keypress('y')

    # writes out ckcc config file, then electrum wallet
    time.sleep(.1)
    title, story = cap_story()
    print(repr(story))
    assert 'Coldcard' in story
    assert 'that file onto the other Coldcards involved' in story
    fname = story.split('\n')[2]
    cc_fname = microsd_path(fname)

    impf = open(cc_fname, 'rt').read()
    assert f'Policy: {M} of {N}' in impf
    if addr_fmt != 'p2sh':
        assert f'Format: {addr_fmt.upper()}' in impf

    need_keypress('y')
    time.sleep(.1)
    title, story = cap_story()
    fname = story.split('\n')[-1]
    assert fname.startswith('el-')
    assert fname.endswith('.json')
    el_fname = microsd_path(fname)

    import json
    wal = json.load(open(el_fname, 'rt'))
    assert f'{M}of{N}' in wal['wallet_type']

    need_keypress('y')
    need_keypress('y')
    
    clear_ms()

    if N == 4:
        import shutil

        # capture useful test data for testing Electrum plugin, etc
        for fn in glob(microsd_path('ccxp-*.json')):
            shutil.copy(fn, 'data/multisig/'+fn.rsplit('/', 1)[1])
        shutil.copy(el_fname, f'data/multisig/el-{addr_fmt}-myself.json')
        shutil.copy(cc_fname, f'data/multisig/export-{addr_fmt}-myself.txt')

    # test re-importing the wallet from export file
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Import from SD')
    time.sleep(.05)
    need_keypress('y')
    time.sleep(.05)
    pick_menu_item(cc_fname.rsplit('/', 1)[1])

    time.sleep(.05)
    title, story = cap_story()
    assert "Create new multisig" in story
    assert f"Policy: {M} of {N}" in story

    need_keypress('1')
    time.sleep(.05)
    title, story = cap_story()
    # test code ehre

    # abort import, good enough
    need_keypress('x')
    need_keypress('x')


@pytest.mark.parametrize('addr_style', ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.bitcoind
def test_bitcoind_cosigning(dev, bitcoind, start_sign, end_sign, import_ms_wallet, clear_ms, explora, try_sign, need_keypress, addr_style):
    # Make a P2SH wallet with local bitcoind as a co-signer (and simulator)
    # - send an receive various
    # - following text of <https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md>
    # - the constructed multisig walelt will only work for a single pubkey on core side
    # - before starting this test, have some funds already deposited to bitcoind testnet wallet
    from pycoin.encoding import sec_to_public_pair
    from binascii import a2b_hex
    import re

    if addr_style == 'legacy':
        addr_fmt = AF_P2SH
    elif addr_style == 'p2sh-segwit':
        addr_fmt = AF_P2WSH_P2SH
    elif addr_style == 'bech32':
        addr_fmt = AF_P2WSH
    
    try:
        addr, = bitcoind.getaddressesbylabel("sim-cosign").keys()
    except:
        addr = bitcoind.getnewaddress("sim-cosign")

    info = bitcoind.getaddressinfo(addr)
    #pprint(info)

    assert info['address'] == addr
    bc_xfp = swab32(int(info['hdmasterfingerprint'], 16))
    bc_deriv = info['hdkeypath']        # example: "m/0'/0'/3'"
    bc_pubkey = info['pubkey']          # 02f75ae81199559c4aa...

    pp = sec_to_public_pair(a2b_hex(bc_pubkey))

    # No means to export XPUB from bitcoind! Still. In 2019.
    # - this fake will only work for for one pubkey value, the first/topmost
    node = BIP32Node('XTN', b'\x23'*32, depth=len(bc_deriv.split('/'))-1,
                        parent_fingerprint=a2b_hex('%08x' % bc_xfp), public_pair=pp)

    keys = [
        (bc_xfp, None, node),
        (1130956047, None, BIP32Node.from_hwif('tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n')),     # simulator: m/45'
    ]

    M,N=2,2

    clear_ms()
    import_ms_wallet(M, N, keys=keys, accept=1, name="core-cosign")

    cc_deriv = "m/45'/55"
    cc_pubkey = B2A(BIP32Node.from_hwif(simulator_fixed_xprv).subkey_for_path(cc_deriv[2:]).sec())

    

    # NOTE: bitcoind doesn't seem to implement pubkey sorting. We have to do it.
    resp = bitcoind.addmultisigaddress(M, list(sorted([cc_pubkey, bc_pubkey])),
                                                'shared-addr-'+addr_style, addr_style)
    ms_addr = resp['address']
    bc_redeem = a2b_hex(resp['redeemScript'])

    assert bc_redeem[0] == 0x52

    def mapper(cosigner_idx):
        return list(str2ipath(cc_deriv if cosigner_idx else bc_deriv))

    scr, pubkeys, xfp_paths = make_redeem(M, keys, mapper)

    assert scr == bc_redeem

    # check Coldcard calcs right address to match
    got_addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                                M, xfp_paths, scr, addr_fmt=addr_fmt), timeout=None)
    assert got_addr == ms_addr
    time.sleep(.1)
    need_keypress('x')      # clear screen / start over

    print(f"Will be signing an input from {ms_addr}")

    if xfp2str(bc_xfp) in ('5380D0ED', 'EDD08053'):
        # my own expected values
        assert ms_addr in ( '2NDT3ymKZc8iMfbWqsNd1kmZckcuhixT5U4',
                            '2N1hZJ5mazTX524GQTPKkCT4UFZn5Fqwdz6',
                            'tb1qpcv2rkc003p5v8lrglrr6lhz2jg8g4qa9vgtrgkt0p5rteae5xtqn6njw9')

    # Need some UTXO to sign
    #
    # - but bitcoind can't give me that (using listunspent) because it's only a watched addr??
    #
    did_fund = False
    while 1:
        rr = explora('address', ms_addr, 'utxo')
        pprint(rr)

        avail = []
        amt = 0
        for i in rr:
            txn = i['txid']
            vout = i['vout']
            avail.append( (txn, vout) )
            amt += i['value']

            # just use first UTXO available; save other for later tests
            break

        else:
            # doesn't need to confirm, but does need to reach public testnet/blockstream
            assert not amt and not avail

            if not did_fund:
                print(f"Sending some XTN to {ms_addr}  (wait)")
                bitcoind.sendtoaddress(ms_addr, 0.0001, 'fund testing')
                did_fund = True
            else:
                print(f"Still waiting ...")

            time.sleep(2)

        if amt: break

    ret_addr = bitcoind.getrawchangeaddress()

    ''' If you get insufficent funds, even tho we provide the UTXO (!!), do this:

            bitcoin-cli importaddress "2NDT3ymKZc8iMfbWqsNd1kmZckcuhixT5U4" true true

        Better method: always fund addresses for testing here from same wallet (ie.
        got from non-multisig to multisig on same bitcoin-qt instance).
        -> Now doing that, automated, above.
    '''
    resp = bitcoind.walletcreatefundedpsbt([dict(txid=t, vout=o) for t,o in avail],
               [{ret_addr: amt/1E8}], 0,
                {'subtractFeeFromOutputs': [0], 'includeWatching': True}, True)

    assert resp['changepos'] == -1
    psbt = b64decode(resp['psbt'])

    open('debug/funded.psbt', 'wb').write(psbt)

    # patch up the PSBT a little ... bitcoind doesn't know the path for the CC's key
    ex = BasicPSBT().parse(psbt)
    cxpk = a2b_hex(cc_pubkey)
    for i in ex.inputs:
        assert cxpk in i.bip32_paths, 'input not to be signed by CC?'
        i.bip32_paths[cxpk] = pack('<3I', keys[1][0], *str2ipath(cc_deriv))

    psbt = ex.as_bytes()

    open('debug/patched.psbt', 'wb').write(psbt)

    _, updated = try_sign(psbt, finalize=False)

    open('debug/cc-updated.psbt', 'wb').write(updated)

    # have bitcoind do the rest of the signing
    rr = bitcoind.walletprocesspsbt(b64encode(updated).decode('ascii'))
    pprint(rr)

    open('debug/bc-processed.psbt', 'wt').write(rr['psbt'])
    assert rr['complete']

    # finalize and send
    rr = bitcoind.finalizepsbt(rr['psbt'], True)
    open('debug/bc-final-txn.txn', 'wt').write(rr['hex'])
    assert rr['complete']

    txn_id = bitcoind.sendrawtransaction(rr['hex'])
    print(txn_id)


# EOF
