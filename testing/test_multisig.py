# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Multisig-related tests.
#
# After this file passes, also run again like this:
#
#       py.test test_multisig.py -m ms_danger --ms-danger
#
import time, pytest, os, random, json, shutil, pdb
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput, PSBT_IN_REDEEM_SCRIPT
from ckcc.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from pprint import pprint, pformat
from base64 import b64encode, b64decode
from helpers import B2A, U2SAT, prandom, fake_dest_addr, swab32, xfp2str, parse_change_back
from helpers import path_to_str, str_to_path, slip132undo
from struct import unpack, pack
from constants import *
from pycoin.key.BIP32Node import BIP32Node
from pycoin.encoding import a2b_hashed_base58
from io import BytesIO
from hashlib import sha256
from test_bip39pw import set_bip39_pw

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

@pytest.fixture(scope='function')
def has_ms_checks(request, sim_exec):
    # Add this fixture to any test that should FAIL if ms checks are disabled
    # - in other words, tests that test the checks which are disabled.
    # - still need to run w/ --ms-danger flag set to test those cases
    # - also mark testcase with ms_danger

    danger_mode = (request.config.getoption('--ms-danger'))
    if danger_mode:
        print("Enabling multisig danger mode")
        
        request.node.add_marker(pytest.mark.xfail(True, strict=True,
                reason="check was bypassed, so testcase should fail"))

    sim_exec(f'from multisig import MultisigWallet; MultisigWallet.disable_checks={danger_mode}')

    return danger_mode


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

    # default is BIP45:   m/45'/... (but no co-signer idx)
    # - but can provide str format for deriviation, use {idx} for cosigner idx

    def doit(M, N, unique=0, deriv=None):
        keys = []

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d - %d' % (i, unique), 'XTN')

            xfp = unpack("<I", pk.fingerprint())[0]

            if not deriv:
                sub = pk.subkey(45, is_hardened=True, as_private=True)
            else:
                path = deriv.format(idx=i).replace('m/', '')
                try:
                    sub = pk.subkey_for_path(path)
                except IndexError:
                    # some test cases are using bogus paths
                    sub = pk

            keys.append((xfp, pk, sub))

        pk = BIP32Node.from_wallet_key(simulator_fixed_xprv)

        if not deriv:
            sub = pk.subkey(45, is_hardened=True, as_private=True)
        else:
            path = deriv.format(idx=N-1).replace('m/', '')
            try:
                sub = pk.subkey_for_path(path)
            except IndexError:
                # some test cases are using bogus paths
                sub = pk

        keys.append((simulator_fixed_xfp, pk, sub))

        return keys

    return doit

@pytest.fixture
def offer_ms_import(cap_story, dev, need_keypress):
    def doit(config):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('ascii'))

        open('debug/last-config.txt', 'wt').write(config)

        dev.send_recv(CCProtocolPacker.multisig_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        #print(repr(story))

        return title, story

    return doit

@pytest.fixture
def import_ms_wallet(dev, make_multisig, offer_ms_import, need_keypress):

    def doit(M, N, addr_fmt=None, name=None, unique=0, accept=False, common=None, keys=None, do_import=True, derivs=None):
        keys = keys or make_multisig(M, N, unique=unique, deriv=common)

        if not do_import:
            return keys

        # render as a file for import
        name = name or f'test-{M}-{N}'
        config = f"name: {name}\npolicy: {M} / {N}\n\n"

        if addr_fmt:
            config += f'format: {addr_fmt.title()}\n'

        # not good enuf anymore, but maybe in some cases, just need one at top
        if common:
            config += f'derivation: {common}\n'

        if not derivs:
            config += '\n'.join('%s: %s' % (xfp2str(xfp), dd.hwif(as_private=False)) 
                                            for xfp, m, dd in keys)
        else:
            # for cases where derivation of each leg is not same/simple
            assert not common and len(derivs) == N
            for idx, (xfp, m, dd) in enumerate(keys):
                config += 'Derivation: %s\n%s: %s\n\n' % (derivs[idx],
                                        xfp2str(xfp), dd.hwif(as_private=False)) 

        #print(config)
        open('debug/last-ms.txt', 'wt').write(config)

        title, story = offer_ms_import(config)

        assert 'Create new multisig' in story \
                or 'Update existing multisig wallet' in story \
                or 'new wallet is similar to' in story
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
    for name in [ 'Zy', 'Z'*20, 'Vault #3' ]:
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
        config.insert(i, ' #')
        config.insert(i, ' # ')
        config.insert(i, ' #  ')
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

def make_redeem(M, keys, path_mapper=None,
                    violate_bip67=False, tweak_redeem=None, tweak_xfps=None,
                    finalizer_hack=None, tweak_pubkeys=None):
    # Construct a redeem script, and ordered list of xfp+path to match.
    N = len(keys)

    assert path_mapper

    # see BIP 67: <https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki>

    data = []
    for cosigner_idx, (xfp, node, sk) in enumerate(keys):
        path = path_mapper(cosigner_idx)
        #print("path: " + ' / '.join(hex(i) for i in path))

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

        #print("path: %s => pubkey %s" % (path_to_str(path, skip=0), B2A(pk)))

    data.sort(key=lambda i:i[0])

    if violate_bip67:
        # move them out of order
        data[0], data[1] = data[1], data[0]
    

    mm = [80 + M] if M <= 16 else [1, M]
    nn = [80 + N] if N <= 16 else [1, N]

    rv = bytes(mm)

    if tweak_pubkeys:
        tweak_pubkeys(data)

    for pk,_,_ in data:
        rv += bytes([len(pk)]) + pk

    rv += bytes(nn + [0xAE])

    if tweak_redeem:
        rv = tweak_redeem(rv)

    #print("redeem script: " + B2A(rv))

    xfp_paths = [[xfp]+xpath for _,xfp,xpath in data]
    #print("xfp_paths: " + repr(xfp_paths))

    if tweak_xfps:
        tweak_xfps(xfp_paths)

    if finalizer_hack:
        rv = finalizer_hack(rv)

    return rv, [pk for pk,_,_ in data], xfp_paths

def make_ms_address(M, keys, idx=0, is_change=0, addr_fmt=AF_P2SH, testnet=1, **make_redeem_args):
    # Construct addr and script need to represent a p2sh address
    import bech32
    from pycoin.encoding import b2a_hashed_base58, hash160

    if 'path_mapper' not in make_redeem_args:
        make_redeem_args['path_mapper'] = lambda cosigner: [HARD(45), cosigner, is_change, idx]

    script, pubkeys, xfp_paths = make_redeem(M, keys, **make_redeem_args)

    if addr_fmt == AF_P2WSH:
        hrp = ['bc', 'tb'][testnet]
        data = sha256(script).digest()
        addr = bech32.encode(hrp, 0, data)
        scriptPubKey = bytes([0x0, 0x20]) + data
    else:
        if addr_fmt == AF_P2SH:
            digest = hash160(script)
        elif addr_fmt == AF_P2WSH_P2SH:
            digest = hash160(b'\x00\x20' + sha256(script).digest())
        else:
            raise ValueError(addr_fmt)

        prefix = bytes([196]) if testnet else bytes([5])
        addr = b2a_hashed_base58(prefix + digest)

        scriptPubKey = bytes([0xa9, 0x14]) + digest + bytes([0x87])

    return addr, scriptPubKey, script, zip(pubkeys, xfp_paths)
    

@pytest.fixture
def test_ms_show_addr(dev, cap_story, need_keypress, addr_vs_path, bitcoind_p2sh, has_ms_checks):
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

        if not has_ms_checks:
            assert got_addr in story
            assert all((xfp2str(xfp) in story) for xfp,_,_ in keys)
            if bip45:
                for i in range(len(keys)):
                    assert ('/_/%d/0/0' % i) in story
        else:
            assert 'UNVERIFIED' in story

        need_keypress('y')

        # check expected addr was generated based on my math
        addr_vs_path(got_addr, addr_fmt=addr_fmt, script=scr)

        # also check against bitcoind
        core_addr, core_scr = bitcoind_p2sh(M, pubkeys, addr_fmt)
        assert B2A(scr) == core_scr
        assert core_addr == got_addr


    return doit
    

@pytest.mark.parametrize('m_of_n', [(1,3), (2,3), (3,3), (3,6), (10, 15), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
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

@pytest.mark.ms_danger
def test_violate_bip67(clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr, has_ms_checks):
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
def test_bad_pubkey(has_ms_checks, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr, which_pubkey):
    # give incorrect pubkey inside redeem script
    M, N = 1, 15
    keys = import_ms_wallet(M, N, accept=1)

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        def tweaker(scr):
            # corrupt the pubkey
            return bytes((s if i != (5 + (34*which_pubkey)) else s^0x1) for i,s in enumerate(scr))

        with pytest.raises(BaseException) as ee:
            test_ms_show_addr(M, keys, tweak_redeem=tweaker)
        assert ('pk#%d wrong' % (which_pubkey+1)) in str(ee.value)
    finally:
        clear_ms()

@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_zero_depth(clear_ms, addr_fmt, import_ms_wallet, need_keypress, test_ms_show_addr, make_multisig):
    # test having a co-signer with "m" only key ... ie. depth=0

    M, N = 1, 2
    keys = make_multisig(M, N, unique=99)

    # censor first co-signer to look like a master key
    kk = keys[0][1].public_copy()
    kk._depth = 0
    kk._child_index = 0
    kk._parent_fingerprint = b'\0\0\0\0'
    keys[0] = (keys[0][0], keys[0][1], kk)

    try:
        keys = import_ms_wallet(M, N, accept=1, keys=keys,
                            addr_fmt=addr_fmt, derivs=["m", "m/45'"])
        def pm(i):
            return [] if i == 0 else [HARD(45), i, 0,0]

        test_ms_show_addr(M, keys, bip45=False, path_mapper=pm)
    finally:
        clear_ms()

@pytest.mark.parametrize('mode', ['wrong-xfp', 'long-path', 'short-path', 'zero-path'])
@pytest.mark.ms_danger
def test_bad_xfp(mode, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr, has_ms_checks, request):
    # give incorrect xfp+path args during show_address

    if has_ms_checks and (mode in {'zero-path', 'wrong-xfp'}):
        # for these 2 cases, we detect the issue regardless of has_ms_checks mode
        request.node.get_closest_marker('xfail').kwargs['strict'] = False

    M, N = 1, 15
    keys = import_ms_wallet(M, N, accept=1)
    try:
        time.sleep(.1)

        def tweaker(xfps):
            print(f"xfps={xfps}")
            if mode == 'wrong-xfp':
                # bad XFP => not right multisig wallet
                xfps[0][0] ^= 0x55
            elif mode == 'long-path':
                # add garbage
                xfps[0].extend([69, 69, 69, 69, 69])
            elif mode == 'short-path':
                # trim last derivation part
                xfps[0] = xfps[0][0:-1]
            elif mode == 'zero-path':
                # just XFP, no path
                xfps[0] = xfps[0][0:1]
            else:
                raise ValueError

        with pytest.raises(BaseException) as ee:
            test_ms_show_addr(M, keys, tweak_xfps=tweaker)

        if mode in { 'wrong-xfp', 'zero-path' }:
            assert 'with those fingerprints not found' in str(ee.value)
        else:
            assert 'pk#1 wrong' in str(ee.value)
            if ('zero' in mode):
                assert 'shallow' in str(ee.value)

    finally:
        clear_ms()

@pytest.mark.parametrize('cpp', [
    "m///",
    "m/",
    "m/1/2/3/4/5/6/7/8/9/10/11/12/13",          # assuming MAX_PATH_DEPTH==12
])
def test_bad_common_prefix(cpp, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr):
    # give some incorrect path values as the common prefix derivation

    M, N = 1, 15
    with pytest.raises(BaseException) as ee:
        keys = import_ms_wallet(M, N, accept=1, common=cpp)
    assert 'bad derivation line' in str(ee)


def test_import_detail(clear_ms, import_ms_wallet, need_keypress, cap_story):
    # check all details are shown right

    M,N = 14, 15

    keys = import_ms_wallet(M, N)

    time.sleep(.2)
    need_keypress('1')

    time.sleep(.1)
    title, story = cap_story()

    #assert title == f'{M} of {N}'
    assert title == f'test-{M}-{N}'
    xpubs = [sk.hwif() for _,_,sk in keys]
    for xp in xpubs:
        assert xp in story

    need_keypress('x')

    time.sleep(.1)
    need_keypress('x')


@pytest.mark.parametrize('acct_num', [ 0, 99, 123])
def test_export_airgap(acct_num, goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path):
    # test UX and math for bip45 export

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')

    time.sleep(.1)
    title, story = cap_story()
    assert 'BIP-48' in story
    assert "m/45'" in story
    assert "m/48'/" in story
    assert "acct'" in story
    
    need_keypress('y')

    # enter account number every time
    time.sleep(.1)
    for n in str(acct_num):
        need_keypress(n)
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

    e = BIP32Node.from_wallet_key(simulator_fixed_xprv)

    n = BIP32Node.from_wallet_key(rv['p2sh'])
    if acct_num == 0:
        assert n.tree_depth() == 1
        assert n.child_index() == 45 | (1<<31)
        mxfp = unpack("<I", n.parent_fingerprint())[0]
        assert hex(mxfp) == hex(simulator_fixed_xfp)

        expect = e.subkey_for_path("45'.pub") 
    else:
        assert n.tree_depth() == 2
        assert n.child_index() == acct_num | (1<<31)
        expect = e.subkey_for_path(f"45'/{acct_num}'.pub") 
    assert expect.hwif() == n.hwif()

    for name, deriv in [ 
        ('p2sh_p2wsh', f"m/48'/1'/{acct_num}'/1'"),
        ('p2wsh', f"m/48'/1'/{acct_num}'/2'"),
    ]:
        e = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        xpub, *_ = slip132undo(rv[name])
        n = BIP32Node.from_wallet_key(xpub)
        assert rv[name+'_deriv'] == deriv
        assert n.hwif() == xpub
        assert n.tree_depth() == 4
        assert n.child_index() & (1<<31)
        assert n.child_index() & 0xff == int(deriv[-2])
        expect = e.subkey_for_path(deriv[2:] + ".pub") 
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
    
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
@pytest.mark.parametrize('comm_prefix', ['m/1/2/3/4/5/6/7/8/9/10/11/12', None, "m/45'"])
def test_export_single_ux(goto_home, comm_prefix, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path, import_ms_wallet, addr_fmt, clear_ms):

    # create a wallet, export to SD card, check file created.
    # - checks some values for derivation path, assuming MAX_PATH_DEPTH==12

    clear_ms()

    name = 'ex-test-%d' % random.randint(10000,99999)
    M,N = 3, 15
    keys = import_ms_wallet(M, N, name=name, addr_fmt=addr_fmt, accept=1, common=comm_prefix)

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
                    assert value == (comm_prefix or "m/45'")
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
        keys = import_ms_wallet(M, N, name=name, addr_fmt='p2wsh', unique=count, accept=0,
                                    common="m/45'/0'/34'")

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

@pytest.mark.parametrize('N', [ 5, 10])
def test_import_dup_safe(N, clear_ms, make_multisig, offer_ms_import, need_keypress, cap_story, goto_home, pick_menu_item, cap_menu):
    # import wallet, rename it, (check that indicated, works), attempt same w/ addr fmt different
    M = N

    clear_ms()

    keys = make_multisig(M, N)

    # render as a file for import
    def make_named(name, af='p2sh', m=M):
        config = f"name: {name}\npolicy: {m} / {N}\nformat: {af}\n\n"
        config += '\n'.join('%s: %s' % (xfp2str(xfp), sk.hwif(as_private=False)) 
                                        for xfp,m,sk in keys)
        return config

    def has_name(name, num_wallets=1):
        # check worked: look in menu for name
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')

        menu = cap_menu()
        assert f'{M}/{N}: {name}' in menu
        assert len(menu) == 5 + num_wallets

    title, story = offer_ms_import(make_named('xxx-orig'))
    assert 'Create new multisig wallet' in story
    assert 'xxx-orig' in story
    assert 'P2SH' in story
    need_keypress('y')
    has_name('xxx-orig')

    # just simple rename
    title, story = offer_ms_import(make_named('xxx-new'))
    assert 'update name only' in story.lower()
    assert 'xxx-new' in story

    need_keypress('y')
    has_name('xxx-new')

    assert N < 15, 'cant make more, no space'

    newer = make_named('xxx-newer', 'p2wsh')
    title, story = offer_ms_import(newer)
    assert 'update name only' not in story.lower()
    assert 'address type' in story.lower()
    assert 'will NOT replace it' in story
    assert 'xxx-newer' in story
    assert 'WARNING:' in story
    assert 'P2WSH' in story

    # should be 2 now, slightly different
    need_keypress('y')
    has_name('xxx-newer', 2)

    # repeat last one, should still be two
    for keys in ['yn', 'n']:
        title, story = offer_ms_import(newer)
        assert 'Duplicate wallet' in story
        assert 'OK to approve' not in story
        assert 'xxx-newer' in story

        for key in keys:
            need_keypress(key)

        has_name('xxx-newer', 2)

    clear_ms()

@pytest.mark.parametrize('N', [ 5])
def test_import_dup_diff_xpub(N, clear_ms, make_multisig, offer_ms_import, need_keypress, cap_story, goto_home, pick_menu_item, cap_menu):
    # import wallet, tweak xpub only, check that change detected
    clear_ms()

    M = N
    keys = make_multisig(M, N)

    # render as a file for import
    def make_named(name, af='p2sh', m=M, tweaked=False):
        config = f"name: {name}\npolicy: {m} / {N}\nformat: {af}\n\n"
        lines = []
        for idx, (xfp,m,sk) in enumerate(keys):
            if idx == 1 and tweaked:
                a,b = sk._public_pair
                sk._public_pair = (a,b^23847239847)
            hwif = sk.hwif(as_private=False)
            lines.append('%s: %s' % (xfp2str(xfp), hwif) )
        config += '\n'.join(lines)
        return config

    title, story = offer_ms_import(make_named('xxx-orig'))
    assert 'Create new multisig wallet' in story
    assert 'xxx-orig' in story
    assert 'P2SH' in story
    need_keypress('y')

    # change one key.
    title, story = offer_ms_import(make_named('xxx-new', tweaked=True))
    assert 'WARNING:' in story
    assert 'xxx-new' in story
    assert 'xpubs' in story

    clear_ms()


@pytest.mark.parametrize('m_of_n', [(2,2), (2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_dup_xfp_fails(m_of_n, addr_fmt, clear_ms, make_multisig, import_ms_wallet, need_keypress, test_ms_show_addr):

    M, N = m_of_n

    keys = make_multisig(M, N)

    pk = BIP32Node.from_master_secret(b'example', 'XTN')
    sub = pk.subkey(45, is_hardened=True, as_private=True)
    sub._parent_fingerprint = keys[-1][2]._parent_fingerprint
    keys[-1] = (simulator_fixed_xfp, pk, sub)

    with pytest.raises(Exception) as ee:
        import_ms_wallet(M, N, addr_fmt, accept=1, keys=keys)

    #assert 'XFP' in str(ee)
    assert 'wrong pubkey' in str(ee)

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
        expect_addr, _, scr2, _ = make_ms_address(M, keys, path_mapper=pmapper, addr_fmt=addr_fmt)
        assert expect_addr == addr
        assert scr2 == scr
        

    # need to re-start our connection once ckcc has talked to simulator
    dev.start_encryption()
    dev.check_mitm()

    clear_ms()


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
                incl_xpubs=False, hack_change_out=False, hack_psbt=None):
        psbt = BasicPSBT()
        txn = Tx(2,[],[])

        if incl_xpubs:
            # add global header with XPUB's
            # - assumes BIP45
            for idx, (xfp, m, sk) in enumerate(keys):
                if callable(incl_xpubs):
                    psbt.xpubs.append( incl_xpubs(idx, xfp, m, sk) )
                else:
                    kk = pack('<II', xfp, 45|0x80000000)
                    psbt.xpubs.append( (sk.serialize(as_private=False), kk) )

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        for i in range(num_ins):
            # make a fake txn to supply each of the inputs
            # - each input is 1BTC

            # addr where the fake money will be stored.
            addr, scriptPubKey, script, details = make_ms_address(M, keys, idx=i)

            # lots of supporting details needed for p2sh inputs
            if segwit_in:
                psbt.inputs[i].witness_script = script
            else:
                psbt.inputs[i].redeem_script = script

            for pubkey, xfp_path in details:
                psbt.inputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)

            # UTXO that provides the funding for to-be-signed txn
            supply = Tx(2,[TxIn(pack('4Q', 0xdead, 0xbeef, 0, 0), 73)],[])

            supply.txs_out.append(TxOut(1E8, scriptPubKey))

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
                make_redeem_args = dict()
                if hack_change_out:
                    make_redeem_args = hack_change_out(i)

                addr, scriptPubKey, scr, details = \
                    make_ms_address(M, keys, idx=i, addr_fmt=unmap_addr_fmt[style],
                    **make_redeem_args)

                for pubkey, xfp_path in details:
                    psbt.outputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)

                if 'w' in style:
                    psbt.outputs[i].witness_script = scr
                    if style.endswith('p2sh'):
                        psbt.outputs[i].redeem_script = b'\0\x20' + sha256(scr).digest()
                elif style.endswith('sh'):
                    psbt.outputs[i].redeem_script = scr
            else:
                scr = fake_dest_addr(style)

            assert scr

            if not outvals:
                h = TxOut(round(((1E8*num_ins)-fee) / num_outs, 4), scriptPubKey)
            else:
                h = TxOut(outvals[i], scriptPubKey)

            txn.txs_out.append(h)

        if hack_psbt:
            hack_psbt(psbt)

        with BytesIO() as b:
            txn.stream(b)
            psbt.txn = b.getvalue()

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH] )
@pytest.mark.parametrize('num_ins', [ 2, 15 ])
@pytest.mark.parametrize('incl_xpubs', [ False, True, 'no-import' ])
@pytest.mark.parametrize('transport', [ 'usb', 'sd' ])
@pytest.mark.parametrize('out_style', ADDR_STYLES_MS)
@pytest.mark.parametrize('has_change', [ True, False])
@pytest.mark.parametrize('N', [ 3, 15])
def test_ms_sign_simple(N, num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet, addr_vs_path, fake_ms_txn, try_sign, try_sign_microsd, transport, out_style, has_change, settings_set, M=1):
    
    num_outs = num_ins-1

    # trust PSBT if we're doing "no-import" case
    settings_set('pms', 2 if (incl_xpubs == 'no-import') else 0)

    clear_ms()
    keys = import_ms_wallet(M, N, name='cli-test', accept=1, do_import=(incl_xpubs != 'no-import'))

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, incl_xpubs=incl_xpubs,
                outstyles=[out_style], change_outputs=[1] if has_change else [])

    open('debug/last.psbt', 'wb').write(psbt)

    if transport == 'sd':
        try_sign_microsd(psbt, encoding=('binary', 'hex', 'base64')[random.randint(0,2)])
    else:
        try_sign(psbt)

@pytest.mark.parametrize('num_ins', [ 15 ])
@pytest.mark.parametrize('M', [ 2, 4, 1])
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('incl_xpubs', [ True, False ])
def test_ms_sign_myself(M, make_myself_wallet, segwit, num_ins, dev, clear_ms,
        fake_ms_txn, try_sign, bitcoind_finalizer, incl_xpubs, bitcoind_analyze, bitcoind_decode):

    # IMPORTANT: wont work if you start simulator with -m flag. Use no args

    all_out_styles = list(unmap_addr_fmt.keys())
    num_outs = len(all_out_styles)

    clear_ms()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, do_import=(not incl_xpubs))
    N = len(keys)
    assert M<=N

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, segwit_in=segwit, incl_xpubs=incl_xpubs, 
                        outstyles=all_out_styles, change_outputs=list(range(1,num_outs)))

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

@pytest.mark.parametrize('addr_fmt', ['p2wsh', 'p2sh-p2wsh', 'p2sh'])
@pytest.mark.parametrize('acct_num', [ 0, 99, 4321])
def test_make_airgapped(addr_fmt, acct_num, goto_home, cap_story, pick_menu_item, cap_menu, need_keypress, microsd_path, set_bip39_pw, clear_ms, get_settings, N=4):
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

        # enter account number every time
        time.sleep(.05)
        for n in str(acct_num):
            need_keypress(n)
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
    elif addr_fmt == 'p2sh-p2wsh':
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

    wal = json.load(open(el_fname, 'rt'))
    assert f'{M}of{N}' in wal['wallet_type']

    need_keypress('y')
    need_keypress('y')

    if N == 4 and acct_num == 0:

        # capture useful test data for testing Electrum plugin, etc
        for fn in glob(microsd_path('ccxp-*.json')):
            shutil.copy(fn, 'data/multisig/'+fn.rsplit('/', 1)[1])
        shutil.copy(el_fname, f'data/multisig/el-{addr_fmt}-myself.json')
        shutil.copy(cc_fname, f'data/multisig/export-{addr_fmt}-myself.txt')

        json.dump(get_settings()['multisig'][0], 
                    open(f'data/multisig/setting-{addr_fmt}-myself.json', 'w'))
    
    clear_ms()

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
    if addr_fmt != 'p2sh':
        assert f"/{acct_num}'/" in story

    need_keypress('1')
    time.sleep(.05)
    title, story = cap_story()
    # test code ehre

    # abort import, good enough
    need_keypress('x')
    need_keypress('x')


@pytest.mark.parametrize('addr_style', ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.bitcoind
def test_bitcoind_cosigning(dev, bitcoind, import_ms_wallet, clear_ms, explora, try_sign, need_keypress, addr_style):
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
        (simulator_fixed_xfp, None, BIP32Node.from_hwif('tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n')),     # simulator: m/45'
    ]

    M,N=2,2

    clear_ms()
    import_ms_wallet(M, N, keys=keys, accept=1, name="core-cosign", derivs=[bc_deriv, "m/45'"])

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

@pytest.mark.parametrize('addr_fmt', [AF_P2WSH] )
@pytest.mark.parametrize('num_ins', [ 3])
@pytest.mark.parametrize('incl_xpubs', [ False])
@pytest.mark.parametrize('out_style', ['p2wsh'])
@pytest.mark.parametrize('bitrot', list(range(0,6)) + [98, 99, 100] + list(range(-5, 0)))
@pytest.mark.ms_danger
def test_ms_sign_bitrot(num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet, addr_vs_path, fake_ms_txn, start_sign, end_sign, out_style, cap_story, bitrot, has_ms_checks):
    
    M = 1
    N = 3
    num_outs = 2

    clear_ms()
    keys = import_ms_wallet(M, N, accept=1)

    # given script, corrupt it a little or a lot
    def rotten(track, bitrot, scr):
        if bitrot == 98:
            rv = scr + scr
        elif bitrot == 98:
            rv = scr[::-1]
        elif bitrot == 100:
            rv = scr*3
        else:
            rv = bytearray(scr)
            rv[bitrot] ^= 0x01

        track.append(rv)
        return rv

    track = []
    psbt = fake_ms_txn(num_ins, num_outs, M, keys, incl_xpubs=incl_xpubs,
                outstyles=[out_style], change_outputs=[0],
                hack_change_out=lambda idx: dict(finalizer_hack=
                        lambda scr: rotten(track, bitrot, scr)))

    assert len(track) == 1

    open('debug/last.psbt', 'wb').write(psbt)

    start_sign(psbt)
    with pytest.raises(Exception) as ee:
        signed = end_sign(True)
    assert 'Output#0:' in str(ee)
    assert 'change output script' in str(ee)

    # Check error details are shown
    time.sleep(.5)
    title, story = cap_story()
    assert story.strip() in str(ee)
    assert len(story.split(':')[-1].strip()), story

@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH] )
@pytest.mark.parametrize('num_ins', [ 1])
@pytest.mark.parametrize('incl_xpubs', [ True])
@pytest.mark.parametrize('out_style', ['p2wsh'])
@pytest.mark.parametrize('pk_num', range(4)) 
@pytest.mark.parametrize('case', ['pubkey', 'path'])
def test_ms_change_fraud(case, pk_num, num_ins, dev, addr_fmt, clear_ms, incl_xpubs, make_multisig, addr_vs_path, fake_ms_txn, start_sign, end_sign, out_style, cap_story):
    
    M = 1
    N = 3
    num_outs = 2

    clear_ms()
    keys = make_multisig(M, N)


    # given 
    def tweak(case, pk_num, data):
        # added from make_redeem() as tweak_pubkeys option
        #(pk, xfp, path))
        assert len(data) == N
        if case == 'xpub':
            return

        if pk_num == 3:
            pk_num = [xfp for _,xfp,_ in data].index(simulator_fixed_xfp)

        pk, xfp, path = data[pk_num]
        if case == 'pubkey':
            pk = pk[:-2] + bytes(2)
        elif case == 'path':
            path[-1] ^= 0x1
        else:
            assert False, case
        data[pk_num] = (pk, xfp, path)

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, incl_xpubs=True,
                outstyles=[out_style], change_outputs=[0],
                hack_change_out=lambda idx: dict(tweak_pubkeys=
                        lambda data: tweak(case, pk_num, data)))

    open('debug/last.psbt', 'wb').write(psbt)

    with pytest.raises(Exception) as ee:
        start_sign(psbt)
        signed = end_sign(accept=True, accept_ms_import=False)
    assert 'Output#0:' in str(ee)
    assert 'P2WSH or P2SH change output script' in str(ee)
    #assert 'Deception regarding change output' in str(ee)

    # Check error details are shown
    time.sleep(.5)
    title, story = cap_story()
    assert story.strip() in str(ee.value.args[0])
    assert len(story.split(':')[-1].strip()), story


@pytest.mark.parametrize('repeat', range(2) )
def test_iss6743(repeat, set_seed_words, sim_execfile, try_sign):
    # from SomberNight <https://github.com/spesmilo/electrum/issues/6743#issuecomment-729965813>
    psbt_b4 = bytes.fromhex('''\
70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae3000008001000080000000800100008000000000030000000000''')

    # pre 3.2.0 result
    psbt_wrong = bytes.fromhex('''\
70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c002202034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef63819483045022100a85d08eef6675803fe2b58dda11a553641080e07da36a2f3e116f1224201931b022071b0ba83ef920d49b520c37993c039d13ae508a1adbd47eb4b329713fcc8baef01010304010000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae300000800100008000000080010000800000000003000000220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae0000''')
    psbt_right = bytes.fromhex('''\
70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c002202034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef63819483045022100ae90a7e4c350389816b03af0af46df59a2f53da04cc95a2abd81c0bbc5950c1d02202f9471d6b0664b7a46e81da62d149f688adc7ba2b3413372d26fa618a8460eba01010304010000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae300000800100008000000080010000800000000003000000220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae0000''')

    seed_words = 'all all all all all all all all all all all all'
    expect_xfp = swab32(int('5c9e228d', 16))
    assert xfp2str(expect_xfp) == '5c9e228d'.upper()

    # load specific private key
    xfp = set_seed_words(seed_words)
    assert xfp == expect_xfp

    # check Coldcard derives expected Upub
    derivation = "m/48'/1'/0'/1'"       # part of devtest/unit_iss6743.py 
    expect_xpub = 'Upub5SJWbuhs5tM4mkJST69tnpGGaf8dDTqByx3BLSocWFpq5YLh1fky4DQTFGQVG6nCSqZfUiAAeStdxSQteUcfMsWjDkhniZx4GdwpB18Tnbq'

    pub = sim_execfile('devtest/unit_iss6743.py')
    assert pub == expect_xpub

    # verify psbt globals section
    tp = BasicPSBT().parse(psbt_b4)
    (hdr_xpub, hdr_path), = [(v,k) for v,k in tp.xpubs if k[0:4] == pack('<I', expect_xfp)]
    from pycoin.encoding import b2a_hashed_base58
    assert expect_xpub == b2a_hashed_base58(hdr_xpub[1:])
    assert derivation == path_to_str(unpack('<%dI' % (len(hdr_path) // 4),hdr_path))

    # sign a multisig, with xpubs in globals
    _, out_psbt = try_sign(psbt_b4, accept=True, accept_ms_import=True)
    assert out_psbt != psbt_wrong
    assert out_psbt == psbt_right

    open('debug/i6.psbt', 'wt').write(out_psbt.hex())

@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('xderiv', [ None, 'any', 'unknown', '*', '', 'none'])
def test_ms_import_nopath(N, xderiv, make_multisig, clear_ms, offer_ms_import, need_keypress):
    # try various synonyms for unknown/any derivation styles

    keys = make_multisig(N, N, deriv="m/48'/0'/0'/1'/0", unique=1)

    # just fingerprints, no deriv paths
    config = 'Format: p2sh-p2wsh\n'
    for xfp,m,sk in keys:
        config += '%s: %s\n' % (xfp2str(xfp), sk.hwif(as_private=False))
    if xderiv != None:
        config += 'Derivation: %s\n' % xderiv

    with pytest.raises(BaseException) as ee:
        title, story = offer_ms_import(config)
    assert 'empty deriv' in str(ee)

@pytest.mark.parametrize('N', [ 15])
@pytest.mark.parametrize('M', [ 1, 15])
def test_ms_import_many_derivs(M, N, make_multisig, clear_ms, offer_ms_import, need_keypress,
        goto_home, pick_menu_item, cap_story, microsd_path):
    # try config file with many different derivation paths given, including None
    # - also check we can convert those into Electrum wallets
    actual = "m/48'/0'/0'/1'/0"
    derivs = [ actual, 'm', "m/45'/0'/99'", "m/45'/34/34'/34"]

    keys = make_multisig(M, N, deriv=actual, unique=1)

    # just fingerprints, no deriv paths
    config = f'Format: p2sh-p2wsh\nName: impmany\n\npolicy: {M} of {N}\n'
    for idx, (xfp,m,sk) in enumerate(keys):
        if idx == len(keys)-1:
            # last one always simulator's xfp, so can't lie about derivation
            config += "Derivation: %s\n" % actual
        else:
            dp = derivs[idx % len(derivs)]
            config += 'Derivation: %s\n' % dp
            print('%s => %s   was %d, gonna be %d' % (
                    xfp2str(xfp), dp, sk._depth, dp.count('/')))
            sk._depth = dp.count('/')
        config += '%s: %s\n' % (xfp2str(xfp), sk.hwif(as_private=False))

    title, story = offer_ms_import(config)
    assert f'Policy: {M} of {N}\n' in story
    assert f'P2SH-P2WSH' in story
    assert 'Derivation:\n  Varies' in story
    assert f'  Varies ({len(set(derivs))})\n' in story
    need_keypress('y')


    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item(f'{M}/{N}: impmany')

    pick_menu_item('Coldcard Export')

    time.sleep(.1)
    title, story = cap_story()
    fname = story.split('\n')[-1]
    assert fname, story
    need_keypress('y')

    with open(microsd_path(fname), 'rt') as fp:
        lines = list(fp.readlines())
    for xfp,_,_ in keys:
        m = xfp2str(xfp)
        assert any(m in ln for ln in lines)

    pick_menu_item('Electrum Wallet')

    time.sleep(.25)
    title, story = cap_story()
    assert 'This saves a skeleton Electrum wallet file' in story
    need_keypress('y')

    time.sleep(.25)
    title, story = cap_story()
    fname2 = story.split('\n')[-1]
    assert fname2, story
    need_keypress('y')

    if M == 1 and N == 15:
        # useful and easier-to-use test wallet
        shutil.copy(microsd_path(fname), f'debug/test-wallet-ms.txt')
        shutil.copy(microsd_path(fname2), f'debug/test-wallet-ms.json')

    with open(microsd_path(fname2), 'rt') as fp:
        el = json.load(fp)
    assert el['seed_version'] == 17
    assert el['wallet_type'] == f"{M}of{N}"
    for n in range(1, N+1):
        kk = f'x{n}/'
        assert kk in el
        co = el[kk]
        assert 'Coldcard' in co['label']
        dd = co['derivation']
        assert (dd in derivs) or (dd == actual) or ("42069'" in dd) or (dd == 'm')

    clear_ms()


@pytest.mark.ms_danger
def test_danger_warning(request, clear_ms, import_ms_wallet, cap_story, fake_ms_txn, start_sign, sim_exec):
    # note: cant use has_ms_checks fixture here
    danger_mode = (request.config.getoption('--ms-danger'))
    sim_exec(f'from multisig import MultisigWallet; MultisigWallet.disable_checks={danger_mode}')

    clear_ms()
    M,N = 2,3
    keys = import_ms_wallet(M, N, accept=1)

    psbt = fake_ms_txn(1, 1, M, keys, incl_xpubs=True)

    open('debug/last.psbt', 'wb').write(psbt)

    start_sign(psbt)
    title, story = cap_story()

    if danger_mode:
        assert 'WARNING' in story
        assert 'Danger' in story
        assert 'Some multisig checks are disabled' in story
    else:
        assert 'WARNING' not in story

@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('M', [ 3, 15])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH] )
def test_ms_addr_explorer(M, N, addr_fmt, make_multisig, clear_ms, offer_ms_import, need_keypress,
        goto_home, pick_menu_item, cap_story, cap_menu, import_ms_wallet):

    wal_name = f"ax{M}-{N}-{addr_fmt}"

    M = min(M, N)

    dd = {
        AF_P2WSH: ("m/48'/1'/0'/2'/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45'/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48'/1'/0'/1'/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]

    keys = make_multisig(M, N, unique=1, deriv=deriv)

    derivs = [deriv.format(idx=i) for i in range(N)]

    clear_ms()
    keys = import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=derivs, addr_fmt=text_a_fmt)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')      # warning

    m = cap_menu()
    assert wal_name in m
    pick_menu_item(wal_name)

    time.sleep(.5)
    title, story = cap_story()

    # unwrap text a bit
    story = story.replace("=>\n", "=> ").replace('0/0\n =>', "0/0 =>")

    maps = []
    for ln in story.split('\n'):
        if '=>' not in ln: continue

        path,chk,addr = ln.split()
        assert chk == '=>'
        assert '/' in path

        maps.append( (path, addr) )

    assert len(maps) == 10
    for idx, (subpath, addr) in enumerate(maps):
        path_mapper = lambda co_idx: str_to_path(derivs[co_idx]) + [0, idx]
        
        expect, pubkey, script, _  = make_ms_address(M, keys, idx=idx, addr_fmt=addr_fmt,
                                                        path_mapper=path_mapper)

        assert int(subpath.split('/')[-1]) == idx
        #print('../0/%s => \n %s' % (idx, B2A(script)))

        trunc = expect[0:8] + "-" + expect[-7:]
        assert trunc == addr

# EOF
