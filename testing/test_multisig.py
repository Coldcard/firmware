# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Multisig-related tests.
#
# After this file passes, also run again like this:
#
#       py.test test_multisig.py -m ms_danger --ms-danger
#
import time, pytest, os, random, json, shutil, pdb, io, base64
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from ckcc.protocol import CCProtocolPacker, MAX_TXN_LEN
from pprint import pprint
from helpers import B2A, fake_dest_addr, swab32, xfp2str
from helpers import str_to_path, slip132undo
from struct import unpack, pack
from constants import *
from pycoin.key.BIP32Node import BIP32Node
from pycoin.tx import Tx
from io import BytesIO
from hashlib import sha256
from descriptor import MULTI_FMT_TO_SCRIPT, MultisigDescriptor, parse_desc_str


def HARD(n=0):
    return 0x80000000 | n

def str2ipath(s):
    # convert text to numeric path for BIP-174
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
            rv = bitcoind.rpc.createmultisig(M, [B2A(i) for i in pubkeys], fmt)
        except ConnectionResetError:
            # bitcoind sleeps on us sometimes, give it another chance.
            rv = bitcoind.rpc.createmultisig(M, [B2A(i) for i in pubkeys], fmt)

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

    # default is BIP-45:   m/45'/... (but no co-signer idx)
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

    def doit(M, N, addr_fmt=None, name=None, unique=0, accept=False, common=None, keys=None, do_import=True, derivs=None,
             descriptor=False, int_ext_desc=False):
        keys = keys or make_multisig(M, N, unique=unique, deriv=common or (derivs[0] if derivs else None))
        name = name or f'test-{M}-{N}'

        if not do_import:
            return keys

        if descriptor:
            if not derivs:
                if not common:
                    common = "m/45'"
                key_list = [(xfp, common, dd.hwif(as_private=False)) for xfp, m, dd in keys]
            else:
                assert len(derivs) == N
                key_list = [(xfp, derivs[idx], dd.hwif(as_private=False)) for idx, (xfp, m, dd) in enumerate(keys)]

            desc = MultisigDescriptor(M=M, N=N, keys=key_list, addr_fmt=addr_fmt)
            if int_ext_desc:
                desc_str = desc.serialize(int_ext=True)
            else:
                desc_str = desc.serialize()
            config = "%s\n" % desc_str

        else:
            # render as a file for import
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
        if descriptor is False:
            # descriptors wallet does not have a name
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
def test_ms_import_variations(N, make_multisig, offer_ms_import, need_keypress):
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
        # testnet=2 --> regtest
        hrp = ['bc', 'tb', 'bcrt'][testnet]
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
    

@pytest.mark.bitcoind
@pytest.mark.parametrize('m_of_n', [(1,3), (2,3), (3,3), (3,6), (10, 15), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_ranges(m_of_n, use_regtest, addr_fmt, clear_ms, import_ms_wallet, test_ms_show_addr):
    use_regtest()
    M, N = m_of_n

    keys = import_ms_wallet(M, N, addr_fmt, accept=1)

    #print("imported: %r" % [x for x,_,_ in keys])

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        test_ms_show_addr(M, keys, addr_fmt=addr_fmt)

    finally:
        clear_ms()

@pytest.mark.bitcoind
@pytest.mark.ms_danger
def test_violate_bip67(clear_ms, use_regtest, import_ms_wallet, need_keypress, test_ms_show_addr, has_ms_checks):
    # detect when pubkeys are not in order in the redeem script
    M, N = 1, 15

    keys = import_ms_wallet(M, N, accept=1)

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        with pytest.raises(BaseException) as ee:
            test_ms_show_addr(M, keys, violate_bip67=1)
        assert 'BIP-67' in str(ee.value)
    finally:
        clear_ms()


@pytest.mark.bitcoind
@pytest.mark.parametrize('which_pubkey', [0, 1, 14])
def test_bad_pubkey(has_ms_checks, use_regtest, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr, which_pubkey):
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


@pytest.mark.bitcoind
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_zero_depth(clear_ms, use_regtest, addr_fmt, import_ms_wallet, need_keypress, test_ms_show_addr, make_multisig):
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
@pytest.mark.bitcoind
def test_bad_xfp(mode, clear_ms, use_regtest, import_ms_wallet, need_keypress, test_ms_show_addr, has_ms_checks, request):
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
@pytest.mark.bitcoind
def test_bad_common_prefix(cpp, use_regtest, clear_ms, import_ms_wallet, need_keypress, test_ms_show_addr):
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


@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('acct_num', [0, 99, 123])
@pytest.mark.parametrize('testnet', [True, False])
def test_export_airgap(acct_num, goto_home, cap_story, pick_menu_item, cap_menu, need_keypress,
                       microsd_path, load_export, use_mainnet, testnet, way):
    if not testnet:
        use_mainnet()

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')

    time.sleep(.1)
    title, story = cap_story()
    assert 'BIP-48' in story
    assert "m/45'" not in story
    assert f"m/48'/{int(testnet)}'" in story
    assert "acct'" in story
    
    need_keypress('y')

    # enter account number every time
    time.sleep(.1)
    for n in str(acct_num):
        need_keypress(n)
    need_keypress('y')

    rv = load_export(way, is_json=True, label="Multisig XPUB", fpattern="ccxp-", sig_check=False)

    assert 'xfp' in rv
    assert len(rv) >= 6

    e = BIP32Node.from_wallet_key(simulator_fixed_xprv)
    if not testnet:
        e._netcode = "BTC"

    if 'p2sh' in rv:
        # perhaps obsolete, but not removed
        assert acct_num == 0

        n = BIP32Node.from_wallet_key(rv['p2sh'])
        assert n.tree_depth() == 1
        assert n.child_index() == 45 | (1<<31)
        mxfp = unpack("<I", n.parent_fingerprint())[0]
        assert hex(mxfp) == hex(simulator_fixed_xfp)

        expect = e.subkey_for_path("45'.pub") 
        assert expect.hwif() == n.hwif()

    for name, deriv in [ 
        ('p2sh_p2wsh', f"m/48'/{int(testnet)}'/{acct_num}'/1'"),
        ('p2wsh', f"m/48'/{int(testnet)}'/{acct_num}'/2'"),
    ]:
        e = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        if not testnet:
            e._netcode = "BTC"
        xpub, *_ = slip132undo(rv[name])
        n = BIP32Node.from_wallet_key(xpub)
        assert rv[name+'_deriv'] == deriv
        assert n.hwif() == xpub
        assert n.tree_depth() == 4
        assert n.child_index() & (1<<31)
        assert n.child_index() & 0xff == int(deriv[-2])
        expect = e.subkey_for_path(deriv[2:] + ".pub") 
        assert expect.hwif() == n.hwif()

        # TODO add tests for descriptor template

@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('vdisk', [True, False])
def test_import_ux(N, vdisk, goto_home, cap_story, pick_menu_item, need_keypress, microsd_path, make_multisig,
                   virtdisk_path):
    # test menu-based UX for importing wallet file from SD
    M = N-1

    keys = make_multisig(M, N)
    name = 'named-%d' % random.randint(10000,99999)
    config = f'policy: {M} of {N}\n'
    config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)

    if vdisk:
        fname = virtdisk_path(f'ms-{name}.txt')
    else:
        fname = microsd_path(f'ms-{name}.txt')
    with open(fname, 'wt') as fp:
        fp.write(config)

    try:
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Import from File')
        time.sleep(0.5)
        _, story = cap_story()
        if vdisk and "Unable to find any suitable files for this operation" in story:
            pytest.skip("Vdisk disabled")
        if "Press (1) to import multisig wallet file from SD Card" in story:
            if vdisk:
                if "press (2) to import from Virtual Disk" not in story:
                    pytest.skip("Vdisk disabled")
                else:
                    need_keypress("2")
            else:
                need_keypress("1")

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

@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
@pytest.mark.parametrize('comm_prefix', ['m/1/2/3/4/5/6/7/8/9/10/11/12', None, "m/45'"])
def test_export_single_ux(goto_home, comm_prefix, cap_story, pick_menu_item, cap_menu, need_keypress,
                          microsd_path, import_ms_wallet, addr_fmt, clear_ms, way, load_export):

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
    contents = load_export(way, label="Coldcard multisig setup", is_json=False, sig_check=False)

    got = set()
    for ln in io.StringIO(contents).readlines():
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
def test_overflow(N, import_ms_wallet, clear_ms, need_keypress, cap_story, mk_num):
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
            assert mk_num < 4
            assert 'No space left' in story
            break

    if mk_num >= 4:
        assert count == 9           # unlimited now
    else:
        if N == 3:
            assert count == 9, "Expect fail at 9"
        if N == 15:
            assert count == 2, "Expect fail at 2"

    need_keypress('y')
    clear_ms()

@pytest.fixture
def test_make_example_file(microsd_path, make_multisig):
    def doit(M, N, addr_fmt=None):
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
        return fname
    return doit

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
        assert (len(menu) - num_wallets) in [6, 7]        # depending if NFC enabled or not

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


@pytest.mark.bitcoind
@pytest.mark.parametrize('m_of_n', [(2,2), (2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_dup_xfp_fails(m_of_n, use_regtest, addr_fmt, clear_ms, make_multisig, import_ms_wallet, need_keypress, test_ms_show_addr):

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


@pytest.fixture
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
            # - assumes BIP-45
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

@pytest.mark.veryslow
@pytest.mark.unfinalized
@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH] )
@pytest.mark.parametrize('num_ins', [ 2, 15 ])
@pytest.mark.parametrize('incl_xpubs', [ False, True, 'no-import' ])
@pytest.mark.parametrize('transport', ['usb', 'sd'])
@pytest.mark.parametrize('out_style', ADDR_STYLES_MS)
@pytest.mark.parametrize('has_change', [ True, False])
@pytest.mark.parametrize('M_N', [(2, 3), (5, 15)])
def test_ms_sign_simple(M_N, num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet,
                        addr_vs_path, fake_ms_txn, try_sign, try_sign_microsd, transport, out_style,
                        has_change, settings_set):
    M, N = M_N
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

@pytest.mark.unfinalized
@pytest.mark.bitcoind
@pytest.mark.parametrize('num_ins', [ 15 ])
@pytest.mark.parametrize('M', [ 2, 4, 1])
@pytest.mark.parametrize('segwit', [True, False])
@pytest.mark.parametrize('incl_xpubs', [ True, False ])
def test_ms_sign_myself(M, use_regtest, make_myself_wallet, segwit, num_ins, dev, clear_ms,
                        fake_ms_txn, try_sign, incl_xpubs, bitcoind):

    # IMPORTANT: wont work if you start simulator with --ms flag. Use no args

    all_out_styles = list(unmap_addr_fmt.keys())
    num_outs = len(all_out_styles)

    clear_ms()
    use_regtest()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, do_import=(not incl_xpubs))
    N = len(keys)
    assert M<=N

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, segwit_in=segwit, incl_xpubs=incl_xpubs, 
                        outstyles=all_out_styles, change_outputs=list(range(1,num_outs)))

    open(f'debug/myself-before.psbt', 'w').write(base64.b64encode(psbt).decode())
    for idx in range(M):
        select_wallet(idx)
        _, updated = try_sign(psbt, accept_ms_import=(incl_xpubs and (idx==0)))
        open(f'debug/myself-after.psbt', 'w').write(base64.b64encode(updated).decode())
        assert updated != psbt

        aft = BasicPSBT().parse(updated)
        # check all inputs gained a signature
        assert all(len(i.part_sigs)==(idx+1) for i in aft.inputs)

        psbt = aft.as_bytes()

    # should be fully signed now.
    anal = bitcoind.rpc.analyzepsbt(base64.b64encode(psbt).decode('ascii'))
    try:
        assert not any(inp.get('missing') for inp in anal['inputs']), "missing sigs: %r" % anal
        assert all(inp['next'] in {'finalizer','updater'} for inp in anal['inputs']), "other issue: %r" % anal
    except:
        # XXX seems to be a bug in analyzepsbt function ... not fully studied
        pprint(anal, stream=open('debug/analyzed.txt', 'wt'))
        decode = bitcoind.rpc.decodepsbt(base64.b64encode(psbt).decode('ascii'))
        pprint(decode, stream=open('debug/decoded.txt', 'wt'))
    
        if M==N or segwit:
            # as observed, bug not trigged, so raise if it *does* happen
            raise
        else:
            print("ignoring bug in bitcoind")

    if 0:
        # why doesn't this work?
        # TODO this does NOT work only if parameter segwit is True
        # TODO I have debuged bitcoin core to see why we're still in updater phase, not in desired finalizer
        # relevant comment from core code:
        #     When we're taking our information from a witness UTXO, we can't verify it is actually data from
        #     the output being spent. This is safe in case a witness signature is produced (which includes this
        #     information directly in the hash), but not for non-witness signatures. Remember that we require
        #     a witness signature in this situation.
        #
        # In our case, witness signature was not produced (but was required)
        rv = bitcoind.rpc.finalizepsbt(b64encode(aft.as_bytes()).decode('ascii'), True)
        _, txn, is_complete = b64decode(rv.get('psbt', '')), rv.get('hex'), rv['complete']
        assert is_complete

@pytest.mark.parametrize('addr_fmt', ['p2wsh', 'p2sh-p2wsh'])
@pytest.mark.parametrize('acct_num', [ 0, 99, 4321])
@pytest.mark.parametrize('N', [ 3, 14])
def test_make_airgapped(addr_fmt, acct_num, N, goto_home, cap_story, pick_menu_item, need_keypress,
                        microsd_path, set_bip39_pw, clear_ms, get_settings, load_export):
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
        time.sleep(0.1)
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

        need_keypress('1')

    set_bip39_pw('')

    assert len(glob(microsd_path('ccxp-*.json'))) == N

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Create Airgapped')
    time.sleep(.1)
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

    impf, fname = load_export("sd", label="Coldcard multisig setup", is_json=False, sig_check=False,
                              tail_check="Import that file onto the other Coldcards involved with this multisig wallet",
                              ret_fname=True)
    cc_fname = microsd_path(fname)
    assert f'Policy: {M} of {N}' in impf
    if addr_fmt != 'p2sh':
        assert f'Format: {addr_fmt.upper()}' in impf

    wal, fname = load_export("sd", is_json=True, label="Electrum multisig wallet", sig_check=False,
                             ret_fname=True)
    el_fname = microsd_path(fname)
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
    pick_menu_item('Import from File')
    time.sleep(0.5)
    _, story = cap_story()
    if "Press (1) to import multisig wallet file from SD Card" in story:
        need_keypress("1")
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


@pytest.mark.unfinalized
@pytest.mark.bitcoind
@pytest.mark.parametrize('addr_style', ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.parametrize('cc_sign_first', [True, False])
def test_bitcoind_cosigning(cc_sign_first, dev, bitcoind, import_ms_wallet, clear_ms, try_sign,
                            need_keypress, addr_style, use_regtest):
    # Make a P2SH wallet with local bitcoind as a co-signer (and simulator)
    # - send an receive various
    # - following text of <https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md>
    # - the constructed multisig walelt will only work for a single pubkey on core side
    # - before starting this test, have some funds already deposited to bitcoind testnet wallet
    from pycoin.encoding import sec_to_public_pair
    from binascii import a2b_hex
    use_regtest()
    if addr_style == 'legacy':
        addr_fmt = AF_P2SH
    elif addr_style == 'p2sh-segwit':
        addr_fmt = AF_P2WSH_P2SH
    elif addr_style == 'bech32':
        addr_fmt = AF_P2WSH


    addr = bitcoind.supply_wallet.getnewaddress("sim-cosign")

    info = bitcoind.supply_wallet.getaddressinfo(addr)

    assert info['address'] == addr
    bc_xfp = swab32(int(info['hdmasterfingerprint'], 16))
    bc_deriv = info['hdkeypath']        # example: "m/0'/0'/3'"
    bc_pubkey = info['pubkey']          # 02f75ae81199559c4aa...

    pp = sec_to_public_pair(a2b_hex(bc_pubkey))

    # No means to export XPUB from bitcoind! Still. In 2019.
    # - this fake will only work for one pubkey value, the first/topmost
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
    resp = bitcoind.supply_wallet.addmultisigaddress(M, list(sorted([cc_pubkey, bc_pubkey])),
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

    # fund multisig address
    bitcoind.supply_wallet.importaddress(ms_addr, 'shared-addr-'+addr_style, True)
    bitcoind.supply_wallet.sendtoaddress(address=ms_addr, amount=5)
    bitcoind.supply_wallet.generatetoaddress(101, bitcoind.supply_wallet.getnewaddress())  # mining
    unspent = bitcoind.supply_wallet.listunspent(addresses=[ms_addr])
    ret_addr = bitcoind.supply_wallet.getrawchangeaddress()

    resp = bitcoind.supply_wallet.walletcreatefundedpsbt([dict(txid=unspent[0]["txid"], vout=unspent[0]["vout"])],
               [{ret_addr: 2}], 0,
                {'subtractFeeFromOutputs': [0], 'includeWatching': True}, True)

    if not cc_sign_first:
        # signing first with bitcoind
        resp = bitcoind.supply_wallet.walletprocesspsbt(resp["psbt"])

    # assert resp['changepos'] == -1
    psbt = base64.b64decode(resp['psbt'])

    open('debug/funded.psbt', 'wb').write(psbt)

    # patch up the PSBT a little ... bitcoind doesn't know the path for the CC's key
    ex = BasicPSBT().parse(psbt)
    cxpk = a2b_hex(cc_pubkey)
    for i in ex.inputs:
        # issues/47 in secret - from 24.0 core does not add out key into PSBT input bip32 paths - no need to check
        # assert cxpk in i.bip32_paths, 'input not to be signed by CC?'
        i.bip32_paths[cxpk] = pack('<3I', keys[1][0], *str2ipath(cc_deriv))

    psbt = ex.as_bytes()

    open('debug/patched.psbt', 'wb').write(psbt)

    _, updated = try_sign(psbt, finalize=False)

    open('debug/cc-updated.psbt', 'wb').write(updated)

    if cc_sign_first:
        # cc signed first - bitcoind is now second
        rr = bitcoind.supply_wallet.walletprocesspsbt(base64.b64encode(updated).decode('ascii'), True, "ALL")
        assert rr["complete"]
        both_signed = rr["psbt"]
    else:
        both_signed = base64.b64encode(updated).decode('ascii')

    # finalize and send
    rr = bitcoind.supply_wallet.finalizepsbt(both_signed, True)
    open('debug/bc-final-txn.txn', 'wt').write(rr['hex'])
    assert rr['complete']
    tx_hex = rr["hex"]
    res = bitcoind.supply_wallet.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(rr['hex'])
    assert len(txn_id) == 64


@pytest.mark.parametrize('addr_fmt', [AF_P2WSH] )
@pytest.mark.parametrize('num_ins', [ 3])
@pytest.mark.parametrize('incl_xpubs', [ False])
@pytest.mark.parametrize('out_style', ['p2wsh'])
@pytest.mark.parametrize('bitrot', list(range(0,6)) + [98, 99, 100] + list(range(-5, 0)))
@pytest.mark.ms_danger
def test_ms_sign_bitrot(num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet, addr_vs_path,
                        fake_ms_txn, start_sign, end_sign, out_style, cap_story, bitrot, has_ms_checks):
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
        signed = end_sign(accept=None)
    assert 'Output#0:' in str(ee)
    assert 'change output script' in str(ee)

    # Check error details are shown
    time.sleep(.01)
    title, story = cap_story()
    assert story.strip() in str(ee)
    assert len(story.split(':')[-1].strip()), story

@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH] )
@pytest.mark.parametrize('num_ins', [ 1])
@pytest.mark.parametrize('incl_xpubs', [ True])
@pytest.mark.parametrize('out_style', ['p2wsh'])
@pytest.mark.parametrize('pk_num', range(4)) 
@pytest.mark.parametrize('case', ['pubkey', 'path'])
def test_ms_change_fraud(case, pk_num, num_ins, dev, addr_fmt, clear_ms, incl_xpubs, make_multisig,
                         addr_vs_path, fake_ms_txn, start_sign, end_sign, out_style, cap_story):
    
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
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_ms_import_many_derivs(M, N, way, make_multisig, clear_ms, offer_ms_import, need_keypress,
                               pick_menu_item, cap_story, microsd_path, virtdisk_path, nfc_read_text,
                               goto_home, load_export):
    # try config file with different derivation paths given, including None
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
    contents = load_export(way, label="Coldcard multisig setup", sig_check=False, is_json=False)
    lines = io.StringIO(contents).readlines()

    for xfp,_,_ in keys:
        m = xfp2str(xfp)
        assert any(m in ln for ln in lines)

    pick_menu_item('Electrum Wallet')

    time.sleep(.25)
    title, story = cap_story()
    assert 'This saves a skeleton Electrum wallet file' in story
    need_keypress('y')

    el = load_export(way, label="Electrum multisig wallet", sig_check=False, is_json=True)

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
@pytest.mark.parametrize('descriptor', [True, False])
def test_danger_warning(request, descriptor, clear_ms, import_ms_wallet, cap_story, fake_ms_txn, start_sign, sim_exec):
    # note: cant use has_ms_checks fixture here
    danger_mode = (request.config.getoption('--ms-danger'))
    sim_exec(f'from multisig import MultisigWallet; MultisigWallet.disable_checks={danger_mode}')

    clear_ms()
    M,N = 2,3
    keys = import_ms_wallet(M, N, accept=1, descriptor=descriptor)
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

@pytest.mark.parametrize('descriptor', [True, False])
@pytest.mark.parametrize('change', [True, False])
@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('M', [ 3, 15])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH] )
def test_ms_addr_explorer(descriptor, change, M, N, addr_fmt, make_multisig, clear_ms, need_keypress, goto_home,
                          pick_menu_item, cap_story, cap_menu, import_ms_wallet):
    clear_ms()
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
    keys = import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=derivs,
                            addr_fmt=text_a_fmt, descriptor=descriptor)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')      # warning
    m = cap_menu()
    if descriptor:
        wal_name = m[-1]
    else:
        assert wal_name in m
    pick_menu_item(wal_name)

    time.sleep(.5)
    title, story = cap_story()
    assert "Press (6)" in story
    assert "change addresses." in story
    if change:
        need_keypress("6")
        time.sleep(0.2)
        title, story = cap_story()
        # once change is selected - do not offer this option again
        assert "change addresses." not in story
        assert "Press (6)" not in story
    # unwrap text a bit
    if change:
        story = story.replace("=>\n", "=> ").replace('1/0]\n =>', "1/0] =>")
    else:
        story = story.replace("=>\n", "=> ").replace('0/0]\n =>', "0/0] =>")

    maps = []
    for ln in story.split('\n'):
        if '=>' not in ln: continue

        path,chk,addr = ln.split()
        assert chk == '=>'
        assert '/' in path

        maps.append( (path, addr) )

    assert len(maps) == 10
    for idx, (subpath, addr) in enumerate(maps):
        chng_idx = 1 if change else 0
        path_mapper = lambda co_idx: str_to_path(derivs[co_idx]) + [chng_idx, idx]
        
        expect, pubkey, script, _ = make_ms_address(M, keys, idx=idx, addr_fmt=addr_fmt,
                                                        path_mapper=path_mapper)

        assert int(subpath.split('/')[-1][0]) == idx
        assert int(subpath.split('/')[-2]) == chng_idx
        #print('../0/%s => \n %s' % (idx, B2A(script)))

        assert addr[:5] == expect[:5]
        assert addr[-6:] == expect[-6:]


def test_dup_ms_wallet_bug(goto_home, pick_menu_item, need_keypress, import_ms_wallet, clear_ms, M=2, N=3):

    deriv = ["m/48'/1'/0'/69'/1"]*N
    fmts = [ 'p2wsh', 'p2sh-p2wsh']

    clear_ms()

    for n, ty in enumerate(fmts):
        import_ms_wallet(M, N, name=f'name-{n}', accept=1, derivs=deriv, addr_fmt=ty)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')

    # drill down to second one
    time.sleep(.1)
    pick_menu_item('2/3: name-1')
    pick_menu_item('Delete')
    need_keypress('y')

    # BUG: pre v4.0.3, would be showing a "Yikes" referencing multisig:419 at this point

    pick_menu_item('2/3: name-0')
    pick_menu_item('Delete')
    need_keypress('y')

    clear_ms()

@pytest.mark.parametrize('M_N', [(2, 3), (2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [ AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH ])
@pytest.mark.parametrize('int_ext_desc', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_import_desciptor(M_N, addr_fmt, int_ext_desc, way, import_ms_wallet, goto_home, pick_menu_item,
                          need_keypress, clear_ms, cap_story, microsd_path, virtdisk_path,
                          nfc_read_text, load_export):
    clear_ms()
    M, N = M_N
    import_ms_wallet(M, N, addr_fmt=addr_fmt, accept=1, descriptor=True, int_ext_desc=int_ext_desc)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    need_keypress('y')  # only one enrolled multisig - choose it
    pick_menu_item('Descriptors')
    pick_menu_item('Export')
    contents = load_export(way, label="Descriptor multisig setup", is_json=False, sig_check=False)
    desc_export = contents.strip()
    with open("debug/last-ms.txt", "r") as f:
        desc_import = f.read().strip()
    normalized = parse_desc_str(desc_export)
    # as new format is not widely supported we only allow to import it - no export yet
    if int_ext_desc:
        # checksum will differ - ignore it
        assert desc_import.split("#")[0] == normalized.split("#")[0].replace("0/*", "<0;1>/*")
    else:
        assert desc_import == normalized
    starts_with = MULTI_FMT_TO_SCRIPT[addr_fmt].split("%")[0]
    assert normalized.startswith(starts_with)
    assert "sortedmulti(" in desc_export


@pytest.mark.bitcoind
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize('descriptor', [True, False])
@pytest.mark.parametrize('M_N', [(3, 15), (2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_bitcoind_ms_address(change, descriptor, M_N, addr_fmt, clear_ms, goto_home, need_keypress,
                             pick_menu_item, cap_menu, cap_story, make_multisig, import_ms_wallet,
                             microsd_path, bitcoind_d_wallet_w_sk, use_regtest, load_export, way):
    use_regtest()
    clear_ms()
    bitcoind = bitcoind_d_wallet_w_sk
    M, N = M_N
    wal_name = f"ax{M}-{N}-{addr_fmt}"

    dd = {
        AF_P2WSH: ("m/48'/1'/0'/2'/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45'/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48'/1'/0'/1'/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]

    keys = make_multisig(M, N, unique=1, deriv=deriv)

    derivs = [deriv.format(idx=i) for i in range(N)]

    clear_ms()
    import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=derivs, addr_fmt=text_a_fmt,
                            descriptor=descriptor)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')  # warning
    m = cap_menu()
    if descriptor:
        wal_name = m[-1]
    else:
        assert wal_name in m
    pick_menu_item(wal_name)

    time.sleep(0.2)
    title, story = cap_story()
    assert "Press (6)" in story
    assert "change addresses." in story
    if change:
        need_keypress("6")
        time.sleep(0.2)
        title, story = cap_story()
        # once change is selected - do not offer this option again
        assert "change addresses." not in story
        assert "Press (6)" not in story

    contents = load_export(way, label="Address summary", is_json=False, sig_check=False, vdisk_key="4")
    addr_cont = contents.strip()
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    need_keypress('y')  # only one enrolled multisig - choose it
    pick_menu_item('Descriptors')
    pick_menu_item("Bitcoin Core")
    contents = load_export(way, label="Bitcoin Core multisig setup", is_json=False, sig_check=False)
    text = contents.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    if change:
        # in descriptor.py we always append external descriptor first
        desc_export = core_desc_object[1]["desc"]
    else:
        desc_export = core_desc_object[0]["desc"]

    if descriptor:
            assert "sortedmulti(" in desc_export
    if way == "nfc":
        addr_range = [0, 9]
        cc_addrs = addr_cont.split("\n")
        part_addr_index = 0
    else:
        addr_range = [0, 249]
        cc_addrs = addr_cont.split("\n")[1:]
        part_addr_index = 1
    bitcoind_addrs = bitcoind.deriveaddresses(desc_export, addr_range)
    for idx, cc_item in enumerate(cc_addrs):
        cc_item = cc_item.split(",")
        partial_address = cc_item[part_addr_index]
        _start, _end = partial_address.split("___")
        if way != "nfc":
            _start, _end = _start[1:], _end[:-1]
        assert bitcoind_addrs[idx].startswith(_start)
        assert bitcoind_addrs[idx].endswith(_end)


@pytest.fixture
def bitcoind_multisig(bitcoind, bitcoind_d_sim_watch, need_keypress, cap_story, load_export, pick_menu_item, goto_home,
                      cap_menu, microsd_path, use_regtest):
    def doit(M, N, script_type, cc_account=0, funded=True):
        use_regtest()
        bitcoind_signers = [
            bitcoind.create_wallet(wallet_name=f"bitcoind--signer{i}", disable_private_keys=False, blank=False,
                                   passphrase=None, avoid_reuse=False, descriptors=True)
            for i in range(N - 1)
        ]
        for signer in bitcoind_signers:
            signer.keypoolrefill(10)
        # watch only wallet where multisig descriptor will be imported
        ms = bitcoind.create_wallet(
            wallet_name=f"watch_only_{script_type}_{M}of{N}", disable_private_keys=True,
            blank=True, passphrase=None, avoid_reuse=False, descriptors=True
        )
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Export XPUB')
        time.sleep(0.5)
        title, story = cap_story()
        assert "extended public keys (XPUB) you would need to join a multisig wallet" in story
        need_keypress("y")
        need_keypress(str(cc_account))  # account
        need_keypress("y")
        xpub_obj = load_export("sd", label="Multisig XPUB", is_json=True, sig_check=False)
        template = xpub_obj[script_type +"_desc"]
        # get keys from bitcoind signers
        bitcoind_signers_xpubs = []
        for signer in bitcoind_signers:
            target_desc = ""
            bitcoind_descriptors = signer.listdescriptors()["descriptors"]
            for desc in bitcoind_descriptors:
                if desc["desc"].startswith("pkh(") and desc["internal"] is False:
                    target_desc = desc["desc"]
            core_desc, checksum = target_desc.split("#")
            # remove pkh(....)
            core_key = core_desc[4:-1]
            bitcoind_signers_xpubs.append(core_key)
        desc = template.replace("M", str(M), 1).replace("...", ",".join(bitcoind_signers_xpubs))

        if script_type == 'p2wsh':
            name = f"core{M}of{N}_native.txt"
        elif script_type == "p2sh_p2wsh":
            name = f"core{M}of{N}_wrapped.txt"
        else:
            name = f"core{M}of{N}_legacy.txt"
        with open(microsd_path(name), "w") as f:
            f.write(desc + "\n")
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Import from File')
        time.sleep(0.3)
        _, story = cap_story()
        if "Press (1) to import multisig wallet file from SD Card" in story:
            # in case Vdisk is enabled
            need_keypress("1")
        time.sleep(0.5)
        need_keypress("y")
        pick_menu_item(name)
        _, story = cap_story()
        assert "Create new multisig wallet?" in story
        assert name.split(".")[0] in story
        assert f"{M} of {N}" in story
        if M == N:
            assert f"All {N} co-signers must approve spends" in story
        else:
            assert f"{M} signatures, from {N} possible" in story
        if script_type == "p2wsh":
            assert "P2WSH" in story
        elif script_type == "p2sh":
            assert "P2SH" in story
        else:
            assert "P2SH-P2WSH" in story
        assert "Derivation:\n  Varies (2)" in story
        need_keypress("y")  # approve multisig import
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        menu = cap_menu()
        pick_menu_item(menu[0])  # pick imported descriptor multisig wallet
        pick_menu_item("Descriptors")
        pick_menu_item("Bitcoin Core")
        text = load_export("sd", label="Bitcoin Core multisig setup", is_json=False, sig_check=False)
        text = text.replace("importdescriptors ", "").strip()
        # remove junk
        r1 = text.find("[")
        r2 = text.find("]", -1, 0)
        text = text[r1: r2]
        core_desc_object = json.loads(text)
        # import descriptors to watch only wallet
        res = ms.importdescriptors(core_desc_object)
        assert res[0]["success"]
        assert res[1]["success"]

        if funded:
            if script_type == "p2wsh":
                addr_type = "bech32"
            elif script_type == "p2tr":
                addr_type = "bech32m"
            elif script_type == "p2sh":
                addr_type = "legacy"
            else:
                addr_type = "p2sh-segwit"

            addr = ms.getnewaddress("", addr_type)
            if script_type == "p2wsh":
                sw = "bcrt1q"
            elif script_type == "p2tr":
                sw = "bcrt1p"
            else:
                sw = "2"
            assert addr.startswith(sw)
            # get some coins and fund above multisig address
            bitcoind.supply_wallet.sendtoaddress(addr, 49)
            bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above

        return ms, bitcoind_signers

    return doit

@pytest.mark.bitcoind
def test_legacy_multisig_witness_utxo_in_psbt(bitcoind, use_regtest, clear_ms, microsd_wipe, goto_home, need_keypress,
                                              pick_menu_item, cap_story, load_export, microsd_path, cap_menu, try_sign):
    use_regtest()
    clear_ms()
    microsd_wipe()
    M,N = 2,2
    cosigner = bitcoind.create_wallet(wallet_name=f"bitcoind--signer-wit-utxo", disable_private_keys=False, blank=False,
                                      passphrase=None, avoid_reuse=False, descriptors=True)
    ms = bitcoind.create_wallet(
        wallet_name=f"watch_only_legacy_2of2", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')
    time.sleep(0.5)
    title, story = cap_story()
    assert "extended public keys (XPUB) you would need to join a multisig wallet" in story
    need_keypress("y")
    need_keypress("0")  # account
    need_keypress("y")
    xpub_obj = load_export("sd", label="Multisig XPUB", is_json=True, sig_check=False)
    template = xpub_obj["p2sh_desc"]
    # get key from bitcoind cosigner
    target_desc = ""
    bitcoind_descriptors = cosigner.listdescriptors()["descriptors"]
    for desc in bitcoind_descriptors:
        if desc["desc"].startswith("pkh(") and desc["internal"] is False:
            target_desc = desc["desc"]
    core_desc, checksum = target_desc.split("#")
    # remove pkh(....)
    core_key = core_desc[4:-1]
    desc = template.replace("M", str(M), 1).replace("...", core_key)
    desc_info = ms.getdescriptorinfo(desc)
    desc_w_checksum = desc_info["descriptor"]  # with checksum
    name = f"core{M}of{N}_legacy.txt"
    with open(microsd_path(name), "w") as f:
        f.write(desc_w_checksum + "\n")
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Import from File')
    time.sleep(0.3)
    _, story = cap_story()
    if "Press (1) to import multisig wallet file from SD Card" in story:
        # in case Vdisk is enabled
        need_keypress("1")
    time.sleep(0.5)
    need_keypress("y")
    pick_menu_item(name)
    _, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert name.split(".")[0] in story
    assert f"{M} of {N}" in story
    assert f"All {N} co-signers must approve spends" in story
    assert "P2SH" in story
    assert "Derivation:\n  Varies (2)" in story
    need_keypress("y")  # approve multisig import
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    menu = cap_menu()
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core multisig setup", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # import descriptors to watch only wallet
    res = ms.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"], obj
    # send to address type
    addr_type = "legacy"
    multi_addr = ms.getnewaddress("", addr_type)
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=49)
    bitcoind.supply_wallet.generatetoaddress(101, bitcoind.supply_wallet.getnewaddress())  # mining
    dest_addr = ms.getnewaddress("", addr_type)
    assert all([addr.startswith("2") for addr in [multi_addr, dest_addr]])
    # create funded PSBT
    psbt_resp = ms.walletcreatefundedpsbt(
        [], [{dest_addr: 5}], 0, {"fee_rate": 20, "change_type": addr_type, "subtractFeeFromOutputs": [0]}
    )
    psbt = psbt_resp.get("psbt")
    import base64
    o = BasicPSBT().parse(base64.b64decode(psbt))
    assert len(o.inputs) == 1
    non_witness_utxo = o.inputs[0].utxo
    from io import BytesIO
    parsed_tx = Tx.Tx.parse(BytesIO(non_witness_utxo))
    witness_utxo = BytesIO()
    for oo in parsed_tx.txs_out:
        if oo.coin_value == 4900000000:
            parsed_tx.txs_out[0].stream(witness_utxo)
    o.inputs[0].witness_utxo = witness_utxo.getvalue()
    updated = o.as_bytes()
    try_sign(updated)


@pytest.mark.bitcoind
@pytest.mark.parametrize("m_n", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("script_type", ["p2wsh", "p2sh_p2wsh", "p2sh"])
@pytest.mark.parametrize("sighash", list(SIGHASH_MAP.keys()))
def test_bitcoind_MofN_tutorial(m_n, script_type, clear_ms, goto_home, need_keypress, pick_menu_item,
                                sighash, cap_menu, cap_story, microsd_path, use_regtest, bitcoind,
                                microsd_wipe, load_export, settings_set, bitcoind_multisig):
    # 2of2 case here is described in docs with tutorial
    M, N = m_n
    settings_set("sighshchk", 1)  # disable checks
    clear_ms()
    microsd_wipe()
    # create multisig with N-1 bitcoind signers + CC sim and register it
    bitcoind_watch_only, bitcoind_signers = bitcoind_multisig(M, N, script_type)
    if script_type == "p2wsh":
        addr_type = "bech32"
    elif script_type == "p2tr":
        addr_type = "bech32m"
    elif script_type == "p2sh":
        addr_type = "legacy"
    else:
        addr_type = "p2sh-segwit"
    # create funded PSBT
    all_of_it = bitcoind_watch_only.getbalance()
    dest_addr = bitcoind_watch_only.getnewaddress("", addr_type)
    # creates two utxos
    psbt_resp = bitcoind_watch_only.walletcreatefundedpsbt(
        [], [{dest_addr: all_of_it - 1}], 0, {"fee_rate": 20, "change_type": addr_type,
                                          "subtractFeeFromOutputs": [0]}
    )
    psbt = psbt_resp.get("psbt")
    x = BasicPSBT().parse(base64.b64decode(psbt))
    for idx, i in enumerate(x.inputs):
        i.sighash = SIGHASH_MAP[sighash]
    psbt = x.as_b64_str()
    # sign with all bitcoind signers
    for signer in bitcoind_signers:
        half_signed_psbt = signer.walletprocesspsbt(psbt, True, sighash, True, False)  # do not finalize
        psbt = half_signed_psbt["psbt"]
    name = f"hsc_{M}of{N}_{script_type}.psbt"
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if "OK TO SEND?" in title:
        # multiple files
        pass
    else:
        try:
            pick_menu_item(name)
        except:
            time.sleep(0.5)
            need_keypress("y")
            pick_menu_item(name)
            time.sleep(0.5)
            title, story = cap_story()
    assert title == "OK TO SEND?"
    if sighash != "ALL":
        assert "(1 warning below)" in story
        assert "---WARNING---" in story
        if sighash in ("NONE", "NONE|ANYONECANPAY"):
            assert "Danger" in story
            assert "Destination address can be changed after signing (sighash NONE)." in story
        else:
            assert "Caution" in story
            assert "Some inputs have unusual SIGHASH values not used in typical cases." in story
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    os.remove(microsd_path(name))
    fname = story.split("\n\n")[-1]
    with open(microsd_path(fname), "r") as f:
        final_psbt = f.read().strip()
    res = bitcoind_watch_only.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id


    consolidate = bitcoind_watch_only.getnewaddress("", addr_type)
    balance = bitcoind_watch_only.getbalance()
    unspent = bitcoind_watch_only.listunspent()
    psbt_outs = [{consolidate: balance}]
    res0 = bitcoind_watch_only.walletcreatefundedpsbt(unspent, psbt_outs, 0,
                                                      {"fee_rate": 20, "subtractFeeFromOutputs": [0]})
    psbt = res0["psbt"]
    x = BasicPSBT().parse(base64.b64decode(psbt))
    for idx, i in enumerate(x.inputs):
        i.sighash = SIGHASH_MAP[sighash]
    psbt = x.as_b64_str()
    name = f"change_{M}of{N}_{script_type}.psbt"
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, _ = cap_story()
    if "OK TO SEND?" in title:
        # multiple files
        pass
    else:
        try:
            pick_menu_item(name)
        except:
            time.sleep(0.5)
            need_keypress("y")
            pick_menu_item(name)
            time.sleep(0.5)
            title, story = cap_story()
    assert title == "OK TO SEND?"
    need_keypress("y")  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    if "SINGLE" in sighash:
        # we have only one output (consolidation) and legacy sighash does not support index out of range
        # now not just legacy but also segwit prohibits SINGLE out of bounds
        # consensus allows it but it really is just bad usage - restricted
        assert "SINGLE corresponding output" in story
        assert "missing" in story
        return

    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    need_keypress("y")
    fname = story.split("\n\n")[-1]
    with open(microsd_path(fname), "r") as f:
        cc_signed_psbt = f.read().strip()
    # CC already signed - now all bitcoin signers
    for signer in bitcoind_signers:
        res1 = signer.walletprocesspsbt(cc_signed_psbt, True, sighash)
        psbt = res1["psbt"]
        cc_signed_psbt = psbt
    res = bitcoind_watch_only.finalizepsbt(cc_signed_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind_signers[0].generatetoaddress(1, bitcoind_signers[0].getnewaddress())  # mine block
    assert len(bitcoind_watch_only.listunspent()) == 1


@pytest.mark.parametrize("desc", [
    # lack of checksum is now legal
    # ("Missing descriptor checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))"),
    ("Wrong checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#gs2fqgl7"),
    ("Invalid subderivation path - only 0/* or <0;1>/* allowed", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/1/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#sj7lxn0l"),
    ("Key derivation too long", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#fy9mm8dt"),
    ("Key origin info is required", "wsh(sortedmulti(2,tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#ypuy22nw"),
    ("xpub depth", "wsh(sortedmulti(2,[0f056943]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#nhjvt4wd"),
    ("Key derivation too long", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0))#s487stua"),
    ("Cannot use hardened sub derivation path", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0'/*))#3w6hpha3"),
    ("M must be <= N", "wsh(sortedmulti(3,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#uueddtsy"),
])
def test_exotic_descriptors(desc, clear_ms, goto_home, need_keypress, pick_menu_item, cap_menu, cap_story, make_multisig,
                            import_ms_wallet, microsd_path, bitcoind_d_wallet_w_sk, use_regtest):
    use_regtest()
    clear_ms()
    msg, desc = desc
    name = "exotic.txt"
    if os.path.exists(microsd_path(name)):
        os.remove(microsd_path(name))
    with open(microsd_path(name), "w") as f:
        f.write(desc + "\n")
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Import from File')
    time.sleep(0.5)
    _, story = cap_story()
    if "Pick multisig wallet file to import" not in story:
        assert "Press (1) to import multisig wallet file from SD Card" in story
        need_keypress("1")
    time.sleep(0.5)
    need_keypress("y")
    pick_menu_item(name)
    _, story = cap_story()
    assert "Failed to import" in story
    assert msg in story

def test_ms_wallet_ordering(clear_ms, import_ms_wallet, try_sign_microsd, fake_ms_txn):
    clear_ms()
    all_out_styles = list(unmap_addr_fmt.keys())
    index = all_out_styles.index("p2sh-p2wsh")
    all_out_styles[index] = "p2wsh-p2sh"
    # create two wallets from same master seed (same extended keys and paths, different length (N))
    # 1. 3of6
    # 2. 3of5  (import in this order, import one with more keys first)
    # create PSBT for wallet with less keys
    # sign it
    # WHY: as we store wallets in list, they are ordered by their addition/import. Iterating over
    # wallet candindates in psbt.py M are equal N differs --> assertion error
    name = f'ms1'
    import_ms_wallet(3, 6, name=name, accept=1, do_import=True, addr_fmt="p2wsh")
    name = f'ms2'
    keys3 = import_ms_wallet(3, 5, name=name, accept=1, do_import=True, addr_fmt="p2wsh")

    psbt = fake_ms_txn(5, 5, 3, keys3, outstyles=all_out_styles, segwit_in=True, incl_xpubs=True)

    open('debug/last.psbt', 'wb').write(psbt)

    try_sign_microsd(psbt, encoding='base64')


@pytest.mark.parametrize("descriptor", [True, False])
@pytest.mark.parametrize("m_n", [(2, 3), (3, 5), (5, 10)])
def test_ms_xpub_ordering(descriptor, m_n, clear_ms, make_multisig, import_ms_wallet, try_sign_microsd, fake_ms_txn):
    import itertools
    clear_ms()
    M, N = m_n
    all_out_styles = list(unmap_addr_fmt.keys())
    index = all_out_styles.index("p2sh-p2wsh")
    all_out_styles[index] = "p2wsh-p2sh"
    name = f'ms1'
    keys = make_multisig(M, N)
    all_options = list(itertools.combinations(keys, len(keys)))
    for opt in all_options:
        import_ms_wallet(M, N, keys=opt, name=name, accept=1, do_import=True, addr_fmt="p2wsh", descriptor=descriptor)
        psbt = fake_ms_txn(5, 5, M, opt, outstyles=all_out_styles, segwit_in=True, incl_xpubs=True)
        open('debug/last.psbt', 'wb').write(psbt)
        try_sign_microsd(psbt, encoding='base64')
        for opt_1 in all_options:
            # create PSBT with original keys order
            psbt = fake_ms_txn(5, 5, M, opt_1, outstyles=all_out_styles, segwit_in=True, incl_xpubs=True)
            open('debug/last.psbt', 'wb').write(psbt)
            try_sign_microsd(psbt, encoding='base64')


@pytest.mark.parametrize('cmn_pth_from_root', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('M_N', [(3, 5), (2, 3), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
def test_multisig_descriptor_export(M_N, way, addr_fmt, cmn_pth_from_root, clear_ms, make_multisig,
                                    import_ms_wallet, goto_home, pick_menu_item, cap_menu,
                                    nfc_read_text, microsd_path, cap_story, need_keypress,
                                    load_export):

    def choose_multisig_wallet():
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        menu = cap_menu()
        pick_menu_item(menu[0])

    M, N = M_N
    wal_name = f"reexport_{M}-{N}-{addr_fmt}"

    dd = {
        AF_P2WSH: ("m/48'/1'/0'/2'/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45'/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48'/1'/0'/1'/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]
    keys = make_multisig(M, N, unique=1, deriv=None if cmn_pth_from_root else deriv)
    derivs = [deriv.format(idx=i) for i in range(N)]
    clear_ms()

    import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name,
                     derivs=None if cmn_pth_from_root else derivs,
                     addr_fmt=text_a_fmt, descriptor=True,
                     common="m/45'" if cmn_pth_from_root else None)

    # get bare descriptor
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("Export")
    contents = load_export(way, label="Descriptor multisig setup", is_json=False, sig_check=False)
    bare_desc = contents.strip()

    # get pretty descriptor
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("View Descriptor")
    need_keypress("1")
    contents = load_export(way, label="Descriptor multisig setup", is_json=False, sig_check=False)
    pretty_desc = contents.strip()

    # get core descriptor json
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    core_desc_text = load_export(way, label="Bitcoin Core multisig setup", is_json=False, sig_check=False)

    # remove junk
    text = core_desc_text.replace("importdescriptors ", "").strip()
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)

    # get descriptor from view descriptor
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("View Descriptor")
    _, story = cap_story()
    view_desc = story.strip().split("\n\n")[1]

    # assert that bare and pretty are the same after parse
    assert bare_desc == view_desc
    assert parse_desc_str(pretty_desc) == bare_desc
    for obj in core_desc_object:
        if obj["internal"]:
            pass
        else:
            assert obj["desc"] == bare_desc
    clear_ms()

# EOF
