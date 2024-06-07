# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Multisig-related tests.
#
# After this file passes, also run again like this:
#
#       py.test test_multisig.py -m ms_danger --ms-danger
#
import sys
sys.path.append("../shared")
from descriptor import MultisigDescriptor, append_checksum, MULTI_FMT_TO_SCRIPT, parse_desc_str
import time, pytest, os, random, json, shutil, pdb, io, base64, struct, bech32, itertools, re
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from ckcc.protocol import CCProtocolPacker, MAX_TXN_LEN
from pprint import pprint
from base64 import b64encode, b64decode
from base58 import encode_base58_checksum
from helpers import B2A, fake_dest_addr, xfp2str, detruncate_address
from helpers import path_to_str, str_to_path, slip132undo, swab32, hash160
from struct import unpack, pack
from constants import *
from bip32 import BIP32Node
from ctransaction import CTransaction, CTxOut, CTxIn, COutPoint, uint256_from_str
from io import BytesIO
from hashlib import sha256
from bbqr import split_qrs
from charcodes import KEY_QR


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

@pytest.fixture
def make_multisig(dev, sim_execfile):
    # make a multsig wallet, always with simulator as an element

    # default is BIP-45:   m/45'/... (but no co-signer idx)
    # - but can provide str format for deriviation, use {idx} for cosigner idx

    def doit(M, N, unique=0, deriv=None, dev_key=False):
        keys = []

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d - %d' % (i, unique), 'XTN')

            xfp = unpack("<I", pk.fingerprint())[0]

            if not deriv:
                sub = pk.subkey_for_path("m/45h")
            else:
                path = deriv.format(idx=i)
                try:
                    sub = pk.subkey_for_path(path)
                except IndexError:
                    # some test cases are using bogus paths
                    sub = pk

            keys.append((xfp, pk, sub))

        if dev_key:
            sk = sim_execfile('devtest/dump_private.py').strip()
            pk = BIP32Node.from_wallet_key(sk)
            xfp_bytes = pk.fingerprint()
            xfp = swab32(struct.unpack('>I', xfp_bytes)[0])
        else:
            pk = BIP32Node.from_wallet_key(simulator_fixed_tprv)
            xfp = simulator_fixed_xfp

        if not deriv:
            sub = pk.subkey_for_path("m/45h")
        else:
            path = deriv.format(idx=N-1)
            try:
                sub = pk.subkey_for_path(path)
            except IndexError:
                # some test cases are using bogus paths
                sub = pk

        keys.append((xfp, pk, sub))

        return keys

    return doit

@pytest.fixture
def offer_ms_import(cap_story, dev):
    def doit(config, allow_non_ascii=False):
        # upload the file, trigger import
        file_len, sha = dev.upload_file(config.encode('utf-8' if allow_non_ascii else 'ascii'))

        open('debug/last-config.txt', 'wt').write(config)

        dev.send_recv(CCProtocolPacker.multisig_enroll(file_len, sha))

        time.sleep(.2)
        title, story = cap_story()
        #print(repr(story))

        return title, story

    return doit

@pytest.fixture
def import_multisig(request, is_q1, need_keypress, offer_ms_import):
    def doit(fname=None, way="sd", data=None, name=None):
        assert fname or data
        if fname:
            if way == "sd":
                microsd_path = request.getfixturevalue("microsd_path")
                fpath = microsd_path(fname)
            else:
                virtdisk_path = request.getfixturevalue("virtdisk_path")
                fpath = virtdisk_path(fname)
            with open(fpath, 'r') as f:
                config = f.read()
        else:
            config = data
        if way is None:  # USB
            title, story = offer_ms_import(config)
        else:
            # only get those simulator related fixtures here, to be able to
            # use this with real HW
            cap_menu = request.getfixturevalue('cap_menu')
            cap_story = request.getfixturevalue('cap_story')
            goto_home = request.getfixturevalue('goto_home')
            pick_menu_item = request.getfixturevalue('pick_menu_item')

            if "Skip Checks?" not in cap_menu():
                # we are not in multisig menu
                goto_home()
                pick_menu_item("Settings")
                pick_menu_item("Multisig Wallets")
                time.sleep(.1)

            ms_menu = cap_menu()
            if way == "qr":
                if "Import from QR" not in ms_menu and not is_q1:
                    pytest.skip("No QR support")

                scan_a_qr = request.getfixturevalue('scan_a_qr')
                pick_menu_item("Import from QR")

                actual_vers, parts = split_qrs(config, 'U', max_version=20)
                random.shuffle(parts)

                for p in parts:
                    scan_a_qr(p)
                    time.sleep(2.0 / len(parts))

            elif way == "nfc":
                if "Import via NFC" not in ms_menu:
                    pytest.skip("NFC disabled")

                nfc_write_text = request.getfixturevalue('nfc_write_text')
                pick_menu_item("Import via NFC")
                nfc_write_text(config)
                time.sleep(0.5)

            else:
                assert way in ("sd", "vdisk")
                if way == "sd":
                    path_f = request.getfixturevalue('microsd_path')
                else:
                    path_f = request.getfixturevalue('virtdisk_path')

                if not fname:
                    fname = (name or "ms_wal.txt") + ".txt"
                    with open(path_f(fname), "w") as f:
                        f.write(config)

                pick_menu_item("Import from File")
                time.sleep(.1)
                _, story = cap_story()
                if way == "vdisk":
                    if "(2) to import from Virtual Disk" not in story:
                        pytest.skip("VDisk disabled")
                    need_keypress("2")
                else:
                    if "Press (1)" in story:
                        need_keypress("1")

                pick_menu_item(fname)

            time.sleep(.1)
            title, story = cap_story()
        return title, story

    return doit

@pytest.fixture
def import_ms_wallet(dev, make_multisig, offer_ms_import, press_select,
                     is_q1, request, need_keypress, import_multisig,
                     settings_set):

    def doit(M, N, addr_fmt=None, name=None, unique=0, accept=False, common=None,
             keys=None, do_import=True, derivs=None, descriptor=False,
             int_ext_desc=False, dev_key=False, way=None, bip67=True,
             force_unsort_ms=True):
        # param: bip67 if false, only usable together with descriptor=True
        if not bip67:
            assert descriptor, "needs descriptor=True"

        if (not bip67) and force_unsort_ms:
            settings_set("unsort_ms", 1)

        keys = keys or make_multisig(M, N, unique=unique, dev_key=dev_key,
                                     deriv=common or (derivs[0] if derivs else None))
        name = name or f'test-{M}-{N}'

        if not do_import:
            return keys

        if descriptor:
            if not derivs:
                if not common:
                    common = "m/45h"
                key_list = [(xfp, common, dd.hwif(as_private=False)) for xfp, m, dd in keys]
            else:
                assert len(derivs) == N
                key_list = [(xfp, derivs[idx], dd.hwif(as_private=False)) for idx, (xfp, m, dd) in enumerate(keys)]
            desc = MultisigDescriptor(M=M, N=N, keys=key_list, addr_fmt=addr_fmt, is_sorted=bip67)
            if int_ext_desc:
                desc_str = desc.serialize(int_ext=True)
            else:
                desc_str = desc.serialize()
            config = "%s\n" % desc_str
        else:
            # render as a file for import
            config = f"name: {name}\npolicy: {M} / {N}\n\n"

            if addr_fmt:
                if isinstance(addr_fmt, int):
                    addr_fmt = addr_fmt_names[addr_fmt]
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

        title, story = import_multisig(data=config, way=way)

        assert 'Create new multisig' in story \
                or 'Update existing multisig wallet' in story \
                or 'new wallet is similar to' in story
        if descriptor is False:
            # descriptors wallet does not have a name
            assert name in story
        assert f'Policy: {M} of {N}\n' in story

        if accept:
            time.sleep(.1)
            press_select()

            # Test it worked.
            time.sleep(.1)      # required
            xor = 0
            for xfp, _, _ in keys:
                xor ^= xfp
            assert dev.send_recv(CCProtocolPacker.multisig_check(M, N, xor)) == 1

        return keys

    return doit


@pytest.mark.parametrize('N', [ 3, 15])
def test_ms_import_variations(N, make_multisig, offer_ms_import, press_cancel, is_q1):
    # all the different ways...
    keys = make_multisig(N, N)


    # bare, no fingerprints
    # - no xfps
    # - no meta data
    config = '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
    title, story = offer_ms_import(config)
    assert f'Policy: {N} of {N}\n' in story
    press_cancel()

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
        press_cancel()
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
    press_cancel()

    # the different addr formats
    for af in unmap_addr_fmt.keys():
        if af == "p2tr": continue
        config = f'format: {af}\n'
        config += '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
        title, story = offer_ms_import(config)
        press_cancel()
        assert f'Policy: {N} of {N}\n' in story

def make_redeem(M, keys, path_mapper=None, violate_script_key_order=False,
                tweak_redeem=None, tweak_xfps=None, finalizer_hack=None,
                tweak_pubkeys=None, bip67=True):
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
            dpath = path[sk.node.depth:]
            assert not dpath or max(dpath) < 1000
            node = sk
        else:
            dpath = path

        node = node.subkey_for_path(path_to_str(dpath, skip=0))

        pk = node.sec()
        data.append( (pk, xfp, path))

        #print("path: %s => pubkey %s" % (path_to_str(path, skip=0), B2A(pk)))

    if bip67:
        data.sort(key=lambda i:i[0])

    if violate_script_key_order:
        # move them out of order works for both multi and sortedmulti
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

def make_ms_address(M, keys, idx=0, is_change=0, addr_fmt=AF_P2SH, testnet=1,
                    bip67=True, **make_redeem_args):
    # Construct addr and script need to represent a p2sh address
    if 'path_mapper' not in make_redeem_args:
        make_redeem_args['path_mapper'] = lambda cosigner: [HARD(45), cosigner, is_change, idx]

    script, pubkeys, xfp_paths = make_redeem(M, keys, bip67=bip67, **make_redeem_args)

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
        addr = encode_base58_checksum(prefix + digest)

        scriptPubKey = bytes([0xa9, 0x14]) + digest + bytes([0x87])

    return addr, scriptPubKey, script, zip(pubkeys, xfp_paths)
    

@pytest.fixture
def test_ms_show_addr(dev, cap_story, press_select, addr_vs_path, bitcoind_p2sh,
                      has_ms_checks, is_q1):
    def doit(M, keys, addr_fmt=AF_P2SH, bip45=True, **make_redeem_args):
        # test we are showing addresses correctly
        # - verifies against bitcoind as well
        addr_fmt = unmap_addr_fmt.get(addr_fmt, addr_fmt)

        # make a redeem script, using provided keys/pubkeys
        if bip45:
            make_redeem_args['path_mapper'] = lambda i: [HARD(45), i, 0,0]

        scr, pubkeys, xfp_paths = make_redeem(M, keys, **make_redeem_args)
        assert len(scr) <= 520, "script too long for standard!"

        got_addr = dev.send_recv(
            CCProtocolPacker.show_p2sh_address(M, xfp_paths, scr, addr_fmt=addr_fmt),
            timeout=None
        )

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

        press_select()

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
def test_violate_bip67(clear_ms, use_regtest, import_ms_wallet,
                       test_ms_show_addr, has_ms_checks,
                       fake_ms_txn, try_sign):
    # detect when pubkeys are not in order in the redeem script
    clear_ms()
    M, N = 1, 15

    keys = import_ms_wallet(M, N, accept=True)

    # test an address that should be in that wallet.
    time.sleep(.1)
    with pytest.raises(BaseException) as ee:
        test_ms_show_addr(M, keys, violate_script_key_order=True)
    assert 'BIP-67' in str(ee.value)

    psbt = fake_ms_txn(1, 3, M, keys,
                       outstyles=ADDR_STYLES_MS,
                       change_outputs=[1],
                       violate_script_key_order=True)

    with open('debug/last.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(Exception) as e:
        try_sign(psbt)
    assert 'BIP-67' in e.value.args[0]


@pytest.mark.parametrize("has_change", [True, False])
def test_violate_import_order_multi(has_change, clear_ms, import_ms_wallet,
                                    fake_ms_txn, try_sign, test_ms_show_addr):
    clear_ms()
    M, N = 3, 5
    keys = import_ms_wallet(M, N, accept=True, descriptor=True, bip67=False)
    time.sleep(.1)
    with pytest.raises(BaseException) as ee:
        test_ms_show_addr(M, keys, violate_script_key_order=True)
    assert "script key order" in str(ee.value)

    psbt = fake_ms_txn(4, 2, M, keys, outstyles=ADDR_STYLES_MS,
                       change_outputs=[1] if has_change else [],
                       bip67=False, violate_script_key_order=True)

    with open('debug/last.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(Exception) as e:
        try_sign(psbt)
    assert "script key order" in e.value.args[0]


@pytest.mark.bitcoind
@pytest.mark.parametrize('which_pubkey', [0, 1, 14])
def test_bad_pubkey(has_ms_checks, use_regtest, clear_ms, import_ms_wallet,
                    test_ms_show_addr, which_pubkey):
    # give incorrect pubkey inside redeem script
    M, N = 1, 15
    keys = import_ms_wallet(M, N, accept=True)

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
def test_zero_depth(clear_ms, use_regtest, addr_fmt, import_ms_wallet
                    , test_ms_show_addr, make_multisig):
    # test having a co-signer with "m" only key ... ie. depth=0

    M, N = 1, 2
    keys = make_multisig(M, N, unique=99)

    # censor first co-signer to look like a master key
    from copy import deepcopy
    kk = deepcopy(keys[0][1])
    kk.node.depth = 0
    kk.node.index = 0
    kk.node.parsed_parent_fingerprint = None
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
def test_bad_xfp(mode, clear_ms, use_regtest, import_ms_wallet
                 , test_ms_show_addr, has_ms_checks, request):
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
def test_bad_common_prefix(cpp, use_regtest, clear_ms, import_ms_wallet,
                           test_ms_show_addr):
    # give some incorrect path values as the common prefix derivation

    M, N = 1, 15
    with pytest.raises(BaseException) as ee:
        keys = import_ms_wallet(M, N, accept=1, common=cpp)
    assert 'bad derivation line' in str(ee)


@pytest.mark.parametrize("desc", ["multi", "sortedmulti"])
def test_import_detail(desc, clear_ms, import_ms_wallet, need_keypress,
                       cap_story, is_q1, press_cancel):
    # check all details are shown right

    M,N = 14, 15
    descriptor, bip67 = (True, False) if desc == "multi" else (False, True)
    keys = import_ms_wallet(M, N, descriptor=descriptor, bip67=bip67)

    time.sleep(.2)
    title, story = cap_story()
    assert f'{M} of {N}' in story
    if desc == "multi":
        assert "WARNING" in story
        assert "BIP-67 disabled" in story
    else:
        assert "WARNING" not in story
        assert "BIP-67 disabled" not in story

    need_keypress('1')
    time.sleep(.1)
    title, story = cap_story()

    if desc == "sortedmulti":
        assert title == f'test-{M}-{N}'
    else:
        # imported from descriptor - name will be just M N
        assert title == f'{M}-of-{N}'

    xpubs = [sk.hwif() for _,_,sk in keys]
    for xp in xpubs:
        assert xp in story

    press_cancel()

    time.sleep(.1)
    press_cancel()


@pytest.mark.parametrize("way", ["qr", "sd", "vdisk", "nfc"])
@pytest.mark.parametrize('acct_num', [0, 99, 123])
@pytest.mark.parametrize('testnet', [True, False])
def test_export_airgap(acct_num, goto_home, cap_story, pick_menu_item, cap_menu,
                       need_keypress, microsd_path, load_export, use_mainnet,
                       testnet, way, is_q1, press_select, skip_if_useless_way):

    skip_if_useless_way(way)

    if not testnet:
        use_mainnet()

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')

    time.sleep(.1)
    title, story = cap_story()
    assert 'BIP-48' in story
    assert "m/45h" not in story
    assert f"m/48h/{int(testnet)}h" in story
    assert "{acct}h" in story
    
    press_select()

    # enter account number every time
    time.sleep(.1)
    for n in str(acct_num):
        need_keypress(n)
    press_select()

    rv = load_export(way, is_json=True, label="Multisig XPUB", fpattern="ccxp-", sig_check=False)

    assert 'xfp' in rv
    assert len(rv) >= 6

    e = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)

    if 'p2sh' in rv:
        # perhaps obsolete, but not removed
        assert acct_num == 0

        n = BIP32Node.from_wallet_key(rv['p2sh'])
        assert n.node.depth == 1
        assert n.node.index == 45 | (1<<31)
        mxfp = unpack("<I", n.parent_fingerprint())[0]
        assert hex(mxfp) == hex(simulator_fixed_xfp)

        expect = e.subkey_for_path("m/45'")
        assert expect.hwif() == n.hwif()

    for name, deriv in [ 
        ('p2sh_p2wsh', f"m/48h/{int(testnet)}h/{acct_num}h/1h"),
        ('p2wsh', f"m/48h/{int(testnet)}h/{acct_num}h/2h"),
    ]:
        e = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
        xpub, *_ = slip132undo(rv[name])
        n = BIP32Node.from_wallet_key(xpub)
        assert rv[name+'_deriv'] == deriv
        assert n.hwif() == xpub
        assert n.node.depth == 4
        assert n.node.index & (1<<31)
        assert n.node.index & 0xff == int(deriv[-2])
        expect = e.subkey_for_path(deriv)
        assert expect.hwif() == n.hwif()

        # TODO add tests for descriptor template

@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('vdisk', [True, False])
def test_import_ux(N, vdisk, goto_home, cap_story, pick_menu_item,
                   need_keypress, microsd_path, make_multisig,
                   virtdisk_path, is_q1, press_cancel, press_select):
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
        if vdisk:
            if "(2) to import from Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress("2")
        else:
            if "(1) to import multisig wallet file from SD Card" in story:
                need_keypress("1")

        time.sleep(.1)
        pick_menu_item(fname.rsplit('/', 1)[1])

        time.sleep(.1)
        _, story = cap_story()

        assert 'Create new multisig' in story
        assert name in story, 'didnt infer wallet name from filename'
        assert f'Policy: {M} of {N}\n' in story

        # abort install
        press_cancel()

    finally:
        # cleanup
        try: os.unlink(fname)
        except: pass

@pytest.mark.parametrize("way", [None, "sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
@pytest.mark.parametrize('comm_prefix', ['m/1/2/3/4/5/6/7/8/9/10/11/12', None, "m/45h"])
def test_export_single_ux(goto_home, comm_prefix, cap_story, pick_menu_item, cap_menu, press_select,
                          microsd_path, import_ms_wallet, addr_fmt, clear_ms, way, load_export, is_q1):

    # create a wallet, export to SD card, check file created.
    # - checks some values for derivation path, assuming MAX_PATH_DEPTH==12

    clear_ms()

    name = 'ex-test-%d' % random.randint(10000,99999)
    M,N = 3, 5
    keys = import_ms_wallet(M, N, name=name, addr_fmt=addr_fmt, accept=1,
                            common=comm_prefix, way=way)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')

    menu = cap_menu()
    item = [i for i in menu if name in i][0]
    pick_menu_item(item)

    pick_menu_item('Coldcard Export')
    contents = load_export(way or "sd", label="Coldcard multisig setup", is_json=False, sig_check=False)
    if way == "qr":
        # QR code still displayed on screen
        press_select()

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
            assert value == (comm_prefix or "m/45h")
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
    title, story = cap_story()
    where = title if is_q1 else story
    assert 'you SURE' in where
    assert name in story

    press_select()
    time.sleep(.1)
    menu = cap_menu()
    assert not [i for i in menu if name in i]
    assert '(none setup yet)' in menu


@pytest.mark.parametrize('N', [ 3, 15])
def test_overflow(N, import_ms_wallet, clear_ms, press_select, cap_story, mk_num, is_q1):

    clear_ms()
    M = N
    name = 'a'*20       # longest possible
    for count in range(1, 10):
        keys = import_ms_wallet(M, N, name=name, addr_fmt='p2wsh', unique=count, accept=0,
                                    common="m/45h/0h/34h")

        time.sleep(.1)
        press_select()

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

    press_select()
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
def test_import_dup_safe(N, clear_ms, make_multisig, offer_ms_import,
                         need_keypress, cap_story, goto_home, pick_menu_item,
                         cap_menu, is_q1, press_select, OK):
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
        # depending if NFC enabled or not, and if Q (has QR)
        assert (len(menu) - num_wallets) in [6, 7, 8]

    title, story = offer_ms_import(make_named('xxx-orig'))
    assert 'Create new multisig wallet' in story
    assert 'xxx-orig' in story
    assert 'P2SH' in story
    press_select()
    has_name('xxx-orig')

    # just simple rename
    title, story = offer_ms_import(make_named('xxx-new'))
    assert 'update name only' in story.lower()
    assert 'xxx-new' in story

    press_select()
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
    press_select()
    has_name('xxx-newer', 2)

    # TODO
    # repeat last one, should still be two
    for keys in ['yn', 'n']:
        title, story = offer_ms_import(newer)
        assert 'Duplicate wallet' in story
        assert f'{OK} to approve' not in story
        assert 'xxx-newer' in story

        for key in keys:
            need_keypress(key)

        has_name('xxx-newer', 2)

    clear_ms()

@pytest.mark.parametrize('N', [ 5])
def test_import_dup_diff_xpub(N, clear_ms, make_multisig, offer_ms_import,
                              press_select, cap_story, goto_home,
                              pick_menu_item, cap_menu, is_q1):
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
                x = bytearray(sk.node.key)
                x[9] = 254
                sk.node.key = bytes(x)

            hwif = sk.hwif()
            lines.append('%s: %s' % (xfp2str(xfp), hwif) )
        config += '\n'.join(lines)
        return config

    title, story = offer_ms_import(make_named('xxx-orig'))
    assert 'Create new multisig wallet' in story
    assert 'xxx-orig' in story
    assert 'P2SH' in story
    press_select()

    # change one key.
    title, story = offer_ms_import(make_named('xxx-new', tweaked=True))
    assert 'WARNING:' in story
    assert 'xxx-new' in story
    assert 'xpubs' in story

    clear_ms()


@pytest.mark.bitcoind
@pytest.mark.parametrize('m_of_n', [(2,2), (2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_dup_xfp_fails(m_of_n, use_regtest, addr_fmt, clear_ms,
                              make_multisig, import_ms_wallet, test_ms_show_addr):

    M, N = m_of_n

    keys = make_multisig(M, N)

    pk = BIP32Node.from_master_secret(b'example', 'XTN')
    sub = pk.subkey_for_path("m/45h")
    sub.node.parent = None
    sub.node.parsed_parent_fingerprint = keys[-1][2].parent_fingerprint()
    keys[-1] = (simulator_fixed_xfp, pk, sub)

    with pytest.raises(Exception) as ee:
        import_ms_wallet(M, N, addr_fmt, accept=1, keys=keys)

    #assert 'XFP' in str(ee)
    assert 'wrong pubkey' in str(ee)

@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_ms_cli(dev, addr_fmt, clear_ms, import_ms_wallet, addr_vs_path, desc):
    # exercise the p2sh command of ckcc:cli ... hard to do manually.
    from subprocess import check_output

    M, N = 2, 3
    clear_ms()
    bip67, descriptor = (False, True) if desc == "multi" else (True, False)
    keys = import_ms_wallet(M, N, name='cli-test', accept=True,
                            addr_fmt=addr_fmt_names[addr_fmt],
                            descriptor=descriptor, bip67=bip67)

    pmapper = lambda i: [HARD(45), i, 0,3]

    scr, pubkeys, xfp_paths = make_redeem(M, keys, pmapper, bip67=bip67)

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
        expect_addr, _, scr2, _ = make_ms_address(M, keys, path_mapper=pmapper,
                                                  addr_fmt=addr_fmt, bip67=bip67)
        assert expect_addr == addr
        assert scr2 == scr

    # need to re-start our connection once ckcc has talked to simulator
    dev.start_encryption()
    dev.check_mitm()

    clear_ms()


@pytest.fixture
def make_myself_wallet(dev, set_bip39_pw, offer_ms_import, press_select, clear_ms,
                       reset_seed_words, is_q1):

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
            # XXX assumes testnet
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
            press_select()

        def select_wallet(idx):
            # select to specific pw
            xfp = set_bip39_pw(passwords[idx])
            if do_import:
                offer_ms_import(config)
                time.sleep(.1)
                press_select()
            assert xfp == keys[idx][0]

        return (keys, select_wallet)

    yield doit

    reset_seed_words()


@pytest.fixture
def fake_ms_txn(pytestconfig):
    # make various size MULTISIG txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    from struct import pack

    def doit(num_ins, num_outs, M, keys, fee=10000, outvals=None, segwit_in=False,
             outstyles=['p2pkh'], change_outputs=[], incl_xpubs=False, hack_psbt=None,
             hack_change_out=False, input_amount=1E8, psbt_v2=None, bip67=True,
             violate_script_key_order=False):

        psbt = BasicPSBT()
        if psbt_v2 is None:
            # anything passed directly to this function overrides
            # pytest flag --psbt2 - only care about pytest flag
            # if psbt_v2 is not specified (None)
            psbt_v2 = pytestconfig.getoption('psbt2')

        if psbt_v2:
            psbt.version = 2
            psbt.txn_version = 2
            psbt.input_count = num_ins
            psbt.output_count = num_outs

        txn = CTransaction()
        txn.nVersion = 2

        if incl_xpubs:
            # add global header with XPUB's
            # - assumes BIP-45
            for idx, (xfp, m, sk) in enumerate(keys):
                if callable(incl_xpubs):
                    psbt.xpubs.append( incl_xpubs(idx, xfp, m, sk) )
                else:
                    kk = pack('<II', xfp, 45|0x80000000)
                    psbt.xpubs.append((sk.node.serialize_public(), kk))

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        for i in range(num_ins):
            # make a fake txn to supply each of the inputs
            # - each input is 1BTC

            # addr where the fake money will be stored.
            addr, scriptPubKey, script, details = make_ms_address(M, keys, idx=i, bip67=bip67,
                                                                  violate_script_key_order=violate_script_key_order)

            # lots of supporting details needed for p2sh inputs
            if segwit_in:
                psbt.inputs[i].witness_script = script
            else:
                psbt.inputs[i].redeem_script = script

            for pubkey, xfp_path in details:
                psbt.inputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)

            # UTXO that provides the funding for to-be-signed txn
            supply = CTransaction()
            supply.nVersion = 2
            out_point = COutPoint(
                uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, 0)),
                73
            )
            supply.vin = [CTxIn(out_point, nSequence=0xffffffff)]

            supply.vout.append(CTxOut(int(input_amount), scriptPubKey))

            if not segwit_in:
                psbt.inputs[i].utxo = supply.serialize_with_witness()
            else:
                psbt.inputs[i].witness_utxo = supply.vout[-1].serialize()

            supply.calc_sha256()
            if psbt_v2:
                psbt.inputs[i].previous_txid = supply.hash
                psbt.inputs[i].prevout_idx = 0
                # TODO sequence
                # TODO height timelock
                # TODO time timelock

            spendable = CTxIn(COutPoint(supply.sha256, 0), nSequence=0xffffffff)
            txn.vin.append(spendable)

        for i in range(num_outs):
            if not outstyles:
                style = ADDR_STYLES[i % len(ADDR_STYLES)]
            elif len(outstyles) == num_outs:
                style = outstyles[i]
            else:
                style = outstyles[i % len(outstyles)]

            if i in change_outputs:
                make_redeem_args = dict()
                if hack_change_out:
                    make_redeem_args = hack_change_out(i)
                if violate_script_key_order:
                    make_redeem_args["violate_script_key_order"] = True

                addr, scriptPubKey, scr, details = \
                    make_ms_address(M, keys, idx=i, addr_fmt=unmap_addr_fmt[style],
                                    bip67=bip67, **make_redeem_args)

                for pubkey, xfp_path in details:
                    psbt.outputs[i].bip32_paths[pubkey] = b''.join(pack('<I', j) for j in xfp_path)

                if 'w' in style:
                    psbt.outputs[i].witness_script = scr
                    if style.endswith('p2sh'):
                        psbt.outputs[i].redeem_script = b'\0\x20' + sha256(scr).digest()
                elif style.endswith('sh'):
                    psbt.outputs[i].redeem_script = scr
            else:
                scriptPubKey = fake_dest_addr(style)

            assert scriptPubKey

            if psbt_v2:
                psbt.outputs[i].script = scriptPubKey
                if outvals:
                    psbt.outputs[i].amount = outvals[i]
                else:
                    psbt.outputs[i].amount = int(round(((input_amount * num_ins) - fee) / num_outs, 4))


            if not outvals:
                h = CTxOut(int(round(((input_amount*num_ins)-fee) / num_outs, 4)), scriptPubKey)
            else:
                h = CTxOut(int(outvals[i]), scriptPubKey)

            txn.vout.append(h)

        if hack_psbt:
            hack_psbt(psbt)

        psbt.txn = txn.serialize_with_witness()

        rv = BytesIO()
        psbt.serialize(rv)
        assert rv.tell() <= MAX_TXN_LEN, 'too fat'

        return rv.getvalue()

    return doit

@pytest.mark.veryslow
@pytest.mark.unfinalized
@pytest.mark.parametrize('addr_fmt', [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH])
@pytest.mark.parametrize('num_ins', [2, 15])
@pytest.mark.parametrize('incl_xpubs', [False, True, 'no-import'])
@pytest.mark.parametrize('transport', ['usb', 'sd'])
@pytest.mark.parametrize('has_change', [True, False])
@pytest.mark.parametrize('M_N', [(2, 3), (5, 15)])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_ms_sign_simple(M_N, num_ins, dev, addr_fmt, clear_ms, incl_xpubs, import_ms_wallet,
                        addr_vs_path, fake_ms_txn, try_sign, try_sign_microsd, transport,
                        has_change, settings_set, desc):
    M, N = M_N
    num_outs = num_ins-1
    descriptor, bip67 = (True, False) if desc == "multi" else (False, True)

    # trust PSBT if we're doing "no-import" case
    settings_set('pms', 2 if (incl_xpubs == 'no-import') else 0)

    clear_ms()

    if incl_xpubs != "no-import":
        do_import = True
    else:
        do_import = False
        if not bip67:
            raise pytest.skip("cannot import unsorted multisig from PSBT")

    keys = import_ms_wallet(M, N, name='cli-test', accept=True, addr_fmt=addr_fmt,
                            do_import=do_import, descriptor=descriptor, bip67=bip67)

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, incl_xpubs=incl_xpubs,
                       outstyles=ADDR_STYLES_MS, change_outputs=[1] if has_change else [],
                       bip67=bip67)

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

    all_out_styles = [af for af in unmap_addr_fmt.keys() if af != "p2tr"]
    num_outs = len(all_out_styles)

    clear_ms()
    use_regtest()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, do_import=(not incl_xpubs))
    N = len(keys)
    assert M<=N

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, segwit_in=segwit, incl_xpubs=incl_xpubs, 
                        outstyles=all_out_styles, change_outputs=list(range(1,num_outs)))

    open(f'debug/myself-before.psbt', 'w').write(b64encode(psbt).decode())
    for idx in range(M):
        select_wallet(idx)
        _, updated = try_sign(psbt, accept_ms_import=incl_xpubs)
        open(f'debug/myself-after.psbt', 'w').write(b64encode(updated).decode())
        assert updated != psbt

        aft = BasicPSBT().parse(updated)
        # check all inputs gained a signature
        assert all(len(i.part_sigs)==(idx+1) for i in aft.inputs)

        psbt = aft.as_bytes()

    # should be fully signed now.
    anal = bitcoind.rpc.analyzepsbt(b64encode(psbt).decode('ascii'))
    try:
        assert not any(inp.get('missing') for inp in anal['inputs']), "missing sigs: %r" % anal
        assert all(inp['next'] in {'finalizer','updater'} for inp in anal['inputs']), "other issue: %r" % anal
    except:
        # XXX seems to be a bug in analyzepsbt function ... not fully studied
        pprint(anal, stream=open('debug/analyzed.txt', 'wt'))
        decode = bitcoind.rpc.decodepsbt(b64encode(psbt).decode('ascii'))
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
@pytest.mark.parametrize('acct_num', [ 0, None, 4321])
@pytest.mark.parametrize('M_N', [(2,3), (8,14)])
@pytest.mark.parametrize('way', ["sd", "qr"])
@pytest.mark.parametrize('incl_self', [True, False, None])
def test_make_airgapped(addr_fmt, acct_num, M_N, goto_home, cap_story, pick_menu_item,
                        need_keypress, microsd_path, set_bip39_pw, clear_ms, enter_number,
                        get_settings, load_export, is_q1, press_select, press_cancel,
                        cap_screen, way, scan_a_qr, skip_if_useless_way, incl_self):
    # test UX and math for bip45 export
    # cleanup
    skip_if_useless_way(way)
    M, N = M_N
    from glob import glob
    for fn in glob(microsd_path('ccxp-*.json')):
        assert fn
        os.unlink(fn)
    clear_ms()

    for idx in range(N - int(incl_self is None)):
        if not idx and (incl_self is True):
            set_bip39_pw('')
        else:
            set_bip39_pw(f'test {idx}')

        goto_home()
        time.sleep(0.1)
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('Export XPUB')
        time.sleep(.05)
        press_select()

        # enter account number every time
        time.sleep(.05)
        if acct_num is None:
            # differing account numbers
            for n in str(idx):
                need_keypress(n)
        else:
            for n in str(acct_num):
                need_keypress(n)
        press_select()

        need_keypress('1')

    set_bip39_pw('')

    assert len(glob(microsd_path('ccxp-*.json'))) == (N - int(incl_self is None))

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Create Airgapped')
    if is_q1:
        time.sleep(.1)
        title, story = cap_story()
        assert "scan multisg XPUBs from QR codes" in story
        if way == "qr":
            need_keypress(KEY_QR)
        else:
            press_select()

    time.sleep(.1)
    title, story = cap_story()
    if way == "sd":
        assert 'XPUB' in story
    else:
        # only QR way offers this special prompt
        assert "address format" in story

    if addr_fmt == 'p2wsh':
        press_select()
    elif addr_fmt == 'p2sh-p2wsh':
        need_keypress('1')
    else:
        assert 0, addr_fmt

    if way == "qr":
        # first non-json garbage
        scan_a_qr("aaaaaaaaaaaaaaaaaaaa")
        time.sleep(1)
        scr = cap_screen()
        assert f"Expected JSON data" in scr

        # JSON but wrong
        _, parts = split_qrs('{"json": "but wrong","missing": "important data"}',
                             'J', max_version=20)
        for p in parts:
            scan_a_qr(p)

        time.sleep(1)
        scr = cap_screen()
        assert f"Missing value: xfp" in scr  # missing xfp

        # need to scan json XPUBs here
        for i, fname in enumerate(glob(microsd_path('ccxp-*.json'))):
            with open(fname, 'r') as f:
                jj = f.read()
            _, parts = split_qrs(jj, 'J', max_version=20)

            for p in parts:
                scan_a_qr(p)

            time.sleep(1)
            scr = cap_screen()
            assert f"Number of keys scanned: {i+1}" in scr

        press_cancel()  # quit QR animation

    if not incl_self:
        time.sleep(.1)
        title, story = cap_story()
        assert "Add current Coldcard" in story
        assert xfp2str(simulator_fixed_xfp) in title
        if incl_self is None:
            # add it here instead of having export xpubs JSON  beforehand
            press_select()
            # choose account number
            enter_number(654 if acct_num is None else acct_num)  # if None, numbers differ
        else:
            press_cancel()

    time.sleep(.1)
    scr = cap_screen()
    assert "How many need to sign?(M)" in scr

    enter_number(M)
    time.sleep(.1)
    title, story = cap_story()

    if incl_self is not False:
        assert "Create new multisig" in story
        press_select()
        # we use clear_ms fixture at the begining of each test
        # new multisig wallet is first menu item
        press_select()
        pick_menu_item("Coldcard Export")
        impf, fname = load_export("sd", label="Coldcard multisig setup", is_json=False,
                                  sig_check=False, ret_fname=True)
        cc_fname = microsd_path(fname)
        assert f'Policy: {M} of {N}' in impf
        if addr_fmt != 'p2sh':
            assert f'Format: {addr_fmt.upper()}' in impf

        press_select()
        press_select()

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
        pick_menu_item(cc_fname.rsplit('/', 1)[1])

        time.sleep(.05)
        title, story = cap_story()
        assert "Create new multisig" in story
        assert f"Policy: {M} of {N}" in story
        if acct_num is None:
            assert ("Varies (%d)" % N) in story
        else:
            assert f"/{acct_num}h/" in story

        need_keypress('1')
        time.sleep(.1)
        title, story = cap_story()
        target = story

    else:
        # own wallet not included in the mix, can only export resulting descriptor
        desc = load_export(way, label="Descriptor multisig setup",
                           is_json=False, sig_check=False)
        desc = desc.strip()
        do = MultisigDescriptor.parse(desc)
        assert do.M == M
        assert do.N == N
        assert do.addr_fmt == (AF_P2WSH if addr_fmt == 'p2wsh' else AF_P2WSH_P2SH)
        target = desc

    if acct_num is None:
        # varies
        # base is the same
        assert len(re.findall(f"/48h/1h/", target)) == N
        for i in range(N - int(incl_self is None)):
            assert len(re.findall(f"/48h/1h/{i}h/{2 if addr_fmt == 'p2wsh' else 1}h", target)) == 1
        if incl_self is None:
            assert len(re.findall(f"/48h/1h/654h/{2 if addr_fmt == 'p2wsh' else 1}h", target)) == 1
    else:
        # all derivations are the same
        assert len(re.findall(f"/48h/1h/{acct_num}h/{2 if addr_fmt == 'p2wsh' else 1}h", target)) == N

    # abort import, good enough
    press_cancel()
    press_cancel()

@pytest.mark.unfinalized
@pytest.mark.bitcoind
@pytest.mark.parametrize('addr_style', ["legacy", "p2sh-segwit", "bech32"])
@pytest.mark.parametrize('cc_sign_first', [True, False])
def test_bitcoind_cosigning(cc_sign_first, dev, bitcoind, import_ms_wallet, clear_ms, try_sign,
                            press_cancel, addr_style, use_regtest, is_q1):
    # Make a P2SH wallet with local bitcoind as a co-signer (and simulator)
    # - send an receive various
    # - following text of <https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md>
    # - the constructed multisig walelt will only work for a single pubkey on core side
    # - before starting this test, have some funds already deposited to bitcoind testnet wallet

    if not bitcoind.has_bdb:
        # addmultisigaddress not supported by descriptor wallets
        pytest.skip("Needs BDB legacy wallet")

    from bip32 import PubKeyNode
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

    node = BIP32Node(PubKeyNode(
        key=a2b_hex(bc_pubkey),
        chain_code=b'\x23'*32,
        depth=len(bc_deriv.split('/'))-1,
        parent_fingerprint=a2b_hex('%08x' % bc_xfp),
        testnet=True
    ))
    # No means to export XPUB from bitcoind! Still. In 2019.
    # - this fake will only work for one pubkey value, the first/topmost
    keys = [
        (bc_xfp, None, node),
        (simulator_fixed_xfp, None, BIP32Node.from_hwif('tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n')),     # simulator: m/45'
    ]

    M,N=2,2

    clear_ms()
    import_ms_wallet(M, N, keys=keys, accept=1, name="core-cosign",
                     addr_fmt=addr_fmt_names[addr_fmt], derivs=[bc_deriv, "m/45h"])

    cc_deriv = "m/45h/55"
    cc_pubkey = B2A(BIP32Node.from_hwif(simulator_fixed_tprv).subkey_for_path(cc_deriv).sec())

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
    press_cancel()      # clear screen / start over

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
    psbt = b64decode(resp['psbt'])

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
        rr = bitcoind.supply_wallet.walletprocesspsbt(b64encode(updated).decode('ascii'), True, "ALL")
        assert rr["complete"]
        both_signed = rr["psbt"]
    else:
        both_signed = b64encode(updated).decode('ascii')

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
    keys = import_ms_wallet(M, N, accept=1, addr_fmt=out_style)

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


@pytest.mark.parametrize('repeat', range(2) )
def test_iss6743(repeat, set_seed_words, sim_execfile, try_sign):
    # from SomberNight <https://github.com/spesmilo/electrum/issues/6743#issuecomment-729965813>
    psbt_b4 = bytes.fromhex('70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae3000008001000080000000800100008000000000030000000000')
    # pre 3.2.0 result
    psbt_wrong = bytes.fromhex('70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c002202034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef63819483045022100a85d08eef6675803fe2b58dda11a553641080e07da36a2f3e116f1224201931b022071b0ba83ef920d49b520c37993c039d13ae508a1adbd47eb4b329713fcc8baef01010304010000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae300000800100008000000080010000800000000003000000220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae0000')
    # psbt_right = bytes.fromhex('70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c002202034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef63819483045022100ae90a7e4c350389816b03af0af46df59a2f53da04cc95a2abd81c0bbc5950c1d02202f9471d6b0664b7a46e81da62d149f688adc7ba2b3413372d26fa618a8460eba01010304010000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae300000800100008000000080010000800000000003000000220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae0000')
    # changed with with introduction of signature grinding
    psbt_right = bytes.fromhex('70736274ff0100520200000001bde05be36069e2e0fe44793c68ad8244bb1a52cc37f152e0fa5b75e40169d7f70000000000fdffffff018b1e000000000000160014ed5180f05c7b1dc980732602c50cda40530e00ad4de11c004f01024289ef0000000000000000007dd565da7ee1cf05c516e89a608968fed4a2450633a00c7b922df66b27afd2e1033a0a4fa4b0a997738ac2f142a395c1f02afcb31d7ffd46a90a0c927a4c411fd704094ef7844f01024289ef0431fcbdcc8000000112d4aaea7292e7870c7eeb3565fa1c1fa8f957fa7c4c24b411d5b4f5710d359a023e63d1e54063525bea286ccb2a0ad7b14560aa31ec4be826afa883141dfe1d53145c9e228d300000800100008000000080010000804f01024289ef04e44b38f1800000014a1960f3a3c86ba355a16a66a548cfb62eeb25663311f7cd662a192896f3777e038cc595159a395e4ec35e477c9523a1512f873e74d303fb03fc9a1503b1ba45271434652fae30000080010000800000008001000080000100df02000000000101d1a321707660769c7f8604d04c9ae2db58cf1ec7a01f4f285cdcbb25ce14bdfd0300000000fdffffff02401f00000000000017a914bfd0b8471a3706c1e17870a4d39b0354bcea57b687c864000000000000160014e608b171d63ec24d9fa252d5c1e45624b14e44700247304402205133eb96df167b895f657cce31c6882840a403013682d9d4651aed2730a7dad502202aaacc045d85d9c711af0c84e7f355cc18bf2f8e6d91774d42ba24de8418a39e012103a58d8eb325abb412eaf927cf11d8b7641c4a468ce412057e47892ca2d13ed6144de11c002202034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381947304402201008b084f53d3064ee381dfb3ff4373b29d6ae765b2af15a4e217e8d5d049c650220576af95d79b8fc686627da8a534141208b225ceb6085cd93fcaffb153ac016ea01010304010000002206034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef638191c5c9e228d3000008001000080000000800100008000000000030000002206039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f1c34652fae300000800100008000000080010000800000000003000000220602ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da60c094ef78400000000030000000104220020a3c65c4e376d82fb3ca45596feee5b08313ad64f38590c1b08bc530d1c0bbfea010569522102ab84641359fa22461b8461515231da63c196614cd22b26e556ed878e30db4da621034211ab0f75c3a307a2f6bf6f09a9e05d3c8edd0ba7a2ac31f432d1045ef6381921039690cf74941da5db291fa8be7348abe3807786732d969eac5d27e0afa909a55f53ae0000')
    seed_words = 'all all all all all all all all all all all all'
    expect_xfp = swab32(int('5c9e228d', 16))
    assert xfp2str(expect_xfp) == '5c9e228d'.upper()

    # load specific private key
    xfp = set_seed_words(seed_words)
    assert xfp == expect_xfp

    # check Coldcard derives expected Upub
    derivation = "m/48h/1h/0h/1h"       # part of devtest/unit_iss6743.py
    expect_xpub = 'Upub5SJWbuhs5tM4mkJST69tnpGGaf8dDTqByx3BLSocWFpq5YLh1fky4DQTFGQVG6nCSqZfUiAAeStdxSQteUcfMsWjDkhniZx4GdwpB18Tnbq'

    pub = sim_execfile('devtest/unit_iss6743.py')
    assert pub == expect_xpub

    # verify psbt globals section
    tp = BasicPSBT().parse(psbt_b4)
    (hdr_xpub, hdr_path), = [(v,k) for v,k in tp.xpubs if k[0:4] == pack('<I', expect_xfp)]
    assert expect_xpub == encode_base58_checksum(hdr_xpub)
    assert derivation == path_to_str(unpack('<%dI' % (len(hdr_path) // 4),hdr_path))

    # sign a multisig, with xpubs in globals
    _, out_psbt = try_sign(psbt_b4, accept=True, accept_ms_import=True)
    assert out_psbt != psbt_wrong
    assert out_psbt == psbt_right

    open('debug/i6.psbt', 'wt').write(out_psbt.hex())

@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('xderiv', [ None, 'any', 'unknown', '*', '', 'none'])
def test_ms_import_nopath(N, xderiv, make_multisig, clear_ms, offer_ms_import):
    # try various synonyms for unknown/any derivation styles

    keys = make_multisig(N, N, deriv="m/48h/0h/0h/1h/0", unique=1)

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
def test_ms_import_many_derivs(M, N, way, make_multisig, clear_ms, offer_ms_import, press_select,
                               pick_menu_item, cap_story, microsd_path, virtdisk_path, nfc_read_text,
                               goto_home, load_export, is_q1):
    # try config file with different derivation paths given, including None
    # - also check we can convert those into Electrum wallets

    actual = "m/48h/0h/0h/1h/0"
    derivs = [ actual, 'm', "m/45h/0h/99h", "m/45h/34/34h/34"]

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
                    xfp2str(xfp), dp, sk.node.depth, dp.count('/')))
            sk.node.depth = dp.count('/')
        config += '%s: %s\n' % (xfp2str(xfp), sk.hwif(as_private=False))

    title, story = offer_ms_import(config)
    assert f'Policy: {M} of {N}\n' in story
    assert f'P2SH-P2WSH' in story
    assert 'Derivation:\n  Varies' in story
    assert f'  Varies ({len(set(derivs))})\n' in story
    press_select()

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
    press_select()

    el = load_export(way, label="Electrum multisig wallet", sig_check=False, is_json=True)

    assert el['seed_version'] == 17
    assert el['wallet_type'] == f"{M}of{N}"
    for n in range(1, N+1):
        kk = f'x{n}/'
        assert kk in el
        co = el[kk]
        assert 'Coldcard' in co['label']
        dd = co['derivation']
        assert (dd in derivs) or (dd == actual) or ("42069h" in dd) or (dd == 'm')

    clear_ms()


@pytest.mark.ms_danger
@pytest.mark.parametrize('descriptor', [True, False])
def test_danger_warning(request, descriptor, clear_ms, import_ms_wallet, cap_story, fake_ms_txn, start_sign, sim_exec):
    # note: cant use has_ms_checks fixture here
    danger_mode = (request.config.getoption('--ms-danger'))
    sim_exec(f'from multisig import MultisigWallet; MultisigWallet.disable_checks={danger_mode}')

    clear_ms()
    M,N = 2,3
    keys = import_ms_wallet(M, N, accept=1, descriptor=descriptor, addr_fmt="p2wsh")
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

@pytest.mark.parametrize('change', [True, False])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize('start_idx', [1000, MAX_BIP32_IDX, 0])
@pytest.mark.parametrize('M_N', [(2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH] )
def test_ms_addr_explorer(change, M_N, addr_fmt, start_idx, clear_ms, cap_menu,
                          need_keypress, goto_home, pick_menu_item, cap_story,
                          import_ms_wallet, make_multisig, settings_set,
                          enter_number, set_addr_exp_start_idx, desc):
    clear_ms()
    M, N = M_N
    wal_name = f"ax{M}-{N}-{addr_fmt}"

    settings_set("aei", True if start_idx else False)

    dd = {
        AF_P2WSH: ("m/48h/1h/0h/2h/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45h/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48h/1h/0h/1h/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]

    keys = make_multisig(M, N, unique=1, deriv=deriv)

    derivs = [deriv.format(idx=i) for i in range(N)]

    clear_ms()

    descriptor = None
    bip67 = True
    if desc == "multi":
        descriptor, bip67 = True, False
    keys = import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=derivs,
                            addr_fmt=text_a_fmt, descriptor=descriptor, bip67=bip67)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')      # warning

    set_addr_exp_start_idx(start_idx)

    m = cap_menu()
    if wal_name in m:
        pick_menu_item(wal_name)
    else:
        # descriptor
        pick_menu_item(f"{M}-of-{N}")

    time.sleep(.5)
    title, story = cap_story()
    assert "(0)" in story
    assert "change addresses." in story
    if change:
        need_keypress("0")
        time.sleep(0.2)
        title, story = cap_story()
        # once change is selected - do not offer this option again
        assert "change addresses." not in story
        assert "(0)" not in story
    # unwrap text a bit
    if change:
        story = story.replace("=>\n", "=> ").replace('1/0]\n =>', "1/0 =>")
    else:
        story = story.replace("=>\n", "=> ").replace('0/0]\n =>', "0/0 =>")

    maps = []
    for ln in story.split('\n'):
        if '=>' not in ln: continue

        path,chk,addr = ln.split()
        assert chk == '=>'
        assert '/' in path

        maps.append( (path, addr) )

    if start_idx <= 2147483638:
        assert len(maps) == 10
    else:
        assert len(maps) == (MAX_BIP32_IDX - start_idx) + 1

    for idx, (subpath, addr) in enumerate(maps, start=start_idx):
        chng_idx = 1 if change else 0
        path_mapper = lambda co_idx: str_to_path(derivs[co_idx]) + [chng_idx, idx]
        
        expect, pubkey, script, _ = make_ms_address(M, keys, idx=idx, addr_fmt=addr_fmt,
                                                    path_mapper=path_mapper, bip67=bip67)

        assert int(subpath.split('/')[-1]) == idx
        #print('../0/%s => \n %s' % (idx, B2A(script)))

        start, end = detruncate_address(addr)
        assert expect.startswith(start)
        assert expect.endswith(end)


def test_dup_ms_wallet_bug(goto_home, pick_menu_item, press_select, import_ms_wallet,
                           clear_ms, is_q1):
    M = 2
    N = 3

    deriv = ["m/48h/1h/0h/69h/1"]*N
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
    press_select()

    # BUG: pre v4.0.3, would be showing a "Yikes" referencing multisig:419 at this point

    pick_menu_item('2/3: name-0')
    pick_menu_item('Delete')
    press_select()

    clear_ms()

@pytest.mark.parametrize('M_N', [(2, 3), (2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [ AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH ])
@pytest.mark.parametrize('int_ext_desc', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_import_desciptor(M_N, addr_fmt, int_ext_desc, way, import_ms_wallet, goto_home, pick_menu_item,
                          press_select, clear_ms, cap_story, microsd_path, virtdisk_path,
                          nfc_read_text, load_export, is_q1, desc):
    clear_ms()
    M, N = M_N
    import_ms_wallet(M, N, addr_fmt=addr_fmt, accept=1, descriptor=True,
                     int_ext_desc=int_ext_desc, bip67=False if desc == "multi" else True)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    press_select()  # only one enrolled multisig - choose it
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
    assert f"{desc}(" in desc_export


@pytest.mark.bitcoind
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize("start_idx", [2147483540, MAX_BIP32_IDX, 0])
@pytest.mark.parametrize('M_N', [(2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_bitcoind_ms_address(change, M_N, addr_fmt, clear_ms, goto_home, need_keypress,
                             pick_menu_item, cap_menu, cap_story, make_multisig, import_ms_wallet,
                             microsd_path, bitcoind_d_wallet_w_sk, use_regtest, load_export, way,
                             is_q1, press_select, start_idx, settings_set, set_addr_exp_start_idx,
                             desc):
    use_regtest()
    clear_ms()
    bitcoind = bitcoind_d_wallet_w_sk
    M, N = M_N
    # whether to import as descriptor or old school to CC
    descriptor = random.choice([True, False])
    bip67 = True
    if desc == "multi":
        bip67 = False
        descriptor = True

    settings_set("aei", True if start_idx else False)

    wal_name = f"ax{M}-{N}-{addr_fmt}"

    dd = {
        AF_P2WSH: ("m/48h/1h/0h/2h/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45h/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48h/1h/0h/1h/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]

    keys = make_multisig(M, N, unique=1, deriv=deriv)

    derivs = [deriv.format(idx=i) for i in range(N)]

    clear_ms()
    import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=derivs,
                     addr_fmt=text_a_fmt, descriptor=descriptor, bip67=bip67)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')  # warning
    set_addr_exp_start_idx(start_idx)

    m = cap_menu()
    if descriptor:
        wal_name = m[-2 if start_idx else -1]
    else:
        assert wal_name in m
    pick_menu_item(wal_name)

    time.sleep(0.2)
    title, story = cap_story()
    assert "(0)" in story
    assert "change addresses." in story
    if change:
        need_keypress("0")
        time.sleep(0.2)
        title, story = cap_story()
        # once change is selected - do not offer this option again
        assert "change addresses." not in story
        assert "(0)" not in story

    contents = load_export(way, label="Address summary", is_json=False, sig_check=False)
    addr_cont = contents.strip()
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    press_select()  # only one enrolled multisig - choose it
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
        assert f"({desc}(" in desc_export

    if way == "nfc":
        end_idx = start_idx + 9
        if end_idx > MAX_BIP32_IDX:
            end_idx = start_idx + (MAX_BIP32_IDX - start_idx)

        addr_range = [start_idx, end_idx]
        cc_addrs = addr_cont.split("\n")
        part_addr_index = 0
    else:
        end_idx = start_idx + 249
        if end_idx > MAX_BIP32_IDX:
            end_idx = start_idx + (MAX_BIP32_IDX - start_idx)

        addr_range = [start_idx, end_idx]
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


@pytest.mark.bitcoind
def test_legacy_multisig_witness_utxo_in_psbt(bitcoind, use_regtest, clear_ms, microsd_wipe, goto_home, need_keypress,
                                              pick_menu_item, cap_story, load_export, microsd_path, cap_menu, try_sign,
                                              is_q1, press_select):

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
    press_select()
    need_keypress("0")  # account
    press_select()
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
    pick_menu_item(name)
    _, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert name.split(".")[0] in story
    assert f"{M} of {N}" in story
    assert f"All {N} co-signers must approve spends" in story
    assert "P2SH" in story
    assert "Derivation:\n  Varies (2)" in story
    press_select()  # approve multisig import
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
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mining
    dest_addr = ms.getnewaddress("", addr_type)
    assert all([addr.startswith("2") for addr in [multi_addr, dest_addr]])
    # create funded PSBT
    psbt_resp = ms.walletcreatefundedpsbt(
        [], [{dest_addr: 5}], 0, {"fee_rate": 1, "change_type": addr_type, "subtractFeeFromOutputs": [0]}
    )
    psbt = psbt_resp.get("psbt")
    import base64
    o = BasicPSBT().parse(base64.b64decode(psbt))
    assert len(o.inputs) == 1
    non_witness_utxo = o.inputs[0].utxo
    from io import BytesIO
    parsed_tx = CTransaction()
    parsed_tx.deserialize(BytesIO(non_witness_utxo))
    witness_utxo = None
    for oo in parsed_tx.vout:
        if oo.nValue == 4900000000:
            witness_utxo = oo.serialize()

    assert witness_utxo is not None
    o.inputs[0].witness_utxo = witness_utxo
    updated = o.as_bytes()
    try_sign(updated)


@pytest.mark.bitcoind
@pytest.mark.parametrize("m_n", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("desc_type", ["p2wsh_desc", "p2sh_p2wsh_desc", "p2sh_desc"])
@pytest.mark.parametrize("sighash", list(SIGHASH_MAP.keys()))
@pytest.mark.parametrize("psbt_v2", [True, False])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_bitcoind_MofN_tutorial(m_n, desc_type, clear_ms, goto_home, need_keypress, pick_menu_item,
                                sighash, cap_menu, cap_story, microsd_path, use_regtest, bitcoind,
                                microsd_wipe, load_export, settings_set, psbt_v2, is_q1,
                                finalize_v2_v0_convert, press_select, desc):
    # 2of2 case here is described in docs with tutorial
    if desc == "multi":
        settings_set("unsort_ms", 1)

    M, N = m_n
    settings_set("sighshchk", 1)  # disable checks
    use_regtest()
    clear_ms()
    microsd_wipe()
    # remova all wallet from datadir
    bitcoind.delete_wallet_files(pattern="bitcoind--signer")
    bitcoind.delete_wallet_files(pattern="watch_only_")
    # create multiple bitcoin wallets (N-1) as one signer is CC
    bitcoind_signers = [
        bitcoind.create_wallet(wallet_name=f"bitcoind--signer{i}", disable_private_keys=False, blank=False,
                               passphrase=None, avoid_reuse=False, descriptors=True)
        for i in range(N-1)
    ]
    for signer in bitcoind_signers:
        signer.keypoolrefill(100)
    # watch only wallet where multisig descriptor will be imported
    bitcoind_watch_only = bitcoind.create_wallet(
        wallet_name=f"watch_only_{desc_type}_{M}of{N}", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('Export XPUB')
    time.sleep(0.5)
    title, story = cap_story()
    assert "extended public keys (XPUB) you would need to join a multisig wallet" in story
    press_select()
    need_keypress("0")  # account
    press_select()
    xpub_obj = load_export("sd", label="Multisig XPUB", is_json=True, sig_check=False)
    template = xpub_obj[desc_type]
    if desc == "multi":
        # if we export descriptor template - it is always correct a.k.a sortedmulti
        template = template.replace("sortedmulti(", "multi(")
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
    desc_info = bitcoind_watch_only.getdescriptorinfo(desc)
    desc_w_checksum = desc_info["descriptor"]  # with checksum
    if desc_type == 'p2wsh_desc':
        name = f"core{M}of{N}_native.txt"
    elif desc_type == "p2sh_p2wsh_desc":
        name = f"core{M}of{N}_wrapped.txt"
    else:
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

    pick_menu_item(name)
    _, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert name.split(".")[0] in story
    assert f"{M} of {N}" in story
    if M == N:
        assert f"All {N} co-signers must approve spends" in story
    else:
        assert f"{M} signatures, from {N} possible" in story
    if desc_type == "p2wsh_desc":
        assert "P2WSH" in story
    elif desc_type == "p2sh_desc":
        assert "P2SH" in story
    else:
        assert "P2SH-P2WSH" in story
    assert "Derivation:\n  Varies (2)" in story
    press_select()  # approve multisig import
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
    res = bitcoind_watch_only.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"], obj
    if desc_type == "p2wsh_desc":
        addr_type = "bech32"
    elif desc_type == "p2sh_desc":
        addr_type = "legacy"
    else:
        addr_type = "p2sh-segwit"
    multi_addr = bitcoind_watch_only.getnewaddress("", addr_type)
    dest_addr = bitcoind_watch_only.getnewaddress("", addr_type)
    if desc_type == "p2wsh_desc":
        assert all([addr.startswith("bcrt1q") for addr in [multi_addr, dest_addr]])
    else:
        assert all([addr.startswith("2") for addr in [multi_addr, dest_addr]])
    # mine some coins and fund above multisig address
    mined = bitcoind_watch_only.generatetoaddress(101, multi_addr)
    assert isinstance(mined, list) and len(mined) == 101
    # create funded PSBT
    all_of_it = bitcoind_watch_only.getbalance()
    psbt_resp = bitcoind_watch_only.walletcreatefundedpsbt(
        [], [{dest_addr: all_of_it}], 0, {"fee_rate": 20, "change_type": addr_type,
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

    if psbt_v2:
        # below is noop is psbt is already v2
        po = BasicPSBT().parse(base64.b64decode(psbt))
        po.to_v2()
        psbt = po.as_b64_str()

    name = f"hsc_{M}of{N}_{desc_type}.psbt"
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, story = cap_story()
    if not "OK TO SEND?" in title:
        pick_menu_item(name)
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
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    assert "Updated PSBT is:" in story
    press_select()
    os.remove(microsd_path(name))

    fname = story.split("\n\n")[-1]
    with open(microsd_path(fname), "r") as f:
        final_psbt = f.read().strip()

    po = BasicPSBT().parse(base64.b64decode(final_psbt))
    res = finalize_v2_v0_convert(po)

    assert res["complete"]
    tx_hex = res["hex"]
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    #  try to sign change - do a consolidation transaction which spends all inputs
    addr_a = bitcoind_watch_only.getnewaddress("", addr_type)
    consolidate = bitcoind_watch_only.getnewaddress("", addr_type)
    bitcoind_watch_only.generatetoaddress(1, addr_a)  # need to mine above tx
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
    name = f"change_{M}of{N}_{desc_type}.psbt"
    with open(microsd_path(name), "w") as f:
        f.write(psbt)
    goto_home()
    pick_menu_item("Ready To Sign")
    time.sleep(0.5)
    title, _ = cap_story()
    if not "OK TO SEND?" in title:
        pick_menu_item(name)
        title, story = cap_story()

    assert title == "OK TO SEND?"
    press_select()  # confirm signing
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
    press_select()
    fname = story.split("\n\n")[-1]
    with open(microsd_path(fname), "r") as f:
        cc_signed_psbt = f.read().strip()

    po = BasicPSBT().parse(base64.b64decode(cc_signed_psbt))
    cc_signed_psbt = finalize_v2_v0_convert(po)["psbt"]

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
    assert len(bitcoind_watch_only.listunspent()) == 2  # (merged all inputs to one + one newly spendable from mining)


@pytest.mark.parametrize("desc", [
    # ("Missing descriptor checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))"),
    ("Wrong checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#gs2fqgl7"),
    ("Invalid subderivation path - only 0/* or <0;1>/* allowed", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/1/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#sj7lxn0l"),
    ("Invalid subderivation path - only 0/* or <0;1>/* allowed", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#fy9mm8dt"),
    ("Key origin info is required", "wsh(sortedmulti(2,tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#ypuy22nw"),
    ("Malformed key derivation info", "wsh(sortedmulti(2,[0f056943]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#nhjvt4wd"),
    ("Invalid subderivation path - only 0/* or <0;1>/* allowed", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#gs2fqgl6"),
    ("Invalid subderivation path - only 0/* or <0;1>/* allowed", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0))#s487stua"),
    ("Cannot use hardened sub derivation path", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0'/*))#3w6hpha3"),
    # ("Unsupported descriptor", "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu"),
    ("Unsupported descriptor", "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)#ml40v0wf"),
    ("M must be <= N", "wsh(sortedmulti(3,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#uueddtsy"),
])
def test_exotic_descriptors(desc, clear_ms, goto_home, need_keypress, pick_menu_item, cap_menu,
                            cap_story, make_multisig, microsd_path, use_regtest, is_q1,
                            press_select):
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
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import multisig wallet file from SD Card" in story:
        need_keypress("1")
        time.sleep(0.1)

    pick_menu_item(name)
    _, story = cap_story()
    assert "Failed to import" in story
    assert msg in story
    press_select()

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
    clear_ms()
    M, N = m_n
    all_out_styles = list(unmap_addr_fmt.keys())
    index = all_out_styles.index("p2sh-p2wsh")
    all_out_styles[index] = "p2wsh-p2sh"
    name = f'ms1'
    keys = make_multisig(M, N)
    all_options = list(itertools.combinations(keys, len(keys)))
    for opt in all_options:
        import_ms_wallet(M, N, keys=opt, name=name, accept=1, do_import=True,
                         addr_fmt="p2wsh", descriptor=descriptor)
        psbt = fake_ms_txn(5, 5, M, opt, outstyles=all_out_styles,
                           segwit_in=True, incl_xpubs=True)
        open('debug/last.psbt', 'wb').write(psbt)
        try_sign_microsd(psbt, encoding='base64')
        for opt_1 in all_options:
            # create PSBT with original keys order
            psbt = fake_ms_txn(5, 5, M, opt_1, outstyles=all_out_styles,
                               segwit_in=True, incl_xpubs=True)
            open('debug/last.psbt', 'wb').write(psbt)
            try_sign_microsd(psbt, encoding='base64')


@pytest.mark.parametrize('cmn_pth_from_root', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('M_N', [(3, 15), (2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
def test_multisig_descriptor_export(M_N, way, addr_fmt, cmn_pth_from_root, clear_ms, make_multisig,
                                    import_ms_wallet, goto_home, pick_menu_item, cap_menu,
                                    nfc_read_text, microsd_path, cap_story, need_keypress,
                                    load_export, desc):

    def choose_multisig_wallet():
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        menu = cap_menu()
        pick_menu_item(menu[0])

    M, N = M_N
    wal_name = f"reexport_{M}-{N}-{addr_fmt}"

    dd = {
        AF_P2WSH: ("m/48h/1h/0h/2h/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45h/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48h/1h/0h/1h/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]
    keys = make_multisig(M, N, unique=1, deriv=None if cmn_pth_from_root else deriv)
    derivs = [deriv.format(idx=i) for i in range(N)]
    clear_ms()
    import_ms_wallet(M, N, accept=1, keys=keys, name=wal_name, derivs=None if cmn_pth_from_root else derivs,
                     addr_fmt=text_a_fmt, descriptor=True, common="m/45h" if cmn_pth_from_root else None,
                     bip67=False if desc == "multi" else True)
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
    for _ in range(5):
        _, story = cap_story()
        if "Press (1) to export" in story:
            need_keypress("1")
            break
        else:
            time.sleep(1)

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
    for _ in range(5):
        try:
            _, story = cap_story()
            if "Press (1)" in story:
                break
        except:
            time.sleep(1)

    view_desc = story.strip().split("\n\n")[1]

    # assert that bare and pretty are the same after parse
    assert f"({desc}(" in bare_desc

    assert bare_desc == view_desc
    assert parse_desc_str(pretty_desc) == bare_desc
    for obj in core_desc_object:
        if obj["internal"]:
            pass
        else:
            assert obj["desc"] == bare_desc
    clear_ms()


def test_multisig_name_validation(microsd_path, offer_ms_import):
    with open("data/multisig/export-p2wsh-myself.txt", "r") as f:
        config = f.read()

    c0 = config.replace("Name: CC-2-of-4", "Name: eê")

    with pytest.raises(Exception) as e:
        offer_ms_import(c0, allow_non_ascii=True)
    assert "must be ascii" in e.value.args[0]

    c0 = config.replace("Name: CC-2-of-4", "Name: eee\teee")

    with pytest.raises(Exception) as e:
        offer_ms_import(c0, allow_non_ascii=True)
    assert "must be ascii" in e.value.args[0]


def test_multisig_deriv_path_migration(settings_set, clear_ms, import_ms_wallet,
                                       press_cancel, settings_get, make_multisig,
                                       goto_home, start_sign, cap_story, end_sign,
                                       pick_menu_item, cap_menu):
    # this test case simulates multisig wallets imported to CC before 5.3.0
    # release; these wallets, saved in user settings, still have "'" in derivation
    # paths; 5.3.1 firmware implements migration to "h" in MultisigWallet.deserialize

    clear_ms()

    deriv, text_a_fmt = ("m/48h/1h/0h/2h/{idx}", 'p2wsh')
    keys = make_multisig(2, 3, unique=1, deriv=deriv)
    derivs = [deriv.format(idx=i) for i in range(3)]
    import_ms_wallet(2, 3, accept=True, keys=keys, name="ms1",
                     derivs=derivs, addr_fmt=text_a_fmt)
    time.sleep(.1)

    import_ms_wallet(3, 5, name="ms2", addr_fmt='p2wsh-p2sh', accept=True)
    time.sleep(.1)

    ms = settings_get("multisig")
    pths0 = ms[0][3]["d"]
    new_pths0 = [p.replace("h", "'") for p in pths0]
    ms[0][3]["d"] = new_pths0

    ms[1][3]["pp"] = ms[1][3]["pp"].replace("h", "'")

    # this matches data/PSBT
    ms.append(
        (
            'ms',
            (2, 2),
            [(2285969762, 0, 'tpubDEy2hd2VTrqbBS8cS2svq12UmjGM2j7FHmocjHzAXfVhmJdhBFVVbmAi13humi49esaAuSmz36NEJ6GL3u58RzNuUkExP9vL4d81PM3s8u6'),
             (1130956047, 1, 'tpubDEFX3QojMWh7x4vSAHN17wpsywpP78aSs2t6nyELHuq1k34gub9mQ7QiaHNCBAYjSQ4UCMMpfBkf5np1cTQaStrvvRCxwxZ7kZaGHqYxUv3')],
            {'ch': 'XTN', 'ft': 14, 'd': ["m/48'/0'/99'/2'", "m/48'/0'/33'/2'"]}
        )
    )
    settings_set("multisig", ms)

    # psbt from nunchuk, with global xpubs belonging to above ms wallet
    b64_psbt = "cHNidP8BAF4CAAAAAfkDjXlS32gzOjVhSRArKxvkAecMTnp1g8wwMJTtq74/AAAAAAD9////AekaAAAAAAAAIgAgzs2e4h4vctbFvvauK+QVFAPzCFnMi1H9hTacH7498P8AAAAATwEENYfPBC7g3O2AAAACLvzTgnL7V0DNOnISJdvOgq/6Pw6DAtkPflmZ+Hc04qwC5CShG0rDIlh8gu7gH2NMBLfrIzYSzoSomnVHeMxtxVQUDwVpQzAAAIAAAACAIQAAgAIAAIBPAQQ1h88EkEB8moAAAALv/1L+Cfeg2EPc01pS00f18DIdU5BOeExlGsXyEFOKGwL71tcAiRuL4Bs+uT1JJjU6AbR3j3X60/rI+rTMJmnOgRRiIUGIMAAAgAAAAIBjAACAAgAAgAABAIkCAAAAAZ5Im3CxbYDyByyrr4luss5vr+s0r7Vt8pK+OvicPLO7AAAAAAD9////AnM2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnTmvqUXAAAAACJRIJF/VcIeZ3E4f+ZEjwiUl5AUUxBJgoaEaPaHHJecq18lq+4qAAEBK3M2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnQiAgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3kcwRAIgHNmbk4J9wu4ljq6UouY132eX1i/2jWvJjuuWWyLRFScCIBPyPCuZ/Hmd06h9KtVkSropBonIuqIc/BK8JZ50YKp/AQEDBAEAAAABBUdSIQMBr34TVHrqSk8K6505//5YTOkHmHqF83J8iUURtL/ptCEDUXZhsRMLD/PMbva5f7RgF6u5D5v+99Mk8kOlx0C/w95SriIGAwGvfhNUeupKTwrrnTn//lhM6QeYeoXzcnyJRRG0v+m0HA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAAAAAAiBgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3hxiIUGIMAAAgAAAAIBjAACAAgAAgAAAAAAAAAAAAAEBR1IhAscIZVvBcy3Q0GKO4UqR3gDB3pm/tWas8siH3Ej8MmuCIQN8lTj0MMTpT+Dlk2MbMdAaL93hezzNP3WDsRn/gwlVQlKuIgICxwhlW8FzLdDQYo7hSpHeAMHemb+1ZqzyyIfcSPwya4IcYiFBiDAAAIAAAACAYwAAgAIAAIAAAAAAAQAAACICA3yVOPQwxOlP4OWTYxsx0Bov3eF7PM0/dYOxGf+DCVVCHA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAEAAAAA"

    goto_home()
    # in time of creatin of PSBT, lopp was making testnet3 unusable...
    settings_set("fee_limit", -1)
    start_sign(base64.b64decode(b64_psbt))
    title, story = cap_story()
    assert title == "OK TO SEND?"
    end_sign()
    settings_set("fee_limit", 10)  # rollback
    pick_menu_item("Settings")
    pick_menu_item("Multisig Wallets")
    m = cap_menu()
    for msi in m[:3]:  # three wallets imported
        pick_menu_item(msi)
        pick_menu_item("View Details")
        time.sleep(.1)
        _, story = cap_story()
        assert "'" not in story
        press_cancel()
        press_cancel()


@pytest.mark.parametrize("fpath", [
    # CC export format
    "data/multisig/export-p2sh-myself.txt",
    "data/multisig/export-p2sh-p2wsh-myself.txt",
    "data/multisig/export-p2wsh-myself.txt",
    # descriptors
    "data/multisig/desc-p2sh-myself.txt",
    "data/multisig/desc-p2sh-p2wsh-myself.txt",
    "data/multisig/desc-p2wsh-myself.txt",
])
def test_scan_any_qr(fpath, is_q1, scan_a_qr, clear_ms, goto_home,
                     pick_menu_item, cap_story, press_cancel):
    if not is_q1:
        pytest.skip("No QR support for Mk4")

    clear_ms()
    goto_home()
    pick_menu_item("Scan Any QR Code")

    with open(fpath, "r") as f:
        config = f.read()

    actual_vers, parts = split_qrs(config, 'U', max_version=20)
    random.shuffle(parts)

    for p in parts:
        scan_a_qr(p)
        time.sleep(2.0 / len(parts))

    time.sleep(.1)
    title, story = cap_story()
    assert "Create new multisig wallet?" in story
    press_cancel()


@pytest.mark.parametrize("N", [3, 15])
def test_bare_cc_ms_qr_import(N, make_multisig, scan_a_qr, clear_ms, goto_home,
                              pick_menu_item, cap_story, press_cancel, is_q1):
    # bare:
    # - no fingerprints
    # - no xfps
    # - no meta data

    if not is_q1:
        raise pytest.skip("No QR support for Mk4")

    keys = make_multisig(N, N)
    config = '\n'.join(sk.hwif(as_private=False) for xfp,m,sk in keys)
    actual_vers, parts = split_qrs(config, 'U', max_version=20)
    random.shuffle(parts)

    # will not work in scan any qr in main menu (no xfp)
    clear_ms()
    goto_home()
    pick_menu_item("Scan Any QR Code")

    for p in parts:
        scan_a_qr(p)
        time.sleep(2.0 / len(parts))

    title, story = cap_story()
    assert title == 'Simple Text'
    assert "We can't do any more with it." in story

    press_cancel()

    # if someone uses this bare format with keys of depth 1
    # multisig import path needs to be used
    pick_menu_item("Settings")
    pick_menu_item("Multisig Wallets")
    pick_menu_item("Import from QR")
    for p in parts:
        scan_a_qr(p)
        time.sleep(2.0 / len(parts))

    title, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert f"{N}-of-{N}" in story
    press_cancel()


@pytest.mark.parametrize("psbtv2", [True, False])
@pytest.mark.parametrize("desc", ["multi", "sortedmulti"])
@pytest.mark.parametrize("data", [
    # (out_style, amount, is_change)
    [("p2wsh", 1000000, 0)] * 99,
    [("p2sh", 1000000, 1)] * 33,
    [("p2wsh-p2sh", 1000000, 1)] * 18 + [("p2wsh", 50000000, 0)] * 12,
    [("p2sh", 1000000, 1), ("p2wsh-p2sh", 50000000, 0), ("p2wsh", 800000, 1)] * 14,
])
def test_txout_explorer(psbtv2, data, clear_ms, import_ms_wallet, fake_ms_txn,
                        start_sign, txout_explorer, desc):
    clear_ms()
    M, N = 2, 3
    descriptor, bip67 = False, True
    if desc == "multi":
        descriptor, bip67 = True, False
    keys = import_ms_wallet(2, 3, name='ms-test', accept=True,
                            descriptor=descriptor, bip67=bip67)

    outstyles = []
    outvals = []
    change_outputs = []
    for i in range(len(data)):
        os, ov, is_change = data[i]
        outstyles.append(os)
        outvals.append(ov)
        if is_change:
            change_outputs.append(i)

    inp_amount = sum(outvals) + 100000  # 100k sat fee
    psbt = fake_ms_txn(1, len(data), M, keys, outstyles=outstyles,
                       outvals=outvals, change_outputs=change_outputs,
                       input_amount=inp_amount, psbt_v2=psbtv2, bip67=bip67)
    start_sign(psbt)
    txout_explorer(data)

def test_import_duplicate_shuffled_keys_legacy(clear_ms, make_multisig, import_ms_wallet,
                                               cap_story, press_cancel, OK):
    clear_ms()
    M, N = 2, 3
    wname = "ms02"
    keys = make_multisig(M, N)
    import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True, keys=keys,
                     descriptor=False)
    # shuffle
    keys[0], keys[1] = keys[1], keys[0]

    with pytest.raises(AssertionError):
        import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True, keys=keys,
                         descriptor=False)

    time.sleep(.1)
    title, story = cap_story()
    assert 'Duplicate wallet' in story
    assert f'{OK} to approve' not in story
    press_cancel()

@pytest.mark.parametrize("order", list(itertools.product([True, False], repeat=2)))
def test_import_duplicate_shuffled_keys(clear_ms, make_multisig, import_ms_wallet,
                                        cap_story, press_cancel, order, OK):
    # DO NOT allow to import both wsh(sortedmulti(2,A,B,C)) and wsh(sortedmulti(2,B,C,A))
    # DO NOT allow to import both wsh(multi(2,A,B,C)) and wsh(multi(2,B,C,A))
    # DO NOT allow to import both wsh(sortedmulti(2,A,B,C)) and wsh(multi(2,B,C,A))
    # MUST BE treated as duplicates
    clear_ms()
    M, N = 2, 3
    A, B = order  # defines bip67
    wname = "ms02"
    keys = make_multisig(M, N)
    import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True, keys=keys,
                     descriptor=True, bip67=A)
    # shuffle
    keys[0], keys[1] = keys[1], keys[0]

    with pytest.raises(AssertionError):
        import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True, keys=keys,
                         descriptor=True, bip67=B)
    time.sleep(.1)
    title, story = cap_story()
    assert 'Duplicate wallet' in story
    assert f'{OK} to approve' not in story
    if A != B:
        assert "BIP-67 clash" in story

    press_cancel()


@pytest.mark.parametrize("int_ext", [True, False])
def test_multi_sortedmulti_duplicate(clear_ms, make_multisig, import_ms_wallet, OK,
                                     cap_story, press_cancel, int_ext, offer_ms_import):
    clear_ms()
    M, N = 3, 5
    wname = "ms001"
    fstr = "m/48h/1h/0h/2h/{idx}"
    derivs = [fstr.format(idx=i) for i in range(N)]
    keys = make_multisig(M, N, deriv=fstr)
    import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True,
                     keys=keys, int_ext_desc=True, derivs=derivs)

    # create identical but unsorted descriptor
    obj_keys = [(keys[i][0], derivs[i], keys[i][2].hwif())
                for i in range(len(keys))]
    d = MultisigDescriptor(M, N, obj_keys, addr_fmt=AF_P2WSH, is_sorted=False)
    ser_desc = d.serialize(int_ext=int_ext)

    title, story = offer_ms_import(ser_desc)
    assert 'Duplicate wallet' in story
    assert f'{OK} to approve' not in story
    assert "BIP-67 clash" in story
    press_cancel()


def test_unsort_multisig_setting(settings_set, import_ms_wallet, goto_home,
                                 pick_menu_item, cap_story, need_keypress,
                                 settings_get, clear_ms, press_select, is_q1):
    clear_ms()
    mi = "Unsorted Multisig" if is_q1 else "Unsorted Multi"
    settings_set("unsort_ms", 0)  # OFF by default
    with pytest.raises(Exception) as e:
        import_ms_wallet(2, 3, "p2wsh", descriptor=True, bip67=False,
                         accept=True, force_unsort_ms=False)
    assert '"multi(...)" not allowed' in e.value.args[0]

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig Wallets")
    pick_menu_item(mi)
    time.sleep(.1)
    title, story = cap_story()
    assert '"multi(...)" unsorted multisig wallets that do not follow BIP-67.' in story
    assert 'preserve order of the keys' in story
    assert 'USE AT YOUR OWN RISK' in story
    assert 'Press (4)' in story
    need_keypress("4")
    time.sleep(.1)
    pick_menu_item("Allow")
    time.sleep(.3)
    assert settings_get("unsort_ms") == 1
    import_ms_wallet(2, 3, "p2wsh", descriptor=True, bip67=False,
                     accept=True, force_unsort_ms=False)
    assert len(settings_get("multisig")) == 1
    pick_menu_item("Settings")
    pick_menu_item("Multisig Wallets")
    pick_menu_item(mi)
    time.sleep(.1)
    title, story = cap_story()
    assert "Remove already saved multi(...) wallets first" in story
    assert "2-of-3" in story  # wallet that needs to be removed
    press_select()
    assert len(settings_get("multisig")) == 1
    clear_ms()
    pick_menu_item(mi)
    pick_menu_item("Do Not Allow")
    time.sleep(.3)
    with pytest.raises(Exception) as e:
        import_ms_wallet(2, 3, "p2wsh", descriptor=True, bip67=False,
                         accept=True, force_unsort_ms=False)
    assert '"multi(...)" not allowed' in e.value.args[0]


@pytest.mark.bitcoind
@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("way", ["usb", "nfc", "sd", "vdisk", "qr"])
def test_import_multisig_usb_json(use_regtest, cs, way, cap_menu, clear_ms,
                                  pick_menu_item, goto_home, need_keypress,
                                  offer_ms_import, bitcoind, microsd_path,
                                  virtdisk_path, import_multisig):
    name = "my_ms_wal"
    use_regtest()
    clear_ms()

    with open("data/multisig/desc-p2wsh-myself.txt", "r") as f:
        desc = f.read().strip()

    if not cs:
        desc, cs = desc.split("#")

    val = json.dumps({"name": name, "desc": desc})

    data = None
    fname = None
    if way == "usb":
        title, story = offer_ms_import(val)
    else:
        if way in ["nfc", "qr"]:
            data = val
        else:
            fname = "diff_name.txt"  # will be ignored as name in the json has preference
            if way == "sd":
                fpath = microsd_path(fname)
            else:
                fpath = virtdisk_path(fname)

            with open(fpath, "w") as f:
                f.write(val)

        title, story = import_multisig(fname=fname, way=way, data=data)

    assert "Create new multisig wallet?" in story
    assert name in story
    need_keypress("y")
    time.sleep(.2)
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig Wallets")
    m = cap_menu()
    assert name in m[0]


@pytest.mark.parametrize("err,config", [
    # all dummy data there to satisfy badlen check in usb.py
    (
        "'desc' key required",
        {"name": "my_miniscript", "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    ),
    (
        "'name' length",
        {"name": "a" * 41, "desc": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    ),
    (
        "'name' length",
        {"name": "a", "desc": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    ),
    (
        "'desc' empty",
        {"name": "ab", "desc": "", "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    ),
    (
        "'desc' empty",
        {"name": "ab", "desc": None, "random": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
    ),
])
def test_json_import_failures(err, config, offer_ms_import):
    with pytest.raises(Exception) as e:
        offer_ms_import(json.dumps(config))
    assert err in e.value.args[0]

# EOF
