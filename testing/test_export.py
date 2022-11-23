# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Exporting of wallet files and similar things.
#
# Start simulator with:   simulator.py --eff --set nfc=1
#
import pytest, time, os, json, io
from pycoin.key.BIP32Node import BIP32Node
from ckcc_protocol.constants import *
from helpers import xfp2str, slip132undo
from conftest import simulator_fixed_xfp, simulator_fixed_xprv
from ckcc_protocol.constants import AF_CLASSIC, AF_P2WPKH
from pprint import pprint

@pytest.mark.bitcoind
@pytest.mark.parametrize('acct_num', [None, '0', '99', '123'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_core(way, dev, use_regtest, acct_num, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path,
                     virtdisk_path, bitcoind_wallet, bitcoind_d_wallet, enter_number, nfc_read_text):
    # test UX and operation of the 'bitcoin core' wallet export
    from pycoin.contrib.segwit_addr import encode as sw_encode
    use_regtest()
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Bitcoin Core')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves' in story
    assert 'including the public keys' in story

    assert 'Press (1) to' in story
    if acct_num is not None:
        need_keypress('1')
        time.sleep(0.1)
        enter_number(acct_num)
    else:
        acct_num = '0'
        need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Bitcoin Core file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            core_export = nfc_read_text()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way == "nfc":
        fp = io.StringIO(core_export).readlines()
    else:
        time.sleep(0.2)
        _, story = cap_story()
        assert 'Bitcoin Core file written' in story
        fname = story.split('\n')[-1]
        need_keypress('y')
        if way == "vdisk":
            path = virtdisk_path(fname)
        else:
            path = microsd_path(fname)
        with open(path, 'rt') as f:
            fp = f.readlines()

    addrs = []
    imm_js = None
    imd_js = None
    for ln in fp:
        if 'importmulti' in ln:
            # PLAN: this will become obsolete
            assert ln.startswith("importmulti '")
            assert ln.endswith("'\n")
            assert not imm_js, "dup importmulti lines"
            imm_js = ln[13:-2]
        elif "importdescriptors '" in ln:
            assert ln.startswith("importdescriptors '")
            assert ln.endswith("'\n")
            assert not imd_js, "dup importdesc lines"
            imd_js = ln[19:-2]
        elif '=>' in ln:
            path, addr = ln.strip().split(' => ', 1)
            assert path.startswith(f"m/84'/1'/{acct_num}'/0")
            assert addr.startswith('bcrt1q') # TODO here we should differentiate if testnet or smthg
            sk = BIP32Node.from_wallet_key(simulator_fixed_xprv).subkey_for_path(path[2:])
            h20 = sk.hash160()
            assert addr == sw_encode(addr[0:4], 0, h20) # TODO here we should differentiate if testnet or smthg
            addrs.append(addr)

    assert len(addrs) == 3

    xfp = xfp2str(simulator_fixed_xfp).lower()

    if imm_js:
        obj = json.loads(imm_js)
        for n, here in enumerate(obj):
            assert here['range'] == [0, 1000]
            assert here['timestamp'] == 'now'
            assert here['internal'] == bool(n)
            assert here['keypool'] == True
            assert here['watchonly'] == True

            d = here['desc']
            desc, chk = d.split('#', 1)
            assert len(chk) == 8
            assert desc.startswith(f'wpkh([{xfp}/84h/1h/{acct_num}h]')

            expect = BIP32Node.from_wallet_key(simulator_fixed_xprv)\
                        .subkey_for_path(f"84'/1'/{acct_num}'.pub").hwif()

            assert expect in desc
            assert expect+f'/{n}/*' in desc

        # test against bitcoind
        for x in obj:
            x['label'] = 'testcase'
        bitcoind_wallet.importmulti(obj)
        x = bitcoind_wallet.getaddressinfo(addrs[-1])
        pprint(x)
        assert x['address'] == addrs[-1]
        if 'label' in x:
            # pre 0.21.?
            assert x['label'] == 'testcase'
        else:
            assert x['labels'] == ['testcase']
        assert x['iswatchonly'] == True
        assert x['iswitness'] == True
        assert x['hdkeypath'] == f"m/84'/1'/{acct_num}'/0/%d" % (len(addrs)-1)

    # importdescriptors -- its better
    assert imd_js
    obj = json.loads(imd_js)
    for n, here in enumerate(obj):
        assert range not in here
        assert here['timestamp'] == 'now'
        assert here['internal'] == bool(n)

        d = here['desc']
        desc, chk = d.split('#', 1)
        assert len(chk) == 8
        assert desc.startswith(f'wpkh([{xfp}/84h/1h/{acct_num}h]')

        expect = BIP32Node.from_wallet_key(simulator_fixed_xprv)\
                    .subkey_for_path(f"84'/1'/{acct_num}'.pub").hwif()

        assert expect in desc
        assert expect+f'/{n}/*' in desc

        if n == 0:
            assert here['label'] == 'Coldcard ' + xfp

        # test against bitcoind -- needs a "descriptor native" wallet
        bitcoind_d_wallet.importdescriptors(obj)

        x = bitcoind_d_wallet.getaddressinfo(addrs[-1])
        pprint(x)
        assert x['address'] == addrs[-1]
        assert x['iswatchonly'] == False
        assert x['iswitness'] == True
        # assert x['ismine'] == True   # TODO we have imported pubkeys - it has no idea if it is ours or solvable
        # assert x['solvable'] == True
        # assert x['hdmasterfingerprint'] == xfp2str(dev.master_fingerprint).lower()
        #assert x['hdkeypath'] == f"m/84'/1'/{acct_num}'/0/%d" % (len(addrs)-1)

@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_wasabi(way, dev, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path, nfc_read_json,
                       virtdisk_path):
    # test UX and operation of the 'wasabi wallet export'

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Wasabi Wallet')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves a skeleton Wasabi' in story

    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Wasabi wallet file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            wasabi_export = nfc_read_json()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")
        
    if way == "nfc":
        obj = wasabi_export
    else:
        time.sleep(0.1)
        title, story = cap_story()

        assert 'wallet file written' in story
        fname = story.split('\n')[-1]

        need_keypress('y')
        if way == "sd":
            path = microsd_path(fname)
        else:
            path = virtdisk_path(fname)
        with open(path, 'rt') as fp:
            obj = json.load(fp)
        os.unlink(path)

    assert 'MasterFingerprint' in obj
    assert 'ExtPubKey' in obj
    assert 'ColdCardFirmwareVersion' in obj
    
    xpub = obj['ExtPubKey']
    assert xpub.startswith('xpub')      # even for testnet

    assert obj['MasterFingerprint'] == xfp2str(simulator_fixed_xfp)

    got = BIP32Node.from_wallet_key(xpub)
    expect = BIP32Node.from_wallet_key(simulator_fixed_xprv).subkey_for_path("84'/0'/0'.pub")

    assert got.sec() == expect.sec()

        
@pytest.mark.parametrize('mode', [ "Legacy (P2PKH)", "P2SH-Segwit", "Native Segwit"])
@pytest.mark.parametrize('acct_num', [ None, '0', '9897'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_electrum(way, dev, mode, acct_num, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path,
                         nfc_read_json, virtdisk_path):
    # lightly test electrum wallet export

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Electrum Wallet')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves a skeleton Electrum wallet' in story

    assert 'Press (1) to' in story
    if acct_num is not None:
        need_keypress('1')
        time.sleep(0.1)
        for n in acct_num:
            need_keypress(n)

    need_keypress('y')

    time.sleep(0.1)
    pick_menu_item(mode)

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Electrum wallet file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            electrum_export = nfc_read_json()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way == "nfc":
        obj = electrum_export
    else:
        time.sleep(0.1)
        title, story = cap_story()

        assert 'wallet file written' in story
        fname = story.split('\n')[-1]

        need_keypress('y')
        if way == "sd":
            path = microsd_path(fname)
        else:
            path = virtdisk_path(fname)
        with open(path, 'rt') as fp:
            obj = json.load(fp)
        os.unlink(path)

    ks = obj['keystore']
    assert ks['ckcc_xfp'] == simulator_fixed_xfp

    assert ks['hw_type'] == 'coldcard'
    assert ks['type'] == 'hardware'

    deriv = ks['derivation']
    assert deriv.startswith('m/')
    assert int(deriv.split("/")[1][:-1]) in {44, 84, 49}        # weak
    assert deriv.split("/")[3] == (acct_num or '0')+"'"

    xpub = ks['xpub']
    assert xpub[1:4] == 'pub'

    if xpub[0] in 'tx': 
        # no slip132 here

        got = BIP32Node.from_wallet_key(xpub)
        expect = BIP32Node.from_wallet_key(simulator_fixed_xprv).subkey_for_path(deriv[2:])

        assert got.sec() == expect.sec()


@pytest.mark.parametrize('acct_num', [ None, '99', '123'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_coldcard(way, dev, acct_num, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path,
                         nfc_read_json, virtdisk_path, addr_vs_path):
    from pycoin.contrib.segwit_addr import encode as sw_encode

    # test UX and values produced.
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Generic JSON')

    time.sleep(0.1)
    title, story = cap_story()
    assert 'Saves JSON file' in story

    need_keypress('y')
    if acct_num:
        for n in acct_num:
            need_keypress(n)
    else:
        acct_num = '0'
    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Generic Export file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            generic_export = nfc_read_json()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way == "nfc":
        obj = generic_export
    else:
        time.sleep(0.1)
        title, story = cap_story()

        assert 'Generic Export file written' in story
        fname = story.split('\n')[-1]

        need_keypress('y')
        if way == "sd":
            path = microsd_path(fname)
        else:
            path = virtdisk_path(fname)
        with open(path, 'rt') as fp:
            obj = json.load(fp)
        os.unlink(path)

    for fn in ['xfp', 'xpub', 'chain']:
        assert fn in obj
        assert obj[fn]
    assert obj['account'] == int(acct_num or 0)

    for fn in ['bip44', 'bip49', 'bip84', 'bip48_1', 'bip48_2', 'bip45']:
        if obj['account'] and fn == 'bip45':
            assert fn not in obj
            continue

        assert fn in obj
        v = obj[fn]
        assert all([i in v for i in ['deriv', 'name', 'xpub', 'xfp']])

        if fn == 'bip45':
            assert v['deriv'] == "m/45'"
        elif 'bip48' not in fn:
            assert v['deriv'].endswith(f"'/{acct_num}'")
        else:
            b48n = fn[-1]
            assert v['deriv'].endswith(f"'/{acct_num}'/{b48n}'")

        node = BIP32Node.from_wallet_key(v['xpub'])
        assert v['xpub'] == node.hwif(as_private=False)
        first = node.subkey_for_path('0/0')
        addr = v.get('first', None)

        if fn == 'bip44':
            assert first.address() == v['first']
            addr_vs_path(addr, v['deriv'] + '/0/0', AF_CLASSIC)
        elif ('bip48_' in fn) or (fn == 'bip45'):
            # multisig: cant do addrs
            assert addr == None
        else:
            assert v['_pub'][1:4] == 'pub'
            assert slip132undo(v['_pub'])[0] == v['xpub']

            h20 = first.hash160()
            if fn == 'bip84':
                assert addr == sw_encode(addr[0:2], 0, h20)
                addr_vs_path(addr, v['deriv'] + '/0/0', AF_P2WPKH)
            elif fn == 'bip49':
                # don't have test logic for verifying these addrs
                # - need to make script, and bleh
                assert addr[0] in '23'
                #addr_vs_path(addr, v['deriv'] + '/0/0', AF_P2WSH_P2SH, script=)
            else:
                assert False

@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_unchained(way, dev, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path, nfc_read_json,
                          virtdisk_path):
    # test UX and operation of the 'unchained capital export'

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Unchained Capital')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Unchained Capital' in story

    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Unchained Capital file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            unchained_export = nfc_read_json()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way == "nfc":
        obj = unchained_export
    else:
        time.sleep(0.1)
        title, story = cap_story()

        assert 'Unchained Capital file' in story
        fname = story.split('\n')[-1]
        assert 'unchained' in fname

        need_keypress('y')
        if way == "sd":
            path = microsd_path(fname)
        else:
            path = virtdisk_path(fname)
        with open(path, 'rt') as fp:
            obj = json.load(fp)
        os.unlink(path)

    root = BIP32Node.from_wallet_key(simulator_fixed_xprv)
    assert obj['xfp'] == xfp2str(simulator_fixed_xfp)
    assert obj['account'] == 0

    assert obj['p2sh_deriv'] == "m/45'"
    for k in ['p2sh_p2wsh', 'p2sh', 'p2wsh']:
        xpub = slip132undo(obj[k])[0] if k != 'p2sh' else obj[k]
        node = BIP32Node.from_wallet_key(xpub)
        assert xpub == node.hwif(as_private=False)
        sk = root.subkey_for_path(obj[f'{k}_deriv'][2:] + '.pub')
        #assert node.chain_code() == sk.chain_code()
        assert node.hwif() == sk.hwif()


@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_export_public_txt(way, dev, pick_menu_item, goto_home, cap_story, need_keypress, microsd_path, addr_vs_path,
                           virtdisk_path, nfc_read_text):
    # test UX and values produced.
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Dump Summary')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Saves a text file' in story
    need_keypress('y')

    time.sleep(0.1)
    title, story = cap_story()
    if way == "sd":
        if "Press (1) to save Summary file to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if "press (3) to share file via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress("3")
            time.sleep(0.2)
            public = nfc_read_text()
            time.sleep(0.3)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way == "nfc":
        fp = io.StringIO(public).readlines()
    else:
        time.sleep(0.2)
        _, story = cap_story()
        assert 'Summary file' in story
        fname = story.split('\n')[-1]
        assert 'public' in fname
        need_keypress('y')
        if way == "vdisk":
            path = virtdisk_path(fname)
        else:
            path = microsd_path(fname)
        with open(path, 'rt') as f:
            fp = f.readlines()

    xfp = xfp2str(simulator_fixed_xfp).upper()

    root = BIP32Node.from_wallet_key(simulator_fixed_xprv)
    for ln in fp:
        if 'fingerprint' in ln:
            assert ln.strip().endswith(xfp)

        if '=>' not in ln:
            continue

        lhs, rhs = ln.strip().split(' => ')
        assert lhs.startswith('m/')
        rhs = rhs.split('#')[0].strip()

        if 'SLIP-132' in ln:
            rhs, _, f, _ = slip132undo(rhs)
        else:
            f = None

        if rhs[1:4] == 'pub':
            expect = root.subkey_for_path(lhs[2:])
            assert expect.hwif(as_private=False) == rhs
            continue

        if not f:
            if rhs[0] in 'mn':
                f = AF_CLASSIC
            elif rhs[0:3] == 'tb1':
                f = AF_P2WPKH
            elif rhs[0] == '2':
                f = AF_P2WPKH_P2SH
            else:
                raise ValueError(rhs)

        addr_vs_path(rhs, path=lhs, addr_fmt=f)


@pytest.mark.qrcode
@pytest.mark.parametrize('acct_num', [ None, 0, 99, 8989])
@pytest.mark.parametrize('use_nfc', [False, True])
def test_export_xpub(use_nfc, acct_num, dev, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress, enter_number,
                     cap_screen_qr, use_mainnet, nfc_read_text):
    # XPUB's via QR

    use_mainnet()

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Export Wallet')
    pick_menu_item('Export XPUB')

    top_items = cap_menu()
    for m in top_items:
        is_xfp = False
        if '-84' in m:
            expect = "m/84'/0'/{acct}'"
        elif '-44' in m:
            expect = "m/44'/0'/{acct}'"
        elif '49' in m:
            expect = "m/49'/0'/{acct}'"
        elif 'Master' in m:
            expect = "m"
        elif 'XFP' in m:
            is_xfp = True

        pick_menu_item(m)
        time.sleep(0.3)
        if is_xfp:
            got = cap_screen_qr().decode('ascii')
            if use_nfc:
                need_keypress('3')
            assert got == xfp2str(simulator_fixed_xfp).upper()
            need_keypress('x')
            continue

        time.sleep(0.3)
        title, story = cap_story()
        assert expect in story

        if 'acct' in expect:
            assert "Press (1) to select account" in story
            if acct_num is not None:
                need_keypress('1')
                enter_number(acct_num)

                time.sleep(0.1)
                expect = expect.format(acct=acct_num)
                title, story = cap_story()
                assert expect in story
                assert "Press (1) to select account" not in story

        expect = expect.format(acct=0)
        if not use_nfc:
            need_keypress('y')
            got_pub = cap_screen_qr().decode('ascii')
        else:
            assert 'Press (3)' in story
            assert 'NFC' in story
            need_keypress('3')
            time.sleep(0.2)
            got_pub = nfc_read_text()
            time.sleep(0.1)
            #need_keypress('y')

        if got_pub[0] not in 'xt':
            got_pub,*_ = slip132undo(got_pub)

        got = BIP32Node.from_wallet_key(got_pub)

        wallet = BIP32Node.from_wallet_key(simulator_fixed_xprv)
        if expect != 'm':
            wallet = wallet.subkey_for_path(expect[2:])
        assert got.sec() == wallet.sec()

        need_keypress('x')


# EOF
