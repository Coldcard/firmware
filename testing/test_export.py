# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Exporting of wallet files and similar things.
#
# Start simulator with:   simulator.py --eff --set nfc=1
#
import sys
sys.path.append("../shared")
from descriptor import Descriptor
from mnemonic import Mnemonic
import pytest, time, os, json, io
from pycoin.key.BIP32Node import BIP32Node
from pycoin.contrib.segwit_addr import encode as sw_encode
from ckcc_protocol.constants import *
from helpers import xfp2str, slip132undo
from conftest import simulator_fixed_xfp, simulator_fixed_tprv, simulator_fixed_words
from ckcc_protocol.constants import AF_CLASSIC, AF_P2WPKH
from pprint import pprint
from charcodes import KEY_NFC


@pytest.fixture
def mk4_qr_not_allowed(is_q1):
    def doit(way):
        if way == "qr" and not is_q1:
            pytest.skip("mk4 QR not allowed")
    return doit



@pytest.mark.bitcoind
@pytest.mark.parametrize('acct_num', [None, '0', '99', '123'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
def test_export_core(way, dev, use_regtest, acct_num, pick_menu_item, goto_home, cap_story,
                     need_keypress, microsd_path, virtdisk_path, bitcoind_wallet, bitcoind_d_wallet,
                     enter_number, nfc_read_text, load_export, bitcoind, press_select,
                     mk4_qr_not_allowed):
    mk4_qr_not_allowed(way)
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
        press_select()

    export = load_export(way, label="Bitcoin Core", is_json=False, addr_fmt=AF_P2WPKH)
    fp = io.StringIO(export).readlines()

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
            assert path.startswith(f"m/84h/1h/{acct_num}h/0")
            assert addr.startswith('bcrt1q') # TODO here we should differentiate if testnet or smthg
            sk = BIP32Node.from_wallet_key(simulator_fixed_tprv).subkey_for_path(path[2:].replace("h", "'"))
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

            expect = BIP32Node.from_wallet_key(simulator_fixed_tprv)\
                        .subkey_for_path(f"84'/1'/{acct_num}'.pub").hwif()

            assert expect in desc
            assert expect+f'/{n}/*' in desc

        if bitcoind.has_bdb:
            # test against bitcoind
            # only legacy wallets do support importmulti
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

        expect = BIP32Node.from_wallet_key(simulator_fixed_tprv)\
                    .subkey_for_path(f"84'/1'/{acct_num}'.pub").hwif()

        assert expect in desc
        assert expect+f'/{n}/*' in desc

        assert 'label' not in d

        # test against bitcoind -- needs a "descriptor native" wallet
        res = bitcoind_d_wallet.importdescriptors(obj)
        assert res[0]["success"]
        assert res[1]["success"]
        core_gen = []
        for i in range(3):
            core_gen.append(bitcoind_d_wallet.getnewaddress())

        assert core_gen == addrs
        x = bitcoind_d_wallet.getaddressinfo(addrs[-1])
        pprint(x)
        assert x['address'] == addrs[-1]
        assert x['iswatchonly'] == False
        assert x['iswitness'] == True
        # assert x['ismine'] == True   # TODO we have imported pubkeys - it has no idea if it is ours or solvable
        # assert x['solvable'] == True
        # assert x['hdmasterfingerprint'] == xfp2str(dev.master_fingerprint).lower()
        #assert x['hdkeypath'] == f"m/84'/1'/{acct_num}'/0/%d" % (len(addrs)-1)


@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
def test_export_wasabi(way, dev, pick_menu_item, goto_home, cap_story, press_select, microsd_path,
                       nfc_read_json, virtdisk_path, testnet, use_mainnet, load_export):
    # test UX and operation of the 'wasabi wallet export'
    if not testnet:
        use_mainnet()

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Wasabi Wallet')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'This saves a skeleton Wasabi' in story
    press_select()

    obj = load_export(way, label="Wasabi wallet", is_json=True, addr_fmt=AF_P2WPKH)

    assert 'MasterFingerprint' in obj
    assert 'ExtPubKey' in obj
    assert 'ColdCardFirmwareVersion' in obj
    
    xpub = obj['ExtPubKey']
    assert xpub.startswith('xpub')

    assert obj['MasterFingerprint'] == xfp2str(simulator_fixed_xfp)

    got = BIP32Node.from_wallet_key(xpub)
    expect = BIP32Node.from_wallet_key(simulator_fixed_tprv).subkey_for_path(f"84'/{int(testnet)}'/0'.pub")

    assert got.sec() == expect.sec()

        
@pytest.mark.parametrize('mode', [ "Classic P2PKH", "P2SH-Segwit", "Segwit P2WPKH"])
@pytest.mark.parametrize('acct_num', [ None, '0', '9897'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
def test_export_electrum(way, dev, mode, acct_num, pick_menu_item, goto_home, cap_story, need_keypress,
                         microsd_path, nfc_read_json, virtdisk_path, use_mainnet, testnet, load_export,
                         press_select, mk4_qr_not_allowed):
    # lightly test electrum wallet export
    mk4_qr_not_allowed(way)
    if not testnet:
        use_mainnet()
    if "P2PKH" in mode:
        af = AF_CLASSIC
    elif "P2SH" in mode:
        af = AF_P2WPKH_P2SH
    else:
        af = AF_P2WPKH
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

    press_select()

    time.sleep(0.1)
    pick_menu_item(mode)

    obj = load_export(way, label="Electrum wallet", is_json=True, addr_fmt=af)

    ks = obj['keystore']
    assert ks['ckcc_xfp'] == simulator_fixed_xfp

    assert ks['hw_type'] == 'coldcard'
    assert ks['type'] == 'hardware'

    deriv = ks['derivation']
    assert deriv.startswith('m/')
    assert int(deriv.split("/")[1][:-1]) in {44, 84, 49}        # weak
    assert deriv.split("/")[3] == (acct_num or '0')+"h"

    xpub = ks['xpub']
    assert xpub[1:4] == 'pub'

    if xpub[0] in 'tx':
        if testnet:
            assert xpub[0] == "t"
        else:
            assert xpub[0] == "x"
        # no slip132 here

        got = BIP32Node.from_wallet_key(xpub)
        expect = BIP32Node.from_wallet_key(simulator_fixed_tprv).subkey_for_path(deriv[2:].replace("h", "'"))

        assert got.sec() == expect.sec()


@pytest.mark.parametrize('acct_num', [ None, '99', '1236'])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
@pytest.mark.parametrize('app', [
    ("Generic JSON", "Generic Export"),
    ("Lily Wallet", "Lily Wallet"),
    ("Sparrow Wallet", "Sparrow Wallet"),
    ("Nunchuk", "Nunchuk"),
])
def test_export_coldcard(way, dev, acct_num, app, pick_menu_item, goto_home, cap_story, need_keypress,
                         microsd_path, nfc_read_json, virtdisk_path, addr_vs_path, enter_number,
                         load_export, testnet, use_mainnet, press_select, mk4_qr_not_allowed):
    mk4_qr_not_allowed(way)

    if not testnet:
        use_mainnet()

    export_mi, app_f_name = app
    # test UX and values produced.
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item(export_mi)

    time.sleep(0.1)
    title, story = cap_story()
    assert 'JSON file' in story

    assert "Press (1)" in story
    if acct_num:
        need_keypress('1')
        time.sleep(0.1)
        enter_number(acct_num)
    else:
        acct_num = '0'
        press_select()

    obj = load_export(way, label=app_f_name, is_json=True, addr_fmt=AF_CLASSIC)

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
            assert v['deriv'] == "m/45h"
        elif 'bip48' not in fn:
            assert v['deriv'].endswith(f"h/{acct_num}h")
        else:
            b48n = fn[-1]
            assert v['deriv'].endswith(f"h/{acct_num}h/{b48n}h")

        node = BIP32Node.from_wallet_key(v['xpub'])
        assert v['xpub'] == node.hwif(as_private=False)
        first = node.subkey_for_path('0/0')
        addr = v.get('first', None)

        if fn == 'bip44':
            assert first.address() == v['first']
            addr_vs_path(addr, v['deriv'] + '/0/0', AF_CLASSIC, testnet=testnet)
        elif ('bip48_' in fn) or (fn == 'bip45'):
            # multisig: cant do addrs
            assert addr == None
        else:
            assert v['_pub'][1:4] == 'pub'
            assert slip132undo(v['_pub'])[0] == v['xpub']

            h20 = first.hash160()
            if fn == 'bip84':
                assert addr == sw_encode(addr[0:2], 0, h20)
                addr_vs_path(addr, v['deriv'] + '/0/0', AF_P2WPKH, testnet=testnet)
            elif fn == 'bip49':
                # don't have test logic for verifying these addrs
                # - need to make script, and bleh
                assert addr[0] in '23'
                #addr_vs_path(addr, v['deriv'] + '/0/0', AF_P2WSH_P2SH, script=)
            else:
                assert False

@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
@pytest.mark.parametrize('acct_num', [None, '0', '99', '123'])
def test_export_unchained(way, dev, pick_menu_item, goto_home, cap_story, need_keypress, acct_num,
                          microsd_path, nfc_read_json, virtdisk_path, testnet, enter_number,
                          load_export, settings_set, use_mainnet, press_select, mk4_qr_not_allowed):
    # test UX and operation of the 'unchained export'
    mk4_qr_not_allowed(way)

    if not testnet:
        use_mainnet()
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Unchained')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Unchained' in story
    assert "Capital" not in story
    assert 'Press (1) to' in story
    if acct_num is not None:
        need_keypress('1')
        time.sleep(0.1)
        enter_number(acct_num)
    else:
        acct_num = '0'
        press_select()

    obj = load_export(way, label="Unchained", is_json=True, sig_check=False)

    root = BIP32Node.from_wallet_key(simulator_fixed_tprv)
    if not testnet:
        root._netcode = "BTC"
    assert obj['xfp'] == xfp2str(simulator_fixed_xfp)
    assert obj['account'] == int(acct_num)
    if acct_num == "0":
        assert obj['p2sh_deriv'] == "m/45h"
        addr_formats = ['p2sh_p2wsh', 'p2sh', 'p2wsh']
    else:
        assert 'p2sh_deriv' not in obj
        addr_formats = ['p2sh_p2wsh', 'p2wsh']

    for k in addr_formats:
        xpub = slip132undo(obj[k])[0] if k != 'p2sh' else obj[k]
        node = BIP32Node.from_wallet_key(xpub)
        assert xpub == node.hwif(as_private=False)
        sk = root.subkey_for_path(obj[f'{k}_deriv'][2:].replace("h", "'") + '.pub')
        #assert node.chain_code() == sk.chain_code()
        assert node.hwif() == sk.hwif()


@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize('testnet', [True, False])
def test_export_public_txt(way, dev, pick_menu_item, goto_home, press_select, microsd_path,
                           addr_vs_path, virtdisk_path, nfc_read_text, cap_story, use_mainnet,
                           load_export, testnet, mk4_qr_not_allowed):
    # test UX and values produced.
    mk4_qr_not_allowed(way)

    if not testnet:
        use_mainnet()
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Export Wallet')
    pick_menu_item('Dump Summary')

    time.sleep(0.1)
    title, story = cap_story()

    assert 'Saves a text file' in story
    press_select()

    contents = load_export(way, label="Summary", is_json=False, addr_fmt=AF_CLASSIC)
    fp = io.StringIO(contents).readlines()

    xfp = xfp2str(simulator_fixed_xfp).upper()

    root = BIP32Node.from_wallet_key(simulator_fixed_tprv)
    if not testnet:
        root._netcode = "BTC"
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
            expect = root.subkey_for_path(lhs[2:].replace("h", "'"))
            assert expect.hwif(as_private=False) == rhs
            continue

        if not f:
            if rhs[0] in '1mn':
                f = AF_CLASSIC
            elif rhs[0:3] in ['tb1', "bc1"]:
                f = AF_P2WPKH
            elif rhs[0] in '23':
                f = AF_P2WPKH_P2SH
            else:
                raise ValueError(rhs)

        addr_vs_path(rhs, path=lhs, addr_fmt=f, testnet=testnet)


@pytest.mark.qrcode
@pytest.mark.parametrize('acct_num', [ None, 0, 99, 8989])
@pytest.mark.parametrize('use_nfc', [False, True])
def test_export_xpub(use_nfc, acct_num, dev, cap_menu, pick_menu_item, goto_home,
                     cap_story, need_keypress, enter_number, cap_screen_qr,
                     use_mainnet, nfc_read_text, is_q1, press_select, press_cancel,
                     press_nfc):
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
            expect = "m/84h/0h/{acct}h"
        elif '-44' in m:
            expect = "m/44h/0h/{acct}h"
        elif '49' in m:
            expect = "m/49h/0h/{acct}h"
        elif 'Master' in m:
            expect = "m"
        elif 'XFP' in m:
            is_xfp = True

        pick_menu_item(m)
        time.sleep(0.3)
        if is_xfp:
            got = cap_screen_qr().decode('ascii')
            if use_nfc:
                press_nfc()
            assert got == xfp2str(simulator_fixed_xfp).upper()
            press_cancel()
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
            press_select()
            got_pub = cap_screen_qr().decode('ascii')
        else:
            if f'Press {KEY_NFC if is_q1 else "(3)"}' not in story:
                raise pytest.skip("NFC disabled")
            assert 'NFC' in story
            press_nfc()
            time.sleep(0.2)
            got_pub = nfc_read_text()
            time.sleep(0.1)
            #press_select()

        if got_pub[0] not in 'xt':
            got_pub,*_ = slip132undo(got_pub)

        got = BIP32Node.from_wallet_key(got_pub)

        wallet = BIP32Node.from_wallet_key(simulator_fixed_tprv)
        if expect != 'm':
            wallet = wallet.subkey_for_path(expect[2:].replace('h', "'"))
        assert got.sec() == wallet.sec()

        press_cancel()

@pytest.mark.parametrize("chain", ["BTC", "XTN", "XRT"])
@pytest.mark.parametrize("way", ["sd", "vdisk", "nfc", "qr"])
@pytest.mark.parametrize("addr_fmt", [AF_P2WPKH, AF_P2WPKH_P2SH, AF_CLASSIC])
@pytest.mark.parametrize("acct_num", [None, 0,  1, (2 ** 31) - 1])
@pytest.mark.parametrize("int_ext", [True, False])
def test_generic_descriptor_export(chain, addr_fmt, acct_num, goto_home, settings_set, need_keypress,
                                   pick_menu_item, way, cap_story, cap_menu, nfc_read_text, int_ext,
                                   microsd_path, settings_get, virtdisk_path, load_export, press_select,
                                   mk4_qr_not_allowed):
    mk4_qr_not_allowed(way)

    settings_set('chain', chain)
    chain_num = 1 if chain in ["XTN", "XRT"] else 0
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Export Wallet")
    pick_menu_item("Descriptor")
    time.sleep(.1)
    _, story = cap_story()
    assert "This saves a ranged xpub descriptor" in story
    assert "Choose descriptor and address type for the wallet on next screens" in story
    assert "Press (1) to enter a non-zero account number" in story
    assert "sensitive--in terms of privacy" in story
    assert "not compromise your funds directly" in story

    if isinstance(acct_num, int):
        need_keypress("1")        # chosse account number
        for ch in str(acct_num):
            need_keypress(ch)     # input num
        press_select()        # confirm selection
    else:
        press_select()  # confirm story

    time.sleep(.1)
    _, story = cap_story()
    assert "To export receiving and change descriptors in one descriptor (<0;1> notation) press OK" in story
    assert "press (1) to export receiving and change descriptors separately" in story
    if int_ext:
        press_select()
    else:
        need_keypress("1")

    menu = cap_menu()
    if addr_fmt == AF_P2WPKH:
        menu_item = "Segwit P2WPKH"
        desc_prefix = "wpkh("
        bip44_purpose = 84
    elif addr_fmt == AF_P2WPKH_P2SH:
        menu_item = "P2SH-Segwit"
        desc_prefix = "sh(wpkh("
        bip44_purpose = 49
    else:
        # addr_fmt == AF_CLASSIC:
        menu_item = "Classic P2PKH"
        desc_prefix = "pkh("
        bip44_purpose = 44

    assert menu_item in menu
    pick_menu_item(menu_item)

    contents = load_export(way, label="Descriptor", is_json=False, addr_fmt=addr_fmt)
    descriptor = contents.strip()

    if int_ext is False:
        descriptor = descriptor.split("\n")[0]  # external
    assert descriptor.startswith(desc_prefix)
    desc_obj = Descriptor.parse(descriptor)
    assert desc_obj.serialize(int_ext=int_ext) == descriptor
    assert desc_obj.addr_fmt == addr_fmt
    assert len(desc_obj.keys) == 1
    xfp, derive, xpub = desc_obj.keys[0]
    assert xfp == settings_get("xfp")
    assert derive == f"m/{bip44_purpose}h/{chain_num}h/{acct_num if acct_num is not None else 0}h"
    seed = Mnemonic.to_seed(simulator_fixed_words)
    node = BIP32Node.from_master_secret(
        seed, netcode="BTC" if chain == "BTC" else "XTN"
    ).subkey_for_path(derive[2:].replace("h", "H"))
    xpub_target = node.hwif()
    assert xpub_target in xpub


@pytest.mark.parametrize("chain", ["BTC", "XTN", "XRT"])
@pytest.mark.parametrize("account", ["Postmix", "Premix"])
def test_samourai_vs_generic(chain, account, settings_set, pick_menu_item, goto_home,
                             need_keypress, cap_story, microsd_path, nfc_read_text,
                             load_export, press_select, press_cancel):
    if account == "Postmix":
        acct_num = 2147483646
        in_story = "Samourai POST-MIX"
    else:
        acct_num = 2147483645
        in_story = "Samourai PRE-MIX"

    settings_set('chain', chain)
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Export Wallet")
    pick_menu_item("Descriptor")

    need_keypress("1")
    for ch in str(acct_num):
        need_keypress(ch)
    press_select()
    press_select()  # int_ext <0;1>
    pick_menu_item("Segwit P2WPKH")  #  both postmix and premix are p2wpkh only
    file_desc_generic = load_export("sd", label="Descriptor", is_json=False, addr_fmt=AF_P2WPKH)
    press_select()  # written
    press_cancel()  # back to export submenu
    press_cancel()  # back to advanced
    pick_menu_item("Export Wallet")
    pick_menu_item(f"Samourai {account}")
    time.sleep(.1)
    _, story = cap_story()
    assert "This saves a ranged xpub descriptor" in story
    assert in_story in story
    assert "Choose an address type for the wallet on the next screen" not in story  # NOT
    assert "Press 1 to enter a non-zero account number" not in story  # NOT
    assert "sensitive--in terms of privacy" in story
    assert "not compromise your funds directly" in story
    press_select()
    file_desc = load_export("sd", label="Descriptor", is_json=False, addr_fmt=AF_P2WPKH)
    assert file_desc.strip() == file_desc_generic.strip()

# EOF
