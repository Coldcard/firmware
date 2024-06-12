# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Address ownership tests.
#
import pytest, time, io, csv, json
from txn import fake_address
from base58 import encode_base58_checksum
from helpers import hash160, taptweak
from bip32 import BIP32Node
from constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from constants import simulator_fixed_xprv, simulator_fixed_tprv, addr_fmt_names

@pytest.fixture
def wipe_cache(sim_exec):
    def doit():
        cmd = f'from ownership import OWNERSHIP; OWNERSHIP.wipe_all();'
        sim_exec(cmd)
    return doit


'''
    >>> [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH]
        [14,       8,       26,            1,          7,         19]
'''
@pytest.mark.parametrize('addr_fmt', [
    AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
])
@pytest.mark.parametrize('testnet', [ False, True] )
def test_negative(addr_fmt, testnet, sim_exec):
    # unit test, no UX
    addr = fake_address(addr_fmt, testnet)

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)

    assert 'Explained' in lst

@pytest.mark.parametrize('addr_fmt, chain', [
	(AF_CLASSIC, "XTN"),
	(AF_CLASSIC, "BTC"),
	(AF_P2WPKH, "XTN"),
	(AF_P2WPKH, "BTC"),
	(AF_P2WPKH_P2SH, "XTN"),
	(AF_P2WPKH_P2SH, "BTC"),
    (AF_P2TR, "XTN"),
    (AF_P2TR, "BTC"),

    # multisig - testnet only
	(AF_P2WSH, "XTN"),
	(AF_P2SH, "XTN"),
	(AF_P2WSH_P2SH, "XTN"),
])
@pytest.mark.parametrize('offset', [ 3, 760] )
@pytest.mark.parametrize('subaccount', [ 0, 34] )
@pytest.mark.parametrize('change_idx', [ 0, 1] )
@pytest.mark.parametrize('from_empty', [ True, False] )
def test_positive(addr_fmt, offset, subaccount, chain, from_empty, change_idx,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    enter_number, press_cancel, settings_set, import_ms_wallet, clear_ms
):
    from bech32 import encode as bech32_encode

    # API/Unit test, limited UX

    if chain == "BTC":
        use_testnet(False)
        testnet = False
        if addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
            # multisig jigs assume testnet
            raise pytest.skip('testnet only')

    coin_type = 0
    if chain == "XTN":
        use_testnet(True)
        coin_type = 1
        testnet = True

    if from_empty:
        wipe_cache()        # very different codepaths
        settings_set('accts', [])

    if addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
        from test_multisig import make_ms_address, HARD
        M, N = 1, 3

        expect_name = f'search-test-{addr_fmt}'
        clear_ms()
        keys = import_ms_wallet(M, N, name=expect_name, accept=1, addr_fmt=addr_fmt_names[addr_fmt])

        # iffy: no cosigner index in this wallet, so indicated that w/ path_mapper
        addr, scriptPubKey, script, details = make_ms_address(M, keys,
                    is_change=change_idx, idx=offset, addr_fmt=addr_fmt, testnet=int(testnet),
                    path_mapper=lambda cosigner: [HARD(45), change_idx, offset])

        path = f'.../{change_idx}/{offset}'
    else:

        if addr_fmt == AF_CLASSIC:
            menu_item = expect_name = 'Classic P2PKH'
            path = "m/44h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2WPKH_P2SH:
            expect_name = 'P2WPKH-in-P2SH'
            menu_item = 'P2SH-Segwit'
            path = "m/49h/{ct}h/{acc}h"
            clear_ms()
        elif addr_fmt == AF_P2WPKH:
            menu_item = expect_name = 'Segwit P2WPKH'
            path = "m/84h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2TR:
            menu_item = expect_name = 'Taproot P2TR'
            path = "m/86h/{ct}h/{acc}h"
        else:
            raise ValueError(addr_fmt)

        path_prefix = path.format(ct=coin_type, acc=subaccount)
        path = path_prefix + f'/{change_idx}/{offset}'
        print(f'path = {path}')

        # see addr_vs_path
        mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
        sk = mk.subkey_for_path(path)

        if addr_fmt == AF_CLASSIC:
            addr = sk.address(chain=chain)
        elif addr_fmt == AF_P2WPKH_P2SH:
            pkh = sk.hash160()
            digest = hash160(b'\x00\x14' + pkh)
            addr = encode_base58_checksum(bytes([196 if testnet else 5]) + digest)
        elif addr_fmt == AF_P2TR:
            from bech32 import encode
            tweked_xonly = taptweak(sk.sec()[1:])
            addr = encode("tb" if testnet else "bc", 1, tweked_xonly)
        else:
            pkh = sk.hash160()
            addr = bech32_encode('tb' if testnet else 'bc', 0, pkh)
    
        if subaccount:
            # need to hint we're doing a non-zero acccount number
            goto_home()
            settings_set('axskip', True)
            pick_menu_item('Address Explorer')
            pick_menu_item('Account Number')
            enter_number(subaccount)
            pick_menu_item(menu_item)
            press_cancel()

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)
    if 'candidates without finding a match' in lst:
        # some kinda timing issue, but don't want big delays, so just retry
        print("RETRY search!")
        lst = sim_exec(cmd)
        
    assert 'Traceback' not in lst, lst

    lst = eval(lst)
    assert len(lst) == 2

    got_name, got_path = lst
    assert expect_name in got_name
    if subaccount and '...' not in path:
        # not expected for multisig, since we have proper wallet name
        assert f'Account#{subaccount}' in got_name

    assert got_path == (change_idx, offset)

@pytest.mark.parametrize('valid', [ True, False] )
@pytest.mark.parametrize('testnet', [ True, False] )
@pytest.mark.parametrize('method', [ 'qr', 'nfc'] )
def test_ux(valid, testnet, method, 
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    press_cancel, press_select, settings_set, is_q1, nfc_write, need_keypress,
    cap_screen, cap_story, load_shared_mod, scan_a_qr
):

    addr_fmt = AF_CLASSIC

    if valid:
        mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
        path = "m/44h/{ct}h/{acc}h/0/3".format(acc=0, ct=(1 if testnet else 0))
        sk = mk.subkey_for_path(path)
        addr = sk.address(chain="XTN" if testnet else "BTC")
    else:
        addr = fake_address(addr_fmt, testnet) 

    if method == 'qr':
        if not is_q1:
            raise pytest.skip('no QR on Mk4')
        goto_home()
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr in story
        assert '(1) to verify ownership' in story
        need_keypress('1')

    elif method == 'nfc':
        
        cc_ndef = load_shared_mod('cc_ndef', '../shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        # run simulator w/ --set nfc=1 --eff
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        open('debug/nfc-addr.ndef', 'wb').write(ccfile)
        nfc_write(ccfile)
        #press_select()

    else:
        raise ValueError(method)

    time.sleep(1)
    title, story = cap_story()

    assert addr in story

    if title == 'Unknown Address' and not testnet:
        assert 'That address is not valid on Bitcoin Testnet' in story
    elif valid:
        assert title == 'Verified Address'
        assert 'Found in wallet' in story
        assert 'Derivation path' in story
        assert 'P2PKH' in story
    else:
        assert title == 'Unknown Address'
        assert 'Searched ' in story
        assert 'candidates without finding a match' in story

@pytest.mark.parametrize("af", ["P2SH-Segwit", "Segwit P2WPKH", "Classic P2PKH", "Taproot P2TR", "ms0", "msc0", "msc2"])
def test_address_explorer_saver(af, wipe_cache, settings_set, goto_address_explorer,
                                pick_menu_item, need_keypress, sim_exec, clear_ms,
                                import_ms_wallet, press_select, goto_home, nfc_write,
                                load_shared_mod, load_export_and_verify_signature,
                                cap_story, load_export, offer_minsc_import):
    goto_home()
    wipe_cache()
    settings_set('accts', [])

    if af == "ms0":
        clear_ms()
        import_ms_wallet(2, 3, name=af)
        press_select()  # accept ms import
    elif "msc" in af:
        from test_miniscript import CHANGE_BASED_DESCS
        which = int(af[-1])
        title, story = offer_minsc_import(json.dumps({"name": af, "desc": CHANGE_BASED_DESCS[which]}))
        assert "Create new miniscript wallet?" in story
        press_select()  # accept

    goto_address_explorer()
    pick_menu_item(af)
    need_keypress("1")  # save to SD

    cmd = f'import os; RV.write(repr([i for i in os.listdir() if ".own" in i]))'
    lst = sim_exec(cmd)
    assert 'Traceback' not in lst, lst
    lst = eval(lst)
    assert lst

    title, body = cap_story()
    if af in ("Taproot P2TR", "ms0", "msc0", "msc2"):
        # p2tr - no signature file
        contents = load_export("sd", label="Address summary", is_json=False, sig_check=False)
    else:
        contents, _ = load_export_and_verify_signature(body, "sd", label="Address summary")

    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    addr = None
    assert hdr[:2] == ['Index', 'Payment Address']
    for n, (idx, addr, *_) in enumerate(cc, start=0):
        assert int(idx) == n
        if idx == 200:
            addr = addr

    cc_ndef = load_shared_mod('cc_ndef', '../shared/ndef.py')
    n = cc_ndef.ndefMaker()
    n.add_text(addr)
    ccfile = n.bytes()

    # run simulator w/ --set nfc=1 --eff
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Verify Address')
    open('debug/nfc-addr.ndef', 'wb').write(ccfile)
    nfc_write(ccfile)

    time.sleep(1)
    title, story = cap_story()

    assert addr in story
    assert title == 'Verified Address'
    assert 'Found in wallet' in story
    # assert 'Derivation path' in story
    if af == "P2SH-Segwit":
        assert "P2WPKH-in-P2SH" in story
    elif af == "Segwit P2WPKH":
        assert " P2WPKH " in story
    else:
        assert af in story

# EOF
