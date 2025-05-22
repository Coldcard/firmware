# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Address ownership tests.
#
import pytest, time, io, csv, json
from txn import fake_address
from base58 import encode_base58_checksum
from helpers import hash160, taptweak, addr_from_display_format
from bech32 import encode as bech32_encode
from bip32 import BIP32Node
from constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from constants import simulator_fixed_xprv, simulator_fixed_tprv, addr_fmt_names
from charcodes import KEY_QR

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
@pytest.mark.parametrize('offset', [ 3, 760, 763] )
@pytest.mark.parametrize('subaccount', [ 0, 34] )
@pytest.mark.parametrize('change_idx', [ 0, 1] )
@pytest.mark.parametrize('from_empty', [ True, False] )
def test_positive(addr_fmt, offset, subaccount, chain, from_empty, change_idx,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    enter_number, press_cancel, settings_set, import_ms_wallet, clear_miniscript, is_q1,
):

    # API/Unit test, limited UX
    ms_addr_fmts = { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }
    if (addr_fmt in ms_addr_fmts) and subaccount:
        raise pytest.skip('multisig with subaccount')

    if chain == "BTC":
        use_testnet(False)
        testnet = False
        if addr_fmt in ms_addr_fmts:
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
        clear_miniscript()
        keys = import_ms_wallet(M, N, name=expect_name, accept=True, addr_fmt=addr_fmt_names[addr_fmt])

        # iffy: no cosigner index in this wallet, so indicated that w/ path_mapper
        addr, scriptPubKey, script, details = make_ms_address(
            M, keys, addr_fmt=addr_fmt, testnet=int(testnet),
            is_change=change_idx, idx=offset
        )

        path = f'.../{change_idx}/{offset}'
    else:

        if addr_fmt == AF_CLASSIC:
            menu_item = expect_name = 'Classic P2PKH'
            path = "m/44h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2WPKH_P2SH:
            menu_item = expect_name = 'P2SH-Segwit'
            path = "m/49h/{ct}h/{acc}h"
            clear_miniscript()
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

    cmd = (f'from ownership import OWNERSHIP;'
           f'c,w,path=OWNERSHIP.search({addr!r});'
           f'RV.write(repr([c, w.name, path]))')

    if not from_empty:
        # we expect here to find address from cache
        # so we first need to generate proper cache
        lst = sim_exec(cmd, timeout=None)
        assert 'Traceback' not in lst, lst
        lst = eval(lst)
        assert len(lst) == 3
        assert lst[0] is False  # not from cache, needed to build it


    lst = sim_exec(cmd, timeout=None)
    assert 'Traceback' not in lst, lst
    lst = eval(lst)
    assert len(lst) == 3

    from_cache, got_name, got_path = lst

    assert from_cache == (not from_empty)
    if is_q1:
        assert expect_name in got_name
    else:
        assert expect_name.split(" ")[-1] in got_name
    if subaccount:
        # not expected for multisig, since we have proper wallet name
        if is_q1:
            assert f'Account#{subaccount}' in got_name
        else:
            assert f'Acct#{subaccount}' in got_name

    assert got_path == (change_idx, offset)

@pytest.mark.parametrize('valid', [ True, False] )
@pytest.mark.parametrize('netcode', [ "BTC", "XTN"] )
@pytest.mark.parametrize('method', [ 'qr', 'nfc'] )
@pytest.mark.parametrize('multisig', [ True, False] )
def test_ux(valid, netcode, method,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    press_cancel, press_select, settings_set, is_q1, nfc_write, need_keypress,
    cap_screen, cap_story, load_shared_mod, scan_a_qr, skip_if_useless_way,
    sign_msg_from_address, multisig, import_ms_wallet, clear_miniscript, verify_qr_address,
    src_root_dir, sim_root_dir
):
    skip_if_useless_way(method)
    addr_fmt = AF_CLASSIC

    testnet = (netcode == "XTN")

    if valid:
        if multisig:
            from test_multisig import make_ms_address, HARD
            M, N = 2, 3

            expect_name = f'own_ux_test'
            clear_miniscript()
            keys = import_ms_wallet(M, N, "p2wsh", name=expect_name, accept=1)

            # iffy: no cosigner index in this wallet, so indicated that w/ path_mapper
            addr, scriptPubKey, script, details = make_ms_address(
                M, keys, is_change=0, idx=50, addr_fmt=AF_P2WSH,
                testnet=int(testnet), path_mapper=lambda cosigner: [HARD(45), 0, 50]
            )
            addr_fmt = AF_P2WSH
        else:
            mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
            path = "m/44h/{ct}h/{acc}h/0/3".format(acc=0, ct=(1 if testnet else 0))
            sk = mk.subkey_for_path(path)
            addr = sk.address(chain=netcode)
    else:
        addr = fake_address(addr_fmt, testnet)

    if method == 'qr':
        goto_home()
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr == addr_from_display_format(story.split("\n\n")[0])
        assert '(1) to verify ownership' in story
        need_keypress('1')

    elif method == 'nfc':
        
        cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        # run simulator w/ --set nfc=1 --eff
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
            f.write(ccfile)
        nfc_write(ccfile)
        #press_select()

    else:
        raise ValueError(method)

    time.sleep(1)
    title, story = cap_story()
    assert addr == addr_from_display_format(story.split("\n\n")[0])

    if title == 'Unknown Address' and not testnet:
        assert 'That address is not valid on Bitcoin Testnet' in story
    elif valid:
        assert title == ('Verified Address' if is_q1 else "Verified!")
        assert 'Found in wallet' in story
        if not multisig:
            assert 'Derivation path' in story

        if is_q1:
            # check it can display as QR from here
            need_keypress(KEY_QR)
            verify_qr_address(addr_fmt, addr)
            press_cancel()

        if multisig:
            assert expect_name in story
            assert "Press (0) to sign message with this key" not in story
        else:
            assert 'P2PKH' in story
            assert "Press (0) to sign message with this key" in story
            need_keypress('0')
            msg = "coinkite CC the most solid HWW"
            sign_msg_from_address(msg, addr, path, addr_fmt, method, netcode)

    else:
        assert title == 'Unknown Address'
        assert 'Searched 1528' in story  # max
        assert "1 wallet(s)" in story
        assert 'without finding a match' in story

@pytest.mark.parametrize("af", ["P2SH-Segwit", "Segwit P2WPKH", "Classic P2PKH", "Taproot P2TR", "ms0", "msc0", "msc2"])
def test_address_explorer_saver(af, wipe_cache, settings_set, goto_address_explorer,
                                pick_menu_item, need_keypress, sim_exec, clear_miniscript,
                                import_ms_wallet, press_select, goto_home, nfc_write,
                                load_shared_mod, load_export_and_verify_signature,
                                cap_story, load_export, offer_minsc_import, is_q1,
                                src_root_dir, sim_root_dir):
    goto_home()
    wipe_cache()
    settings_set('accts', [])

    if af == "ms0":
        clear_miniscript()
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
    contents, _, _ = load_export_and_verify_signature(body, "sd", label="Address summary")

    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    addr = None
    assert hdr[:2] == ['Index', 'Payment Address']
    for n, (idx, addr, *_) in enumerate(cc, start=0):
        assert int(idx) == n
        if idx == 200:
            addr = addr

    cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
    n = cc_ndef.ndefMaker()
    n.add_text(addr)
    ccfile = n.bytes()

    # run simulator w/ --set nfc=1 --eff
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Verify Address')
    with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
        f.write(ccfile)

    nfc_write(ccfile)

    time.sleep(1)
    title, story = cap_story()

    assert addr == addr_from_display_format(story.split("\n\n")[0])
    assert title == ('Verified Address' if is_q1 else "Verified!")
    assert 'Found in wallet' in story
    if "ms" not in af:
        assert 'Derivation path' in story
    if af == "Segwit P2WPKH":
        assert " P2WPKH " in story
    else:
        assert af in story

    settings_remove("msas")


def test_ae_saver(wipe_cache, settings_set, goto_address_explorer, cap_story,
                  pick_menu_item, need_keypress, sim_exec, clear_ms, is_q1,
                  import_ms_wallet, press_select, goto_home, nfc_write,
                  load_shared_mod, load_export_and_verify_signature,
                  set_addr_exp_start_idx, use_testnet):

    cmd = lambda a: (
        f'from ownership import OWNERSHIP;'
        f'c,w,path=OWNERSHIP.search({a!r});'
        f'RV.write(repr([c, w.name, path]))')

    def cache_check(a, from_cache):
        l = sim_exec(cmd(a), timeout=None)
        assert 'Traceback' not in l, l
        assert eval(l)[0] == from_cache

    use_testnet()
    goto_home()
    wipe_cache()
    settings_set('accts', [])
    settings_set('aei', True)

    goto_address_explorer()
    set_addr_exp_start_idx(7)  # starting from index 7
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    contents, sig_addr, _ = load_export_and_verify_signature(body, "sd", label="Address summary")
    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    assert hdr == ['Index', 'Payment Address', 'Derivation']
    addrs = {}
    for idx, addr, deriv in cc:
        addrs[int(idx)] = addr

    # nothing was created from above as start index was 7
    cache_check(addrs[7], False)
    # now we have cached addresses up to 27
    for i in range(8, 28):
        cache_check(addrs[i], True)

    # cache file position at 27 (aka count)
    goto_address_explorer()
    set_addr_exp_start_idx(1)  # starting from index 1
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    load_export_and_verify_signature(body, "sd", label="Address summary")

    # after above we must have first 250 addresses cached
    cache_check(addrs[249], True)

    # cache file position at 250 (aka count)
    goto_address_explorer()
    set_addr_exp_start_idx(250)  # starting from index 250
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    contents, sig_addr, _ = load_export_and_verify_signature(body, "sd", label="Address summary")
    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    assert hdr == ['Index', 'Payment Address', 'Derivation']
    addrs = {}
    for idx, addr, deriv in cc:
        addrs[int(idx)] = addr

    # after above we must have first 500 addresses cached
    cache_check(addrs[300], True)
    cache_check(addrs[400], True)
    cache_check(addrs[499], True)

    # now addresses that we already have, does nothing
    goto_address_explorer()
    set_addr_exp_start_idx(100)  # starting from index 100
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    load_export_and_verify_signature(body, "sd", label="Address summary")
    cache_check(addrs[499], True)

    # now move count up via ownership
    mk = BIP32Node.from_wallet_key(simulator_fixed_tprv)
    sk = mk.subkey_for_path("84h/1h/0h/0/580")
    addr = bech32_encode('tb', 0, sk.hash160())
    cache_check(addr, False)
    # now count at 600 (580+20)

    # now over the max but with some we already have
    goto_address_explorer()
    set_addr_exp_start_idx(550)  # starting from index 550 (would go up to 800)
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    contents, sig_addr, _ = load_export_and_verify_signature(body, "sd", label="Address summary")
    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    assert hdr == ['Index', 'Payment Address', 'Derivation']
    addrs = {}
    for idx, addr, deriv in cc:
        addrs[int(idx)] = addr

    assert 799 in addrs
    cache_check(addrs[763], True)  # max

    # start idx over max stored addresses
    goto_address_explorer()
    set_addr_exp_start_idx(764)  # starting from index 764
    pick_menu_item("Segwit P2WPKH")
    need_keypress("1")  # save to SD

    time.sleep(.1)
    title, body = cap_story()
    load_export_and_verify_signature(body, "sd", label="Address summary")
    # does notthing harmful, nothing added

    cache_check(addrs[763], True)  # max
    l = sim_exec(cmd(addrs[764]), timeout=None)
    assert 'Traceback' in l
    assert 'Searched 1528' in l  # max
    assert "1 wallet(s)" in l
    assert 'without finding a match' in l


def test_regtest_addr_on_mainnet(goto_home, is_q1, pick_menu_item, scan_a_qr, nfc_write, cap_story,
                                 need_keypress, load_shared_mod, use_mainnet, src_root_dir, sim_root_dir):
    # testing bug in chains.possible_address_fmt
    # allowed regtest addresses to be allowed on main chain
    goto_home()
    use_mainnet()
    addr = "bcrt1qmff7njttlp6tqtj0nq7svcj2p9takyqm3mfl06"
    if is_q1:
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr == addr_from_display_format(story.split("\n\n")[0])
        assert '(1) to verify ownership' in story
        need_keypress('1')

    else:
        cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        # run simulator w/ --set nfc=1 --eff
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
            f.write(ccfile)
        nfc_write(ccfile)
        # press_select()

    time.sleep(1)
    title, story = cap_story()
    assert addr == addr_from_display_format(story.split("\n\n")[0])

    assert title == 'Unknown Address'
    assert "not valid on Bitcoin Mainnet" in story


def test_20_more_build_after_match(sim_exec, import_ms_wallet, clear_ms, wipe_cache, settings_set):
    from test_multisig import make_ms_address, HARD

    cmd = lambda a: (
        f'from ownership import OWNERSHIP;'
        f'c,w,path=OWNERSHIP.search({a!r});'
        f'RV.write(repr([c, w.name, path]))')

    # create multisig wallet
    M, N = 2, 3
    expect_name = 'test20more'
    clear_ms()
    keys = import_ms_wallet(M, N, name=expect_name, accept=True, addr_fmt="p2wsh")

    make_a = lambda index: make_ms_address(
        M, keys,
        is_change=False, idx=index, addr_fmt=AF_P2WSH, testnet=True,
        path_mapper=lambda cosigner: [HARD(45), 0, index])

    def cache_check(index, from_cache):
        a = make_a(index)[0]
        l = sim_exec(cmd(a), timeout=None)
        assert 'Traceback' not in l, l
        assert eval(l)[0] == from_cache

    # clean slate
    wipe_cache()
    settings_set('accts', [])

    # generate 10th (idx=9) address (external)
    # first run, generated first 10 addresses + 20
    cache_check(9, False)

    # now we can go up to index 29 - all must come from cache
    for i in range(10, 30):
        cache_check(i, True)

    # idx 30 - not in cache
    # but will cache next 20 addrs
    cache_check(30, False)

    # now we can go up to index 51 - all must come from cache
    for i in range(31, 51):
        cache_check(i, True)

    # idx 51 - not in cache
    # but will cache next 20 addrs
    cache_check(51, False)

    cache_check(760, False)
    cache_check(761, True)
    cache_check(762, True)
    cache_check(763, True)

    # after max - not gonna find
    addr = make_a(764)[0]
    l = sim_exec(cmd(addr), timeout=None)
    assert 'Traceback' in l
    assert 'Searched 1528' in l  # max
    assert "1 wallet(s)" in l
    assert 'without finding a match' in l


def test_named_wallet_search_fail(load_shared_mod, goto_home, pick_menu_item, nfc_write,
                                  cap_story):
    addr = fake_address(AF_P2WSH, True)
    addr = f"{addr}?wallet=unknown"
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
    assert addr.split("?", 1)[0] == addr_from_display_format(story.split("\n\n")[0])
    assert "Wallet 'unknown' not defined." in story


@pytest.mark.parametrize('valid', [True, False])
@pytest.mark.parametrize('method', ["qr", "nfc"])
def test_named_wallet_search(valid, method, clear_ms, import_ms_wallet, is_q1,
                             load_shared_mod, goto_home, pick_menu_item, scan_a_qr,
                             cap_story, need_keypress, nfc_write, use_testnet,
                             wipe_cache, settings_set):

    from test_multisig import make_ms_address, HARD

    if method == "qr" and (not is_q1):
        raise pytest.skip("QR Mk")

    wipe_cache()  # very different codepaths
    settings_set('accts', [])
    use_testnet()
    M, N = 2, 3
    clear_ms()
    ms_data = {}
    # all ms wallets have same address format, different M/N
    for i in range(3):
        idx = 5
        if i == 2:
            idx = 763
        name = f'msnw{i}'
        keys = import_ms_wallet(M+i, N+i, AF_P2WSH, name=name, accept=True)
        # last address
        addr, scriptPubKey, script, details = make_ms_address(
            M+i, keys, is_change=0, idx=idx, addr_fmt=AF_P2WSH,
            testnet=True, path_mapper=lambda cosigner: [HARD(45), 0, idx]
        )
        ms_data[name] = (addr, scriptPubKey, script, keys)

    if valid:
        # msnw2 -> last added wallet
        addr, *_ = ms_data["msnw2"]
    else:
        # will fail, even tho address is present in different wallet
        # with wallet=<wal> only specified wallet is searched
        addr, *_ = ms_data["msnw0"]

    # will only search specified wallet
    addr = f"{addr}?wallet=msnw2"

    if method == 'qr':
        goto_home()
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr.split("?", 1)[0] == addr_from_display_format(story.split("\n\n")[0])
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
        # press_select()

    else:
        raise ValueError(method)

    time.sleep(1)
    title, story = cap_story()
    assert addr.split("?", 1)[0] == addr_from_display_format(story.split("\n\n")[0])

    if valid:
        assert title == ('Verified Address' if is_q1 else "Verified!")
        assert 'Found in wallet' in story
        assert 'Derivation path' in story

        assert "msnw2" in story

    else:
        assert title == 'Unknown Address'
        assert 'Searched 1528' in story  # max
        assert "1 wallet(s)" in story
        assert 'without finding a match' in story

# EOF
