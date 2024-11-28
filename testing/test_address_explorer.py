# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Test the address explorer.
#
# Only single-sig here. Multisig cases are elsewhere.
#
import pytest, time, io, csv, bech32
from ckcc_protocol.constants import *
from bip32 import BIP32Node
from base58 import decode_base58_checksum
from helpers import detruncate_address, hash160
from charcodes import KEY_QR, KEY_LEFT, KEY_RIGHT
from constants import MAX_BIP32_IDX

@pytest.fixture
def mk_common_derivations():
    def doit(netcode):
        netcode_map = {'BTC': '0', 'XTN': '1'}
        if netcode not in netcode_map.keys():
            raise ValueError(netcode)
        coin_type = netcode_map[netcode]
        return [
            # path format, address format
            # Removed in v4.1.3: ( "m/{change}/{idx}", AF_CLASSIC ),
            #( "m/{account}'/{change}'/{idx}'", AF_CLASSIC ),
            #( "m/{account}'/{change}'/{idx}'", AF_P2WPKH ),
            ("m/44h/{coin_type}h/{account}h/{change}/{idx}".replace('{coin_type}', coin_type), AF_CLASSIC),
            ("m/49h/{coin_type}h/{account}h/{change}/{idx}".replace('{coin_type}', coin_type), AF_P2WPKH_P2SH),
            ("m/84h/{coin_type}h/{account}h/{change}/{idx}".replace('{coin_type}', coin_type), AF_P2WPKH),
            ("m/86h/{coin_type}h/{account}h/{change}/{idx}".replace('{coin_type}', coin_type), AF_P2TR),
        ]
    return doit


@pytest.fixture
def parse_display_screen(cap_story, is_mark3):
    # start: index of first address displayed in body
    # n: number of addresses displayed in body
    # return: dictionary of subpath => address
    def doit(start, n):
        if (start + n) > MAX_BIP32_IDX:
            n = MAX_BIP32_IDX - start + 1
        title, body = cap_story()
        lines = body.split('\n')
        if start == 0:
            # no header after first page
            assert 'to save address summary file' in body
            assert 'show QR code' in body

        assert lines[0] == 'Addresses %d⋯%d:' % (start, start + n - 1)
        raw_addrs = lines[2:-1]

        d = dict()
        for path_raw, addr, empty in zip(*[iter(raw_addrs)]*3):
            path = path_raw.split(" =>")[0]
            d[path] = addr
        assert len(d) == n
        return d
    return doit


@pytest.fixture
def generate_addresses_file(goto_address_explorer, need_keypress, cap_story, microsd_path,
                            virtdisk_path, nfc_read_text, load_export_and_verify_signature,
                            press_select, press_nfc, load_export):
    # Generates the address file through the simulator, reads the file and
    # returns a list of tuples of the form (subpath, address)
    def doit(start_idx=0, way="sd", change=False, is_custom_single=False, is_p2tr=False):
        expected_qty = 250 if way != "nfc" else 10
        if (start_idx + expected_qty) > MAX_BIP32_IDX:
            expected_qty = (MAX_BIP32_IDX - start_idx) + 1

        time.sleep(.1)
        title, story = cap_story()
        if change and not is_custom_single:
            need_keypress("0")
        if way == "sd":
            if "Press (1)" in story:
                need_keypress('1')
        elif way == "vdisk":
            if "save to Virtual Disk" not in story:
                raise pytest.skip("Vdisk disabled")
            need_keypress("2")
        else:
            # NFC
            if "share via NFC" not in story:
                raise pytest.skip("NFC disabled")
            press_nfc()
            time.sleep(0.3)
            addresses = nfc_read_text()
            time.sleep(0.3)
            press_select()
            # nfc just returns 10 addresses
            assert len(addresses.split("\n")) == expected_qty
            raise pytest.xfail("PASSED - different export format for NFC")

        if is_p2tr:
            # p2tr - no signature file
            contents = load_export(way, label="Address summary", is_json=False,
                                   sig_check=False, skip_query=True)
            sig_addr = None
        else:
            time.sleep(.5)  # always long enough to write the file?
            title, body = cap_story()
            contents, sig_addr = load_export_and_verify_signature(body, way, label="Address summary")

        addr_dump = io.StringIO(contents)
        cc = csv.reader(addr_dump)
        hdr = next(cc)
        assert hdr == ['Index', 'Payment Address', 'Derivation']
        for n, (idx, addr, deriv) in enumerate(cc, start=start_idx):
            assert int(idx) == n
            if n == start_idx:
                if sig_addr:
                    assert sig_addr == addr
            if not is_custom_single:
                assert ('/%s' % idx) in deriv

            yield deriv, addr

        if is_custom_single:
            assert n+1 == 1
        else:
            assert (n+1-start_idx) == expected_qty

    return doit


@pytest.mark.parametrize("start_idx", [999999, 0])
def test_stub_menu(sim_execfile, goto_address_explorer, need_keypress,
                   cap_menu, mk_common_derivations, pick_menu_item,
                   parse_display_screen, validate_address, press_cancel,
                   settings_set, set_addr_exp_start_idx, start_idx):
    # For a given wallet, ensure the explorer shows the correct stub addresses
    settings_set('aei', True if start_idx else False)
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    common_derivs = mk_common_derivations(node_prv.netcode())

    # capture menu address stubs
    goto_address_explorer()
    need_keypress('4')
    time.sleep(.1)
    set_addr_exp_start_idx(start_idx)
    time.sleep(.1)
    m = cap_menu()

    gap = iter(range(1, 10))
    for idx, (path, addr_format) in enumerate(common_derivs):
        # derive index=0 address
        _id = next(gap) + idx
        subpath = path.format(account=0, change=0, idx=start_idx) # e.g. "m/44h/1h/0h/0/0"
        sk = node_prv.subkey_for_path(subpath)

        # capture full index=0 address from display screen & validate it
        mi = m[_id]
        pick_menu_item(mi)
        addr_dict = parse_display_screen(start_idx, 10)
        assert subpath in addr_dict, 'subpath ("%s") not found' % subpath
        expected_addr = addr_dict[subpath]
        validate_address(expected_addr, sk)

        # validate that stub is correct
        start, end = detruncate_address(mi)
        assert expected_addr.startswith(start)
        assert expected_addr.endswith(end)
        press_cancel()

@pytest.mark.parametrize("chain", ["BTC", "XRT", "XTN"])
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize("start_idx", [69400, 0])
@pytest.mark.parametrize("option", [
    ("Pre-mix", "2147483645h"),
    # ("Bad Bank", "2147483644'"),  not released yet
    ("Post-mix", "2147483646h")
])
def test_applications_samourai(chain, change, option, goto_address_explorer, cap_menu,
                               pick_menu_item, validate_address, parse_display_screen,
                               sim_execfile, settings_set, need_keypress, start_idx,
                               generate_addresses_file, set_addr_exp_start_idx):
    settings_set('aei', True if start_idx else False)
    menu_option, account_num = option
    if chain in ["XTN", "XRT"]:
        coin_type = "1h"
    else:
        coin_type = "0h"
    settings_set('chain', chain)
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    goto_address_explorer()
    set_addr_exp_start_idx(start_idx)
    pick_menu_item("Applications")
    menu = cap_menu()
    assert "Samourai" in menu
    pick_menu_item("Samourai")
    menu = cap_menu()
    assert menu_option in menu
    pick_menu_item(menu_option)
    if change:
        need_keypress("0")  # change (internal)
        time.sleep(.1)
    screen_addrs = parse_display_screen(start_idx, 10)
    file_addr_gen = generate_addresses_file(change=change, start_idx=start_idx)
    for subpath, addr in screen_addrs.items():
        f_subpath, f_addr = next(file_addr_gen)
        assert f_subpath == subpath
        assert f_addr == addr
        assert subpath.startswith(f"m/84h/{coin_type}/{account_num}/{1 if change else 0}")
        # derive the subkey and validate the corresponding address
        sk = node_prv.subkey_for_path(subpath)
        validate_address(addr, sk)

@pytest.mark.parametrize('start_idx, press_seq, expected_start, expected_n', [
    (0, ['9', '9', '9', '7', '7', '9'], 20, 10), # forward backward forward
    (0, [], 0, 10), # initial
    (0, ['7', '7', '7'], 0, 10), # cannot go past 0
    (0, ['7', '7', '9'], 10, 10), # backwards at start is idempotent
    (0, ['9', '9', '9', '9', '9', '9', '9', '9', '9', '9'], 100, 10),
    (MAX_BIP32_IDX, ['9', '9', '9'], MAX_BIP32_IDX, 1),
    (MAX_BIP32_IDX, ['7', '7', '7'], 2147483617, 10),
    (100003, ['9', '9', '9', '9', '9', '9'], 100063, 10),
    (2147483638, ['9', '9', '9'], 2147483638, 10),
    (2147483637, ['9', '9', '9'], MAX_BIP32_IDX, 1),
    (2147483636, ['9', '9', '9'], 2147483646, 2),
])
def test_address_display(goto_address_explorer, parse_display_screen, mk_common_derivations,
                         need_keypress, sim_execfile, validate_address, press_seq, expected_n,
                         expected_start, pick_menu_item, cap_menu, is_q1, press_cancel,
                         start_idx, settings_set, set_addr_exp_start_idx):
    # The proper addresses are displayed
    # given the sequence of  keys pressed
    settings_set('aei', True if start_idx else False)

    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    common_derivs = mk_common_derivations(node_prv.netcode())
    gap = iter(range(1, 10))

    goto_address_explorer()
    set_addr_exp_start_idx(start_idx)

    m = cap_menu()
    for click_idx, (path, addr_format) in enumerate(common_derivs):
        # Click on specified derivation idx in explorer
        _id = next(gap) + click_idx
        mi = m[_id]
        pick_menu_item(mi)

        # perform keypad press sequence
        for key in press_seq:
            if is_q1:
                key = KEY_RIGHT if key == "9" else KEY_LEFT
            need_keypress(key)
            time.sleep(0.01)

        # validate each address on screen
        addr_dict = parse_display_screen(expected_start, expected_n)
        for subpath, given_addr in addr_dict.items():
            sk = node_prv.subkey_for_path(subpath)
            validate_address(given_addr, sk)

        press_cancel()  # back

@pytest.mark.parametrize('click_idx', ["Classic P2PKH", "P2SH-Segwit", "Segwit P2WPKH", 'Taproot P2TR'])
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize("start_idx", [MAX_BIP32_IDX, 80965, 0])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_dump_addresses(way, change, generate_addresses_file, mk_common_derivations,
                        sim_execfile, validate_address, click_idx, pick_menu_item,
                        goto_address_explorer, start_idx, settings_set,
                        set_addr_exp_start_idx):
    # Validate  addresses dumped to text file
    settings_set('aei', True if start_idx else False)
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    goto_address_explorer()
    set_addr_exp_start_idx(start_idx)
    pick_menu_item(click_idx)
    # Generate the addresses file and get each line in a list
    is_p2tr = click_idx == 'Taproot P2TR'
    for subpath, addr in generate_addresses_file(way=way, start_idx=start_idx, change=change, is_p2tr=is_p2tr):
        # derive the subkey and validate the corresponding address
        assert subpath.split("/")[-2] == "1" if change else "0"
        sk = node_prv.subkey_for_path(subpath)
        validate_address(addr, sk)

@pytest.mark.parametrize('account_num', [ 34, 9999, 1])
@pytest.mark.parametrize('start_idx', [10000, MAX_BIP32_IDX, 0])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_account_menu(way, account_num, sim_execfile, pick_menu_item,
                      goto_address_explorer, need_keypress, cap_menu,
                      mk_common_derivations, parse_display_screen,
                      validate_address, generate_addresses_file,
                      press_cancel, press_select, enter_number,
                      start_idx, settings_set, set_addr_exp_start_idx
):
    # Try a few sub-accounts
    settings_set('aei', True if start_idx else False)
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    common_derivs = mk_common_derivations(node_prv.netcode())

    # capture menu address stubs
    goto_address_explorer()
    time.sleep(.01)
    # skip warning
    need_keypress('4')
    time.sleep(.01)

    m = cap_menu()
    pick_menu_item([i for i in m if i.startswith('Account')][0])

    # enter account number
    enter_number(account_num)

    m = cap_menu()
    assert f'Account: {account_num}' in m

    set_addr_exp_start_idx(start_idx)

    gap = iter(range(1,10))
    for idx, (path, addr_format) in enumerate(common_derivs):
        _id = next(gap) + idx
        # derive index=0 address
        assert '{account}' in path

        subpath = path.format(account=account_num, change=0, idx=start_idx, is_p2tr=addr_format==AF_P2TR) # e.g. "m/44'/1'/X'/0/0"
        sk = node_prv.subkey_for_path(subpath)

        # capture full index=0 address from display screen & validate it

        # go down menu to expected derivation spot
        m = cap_menu()
        pick_menu_item(m[_id])
        time.sleep(0.1)

        addr_dict = parse_display_screen(start_idx, 10)
        if subpath not in addr_dict:
            raise Exception('Subpath ("%s") not found in address explorer display' % subpath)
        expected_addr = addr_dict[subpath]
        validate_address(expected_addr, sk)

        # validate that stub is correct
        start, end = detruncate_address(m[_id])
        assert expected_addr.startswith(start)
        assert expected_addr.endswith(end)

        for subpath, addr in generate_addresses_file(way=way, start_idx=start_idx,is_p2tr=addr_format==AF_P2TR):
            assert subpath.split('/')[-3] == str(account_num)+"h"
            sk = node_prv.subkey_for_path(subpath)
            validate_address(addr, sk)

        press_cancel()
        press_cancel()


@pytest.mark.qrcode
@pytest.mark.parametrize('path_sidx', [
    # NOTE: (2**31)-1 = 0x7fff_ffff = 2147483647
    ("m/1h/{idx}", 0),
    ("m/1h/{idx}", 1999),
    ("m/1h/{idx}", MAX_BIP32_IDX),
    # for paths that are not ranged (does not end with {idx}) start index is ignored
    ("m/2147483647/2147483647/2147483647h/2147483647/2147483647/2147483647h/2147483647/2147483647", 0),
    ("m/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647", 1999),
    ("m/1/2/3/4/5", MAX_BIP32_IDX),
    ("m/1h/2h/3h/4h/5h", 0),
])
@pytest.mark.parametrize('which_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR])
def test_custom_path(path_sidx, which_fmt, addr_vs_path, pick_menu_item, goto_address_explorer,
                     need_keypress, cap_menu, parse_display_screen, validate_address,
                     cap_screen_qr, qr_quality_check, nfc_read_text, get_setting,
                     press_select, press_cancel, is_q1, press_nfc, cap_story,
                     generate_addresses_file, settings_set, set_addr_exp_start_idx):

    path, start_idx = path_sidx
    settings_set('aei', True if start_idx else False)
    is_single = '{idx}' not in path

    goto_address_explorer()
    time.sleep(.01)
    # skip warning
    need_keypress('4')
    time.sleep(.01)

    set_addr_exp_start_idx(start_idx)

    def ss(x):
        return x.split('/')

    pick_menu_item('Custom Path')

    # blind entry, using only first 2 menu items
    deeper = ss(path)[1:]
    last = ss(path)[-1]
    for depth, part in enumerate(deeper):
        time.sleep(.01)
        m = cap_menu()
        if depth == 0:
            assert m[0] == 'm/⋯'
            pick_menu_item(m[0])
        elif part == '{idx}':
            break
        else:
            assert m[0].endswith("h/⋯")
            assert m[1].endswith("/⋯")
            assert m[0] != m[1]

            pick_menu_item(m[0 if last_part[-1] == "h" else 1])

        # enter path component
        for d in part:
            if d == "h": break
            need_keypress(d)
        press_select()

        last_part = part

    time.sleep(.01)
    m = cap_menu()
    if is_single:
        if len(last) <= 3:
            assert m[2].endswith(f"/{last}") or m[3].endswith(f"/{last}")

        pick_menu_item(m[2 if part[-1] == "h" else 3])
    else:
        assert last == '{idx}'
        iis = [i for i in m if i.endswith(f"/{last_part}"+"/{idx}")]
        assert len(iis) == 1
        pick_menu_item(iis[0])

    time.sleep(.5)          # .2 not enuf
    m = cap_menu()
    assert m[0] == 'Classic P2PKH'
    assert m[1] == 'Segwit P2WPKH'
    assert m[2] == 'Taproot P2TR'
    assert m[3] == 'P2SH-Segwit'

    fmts = {
        AF_CLASSIC: 'Classic P2PKH', 
        AF_P2WPKH: 'Segwit P2WPKH', 
        AF_P2WPKH_P2SH: 'P2SH-Segwit',
        AF_P2TR: 'Taproot P2TR',
    }

    pick_menu_item(fmts[which_fmt])

    title, body = cap_story()
    assert 'DANGER' in title
    assert 'DO NOT DEPOSIT' in body
    assert path in body

    need_keypress('3')      # approve risk
    time.sleep(.2)

    if is_single:
        # check that lateral scrolling on single address does not cause the yikes
        need_keypress(KEY_RIGHT if is_q1 else "9")
        need_keypress(KEY_LEFT if is_q1 else "7")

        time.sleep(.2)
        title, body = cap_story()
        assert 'Showing single addr' in body
        assert path in body

        addr = body.split("\n")[3]

        addr_vs_path(addr, path, addr_fmt=which_fmt)

        need_keypress(KEY_QR if is_q1 else '4')
        qr = cap_screen_qr().decode('ascii')
        if which_fmt in (AF_P2WPKH, AF_P2TR):
            assert qr == addr.upper()
        else:
            assert qr == addr

        if get_setting('nfc', 0):
            # this is actually testing NFC export in qr code menu
            press_nfc()
            time.sleep(.1)
            assert nfc_read_text() == addr
            press_cancel()  # leave NFC animation
            press_cancel()  # leave QR code display
            # test NFC export in address explorer
            press_nfc()
            time.sleep(.1)
            assert nfc_read_text() == addr
            time.sleep(.2)
            press_cancel()
        else:
            # remove QR from screen
            press_cancel()

        addr_gen = generate_addresses_file(change=False, is_custom_single=True, is_p2tr=which_fmt == AF_P2TR)
        f_path, f_addr = next(addr_gen)
        assert f_path == path
        assert f_addr == addr
    else:
        n = 10
        if (start_idx + n) > MAX_BIP32_IDX:
            n = MAX_BIP32_IDX - start_idx + 1

        addr_dict = parse_display_screen(start_idx, n)
        for i in range(start_idx, start_idx+n):
            p = path.format(idx=i)
            assert p in addr_dict
            addr_vs_path(addr_dict[p], p, addr_fmt=which_fmt)

        nfc_addr_list = None
        if get_setting('nfc', 0):
            press_nfc()
            time.sleep(.1)
            nfc_addrs = nfc_read_text()
            time.sleep(.2)
            press_cancel()
            nfc_addr_list = nfc_addrs.split("\n")

        qr_addr_list = []
        need_keypress(KEY_QR if is_q1 else '4')
        for i in range(n):
            qr = cap_screen_qr().decode('ascii')
            if which_fmt in (AF_P2WPKH, AF_P2TR):
                qr = qr.lower()
            qr_addr_list.append(qr)
            need_keypress(KEY_RIGHT if is_q1 else "9")
            time.sleep(.5)

        press_cancel()  # QR code on screen

        if nfc_addr_list:
            assert qr_addr_list == nfc_addr_list

        assert sorted(qr_addr_list) == sorted(addr_dict.values())

        addr_gen = generate_addresses_file(start_idx=start_idx, change=False, is_p2tr=which_fmt==AF_P2TR)
        assert addr_dict == {p: a for i,(p, a) in enumerate(addr_gen) if i < n}

        # check the rest of file export
        for p, a in addr_gen:
            addr_vs_path(a, p, addr_fmt=which_fmt)


@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", [AF_P2WPKH, AF_P2WPKH_P2SH, AF_CLASSIC, AF_P2TR])
@pytest.mark.parametrize("acct_num", [None, "999"])
def test_bitcoind_descriptor_address(addr_fmt, acct_num, bitcoind, goto_home, pick_menu_item, cap_story,
                                     use_regtest, need_keypress, microsd_path, generate_addresses_file,
                                     bitcoind_d_wallet_w_sk, load_export, settings_set, cap_menu,
                                     goto_address_explorer, press_cancel, press_select, enter_number):
    # export single sig descriptors (external, internal)
    # export addressses from address explorer
    # derive addresses from descriptor with bitcoind
    # compare bitcoind derived addressses with those exported from address explorer
    bitcoind = bitcoind_d_wallet_w_sk
    use_regtest()
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Export Wallet")
    pick_menu_item("Descriptor")
    time.sleep(.1)
    _, story = cap_story()
    assert "This saves a ranged xpub descriptor" in story
    assert "Press (1) to enter a non-zero account number" in story
    assert "sensitive--in terms of privacy" in story
    assert "not compromise your funds directly" in story

    if isinstance(acct_num, str):
        need_keypress("1")        # chosse account number
        for ch in acct_num:
            need_keypress(ch)     # input num
        press_select()       # confirm selection
    else:
        press_select()  # confirm story

    time.sleep(.1)
    _, story = cap_story()
    assert "press (1) to export receiving and change descriptors separately" in story
    need_keypress("1")

    sig_check = True
    if addr_fmt == AF_P2WPKH:
        menu_item = "Segwit P2WPKH"
        desc_prefix = "wpkh("
    elif addr_fmt == AF_P2WPKH_P2SH:
        menu_item = "P2SH-Segwit"
        desc_prefix = "sh(wpkh("
    elif addr_fmt == AF_P2TR:
        menu_item = "Taproot P2TR"
        desc_prefix = "tr("
        sig_check = False
    else:
        # addr_fmt == AF_CLASSIC:
        menu_item = "Classic P2PKH"
        desc_prefix = "pkh("

    pick_menu_item(menu_item)
    contents = load_export("sd", label="Descriptor", is_json=False, addr_fmt=addr_fmt,
                           sig_check=sig_check)
    descriptors = contents.strip()
    ext_desc, int_desc = descriptors.split("\n")
    assert ext_desc.startswith(desc_prefix)
    assert int_desc.startswith(desc_prefix)

    # check both external and internal
    for chng in [False, True]:
        goto_address_explorer()
        if acct_num:
            menu = cap_menu()
            # can be "Account number" or "Account: N"
            mi = [m for m in menu if "Account" in m]
            assert len(mi) == 1
            pick_menu_item(mi[0])
            enter_number(acct_num)

        desc = int_desc if chng else ext_desc
        settings_set("axi", 0)
        pick_menu_item(menu_item)
        cc_addrs_gen = generate_addresses_file(change=chng, is_p2tr=addr_fmt == AF_P2TR)
        cc_addrs = [addr for deriv, addr in cc_addrs_gen]
        bitcoind_addrs = bitcoind.deriveaddresses(desc, [0, 249])
        assert cc_addrs == bitcoind_addrs

# EOF
