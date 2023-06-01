# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, os, io, csv, hashlib
from ckcc_protocol.constants import *
from pycoin.key.BIP32Node import BIP32Node
from pycoin.contrib.segwit_addr import encode as sw_encode
from pycoin.encoding import a2b_hashed_base58, hash160
from helpers import detruncate_address


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
            ( "m/44'/{coin_type}'/{account}'/{change}/{idx}".replace('{coin_type}', coin_type), AF_CLASSIC ),
            ( "m/49'/{coin_type}'/{account}'/{change}/{idx}".replace('{coin_type}', coin_type), AF_P2WPKH_P2SH ),
            ( "m/84'/{coin_type}'/{account}'/{change}/{idx}".replace('{coin_type}', coin_type), AF_P2WPKH )
        ]
    return doit

@pytest.fixture
def goto_address_explorer(goto_home, pick_menu_item, need_keypress):
    def doit(click_idx=None):
        goto_home()
        pick_menu_item('Address Explorer')

        if click_idx is not None:
            need_keypress('4') # click into stub menu
            time.sleep(0.01)

            for _ in range(2): # top of menu (requires two left clicks)
                need_keypress('7')
                time.sleep(0.01)

            for _ in range(click_idx): # iterate down
                need_keypress('8')
                time.sleep(0.01)

            need_keypress('y')
            time.sleep(0.01)
    return doit

@pytest.fixture
def parse_display_screen(cap_story, is_mark3):
    # start: index of first address displayed in body
    # n: number of addresses displayed in body
    # return: dictionary of subpath => address
    def doit(start, n):
        title, body = cap_story()
        lines = body.split('\n')
        if start == 0:
            assert 'Press (1) to save Address summary file to SD Card.' in lines[0]
            if is_mark3:
                assert '(2) to view QR Codes' in lines[0]
            assert lines[2] == 'Addresses %d..%d:' % (start, start + n - 1)
            raw_addrs = lines[4:-1] # Remove header & last line
        else:
            # no header after first page
            assert lines[0] == 'Addresses %d..%d:' % (start, start + n - 1)
            raw_addrs = lines[2:-1]

        d = dict()
        for path_raw, addr, empty in zip(*[iter(raw_addrs)]*3):
            path = path_raw.split(" =>")[0]
            d[path] = addr
        assert len(d) == n
        return d
    return doit

@pytest.fixture
def validate_address():
    # Check whether an address is covered by the given subkey
    def doit(addr, sk):
        if addr[0] in '1mn':
            assert addr == sk.address(False)
        elif addr[0:3] in { 'bc1', 'tb1' }:
            h20 = sk.hash160()
            assert addr == sw_encode(addr[0:2], 0, h20)
        elif addr[0:5] == "bcrt1":
            h20 = sk.hash160()
            assert addr == sw_encode(addr[0:4], 0, h20)
        elif addr[0] in '23':
            h20 = hash160(b'\x00\x14' + sk.hash160())
            assert h20 == a2b_hashed_base58(addr)[1:]
        else:
            raise ValueError(addr)
    return doit

@pytest.fixture
def generate_addresses_file(goto_address_explorer, need_keypress, cap_story, microsd_path,
                            virtdisk_path, nfc_read_text, load_export_and_verify_signature):
    # Generates the address file through the simulator, reads the file and
    # returns a list of tuples of the form (subpath, address)
    def doit(click_idx=None, expected_qty=250, way="sd", change=False):
        if click_idx is not None:
            goto_address_explorer(click_idx=click_idx)
        time.sleep(.3)
        title, story = cap_story()
        if change:
            need_keypress("6")
        if way == "sd":
            need_keypress('1')
        elif way == "vdisk":
            if "Press (4) to save to Virtual Disk." not in story:
                pytest.skip("Vdisk disabled")
            need_keypress("4")
        else:
            # NFC
            if "Press (3) to share via NFC." not in story:
                pytest.skip("NFC disabled")
            need_keypress("3")
            time.sleep(0.3)
            addresses = nfc_read_text()
            time.sleep(0.3)
            need_keypress("y")
            # nfc just returns 10 addresses
            assert len(addresses.split("\n")) == 10
            pytest.xfail("PASSED - different export format for NFC")

        time.sleep(.5)  # always long enough to write the file?
        title, body = cap_story()
        contents, sig_addr = load_export_and_verify_signature(body, way, label="Address summary")
        addr_dump = io.StringIO(contents)
        cc = csv.reader(addr_dump)
        hdr = next(cc)
        assert hdr == ['Index', 'Payment Address', 'Derivation']
        for n, (idx, addr, deriv) in enumerate(cc):
            assert int(idx) == n
            if n == 0:
                assert sig_addr == addr
            assert ('/%s' % idx) in deriv

            yield deriv, addr

        assert (n+1) == expected_qty

    return doit


def test_stub_menu(sim_execfile, goto_address_explorer, need_keypress, cap_menu, mk_common_derivations,
                   parse_display_screen, validate_address):
    # For a given wallet, ensure the explorer shows the correct stub addresses
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    common_derivs = mk_common_derivations(node_prv.netcode())

    # capture menu address stubs
    goto_address_explorer()
    need_keypress('4')
    time.sleep(.01)
    m = cap_menu()
    gap = iter(range(1, 10))
    for idx, (path, addr_format) in enumerate(common_derivs):
        # derive index=0 address
        _id = next(gap) + idx
        subpath = path.format(account=0, change=0, idx=0) # e.g. "m/44'/1'/0'/0/0"
        sk = node_prv.subkey_for_path(subpath[2:])

        # capture full index=0 address from display screen & validate it
        goto_address_explorer(click_idx=_id)
        addr_dict = parse_display_screen(0, 10)
        if subpath not in addr_dict:
            raise Exception('Subpath ("%s") not found in address explorer display' % subpath)
        expected_addr = addr_dict[subpath]
        validate_address(expected_addr, sk)

        # validate that stub is correct
        start, end = detruncate_address(m[_id])
        assert expected_addr.startswith(start)
        assert expected_addr.endswith(end)

@pytest.mark.parametrize("chain", ["BTC", "XRT", "XTN"])
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize("option", [
    ("Pre-mix", "2147483645'"),
    # ("Bad Bank", "2147483644'"),  not released yet
    ("Post-mix", "2147483646'")
])
def test_applications_samourai(chain, change, option, goto_address_explorer, cap_menu, pick_menu_item, validate_address,
                               parse_display_screen, sim_execfile, settings_set, need_keypress, generate_addresses_file):
    menu_option, account_num = option
    if chain in ["XTN", "XRT"]:
        coin_type = "1'"
    else:
        coin_type = "0'"
    settings_set('chain', chain)
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    goto_address_explorer(click_idx=6)  # "applications" at index 3
    menu = cap_menu()
    assert "Samourai" in menu
    pick_menu_item("Samourai")
    menu = cap_menu()
    assert menu_option in menu
    pick_menu_item(menu_option)
    if change:
        need_keypress("6")  # change (internal)
        time.sleep(.1)
    screen_addrs = parse_display_screen(0, 10)
    file_addr_gen = generate_addresses_file(None)
    for subpath, addr in screen_addrs.items():
        f_subpath, f_addr = next(file_addr_gen)
        assert f_subpath == subpath
        assert f_addr == addr
        assert subpath.startswith(f"m/84'/{coin_type}/{account_num}/{1 if change else 0}")
        # derive the subkey and validate the corresponding address
        sk = node_prv.subkey_for_path(subpath[2:])
        validate_address(addr, sk)

@pytest.mark.parametrize('press_seq, expected_start, expected_n', [
    (['9', '9', '9', '7', '7', '9'], 20, 10), # forward backward forward
    ([], 0, 10), # initial
    (['7', '7', '9'], 10, 10), # backwards at start is idempotent
    (['9', '9', '9', '9', '9', '9', '9', '9', '9', '9'], 100, 10)
])
def test_address_display(goto_address_explorer, parse_display_screen, mk_common_derivations, need_keypress, sim_execfile, validate_address, press_seq, expected_start, expected_n):
    # The proper addresses are displayed
    # given the sequence of  keys pressed
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    common_derivs = mk_common_derivations(node_prv.netcode())
    gap = iter(range(1, 10))
    for click_idx, (path, addr_format) in enumerate(common_derivs):
        # Click on specified derivation idx in explorer
        _id = next(gap) + click_idx
        goto_address_explorer(click_idx=click_idx)

        # perform keypad press sequence
        for key in press_seq:
            need_keypress(key)
            time.sleep(0.01)

        # validate each address on screen
        addr_dict = parse_display_screen(expected_start, expected_n)
        for subpath, given_addr in addr_dict.items():
            sk = node_prv.subkey_for_path(subpath[2:])
            validate_address(given_addr, sk)

@pytest.mark.parametrize('click_idx', [1,3,5])
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_dump_addresses(way, change, generate_addresses_file, mk_common_derivations, sim_execfile, validate_address,
                        click_idx):
    # Validate  addresses dumped to text file
    node_prv = BIP32Node.from_wallet_key(
        sim_execfile('devtest/dump_private.py').strip()
    )
    # Generate the addresses file and get each line in a list
    for subpath, addr in generate_addresses_file(click_idx, way=way, change=change):
        # derive the subkey and validate the corresponding address
        assert subpath.split("/")[-2] == "1" if change else "0"
        sk = node_prv.subkey_for_path(subpath[2:])
        validate_address(addr, sk)

@pytest.mark.parametrize('account_num', [ 34, 100, 9999, 1])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
def test_account_menu(way, account_num, sim_execfile, pick_menu_item, goto_address_explorer, need_keypress, cap_menu,
                      mk_common_derivations, parse_display_screen, validate_address, generate_addresses_file):
    # Try a few sub-accounts
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
    time.sleep(0.1)
    for d in str(account_num):
        need_keypress(d)
    need_keypress('y')
    time.sleep(0.1)

    m = cap_menu()
    assert f'Account: {account_num}' in m

    which = 0
    gap = iter(range(1,10))
    for idx, (path, addr_format) in enumerate(common_derivs):
        _id = next(gap) + idx
        # derive index=0 address
        assert '{account}' in path

        subpath = path.format(account=account_num, change=0, idx=0) # e.g. "m/44'/1'/X'/0/0"
        sk = node_prv.subkey_for_path(subpath[2:])

        # capture full index=0 address from display screen & validate it

        # go down menu to expected derivation spot
        m = cap_menu()
        pick_menu_item(m[_id])
        time.sleep(0.1)

        addr_dict = parse_display_screen(0, 10)
        if subpath not in addr_dict:
            raise Exception('Subpath ("%s") not found in address explorer display' % subpath)
        expected_addr = addr_dict[subpath]
        validate_address(expected_addr, sk)

        # validate that stub is correct
        start, end = detruncate_address(m[_id])
        assert expected_addr.startswith(start)
        assert expected_addr.endswith(end)

        for subpath, addr in generate_addresses_file(way=way):
            assert subpath.split('/')[-3] == str(account_num)+"'"
            sk = node_prv.subkey_for_path(subpath[2:])
            validate_address(addr, sk)

        need_keypress('x')
        need_keypress('x')

# NOTE: (2**31)-1 = 0x7fff_ffff = 2147483647

@pytest.mark.qrcode
@pytest.mark.parametrize('path', [
    "m/1'/{idx}",
    "m/2147483647/2147483647/2147483647'/2147483647/2147483647/2147483647'/2147483647/2147483647",
    "m/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647/2147483647",
    "m/1/2/3/4/5",
    "m/1'/2'/3'/4'/5'",
])
@pytest.mark.parametrize('which_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_custom_path(path, which_fmt, addr_vs_path, pick_menu_item, goto_address_explorer, need_keypress, cap_menu, parse_display_screen, validate_address, cap_story, cap_screen_qr, qr_quality_check, is_mark4plus, nfc_read_text, get_setting, press_select):

    is_single = '{idx}' not in path

    goto_address_explorer()
    time.sleep(.01)
    # skip warning
    need_keypress('4')
    time.sleep(.01)

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
            assert m[0] == 'm/..'
            pick_menu_item(m[0])
        elif part == '{idx}':
            break
        else:
            assert m[0].endswith("'/..")
            assert m[1].endswith("/..")
            assert m[0] != m[1]

            pick_menu_item(m[0 if last_part[-1] == "'" else 1])

        # enter path component
        for d in part:
            if d == "'": break
            need_keypress(d)
        press_select()

        last_part = part

    time.sleep(.01)
    m = cap_menu()
    if is_single:
        if len(last) <= 3:
            assert m[2].endswith(f"/{last}") or m[3].endswith(f"/{last}")

        pick_menu_item(m[2 if part[-1] == "'" else 3])
    else:
        assert last == '{idx}'
        iis = [i for i in m if i.endswith(f"/{last_part}"+"/{idx}")]
        assert len(iis) == 1
        pick_menu_item(iis[0])

    time.sleep(.5)          # .2 not enuf
    m = cap_menu()
    assert m[0] == 'Classic P2PKH'
    assert m[1] == 'Segwit P2WPKH'
    assert m[2] == 'P2SH-Segwit'
        
    fmts = {
        AF_CLASSIC: 'Classic P2PKH', 
        AF_P2WPKH: 'Segwit P2WPKH', 
        AF_P2WPKH_P2SH: 'P2SH-Segwit',
    }

    pick_menu_item(fmts[which_fmt])

    title, body = cap_story()
    assert 'DANGER' in title
    assert 'DO NOT DEPOSIT' in body
    assert path in body

    need_keypress('3')      # approve risk

    if is_single:
        time.sleep(.2)
        title, body = cap_story()
        assert 'Showing single addr' in body
        assert path in body

        addr = body.split()[-1]

        addr_vs_path(addr, path, addr_fmt=which_fmt)

        need_keypress('2')
        qr = cap_screen_qr().decode('ascii')
        if which_fmt == AF_P2WPKH:
            assert qr == addr.upper()
        else:
            assert qr == addr

        if is_mark4plus and get_setting('nfc', 0):
            # this is actually testing NFC export in qr code menu
            need_keypress('3')
            time.sleep(.1)
            assert nfc_read_text() == addr
            need_keypress("x")  # leave NFC animation
            need_keypress("x")  # leave QR code display
            # test NFC export in address explorer
            need_keypress('3')
            time.sleep(.1)
            assert nfc_read_text() == addr

    else:
        n = 10
        addr_dict = parse_display_screen(0, n)
        for i in range(n):
            p = path.format(idx=i)
            assert p in addr_dict
            addr_vs_path(addr_dict[p], p, addr_fmt=which_fmt)

# EOF
