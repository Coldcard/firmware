# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Multisig-related tests.
#
# After this file passes, also run again like this:
#
#       py.test test_multisig.py -m ms_danger --ms-danger
#
import time, pytest, os, random, json, shutil, pdb, io, base64, struct, bech32, itertools, re
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from ckcc.protocol import CCProtocolPacker, MAX_TXN_LEN
from pprint import pprint
from base64 import b64encode, b64decode
from base58 import encode_base58_checksum
from helpers import B2A, fake_dest_addr, xfp2str, addr_from_display_format
from helpers import path_to_str, str_to_path, slip132undo, swab32, hash160, bitcoind_addr_fmt
from struct import unpack, pack
from constants import *
from bip32 import BIP32Node
from ctransaction import CTransaction, CTxOut, CTxIn, COutPoint, uint256_from_str
from io import BytesIO
from hashlib import sha256
from bbqr import split_qrs
from descriptor import MULTI_FMT_TO_SCRIPT, MultisigDescriptor, parse_desc_str
from charcodes import KEY_QR, KEY_DELETE


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


@pytest.fixture
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
def make_multisig(dev, sim_execfile):
    # make a multsig wallet, always with simulator as an element

    # default is BIP-45:   m/45'/... (but no co-signer idx)
    # - but can provide str format for deriviation, use {idx} for cosigner idx

    def doit(M, N, unique=0, deriv=None, dev_key=False, netcode="XTN"):

        if netcode == "XRT":
            # makes no sense keys wise
            netcode = "XTN"

        def _derive(master, origin_der, idx):
            if origin_der == "m":
                return master

            d = origin_der.format(idx=idx) if origin_der else "m/45h"
            try:
                child = master.subkey_for_path(d)
            except IndexError:
                # some test cases are using bogus paths
                child = master
            return child

        keys = []

        for i in range(N-1):
            pk = BIP32Node.from_master_secret(b'CSW is a fraud %d - %d' % (i, unique), netcode)

            xfp = unpack("<I", pk.fingerprint())[0]

            sub = _derive(pk, deriv, i)
            keys.append((xfp, pk, sub))

        if dev_key:
            sk = sim_execfile('devtest/dump_private.py').strip()
            pk = BIP32Node.from_wallet_key(sk)
            xfp_bytes = pk.fingerprint()
            xfp = swab32(struct.unpack('>I', xfp_bytes)[0])
        else:
            pk = BIP32Node.from_wallet_key(simulator_fixed_tprv if netcode == "XTN" else simulator_fixed_xprv)
            xfp = simulator_fixed_xfp

        dev_sim = _derive(pk, deriv, N-1)

        keys.append((xfp, pk, dev_sim))

        return keys

    return doit

@pytest.fixture
def import_ms_wallet(dev, make_multisig, offer_minsc_import, press_select,
                     is_q1, request, need_keypress, usb_miniscript_get,
                     settings_set, sim_root_dir, import_miniscript):

    def doit(M, N, addr_fmt=None, name=None, unique=0, accept=False, common=None,
             keys=None, do_import=True, derivs=None,
             int_ext_desc=False, dev_key=False, way=None, bip67=True,
             chain="XTN"):

        keys = keys or make_multisig(M, N, unique=unique, dev_key=dev_key,
                                     deriv=common or (derivs[0] if derivs else None),
                                     netcode=chain)

        if addr_fmt is None:
            addr_fmt = "p2wsh"

        if not derivs:
            if not common:
                common = "m/45h"
            key_list = [(xfp, common, dd.hwif(as_private=False)) for xfp, m, dd in keys]
        else:
            assert len(derivs) == N
            key_list = [(xfp, derivs[idx], dd.hwif(as_private=False))
                        for idx, (xfp, m, dd) in enumerate(keys)]

        desc = MultisigDescriptor(M=M, N=N, keys=key_list, addr_fmt=addr_fmt,
                                  is_sorted=bip67)
        if int_ext_desc:
            config = desc.serialize(int_ext=True)
        else:
            config = desc.serialize()

        if name:
            config = json.dumps({"name": name, "desc": config})

        if not do_import:
            return keys, config

        with open(f'{sim_root_dir}/debug/last-ms.txt', 'wt') as f:
            f.write(config)

        title, story = import_miniscript(data=config, way=way)

        assert 'Create new miniscript wallet' in story \
                or 'Update existing multisig wallet' in story \
                or 'new wallet is similar to' in story

        story_name = None
        assert addr_fmt.upper() in story
        assert f'Policy: {M} of {N}\n' in story
        for ll in story.split("\n\n"):
            if ll.startswith("Wallet Name"):
                story_name = ll.split("\n")[-1].strip()

        assert story_name
        if name:
            assert name == story_name

        if accept:
            time.sleep(.1)
            press_select()
            # Test it worked.
            time.sleep(.1)      # required
            # below raises if miniscript wallet not enrolled
            usb_miniscript_get(story_name)

        return keys

    return doit


@pytest.mark.parametrize('N', [ 3, 15])
def test_ms_import_variations(N, offer_minsc_import, press_cancel, is_q1, get_cc_key):
    # all the different ways...
    my_key = get_cc_key(path="").replace("/<0;1>/*", "")
    keys = [BIP32Node.from_master_secret(os.urandom(32), "XTN").hwif() for _ in range(N-1)]
    keys = [my_key] + keys

    # bare, no fingerprints
    # - no xfps
    # - no meta data
    k0 = ','.join(keys)
    title, story = offer_minsc_import(f"sh(multi({N},{k0}))")
    assert f'Policy: {N} of {N}\n' in story
    press_cancel()

    # exclude myself (expect fail)
    k1 = ','.join(keys[1:])
    with pytest.raises(BaseException) as ee:
        title, story = offer_minsc_import(f"wsh(sortedmulti({N-1},{k1}))")
    assert "My key 0F056943 missing in descriptor" in str(ee.value)

    desc0 = f"wsh(sortedmulti({N},{k0}))"
    # normal names
    for name in [ 'Zy', 'Z'*20, 'Vault #3' ]:
        title, story = offer_minsc_import(json.dumps({"name": name, "desc": desc0}))
        press_cancel()
        assert name in story

    # too long name
    name = 'A' * 21
    with pytest.raises(BaseException) as ee:
        title, story = offer_minsc_import(json.dumps({"name": name, "desc": desc0}))
    assert 'name len' in str(ee.value)


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
    if not make_redeem_args.get('path_mapper'):
        make_redeem_args['path_mapper'] = lambda cosigner: [HARD(45), is_change, idx]

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
def test_ms_show_addr(dev, cap_story, press_select, bitcoind, is_q1,
                      usb_miniscript_addr, usb_miniscript_get):
    def doit(name, idx=0, change=False):
        # test we are showing addresses correctly
        # - verifies against bitcoind as well

        got_addr = usb_miniscript_addr(name, idx, change)

        title, story = cap_story()

        assert got_addr == addr_from_display_format(story.split("\n\n")[0])

        press_select()

        # check against bitcoind
        desc_obj = usb_miniscript_get(name)
        ext_a, int_a = bitcoind.supply_wallet.deriveaddresses(desc_obj["desc"], [idx, idx])
        if change:
            assert int_a[0] == got_addr
        else:
            assert ext_a[0] == got_addr

    return doit
    

@pytest.mark.bitcoind
@pytest.mark.parametrize('m_of_n', [(1,3), (2,3), (3,3), (3,6), (10, 15), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_ranges(m_of_n, use_regtest, addr_fmt, clear_miniscript, import_ms_wallet,
                       usb_miniscript_addr, test_ms_show_addr):
    use_regtest()
    M, N = m_of_n

    wname = "my_rand_wal"
    import_ms_wallet(M, N, addr_fmt, name=wname, accept=True)

    #print("imported: %r" % [x for x,_,_ in keys])

    try:
        # test an address that should be in that wallet.
        time.sleep(.1)
        test_ms_show_addr(wname)

    finally:
        clear_miniscript()

@pytest.mark.bitcoind
@pytest.mark.ms_danger
def test_violate_bip67(clear_miniscript, use_regtest, import_ms_wallet,
                       test_ms_show_addr, sim_root_dir, try_sign,
                       fake_ms_txn):
    # detect when pubkeys are not in order in the redeem script
    clear_miniscript()
    M, N = 1, 15

    keys = import_ms_wallet(M, N, accept=True)

    psbt = fake_ms_txn(1, 3, M, keys,
                       outstyles=ADDR_STYLES_MS,
                       change_outputs=[1],
                       violate_script_key_order=True)

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(Exception) as e:
        try_sign(psbt)
    assert 'spk mismatch' in e.value.args[0]


@pytest.mark.parametrize("has_change", [True, False])
def test_violate_import_order_multi(has_change, clear_miniscript, import_ms_wallet,
                                    fake_ms_txn, try_sign, test_ms_show_addr,
                                    sim_root_dir):
    clear_miniscript()
    M, N = 3, 5
    keys = import_ms_wallet(M, N, accept=True, bip67=False)
    time.sleep(.1)

    psbt = fake_ms_txn(4, 2, M, keys, outstyles=ADDR_STYLES_MS,
                       change_outputs=[1] if has_change else [],
                       bip67=False, violate_script_key_order=True)

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(Exception) as e:
        try_sign(psbt)
    assert "spk mismatch" in e.value.args[0]


@pytest.mark.bitcoind
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
@pytest.mark.parametrize('desc_type', ['multi', 'sortedmulti' ])
def test_zero_depth(dev, clear_miniscript, use_regtest, addr_fmt, offer_minsc_import,
                    make_multisig, bitcoind, desc_type, settings_set, press_select,
                    goto_home, pick_menu_item, load_export, goto_address_explorer,
                    cap_story, need_keypress, try_sign):

    settings_set("chain", "XRT")
    ms_name = "zero_depth"
    clear_miniscript()
    bitcoind.delete_wallet_files(pattern="zero_depth_s")
    bitcoind.delete_wallet_files(pattern="zero_depth_wo")
    # create multiple bitcoin wallets (N-1) as one signer is CC
    cosig = bitcoind.create_wallet(wallet_name="zero_depth_s", disable_private_keys=False,
                                   blank=False, passphrase=None, avoid_reuse=False,
                                   descriptors=True)
    cosig.keypoolrefill(100)
    descs = cosig.listdescriptors()["descriptors"]
    target_desc = None
    for desc in descs:
        if desc["desc"].startswith("wpkh(") and desc["internal"] is False:
            target_desc = desc["desc"]
    core_desc, checksum = target_desc.split("#")
    # remove wpkh(....)
    core_key = core_desc[5:-1]
    my_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub("m"), timeout=None)
    my_xfp = dev.master_fingerprint
    my_xfp = xfp2str(my_xfp).lower()  # if any letters - lower them
    my_data = f"[{my_xfp}]{my_master_xpub}/0/*"
    # watch only wallet where multisig descriptor will be imported
    wo = bitcoind.create_wallet(
        wallet_name="zero_depth_wo", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )

    if addr_fmt == 'p2wsh':
        tmplt = "wsh(%s)"
        af = "bech32"
    elif addr_fmt == "p2sh-p2wsh":
        tmplt = "sh(wsh(%s))"
        af = "p2sh-segwit"
    else:
        assert addr_fmt == "p2sh"
        tmplt = "sh(%s)"
        af = "legacy"

    inner = "%s(2,%s)" % (desc_type, ",".join([core_key, my_data]))
    desc = tmplt % inner
    desc_info = wo.getdescriptorinfo(desc)
    desc_w_checksum = desc_info["descriptor"]  # with checksum


    title, story = offer_minsc_import(json.dumps({"desc": desc_w_checksum, "name": ms_name}))
    assert "Create new miniscript wallet?" in story
    press_select()

    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item(ms_name)
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # import descriptors to watch only wallet
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"], obj

    goto_address_explorer()
    pick_menu_item(ms_name)
    time.sleep(.1)
    _, story = cap_story()
    ea = [i.replace("\x02", "") for i in story.split("\n") if i and i.startswith("\x02")]
    need_keypress("0") # change
    time.sleep(.1)
    _, story = cap_story()
    ia = [i.replace("\x02", "") for i in story.split("\n") if i and i.startswith("\x02")]

    # check both external and internal
    eabc, iabc = wo.deriveaddresses(core_desc_object[0]["desc"], [0, 9])
    for i in range(10):
        assert eabc[i] == ea[i]
        assert iabc[i] == ia[i]

    multi_addr = wo.getnewaddress("", af)
    dest_addr = bitcoind.supply_wallet.getnewaddress("")
    bitcoind.supply_wallet.sendtoaddress(multi_addr, 2)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress(""))
    # create funded PSBT
    psbt_resp = wo.walletcreatefundedpsbt([], [{dest_addr: 1.2}], 0,
                                          {"fee_rate": 2, "change_type": af})
    psbt = psbt_resp.get("psbt")

    _, updated = try_sign(base64.b64decode(psbt), finalize=False)
    signed = cosig.walletprocesspsbt(b64encode(updated).decode('ascii'), True, "ALL")["psbt"]

    # finalize and send
    rr = bitcoind.supply_wallet.finalizepsbt(signed, True)
    assert rr['complete']
    tx_hex = rr["hex"]
    res = bitcoind.supply_wallet.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(rr['hex'])
    assert len(txn_id) == 64


@pytest.mark.bitcoind
def test_bad_common_prefix(use_regtest, clear_miniscript, import_ms_wallet,
                           test_ms_show_addr):
    # assuming MAX_PATH_DEPTH==12
    cpp = "m/1/2/3/4/5/6/7/8/9/10/11/12/13"
    clear_miniscript()
    M, N = 1, 15
    with pytest.raises(BaseException) as ee:
        keys = import_ms_wallet(M, N, accept=True, common=cpp)
    assert 'origin too deep' in str(ee)


@pytest.mark.parametrize("desc", ["multi", "sortedmulti"])
def test_import_detail(desc, clear_miniscript, import_ms_wallet, need_keypress,
                       cap_story, is_q1, press_cancel):
    # check all details are shown right

    M,N = 14, 15
    descriptor, bip67 = (True, False) if desc == "multi" else (False, True)
    keys = import_ms_wallet(M, N, bip67=bip67)

    time.sleep(.2)
    title, story = cap_story()
    assert f'{M} of {N}' in story

    # TODO emitting no warning here
    if desc == "multi":
        assert "WARNING" in story
        assert "BIP-67 disabled" in story
    else:
        assert "WARNING" not in story
        assert "BIP-67 disabled" not in story

    assert f'{M} of {N}' in story

    need_keypress('1')
    time.sleep(.1)
    title, story = cap_story()

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
    pick_menu_item('Miniscript')
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

    rv = load_export(way, is_json=True, label="Multisig XPUB", fpattern="ccxp-")

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
        assert rv["p2sh_key_exp"] == f"[{rv['xfp']}/45h]{n.hwif()}"

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
        assert rv[name+"_key_exp"] == f"[{rv['xfp']}/{deriv.replace('m/', '')}]{n.hwif()}"


@pytest.mark.parametrize('N', [ 3, 15])
@pytest.mark.parametrize('vdisk', [True, False])
def test_import_ux(N, vdisk, goto_home, cap_story, pick_menu_item,
                   need_keypress, microsd_path, get_cc_key,
                   virtdisk_path, is_q1, press_cancel, press_select):
    # test menu-based UX for importing wallet file from SD
    M = N-1

    keys = [BIP32Node.from_master_secret(os.urandom(32)).hwif() for _ in range(M)]
    keys.append(get_cc_key("", ""))
    name = 'named-%d' % random.randint(10000,99999)
    config = {"name": name, "desc": f"wsh(sortedmulti({M},{','.join(keys)}))"}

    if vdisk:
        fname = virtdisk_path(f'ms-{name}.txt')
    else:
        fname = microsd_path(f'ms-{name}.txt')

    with open(fname, 'wt') as fp:
        fp.write(json.dumps(config))

    try:
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        pick_menu_item('Import')
        time.sleep(0.1)
        _, story = cap_story()
        if vdisk:
            if "(2) to import from Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress("2")
        else:
            if "(1) to import miniscript wallet file from SD Card" in story:
                need_keypress("1")

        time.sleep(.1)
        pick_menu_item(fname.rsplit('/', 1)[1])

        time.sleep(.1)
        _, story = cap_story()

        assert 'Create new miniscript' in story
        assert name in story, 'didnt infer wallet name from filename'
        assert f'Policy: {M} of {N}\n' in story

        # abort install
        press_cancel()

    finally:
        # cleanup
        try: os.unlink(fname)
        except: pass


@pytest.mark.parametrize('N', [ 3, 15])
def test_overflow(N, import_ms_wallet, clear_miniscript, press_select, cap_story, mk_num, is_q1):

    clear_miniscript()
    M = N
    name = 'a'*19       # longest possible
    for count in range(1, 10):
        keys = import_ms_wallet(M, N, name=f"{name}{count}", addr_fmt='p2wsh', unique=count,
                                accept=True, common="m/45h/0h/34h")

        time.sleep(.2)
        title, story = cap_story()
        if title or story:
            print(f'Failed with {count} @ {N} keys each')
            assert mk_num < 4
            assert 'No space left' in story
            break

    assert count == 9           # unlimited now

    press_select()
    clear_miniscript()


@pytest.mark.parametrize('N', [ 5, 10])
def test_import_dup_safe(N, clear_miniscript, make_multisig, offer_minsc_import,
                         need_keypress, cap_story, goto_home, pick_menu_item,
                         cap_menu, is_q1, press_select, OK, settings_get, enter_text):
    # import wallet, rename it, (check that indicated, works), attempt same w/ addr fmt different

    M = N

    clear_miniscript()

    keys = make_multisig(M, N)

    # render as a file for import
    def make_named(name, af='sh', m=M):
        k = ','.join('[%s/45h]%s' % (xfp2str(xfp), sk.hwif()) for xfp, m, sk in keys)
        desc_obj = {"name": name, "desc": f"{af}(sortedmulti({m},{k}))"}
        return json.dumps(desc_obj)

    def has_name(name, num_wallets=1):
        # check worked: look in menu for name
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')

        menu = cap_menu()
        assert name in menu
        assert len(settings_get("miniscript")) == num_wallets

    orig_name = "xxx-orig"
    title, story = offer_minsc_import(make_named(orig_name))
    assert 'Create new miniscript wallet' in story
    assert orig_name in story
    assert 'P2SH' in story
    press_select()
    has_name(orig_name)

    new_name = "xxx-new"
    title, story = offer_minsc_import(make_named(new_name))
    assert 'Duplicate wallet' in story
    assert f"'{orig_name}' is the same"
    assert new_name in story
    try:
        has_name(new_name)
        raise ValueError
    except AssertionError: pass
    has_name(orig_name, 1)

    # just simple rename
    pick_menu_item(orig_name)
    pick_menu_item('Rename')
    for i in range(len(orig_name)):
        need_keypress(KEY_DELETE if is_q1 else "x")


    enter_text(new_name)

    press_select()
    has_name(new_name)

    newer_name = "xxx-newer"
    newer = make_named(newer_name, 'wsh')
    title, story = offer_minsc_import(newer)
    assert newer_name in story
    assert 'P2WSH' in story

    # should be 2 now, slightly different
    press_select()
    has_name(newer_name, 2)

    # repeat last one, should still be two
    for keys in ['yn', 'n']:
        title, story = offer_minsc_import(newer)
        assert 'unique names' in story
        assert f'{OK} to approve' not in story
        assert newer_name in story

        for key in keys:
            need_keypress(key)

        has_name(newer_name, 2)

    clear_miniscript()


@pytest.mark.bitcoind
@pytest.mark.parametrize('m_of_n', [(2,2), (2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', ['p2sh-p2wsh', 'p2sh', 'p2wsh' ])
def test_import_dup_xfp_fails(m_of_n, use_regtest, addr_fmt, clear_miniscript,
                              make_multisig, import_ms_wallet, test_ms_show_addr):

    M, N = m_of_n

    keys = make_multisig(M, N)

    pk = BIP32Node.from_master_secret(b'example', 'XTN')
    sub = pk.subkey_for_path("m/45h")
    sub.node.parent = None
    sub.node.parsed_parent_fingerprint = keys[-1][2].parent_fingerprint()
    keys[-1] = (simulator_fixed_xfp, pk, sub)

    with pytest.raises(Exception) as ee:
        import_ms_wallet(M, N, addr_fmt, accept=True, keys=keys)

    #assert 'XFP' in str(ee)
    assert 'wrong pubkey' in str(ee)


@pytest.fixture
def make_myself_wallet(dev, set_bip39_pw, offer_minsc_import, press_select, clear_miniscript,
                       reset_seed_words, is_q1):

    # construct a wallet (M of 4) using different bip39 passwords, and default sim
    def doit(M, addr_fmt="p2wsh", do_import=True, desc="sortedmulti"):

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
            msc = {"name": f"Myself-{M}"}
            kk = ','.join('[%s/45h]%s' % (xfp2str(xfp), sk.hwif()) for xfp, _, sk in keys)

            if addr_fmt == "p2wsh":
                d = f"wsh({desc}({M},{kk}))"
            elif addr_fmt == "p2sh-p2wsh":
                d = f"sh(wsh({desc}({M},{kk})))"
            elif addr_fmt == "p2sh":
                d = f"sh({desc}({M},{kk}))"
            else:
                raise ValueError("Unknown address format: " + addr_fmt)

            msc["desc"] = d
            config = json.dumps(msc)
            title, story = offer_minsc_import(config)
            assert "Create new miniscript wallet" in story

            # don't care if update or create; accept it.
            time.sleep(.1)
            press_select()

        def select_wallet(idx):
            # select to specific pw
            print(f"--- switch to another leg of MS: {idx} ---")
            xfp = set_bip39_pw(passwords[idx])
            if do_import:
                offer_minsc_import(config)
                time.sleep(.1)
                press_select()
            assert xfp == keys[idx][0]
            return xfp

        return (keys, select_wallet)

    yield doit

    reset_seed_words()


@pytest.fixture
def fake_ms_txn(pytestconfig):
    # make various size MULTISIG txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    from struct import pack

    def doit(num_ins, num_outs, M, keys, fee=10000, outvals=None, inp_addr_fmt="p2wsh",
             outstyles=['p2pkh'], change_outputs=[], incl_xpubs=False, hack_psbt=None,
             hack_change_out=False, input_amount=1E8, psbt_v2=None, bip67=True,
             violate_script_key_order=False, path_mapper=None, netcode="XTN"):

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

        if netcode == "XTN":
            net = 1
        elif netcode == "XRT":
            net = 2
        else:
            net = 0

        af = unmap_addr_fmt[inp_addr_fmt]
        for i in range(num_ins):
            # make a fake txn to supply each of the inputs
            # - each input is 1BTC
            # addr where the fake money will be stored.
            addr, scriptPubKey, script, details = make_ms_address(
                M, keys, idx=i, bip67=bip67,
                violate_script_key_order=violate_script_key_order,
                path_mapper=path_mapper, addr_fmt=af, testnet=net
            )
            # lots of supporting details needed for p2sh inputs
            if inp_addr_fmt in ["p2wsh", "p2sh-p2wsh", "p2wsh-p2sh"]:
                segwit_in = True
                psbt.inputs[i].witness_script = script
                if "p2sh" in inp_addr_fmt:
                    psbt.inputs[i].redeem_script = b'\x00\x20' + sha256(script).digest()
            else:
                # p2sh
                segwit_in = False
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
@pytest.mark.parametrize('addr_fmt', ["p2wsh", "p2sh-p2wsh", "p2sh"])
@pytest.mark.parametrize('num_ins', [2, 15])
@pytest.mark.parametrize('incl_xpubs', [True, False, None])
@pytest.mark.parametrize('transport', ['usb', 'sd'])
@pytest.mark.parametrize('has_change', [True, False])
@pytest.mark.parametrize('M_N', [(2, 3), (5, 15)])
@pytest.mark.parametrize('desc', ["sortedmulti", "multi"])
def test_ms_sign_simple(M_N, num_ins, dev, addr_fmt, clear_miniscript, import_ms_wallet,
                        addr_vs_path, fake_ms_txn, try_sign, try_sign_microsd, transport,
                        has_change, settings_set, desc, sim_root_dir, incl_xpubs):
    M, N = M_N
    num_outs = num_ins-1
    bip67 = False if desc == "multi" else True

    # TODO
    # # trust PSBT if we're doing "no-import" case
    settings_set('pms', 2 if (incl_xpubs == 'no-import') else 0)

    clear_miniscript()

    if incl_xpubs:
        # test enrolling xpubs form PSBT
        do_import = False
        if not bip67:
            raise pytest.skip("cannot import unsorted multisig from PSBT")
    elif incl_xpubs is None:
        # test verification of PSBT xpubs against our enrolled wallet
        do_import = True
        incl_xpubs = True
    else:
        do_import = True

    keys = import_ms_wallet(M, N, name='ms-sign-simple', accept=True, addr_fmt=addr_fmt,
                            do_import=do_import, bip67=bip67)

    if do_import is False:
        keys = keys[0]

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, inp_addr_fmt=addr_fmt, incl_xpubs=incl_xpubs,
                       outstyles=[addr_fmt], change_outputs=[1] if has_change else [],
                       bip67=bip67, netcode="XRT")

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    if transport == 'sd':
        try_sign_microsd(psbt, encoding=('binary', 'hex', 'base64')[random.randint(0,2)])
    else:
        try_sign(psbt)

@pytest.mark.unfinalized
@pytest.mark.bitcoind
@pytest.mark.parametrize('num_ins', [ 15 ])
@pytest.mark.parametrize('M', [ 2, 4])
@pytest.mark.parametrize('inp_af', ["p2wsh", "p2sh-p2wsh", "p2sh"])
@pytest.mark.parametrize('incl_xpubs', [ True, False ])
def test_ms_sign_myself(M, use_regtest, make_myself_wallet, inp_af, num_ins, dev, incl_xpubs,
                        clear_miniscript, fake_ms_txn, try_sign, bitcoind, sim_root_dir):

    # IMPORTANT: won't work if you start simulator with --ms flag. Use no args

    all_out_styles = [af for af in unmap_addr_fmt.keys() if af != "p2tr"]
    num_outs = len(all_out_styles)

    clear_miniscript()
    use_regtest()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, addr_fmt=inp_af, do_import=(not incl_xpubs))
    N = len(keys)
    assert M<=N

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, inp_addr_fmt=inp_af, incl_xpubs=incl_xpubs,
                       outstyles=[inp_af], change_outputs=list(range(1,num_outs)))

    with open(f'{sim_root_dir}/debug/myself-before.psbt', 'w') as f:
        f.write(b64encode(psbt).decode())
    for idx in range(M):
        select_wallet(idx)
        _, updated = try_sign(psbt, accept_ms_import=incl_xpubs)
        with open(f'{sim_root_dir}/debug/myself-after.psbt', 'w') as f:
            f.write(b64encode(updated).decode())
        assert updated != psbt

        aft = BasicPSBT().parse(updated)
        # check all inputs gained a signature
        assert all(len(i.part_sigs)==(idx+1) for i in aft.inputs)

        psbt = aft.as_bytes()

    # should be fully signed now.
    anal = bitcoind.rpc.analyzepsbt(b64encode(psbt).decode('ascii'))
    assert not any(inp.get('missing') for inp in anal['inputs']), "missing sigs: %r" % anal
    assert all(inp['next'] in {'finalizer','updater'} for inp in anal['inputs']), "other issue: %r" % anal


@pytest.mark.parametrize('addr_fmt', ['p2wsh', 'p2sh-p2wsh'])
@pytest.mark.parametrize('acct_num', [None, 4321])
@pytest.mark.parametrize('M_N', [(2,3), (8,14)])
@pytest.mark.parametrize('way', ["sd", "qr"])
@pytest.mark.parametrize('incl_self', [True, False, None])
def test_make_airgapped(addr_fmt, acct_num, M_N, goto_home, cap_story, pick_menu_item,
                        need_keypress, microsd_path, set_bip39_pw, clear_miniscript, enter_number,
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
    clear_miniscript()

    for idx in range(N - int(incl_self is None)):
        if not idx and (incl_self is True):
            set_bip39_pw('')
        else:
            set_bip39_pw(f'test {idx}')

        goto_home()
        time.sleep(0.1)
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
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
    pick_menu_item('Miniscript')
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

        press_select()  # quit QR animation

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
        assert "Create new miniscript" in story
        press_select()
        # we use clear_miniscript fixture at the begining of each test
        # new multisig wallet is first menu item
        press_select()
        pick_menu_item("Descriptors")
        pick_menu_item("Export")
        impf, fname = load_export("sd", label="Miniscript", is_json=False,
                                  ret_fname=True)
        cc_fname = microsd_path(fname)
        strt = "wsh(sortedmulti" if addr_fmt == 'p2wsh' else "sh(wsh(sortedmulti("
        strt += str(M)

        press_select()
        press_select()

        clear_miniscript()

        # test re-importing the wallet from export file
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        pick_menu_item('Import')
        time.sleep(0.5)
        _, story = cap_story()
        if "Press (1) to import miniscript" in story:
            need_keypress("1")

        time.sleep(.05)
        pick_menu_item(cc_fname.rsplit('/', 1)[1])

        time.sleep(.05)
        title, story = cap_story()
        assert "Create new miniscript" in story
        assert f"Policy: {M} of {N}" in story

        need_keypress('1')
        time.sleep(.1)
        title, story = cap_story()
        target = story

    else:
        # own wallet not included in the mix, can only export resulting descriptor
        desc = load_export(way, label="Miniscript", is_json=False, sig_check=False)
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


@pytest.mark.parametrize('addr_fmt', [AF_P2WSH] )
@pytest.mark.parametrize('num_ins', [ 3])
@pytest.mark.parametrize('out_style', ['p2wsh'])
@pytest.mark.parametrize('bitrot', list(range(0,6)) + [98, 99, 100] + list(range(-5, 0)))
@pytest.mark.ms_danger
def test_ms_sign_bitrot(num_ins, dev, addr_fmt, clear_miniscript, import_ms_wallet,
                        addr_vs_path, fake_ms_txn, start_sign, end_sign, out_style, cap_story,
                        bitrot, sim_root_dir):
    M = 1
    N = 3
    num_outs = 2

    clear_miniscript()
    keys = import_ms_wallet(M, N, accept=True, addr_fmt=out_style)

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
    psbt = fake_ms_txn(
        num_ins, num_outs, M, keys, outstyles=[out_style], change_outputs=[0],
        hack_change_out=lambda idx: dict(finalizer_hack=lambda scr: rotten(track, bitrot, scr))
    )

    assert len(track) == 1

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    start_sign(psbt)
    with pytest.raises(Exception) as ee:
        end_sign(accept=None)
    assert 'Output#0:' in str(ee)
    assert 'Change output script' in str(ee)

    # Check error details are shown
    time.sleep(.01)
    title, story = cap_story()
    assert 'Output#0:' in story
    assert 'Change output script' in story

@pytest.mark.parametrize('addr_fmt', ["p2wsh", "p2sh-p2wsh", "p2sh"] )
@pytest.mark.parametrize('pk_num', range(4))
@pytest.mark.parametrize('case', ['pubkey', 'path'])
def test_ms_change_fraud(case, pk_num, dev, addr_fmt, clear_miniscript, make_multisig,
                         addr_vs_path, fake_ms_txn, start_sign, end_sign, cap_story,
                         sim_root_dir):
    
    M = 1
    N = 3
    num_ins = 1
    num_outs = 2

    clear_miniscript()
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
                outstyles=[addr_fmt, "p2wpkh"], change_outputs=[0],
                hack_change_out=lambda idx: dict(tweak_pubkeys=
                        lambda data: tweak(case, pk_num, data)))

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    with pytest.raises(Exception) as ee:
        start_sign(psbt)
        end_sign(accept=True, accept_ms_import=False)
    assert 'Output#0:' in str(ee)
    assert 'Change output script' in str(ee)
    #assert 'Deception regarding change output' in str(ee)

    # Check error details are shown
    time.sleep(.5)
    title, story = cap_story()
    assert 'Output#0:' in story
    assert 'Change output script' in story


@pytest.mark.ms_danger
def test_danger_warning(request, clear_miniscript, import_ms_wallet, cap_story, fake_ms_txn,
                        start_sign, sim_exec, sim_root_dir, goto_home, pick_menu_item,
                        need_keypress):
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item("Skip Checks?")
    need_keypress("4")
    pick_menu_item("Skip Checks")

    time.sleep(.1)

    clear_miniscript()
    M,N = 2,3
    keys = import_ms_wallet(M, N, accept=True, addr_fmt="p2wsh")
    psbt = fake_ms_txn(1, 1, M, keys, inp_addr_fmt="p2wsh", incl_xpubs=True)

    with open(f'{sim_root_dir}/debug/last.psbt', 'wb') as f:
        f.write(psbt)

    start_sign(psbt)
    title, story = cap_story()

    assert 'WARNING' in story
    assert 'Danger' in story
    assert 'Some miniscript checks are disabled' in story

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item("Skip Checks?")
    pick_menu_item("Normal")

    start_sign(psbt)
    title, story = cap_story()

    assert 'WARNING' not in story

@pytest.mark.parametrize('change', [True, False])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize('start_idx', [1000, MAX_BIP32_IDX, 0])
@pytest.mark.parametrize('M_N', [(2,3), (15,15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH] )
def test_ms_addr_explorer(change, M_N, addr_fmt, start_idx, clear_miniscript, cap_menu,
                          need_keypress, goto_home, pick_menu_item, cap_story,
                          import_ms_wallet, make_multisig, settings_set,
                          enter_number, set_addr_exp_start_idx, desc,
                          cap_screen_qr, press_cancel, press_right):
    clear_miniscript()
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

    bip67 = True
    if desc == "multi":
        bip67 = False
    keys = import_ms_wallet(M, N, accept=True, keys=keys, name=wal_name,
                            derivs=derivs, addr_fmt=text_a_fmt, bip67=bip67)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')      # warning

    set_addr_exp_start_idx(start_idx)

    pick_menu_item(wal_name)

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
        story = story.replace("=>\n", "=> ").replace('1/0]\n =>', "1/0] =>")
    else:
        story = story.replace("=>\n", "=> ").replace('0/0]\n =>', "0/0] =>")

    maps = []
    for ln in story.split('\n'):
        if '=>' not in ln: continue

        path,chk,addr = ln.split(" ", 2)
        assert chk == '=>'
        assert '/' in path
        path = path.replace("[", "").replace("]", "")

        maps.append((path, addr))

    if start_idx <= 2147483638:
        assert len(maps) == 10
    else:
        assert len(maps) == (MAX_BIP32_IDX - start_idx) + 1

    need_keypress(KEY_QR)
    qr_addrs = []
    for i in range(10):
        addr_qr = cap_screen_qr().decode()
        if addr_fmt == AF_P2WSH:
            # segwit addresses are case insensitive
            addr_qr = addr_qr.lower()
        qr_addrs.append(addr_qr)
        press_right()
        time.sleep(.2)
    press_cancel()

    c = 0
    for idx, (subpath, addr) in enumerate(maps, start=start_idx):
        chng_idx = 1 if change else 0
        path_mapper = lambda co_idx: str_to_path(derivs[co_idx]) + [chng_idx, idx]
        
        expect, pubkey, script, _ = make_ms_address(M, keys, idx=idx, addr_fmt=addr_fmt,
                                                    path_mapper=path_mapper, bip67=bip67)

        assert int(subpath.split('/')[-1]) == idx
        # assert int(subpath.split('/')[-2]) == chng_idx
        #print('../0/%s => \n %s' % (idx, B2A(script)))

        addr = addr_from_display_format(addr)
        assert addr == expect == qr_addrs[c]
        c += 1


def test_dup_ms_wallet_bug(goto_home, pick_menu_item, press_select, import_ms_wallet,
                           clear_miniscript, is_q1):
    M = 2
    N = 3

    deriv = ["m/48h/1h/0h/69h/1"]*N
    fmts = [ 'p2wsh', 'p2sh-p2wsh']

    clear_miniscript()

    for n, ty in enumerate(fmts):
        import_ms_wallet(M, N, name=f'name-{n}', accept=True, derivs=deriv, addr_fmt=ty)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')

    # drill down to second one
    time.sleep(.1)
    pick_menu_item('name-1')
    pick_menu_item('Delete')
    press_select()

    # BUG: pre v4.0.3, would be showing a "Yikes" referencing multisig:419 at this point

    pick_menu_item('name-0')
    pick_menu_item('Delete')
    press_select()

    clear_miniscript()

@pytest.mark.parametrize('M_N', [(2, 3), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', ["p2wsh", "p2sh-p2wsh", "p2sh"])
@pytest.mark.parametrize('int_ext_desc', [True, False])
@pytest.mark.parametrize('json_wrapped', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_import_descriptor(M_N, addr_fmt, int_ext_desc, way, import_ms_wallet, goto_home, pick_menu_item,
                           press_select, clear_miniscript, cap_story, microsd_path, virtdisk_path,
                           nfc_read_text, load_export, is_q1, desc, sim_root_dir, skip_if_useless_way,
                           json_wrapped):
    skip_if_useless_way(way)
    M, N = M_N

    if (way == "nfc") and (M == N == 15):
        raise pytest.skip("too big for simulated NFC")

    clear_miniscript()
    goto_home()

    name = None
    if json_wrapped:
        # descriptor wrapped in JSON with name key
        name = "aaa"

    import_ms_wallet(
        M, N, addr_fmt=addr_fmt, accept=True, way=way, name=name,
        int_ext_desc=int_ext_desc, bip67=False if desc == "multi" else True,
    )
    with open(f'{sim_root_dir}/debug/last-ms.txt', 'r') as f:
        desc_import = f.read().strip()

    if json_wrapped:
        desc_obj = json.loads(desc_import)
        desc_import = desc_obj["desc"]
        pick_menu_item(name)
    else:
        press_select()  # only one enrolled multisig - choose it

    pick_menu_item('Descriptors')
    pick_menu_item('Export')
    contents = load_export(way, label="Miniscript", is_json=False)
    desc_export = contents.strip()

    normalized = parse_desc_str(desc_export)
    # needs bitcoin core client at least on 29.0
    if int_ext_desc:
        assert desc_import == normalized
    else:
        # we always export with multipath
        assert normalized.split("#")[0] == desc_import.split("#")[0].replace("/0/*", "/<0;1>/*")
    starts_with = MULTI_FMT_TO_SCRIPT[addr_fmt].split("%")[0]
    assert normalized.startswith(starts_with)
    assert f"{desc}(" in desc_export


@pytest.mark.bitcoind
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize("start_idx", [2147483540, MAX_BIP32_IDX, 0])
@pytest.mark.parametrize('M_N', [(2, 2), (3, 5), (15, 15)])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
@pytest.mark.parametrize('way', ["sd", "nfc"])  # vdisk
def test_bitcoind_ms_address(change, M_N, addr_fmt, clear_miniscript, goto_home, need_keypress,
                             pick_menu_item, cap_menu, cap_story, make_multisig, import_ms_wallet,
                             microsd_path, bitcoind_d_wallet_w_sk, use_regtest, load_export, way,
                             is_q1, press_select, start_idx, settings_set, set_addr_exp_start_idx,
                             desc, garbage_collector, virtdisk_path, skip_if_useless_way):
    skip_if_useless_way(way)
    use_regtest()
    clear_miniscript()
    bitcoind = bitcoind_d_wallet_w_sk
    M, N = M_N
    path_f = microsd_path if way == "sd" else virtdisk_path

    bip67 = True
    if desc == "multi":
        bip67 = False

    settings_set("aei", True if start_idx else False)
    # adding this as parameter doubles the time this runs

    wal_name = f"ax{M}-{N}-{addr_fmt}"

    dd = {
        AF_P2WSH: ("m/48h/1h/0h/2h/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45h/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48h/1h/0h/1h/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]

    keys = make_multisig(M, N, unique=1, deriv=deriv)

    derivs = [deriv.format(idx=i) for i in range(N)]

    clear_miniscript()
    import_ms_wallet(M, N, accept=True, keys=keys, name=wal_name, derivs=derivs,
                     addr_fmt=text_a_fmt, bip67=bip67)

    goto_home()
    pick_menu_item("Address Explorer")
    need_keypress('4')  # warning
    set_addr_exp_start_idx(start_idx)

    m = cap_menu()
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

    if way != "nfc":
        contents, exp_fname = load_export(way, label="Address summary",
                                          is_json=False, ret_fname=True)
        garbage_collector.append(path_f(exp_fname))
    else:
        contents = load_export(way, label="Address summary", is_json=False)
    addr_cont = contents.strip()
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    press_select()  # only one enrolled multisig - choose it
    pick_menu_item('Descriptors')
    pick_menu_item("Bitcoin Core")
    if way != "nfc":
        contents, exp_fname = load_export(way, label="Bitcoin Core miniscript", is_json=False,
                                          ret_fname=True)
        garbage_collector.append(path_f(exp_fname))
    else:
        contents = load_export(way, label="Bitcoin Core miniscript", is_json=False)
    text = contents.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    desc_core = core_desc_object[0]["desc"]

    assert f"({desc}(" in desc_core

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

    ea, ia = bitcoind.deriveaddresses(desc_core, addr_range)
    bitcoind_addrs = ia if change else ea
    for idx, cc_item in enumerate(cc_addrs):
        cc_item = cc_item.split(",")
        address = cc_item[part_addr_index]
        if way != "nfc":
            address = address[1:-1]
        assert bitcoind_addrs[idx] == address


@pytest.mark.bitcoind
def test_legacy_multisig_witness_utxo_in_psbt(bitcoind, use_regtest, clear_miniscript, microsd_wipe, goto_home, need_keypress,
                                              pick_menu_item, cap_story, load_export, microsd_path, cap_menu, try_sign,
                                              is_q1, press_select):
    use_regtest()
    clear_miniscript()
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
    pick_menu_item('Miniscript')
    pick_menu_item('Export XPUB')
    time.sleep(0.5)
    title, story = cap_story()
    assert "extended public keys (XPUB) you would need to join a multisig wallet" in story
    press_select()
    need_keypress("0")  # account
    press_select()
    xpub_obj = load_export("sd", label="Multisig XPUB", is_json=True)
    cc_key = xpub_obj["p2sh_key_exp"]
    # get key from bitcoind cosigner
    target_desc = ""
    bitcoind_descriptors = cosigner.listdescriptors()["descriptors"]
    for desc in bitcoind_descriptors:
        if desc["desc"].startswith("pkh(") and desc["internal"] is False:
            target_desc = desc["desc"]
    core_desc, checksum = target_desc.split("#")
    # remove pkh(....)
    core_key = core_desc[4:-1]
    desc = f"sh(sortedmulti({M},{core_key},{cc_key}))"
    desc_info = ms.getdescriptorinfo(desc)
    desc_w_checksum = desc_info["descriptor"]  # with checksum
    name = f"core{M}of{N}_legacy.txt"
    with open(microsd_path(name), "w") as f:
        f.write(desc_w_checksum + "\n")
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    pick_menu_item('Import')
    time.sleep(0.3)
    _, story = cap_story()
    if "Press (1) to import miniscript" in story:
        # in case Vdisk is enabled
        need_keypress("1")

    time.sleep(0.5)
    pick_menu_item(name)
    _, story = cap_story()
    assert "Create new miniscript wallet?" in story
    assert name.split(".")[0] in story
    assert f"{M} of {N}" in story
    assert "P2SH" in story
    press_select()  # approve multisig import
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    menu = cap_menu()
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False)
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


@pytest.fixture
def get_cc_key(dev):
    def doit(path, subderiv=None):
        # cc device key
        cc_key = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        if subderiv is None:
            cc_key = cc_key + "/<0;1>/*"

        if not path:
            return cc_key

        master_xfp_str = struct.pack('<I', dev.master_fingerprint).hex()
        return f"[{master_xfp_str}/{path}]{cc_key}"
    return doit

@pytest.fixture
def bitcoind_multisig(bitcoind, bitcoind_d_sim_watch, need_keypress, cap_story, load_export,
                      pick_menu_item, goto_home, cap_menu, microsd_path, settings_get,
                      press_select, get_cc_key, import_miniscript):

    def doit(M, N, script_type, cc_account=0, funded=True, ms_script="sortedmulti", name=None,
             way="sd", keypool_size=10):
        # remove all previous wallet from datadir
        assert settings_get("chain", None) == "XRT"
        bitcoind.delete_wallet_files(pattern="bitcoind--signer")
        bitcoind.delete_wallet_files(pattern="bitcoind_ms_wo_")

        bitcoind_signers = [
            bitcoind.create_wallet(wallet_name=f"bitcoind--signer{i}", disable_private_keys=False, blank=False,
                                   passphrase=None, avoid_reuse=False, descriptors=True)
            for i in range(N - 1)
        ]
        for signer in bitcoind_signers:
            signer.keypoolrefill(keypool_size)
        # watch only wallet where multisig descriptor will be imported
        ms = bitcoind.create_wallet(
            wallet_name=f"bitcoind_ms_wo_{script_type}_{M}of{N}", disable_private_keys=True,
            blank=True, passphrase=None, avoid_reuse=False, descriptors=True
        )

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

        cc_key = get_cc_key(f"100h/0h/{cc_account}h", subderiv="/0/*")  # subderiv compat
        all_signers = bitcoind_signers_xpubs + [cc_key]

        if script_type == 'p2wsh':
            tmplt = "wsh(%s)"
        elif script_type == "p2sh-p2wsh":
            tmplt = "sh(wsh(%s))"
        else:
            assert script_type == "p2sh"
            tmplt = "sh(%s)"

        inner = f"{ms_script}({M},{','.join(all_signers)})"
        desc = tmplt % inner

        if name:
            res = json.dumps({"desc": desc, "name": name})
        else:
            res = desc

        title, story = import_miniscript(way=way, data=res)

        assert "Create new miniscript wallet?" in story
        assert f"{M} of {N}" in story
        # TODO this UX lost
        # if M == N:
        #     assert f"All {N} co-signers must approve spends" in story
        # else:
        #     assert f"{M} signatures, from {N} possible" in story
        if script_type == "p2wsh":
            assert "P2WSH" in story
        elif script_type == "p2sh":
            assert "P2SH" in story
        else:
            assert script_type == "p2sh-p2wsh"
            assert "P2SH-P2WSH" in story
        # assert "Derivation:\n  Varies (2)" in story
        press_select()  # approve multisig import
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        menu = cap_menu()
        pick_menu_item(menu[0])  # pick imported descriptor multisig wallet
        pick_menu_item("Descriptors")
        pick_menu_item("Bitcoin Core")
        text = load_export("sd", label="Bitcoin Core miniscript", is_json=False)
        text = text.replace("importdescriptors ", "").strip()
        # remove junk
        r1 = text.find("[")
        r2 = text.find("]", -1, 0)
        text = text[r1: r2]
        core_desc_object = json.loads(text)
        # import descriptors to watch only wallet
        res = ms.importdescriptors(core_desc_object)
        assert res[0]["success"]

        if funded:
            addr = ms.getnewaddress("", bitcoind_addr_fmt(script_type))
            if script_type == "p2wsh":
                sw = "bcrt1q"
            else:
                sw = "2"
            assert addr.startswith(sw)
            # get some coins and fund above multisig address
            bitcoind.supply_wallet.sendtoaddress(addr, 49)
            bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine above
            ms.keypoolrefill(keypool_size)

        return ms, bitcoind_signers

    return doit

@pytest.mark.bitcoind
@pytest.mark.parametrize("m_n", [(2, 2), (2, 3), (3, 5), (6, 6), (5, 8), (10, 15)])
@pytest.mark.parametrize("script", ["p2wsh", "p2sh-p2wsh", "p2sh"])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_finalization(m_n, script, desc, use_regtest, clear_miniscript, bitcoind_multisig, bitcoind,
                      try_sign, cap_story, settings_set, txid_from_export_prompt, press_cancel):

    M, N = m_n
    use_regtest()
    clear_miniscript()
    addr_type = bitcoind_addr_fmt(script)

    wo, bitcoind_signers = bitcoind_multisig(M, N, script, ms_script=desc,
                                             keypool_size=30, way="usb")
    # 3 outputs going out
    destinations = [{bitcoind.supply_wallet.getnewaddress("", "bech32"): 5.0} for _ in range(3)]
    # 3 going back (below 2 + rest cc 24btc)
    destinations.append({wo.getnewaddress("", addr_type): 5.0})
    destinations.append({wo.getnewaddress("", addr_type): 5.0})

    psbt = wo.walletcreatefundedpsbt(
        [], destinations, 0, {"fee_rate": 2, "change_type": addr_type}
    )["psbt"]

    # sign with M - 1 bitcoind signers so COLDCARD can just sign+finalize
    for signer in bitcoind_signers[:M-1]:
        half_signed_psbt = signer.walletprocesspsbt(psbt, True, "ALL", True)  # do not finalize
        psbt = half_signed_psbt["psbt"]

    psbt_bytes = base64.b64decode(psbt)
    # USB sign with COLDCARD & finalize
    _, txn = try_sign(psbt_bytes, finalize=True, exit_export_loop=False)
    tx_hex = txn.hex()
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    cc_tx_id = txid_from_export_prompt()
    press_cancel()  # exit QR display
    press_cancel()  # exit export loop
    assert res == cc_tx_id

    wo.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    assert len(wo.listunspent()) == 3

    # consolidate
    psbt = wo.walletcreatefundedpsbt(
        [], [{wo.getnewaddress("", addr_type): wo.getbalance()}], 0,
        {"fee_rate": 4, "subtractFeeFromOutputs": [0], "change_type": addr_type}
    )["psbt"]

    for signer in bitcoind_signers[:M-1]:
        half_signed_psbt = signer.walletprocesspsbt(psbt, True, "ALL", True)  # do not finalize
        psbt = half_signed_psbt["psbt"]

    psbt_bytes = base64.b64decode(psbt)
    # USB sign with COLDCARD & finalize
    _, txn = try_sign(psbt_bytes, finalize=True, exit_export_loop=False)
    tx_hex = txn.hex()
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

    cc_tx_id = txid_from_export_prompt()
    press_cancel()  # exit QR display
    press_cancel()  # exit export loop
    assert res == cc_tx_id

    wo.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    assert len(wo.listunspent()) == 1


@pytest.mark.bitcoind
@pytest.mark.parametrize("m_n", [(2,3), (3,5), (15,15)])
@pytest.mark.parametrize("script", ["p2wsh", "p2sh-p2wsh", "p2sh"])
@pytest.mark.parametrize("sighash", list(SIGHASH_MAP.keys()))
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
def test_bitcoind_MofN_tutorial(m_n, script, clear_miniscript, goto_home, need_keypress, pick_menu_item,
                                sighash, cap_menu, cap_story, microsd_path, use_regtest, bitcoind,
                                microsd_wipe, settings_set, is_q1, try_sign, press_select,
                                finalize_v2_v0_convert, desc, bitcoind_multisig, press_cancel,
                                txid_from_export_prompt, pytestconfig, file_tx_signing_done):
    # 2of2 case here is described in docs with tutorial
    # TODO This test MUST be run with --psbt2 flag on and off

    addr_type = bitcoind_addr_fmt(script)

    M, N = m_n
    settings_set("sighshchk", 1)  # disable checks
    use_regtest()
    clear_miniscript()
    microsd_wipe()

    # actual bitcoind watch-only creation + COLDCARD enroll
    bitcoind_watch_only, bitcoind_signers = bitcoind_multisig(M, N, script, ms_script=desc, keypool_size=30)

    dest_addr = bitcoind_watch_only.getnewaddress("", addr_type)
    # create funded PSBT
    all_of_it = bitcoind_watch_only.getbalance()
    psbt_resp = bitcoind_watch_only.walletcreatefundedpsbt(
        [], [{dest_addr: all_of_it}], 0, {"fee_rate": 20, "subtractFeeFromOutputs": [0],
                                          "change_type": addr_type}
    )
    psbt = psbt_resp.get("psbt")
    x = BasicPSBT().parse(base64.b64decode(psbt))
    # simple 1 in 1 out shady business
    assert len(x.inputs) == 1
    assert len(x.outputs) == 1

    for idx, i in enumerate(x.inputs):
        i.sighash = SIGHASH_MAP[sighash]
    psbt = x.as_b64_str()

    # sign with M - 1 bitcoind signers
    for signer in bitcoind_signers[:M-1]:
        half_signed_psbt = signer.walletprocesspsbt(psbt, True, sighash, True)  # do not finalize
        psbt = half_signed_psbt["psbt"]

    if pytestconfig.getoption('psbt2'):
        # below is noop if psbt is already v2
        po = BasicPSBT().parse(base64.b64decode(psbt))
        po.to_v2()
        psbt = po.as_b64_str()

    name = f"hsc_{M}of{N}_{script}.psbt"
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
    assert "Consolidating" in story
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
    time.sleep(0.1)
    title, story = cap_story()
    assert "Updated PSBT is:" in story
    press_select()
    os.remove(microsd_path(name))

    final_psbt, final_tx, cc_tx_id = file_tx_signing_done(story)

    po = BasicPSBT().parse(base64.b64decode(final_psbt))
    res = finalize_v2_v0_convert(po)

    assert res["complete"]
    tx_hex = res["hex"]
    assert final_tx == tx_hex
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    assert res == cc_tx_id

    bitcoind_watch_only.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # need to mine above tx

    # split UTXO into many for further consolidation
    out_num = 21
    dest_outs = [{bitcoind_watch_only.getnewaddress("", addr_type):1.0} for _ in range(out_num-1)]
    psbt_resp = bitcoind_watch_only.walletcreatefundedpsbt(
        [], dest_outs, 0, {"fee_rate": 7, "change_type": addr_type}
    )
    psbt = psbt_resp.get("psbt")
    # sign with M - 1 bitcoind signers
    for signer in bitcoind_signers[:M-1]:
        half_signed_psbt = signer.walletprocesspsbt(psbt, True, sighash, True)  # do not finalize
        psbt = half_signed_psbt["psbt"]

    if pytestconfig.getoption('psbt2'):
        # below is noop if psbt is already v2
        po = BasicPSBT().parse(base64.b64decode(psbt))
        po.to_v2()
        psbt = po.as_b64_str()

    psbt_bytes = base64.b64decode(psbt)
    # USB sign with COLDCARD & finalize
    _, txn = try_sign(psbt_bytes, finalize=True, exit_export_loop=False)
    tx_hex = txn.hex()
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    cc_tx_id = txid_from_export_prompt()
    press_cancel()  # exit QR display
    press_cancel()  # exit export loop
    assert res == cc_tx_id

    bitcoind_watch_only.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # need to mine above tx

    assert len(bitcoind_watch_only.listunspent()) == 21

    #  try to sign change - do a consolidation transaction which spends all inputs
    consolidate = bitcoind_watch_only.getnewaddress("", addr_type)
    balance = bitcoind_watch_only.getbalance()
    psbt_outs = [{consolidate: balance}]
    res0 = bitcoind_watch_only.walletcreatefundedpsbt([], psbt_outs, 0,
                                                      {"fee_rate": 5, "subtractFeeFromOutputs": [0],
                                                       "change_type": addr_type})
    psbt = res0["psbt"]
    x = BasicPSBT().parse(base64.b64decode(psbt))
    for idx, i in enumerate(x.inputs):
        i.sighash = SIGHASH_MAP[sighash]

    if pytestconfig.getoption('psbt2'):
        x.to_v2()

    psbt = x.as_b64_str()

    name = f"change_{M}of{N}_{script}.psbt"
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

    assert "Updated PSBT is:" in story
    cc_signed_psbt, _txn, _txid = file_tx_signing_done(story)
    assert _txn is None and _txid is None

    press_cancel()  # exit re-export loop

    po = BasicPSBT().parse(base64.b64decode(cc_signed_psbt))
    cc_signed_psbt = finalize_v2_v0_convert(po)["psbt"]

    # CC already signed - now all bitcoin signers
    for signer in bitcoind_signers[:M-1]:
        res1 = signer.walletprocesspsbt(cc_signed_psbt, True, sighash, True)
        psbt = res1["psbt"]
        cc_signed_psbt = psbt

    res = bitcoind_watch_only.finalizepsbt(cc_signed_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = bitcoind_watch_only.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = bitcoind_watch_only.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id
    bitcoind_signers[0].generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mine block
    assert len(bitcoind_watch_only.listunspent()) == 1  # merged all inputs to one


@pytest.mark.parametrize("desc", [
    # lack of checksum is now legal
    # ("Missing descriptor checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))"),
    ("Wrong checksum", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#gs2fqgl7"),
    ("need multipath", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/1/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#sj7lxn0l"),
    ("All keys must be ranged", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/0,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#9h02aqg5"),
    ("need multipath", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#fy9mm8dt"),
    # ("Key origin info is required", "wsh(sortedmulti(2,tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#ypuy22nw"),
    ("wrong pubkey", "wsh(sortedmulti(2,[0f056943]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))#nhjvt4wd"),
    ("deriv len != xpub depth", "wsh(sortedmulti(2,[0f056943/0h]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M))"),
    ("All keys must be ranged", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0))#s487stua"),
    ("Cannot use hardened sub derivation path", "wsh(sortedmulti(2,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0'/*))#3w6hpha3"),
    ("M must be <= N", "wsh(sortedmulti(3,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,[c463f778/44'/0'/0']tpubDD8pw7eZ9bUzYUR1LK5wpkA69iy3BpuLxPzsE6FFNdtTnJDySduc1VJdFEhEJQDKjYktznKdJgHwaQDRfQDQJpceDxH22c1ZKUMjrarVs7M/0/*))#uueddtsy"),
])
def test_exotic_descriptors(desc, clear_miniscript, goto_home, need_keypress, pick_menu_item, cap_menu,
                            cap_story, make_multisig, microsd_path, use_regtest, is_q1,
                            press_select):
    use_regtest()
    clear_miniscript()
    msg, desc = desc
    name = "exotic.txt"
    if os.path.exists(microsd_path(name)):
        os.remove(microsd_path(name))
    with open(microsd_path(name), "w") as f:
        f.write(desc + "\n")
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    pick_menu_item('Import')
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import miniscript wallet file from SD Card" in story:
        need_keypress("1")
        time.sleep(0.1)

    pick_menu_item(name)
    _, story = cap_story()
    assert "Failed to import miniscript" in story
    assert msg in story
    press_select()

def test_ms_wallet_ordering(clear_miniscript, import_ms_wallet, try_sign_microsd, fake_ms_txn):
    clear_miniscript()
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
    import_ms_wallet(3, 6, name=name, accept=True, do_import=True, addr_fmt="p2wsh")
    name = f'ms2'
    keys3 = import_ms_wallet(3, 5, name=name, accept=True, do_import=True, addr_fmt="p2wsh")

    psbt = fake_ms_txn(5, 5, 3, keys3, outstyles=all_out_styles, inp_addr_fmt="p2wsh", incl_xpubs=True)

    try_sign_microsd(psbt, encoding='base64')


@pytest.mark.parametrize("descriptor", [True, False])
@pytest.mark.parametrize("m_n", [(2, 3), (3, 5), (5, 10)])
def test_ms_xpub_ordering(descriptor, m_n, clear_miniscript, make_multisig, import_ms_wallet,
                          try_sign_microsd, fake_ms_txn):
    clear_miniscript()
    M, N = m_n
    all_out_styles = list(unmap_addr_fmt.keys())
    index = all_out_styles.index("p2sh-p2wsh")
    all_out_styles[index] = "p2wsh-p2sh"
    name = f'ms1'
    keys = make_multisig(M, N)
    all_options = list(itertools.combinations(keys, len(keys)))
    for opt in all_options:
        import_ms_wallet(M, N, keys=opt, name=name, accept=True, do_import=True, addr_fmt="p2wsh")
        psbt = fake_ms_txn(5, 5, M, opt, outstyles=all_out_styles,
                           inp_addr_fmt="p2wsh", incl_xpubs=True)
        try_sign_microsd(psbt, encoding='base64')
        for opt_1 in all_options:
            # create PSBT with original keys order
            psbt = fake_ms_txn(5, 5, M, opt_1, outstyles=all_out_styles,
                               inp_addr_fmt="p2wsh", incl_xpubs=True)
            try_sign_microsd(psbt, encoding='base64')


@pytest.mark.parametrize('cmn_pth_from_root', [True, False])
@pytest.mark.parametrize('way', ["sd", "vdisk", "nfc"])
@pytest.mark.parametrize('M_N', [(2, 3), (3, 5), (15, 15)])
@pytest.mark.parametrize('desc', ["multi", "sortedmulti"])
@pytest.mark.parametrize('addr_fmt', [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH])
def test_multisig_descriptor_export(M_N, way, addr_fmt, cmn_pth_from_root, clear_miniscript, make_multisig,
                                    import_ms_wallet, goto_home, pick_menu_item, cap_menu,
                                    nfc_read_text, microsd_path, cap_story, need_keypress,
                                    load_export, desc):

    def choose_multisig_wallet():
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Miniscript')
        menu = cap_menu()
        pick_menu_item(menu[0])

    M, N = M_N
    wal_name = f"reexport"

    dd = {
        AF_P2WSH: ("m/48h/1h/0h/2h/{idx}", 'p2wsh'),
        AF_P2SH: ("m/45h/{idx}", 'p2sh'),
        AF_P2WSH_P2SH: ("m/48h/1h/0h/1h/{idx}", 'p2sh-p2wsh'),
    }
    deriv, text_a_fmt = dd[addr_fmt]
    keys = make_multisig(M, N, unique=1, deriv=None if cmn_pth_from_root else deriv)
    derivs = [deriv.format(idx=i) for i in range(N)]
    clear_miniscript()
    import_ms_wallet(M, N, accept=True, keys=keys, name=wal_name,
                     derivs=None if cmn_pth_from_root else derivs,
                     addr_fmt=text_a_fmt, common="m/45h" if cmn_pth_from_root else None,
                     bip67=False if desc == "multi" else True)
    # get bare descriptor
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("Export")
    contents = load_export(way, label="Miniscript", is_json=False)
    bare_desc = contents.strip()

    # get core descriptor json
    choose_multisig_wallet()
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    core_desc_text = load_export(way, label="Bitcoin Core miniscript", is_json=False)

    # remove junk
    text = core_desc_text.replace("importdescriptors ", "").strip()
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)

    # assert that bare and pretty are the same after parse
    assert f"({desc}(" in bare_desc

    assert core_desc_object[0]["desc"] == bare_desc
    clear_miniscript()


def test_chain_switching(use_mainnet, use_regtest, settings_get, settings_set,
                         clear_miniscript, goto_home, cap_menu, pick_menu_item,
                         need_keypress, import_ms_wallet):
    clear_miniscript()
    use_regtest()

    # cannot import XPUBS when testnet/regtest enabled
    with pytest.raises(Exception):
        import_ms_wallet(3, 3, addr_fmt="p2wsh", accept=True, chain="BTC")

    on_regtest = "xtn0"
    import_ms_wallet(2, 2, name=on_regtest, addr_fmt="p2wsh", accept=True, chain="XRT")
    res = settings_get("miniscript")
    assert len(res) == 1
    assert res[0][-1] == "XRT"

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert "(none setup yet)" not in m
    assert on_regtest == m[0]
    goto_home()
    settings_set("chain", "BTC")
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert "(none setup yet)" in m
    on_mainnet = "btc0"
    import_ms_wallet(3, 3, addr_fmt="p2wsh", accept=True, chain="BTC", name=on_mainnet)
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert on_mainnet == m[0]
    assert on_regtest not in m

    goto_home()
    settings_set("chain", "XTN")
    import_ms_wallet(4, 4, addr_fmt="p2wsh", accept=True, chain="XTN", name="xtn1")
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    time.sleep(0.1)
    m = cap_menu()
    assert "(none setup yet)" not in m
    assert on_regtest == m[0]
    assert "xtn1" == m[1]
    assert on_mainnet not in m


@pytest.mark.parametrize("desc", [
    ("wsh(sortedmulti(2,"
    "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*,"
    "[0f056943/84'/1'/9']tpubDC7jGaaSE66QBAcX8TUD3JKWari1zmGH4gNyKZcrfq6NwCofKujNF2kyeVXgKshotxw5Yib8UxLrmmCmWd8NVPVTAL8rGfMdc7TsAKqsy6y/<0;1>/*"
    "))"),
    ("wsh(sortedmulti(2,"
     "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*,"
     "[0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<2;3>/*"
     "))"),
])
def test_same_key_account_based_multisig(goto_home, need_keypress, pick_menu_item, cap_story,
                                         clear_miniscript, microsd_path, load_export, desc,
                                         offer_minsc_import):
    clear_miniscript()
    _, story = offer_minsc_import(desc)
    # this is allowed now
    assert "Create new miniscript wallet" in story


def test_multisig_name_validation(microsd_path, offer_minsc_import):
    with open("data/multisig/desc-p2wsh-myself.txt", "r") as f:
        config = f.read()

    with pytest.raises(Exception) as e:
        offer_minsc_import(json.dumps({"name": "eê", "desc": config}), allow_non_ascii=True)
    assert "must be ascii" in e.value.args[0]

    with pytest.raises(Exception) as e:
        offer_minsc_import(json.dumps({"name": "eee\teee", "desc": config}), allow_non_ascii=True)
    assert "must be ascii" in e.value.args[0]


# def test_multisig_deriv_path_migration(settings_set, clear_miniscript, import_ms_wallet,
#                                        press_cancel, settings_get, make_multisig,
#                                        goto_home, start_sign, cap_story, end_sign,
#                                        pick_menu_item, cap_menu):
#     # this test case simulates multisig wallets imported to CC before 5.3.0
#     # release; these wallets, saved in user settings, still have "'" in derivation
#     # paths; 5.3.1 firmware implements migration to "h" in MultisigWallet.deserialize
#
#     clear_miniscript()
#
#     deriv, text_a_fmt = ("m/48h/1h/0h/2h/{idx}", 'p2wsh')
#     keys = make_multisig(2, 3, unique=1, deriv=deriv)
#     derivs = [deriv.format(idx=i) for i in range(3)]
#     import_ms_wallet(2, 3, accept=True, keys=keys, name="ms1",
#                      derivs=derivs, addr_fmt=text_a_fmt)
#     time.sleep(.1)
#
#     import_ms_wallet(3, 5, name="ms2", addr_fmt='p2wsh-p2sh', accept=True)
#     time.sleep(.1)
#
#     ms = settings_get("multisig")
#     pths0 = ms[0][3]["d"]
#     new_pths0 = [p.replace("h", "'") for p in pths0]
#     ms[0][3]["d"] = new_pths0
#
#     ms[1][3]["pp"] = ms[1][3]["pp"].replace("h", "'")
#
#     # this matches data/PSBT
#     ms.append(
#         (
#             'ms',
#             (2, 2),
#             [(2285969762, 0, 'tpubDEy2hd2VTrqbBS8cS2svq12UmjGM2j7FHmocjHzAXfVhmJdhBFVVbmAi13humi49esaAuSmz36NEJ6GL3u58RzNuUkExP9vL4d81PM3s8u6'),
#              (1130956047, 1, 'tpubDEFX3QojMWh7x4vSAHN17wpsywpP78aSs2t6nyELHuq1k34gub9mQ7QiaHNCBAYjSQ4UCMMpfBkf5np1cTQaStrvvRCxwxZ7kZaGHqYxUv3')],
#             {'ch': 'XTN', 'ft': 14, 'd': ["m/48'/0'/99'/2'", "m/48'/0'/33'/2'"]}
#         )
#     )
#     settings_set("multisig", ms)
#
#     # psbt from nunchuk, with global xpubs belonging to above ms wallet
#     b64_psbt = "cHNidP8BAF4CAAAAAfkDjXlS32gzOjVhSRArKxvkAecMTnp1g8wwMJTtq74/AAAAAAD9////AekaAAAAAAAAIgAgzs2e4h4vctbFvvauK+QVFAPzCFnMi1H9hTacH7498P8AAAAATwEENYfPBC7g3O2AAAACLvzTgnL7V0DNOnISJdvOgq/6Pw6DAtkPflmZ+Hc04qwC5CShG0rDIlh8gu7gH2NMBLfrIzYSzoSomnVHeMxtxVQUDwVpQzAAAIAAAACAIQAAgAIAAIBPAQQ1h88EkEB8moAAAALv/1L+Cfeg2EPc01pS00f18DIdU5BOeExlGsXyEFOKGwL71tcAiRuL4Bs+uT1JJjU6AbR3j3X60/rI+rTMJmnOgRRiIUGIMAAAgAAAAIBjAACAAgAAgAABAIkCAAAAAZ5Im3CxbYDyByyrr4luss5vr+s0r7Vt8pK+OvicPLO7AAAAAAD9////AnM2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnTmvqUXAAAAACJRIJF/VcIeZ3E4f+ZEjwiUl5AUUxBJgoaEaPaHHJecq18lq+4qAAEBK3M2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnQiAgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3kcwRAIgHNmbk4J9wu4ljq6UouY132eX1i/2jWvJjuuWWyLRFScCIBPyPCuZ/Hmd06h9KtVkSropBonIuqIc/BK8JZ50YKp/AQEDBAEAAAABBUdSIQMBr34TVHrqSk8K6505//5YTOkHmHqF83J8iUURtL/ptCEDUXZhsRMLD/PMbva5f7RgF6u5D5v+99Mk8kOlx0C/w95SriIGAwGvfhNUeupKTwrrnTn//lhM6QeYeoXzcnyJRRG0v+m0HA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAAAAAAiBgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3hxiIUGIMAAAgAAAAIBjAACAAgAAgAAAAAAAAAAAAAEBR1IhAscIZVvBcy3Q0GKO4UqR3gDB3pm/tWas8siH3Ej8MmuCIQN8lTj0MMTpT+Dlk2MbMdAaL93hezzNP3WDsRn/gwlVQlKuIgICxwhlW8FzLdDQYo7hSpHeAMHemb+1ZqzyyIfcSPwya4IcYiFBiDAAAIAAAACAYwAAgAIAAIAAAAAAAQAAACICA3yVOPQwxOlP4OWTYxsx0Bov3eF7PM0/dYOxGf+DCVVCHA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAEAAAAA"
#
#     goto_home()
#     # in time of creatin of PSBT, lopp was making testnet3 unusable...
#     settings_set("fee_limit", -1)
#     start_sign(base64.b64decode(b64_psbt))
#     title, story = cap_story()
#     assert title == "OK TO SEND?"
#     end_sign()
#     settings_set("fee_limit", 10)  # rollback
#     pick_menu_item("Settings")
#     pick_menu_item("Multisig Wallets")
#     m = cap_menu()
#     for msi in m[:3]:  # three wallets imported
#         pick_menu_item(msi)
#         pick_menu_item("View Details")
#         time.sleep(.1)
#         _, story = cap_story()
#         assert "'" not in story
#         press_cancel()
#         press_cancel()


@pytest.mark.parametrize("fpath", [
    # descriptors
    "data/multisig/desc-p2sh-myself.txt",
    "data/multisig/desc-p2sh-p2wsh-myself.txt",
    "data/multisig/desc-p2wsh-myself.txt",
])
def test_scan_any_qr(fpath, is_q1, scan_a_qr, clear_miniscript, goto_home,
                     pick_menu_item, cap_story, press_cancel):
    if not is_q1:
        pytest.skip("No QR support for Mk4")

    clear_miniscript()
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
    assert "Create new miniscript wallet?" in story
    press_cancel()


@pytest.mark.parametrize("desc", ["multi", "sortedmulti"])
@pytest.mark.parametrize("data,af", [
    # (out_style, amount, is_change)
    # change can only be of the same address type as imported wallet
    ([("p2wsh", 1000000, 0)] * 99, "p2wsh"),
    ([("p2sh", 1000000, 1)] * 33, "p2sh"),
    ([("p2wsh-p2sh", 1000000, 1)] * 18 + [("p2wsh", 50000000, 0)] * 12, "p2sh-p2wsh"),
    ([("p2sh", 1000000, 0), ("p2wsh-p2sh", 50000000, 0), ("p2wsh", 800000, 1)] * 14, "p2wsh"),
])
def test_txout_explorer(data, af, desc, clear_miniscript, import_ms_wallet, fake_ms_txn,
                        start_sign, txout_explorer, pytestconfig):
    # TODO This test MUST be run with --psbt2 flag on and off

    outstyles = []
    outvals = []
    change_outputs = []
    for i in range(len(data)):
        os, ov, is_change = data[i]
        outstyles.append(os)
        outvals.append(ov)
        if is_change:
            change_outputs.append(i)

    clear_miniscript()
    M, N = 2, 3
    bip67 = True if desc == "multi" else False
    keys = import_ms_wallet(2, 3, name='ms-test', accept=True, bip67=bip67, addr_fmt=af)

    inp_amount = sum(outvals) + 100000  # 100k sat fee
    psbt = fake_ms_txn(1, len(data), M, keys, outstyles=outstyles, inp_addr_fmt=af,
                       outvals=outvals, change_outputs=change_outputs,
                       input_amount=inp_amount, psbt_v2=pytestconfig.getoption('psbt2'),
                       bip67=bip67)
    start_sign(psbt)
    txout_explorer(data)


@pytest.mark.parametrize("order", list(itertools.product([True, False], repeat=2)))
def test_import_duplicate_shuffled_keys(clear_miniscript, make_multisig, import_ms_wallet,
                                        cap_story, press_cancel, order, OK):
    # DO NOT allow to import both wsh(sortedmulti(2,A,B,C)) and wsh(sortedmulti(2,B,C,A))
    # DO NOT allow to import both wsh(multi(2,A,B,C)) and wsh(multi(2,B,C,A))
    # DO NOT allow to import both wsh(sortedmulti(2,A,B,C)) and wsh(multi(2,B,C,A))
    # MUST BE treated as duplicates
    clear_miniscript()
    M, N = 2, 3
    A, B = order  # defines bip67
    keys = make_multisig(M, N)
    import_ms_wallet(M, N, addr_fmt="p2wsh", name="ms0", accept=True, keys=keys, bip67=A)
    # shuffle
    keys[0], keys[1] = keys[1], keys[0]

    with pytest.raises(AssertionError):
        import_ms_wallet(M, N, addr_fmt="p2wsh", name="ms1", accept=True, keys=keys, bip67=B)

    time.sleep(.1)
    title, story = cap_story()
    assert 'Duplicate wallet' in story
    assert f'{OK} to approve' not in story
    if A != B:
        assert "BIP-67 clash" in story

    press_cancel()


@pytest.mark.parametrize("int_ext", [True, False])
def test_multi_sortedmulti_duplicate(clear_miniscript, make_multisig, import_ms_wallet, OK,
                                     cap_story, press_cancel, int_ext, offer_minsc_import,
                                     settings_set):
    clear_miniscript()
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

    title, story = offer_minsc_import(ser_desc)
    assert 'Duplicate wallet' in story
    assert f'{OK} to approve' not in story
    assert "BIP-67 clash" in story
    press_cancel()


@pytest.mark.bitcoind
@pytest.mark.parametrize("cs", [True, False])
@pytest.mark.parametrize("way", ["usb", "nfc", "sd", "vdisk", "qr"])
def test_import_multisig_usb_json(use_regtest, cs, way, cap_menu, clear_miniscript,
                                  pick_menu_item, goto_home, need_keypress,
                                  offer_minsc_import, bitcoind, microsd_path,
                                  virtdisk_path, import_miniscript):
    name = "my_ms_wal"
    use_regtest()
    clear_miniscript()

    with open("data/multisig/desc-p2wsh-myself.txt", "r") as f:
        desc = f.read().strip()

    if not cs:
        desc, cs = desc.split("#")

    val = json.dumps({"name": name, "desc": desc})

    data = None
    fname = None
    if way == "usb":
        title, story = offer_minsc_import(val)
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

        title, story = import_miniscript(fname=fname, way=way, data=data)

    assert "Create new miniscript wallet?" in story
    assert name in story
    need_keypress("y")
    time.sleep(.2)
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
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
def test_json_import_failures(err, config, offer_minsc_import):
    with pytest.raises(Exception) as e:
        offer_minsc_import(json.dumps(config))
    assert err in e.value.args[0]


@pytest.mark.bitcoind
def test_cc_root_key(import_ms_wallet, bitcoind, use_regtest, clear_miniscript, microsd_wipe, goto_home,
                     pick_menu_item, cap_story, press_select, need_keypress, offer_minsc_import,
                     cap_menu, load_export, try_sign, goto_address_explorer, settings_set):
    # only CC has root key here, not practical to attempt get xpub from core, if possible
    use_regtest()
    clear_miniscript()
    microsd_wipe()
    M, N = 2, 2
    cosigner = bitcoind.create_wallet(wallet_name=f"bds", disable_private_keys=False, blank=False,
                                      passphrase=None, avoid_reuse=False, descriptors=True)
    ms = bitcoind.create_wallet(
        wallet_name=f"watch_only_roots", disable_private_keys=True,
        blank=True, passphrase=None, avoid_reuse=False, descriptors=True
    )
    goto_home()
    target_first_der = []

    # get key from bitcoind cosigner
    target_desc = ""
    bitcoind_descriptors = cosigner.listdescriptors()["descriptors"]
    for desc in bitcoind_descriptors:
        if desc["desc"].startswith("pkh(") and desc["internal"] is False:
            target_desc = desc["desc"]
    core_desc, checksum = target_desc.split("#")
    # remove pkh(....)
    core_key = core_desc[4:-1]

    _idx = core_key.find("]")
    assert _idx != -1
    inner = core_key[1:_idx].split("/")
    # xfp to upper
    inner[0] = inner[0].upper()
    core_der_base = f"[{'/'.join(inner)}/0/%d]"
    cc_der_base = f"[{xfp2str(simulator_fixed_xfp)}/0/%d]"
    target_first_der.append(core_der_base % 0)
    target_first_der.append(cc_der_base % 0)

    desc = f"wsh(sortedmulti(2,{core_key},[{xfp2str(simulator_fixed_xfp).lower()}]{simulator_fixed_tpub}/0/*))"
    desc_info = ms.getdescriptorinfo(desc)
    desc_w_checksum = desc_info["descriptor"]  # with checksum

    name = "cc_root_key"
    title, story = offer_minsc_import(json.dumps({"name": name, "desc": desc_w_checksum}))

    assert "Create new miniscript wallet?" in story
    assert name in story
    # assert f"All {N} co-signers must approve spends" in story
    assert "P2WSH" in story
    press_select()  # approve multisig import
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Miniscript')
    menu = cap_menu()
    pick_menu_item(menu[0])  # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    # bump range to be able to verify multisig scripts against bitcoind
    # default exported range from us is just 100 addresses
    for i in range(len(core_desc_object)):
        core_desc_object[i]["range"] = [0,250]

    # import descriptors to watch only wallet
    res = ms.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"], obj

    addr_type = "bech32"
    multi_addr = ms.getnewaddress("", addr_type)
    bitcoind.supply_wallet.sendtoaddress(address=multi_addr, amount=49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())  # mining
    dest_addr = ms.getnewaddress("", addr_type)
    # create funded PSBT
    psbt_resp = ms.walletcreatefundedpsbt(
        [], [{dest_addr: 5}], 0, {"fee_rate": 2, "change_type": addr_type}
    )

    _, updated = try_sign(base64.b64decode(psbt_resp.get("psbt")))

    done = cosigner.walletprocesspsbt(base64.b64encode(updated).decode(), True)["psbt"]

    rr = ms.finalizepsbt(done)

    assert rr['complete']
    tx_hex = rr["hex"]
    res = bitcoind.supply_wallet.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    txn_id = bitcoind.supply_wallet.sendrawtransaction(rr['hex'])
    assert len(txn_id) == 64

    bitcoind_addrs = ms.deriveaddresses(desc_w_checksum, [0,250])

    goto_address_explorer()
    pick_menu_item(name)
    # TODO
    # _, story = cap_story()
    # # 2of2 - full paths shown for first address
    # der_paths = story.split("\n\n")[1].split("\n")[:N]
    # assert der_paths == target_first_der

    need_keypress('1')  # SD
    contents = load_export("sd", label="Address summary", is_json=False)
    cc_addrs = contents.strip().split("\n")[1:]

    # Generate the addresses file and get each line in a list
    for i, line in enumerate(cc_addrs):
        split_line = line.split(",")
        addr = split_line[1][1:-1]
        # TODO
        # script_hex = split_line[2][1:-1]
        # cc_der = split_line[-1][1:-1]
        # core_der = split_line[-2][1:-1]
        # assert cc_der == (cc_der_base % i)
        # assert core_der == (core_der_base % i)
        assert addr == bitcoind_addrs[i]
        addr_info = ms.getaddressinfo(addr)
        assert addr_info["ismine"]
        # assert addr_info["hex"] == script_hex


@pytest.mark.parametrize("way", ["nfc", "qr"])
def test_multisig_nfc_qr_finalization(way, clear_miniscript, make_multisig, import_ms_wallet,
                                      cap_story, press_cancel, OK, settings_set,
                                      fake_ms_txn, try_sign_nfc, settings_remove,
                                      try_sign_bbqr):
    clear_miniscript()
    settings_remove("ptxurl")  # tesing above parameter, ptxurl needs to be off
    M, N = 1, 2
    wname = "finms-%s" % way
    keys = import_ms_wallet(M, N, addr_fmt="p2wsh", name=wname, accept=True)

    psbt = fake_ms_txn(2, 2, M, keys, outstyles=['p2wsh', 'p2wsh-p2sh'],
                       change_outputs=[0], inp_addr_fmt="p2wsh")

    if way == "nfc":
        ip, result, txid = try_sign_nfc(psbt, expect_finalize=True,
                                        nfc_tools=True, encoding="hex")
        is_fin = bool(txid)
    else:
        assert way == "qr"
        ip, ft, result = try_sign_bbqr(psbt)
        is_fin = (ft == "T")

    assert is_fin


@pytest.mark.parametrize("has_orig", [False, True])
def test_originless_keys(get_cc_key, bitcoin_core_signer, bitcoind, offer_minsc_import,
                         pick_menu_item, load_export, goto_home, cap_menu, clear_miniscript,
                         use_regtest, press_select, start_sign, end_sign, cap_story,
                         has_orig, need_keypress):
    # can be both:
    #   a.) just ranged xpub without origin info -> xpub1/<0;1>/*
    #   b.) ranged xpub with its fp -> [xpub1_fp]xpub1/<0;1>/*

    use_regtest()
    clear_miniscript()
    af = "bech32"
    name = "originless_multlisig"

    cc_key = get_cc_key("m/84h/1h/0h")
    cs, ck = bitcoin_core_signer(name+"_signer")
    originless_ck = ck.split("]")[-1]

    n = BIP32Node.from_hwif(originless_ck.split("/")[0])  # just extended key
    fp_str = "[" + n.fingerprint().hex() + "]"
    if has_orig:
        originless_ck = fp_str + originless_ck

    tmplt = "wsh(sortedmulti(2,@0,@1))"
    desc = tmplt.replace("@0", cc_key)
    desc = desc.replace("@1", originless_ck)
    to_import = {"desc": desc, "name": name}
    offer_minsc_import(json.dumps(to_import))
    press_select()

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                passphrase=None, avoid_reuse=False, descriptors=True)

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Miniscript")
    pick_menu_item(name)  # pick imported descriptor miniscript wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]

    # fund wallet
    addr = wo.getnewaddress("", af)
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())

    unspent = wo.listunspent()
    assert len(unspent) == 1

    # split to 10 utxos
    dest_addrs = [wo.getnewaddress(f"a{i}", af) for i in range(10)]
    psbt_resp = wo.walletcreatefundedpsbt(
        [],
        [{a: 4} for a in dest_addrs] + [{bitcoind.supply_wallet.getnewaddress(): 5}],
        0,
        {"fee_rate": 3, "change_type": af, "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    start_sign(base64.b64decode(psbt))
    time.sleep(.1)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    cc_signed = end_sign(True)
    cc_signed = base64.b64encode(cc_signed).decode()

    final_psbt_o = cs.walletprocesspsbt(cc_signed, True, "ALL")
    final_psbt = final_psbt_o["psbt"]
    assert psbt != final_psbt

    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    res = wo.testmempoolaccept([tx_hex])
    assert res[0]["allowed"]
    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id

# EOF
