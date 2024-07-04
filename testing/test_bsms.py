import sys
sys.path.append("../shared")
import pytest, time, pdb, os, random, hashlib, base64
from constants import simulator_fixed_tprv
from charcodes import KEY_NFC
from bsms import CoordinatorSession, Signer
from bsms.encryption import key_derivation_function, decrypt, encrypt
from bsms.util import bitcoin_msg, str2path
from bsms.bip32 import PrvKeyNode, PubKeyNode
from bsms.ecdsa import ecdsa_verify, ecdsa_recover
from bsms.address import p2wsh_address, p2sh_p2wsh_address
from descriptor import MultisigDescriptor, append_checksum
from msg import sign_message
from bip32 import BIP32Node


BSMS_VERSION = "BSMS 1.0"
ALLOWED_PATH_RESTRICTIONS = "/0/*,/1/*"


# keys in settings object
BSMS_SETTINGS = "bsms"
BSMS_SIGNER_SETTINGS = "s"
BSMS_COORD_SETTINGS = "c"


et_map = {
    "1": "STANDARD",
    "2": "EXTENDED",
    "3": "NO_ENCRYPTION"
}

af_map = {
    "p2wsh": 14,
    "p2sh-p2wsh": 26
}


def coordinator_label(M, N, addr_fmt, et, index=None):
    fmt_str = "%dof%d_%s_%s" % (M, N, "native" if addr_fmt == "p2wsh" else "nested", et)
    if index:
        fmt_str = "%d %s" % (index, fmt_str)
    return fmt_str


def assert_coord_summary(title, story, M, N, addr_fmt, et):
    assert title == "SUMMARY"
    assert f"{M} of {N}" in story
    assert f"Address format:\n{addr_fmt}" in story
    assert f"Encryption type:\n{et_map[et].replace('_', ' ')}" in story
    tokens = story.split("\n\n")[3:-1]
    if et == "1":
        assert len(tokens) == 1
    elif et == "2":
        assert len(tokens) == N
    else:
        assert len(tokens) == 0
    return tokens

@pytest.fixture
def make_coordinator_round1(settings_remove, settings_get, settings_set, microsd_path, virtdisk_path):
    def doit(M, N, addr_fmt, et, way, purge_bsms=True, tokens_only=False):
        if purge_bsms:
            settings_remove(BSMS_SETTINGS)  # clear bsms
        bsms = settings_get(BSMS_SETTINGS) or {}
        tokens = []
        if et == "1":
            tokens = [os.urandom(8).hex()]
        elif et == "2":
            tokens = [os.urandom(16).hex() for _ in range(N)]
        coord_tuple = (M, N, af_map[addr_fmt], et, tokens)
        if BSMS_COORD_SETTINGS in bsms:
            bsms[BSMS_COORD_SETTINGS].append(coord_tuple)
        else:
            bsms[BSMS_COORD_SETTINGS] = [coord_tuple]
        settings_set(BSMS_SETTINGS, bsms)
        if tokens_only:
            return tokens
        if way == "sd":
            path_fn = microsd_path
        elif way == "vdisk":
            path_fn = virtdisk_path
        else:
            return tokens
        for token_hex in tokens:
            basename = "bsms_%s.token" % token_hex[:4]
            with open(path_fn(basename), "w") as f:
                f.write(token_hex)
        return tokens
    return doit


def bsms_sr1_fname(token, is_extended, suffix, index=None):
    fname = "bsms_sr1"
    if is_extended:
        fname += "_" + token[:4]
    else:
        if index:  # ignores index = 0
            fname += "-" + str(index)
    return fname + suffix


@pytest.fixture
def make_signer_round1(settings_get, settings_set, settings_remove, microsd_path, virtdisk_path):
    def doit(token, way, root_xprv=None, bsms_version=BSMS_VERSION, description=None, purge_bsms=True,
             add_to_settings=False, data_only=False, index=None, wrong_sig=False, wrong_encryption=False, slip=False):
        is_extended = len(token) == 32
        if purge_bsms:
            settings_remove(BSMS_SETTINGS)  # clear bsms
        if add_to_settings:
            bsms = settings_get(BSMS_SETTINGS) or {}
            if BSMS_SIGNER_SETTINGS in bsms:
                bsms[BSMS_COORD_SETTINGS].append(token)
            else:
                bsms[BSMS_SIGNER_SETTINGS] = [token]

        if root_xprv:
            wk = BIP32Node.from_wallet_key(root_xprv)
        else:
            wk = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN")
        root_xfp = wk.fingerprint().hex()
        paths = ["48'/1'/0'/2'", "48'/1'/0'/1'", "0'/1'/0'/0'", "0'", "100'/0'"]
        path = random.choice(paths)
        sk = wk.subkey_for_path(path)
        xpub = sk.hwif(as_private=False)
        if slip:
            xpub = xpub.replace("tpub", random.choice(["upub", "vpub", "Upub", "Vpub"]))
        key_expr = "[%s/%s]%s" % (root_xfp, path, xpub)
        data = "%s\n" % bsms_version
        data += "%s\n" % token
        data += "%s\n" % key_expr
        if description is None:
            description = "Coldcard Signer %s" % root_xfp
        data += "%s" % description
        sig = sign_message(bytes(sk.node.private_key),
                           data.encode()+b"ff" if wrong_sig else data.encode(),
                           b64=True)
        data += "\n%s" % sig
        suffix = ".txt"
        mode = "wt"
        if token != "00":
            suffix = ".dat"
            mode = "wb"
            dkey = key_derivation_function(token)
            if wrong_encryption:
                wrong = "ffff" + token[4:]
                dkey = key_derivation_function(wrong)
            data = encrypt(dkey, token, data)
            data = bytes.fromhex(data)
        if data_only:
            return data
        if way != "nfc":
            if way == "sd":
                path_fn = microsd_path
            else:
                # vdisk
                path_fn = virtdisk_path
            basename = bsms_sr1_fname(token, is_extended, suffix, index)
            with open(path_fn(basename), mode) as f:
                f.write(data)
        return data

    return doit


def ms_address_from_descriptor_bsms(desc_obj: MultisigDescriptor, subpath="0/0", network="XTN"):
    testnet = True if network == "XTN" else False
    nodes = [
        PubKeyNode.parse(ek).derive_path(str2path(subpath))
        for _, _, ek in desc_obj.keys
    ]
    secs = [node.sec() for node in nodes]
    secs.sort()
    if desc_obj.addr_fmt == af_map["p2wsh"]:
        address = p2wsh_address(secs, desc_obj.M, sortedmulti=True, testnet=testnet)
    else:
        address = p2sh_p2wsh_address(secs, desc_obj.M, sortedmulti=True, testnet=testnet)
    return address


def bsms_cr2_fname(token, is_extended, suffix):
    fname = "bsms_cr2"
    if is_extended:
        fname += "_" + token[:4]
    return fname + suffix


@pytest.fixture
def make_coordinator_round2(make_coordinator_round1, settings_get, settings_set, microsd_path, virtdisk_path):
    def doit(M, N, addr_fmt, et, way, has_ours=True, ours_no=1, path_restrictions=ALLOWED_PATH_RESTRICTIONS,
             bsms_version=BSMS_VERSION, sortedmulti=True, wrong_address=False, wrong_encryption=False,
             wrong_chain=False, add_checksum=False, wrong_checksum=False):
        tokens = make_coordinator_round1(M, N, addr_fmt, et, way=way, purge_bsms=True, tokens_only=True)
        range_num = N if has_ours is False else N - ours_no
        keys = []
        for _ in range(range_num):
            wk = BIP32Node.from_master_secret(os.urandom(32), netcode="BTC" if wrong_chain else "XTN")
            root_xfp = wk.fingerprint().hex()
            paths = ["48'/1'/0'/2'", "48'/1'/0'/1'", "0'/1'/0'/0'", "0'", "100'/0'"]
            path = random.choice(paths)
            sk = wk.subkey_for_path(path)
            xpub = sk.hwif(as_private=False)
            keys.append((root_xfp, "m/" + path, xpub))
        if has_ours:
            for _ in range(ours_no):
                wk = BIP32Node.from_wallet_key(simulator_fixed_tprv)
                root_xfp = wk.fingerprint().hex()
                paths = ["48'/1'/0'/2'", "48'/1'/0'/1'", "0'/1'/0'/0'", "0'", "100'/0'"]
                path = random.choice(paths)
                sk = wk.subkey_for_path(path)
                xpub = sk.hwif(as_private=False)
                keys.append((root_xfp, "m/" + path, xpub))

        desc_obj = MultisigDescriptor(M=M, N=N, addr_fmt=af_map[addr_fmt], keys=keys)
        desc = desc_obj._serialize(int_ext=True)
        wcs = append_checksum(desc).split("#")[-1]
        desc = desc.replace("/<0;1>/*", "/**")
        if add_checksum:
            desc = append_checksum(desc)
        elif wrong_checksum:
            desc = desc + "#" + wcs
        if not sortedmulti:
            desc = desc.replace("sortedmulti", "multi")
        desc_template = "%s\n" % bsms_version
        desc_template += "%s\n" % desc
        desc_template += "%s\n" % path_restrictions
        if wrong_address:
            addr = ms_address_from_descriptor_bsms(desc_obj, subpath="1000/100")
        else:
            addr = ms_address_from_descriptor_bsms(desc_obj)
        desc_template += "%s" % addr

        # create signer artificialy and produce correct descriptor template file
        bsms = settings_get(BSMS_SETTINGS) or {}
        bsms[BSMS_SIGNER_SETTINGS] = []  # purge
        if not tokens:
            token = "00"
            bsms[BSMS_SIGNER_SETTINGS].append(token)
            res = desc_template
        else:
            token = tokens[0]
            # same for STANDARD and EXTENDED --> encrypt
            bsms[BSMS_SIGNER_SETTINGS].append(token)
            if wrong_encryption:
                res = encrypt(key_derivation_function(os.urandom(16).hex()), token, desc_template)
            else:
                res = encrypt(key_derivation_function(token), token, desc_template)
            res = bytes.fromhex(res)

        settings_set(BSMS_SETTINGS, bsms)
        if way != "nfc":
            if way == "sd":
                path_fn = microsd_path
            else:
                # vdisk
                path_fn = virtdisk_path
            mode = "wb" if et in ["1", "2"] else "wt"
            suffix = ".dat" if et in ["1", "2"] else ".txt"
            basename = bsms_cr2_fname(token, et == "2", suffix)
            with open(path_fn(basename), mode) as f:
                f.write(res)

        return res, token

    return doit


@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk"])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
def test_coordinator_round1(way, encryption_type, M_N, addr_fmt, clear_ms, goto_home, need_keypress,
                            pick_menu_item, cap_menu, cap_story, microsd_path, settings_remove,
                            nfc_read_text, request, settings_get, microsd_wipe, press_select, is_q1):
    if way == "vdisk":
        virtdisk_wipe = request.getfixturevalue("virtdisk_wipe")
        virtdisk_path = request.getfixturevalue("virtdisk_path")
        virtdisk_wipe()

    M, N = M_N

    microsd_wipe()
    settings_remove(BSMS_SETTINGS)  # clear bsms
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 1  # nothing should be in menu at this point but round 1
    pick_menu_item('Create BSMS')
    # choose number of signers N
    for num in str(N):
        need_keypress(num)
    press_select()
    # choose threshold M
    for num in str(M):
        need_keypress(num)
    press_select()
    if addr_fmt == "p2wsh":
        press_select()
    else:
        need_keypress("2")
    time.sleep(0.1)
    title, story = cap_story()
    assert story == "Choose encryption type. Press (1) for STANDARD encryption, (2) for EXTENDED, and (3) for no encryption"
    need_keypress(encryption_type)
    time.sleep(0.1)
    title, story = cap_story()
    tokens = assert_coord_summary(title, story, M, N, addr_fmt, encryption_type)
    press_select()  # confirm summary
    time.sleep(0.1)
    title, story = cap_story()
    assert "Press (1) to participate as co-signer in this BSMS" in story
    press_select() # continue normally
    time.sleep(0.1)
    title, story = cap_story()
    if encryption_type == "3":
        assert story == "Success. Coordinator round 1 saved."
    else:
        if way == "sd":
            if "Press (1) to save BSMS token file(s) to SD Card" in story:
                need_keypress("1")
            # else no prompt if both NFC and vdisk disabled
        elif way == "nfc":

            if f"press {KEY_NFC if is_q1 else '(3)'} to share via NFC" not in story:
                pytest.skip("NFC disabled")
            else:
                need_keypress(KEY_NFC if is_q1 else "3")
                time.sleep(0.2)
                bsms_tokens = nfc_read_text()
                time.sleep(0.2)
                press_select()  # exit NFC UI simulation
                time.sleep(0.5)
        else:
            # virtual disk
            if "press (2) to save to Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress("2")

        read_tokens = []
        if way == "nfc" and encryption_type != "3":
            read_tokens = bsms_tokens.split("\n\n")
        else:
            time.sleep(0.2)
            _, story = cap_story()
            assert 'BSMS token file(s) written' in story
            fnames = story.split('\n\n')[2:]
            # check token files contains first 4 chars of token
            try:
                token_start = set([tok.split(" ")[1][:4] for tok in tokens])
            except IndexError:
                # only one token - special case without numbering
                assert len(tokens) == 1
                token_start = set([tokens[0].split("\n")[1][:4]])
            token_fnames_start = set([fn.replace(".token", "").split("_")[-1].split("-")[0] for fn in fnames])
            assert token_start == token_fnames_start
            read_tokens = []
            for fname in fnames:
                if way == "vdisk":
                    path = virtdisk_path(fname)
                else:
                    path = microsd_path(fname)
                with open(path, 'rt') as f:
                    token = f.read().strip()
                    read_tokens.append(token)

        if encryption_type == "1":
            assert len(read_tokens) == 1
        elif encryption_type == "2":
            assert len(read_tokens) == N
        else:
            assert len(tokens) == 0

    press_select()  # confirm success or files written story
    time.sleep(0.1)
    menu = cap_menu()
    assert len(menu) == 2
    current_coord_menu_item = coordinator_label(M, N, addr_fmt, encryption_type, index=1)
    assert menu[0] == current_coord_menu_item
    assert menu[1] == "Create BSMS"
    # check correct summary in detail
    pick_menu_item(menu[0])
    time.sleep(0.1)
    menu = cap_menu()
    assert len(menu) == 3
    assert menu[0] == "Round 2"
    assert menu[1] == "Detail"
    assert menu[2] == "Delete"
    pick_menu_item("Detail")
    time.sleep(0.1)
    title, story = cap_story()
    assert_coord_summary(title, story, M, N, addr_fmt, encryption_type)
    press_select()
    # check correct coord tuple saved
    bsms_settings = settings_get(BSMS_SETTINGS)
    if BSMS_SIGNER_SETTINGS in bsms_settings:
        assert bsms_settings[BSMS_SIGNER_SETTINGS] == []
    coord_settings = bsms_settings[BSMS_COORD_SETTINGS]
    assert len(coord_settings) == 1
    assert coord_settings[0] == (
        M, N, af_map[addr_fmt], encryption_type,
        [tok.split(" ")[-1].replace("Tokens:\n", "") for tok in tokens] if tokens else []
    )
    # delete coordinator settings
    pick_menu_item("Delete")
    time.sleep(0.1)
    menu = cap_menu()
    assert len(menu) == 1
    assert menu[0] == "Create BSMS"
    bsms_settings = settings_get(BSMS_SETTINGS)
    coord_settings = bsms_settings[BSMS_COORD_SETTINGS]
    assert coord_settings == []


@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk"])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
def test_signer_round1(way, encryption_type, M_N, addr_fmt, clear_ms, goto_home, need_keypress, pick_menu_item, cap_menu,
                       cap_story, microsd_path, settings_remove, nfc_read_text, request, settings_get,
                       make_coordinator_round1, nfc_write_text, microsd_wipe, press_select,
                       is_q1):
    if way == "vdisk":
        virtdisk_wipe = request.getfixturevalue("virtdisk_wipe")
        virtdisk_path = request.getfixturevalue("virtdisk_path")
        virtdisk_wipe()

    M, N = M_N
    microsd_wipe()
    tokens = make_coordinator_round1(M, N, addr_fmt, encryption_type, way)
    if encryption_type != "3":
        assert tokens
    else:
        assert tokens == []
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    menu = cap_menu()
    assert len(menu) == 1  # nothing should be in menu at this point but round 1
    pick_menu_item('Round 1')
    time.sleep(0.1)
    title, story = cap_story()
    if encryption_type == "3":
        token = "00"
        need_keypress("3")  # no token (unencrypted BSMS)
    else:
        token = random.choice(tokens)
        if way == "sd":
            if "Press (1) to import token file from SD Card" in story:
                need_keypress("1")
            # else no prompt if both NFC and vdisk disabled
        elif way == "nfc":
            if f"{KEY_NFC if is_q1 else '(4)'} to import via NFC" not in story:
                pytest.skip("NFC disabled")
            else:
                need_keypress(KEY_NFC if is_q1 else "4")
                time.sleep(0.1)
                nfc_write_text(token)
                time.sleep(0.4)
        else:
            # virtual disk
            if "(6) to import from Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress("6")

        if way != "nfc":
            time.sleep(0.2)
            fname = "bsms_%s.token" % token[:4]
            pick_menu_item(fname)

    time.sleep(0.1)
    title, story = cap_story()
    assert "You have entered token:\n%s" % token in story
    press_select()
    time.sleep(0.1)
    _, story = cap_story()
    # address format a.k.a. SLIP derivation path - ignore and use SLIP agnostic
    assert "Choose co-signer address format for correct SLIP derivation path" in story
    press_select()  # default
    # account number prompt
    press_select()
    time.sleep(0.1)
    _, story = cap_story()
    # textual key description
    assert "Choose key description" in story
    press_select()  # default
    time.sleep(0.1)
    title, story = cap_story()
    suffix = ".txt" if encryption_type == "3" else ".dat"
    mode = "rt" if encryption_type == "3" else "rb"
    if way == "sd":
        if "Press (1) to save BSMS signer round 1 file to SD Card" in story:
            need_keypress("1")
    elif way == "nfc":
        if f"press {KEY_NFC if is_q1 else '(3)'} to share via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress(KEY_NFC if is_q1 else "3")
            time.sleep(0.2)
            signer_r1 = nfc_read_text()
            time.sleep(0.2)
            press_select()  # exit NFC UI simulation
            time.sleep(0.5)
    else:
        # virtual disk
        if "press (2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    if way != "nfc":
        time.sleep(0.2)
        _, story = cap_story()
        assert 'BSMS signer round 1 file written' in story
        fname = story.split('\n\n')[-1]
        assert suffix in fname
        if encryption_type == "2":
            # check token files contains first 4 chars of token or just 00
            assert token[:4] == fname.split(".")[0][-4:]
        if way == "vdisk":
            path = virtdisk_path(fname)
        else:
            path = microsd_path(fname)
        with open(path, mode) as f:
            signer_r1 = f.read()

    bsms = settings_get(BSMS_SETTINGS)
    assert len(bsms[BSMS_SIGNER_SETTINGS]) == 1
    assert bsms[BSMS_SIGNER_SETTINGS][0] == token

    if encryption_type in ["1", "2"]:
        # decrypt
        if isinstance(signer_r1, bytes):
            signer_r1 = signer_r1.hex()
        signer_r1 = decrypt(key_derivation_function(token), signer_r1)

    version, tok, key_exp, description, sig = signer_r1.strip().split("\n")
    assert version == BSMS_VERSION
    assert tok == token
    close_index = key_exp.find("]")
    assert key_exp[0] == "[" and close_index != -1
    key_orig_info = key_exp[1:close_index]  # remove brackets
    xpub = key_exp[close_index + 1:]
    assert xpub[:4] in ["xpub", "tpub"]
    xfp, path = key_orig_info.split("/", 1)
    # pycoin xpub check
    mk = BIP32Node.from_wallet_key(simulator_fixed_tprv)
    sk = mk.subkey_for_path(path)
    pycoin_xpub = sk.hwif(as_private=False)
    assert xpub == pycoin_xpub
    # bsms lib xpub check
    mk0 = PrvKeyNode.parse(simulator_fixed_tprv, testnet=True)
    sk0 = mk0.derive_path(str2path(path))
    bsms_xpub = sk0.extended_public_key()
    assert xpub == bsms_xpub
    signed_data = "\n".join([version, tok, key_exp, description])
    # verify msg bsms lib (pure python ecdsa)
    signed_digest = bitcoin_msg(signed_data)
    decoded_sig = base64.b64decode(sig)
    recovered_sec = ecdsa_recover(signed_digest, decoded_sig)
    assert ecdsa_verify(signed_digest, decoded_sig, recovered_sec), "Signature invalid"


@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk"])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
@pytest.mark.parametrize("auto_collect", [True, False])
def test_coordinator_round2(way, encryption_type, M_N, addr_fmt, auto_collect, clear_ms, goto_home, need_keypress,
                            cap_menu, cap_story, microsd_path, settings_remove, nfc_read_text, request,
                            settings_get, make_coordinator_round1, make_signer_round1, nfc_write_text,
                            microsd_wipe, pick_menu_item, press_select, is_q1):
    def get_token(index):
        if len(tokens) == 1 and encryption_type == "1":
            token = tokens[0]
        elif len(tokens) == N and encryption_type == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    if way == "vdisk":
        virtdisk_wipe = request.getfixturevalue("virtdisk_wipe")
        virtdisk_path = request.getfixturevalue("virtdisk_path")
        virtdisk_wipe()

    M, N = M_N
    microsd_wipe()
    tokens = make_coordinator_round1(M, N, addr_fmt, encryption_type, way=way, tokens_only=True)
    all_data = []
    for i in range(N):
        token = get_token(i)
        index = None
        if encryption_type != "2":
            index = i + 1

        all_data.append(make_signer_round1(token, way, purge_bsms=False, index=index))

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 2
    coord_menu_item = coordinator_label(M, N, addr_fmt, encryption_type, index=1)
    assert coord_menu_item in menu
    pick_menu_item(coord_menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import co-signer round 1 files from SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "vdisk":
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")
    else:
        # NFC
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress(KEY_NFC if is_q1 else "3")

    if way == "nfc":
        if auto_collect is True:
            pytest.skip("No auto-collection for NFC")
        for i, data in enumerate(all_data):
            time.sleep(0.1)
            title, story = cap_story()
            token = get_token(i)
            if encryption_type == "2":
                expect = "Share co-signer #%d round-1 data for token starting with %s" % (i + 1, token[:4])
            else:
                expect = "Share co-signer #%d round-1 data" % (i + 1)
            assert expect in story
            press_select()
            time.sleep(.2)
            nfc_write_text(data.hex() if isinstance(data, bytes) else data)
            time.sleep(0.3)
    else:
        suffix = ".txt" if encryption_type == "3" else ".dat"
        time.sleep(0.1)
        title, story = cap_story()
        assert "Press OK to pick co-signer round 1 files manually, or press (1) to attempt auto-collection." in story
        assert "For auto-collection to succeed all filenames have to start with 'bsms_sr1'" in story
        suffix_target = "and end with extension '%s'" % suffix
        assert suffix_target in story
        if encryption_type == "2":
            assert "In addition for EXTENDED encryption all files must contain first four characters of respective token." in story
        elif encryption_type == "3":
            assert ("In addition for NO ENCRYPTION cases, number of files with above mentioned"
                    " pattern and suffix must equal number of signers (N).") in story
        assert "If above is not respected auto-collection fails and defaults to manual selection of files." in story
        if auto_collect:
            need_keypress("1")
        else:
            press_select()  # continue with manual selection
            for i, _ in enumerate(all_data, start=1):
                token = get_token(i - 1)
                time.sleep(0.1)
                title, story = cap_story()
                if encryption_type == "2":
                    expect = 'Select co-signer #%d file containing round 1 data for token starting with %s' % (i, token[:4])
                else:
                    expect = 'Select co-signer #%d file containing round 1 data' % i
                expect += '. File extension has to be "%s"' % suffix
                assert expect in story
                press_select()
                menu_item = bsms_sr1_fname(token, encryption_type == "2", suffix, i)
                pick_menu_item(menu_item)

    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to save BSMS descriptor template file(s) to SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "nfc":
        if f"{KEY_NFC if is_q1 else '(3)'} to share via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress(KEY_NFC if is_q1 else "3")
    else:
        # virtual disk
        if "(2) to save to Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")

    descriptor_templates = []
    if way == "nfc":
        # not implemented because of the fake nfc limit
        # pytest skip will be raised before we can get here
        if encryption_type == "2":
            for i, token in enumerate(tokens, start=1):
                time.sleep(.1)
                title, story = cap_story()
                expect = "Exporting data for co-signer #%d with token %s" % (i, token[:4])
                assert expect in story
                press_select()
                time.sleep(.5)
                rv = nfc_read_text()
                time.sleep(.5)
                descriptor_templates.append(rv)
                press_select()  # exit animation

            time.sleep(.1)
            title, story = cap_story()
            assert "All done" in story
            press_select()
        else:
            time.sleep(.5)
            rv = nfc_read_text()
            time.sleep(.5)
            descriptor_templates.append(rv)
            press_select()  # exit animation
    else:
        if way == "sd":
            path_fn = microsd_path
        else:
            path_fn = virtdisk_path
        time.sleep(0.1)
        _, story = cap_story()
        assert "BSMS descriptor template file(s) written." in story
        fnames = story.split("\n\n")[1:]
        if encryption_type == "2":
            for fname, token in zip(fnames, tokens):
                assert token[:4] in fname

        for fname in fnames:
            with open(path_fn(fname), "rt" if encryption_type == "3" else "rb") as f:
                desc_temp = f.read()
                descriptor_templates.append(desc_temp)

    assert descriptor_templates
    if encryption_type == "2":
        # each file encrypted with different token/key
        templates = set()
        for token, desc_template in zip(tokens, descriptor_templates):
            plaintext = decrypt(
                key_derivation_function(token),
                desc_template if isinstance(desc_template, str) else desc_template.hex()
            )
            assert plaintext
            templates.add(plaintext)
        assert len(templates) == 1
        # pick last to be the template
        the_template = plaintext
    elif encryption_type == "1":
        # just one template but encrypted
        assert len(descriptor_templates) == 1
        plaintext = decrypt(
            key_derivation_function(get_token(0)),
            descriptor_templates[0] if isinstance(descriptor_templates[0], str) else descriptor_templates[0].hex()
        )
        assert plaintext
        the_template = plaintext
    else:
        assert len(descriptor_templates) == 1
        the_template = descriptor_templates[0]

    version, descriptor, pth_restrictions, addr = the_template.split("\n")
    assert version == BSMS_VERSION
    try:
        MultisigDescriptor.checksum_check(descriptor)
        descriptor = descriptor.split("#")[0]
    except ValueError:
        pass
    # replace /** so we can parse it
    descriptor = descriptor.replace("/**", "/0/*")
    descriptor = append_checksum(descriptor)
    desc_obj = MultisigDescriptor.parse(descriptor)
    assert len(desc_obj.keys) == N
    assert pth_restrictions == ALLOWED_PATH_RESTRICTIONS
    # bsms lib test ms address
    address = ms_address_from_descriptor_bsms(desc_obj)
    assert addr == address


@pytest.mark.parametrize("refuse", [True, False])
@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk"])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("with_checksum", [True, False])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
def test_signer_round2(refuse, way, encryption_type, M_N, addr_fmt, clear_ms, goto_home, need_keypress, pick_menu_item,
                       cap_menu, cap_story, microsd_path, settings_remove, nfc_read_text, request, settings_get,
                       make_coordinator_round2, nfc_write_text, microsd_wipe, with_checksum,
                       press_select, press_cancel, is_q1):
    if way == "vdisk":
        virtdisk_wipe = request.getfixturevalue("virtdisk_wipe")
        virtdisk_path = request.getfixturevalue("virtdisk_path")
        virtdisk_wipe()
    M, N = M_N
    clear_ms()
    microsd_wipe()
    desc_template, token = make_coordinator_round2(M, N, addr_fmt, encryption_type, way=way, add_checksum=with_checksum)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    menu = cap_menu()
    assert len(menu) == 2
    assert "Round 1" in menu
    menu_item = "1   %s" % token[:4]
    assert menu_item in menu
    pick_menu_item(menu_item)
    menu = cap_menu()
    assert len(menu) == 3
    assert "Detail" in menu
    assert "Delete" in menu
    assert "Round 2" in menu
    pick_menu_item("Detail")
    time.sleep(0.1)
    _, story = cap_story()
    assert token in story
    assert str(int(token, 16)) in story
    press_select()
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if way == "sd":
        if "Press (1) to import descriptor template file from SD Card" in story:
            need_keypress("1")
        # else no prompt if both NFC and vdisk disabled
    elif way == "vdisk":
        if "(2) to import from Virtual Disk" not in story:
            pytest.skip("Vdisk disabled")
        else:
            need_keypress("2")
    else:
        # NFC
        if f"{KEY_NFC if is_q1 else '(3)'} to import via NFC" not in story:
            pytest.skip("NFC disabled")
        else:
            need_keypress(KEY_NFC if is_q1 else "3")

    if way == "nfc":
        time.sleep(0.1)
        nfc_write_text(desc_template.hex() if isinstance(desc_template, bytes) else desc_template)
        time.sleep(0.3)
    else:
        suffix = ".txt" if encryption_type == "3" else ".dat"
        time.sleep(0.1)
        menu_item = bsms_cr2_fname(token, encryption_type == "2", suffix)
        pick_menu_item(menu_item)

    time.sleep(0.5)
    _, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert "bsms" in story  # part of the name
    policy = "Policy: %d of %d" % (M, N)
    assert policy in story
    assert addr_fmt.upper() in story
    ms_wal_name = story.split("\n\n")[1].split("\n")[-1].strip()
    ms_wal_menu_item = "%d/%d: %s" % (M, N, ms_wal_name)
    if refuse:
        press_cancel()
        time.sleep(0.1)
        menu = cap_menu()
        assert ms_wal_menu_item not in menu
        bsms_settings = settings_get(BSMS_SETTINGS)
        # signer round 2 NOT removed
        assert bsms_settings.get(BSMS_SIGNER_SETTINGS)
    else:
        press_select()
        time.sleep(0.1)
        menu = cap_menu()
        assert ms_wal_menu_item in menu
        bsms_settings = settings_get(BSMS_SETTINGS)
        # signer round 2 removed
        assert not bsms_settings.get(BSMS_SIGNER_SETTINGS, None)


@pytest.mark.parametrize("token", [
    "f" * 15,
    "f" * 17,
    "0" * 31,
    "0" * 33,
])
@pytest.mark.parametrize("way", ["sd", "nfc", "vdisk", "manual"])
def test_invalid_token_signer_round1(token, way, pick_menu_item, cap_story, need_keypress,
                                     nfc_write_text, microsd_path, virtdisk_path, goto_home,
                                     press_select, is_q1):
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    pick_menu_item('Round 1')
    time.sleep(0.1)
    title, story = cap_story()
    if way == "manual":
        need_keypress("2")  # manual
        need_keypress("2")  # decimal
        for num in str(int(token, 16)):
            need_keypress(num)
        press_select()
    else:
        if way != "nfc":
            token_fname = "error.token"
            path_func = virtdisk_path if way == "vdisk" else microsd_path
            with open(path_func(token_fname), "w") as f:
                f.write(token)
        if way == "sd":
            if "Press (1) to import token file from SD Card" in story:
                need_keypress("1")
            # else no prompt if both NFC and vdisk disabled
        elif way == "nfc":
            if f"{KEY_NFC if is_q1 else '(4)'} to import via NFC" not in story:
                pytest.skip("NFC disabled")
            else:
                need_keypress(KEY_NFC if is_q1 else "4")
                time.sleep(0.1)
                nfc_write_text(token)
                time.sleep(0.4)
        else:
            # virtual disk
            if "(6) to import from Virtual Disk" not in story:
                pytest.skip("Vdisk disabled")
            else:
                need_keypress("6")

        if way != "nfc":
            time.sleep(0.2)
            pick_menu_item(token_fname)

    time.sleep(0.1)
    title, story = cap_story()
    assert title == "FAILURE"
    assert "BSMS signer round1 failed" in story
    assert "Invalid token length. Expected 64 or 128 bits (16 or 32 hex characters)" in story


@pytest.mark.parametrize("failure", ["slip", "wrong_sig", "bsms_version"])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
def test_failure_coordinator_round2(encryption_type, make_coordinator_round1, make_signer_round1, microsd_wipe, cap_menu,
                                    pick_menu_item, press_select, goto_home, cap_story, failure,
                                    need_keypress):
    microsd_wipe()

    def get_token(index):
        if len(tokens) == 1 and encryption_type == "1":
            token = tokens[0]
        elif len(tokens) == 2 and encryption_type == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    if failure == "bsms_version":
        kws = {failure: "BSMS 1.1"}
    else:
        kws = {failure: True}
    tokens = make_coordinator_round1(2, 2, "p2wsh", encryption_type, way="sd", tokens_only=True)
    for i in range(2):
        token = get_token(i)
        index = None
        if encryption_type != "2":
            index = i + 1
        make_signer_round1(token, "sd", purge_bsms=False, index=index, **kws)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 2
    coord_menu_item = coordinator_label(2, 2, "p2wsh", encryption_type, index=1)
    assert coord_menu_item in menu
    pick_menu_item(coord_menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import co-signer round 1 files from SD Card" in story:
        need_keypress("1")
    press_select()  # continue with manual file selection
    suffix = ".txt" if encryption_type == "3" else ".dat"
    for i, _ in enumerate(range(2), start=1):
        token = get_token(i - 1)
        time.sleep(0.1)
        title, story = cap_story()
        if encryption_type == "2":
            expect = 'Select co-signer #%d file containing round 1 data for token starting with %s' % (i, token[:4])
        else:
            expect = 'Select co-signer #%d file containing round 1 data' % i
        expect += '. File extension has to be "%s"' % suffix
        assert expect in story
        press_select()
        menu_item = bsms_sr1_fname(token, encryption_type == "2", suffix, i)
        pick_menu_item(menu_item)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "FAILURE"
    assert "BSMS coordinator round2 failed" in story
    if failure == "slip":
        failure_msg = "no slip"
    elif failure == "wrong_sig":
        failure_msg = "Recovered key from signature does not equal key provided. Wrong signature?"
    else:
        failure_msg = "Incompatible BSMS version. Need BSMS 1.0 got BSMS 1.1"
    assert failure_msg in story


# TODO do this for NFC too when length requirements are lifted from 250
@pytest.mark.parametrize("encryption_type", ["1", "2"])
def test_wrong_encryption_coordinator_round2(encryption_type, make_coordinator_round1, make_signer_round1, microsd_wipe,
                                             cap_menu, pick_menu_item, need_keypress, goto_home, cap_story,
                                             press_cancel, press_select):
    def get_token(index):
        if len(tokens) == 1 and encryption_type == "1":
            token = tokens[0]
        elif len(tokens) == 2 and encryption_type == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    microsd_wipe()
    tokens = make_coordinator_round1(2, 2, "p2wsh", encryption_type, way="sd", tokens_only=True)
    for i in range(2):
        token = get_token(i)
        index = None
        if encryption_type == "1":
            index = i + 1
        make_signer_round1(token, "sd", purge_bsms=False, index=index, wrong_encryption=True)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 2
    coord_menu_item = coordinator_label(2, 2, "p2wsh", encryption_type, index=1)
    assert coord_menu_item in menu
    pick_menu_item(coord_menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import co-signer round 1 files from SD Card" in story:
        need_keypress("1")
    press_select()  # continue with manual file selection
    suffix = ".txt" if encryption_type == "3" else ".dat"
    for i, _ in enumerate(range(2), start=1):
        for attempt in range(2):
            token = get_token(i - 1)
            time.sleep(0.1)
            title, story = cap_story()
            if encryption_type == "2":
                expect = 'Select co-signer #%d file containing round 1 data for token starting with %s' % (i, token[:4])
            else:
                expect = 'Select co-signer #%d file containing round 1 data' % i
            expect += '. File extension has to be "%s"' % suffix
            assert expect in story
            press_select()
            menu_item = bsms_sr1_fname(token, encryption_type == "2", suffix, i)
            pick_menu_item(menu_item)
            time.sleep(0.1)
            _, story = cap_story()
            expect_story = "Decryption failed for co-signer #%d" % i
            if encryption_type == 2:
                expect_story += " with token %s" % token[:4]
            assert expect_story in story
            if attempt == 0:
                assert "Try again?" in story
                press_select()
            else:
                assert "Try again?" not in story
                press_cancel()
                break
        break


@pytest.mark.parametrize("failure", [
    "wrong_address", "path_restrictions", "bsms_version", "sortedmulti", "has_ours", "ours_no",
    "wrong_encryption", "wrong_chain", "wrong_checksum"
])
@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
def test_failure_signer_round2(encryption_type, goto_home, press_select, pick_menu_item, cap_menu, cap_story,
                               microsd_path, settings_remove, nfc_read_text, virtdisk_path, settings_get, microsd_wipe,
                               make_coordinator_round2, failure, need_keypress):
    microsd_wipe()
    if failure == "wrong_address":
        kws = {failure: True}
        failure_msg = "Address mismatch!"
    elif failure == "path_restrictions":
        kws = {failure: "5/*,4/*"}
        failure_msg = "Only '/0/*,/1/*' allowed as path restrictions."
    elif failure == "bsms_version":
        kws = {failure: "BSMS 2.0"}
        failure_msg = "Incompatible BSMS version. Need BSMS 1.0 got BSMS 2.0"
    elif failure == "sortedmulti":
        kws = {failure: False}
        failure_msg = "Unsupported descriptor. Supported: sh(, sh(wsh(, wsh(. MUST be sortedmulti."
    elif failure == "has_ours":
        kws = {failure: False}
        failure_msg = "My key 0F056943 missing in descriptor."
    elif failure == "ours_no":
        kws = {failure: 2}
        failure_msg = "Multiple 0F056943 keys in descriptor (2)"
    elif failure == "wrong_chain":
        kws = {failure: True}
        failure_msg = "wrong chain"
    elif failure == "wrong_checksum":
        kws = {failure: True}
        failure_msg = "Wrong checksum"
    else:
        assert failure == "wrong_encryption"
        if encryption_type == "3":
            pytest.skip("Cannot test wrong encryption on unencrypted BSMS")
        kws = {failure: True}
        failure_msg = "Decryption with token {token} failed."

    desc_template, token = make_coordinator_round2(2, 2, "p2wsh", encryption_type, way="sd", **kws)
    failure_msg = failure_msg.format(token=token[:4])
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    menu_item = "1   %s" % token[:4]
    pick_menu_item(menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import descriptor template file from SD Card" in story:
        need_keypress("1")

    suffix = ".txt" if encryption_type == "3" else ".dat"
    time.sleep(0.1)
    menu_item = bsms_cr2_fname(token, encryption_type == "2", suffix)
    pick_menu_item(menu_item)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "FAILURE"
    assert "BSMS signer round2 failed" in story
    assert failure_msg in story


@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
def test_integration_signer(encryption_type, M_N, addr_fmt, clear_ms, microsd_wipe, goto_home, pick_menu_item, cap_story,
                            press_select, settings_remove, microsd_path, settings_get, cap_menu, use_mainnet,
                            need_keypress):
    # test CC signer full with bsms lib coordinator (test just SD card no need to retest IO paths again - tested above)
    def get_token(index):
        if len(tokens) == 1 and encryption_type == "1":
            token = tokens[0]
        elif len(tokens) == N and encryption_type == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    M, N = M_N
    settings_remove(BSMS_SETTINGS)
    use_mainnet()
    clear_ms()
    microsd_wipe()
    coordinator = CoordinatorSession(M, N, addr_fmt, et_map[encryption_type])
    session_data = coordinator.generate_token_key_pairs()
    tokens = [x[0] for x in session_data]
    cc_token = get_token(0)
    other_signers = []
    for i in range(1, N):
        other_signers.append(Signer(token=get_token(i), key_description="Other signer %d" % i))
    # ROUND 1
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    pick_menu_item('Round 1')
    time.sleep(0.1)
    _, story = cap_story()
    if encryption_type == "3":
        need_keypress("3")  # no token (unencrypted BSMS)
    else:
        fname = "bsms_%s.token" % cc_token[:4] if cc_token != "00" else "1"
        with open(microsd_path(fname), "w") as f:
            f.write(cc_token)
        if "Press (1) to import token file from SD Card" in story:
            need_keypress("1")
        time.sleep(0.2)
        fname = "bsms_%s.token" % cc_token[:4]
        pick_menu_item(fname)

    time.sleep(0.1)
    title, story = cap_story()
    assert "You have entered token:\n%s" % cc_token in story
    press_select()
    time.sleep(0.1)
    _, story = cap_story()
    # address format a.k.a. SLIP derivation path - ignore and use SLIP agnostic
    assert "Choose co-signer address format for correct SLIP derivation path" in story
    press_select()
    # account number prompt
    press_select()
    time.sleep(0.1)
    _, story = cap_story()
    # textual key description
    assert "Choose key description" in story
    press_select()  # default
    time.sleep(0.1)
    title, story = cap_story()
    suffix = ".txt" if encryption_type == "3" else ".dat"
    mode = "rt" if encryption_type == "3" else "rb"
    if "Press (1) to save BSMS signer round 1 file to SD Card" in story:
        need_keypress("1")
    time.sleep(0.2)
    _, story = cap_story()
    assert 'BSMS signer round 1 file written' in story
    fname = story.split('\n\n')[-1]
    assert suffix in fname
    path = microsd_path(fname)
    with open(path, mode) as f:
        signer_r1 = f.read()

    bsms = settings_get(BSMS_SETTINGS)
    assert len(bsms[BSMS_SIGNER_SETTINGS]) == 1
    assert bsms[BSMS_SIGNER_SETTINGS][0] == cc_token

    # ROUND 2
    all_r1_data = [signer_r1.hex() if encryption_type != "3" else signer_r1]
    for s in other_signers:
        all_r1_data.append(s.round_1())

    descriptor_templates = coordinator.round_2(all_r1_data)
    if encryption_type == "2":
        assert len(descriptor_templates) == N
        for signer, tmplt in zip(other_signers, descriptor_templates[1:]):
            signer.round_2(tmplt)
    else:
        assert len(descriptor_templates) == 1
        for signer in other_signers:
            signer.round_2(descriptor_templates[0])

    cc_desc_template = descriptor_templates[0]  # zeroeth as our token is zero too
    suffix = ".txt" if encryption_type == "3" else ".dat"
    mode = "wt" if encryption_type == "3" else "wb"
    fname = bsms_cr2_fname(cc_token, encryption_type == "2", suffix)
    with open(microsd_path(fname), mode) as f:
        f.write(bytes.fromhex(cc_desc_template) if mode == "wb" else cc_desc_template)
    time.sleep(0.1)
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Signer')
    menu_item = "1   %s" % cc_token[:4]
    pick_menu_item(menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import descriptor template file from SD Card" in story:
        need_keypress("1")
    time.sleep(0.1)
    menu_item = bsms_cr2_fname(cc_token, encryption_type == "2", suffix)
    pick_menu_item(menu_item)
    time.sleep(0.1)
    title, story = cap_story()
    assert "Create new multisig wallet?" in story
    assert "bsms" in story  # part of the name
    policy = "Policy: %d of %d" % (M, N)
    assert policy in story
    assert addr_fmt.upper() in story
    ms_wal_name = story.split("\n\n")[1].split("\n")[-1].strip()
    ms_wal_menu_item = "%d/%d: %s" % (M, N, ms_wal_name)
    press_select()
    time.sleep(0.1)
    menu = cap_menu()
    assert ms_wal_menu_item in menu
    bsms_settings = settings_get(BSMS_SETTINGS)
    # signer round 2 removed
    assert not bsms_settings.get(BSMS_SIGNER_SETTINGS, None)


@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2,2), (3, 5), (15, 15)])
@pytest.mark.parametrize("addr_fmt", ["p2wsh", "p2sh-p2wsh"])
@pytest.mark.parametrize("cr1_shortcut", [True, False])
def test_integration_coordinator(encryption_type, M_N, addr_fmt, clear_ms, microsd_wipe, goto_home, pick_menu_item,
                                 cap_story, need_keypress, settings_remove, microsd_path, settings_get, cap_menu,
                                 use_mainnet, cr1_shortcut, press_select):
    M, N = M_N
    settings_remove(BSMS_SETTINGS)
    use_mainnet()
    clear_ms()
    microsd_wipe()
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 1  # nothing should be in menu at this point but round 1
    pick_menu_item('Create BSMS')
    # choose number of signers N
    for num in str(N):
        need_keypress(num)
    press_select()
    # choose threshold M
    for num in str(M):
        need_keypress(num)
    press_select()
    if addr_fmt == "p2wsh":
        press_select()
    else:
        need_keypress("2")
    time.sleep(0.1)
    title, story = cap_story()
    assert story == "Choose encryption type. Press (1) for STANDARD encryption, (2) for EXTENDED, and (3) for no encryption"
    need_keypress(encryption_type)
    time.sleep(0.1)
    title, story = cap_story()
    assert_coord_summary(title, story, M, N, addr_fmt, encryption_type)
    press_select()  # confirm summary
    time.sleep(0.1)
    title, story = cap_story()
    assert "Press (1) to participate as co-signer in this BSMS" in story
    if cr1_shortcut:
        _start_idx = 1
        need_keypress("1")
        press_select()  # slip
        press_select()  # acct num 0
        press_select()  # default textual key description
        time.sleep(0.1)
        _, story = cap_story()
        if "Press (1) to save BSMS signer round 1 file to SD Card" in story:
            need_keypress("1")
        time.sleep(0.2)
        _, story = cap_story()
        shortcut_fname = story.split("\n\n")[-1]
        press_select() # looking at save sr1 filename
    else:
        _start_idx = 0
        press_select() # continue normally

    time.sleep(0.1)
    title, story = cap_story()
    read_tokens = []
    if encryption_type == "3":
        assert story == "Success. Coordinator round 1 saved."
    else:
        if "Press (1) to save BSMS token file(s) to SD Card" in story:
            need_keypress("1")
        time.sleep(0.2)
        _, story = cap_story()
        assert 'BSMS token file(s) written' in story
        fnames = story.split('\n\n')[2:]
        for fname in fnames:
            path = microsd_path(fname)
            with open(path, 'rt') as f:
                tok = f.read().strip()
                read_tokens.append(tok)

    all_signers = []
    if encryption_type == "1":
        assert len(read_tokens) == 1
        for i in range(_start_idx, N):
            all_signers.append(Signer(read_tokens[0], "key %d" % i))
    elif encryption_type == "2":
        assert len(read_tokens) == (N - _start_idx)
        for i in range(N - _start_idx):
            all_signers.append(Signer(read_tokens[i], "key %d" % i))
    else:
        assert len(read_tokens) == 0
        for i in range(N - _start_idx):
            all_signers.append(Signer("00", "key %d" % i))

    press_select()  # confirm success or files written story
    time.sleep(0.1)
    menu = cap_menu()
    assert len(menu) == 2
    current_coord_menu_item = coordinator_label(M, N, addr_fmt, encryption_type, index=1)
    assert menu[0] == current_coord_menu_item
    # check correct coord tuple saved
    bsms_settings = settings_get(BSMS_SETTINGS)
    if BSMS_SIGNER_SETTINGS in bsms_settings:
        if cr1_shortcut:
            assert len(bsms_settings[BSMS_SIGNER_SETTINGS]) == 1
            shortcut_token = bsms_settings[BSMS_SIGNER_SETTINGS][0]
        else:
            assert bsms_settings[BSMS_SIGNER_SETTINGS] == []
            shortcut_token = None
    coord_settings = bsms_settings[BSMS_COORD_SETTINGS]
    assert len(coord_settings) == 1
    if read_tokens:
        expect_tokens = [tok.split(" ")[-1] for tok in read_tokens]
        if cr1_shortcut and encryption_type == "2":
            expect_tokens = [shortcut_token] + expect_tokens
    else:
        expect_tokens = []
    assert coord_settings[0] == (M, N, af_map[addr_fmt], encryption_type, expect_tokens)

    # ROUND 2
    def get_token(index):
        if len(read_tokens) == 1 and encryption_type == "1":
            token = read_tokens[0]
        elif encryption_type == "2":
            token = read_tokens[index]
        else:
            token = "00"
        return token

    all_r1_signer_data = [s.round_1() for s in all_signers]
    mode = "wt" if encryption_type == "3" else "wb"
    suffix = ".txt" if encryption_type == "3" else ".dat"
    for i, data in enumerate(all_r1_signer_data, start=1):
        token = get_token(i - 1)
        fname = bsms_sr1_fname(token, encryption_type == "2", suffix, i)
        with open(microsd_path(fname), mode) as f:
            f.write(bytes.fromhex(data) if mode == "wb" else data)

    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    menu = cap_menu()
    assert len(menu) == 2
    coord_menu_item = coordinator_label(M, N, addr_fmt, encryption_type, index=1)
    assert coord_menu_item in menu
    pick_menu_item(coord_menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import co-signer round 1 files from SD Card" in story:
        need_keypress("1")
    press_select()  # continue with manual file selection
    if cr1_shortcut:
        time.sleep(0.1)
        title, story = cap_story()
        if encryption_type == "2":
            expect = 'Select co-signer #1 file containing round 1 data for token starting with %s' % shortcut_token[:4]
        else:
            expect = 'Select co-signer #1 file containing round 1 data'
        assert expect in story
        press_select()
        pick_menu_item(shortcut_fname)
    for i in range(_start_idx, N):
        token = get_token(i - _start_idx)
        time.sleep(0.1)
        title, story = cap_story()
        if encryption_type == "2":
            expect = 'Select co-signer #%d file containing round 1 data for token starting with %s' % (i + 1, token[:4])
        else:
            expect = 'Select co-signer #%d file containing round 1 data' % (i + 1)
        expect += '. File extension has to be "%s"' % suffix
        assert expect in story
        press_select()
        fname = bsms_sr1_fname(token, encryption_type == "2", suffix, i + 1 - _start_idx)
        pick_menu_item(fname)

    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to save BSMS descriptor template file(s) to SD Card" in story:
        need_keypress("1")
    time.sleep(0.1)
    _, story = cap_story()
    assert "BSMS descriptor template file(s) written." in story
    fnames = story.split("\n\n")[1:]
    if encryption_type == "2":
        if cr1_shortcut:
            read_tokens = [shortcut_token] + read_tokens
        for fname, token in zip(fnames, read_tokens):
            assert token[:4] in fname
    descriptor_templates = []
    for fname in fnames:
        with open(microsd_path(fname), "rt" if encryption_type == "3" else "rb") as f:
            desc_temp = f.read()
            descriptor_templates.append(desc_temp)
    if len(descriptor_templates) == 1:
        target = descriptor_templates[0]
        if isinstance(target, bytes):
            target = target.hex()
        for signer in all_signers:
            signer.round_2(target)
    else:
        if cr1_shortcut:
            _, descriptor_templates = descriptor_templates[0], descriptor_templates[1:]
        for signer, desc_tmplt in zip(all_signers, descriptor_templates):
            if isinstance(desc_tmplt, bytes):
                desc_tmplt = desc_tmplt.hex()
            signer.round_2(desc_tmplt)
    if cr1_shortcut:
        # still need to add our signer
        goto_home()
        pick_menu_item('Settings')
        pick_menu_item('Multisig Wallets')
        pick_menu_item('BSMS (BIP-129)')
        press_select()
        pick_menu_item('Signer')
        menu_item = "1   %s" % shortcut_token[:4]
        pick_menu_item(menu_item)
        pick_menu_item("Round 2")
        time.sleep(0.1)
        _, story = cap_story()
        if "Press (1) to import descriptor template file from SD Card" in story:
            need_keypress("1")
        time.sleep(0.1)
        pick_menu_item(fnames[0])
        time.sleep(0.1)
        title, story = cap_story()
        assert "Create new multisig wallet?" in story
        assert "bsms" in story  # part of the name
        policy = "Policy: %d of %d" % (M, N)
        assert policy in story
        assert addr_fmt.upper() in story
        ms_wal_name = story.split("\n\n")[1].split("\n")[-1].strip()
        ms_wal_menu_item = "%d/%d: %s" % (M, N, ms_wal_name)
        press_select()
        time.sleep(0.1)
        menu = cap_menu()
        assert ms_wal_menu_item in menu
        bsms_settings = settings_get(BSMS_SETTINGS)
        # signer round 2 removed
        assert not bsms_settings.get(BSMS_SIGNER_SETTINGS, None)



@pytest.mark.parametrize("encryption_type", ["1", "2", "3"])
@pytest.mark.parametrize("M_N", [(2, 2), (3, 5), (15, 15)])
def test_auto_collection_coordinator_r2(encryption_type, M_N, goto_home, need_keypress, pick_menu_item, microsd_wipe,
                                        cap_story, microsd_path,make_coordinator_round1, make_signer_round1,
                                        press_select):
    M, N = M_N
    microsd_wipe()

    def get_token(index):
        if len(tokens) == 1 and encryption_type == "1":
            token = tokens[0]
        elif len(tokens) == N and encryption_type == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    # add twice as many files with different tokens - should be still able to collect the correct ones
    f_pattern = "bsms_sr1"
    if encryption_type == "2":
        suffix = ".dat"
        for i in range(N):
            token = os.urandom(16).hex()
            s = Signer(token=token, key_description="key%d" % i)
            r1 = s.round_1()
            fname = "%s_%s%s" % (f_pattern, token[:4], suffix)
            with open(microsd_path(fname), "wb") as f:
                f.write(bytes.fromhex(r1))

    elif encryption_type == "1":
        suffix = ".dat"
        for i in range(N):
            token = os.urandom(8).hex()
            s = Signer(token=token, key_description="key%d" % i)
            r1 = s.round_1()
            fname = "%s%s" % (f_pattern, suffix)
            with open(microsd_path(fname), "wb") as f:
                f.write(bytes.fromhex(r1))

    else:
        suffix = ".txt"
        for i in range(N):
            s = Signer(token="00", key_description="key%d" % i)
            r1 = s.round_1()
            fname = "%s%s" % (f_pattern, suffix)
            with open(microsd_path(fname), "w") as f:
                f.write(r1)

    tokens = make_coordinator_round1(M, N, "p2wsh", encryption_type, way="sd", tokens_only=True)
    all_data = []
    for i in range(N):
        token = get_token(i)
        index = None
        if encryption_type == "1":
            index = i + 1
        all_data.append(make_signer_round1(token, "sd", purge_bsms=False, index=index))
    goto_home()
    pick_menu_item('Settings')
    pick_menu_item('Multisig Wallets')
    pick_menu_item('BSMS (BIP-129)')
    title, story = cap_story()
    assert "Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets." in story
    assert "WARNING: BSMS is an EXPERIMENTAL and BETA feature" in story
    press_select()
    pick_menu_item('Coordinator')
    coord_menu_item = coordinator_label(M, N, "p2wsh", encryption_type, index=1)
    pick_menu_item(coord_menu_item)
    pick_menu_item("Round 2")
    time.sleep(0.1)
    _, story = cap_story()
    if "Press (1) to import co-signer round 1 files from SD Card" in story:
            need_keypress("1")
    need_keypress("1") # auto-collection
    time.sleep(0.1)
    title, story = cap_story()
    if encryption_type == "3":
        # we need exact number of files for unencrypted as we would have no idea which are part of this multisig setup
        assert "Auto-collection failed. Defaulting to manual selection of files." in story
    else:
        if "Press (1) to save BSMS descriptor template file(s) to SD Card" in story:
            # if NFC or Vdisk enabled - but means auto-collection was successful and we are prompted where to
            # save the resulting descriptor (coordinator round2 data)
            assert True
        else:
            # NFC and Vdisk disabled, automatically written to SD card - success
            assert "BSMS descriptor template file(s) written" in story
