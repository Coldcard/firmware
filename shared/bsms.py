
# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# bsms.py - Bitcoin Secure Multisig Setup: BIP-129
#
# For faster testing...
#   ./simulator.py --seq 99y3y4y
#
import ngu, os, stash, chains, aes256ctr, version
from ubinascii import b2a_base64, a2b_base64
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex

from public_constants import AF_P2WSH, AF_P2WSH_P2SH, AF_CLASSIC, MAX_SIGNERS
from utils import xfp2str, problem_file_line
from menu import MenuSystem, MenuItem
from files import CardSlot, CardMissingError, needs_microsd
from ux import ux_show_story, ux_enter_number, restore_menu, ux_input_numbers, ux_input_text
from ux import the_ux, _import_prompt_builder, export_prompt_builder
from descriptor import Descriptor, Key, append_checksum
from miniscript import Sortedmulti, Number
from charcodes import KEY_NFC, KEY_QR


BSMS_VERSION = "BSMS 1.0"
ALLOWED_PATH_RESTRICTIONS = "/0/*,/1/*"

ENCRYPTION_TYPES = {
    "1": "STANDARD",
    "2": "EXTENDED",
    "3": "NO ENCRYPTION"
}

class RejectAutoCollection(BaseException):
    pass

class BSMSOutOfSpace(RuntimeError):
    # should not be a concern on Mk4 and later; just in case, handle well.
    pass

def exceptions_handler(f):
    nice_name = " ".join(f.__name__.split("_")).replace("bsms", "BSMS")
    async def new_func(*args):
        try:
            await f(*args)
        except BaseException as e:
            await ux_show_story(title="FAILURE", msg='%s\n\n%s failed\n%s' % (e, nice_name, problem_file_line(e)))
    return new_func


def normalize_token(token_hex):
    if token_hex[:2] in ["0x", "0X"]:
        token_hex = token_hex[2:]  # remove 0x prefix
    return token_hex


def validate_token(token_hex):
    if token_hex == "00":
        return
    try:
        int(token_hex, 16)
    except:
        raise ValueError("Invalid token: %s" % token_hex)
    if len(token_hex) not in [16, 32]:
        raise ValueError("Invalid token length. Expected 64 or 128 bits (16 or 32 hex characters)")


def key_derivation_function(token_hex):
    if token_hex == "00":
        return
    return ngu.hash.pbkdf2_sha512("No SPOF", a2b_hex(token_hex), 2048)[:32]


def hmac_key(key):
    return ngu.hash.sha256s(key)


def msg_auth_code(key, token_hex, data):
    msg_str = token_hex + data
    msg_bytes = bytes(msg_str, "utf-8")
    return ngu.hmac.hmac_sha256(key, msg_bytes)


def bsms_decrypt(key, data_bytes):
    mac, ciphertext = data_bytes[:32], data_bytes[32:]
    iv = mac[:16]
    decrypt = aes256ctr.new(key, iv)
    decrypted = decrypt.cipher(ciphertext)
    try:
        plaintext = decrypted.decode()
        if not plaintext.startswith("BSMS"):
            raise ValueError
        return plaintext
    except:
        # failed decryption
        return ""


def bsms_encrypt(key, token_hex, data_str):
    hmac_k = hmac_key(key)
    mac = msg_auth_code(hmac_k, token_hex, data_str)
    iv = mac[:16]
    encrypt = aes256ctr.new(key, iv)
    ciphertext = encrypt.cipher(data_str)

    return mac + ciphertext


def signer_data_round1(token_hex, desc_type_key, key_description, sig_bytes=None):
    result = "%s\n" % BSMS_VERSION
    result += "%s\n" % token_hex
    result += "%s\n" % desc_type_key
    result += "%s" % key_description

    if sig_bytes:
        sig = b2a_base64(sig_bytes).decode().strip()
        result += "\n" + sig

    return result


def coordinator_data_round2(desc_template, addr, path_restrictions=ALLOWED_PATH_RESTRICTIONS):
    result = "%s\n" % BSMS_VERSION
    result += "%s\n" % desc_template
    result += "%s\n" % path_restrictions
    result += "%s" % addr

    return result


def token_summary(tokens):
    if len(tokens) == 1:
        return tokens[0]

    numbered_tokens = ["%d. %s" % (i, token) for i, token in enumerate(tokens, start=1)]
    return "\n\n".join(numbered_tokens)


def coordinator_summary(M, N, addr_fmt, et, tokens):
    addr_fmt_str = "p2wsh" if addr_fmt == AF_P2WSH else "p2sh-p2wsh"
    summary = "%d of %d\n\n" % (M, N)
    summary += "Address format:\n%s\n\n" % addr_fmt_str
    summary += "Encryption type:\n%s\n\n" % ENCRYPTION_TYPES[et]

    if tokens:
        summary += "Tokens:\n" + token_summary(tokens) + "\n\n"

    return summary


class BSMSSettings:
    # keys in settings object
    BSMS_SETTINGS = "bsms"
    BSMS_SIGNER_SETTINGS = "s"
    BSMS_COORD_SETTINGS = "c"

    @classmethod
    def save(cls, updated_settings, orig):
        try:
            updated_settings.save()
        except:
            # back out change; no longer sure of NVRAM state
            try:
                updated_settings.set(cls.BSMS_SETTINGS, orig)
                updated_settings.save()
            except:
                pass  # give up on recovery
            raise BSMSOutOfSpace

    @classmethod
    def add(cls, who, value):
        from glob import settings

        settings_bsms = settings.get(cls.BSMS_SETTINGS, {})
        orig = settings_bsms.copy()
        if who in settings_bsms:
            settings_bsms[who].append(value)
        else:
            settings_bsms[who] = [value]

        settings.set(cls.BSMS_SETTINGS, settings_bsms)
        cls.save(settings, orig)

    @classmethod
    def delete(cls, who, index):
        from glob import settings

        settings_bsms = settings.get(cls.BSMS_SETTINGS, {})
        orig = settings_bsms.copy()
        if who in settings_bsms:
            try:
                settings_bsms[who].pop(index)
                settings.set(cls.BSMS_SETTINGS, settings_bsms)
                cls.save(settings, orig)
            except IndexError:
                pass

    @classmethod
    def signer_add(cls, token_hex):
        cls.add(cls.BSMS_SIGNER_SETTINGS, token_hex)

    @classmethod
    def coordinator_add(cls, config_tuple):
        cls.add(cls.BSMS_COORD_SETTINGS, config_tuple)

    @classmethod
    def signer_delete(cls, index):
        cls.delete(cls.BSMS_SIGNER_SETTINGS, index)

    @classmethod
    def coordinator_delete(cls, index):
        cls.delete(cls.BSMS_COORD_SETTINGS, index)

    @classmethod
    def get(cls):
        from glob import settings
        return settings.get(cls.BSMS_SETTINGS, {})

    @classmethod
    def get_signers(cls):
        bsms = cls.get()
        return bsms.get(cls.BSMS_SIGNER_SETTINGS, [])

    @classmethod
    def get_coordinators(cls):
        bsms = cls.get()
        return bsms.get(cls.BSMS_COORD_SETTINGS, [])


class BSMSMenu(MenuSystem):
    @classmethod
    def construct(cls):
        raise NotImplementedError

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)


async def user_delete_signer_settings(menu, label, item):
    index = item.arg
    BSMSSettings.signer_delete(index)
    the_ux.pop()
    restore_menu()

async def bsms_signer_detail(menu, label, item):
    token_hex = BSMSSettings.get_signers()[item.arg]
    # shoulf not raise here, as token is only saved if properly validated
    token_dec = str(int(token_hex, 16))
    await ux_show_story("Token HEX:\n%s\n\nToken decimal:\n%s" % (token_hex, token_dec))


async def bsms_coordinator_detail(menu, label, item):
    M, N, addr_fmt, et, tokens = BSMSSettings.get_coordinators()[item.arg]
    summary = coordinator_summary(M, N, addr_fmt, et, tokens)
    await ux_show_story(title="SUMMARY", msg=summary)


async def make_bsms_signer_r2_menu(menu, label, item):
    index = item.arg
    rv = [
        MenuItem('Round 2', f=bsms_signer_round2, arg=index),
        MenuItem('Detail', f=bsms_signer_detail, arg=index),
        MenuItem('Delete', f=user_delete_signer_settings, arg=index),
    ]
    return rv


class BSMSSignerMenu(BSMSMenu):
    @classmethod
    def construct(cls):
        # Dynamic
        rv = []
        signers = BSMSSettings.get_signers()
        if signers:
            for i, token_hex in enumerate(signers):
                label = "%d   %s" % (i+1, token_hex[:4])
                rv.append(MenuItem('%s' % label, menu=make_bsms_signer_r2_menu, arg=i))
        rv.append(MenuItem('Round 1', f=bsms_signer_round1))

        return rv


async def user_delete_coordinator_settings(menu, label, item):
    index = item.arg
    BSMSSettings.coordinator_delete(index)
    the_ux.pop()
    restore_menu()


async def make_bsms_coord_r2_menu(menu, label, item):
    index = item.arg
    rv = [
        MenuItem('Round 2', f=bsms_coordinator_round2, arg=index),
        MenuItem('Detail', f=bsms_coordinator_detail, arg=index),
        MenuItem('Delete', f=user_delete_coordinator_settings, arg=index),
    ]
    return rv


class BSMSCoordinatorMenu(BSMSMenu):
    @classmethod
    def construct(cls):
        # Dynamic
        rv = []
        coordinators = BSMSSettings.get_coordinators()
        if coordinators:
            for i, (M, N, addr_fmt, et, tokens) in enumerate(coordinators):
                # only p2wsh and p2sh-p2wsh are allowed
                if addr_fmt == AF_P2WSH:
                    af_str = "native"
                else:
                    af_str = "nested"
                label = "%d %dof%d_%s_%s" % (i+1, M, N, af_str, et)
                rv.append(MenuItem('%s' % label, menu=make_bsms_coord_r2_menu, arg=i))
        rv.append(MenuItem('Create BSMS', f=bsms_coordinator_start))

        return rv


async def make_ms_wallet_bsms_menu(menu, label, item):
    from pincodes import pa

    if pa.is_secret_blank():
        await ux_show_story("You must have wallet seed before creating multisig wallets.")
        return

    await ux_show_story(
"Bitcoin Secure Multisig Setup (BIP-129) is a mechanism to securely create multisig wallets. "
"On the next screen you choose your role in this process.\n\n"
"WARNING: BSMS is an EXPERIMENTAL and BETA feature which requires supporting implementations "
"on other signing devices to work properly. Please test the final wallet carefully "
"and report any problems to appropriate vendor. Deposit only small test amounts and verify "
"all co-signers can sign transactions before use.")
    rv = [
        MenuItem('Signer', menu=make_bsms_signer_menu),
        MenuItem('Coordinator', menu=make_bsms_coordinator_menu),
    ]
    return rv


async def make_bsms_signer_menu(menu, label, item):
    rv = BSMSSignerMenu.construct()
    return BSMSSignerMenu(rv)


async def make_bsms_coordinator_menu(menu, label, item):
    rv = BSMSCoordinatorMenu.construct()
    return BSMSCoordinatorMenu(rv)


async def decrypt_nfc_data(key, data):
    try:
        data_bytes = a2b_hex(data)
        data = bsms_decrypt(key, data_bytes)
        return data
    except:
        # will be offered another chance
        return

@exceptions_handler
async def bsms_coordinator_start(*a):
    from glob import NFC, dis, settings
    xfp = xfp2str(settings.get('xfp', 0))
    # M/N
    N = await ux_enter_number('No. of signers?(N)', 15)
    assert 2 <= N <= MAX_SIGNERS, "Number of co-signers must be 2-15"

    M = await ux_enter_number("Threshold? (M)", 15)
    assert 1 <= M <= N, "M cannot be bigger than N (N=%d)" % N

    ch = await ux_show_story("Default address format is P2WSH.\n\n"
                             "Press (2) for P2SH-P2WSH instead.", escape='2')
    if ch == 'y':
        addr_fmt = AF_P2WSH
    elif ch == '2':
        addr_fmt = AF_P2WSH_P2SH
    else:
        return

    while 1:
        encryption_type = await ux_show_story(
            "Choose encryption type. Press (1) for STANDARD encryption, (2) for EXTENDED,"
            " and (3) for no encryption", escape="123")

        if encryption_type == 'x': return
        if encryption_type in "123":
            break

    tokens = []
    if encryption_type == "2":
        dis.fullscreen('Generating...')
        for i in range(N):  # each signer different 16 bytes (128bits) nonce/token
            tokens.append(b2a_hex(ngu.random.bytes(16)).decode())
            dis.progress_bar_show(i / N)
    elif encryption_type == "1":
        tokens.append(b2a_hex(ngu.random.bytes(8)).decode())  # all signers same token

    summary = coordinator_summary(M, N, addr_fmt, encryption_type, tokens)
    summary += "Press OK to continue, or X to cancel"
    ch = await ux_show_story(title="SUMMARY", msg=summary)
    if ch != "y":
        return

    token_hex = "00" if not tokens else tokens[0]
    ch = await ux_show_story("Press (1) to participate as co-signer in this BSMS "
                             "with current active key [%s] and token '%s'. "
                             "Press OK to continue normally." % (xfp, token_hex), escape="1")
    export_tokens = tokens[:]
    if ch == "1":
        b4 = len(BSMSSettings.get_signers())
        await bsms_signer_round1(token_hex)
        current = BSMSSettings.get_signers()
        if len(current) > b4 and token_hex in current:
            if encryption_type == "2":
                # remove 0th token from the list as we already used that for self
                # we do not need this token for export, but still need to store it in settings
                export_tokens = tokens[1:]

    force_vdisk = False
    title = "BSMS token file(s)"
    prompt, escape = export_prompt_builder(title)
    if tokens and prompt:
        ch = await ux_show_story(prompt, escape=escape)
        if ch == (KEY_NFC if version.has_qwerty else '3') and tokens:
            force_vdisk = None
            await NFC.share_text(token_summary(export_tokens))
        elif ch == "2":
            force_vdisk = True
        elif ch == '1':
            force_vdisk = False
        else:
            return

    msg = "Success. Coordinator round 1 saved."
    if tokens and force_vdisk is not None:
        dis.fullscreen("Saving...")
        f_pattern = "bsms"
        f_names = []
        try:
            with CardSlot(force_vdisk=force_vdisk) as card:
                for i, token in enumerate(export_tokens, start=1):
                    f_name = "%s_%s.token" % (f_pattern, token[:4])
                    fname, nice = card.pick_filename(f_name)
                    with open(fname, 'wt') as fd:
                        fd.write(token)
                    f_names.append(nice)
                    dis.progress_bar_show(i / len(tokens))
        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n\n' + str(e))
            return
        msg = '''%s written.\n\nFiles:\n\n%s''' % (title, "\n\n".join(f_names))

    BSMSSettings.coordinator_add((M, N, addr_fmt, encryption_type, tokens))
    await ux_show_story(msg)
    restore_menu()


async def nfc_import_signer_round1_data(N, tkm, et, get_token_func):
    from glob import NFC

    all_data = []
    for i in range(N):
        token = get_token_func(i)
        for attempt in range(2):
            prompt = "Share co-signer #%d round-1 data" % (i + 1)
            if et == "2":
                prompt += " for token starting with %s" % token[:4]
            ch = await ux_show_story(prompt)
            if ch != "y":
                return

            data = await NFC.read_bsms_data()
            if et in "12":
                encryption_key = key_derivation_function(token)
                data = await decrypt_nfc_data(encryption_key, data)
                if not data:
                    fail_msg = "Decryption failed for co-signer #%d" % (i + 1)
                    if et == "2":
                        fail_msg += " with token %s" % token[:4]
                    ch = await ux_show_story(
                        title="FAILURE",
                        msg=fail_msg + ". Try again?" if attempt == 0 else fail_msg)  # second chance
                    if ch == "y" and attempt == 0:
                        continue
                    else:
                        return
                tkm[token] = encryption_key

            all_data.append(data)
            break  # exit "second chance" loop
    return all_data

@exceptions_handler
async def bsms_coordinator_round2(menu, label, item):
    import version as version_mod
    from glob import NFC, dis
    from actions import file_picker
    from multisig import make_redeem_script

    bsms_settings_index = item.arg
    chain = chains.current_chain()

    force_vdisk = False

    # this can be RAM intensive (max 15 F mapped to keys)
    #  => ((32 + 16) * 15) roughly (actually more with python overhead)
    token_key_map = {}

    # choose correct values based on label (index in coordinator bsms settings)
    M, N, addr_fmt, et, tokens = BSMSSettings.get_coordinators()[bsms_settings_index]

    def get_token(index):
        if len(tokens) == 1 and et == "1":
            token = tokens[0]
        elif len(tokens) == N and et == "2":
            token = tokens[index]
        else:
            token = "00"
        return token

    is_encrypted = et in "12" and tokens
    suffix = ".dat" if is_encrypted else ".txt"
    mode = "rb" if is_encrypted else "rt"
    prompt, escape = _import_prompt_builder("co-signer round 1 files", False, False)
    if prompt:
        ch = await ux_show_story(prompt, escape=escape)
        if ch == (KEY_NFC if version_mod.has_qwerty else '3'):
            force_vdisk = None
            r1_data = await nfc_import_signer_round1_data(N, token_key_map, et, get_token)
        else:
            if ch == "1":
                force_vdisk = False
            else:
                force_vdisk = True

    if force_vdisk is not None:
        # auto-collection attempt
        r1_data = []
        try:
            f_pattern = "bsms_sr1"
            auto_msg = "Press OK to pick co-signer round 1 files manually, or press (1) to attempt auto-collection."
            auto_msg += " For auto-collection to succeed all filenames have to start with '%s'" % f_pattern
            auto_msg += " and end with extension '%s'." % suffix
            if et == "2":  # EXTENDED
                auto_msg += (" In addition for EXTENDED encryption all files must contain first four characters of"
                             " respective token. For example '%s_af9f%s'." % (f_pattern, suffix))
            elif et == "3":  # NO_ENCRYPTION
                auto_msg += (" In addition for NO ENCRYPTION cases, number of files with above mentioned"
                             " pattern and suffix must equal number of signers (N).")
            auto_msg += " If above is not respected auto-collection fails and defaults to manual selection of files."
            ch = await ux_show_story(auto_msg, escape="1")
            if ch == "x": return  # exit
            if ch == "y": raise RejectAutoCollection
            # try autodiscovery first - if failed - default to manual input
            dis.fullscreen("Collecting...")
            file_names = []
            with CardSlot(force_vdisk=force_vdisk) as card:
                f_list = os.listdir(card.mountpt)
                f_list_len = len(f_list)
                for i, name in enumerate(f_list, start=1):
                    if not card.is_dir(name) and f_pattern in name and name.endswith(suffix):
                        file_names.append(name)
                    dis.progress_bar_show(i / f_list_len)
            file_names_len = len(file_names)
            dis.fullscreen("Validating...")
            if et == "1":
                # can have multiple of these files - we will try to decrypt all that
                # have above pattern. Those that fail will be ignored and at the end
                # we check if we have correct num of files (num==N)
                token = get_token(0)  # STANDARD encryption has just one token
                encryption_key = key_derivation_function(token)
                token_key_map[token] = encryption_key

                with CardSlot(force_vdisk=force_vdisk) as card:
                    for i, fname in enumerate(file_names, start=1):
                        with open(card.abs_path(fname), mode) as f:
                            data = f.read()
                        data = bsms_decrypt(encryption_key, data)
                        if not data:
                            continue

                        assert data.startswith("BSMS"), "Failure - not BSMS file?"
                        r1_data.append(data)
                        dis.progress_bar_show(i / file_names_len)

            elif et == "2":
                with CardSlot(force_vdisk=force_vdisk) as card:
                    for i in range(N):
                        token = get_token(i)
                        for fname in file_names:
                            if token[:4] in fname:
                                with open(card.abs_path(fname), mode) as f:
                                    data = f.read()
                                encryption_key = key_derivation_function(token)
                                data = bsms_decrypt(encryption_key, data)

                                assert data, "Failed to decrypt %s with token %s" % (fname, token)
                                assert data.startswith("BSMS"), "Failure - not BSMS file?"
                                token_key_map[token] = encryption_key
                                r1_data.append(data)

                                break
                        else:
                            assert False, "haven't find file for token %s" % token

                        dis.progress_bar_show(i / N)
            else:
                assert file_names_len == N, "Need same number of files (%d) as co-signers(N=%d)"\
                                                             % (file_names_len, N)

                with CardSlot(force_vdisk=force_vdisk) as card:
                    for i, fname in enumerate(file_names, start=1):
                        with open(card.abs_path(fname), mode) as f:
                            data = f.read()
                        assert data.startswith("BSMS"), "Failure - not BSMS file?"
                        r1_data.append(data)
                        dis.progress_bar_show(i / file_names_len)

            assert len(r1_data) == N, "No. of signer round 1 data auto-collected "\
                                        "does not equal number of signers (N)"
        except BaseException as e:
            if isinstance(e, RejectAutoCollection):
                # raised when user manually chooses not to use auto-collection
                msg_prefix = ""
            else:
                msg_prefix = "Auto-collection failed. Defaulting to manual selection of files. "

            # iterate over N and prompt user to choose correct files
            for i in range(N):
                token = get_token(i)
                f_pick_msg = msg_prefix
                f_pick_msg += 'Select co-signer #%d file containing round 1 data' % (i + 1)
                if et == "2":
                    f_pick_msg += " for token starting with %s" % token[:4]
                f_pick_msg += '. File extension has to be "%s"' % suffix
                for attempt in range(2):  # two chances to succeed
                    await ux_show_story(f_pick_msg)
                    fn = await file_picker(suffix=suffix, min_size=220, max_size=500,
                                           force_vdisk=force_vdisk)
                    if not fn: return

                    dis.fullscreen("Wait...")
                    with CardSlot(force_vdisk=force_vdisk) as card:
                        dis.progress_bar_show(0.1)
                        with open(fn, mode) as fd:
                            data = fd.read()
                            dis.progress_bar_show(0.3)
                            if is_encrypted:
                                encryption_key = key_derivation_function(token)
                                dis.progress_bar_show(0.6)
                                data = bsms_decrypt(encryption_key, data)
                                if not data:
                                    fail_msg = "Decryption failed for co-signer #%d" % (i + 1)
                                    if et == "2":
                                        fail_msg += " with token %s" % token[:4]
                                    ch = await ux_show_story(title="FAILURE", msg=fail_msg +
                                                    (" Try again?" if attempt == 0 else fail_msg))

                                    if ch == "y" and attempt == 0:
                                        continue
                                    else:
                                        return

                                dis.progress_bar_show(0.9)
                                token_key_map[token] = encryption_key

                            r1_data.append(data)
                            dis.progress_bar_show(1)

                            break  # break from "second chance loop"

    if not r1_data:
        return

    keys = []
    dis.fullscreen("Validating...")
    for i, data in enumerate(r1_data):
        # divided in the loop with number of in-loop occurences of 'dis.progress_bar_show' (currently 5)
        i_div_N = (i+1) / N
        token = get_token(i)
        assert data.startswith(BSMS_VERSION), "Incompatible BSMS version. Need %s got %s" % (
            BSMS_VERSION, data[:9]
        )
        version, tok, key_exp, description, sig = data.strip().split("\n")
        assert tok == token, "Token mismatch saved %s, received from signer %s" % (token, tok)
        key = Key.from_string(key_exp)
        dis.progress_bar_show(i_div_N / 4)
        msg = signer_data_round1(token, key_exp, description)
        digest = chain.hash_message(msg.encode())
        dis.progress_bar_show(i_div_N / 3)
        _, recovered_pk = chains.verify_recover_pubkey(a2b_base64(sig), digest)
        assert key.node.pubkey() == recovered_pk, "Recovered key from signature does not equal key provided. Wrong signature?"
        dis.progress_bar_show(i_div_N / 2)
        keys.append(key)
        dis.progress_bar_show(i_div_N / 1)

    dis.fullscreen("Generating...")
    miniscript = Sortedmulti(Number(M), *keys)
    desc_obj = Descriptor(miniscript=miniscript)
    desc_obj.set_from_addr_fmt(addr_fmt)
    desc = desc_obj.to_string(checksum=False)
    desc = desc.replace("<0;1>/*", "**")
    if not is_encrypted:
        # append checksum for unencrypted BSMS
        desc = append_checksum(desc)
    for i, ko in enumerate(keys):
        ko.node.derive(0, False)  # external is always first our coordinating "0/*,1/*"
        dis.progress_bar_show(i / N)

    # TODO this can be done with .script_pubkey
    script = make_redeem_script(M, [k.node for k in keys], 0)  # first address
    addr = chain.p2sh_address(addr_fmt, script)
    # ==
    r2_data = coordinator_data_round2(desc, addr)
    dis.progress_bar_show(1)

    force_vdisk = False
    title = "BSMS descriptor template file(s)"
    prompt, escape = export_prompt_builder(title)
    if prompt:
        ch = await ux_show_story(prompt, escape=escape)
        if ch == KEY_NFC if version_mod.has_qwerty else '3':
            if et == "2":
                for i, token in enumerate(tokens):
                    ch = await ux_show_story("Exporting data for co-signer #%d with token %s"
                                                    % (i+1, token[:4]))
                    if ch != "y":
                        return
                    data = bsms_encrypt(token_key_map[token], token, r2_data)
                    await NFC.share_text(b2a_hex(data).decode())
            elif et == "1":
                token = get_token(0)
                data = bsms_encrypt(token_key_map[token], token, r2_data)
                await NFC.share_text(b2a_hex(data).decode())
            else:
                await NFC.share_text(r2_data)
            await ux_show_story("All done.")
            return
        elif ch == "2":
            force_vdisk = True
        elif ch == '1':
            force_vdisk = False
        else:
            return

    def to_export_generator():
        # save memory
        if et == "3":  # NO_ENCRYPTION
            yield None, r2_data
        elif et == "1":  # STANDARD
            token = get_token(0)
            yield token, bsms_encrypt(token_key_map[token], token, r2_data)
        else:
            # EXTENDED
            for token in tokens:
                yield token, bsms_encrypt(token_key_map[token], token, r2_data)

    dis.fullscreen("Saving...")
    mode = "wb" if is_encrypted else "wt"
    f_pattern = "bsms_cr2"
    f_names = []
    try:
        with CardSlot(force_vdisk=force_vdisk) as card:
            for i, (token, data) in enumerate(to_export_generator(), start=1):
                f_name = "%s%s%s" % (f_pattern, "_" + token[:4] if et == "2" else "", suffix)
                fname, nice = card.pick_filename(f_name)
                with open(fname, mode) as fd:
                    fd.write(data)
                f_names.append(nice)
                dis.progress_bar_show(i / (len(token_key_map) or 1))
    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n' + str(e))
        return
    msg = '''%s written. Files:\n\n%s''' % (title, "\n\n".join(f_names))
    await ux_show_story(msg)


@exceptions_handler
async def bsms_signer_round1(*a):
    from glob import dis, NFC, VD, settings

    shortcut = len(a) == 1
    token_int = None
    if not shortcut:
        prompt = "Press (1) to import token file from SD Card, (2) to input token manually"
        prompt += ", (3) for unencrypted BSMS."
        escape = "123"
        if version.has_qwerty:
            prompt += "%s to scan QR. " % KEY_QR
            escape += KEY_QR
        if NFC is not None:
            prompt += " %s to import via NFC" % (KEY_NFC if version.has_qwerty else "(4)")
            escape += KEY_NFC if version.has_qwerty else "4"
        if VD is not None:
            prompt += ", (6) to import from Virtual Disk"
            escape += "6"
        prompt += "."

        ch = await ux_show_story(prompt, escape=escape)

        if ch == '3':
            token_hex = "00"
        elif ch in "4"+KEY_NFC:
            token_hex = await NFC.read_bsms_token()
        elif ch == "2":
            prompt = "To input token as hex press (1), as decimal press (2)"
            escape = "12"
            ch = await ux_show_story(prompt, escape=escape)
            if ch == "1":
                token_hex = await ux_input_text("", hex_only=True, scan_ok=True,
                                                prompt="Hex Token")
            elif ch == "2":
                if version.has_qwerty:
                    token_int = await ux_input_text("", scan_ok=True, prompt="Decimal Token")
                else:
                    token_int = await ux_input_numbers("", lambda: True)
                token_hex = hex(int(token_int))
            else:
                return
        elif ch in "16":
            from actions import file_picker
            force_vdisk = (ch == '6')

            # pick a likely-looking file.
            fn = await file_picker(suffix=".token", min_size=15, max_size=35,
                                   force_vdisk=force_vdisk)
            if not fn: return

            with CardSlot(force_vdisk=force_vdisk) as card:
                with open(fn, 'rt') as fd:
                    token_hex = fd.read().strip()
        else:
            return
    else:
        token_hex = a[0]

    # will raise, exc catched in decorator, FAILURE msg provided
    validate_token(token_hex)
    token_hex = normalize_token(token_hex)
    is_extended = (len(token_hex) == 32)
    entered_msg = "%s\n\nhex:\n%s" % (token_int, token_hex) if token_int else token_hex

    if not shortcut:
        ch = await ux_show_story("You have entered token:\n" + entered_msg + "\n\nIs token correct?")
        if ch != "y":
            return

    xfp = xfp2str(settings.get('xfp', 0))
    chain = chains.current_chain()
    ch = await ux_show_story(
"Choose co-signer address format for correct SLIP derivation path. Default is 'unknown' as this "
"information may not be known at this point in BSMS. SLIP agnostic path will be chosen. "
"Press (1) for P2WSH. Press (2) for P2SH-P2WSH. "
"Correct SLIP path is completely unnecessary as descriptors (BIP-0380) are used.",
                             escape='12')
    if ch == 'y':
        pth_template = "m/129'/{coin}'/{acct_num}'"
        af_str = ""
    elif ch == '1':
        pth_template = "m/48'/{coin}'/{acct_num}'/2'"
        af_str = " P2WSH"
    elif ch == '2':
        pth_template = "m/48'/{coin}'/{acct_num}'/1'"
        af_str = " P2SH-P2WSH"
    else:
        return

    acct_num = await ux_enter_number('Account Number:', 9999) or 0

    # textual key description
    key_description = "Coldcard signer%s account %d" % (af_str, acct_num)
    ch = await ux_show_story(
"Choose key description. To continue with default, generated description: '%s' press OK."
"\n\nPress (1) for custom key description." % key_description, escape="1")

    if ch == "1":
        key_description = await ux_input_text("", confirm_exit=False) or ""

    key_description_len = len(key_description)
    assert key_description_len <= 80, "Key Description: 80 char max (was %d)" % key_description_len

    dis.fullscreen("Wait...")

    with stash.SensitiveValues() as sv:
        dis.progress_bar_show(0.1)

        dd = pth_template.format(coin=chain.b44_cointype, acct_num=acct_num)
        node = sv.derive_path(dd)
        ext_key = chain.serialize_public(node)

        dis.progress_bar_show(0.25)

        desc_type_key = "[%s%s]%s" % (xfp, dd[1:], ext_key)
        msg = signer_data_round1(token_hex, desc_type_key, key_description)
        digest = chain.hash_message(msg.encode())
        sk = node.privkey()
        sv.register(sk)

        dis.progress_bar_show(0.5)

        sig = ngu.secp256k1.sign(sk, digest, 0).to_bytes()
        result_data = signer_data_round1(token_hex, desc_type_key, key_description, sig_bytes=sig)

        dis.progress_bar_show(.75)

    encryption_key = key_derivation_function(token_hex)
    if encryption_key:
        result_data = bsms_encrypt(encryption_key, token_hex, result_data)

    dis.progress_bar_show(1)

    # export round 1 file
    force_vdisk = False
    title = "BSMS signer round 1 file"
    prompt, escape = export_prompt_builder(title)
    if prompt:
        ch = await ux_show_story(prompt, escape=escape)
        if ch == KEY_NFC if version.has_qwerty else '3':
            force_vdisk = None
            if isinstance(result_data, bytes):
                result_data = b2a_hex(result_data).decode()
            await NFC.share_text(result_data)
        elif ch == "2":
            force_vdisk = True
        elif ch == '1':
            force_vdisk = False
        else:
            return

    msg = "Success. Signer round 1 saved."
    if force_vdisk is not None:
        basename = "bsms_sr1%s" % "_" + token_hex[:4] if is_extended else "bsms_sr1"
        f_pattern = basename + ".txt" if encryption_key is None else basename + ".dat"
        # choose a filename
        try:
            with CardSlot(force_vdisk=force_vdisk) as card:
                fname, nice = card.pick_filename(f_pattern)
                with open(fname, 'wb') as fd:
                    if isinstance(result_data, str):
                        result_data = result_data.encode()
                    fd.write(result_data)
        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n\n' + str(e))
            return
        msg = '''%s written:\n\n%s''' % (title, nice)
    BSMSSettings.signer_add(token_hex)
    await ux_show_story(msg)
    if not shortcut:
        restore_menu()


@exceptions_handler
async def bsms_signer_round2(menu, label, item):
    import version
    from glob import NFC, dis, settings
    from actions import file_picker
    from auth import maybe_enroll_xpub
    from multisig import make_redeem_script

    chain = chains.current_chain()

    # or xpub or tpub as we use descriptors (no SLIP132 allowed)
    ext_key_prefix = "%spub" % chain.slip132[AF_CLASSIC].hint
    force_vdisk = False

    # choose correct values based on label (index in signer bsms settings)
    bsms_settings_index = item.arg
    token = BSMSSettings.get_signers()[bsms_settings_index]

    decrypt_fail_msg = "Decryption with token %s failed." % token[:4]
    is_encrypted = False if token == "00" else True
    suffix = ".dat" if is_encrypted else ".txt"
    mode = "rb" if is_encrypted else "rt"

    prompt, escape = _import_prompt_builder("descriptor template file", False, False)
    if prompt:
        ch = await ux_show_story(prompt, escape=escape)

        if ch == KEY_NFC if version.has_qwerty else '3':
            force_vdisk = None
            desc_template_data = await NFC.read_bsms_data()

            if desc_template_data is None:
                return

            if is_encrypted:
                data_bytes = a2b_hex(desc_template_data)
                encryption_key = key_derivation_function(token)
                desc_template_data = bsms_decrypt(encryption_key, data_bytes)
                assert desc_template_data, decrypt_fail_msg
        else:
            if ch == "1":
                force_vdisk = False
            else:
                force_vdisk = True

    if force_vdisk is not None:
        fn = await file_picker(suffix=suffix, min_size=200, max_size=10000,
                               force_vdisk=force_vdisk)
        if not fn: return

        with CardSlot(force_vdisk=force_vdisk) as card:
            with open(fn, mode) as fd:
                desc_template_data = fd.read()
                if is_encrypted:
                    encryption_key = key_derivation_function(token)
                    desc_template_data = bsms_decrypt(encryption_key, desc_template_data)
                    assert desc_template_data, decrypt_fail_msg

    dis.fullscreen("Validating...")
    assert desc_template_data.startswith(BSMS_VERSION), \
        "Incompatible BSMS version. Need %s got %s" % (BSMS_VERSION, desc_template_data[:9])

    dis.progress_bar_show(0.05)
    version, desc_template, pth_restrictions, addr = desc_template_data.split("\n")
    assert pth_restrictions == ALLOWED_PATH_RESTRICTIONS, \
        "Only '%s' allowed as path restrictions. Got %s" % (
                            ALLOWED_PATH_RESTRICTIONS, pth_restrictions)

    # if checksum is provided we better verify it
    # remove checksum as we need to replace /**
    desc_template, csum = Descriptor.checksum_check(desc_template)
    desc = desc_template.replace("/**", "/0/*")

    dis.progress_bar_show(0.1)
    desc = append_checksum(desc)

    ms_name = "bsms_" + desc[-4:]

    desc_obj = Descriptor.from_string(desc)
    desc_obj.legacy_ms_compat()

    dis.progress_bar_show(0.2)

    my_xfp = settings.get('xfp')
    my_keys = []
    nodes = []
    progress_counter = 0.2  # last displayed progress
    # (desired value after loop - last displayed progress) / N
    progress_chunk = (0.5 - progress_counter) / len(desc_obj.miniscript.keys)
    for key in desc_obj.keys:
        if key.origin.cc_fp == my_xfp:
            my_keys.append(key)
        nodes.append(key.node)
        progress_counter += progress_chunk
        dis.progress_bar_show(progress_counter)

    num_my_keys = len(my_keys)
    assert num_my_keys <= 1, "Multiple %s keys in descriptor (%d)" % (xfp2str(my_xfp), num_my_keys)
    assert num_my_keys == 1, "My key %s missing in descriptor." % xfp2str(my_xfp)

    with stash.SensitiveValues() as sv:
        node = sv.derive_path(my_keys[0].origin.str_derivation())
        ext_key = chain.serialize_public(node)
        assert ext_key == my_keys[0].extended_public_key(), "My key %s missing in descriptor." % ext_key

    dis.progress_bar_show(0.55)

    # check address is correct
    progress_counter = 0.55  # last displayed progress
    # (desired value after loop - last displayed progress) / N
    M, N = desc_obj.miniscript.m_n()
    progress_chunk = (0.9 - progress_counter) / N
    for node in nodes:
        node.derive(0, False)  # external is always first in our allowed path restrictions
        progress_counter += progress_chunk
        dis.progress_bar_show(progress_counter)

    script = make_redeem_script(M, nodes, 0)  # first address
    dis.progress_bar_show(0.95)
    calc_addr = chain.p2sh_address(desc_obj.addr_fmt, script)

    assert calc_addr == addr, "Address mismatch! Calculated %s, got %s" % (calc_addr, addr)

    dis.progress_bar_show(1)
    try:
        maybe_enroll_xpub(config=desc, name=ms_name, bsms_index=bsms_settings_index)
        # bsms_settings_signer_delete(bsms_settings_index) --> moved to auth.py to only be done if actually approved
    except Exception as e:
        await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

# EOF