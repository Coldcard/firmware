# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/miniscript.py
#
import ngu, ujson, uio, chains, ure, version, stash
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from serializations import ser_compact_size, ser_string
from desc_utils import Key, read_until, bip388_wallet_policy_to_descriptor, append_checksum, bip388_validate_policy
from public_constants import MAX_TR_SIGNERS, AF_P2TR
from wallet import BaseStorageWallet, MAX_BIP32_IDX
from menu import MenuSystem, MenuItem
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
from files import CardSlot, CardMissingError, needs_microsd
from utils import problem_file_line, xfp2str, to_ascii_printable, swab32, show_single_address
from charcodes import KEY_QR, KEY_CANCEL, KEY_NFC, KEY_ENTER
from glob import settings

# Arbitrary value, not 0 or 1, used to derive a pubkey from preshared xpub in Key Teleport
KT_RXPUBKEY_DERIV = const(20250317)

# PSBT Xpub trust policies
TRUST_VERIFY = const(0)
TRUST_OFFER = const(1)
TRUST_PSBT = const(2)


class MiniScriptWallet(BaseStorageWallet):
    key_name = "miniscript"
    disable_checks = False

    def __init__(self, name, desc_tmplt=None, keys_info=None, desc=None,
                 af=None, ik_u=None):

        assert (desc_tmplt and keys_info) or desc

        super().__init__()
        self.name = name
        self.desc_tmplt = desc_tmplt
        self.keys_info = keys_info
        self.desc = desc
        self.addr_fmt = af
        self.ik_u = ik_u

    @classmethod
    def get_trust_policy(cls):

        which = settings.get('pms', None)
        if which is None:
            which = TRUST_VERIFY if cls.exists() else TRUST_OFFER

        return which

    @property
    def chain(self):
        return chains.current_chain()

    def serialize(self):
        return self.name, self.desc_tmplt, self.keys_info, self.addr_fmt, self.ik_u

    @classmethod
    def deserialize(cls, c, idx=-1):
        # after deserialization - we lack loaded descriptor object
        # we do not need it for everything
        name, desc_tmplt, keys_info, af, ik_u = c
        rv = cls(name, desc_tmplt, keys_info, af=af, ik_u=ik_u)
        rv.storage_idx = idx
        return rv

    def to_descriptor(self, validate=False):
        if self.desc is None:
            # actual descriptor is not loaded, but was asked for
            # fill policy - aka storage format - to actual descriptor
            from descriptor import Descriptor
            import glob

            if self.name in glob.DESC_CACHE:
                # loaded descriptor from cache
                print("to_descriptor CACHE")
                self.desc = glob.DESC_CACHE[self.name]
            else:
                desc_str = bip388_wallet_policy_to_descriptor(self.desc_tmplt, self.keys_info)
                print("loading... filled policy:\n", desc_str)
                # no need to validate already saved descriptor - was validated upon enroll
                self.desc = Descriptor.from_string(desc_str, validate=validate)
                # cache len always 1
                glob.DESC_CACHE = {}
                glob.DESC_CACHE[self.name] = self.desc

        return self.desc

    @classmethod
    def find_match(cls, xfp_paths, addr_fmt=None):
        for rv in cls.iter_wallets():
            if addr_fmt is not None:
                if rv.addr_fmt != addr_fmt:
                    continue

            if rv.matching_subpaths(xfp_paths):
                return rv
        return None

    def matching_subpaths(self, xfp_paths):
        my_xfp_paths = self.to_descriptor().xfp_paths()

        if len(xfp_paths) != len(my_xfp_paths):
            return False

        for x in my_xfp_paths:
            prefix_len = len(x)
            for y in xfp_paths:
                if x == y[:prefix_len]:
                    break
            else:
                return False
        return True

    def subderivation_indexes(self, xfp_paths):
        # we already know that they do match
        my_xfp_paths = self.to_descriptor().xfp_paths()
        res = set()
        for x in my_xfp_paths:
            prefix_len = len(x)
            for y in xfp_paths:
                if x == y[:prefix_len]:
                    to_derive = tuple(y[prefix_len:])
                    res.add(to_derive)

        assert res
        if len(res) == 1:
            branch, idx = list(res)[0]
        else:
            branch = [i[0] for i in res]
            indexes = set([i[1] for i in res])
            assert len(indexes) == 1
            idx = list(indexes)[0]

        return branch, idx

    def get_my_deriv(self, my_xfp):
        # lowest public key from lexicographically sorted list is at index 0
        mine = self.xpubs_from_xfp(my_xfp)
        return mine[0].origin.str_derivation()

    def derive_desc(self, xfp_paths):
        branch, idx = self.subderivation_indexes(xfp_paths)
        derived_desc = self.desc.derive(branch).derive(idx)
        return derived_desc

    def validate_script_pubkey(self, script_pubkey, xfp_paths, merkle_root=None):
        derived_desc = self.derive_desc(xfp_paths)
        derived_spk = derived_desc.script_pubkey()
        assert derived_spk == script_pubkey, "spk mismatch"
        if merkle_root:
            assert derived_desc.tapscript.merkle_root == merkle_root, "psbt merkle root"
        return derived_desc

    async def _detail(self, new_wallet=False, is_duplicate=False):

        s = chains.addr_fmt_label(self.addr_fmt) + "\n\n"
        s += self.desc_tmplt

        story = s + "\n\nPress (1) to see extended public keys"
        if new_wallet and not is_duplicate:
            story += ", OK to approve, X to cancel."
        return story

    async def show_detail(self, new_wallet=False, duplicates=None):
        title = self.name
        story = ""
        if duplicates:
            title = None
            story += "This wallet is a duplicate of already saved wallet %s\n\n" % duplicates[0].name
        elif new_wallet:
            title = None
            story += "Create new miniscript wallet?\n\nWallet Name:\n  %s\n\n" % self.name

        story += (chains.addr_fmt_label(self.addr_fmt) + "\n\n" + self.desc_tmplt)
        story += "\n\nPress (1) to see extended public keys"

        if new_wallet and not duplicates:
            story += ", OK to approve, X to cancel."

        while True:
            ch = await ux_show_story(story, title=title, escape="1")
            if ch == "1":
                await self.show_keys()

            elif ch != "y":
                return None
            else:
                return True

    async def show_keys(self):
        msg = ""
        for idx, k_str in enumerate(self.keys_info):
            if idx:
                msg += '\n---===---\n\n'
            elif self.addr_fmt == AF_P2TR:
                # index 0, taproot internal key
                msg += "Taproot internal key:\n\n"
                if self.ik_u:
                    msg += "(provably unspendable)\n\n"

            msg += '@%s:\n  %s\n\n' % (idx, k_str)

        await ux_show_story(msg)

    @classmethod
    def from_bip388_wallet_policy(cls, name, desc_template, keys_info):
        bip388_validate_policy(desc_template, keys_info)
        msc = cls(name, desc_template, keys_info)
        msc.to_descriptor(validate=True)
        return msc

    @classmethod
    def from_file(cls, config, name=None, bip388=False):
        from descriptor import Descriptor

        if bip388:
            # config is JSON wallet policy
            wal = cls.from_bip388_wallet_policy(config["name"], config["desc_template"],
                                                config["keys_info"])
        else:
            if name is None:
                desc_obj, cs = Descriptor.from_string(config.strip(), checksum=True)
                name = cs
            else:
                name = to_ascii_printable(name)
                desc_obj = Descriptor.from_string(config.strip())

            wal = cls(name, desc=desc_obj)

            # BIP388 wasn't generated yet - generating from descriptor upon import/enroll
            wal.desc_tmplt, wal.keys_info = desc_obj.bip388_wallet_policy()

            bip388_validate_policy(wal.desc_tmplt, wal.keys_info)

        wal.ik_u = wal.desc.key and wal.desc.key.is_provably_unspendable
        wal.addr_fmt = wal.desc.addr_fmt
        return wal

    def find_duplicates(self):
        matches = []
        name_unique = True
        for rv in self.iter_wallets():
            if self.name == rv.name:
                name_unique = False
            if self.desc_tmplt != rv.desc_tmplt:
                continue
            if self.keys_info != rv.keys_info:
                continue

            matches.append(rv)

        return matches, name_unique

    async def confirm_import(self):
        nope, yes = (KEY_CANCEL, KEY_ENTER) if version.has_qwerty else ("x", "y")
        dups, name_unique = self.find_duplicates()
        if not name_unique:
            await ux_show_story(title="FAILED", msg=("Miniscript wallet with name '%s'"
                                                     " already exists. All wallets MUST"
                                                     " have unique names.") % self.name)
            return nope
        to_save = await self.show_detail(new_wallet=True, duplicates=dups)

        ch = yes if to_save else nope
        if to_save and not dups:
            assert self.storage_idx == -1
            self.commit()
            import glob
            # new wallet was imported - cache descriptor
            glob.DESC_CACHE = {}
            assert self.desc
            glob.DESC_CACHE[self.name] = self.desc
            await ux_dramatic_pause("Saved.", 2)

        return ch

    def yield_addresses(self, start_idx, count, change=False, scripts=False, change_idx=0):
        ch = chains.current_chain()
        dd = self.to_descriptor().derive(None, change=change)
        idx = start_idx
        while count:
            if idx > MAX_BIP32_IDX:
                break
            # make the redeem script, convert into address
            d = dd.derive(idx)
            scr = d.miniscript.compile() if d.miniscript else None
            addr = ch.render_address(d.script_pubkey(compiled_scr=scr))
            ders = script = None
            if scripts:
                ders = ["[%s]" % str(k.origin) for k in d.keys]
                if d.tapscript:
                    script = d.tapscript.script_tree()
                else:
                    script = b2a_hex(ser_string(scr)).decode()

            yield idx, addr, ders, script

            idx += 1
            count -= 1

    def make_addresses_msg(self, msg, start, n, change=0):
        from glob import dis

        addrs = []

        for idx, addr, *_ in self.yield_addresses(start, n, change=bool(change), scripts=False):
            msg += '.../%d =>\n' % idx  # just idx, if derivations or scripts needed - export csv
            addrs.append(addr)
            msg += show_single_address(addr) + '\n\n'
            dis.progress_sofar(idx - start + 1, n)

        return msg, addrs

    def generate_address_csv(self, start, n, change):
        yield '"' + '","'.join(
            ['Index', 'Payment Address']
        ) + '"\n'
        for idx, addr, ders, script in self.yield_addresses(start, n, change=bool(change)):
            ln = '%d,"%s"' % (idx, addr)
            if ders:
                ln += ',"%s","' % script
                ln += '","'.join(ders)
                ln += '"'
            ln += '\n'
            yield ln

    def to_string(self, checksum=True):
        # policy filling - not posible to specify internal/external always multipath export
        # only supported from bitcoin-core 29.0
        if self.desc_tmplt and self.keys_info:
            desc = bip388_wallet_policy_to_descriptor(self.desc_tmplt, self.keys_info)
            if checksum:
                desc = append_checksum(desc)
            return desc

        return self.desc.to_string()

    def bitcoin_core_serialize(self):
        return [{
            "desc": self.to_string(),  # policy fill
            "active": True,
            "timestamp": "now",
            "range": [0, 100],
        }]

    async def export_wallet_file(self, extra_msg=None, core=False, bip388=False):
        # do not load descriptor - just fill policy
        # only with multipath format <0;1>
        from glob import NFC, dis
        from ux import import_export_prompt

        dis.fullscreen('Wait...')

        if core:
            name = "Bitcoin Core miniscript"
            fname_pattern = 'bitcoin-core-%s.txt' % self.name
            msg = "importdescriptors cmd"
            core_obj = self.bitcoin_core_serialize()
            core_str = ujson.dumps(core_obj)
            res = "importdescriptors '%s'\n" % core_str
        elif bip388:
            # policy as JSON
            name = "BIP-388 Wallet Policy"
            fname_pattern = 'b388-%s.json' % self.name
            res = ujson.dumps({"name": self.name,
                               "desc_template": self.desc_tmplt.replace("/<0;1>/*", "/**"),
                               "keys_info": self.keys_info})
        else:
            name = "Miniscript"
            fname_pattern = 'minsc-%s.txt' % self.name
            msg = self.name
            res = self.to_string()

        ch = await import_export_prompt("%s file" % name)
        if isinstance(ch, str):
            if ch in "3"+KEY_NFC:
                await NFC.share_text(res)
            elif ch == KEY_QR:
                try:
                    from ux import show_qr_code
                    await show_qr_code(res, msg=msg)
                except:
                    if version.has_qwerty:
                        from ux_q1 import show_bbqr_codes
                        await show_bbqr_codes('U', res, msg)
            return

        try:
            with CardSlot(**ch) as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with open(fname, 'w+') as fp:
                    fp.write(res)
                #     fp.seek(0)
                #     contents = fp.read()
                # TODO re-enable once we know how to proceed with regards to with which key to sign
                # TODO need function to get my xpub from just policy
                # from auth import write_sig_file
                # h = ngu.hash.sha256s(contents.encode())
                # sig_nice = write_sig_file([(h, fname)])

            msg = '%s file written:\n\n%s' % (name, nice)
            # msg += '\n\nColdcard multisig signature file written:\n\n%s' % sig_nice
            if extra_msg:
                msg += extra_msg

            await ux_show_story(msg)

        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n%s\n%s' % (e, problem_file_line(e)))
            return

    def xpubs_from_xfp(self, xfp):
        # return list of XPUB's which match xfp
        res = []
        desc = self.to_descriptor()
        for k in desc.keys:
            if k.origin and k.origin.cc_fp == xfp:
                res.append(k)
            elif swab32(k.node.my_fp()) == xfp:
                res.append(k)

        assert res, "missing xfp %s" % xfp2str(xfp)
        # returned is list of keys with corresponding master xfp
        # key in list are lexicographically sorted based on their public keys
        # lowest public key first
        return sorted(res, key=lambda o: o.serialize())

    def kt_make_rxkey(self, xfp):
        # Derive the receiver's pubkey from preshared xpub and a special derivation
        # - also provide the keypair we're using from our side of connection
        # - returns 4 byte nonce which is sent un-encrypted, his_pubkey and my_keypair
        ri = ngu.random.uniform(1<<28)

        # sorted lexicographically, always use the lowest pubkey from the list at index 0
        keys =  self.xpubs_from_xfp(xfp)
        k = keys[0]
        k = k.derive(KT_RXPUBKEY_DERIV).derive(ri)
        pubkey = k.node.pubkey()

        kp = self.kt_my_keypair(ri)
        return ri.to_bytes(4, 'big'), pubkey, kp

    def kt_my_keypair(self, ri):
        # Calc my keypair for sending PSBT files.
        #
        # sorted lexicographically, always use the lowest pubkey from the list at index 0
        keys = self.xpubs_from_xfp(settings.get('xfp'))

        subpath = "/%d/%d" % (KT_RXPUBKEY_DERIV, ri)
        path = keys[0].origin.str_derivation() + subpath
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(path)
            kp = ngu.secp256k1.keypair(node.privkey())
            return kp

    @classmethod
    def kt_search_rxkey(cls, payload):
        # Construct the keypair for to be decryption
        # - has to try pubkey each all the unique XFP for all co-signers in all wallets
        # - checks checksum of ECDH unwrapped data to see if it's the right one
        # - returns session key, decrypted first layer, and XFP of sender
        from teleport import decode_step1

        # this nonce is part of the derivation path so each txn gets new keys
        ri = int.from_bytes(payload[0:4], 'big')

        my_xfp = settings.get('xfp')

        for msc in cls.iter_wallets():
            kp = msc.kt_my_keypair(ri)
            for k in msc.to_descriptor().keys:
                if k.origin.cc_fp == my_xfp:
                    continue
                kk = k.derive(KT_RXPUBKEY_DERIV).derive(ri)
                his_pubkey = kk.node.pubkey()
                # if implied session key decodes the checksum, it is right
                ses_key, body = decode_step1(kp, his_pubkey, payload[4:])
                if ses_key:
                    return ses_key, body, kk.origin.cc_fp

        return None, None, None

async def no_miniscript_yet(*a):
    await ux_show_story("You don't have any miniscript wallets yet.")

async def miniscript_delete(msc):
    if not await ux_confirm("Delete miniscript wallet '%s'?\n\nFunds may be impacted." % msc.name):
        await ux_dramatic_pause('Aborted.', 3)
        return

    msc.delete()
    await ux_dramatic_pause('Deleted.', 3)

async def miniscript_wallet_delete(menu, label, item):
    msc = item.arg

    await miniscript_delete(msc)

    from ux import the_ux
    # pop stack
    the_ux.pop()

    m = the_ux.top_of_stack()
    m.update_contents()

async def miniscript_wallet_detail(menu, label, item):
    # show details of single multisig wallet

    msc = item.arg

    return await msc.show_detail()

async def import_miniscript(*a):
    # pick text file from SD card, import as multisig setup file
    from actions import file_picker
    from ux import import_export_prompt

    ch = await import_export_prompt("miniscript wallet file", is_import=True)
    if isinstance(ch, str):
        if ch == KEY_QR:
            await import_miniscript_qr()
        elif ch == KEY_NFC:
            await import_miniscript_nfc()
        return

    def possible(filename):
        with open(filename, 'rt') as fd:
            for ln in fd:
                if "sh(" in ln or "wsh(" in ln or "tr(" in ln:
                    # descriptor import
                    return True

    fn = await file_picker(suffix=['.txt', '.json'], min_size=100,
                           taster=possible, **ch)
    if not fn: return

    try:
        with CardSlot(**ch) as card:
            with open(fn, 'rt') as fp:
                data = fp.read()
    except CardMissingError:
        await needs_microsd()
        return

    from auth import maybe_enroll_xpub
    try:
        possible_name = (fn.split('/')[-1].split('.'))[0] if fn else None
        maybe_enroll_xpub(config=data, name=possible_name)
    except BaseException as e:
        await ux_show_story('Failed to import miniscript.\n\n%s\n%s' % (e, problem_file_line(e)))

async def import_miniscript_nfc(*a):
    from glob import NFC
    try:
        return await NFC.import_miniscript_nfc()
    except Exception as e:
        await ux_show_story('Failed to import miniscript.\n\n%s\n%s' % (e, problem_file_line(e)))

async def import_miniscript_qr(*a):
    from auth import maybe_enroll_xpub
    from ux_q1 import QRScannerInteraction
    data = await QRScannerInteraction().scan_text('Scan Miniscript from a QR code')
    if not data:
        # press pressed CANCEL
        return
    try:
        maybe_enroll_xpub(config=data)
    except Exception as e:
        await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

async def miniscript_wallet_export(menu, label, item):
    # create a text file with the details; ready for import to next Coldcard
    msc = item.arg[0]
    kwargs = item.arg[1]
    await msc.export_wallet_file(**kwargs)

async def make_miniscript_wallet_descriptor_menu(menu, label, item):
    # descriptor menu
    msc = item.arg
    if not msc:
        return

    rv = [
        MenuItem('Export', f=miniscript_wallet_export, arg=(msc, {"core": False})),
        MenuItem('Bitcoin Core', f=miniscript_wallet_export, arg=(msc, {"core": True})),
        MenuItem('BIP-388 Policy', f=miniscript_wallet_export, arg=(msc, {"bip388":True})),
    ]
    return rv

async def make_miniscript_wallet_menu(menu, label, item):
    # details, actions on single multisig wallet
    msc = MiniScriptWallet.get_by_idx(item.arg)
    if not msc: return

    rv = [
        MenuItem('"%s"' % msc.name, f=miniscript_wallet_detail, arg=msc),
        MenuItem('View Details', f=miniscript_wallet_detail, arg=msc),
        MenuItem('Delete', f=miniscript_wallet_delete, arg=msc),
        MenuItem('Descriptors', menu=make_miniscript_wallet_descriptor_menu, arg=msc),
    ]
    return rv


class MiniscriptMenu(MenuSystem):
    @classmethod
    def construct(cls):
        import version
        from menu import ShortcutItem

        if not MiniScriptWallet.exists():
            rv = [MenuItem(MiniScriptWallet.none_setup_yet(), f=no_miniscript_yet)]
        else:
            rv = []
            for msc in MiniScriptWallet.get_all():
                rv.append(MenuItem('%s' % msc.name,
                                   menu=make_miniscript_wallet_menu,
                                   arg=msc.storage_idx))
        from glob import NFC
        rv.append(MenuItem('Import', f=import_miniscript))
        rv.append(MenuItem('Export XPUB', f=export_miniscript_xpubs))
        rv.append(MenuItem('BSMS (BIP-129)', menu=make_ms_wallet_bsms_menu))
        rv.append(MenuItem('Create Airgapped', f=create_ms_step1))
        rv.append(MenuItem('Trust PSBT?', f=trust_psbt_menu))
        rv.append(MenuItem('Skip Checks?', f=disable_checks_menu))
        rv.append(ShortcutItem(KEY_NFC, predicate=lambda: NFC is not None,
                               f=import_miniscript_nfc))
        rv.append(ShortcutItem(KEY_QR, predicate=lambda: version.has_qwerty,
                               f=import_miniscript_qr))
        return rv

    def update_contents(self):
        # Reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)

async def make_miniscript_menu(*a):
    # list of all multisig wallets, and high-level settings/actions
    from pincodes import pa

    if pa.is_secret_blank():
        await ux_show_story("You must have wallet seed before creating miniscript wallets.")
        return

    rv = MiniscriptMenu.construct()
    return MiniscriptMenu(rv)


def disable_checks_chooser():
    ch = ['Normal', 'Skip Checks']

    def xset(idx, text):
        MiniScriptWallet.disable_checks = bool(idx)

    return int(MiniScriptWallet.disable_checks), ch, xset

async def disable_checks_menu(*a):

    if not MiniScriptWallet.disable_checks:
        ch = await ux_show_story('''\
With many different wallet vendors and implementors involved, it can \
be hard to create a PSBT consistent with the many keys involved. \
With this setting, you can \
disable the more stringent verification checks your Coldcard normally provides.

USE AT YOUR OWN RISK. These checks exist for good reason! Signed txn may \
not be accepted by network.

This settings lasts only until power down.

Press (4) to confirm entering this DANGEROUS mode.
''', escape='4')

        if ch != '4': return

    start_chooser(disable_checks_chooser)


def psbt_xpubs_policy_chooser():
    # Chooser for trust policy
    ch = ['Verify Only', 'Offer Import', 'Trust PSBT']

    def xset(idx, text):
        settings.set('pms', idx)

    return MiniScriptWallet.get_trust_policy(), ch, xset

async def trust_psbt_menu(*a):
    # show a story then go into chooser

    ch = await ux_show_story('''\
This setting controls what the Coldcard does \
with the co-signer public keys (XPUB) that may \
be provided inside a PSBT file. Three choices:

- Verify Only. Do not import the xpubs found, but do \
verify the correct wallet already exists on the Coldcard.

- Offer Import. If it's a new multisig wallet, offer to import \
the details and store them as a new wallet in the Coldcard.

- Trust PSBT. Use the wallet data in the PSBT as a temporary,
multisig wallet, and do not import it. This permits some \
deniability and additional privacy.

When the XPUB data is not provided in the PSBT, regardless of the above, \
we require the appropriate multisig wallet to already exist \
on the Coldcard. Default is to 'Offer' unless a multisig wallet already \
exists, otherwise 'Verify'.''')

    if ch == 'x': return
    start_chooser(psbt_xpubs_policy_chooser)


async def ms_wallet_electrum_export(menu, label, item):
    # create a JSON file that Electrum can use. Challenges:
    # - file contains derivation paths for each co-signer to use
    # - electrum is using BIP-43 with purpose=48 (purpose48_derivation) to make paths like:
    #       m/48h/1h/0h/2h
    # - above is now called BIP-48
    # - other signers might not be coldcards (we don't know)
    # solution:
    # - when building air-gap, pick address type at that point, and matching path to suit
    # - could check path prefix and addr_fmt make sense together, but meh.
    ms = item.arg
    from actions import electrum_export_story

    derivs, dsum = ms.get_deriv_paths()

    msg = 'The new wallet will have derivation path:\n  %s\n and use %s addresses.\n' % (
            dsum, MultisigWallet.render_addr_fmt(ms.addr_fmt) )

    if await ux_show_story(electrum_export_story(msg)) != 'y':
        return

    await ms.export_electrum()


async def export_miniscript_xpubs(*a, xfp=None, alt_secret=None, skip_prompt=False):
    # WAS: Create a single text file with lots of docs, and all possible useful xpub values.
    # THEN: Just create the one-liner xpub export value they need/want to support BIP-45
    # NOW: Export JSON with one xpub per useful address type and semi-standard derivation path
    #
    # - consumer for this file is supposed to be ourselves, when we build on-device multisig.
    # - however some 3rd parties are making use of it as well.
    # - used for CCC feature now as well, but result looks just like normal export
    #
    xfp = xfp2str(xfp or settings.get('xfp', 0))
    chain = chains.current_chain()

    fname_pattern = 'ccxp-%s.json' % xfp
    label = "Multisig XPUB"

    if not skip_prompt:
        msg = '''\
This feature creates a small file containing \
the extended public keys (XPUB) you would need to join \
a multisig wallet.

Public keys for BIP-48 conformant paths are used:

P2SH-P2WSH:
   m/48h/{coin}h/{{acct}}h/1h
P2WSH:
   m/48h/{coin}h/{{acct}}h/2h
P2TR:
   m/48h/{coin}h/{{acct}}h/3h

{ok} to continue. {x} to abort.'''.format(coin=chain.b44_cointype, ok=OK, x=X)

        ch = await ux_show_story(msg)
        if ch != "y":
            return

    acct = await ux_enter_bip32_index('Account Number:') or 0

    def render(acct_num):
        sign_der = None
        with uio.StringIO() as fp:
            fp.write('{\n')
            with stash.SensitiveValues(secret=alt_secret) as sv:
                for name, deriv, fmt in chains.MS_STD_DERIVATIONS:
                    if fmt == AF_P2SH and acct_num:
                        continue
                    dd = deriv.format(coin=chain.b44_cointype, acct_num=acct_num)
                    if fmt == AF_P2WSH:
                        sign_der = dd + "/0/0"
                    node = sv.derive_path(dd)
                    xp = chain.serialize_public(node, fmt)
                    fp.write('  "%s_deriv": "%s",\n' % (name, dd))
                    fp.write('  "%s": "%s",\n' % (name, xp))
                    xpub = chain.serialize_public(node)
                    descriptor_template = multisig_descriptor_template(xpub, dd, xfp, fmt)
                    if descriptor_template is None:
                        continue
                    fp.write('  "%s_desc": "%s",\n' % (name, descriptor_template))

            fp.write('  "account": "%d",\n' % acct_num)
            fp.write('  "xfp": "%s"\n}\n' % xfp)
            return fp.getvalue(), sign_der, AF_CLASSIC

    from export import export_contents
    await export_contents(label, lambda: render(acct), fname_pattern,
                          force_bbqr=True, is_json=True)


class Number:
    def __init__(self, num):
        self.num = num

    @classmethod
    def read_from(cls, s, taproot=False):
        num = 0
        char = s.read(1)
        while char in b"0123456789":
            num = 10 * num + int(char.decode())
            char = s.read(1)
        s.seek(-1, 1)
        return cls(num)

    def compile(self):
        if self.num == 0:
            return b"\x00"
        if self.num <= 16:
            return bytes([80 + self.num])
        b = self.num.to_bytes(32, "little").rstrip(b"\x00")
        if b[-1] >= 128:
            b += b"\x00"
        return bytes([len(b)]) + b

    def __len__(self):
        return len(self.compile())

    def to_string(self, *args, **kwargs):
        return "%d" % self.num


class KeyHash(Key):
    @classmethod
    def parse_key(cls, k: bytes, *args, **kwargs):
        # convert to string
        kd = k.decode()
        # raw 20-byte hash
        if len(kd) == 40:
            return kd, None
        return super().parse_key(k, *args, **kwargs)

    def serialize(self, *args, **kwargs):
        start = 1 if self.taproot else 0
        return ngu.hash.hash160(self.node.pubkey()[start:33])

    def __len__(self):
        return 21 # <20:pkh>

    def compile(self):
        d = self.serialize()
        return ser_compact_size(len(d)) + d


class Raw:
    def __init__(self, raw):
        if len(raw) != self.LEN * 2:
            raise ValueError("Invalid raw element length: %d" % len(raw))
        self.raw = a2b_hex(raw)

    @classmethod
    def read_from(cls, s, taproot=False):
        return cls(s.read(2 * cls.LEN).decode())

    def to_string(self, *args, **kwargs):
        return b2a_hex(self.raw).decode()

    def compile(self):
        return ser_compact_size(len(self.raw)) + self.raw

    def __len__(self):
        return len(ser_compact_size(self.LEN)) + self.LEN


class Raw32(Raw):
    LEN = 32
    def __len__(self):
        return 33


class Raw20(Raw):
    LEN = 20
    def __len__(self):
        return 21


class Miniscript:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.taproot = kwargs.get("taproot", False)

    def compile(self):
        return self.inner_compile()

    def verify(self):
        for arg in self.args:
            if isinstance(arg, Miniscript):
                arg.verify()

    @property
    def keys(self):
        res = []
        for arg in self.args:
            if isinstance(arg, Miniscript):
                res += arg.keys
            elif isinstance(arg, Key):  # KeyHash is subclass of Key
                res.append(arg)
        return res

    def is_sane(self, taproot=False):
        err = "multi mixin"
        forbiden = (Sortedmulti, Multi) if taproot else (Sortedmulti_a, Multi_a)
        assert type(self) not in forbiden, err

        for arg in self.args:
            assert type(arg) not in forbiden, err
            if isinstance(arg, Miniscript):
                arg.is_sane(taproot=taproot)

    @staticmethod
    def key_derive(key, idx, key_map=None, change=False):
        if key_map and key in key_map:
            kd = key_map[key]
        else:
            kd = key.derive(idx, change=change)
        return kd

    def derive(self, idx, key_map=None, change=False):
        args = []
        for arg in self.args:
            if isinstance(arg, Key):  # KeyHash is subclass of Key
                arg = self.key_derive(arg, idx, key_map, change=change)
            elif hasattr(arg, "derive"):
                arg = arg.derive(idx, key_map, change)

            args.append(arg)
        return type(self)(*args)

    @property
    def properties(self):
        return self.PROPS

    @property
    def type(self):
        return self.TYPE

    @classmethod
    def read_from(cls, s, taproot=False):
        op, char = read_until(s, b"(")
        op = op.decode()
        wrappers = ""
        if ":" in op:
            wrappers, op = op.split(":")
        if char != b"(":
            raise ValueError("Missing operator")
        if op not in OPERATOR_NAMES:
            raise ValueError("Unknown operator '%s'" % op)
        # number of arguments, classes of arguments, compile function, type, validity checker
        MiniscriptCls = OPERATORS[OPERATOR_NAMES.index(op)]
        args = MiniscriptCls.read_arguments(s, taproot=taproot)
        miniscript = MiniscriptCls(*args, taproot=taproot)
        for w in reversed(wrappers):
            if w not in WRAPPER_NAMES:
                raise ValueError("Unknown wrapper %s" % w)
            WrapperCls = WRAPPERS[WRAPPER_NAMES.index(w)]
            miniscript = WrapperCls(miniscript, taproot=taproot)
        return miniscript

    @classmethod
    def read_arguments(cls, s, taproot=False):
        args = []
        if cls.NARGS is None:
            if type(cls.ARGCLS) == tuple:
                firstcls, nextcls = cls.ARGCLS
            else:
                firstcls, nextcls = cls.ARGCLS, cls.ARGCLS

            args.append(firstcls.read_from(s, taproot=taproot))
            while True:
                char = s.read(1)
                if char == b",":
                    args.append(nextcls.read_from(s, taproot=taproot))
                elif char == b")":
                    break
                else:
                    raise ValueError(
                        "Expected , or ), got: %s" % (char + s.read())
                    )
        else:
            for i in range(cls.NARGS):
                args.append(cls.ARGCLS.read_from(s, taproot=taproot))
                if i < cls.NARGS - 1:
                    char = s.read(1)
                    if char != b",":
                        raise ValueError("Missing arguments, %s" % char)
            char = s.read(1)
            if char != b")":
                raise ValueError("Expected ) got %s" % (char + s.read()))
        return args

    def to_string(self, external=True, internal=True):
        # meh
        res = type(self).NAME + "("
        res += ",".join([
            arg.to_string(external, internal)
            for arg in self.args
        ])
        res += ")"
        return res

    def __len__(self):
        """Length of the compiled script, override this if you know the length"""
        return len(self.compile())

    def len_args(self):
        return sum([len(arg) for arg in self.args])

########### Known fragments (miniscript operators) ##############


class OneArg(Miniscript):
    NARGS = 1
    # small handy functions
    @property
    def arg(self):
        return self.args[0]

    @property
    def carg(self):
        return self.arg.compile()


class PkK(OneArg):
    # <key>
    NAME = "pk_k"
    ARGCLS = Key
    TYPE = "K"
    PROPS = "ondu"

    def inner_compile(self):
        return self.carg

    def __len__(self):
        return self.len_args()


class PkH(OneArg):
    # DUP HASH160 <HASH160(key)> EQUALVERIFY
    NAME = "pk_h"
    ARGCLS = KeyHash
    TYPE = "K"
    PROPS = "ndu"

    def inner_compile(self):
        return b"\x76\xa9" + self.carg + b"\x88"

    def __len__(self):
        return self.len_args() + 3

class Older(OneArg):
    # <n> CHECKSEQUENCEVERIFY
    NAME = "older"
    ARGCLS = Number
    TYPE = "B"
    PROPS = "z"

    def inner_compile(self):
        return self.carg + b"\xb2"

    def verify(self):
        super().verify()
        if (self.arg.num < 1) or (self.arg.num >= 0x80000000):
            raise ValueError(
                "%s should have an argument in range [1, 0x80000000)" % self.NAME
            )

    def __len__(self):
        return self.len_args() + 1

class After(Older):
    # <n> CHECKLOCKTIMEVERIFY
    NAME = "after"

    def inner_compile(self):
        return self.carg + b"\xb1"


class Sha256(OneArg):
    # SIZE <32> EQUALVERIFY SHA256 <h> EQUAL
    NAME = "sha256"
    ARGCLS = Raw32
    TYPE = "B"
    PROPS = "ondu"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa8" + self.carg + b"\x87"

    def __len__(self):
        return self.len_args() + 6

class Hash256(Sha256):
    # SIZE <32> EQUALVERIFY HASH256 <h> EQUAL
    NAME = "hash256"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xaa" + self.carg + b"\x87"


class Ripemd160(Sha256):
    # SIZE <32> EQUALVERIFY RIPEMD160 <h> EQUAL
    NAME = "ripemd160"
    ARGCLS = Raw20

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa6" + self.carg + b"\x87"


class Hash160(Ripemd160):
    # SIZE <32> EQUALVERIFY HASH160 <h> EQUAL
    NAME = "hash160"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa9" + self.carg + b"\x87"


class AndOr(Miniscript):
    # [X] NOTIF [Z] ELSE [Y] ENDIF
    NAME = "andor"
    NARGS = 3
    ARGCLS = Miniscript

    @property
    def type(self):
        # type same as Y/Z
        return self.args[1].type

    def verify(self):
        # requires: X is Bdu; Y and Z are both B, K, or V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("andor: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise ValueError("andor: X should be 'du'")
        if self.args[1].type != self.args[2].type:
            raise ValueError("andor: Y and Z should have the same types")
        if self.args[1].type not in "BKV":
            raise ValueError("andor: Y and Z should be B K or V")

    @property
    def properties(self):
        # props: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
        props = ""
        px, py, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in py and "z" in pz:
            props += "z"
        if ("z" in px and "o" in py and "o" in pz) or (
            "o" in px and "z" in py and "z" in pz
        ):
            props += "o"
        if "u" in py and "u" in pz:
            props += "u"
        if "d" in pz:
            props += "d"
        return props

    def inner_compile(self):
        return (
            self.args[0].compile()
            + b"\x64"
            + self.args[2].compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 3

class AndV(Miniscript):
    # [X] [Y]
    NAME = "and_v"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile()

    def __len__(self):
        return self.len_args()

    def verify(self):
        # X is V; Y is B, K, or V
        super().verify()
        if self.args[0].type != "V":
            raise ValueError("and_v: X should be 'V'")
        if self.args[1].type not in "BKV":
            raise ValueError("and_v: Y should be B K or V")

    @property
    def type(self):
        # same as Y
        return self.args[1].type

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
        px, py = [arg.properties for arg in self.args]
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "u" in py:
            props += "u"
        return props


class AndB(Miniscript):
    # [X] [Y] BOOLAND
    NAME = "and_b"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile() + b"\x9a"

    def __len__(self):
        return self.len_args() + 1

    def verify(self):
        # X is B; Y is W
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("and_b: X should be B")
        if self.args[1].type != "W":
            raise ValueError("and_b: Y should be W")

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; d=dXdY; u
        px, py = [arg.properties for arg in self.args]
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "d" in px and "d" in py:
            props += "d"
        props += "u"
        return props


class AndN(Miniscript):
    # [X] NOTIF 0 ELSE [Y] ENDIF
    # andor(X,Y,0)
    NAME = "and_n"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return (
            self.args[0].compile()
            + b"\x64"
            + Number(0).compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 4

    @property
    def type(self):
        # type same as Y/Z
        return self.args[1].type

    def verify(self):
        # requires: X is Bdu; Y and Z are both B, K, or V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("and_n: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise ValueError("and_n: X should be 'du'")
        if self.args[1].type != "B":
            raise ValueError("and_n: Y should be B")

    @property
    def properties(self):
        # props: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
        props = ""
        px, py = [arg.properties for arg in self.args]
        pz = "zud"
        if "z" in px and "z" in py and "z" in pz:
            props += "z"
        if ("z" in px and "o" in py and "o" in pz) or (
            "o" in px and "z" in py and "z" in pz
        ):
            props += "o"
        if "u" in py and "u" in pz:
            props += "u"
        if "d" in pz:
            props += "d"
        return props


class OrB(Miniscript):
    # [X] [Z] BOOLOR
    NAME = "or_b"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile() + b"\x9b"

    def __len__(self):
        return self.len_args() + 1

    def verify(self):
        # X is Bd; Z is Wd
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_b: X should be B")
        if "d" not in self.args[0].properties:
            raise ValueError("or_b: X should be d")
        if self.args[1].type != "W":
            raise ValueError("or_b: Z should be W")
        if "d" not in self.args[1].properties:
            raise ValueError("or_b: Z should be d")

    @property
    def properties(self):
        # z=zXzZ; o=zXoZ or zZoX; d; u
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if ("z" in px and "o" in pz) or ("z" in pz and "o" in px):
            props += "o"
        props += "du"
        return props


class OrC(Miniscript):
    # [X] NOTIF [Z] ENDIF
    NAME = "or_c"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "V"

    def inner_compile(self):
        return self.args[0].compile() + b"\x64" + self.args[1].compile() + b"\x68"

    def __len__(self):
        return self.len_args() + 2

    def verify(self):
        # X is Bdu; Z is V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_c: X should be B")
        if self.args[1].type != "V":
            raise ValueError("or_c: Z should be V")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise ValueError("or_c: X should be du")

    @property
    def properties(self):
        # z=zXzZ; o=oXzZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if "o" in px and "z" in pz:
            props += "o"
        return props


class OrD(Miniscript):
    # [X] IFDUP NOTIF [Z] ENDIF
    NAME = "or_d"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + b"\x73\x64" + self.args[1].compile() + b"\x68"

    def __len__(self):
        return self.len_args() + 3

    def verify(self):
        # X is Bdu; Z is B
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_d: X should be B")
        if self.args[1].type != "B":
            raise ValueError("or_d: Z should be B")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise ValueError("or_d: X should be du")

    @property
    def properties(self):
        # z=zXzZ; o=oXzZ; d=dZ; u=uZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if "o" in px and "z" in pz:
            props += "o"
        if "d" in pz:
            props += "d"
        if "u" in pz:
            props += "u"
        return props


class OrI(Miniscript):
    # IF [X] ELSE [Z] ENDIF
    NAME = "or_i"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return (
            b"\x63"
            + self.args[0].compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 3

    def verify(self):
        # both are B, K, or V
        super().verify()
        if self.args[0].type != self.args[1].type:
            raise ValueError("or_i: X and Z should be the same type")
        if self.args[0].type not in "BKV":
            raise ValueError("or_i: X and Z should be B K or V")

    @property
    def type(self):
        return self.args[0].type

    @property
    def properties(self):
        # o=zXzZ; u=uXuZ; d=dX or dZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "o"
        if "u" in px and "u" in pz:
            props += "u"
        if "d" in px or "d" in pz:
            props += "d"
        return props


class Thresh(Miniscript):
    # [X1] [X2] ADD ... [Xn] ADD ... <k> EQUAL
    NAME = "thresh"
    NARGS = None
    ARGCLS = (Number, Miniscript)
    TYPE = "B"

    def inner_compile(self):
        return (
            self.args[1].compile()
            + b"".join([arg.compile()+b"\x93" for arg in self.args[2:]])
            + self.args[0].compile()
            + b"\x87"
        )

    def __len__(self):
        return self.len_args() + len(self.args) - 1

    def verify(self):
        # 1 <= k <= n; X1 is Bdu; others are Wdu
        super().verify()
        if self.args[0].num < 1 or self.args[0].num >= len(self.args):
            raise ValueError(
                "thresh: Invalid k! Should be 1 <= k <= %d, got %d"
                % (len(self.args) - 1, self.args[0].num)
            )
        if self.args[1].type != "B":
            raise ValueError("thresh: X1 should be B")
        px = self.args[1].properties
        if "d" not in px or "u" not in px:
            raise ValueError("thresh: X1 should be du")
        for i, arg in enumerate(self.args[2:]):
            if arg.type != "W":
                raise ValueError("thresh: X%d should be W" % (i + 1))
            p = arg.properties
            if "d" not in p or "u" not in p:
                raise ValueError("thresh: X%d should be du" % (i + 1))

    @property
    def properties(self):
        # z=all are z; o=all are z except one is o; d; u
        props = ""
        parr = [arg.properties for arg in self.args[1:]]
        zarr = ["z" for p in parr if "z" in p]
        if len(zarr) == len(parr):
            props += "z"
        noz = [p for p in parr if "z" not in p]
        if len(noz) == 1 and "o" in noz[0]:
            props += "o"
        props += "du"
        return props


class Multi(Miniscript):
    # <k> <key1> ... <keyn> <n> CHECKMULTISIG
    NAME = "multi"
    NARGS = None
    ARGCLS = (Number, Key)
    TYPE = "B"
    PROPS = "ndu"
    N_MAX = 20

    def inner_compile(self):
        # scr = [arg.compile() for arg in self.args[1:]]
        # optimization - it is all keys with known length (xonly keys not allowed here)
        scr = [b'\x21' + arg.key_bytes() for arg in self.args[1:]]
        if self.NAME == "sortedmulti":
            scr.sort()
        return (
            self.args[0].compile()
            + b"".join(scr)
            + Number(len(self.args) - 1).compile()
            + b"\xae"
        )

    def __len__(self):
        return self.len_args() + 2

    def m_n(self):
        return self.args[0].num, len(self.args[1:])

    def verify(self):
        super().verify()
        N = (len(self.args) - 1)
        assert N <= self.N_MAX, 'M/N range'
        M = self.args[0].num
        if M < 1 or M > N:
            raise ValueError(
                "M must be <= N: 1 <= M <= %d, got %d" % ((len(self.args) - 1), self.args[0].num)
            )


class Sortedmulti(Multi):
    # <k> <key1> ... <keyn> <n> CHECKMULTISIG
    NAME = "sortedmulti"


class Multi_a(Multi):
    # <key1> CHECKSIG <key> CHECKSIGADD ... <keyn> CHECKSIGADD EQUALVERIFY
    NAME = "multi_a"
    PROPS = "du"
    N_MAX = MAX_TR_SIGNERS

    def inner_compile(self):
        from opcodes import OP_CHECKSIGADD, OP_NUMEQUAL, OP_CHECKSIG
        script = b""
        # scr = [arg.compile() for arg in self.args[1:]]
        # optimization - it is all keys with known length (only xonly keys allowed here)
        scr = [b"\x20" + arg.key_bytes() for arg in self.args[1:]]
        if self.NAME == "sortedmulti_a":
            scr.sort()

        for i, key in enumerate(scr):
            script += key
            if i == 0:
                script += bytes([OP_CHECKSIG])
            else:
                script += bytes([OP_CHECKSIGADD])

        script += self.args[0].compile()  # M (threshold)
        script += bytes([OP_NUMEQUAL])
        return script

    def __len__(self):
        # len(M) + len(k0) ... + len(kN) + len(keys) + 1
        return self.len_args() + len(self.args)


class Sortedmulti_a(Multi_a):
    # <key1> CHECKSIG <key> CHECKSIGADD ... <keyn> CHECKSIGADD EQUALVERIFY
    NAME = "sortedmulti_a"


class Pk(OneArg):
    # <key> CHECKSIG
    NAME = "pk"
    ARGCLS = Key
    TYPE = "B"
    PROPS = "ondu"

    def inner_compile(self):
        return self.carg + b"\xac"

    def __len__(self):
        return self.len_args() + 1


class Pkh(OneArg):
    # DUP HASH160 <HASH160(key)> EQUALVERIFY CHECKSIG
    NAME = "pkh"
    ARGCLS = KeyHash
    TYPE = "B"
    PROPS = "ndu"

    def inner_compile(self):
        return b"\x76\xa9" + self.carg + b"\x88\xac"

    def __len__(self):
        return self.len_args() + 4


OPERATORS = [
    PkK,
    PkH,
    Older,
    After,
    Sha256,
    Hash256,
    Ripemd160,
    Hash160,
    AndOr,
    AndV,
    AndB,
    AndN,
    OrB,
    OrC,
    OrD,
    OrI,
    Thresh,
    Multi,
    Sortedmulti,
    Multi_a,
    Sortedmulti_a,
    Pk,
    Pkh,
]
OPERATOR_NAMES = [cls.NAME for cls in OPERATORS]


class Wrapper(OneArg):
    ARGCLS = Miniscript

    @property
    def op(self):
        return type(self).__name__.lower()

    def to_string(self, *args, **kwargs):
        # more wrappers follow
        if isinstance(self.arg, Wrapper):
            return self.op + self.arg.to_string(*args, **kwargs)
        # we are the last wrapper
        return self.op + ":" + self.arg.to_string(*args, **kwargs)


class A(Wrapper):
    # TOALTSTACK [X] FROMALTSTACK
    TYPE = "W"

    def inner_compile(self):
        return b"\x6b" + self.carg + b"\x6c"

    def __len__(self):
        return len(self.arg) + 2

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("a: X should be B")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        if "d" in px:
            props += "d"
        if "u" in px:
            props += "u"
        return props


class S(Wrapper):
    # SWAP [X]
    TYPE = "W"

    def inner_compile(self):
        return b"\x7c" + self.carg

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("s: X should be B")
        if "o" not in self.arg.properties:
            raise ValueError("s: X should be o")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        if "d" in px:
            props += "d"
        if "u" in px:
            props += "u"
        return props


class C(Wrapper):
    # [X] CHECKSIG
    TYPE = "B"

    def inner_compile(self):
        return self.carg + b"\xac"

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "K":
            raise ValueError("c: X should be K")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        for p in ["o", "n", "d"]:
            if p in px:
                props += p
        props += "u"
        return props


class T(Wrapper):
    # [X] 1
    TYPE = "B"

    def inner_compile(self):
        return self.carg + Number(1).compile()

    def __len__(self):
        return len(self.arg) + 1

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
        px = self.arg.properties
        py = "zu"
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "u" in py:
            props += "u"
        return props


class D(Wrapper):
    # DUP IF [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x76\x63" + self.carg + b"\x68"

    def __len__(self):
        return len(self.arg) + 3

    def verify(self):
        super().verify()
        if self.arg.type != "V":
            raise ValueError("d: X should be V")
        if "z" not in self.arg.properties:
            raise ValueError("d: X should be z")

    @property
    def properties(self):
        # https://github.com/bitcoin/bitcoin/pull/24906
        if self.taproot:
            props = "ndu"
        else:
            props = "nd"
        px = self.arg.properties
        if "z" in px:
            props += "o"
        return props


class V(Wrapper):
    # [X] VERIFY (or VERIFY version of last opcode in [X])
    TYPE = "V"

    def inner_compile(self):
        """Checks last check code and makes it verify"""
        if self.carg[-1] in [0xAC, 0xAE, 0x9C, 0x87]:
            return self.carg[:-1] + bytes([self.carg[-1] + 1])
        return self.carg + b"\x69"

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("v: X should be B")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        for p in ["z", "o", "n"]:
            if p in px:
                props += p
        return props


class J(Wrapper):
    # SIZE 0NOTEQUAL IF [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x82\x92\x63" + self.carg + b"\x68"

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("j: X should be B")
        if "n" not in self.arg.properties:
            raise ValueError("j: X should be n")

    @property
    def properties(self):
        props = "nd"
        px = self.arg.properties
        for p in ["o", "u"]:
            if p in px:
                props += p
        return props


class N(Wrapper):
    # [X] 0NOTEQUAL
    TYPE = "B"

    def inner_compile(self):
        return self.carg + b"\x92"

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("n: X should be B")

    @property
    def properties(self):
        props = "u"
        px = self.arg.properties
        for p in ["z", "o", "n", "d"]:
            if p in px:
                props += p
        return props


class L(Wrapper):
    # IF 0 ELSE [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x63" + Number(0).compile() + b"\x67" + self.carg + b"\x68"

    def __len__(self):
        return len(self.arg) + 4

    def verify(self):
        # both are B, K, or V
        super().verify()
        if self.arg.type != "B":
            raise ValueError("or_i: X and Z should be the same type")

    @property
    def properties(self):
        # o=zXzZ; u=uXuZ; d=dX or dZ
        props = "d"
        pz = self.arg.properties
        if "z" in pz:
            props += "o"
        if "u" in pz:
            props += "u"
        return props


class U(L):
    # IF [X] ELSE 0 ENDIF
    def inner_compile(self):
        return b"\x63" + self.carg + b"\x67" + Number(0).compile() + b"\x68"

    def __len__(self):
        return len(self.arg) + 4


WRAPPERS = [A, S, C, T, D, V, J, N, L, U]
WRAPPER_NAMES = [w.__name__.lower() for w in WRAPPERS]