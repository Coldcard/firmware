# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/miniscript.py
#
import ngu, ujson, uio, chains, ure, version
from ucollections import OrderedDict
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from serializations import ser_compact_size, ser_string
from desc_utils import Key, read_until, fill_policy, append_checksum
from public_constants import MAX_TR_SIGNERS
from wallet import BaseStorageWallet
from menu import MenuSystem, MenuItem
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
from files import CardSlot, CardMissingError, needs_microsd
from utils import problem_file_line, xfp2str, addr_fmt_label, truncate_address, to_ascii_printable, swab32
from charcodes import KEY_QR, KEY_CANCEL, KEY_NFC, KEY_ENTER


class MiniscriptException(ValueError):
    pass


class MiniScriptWallet(BaseStorageWallet):
    key_name = "miniscript"

    def __init__(self, desc=None, policy=None, keys=None, key=None,
                 af=None, name=None, taproot=False, sh=False, wsh=False,
                 wpkh=False, chain_type=None):
        super().__init__(chain_type=chain_type)
        self._policy = policy
        self._keys = keys
        self._key = key
        self._af = af
        self._taproot = taproot
        self._sh = sh
        self._wsh = wsh
        self._wpkh = wpkh
        self._desc = desc
        self.name = name

    @property
    def policy(self):
        if not self._policy:
            self._policy = self.desc.storage_policy()
        return self._policy

    @property
    def keys(self):
        if not self._keys:
            self._keys = self.desc.keys
            if self._keys is not None:
                self._keys = [k.to_string() for k in self._keys]
        return self._keys

    @property
    def key(self):
        if not self._key:
            self._key = self.desc.key
            if self._key is not None:
                self._key = self._key.to_string()
        return self._key

    @property
    def addr_fmt(self):
        if not self._af:
            self._af = self.desc.addr_fmt
        return self._af

    @property
    def taproot(self):
        if not self._taproot:
            self._taproot = self.desc.taproot
        return self._taproot

    @property
    def sh(self):
        if not self._sh:
            self._sh = self.desc.sh
        return self._sh

    @property
    def wsh(self):
        if not self._wsh:
            self._wsh = self.desc.wsh
        return self._wsh

    @property
    def wpkh(self):
        if not self._wpkh:
            self._wpkh = self.desc.wpkh
        return self._wpkh

    @property
    def desc(self):
        if self._desc is None:
            from descriptor import Descriptor, Tapscript

            ts = None
            ms = None
            key = None
            if self._key:
                key = Key.from_string(self._key)

            filled_policy = fill_policy(self.policy, self.keys)
            if self._taproot and self._policy:
                # tapscript
                ts = Tapscript.read_from(uio.BytesIO(filled_policy))
            elif self._policy:
                # miniscript
                ms = Miniscript.read_from(uio.BytesIO(filled_policy))
            self._desc = Descriptor(key=key, tapscript=ts, miniscript=ms,
                                    taproot=self._taproot, sh=self._sh,
                                    wsh=self._wsh, wpkh=self._wpkh)
            self._desc.set_from_addr_fmt(self._af)
        return self._desc

    def to_descriptor(self):
        return self.desc

    def serialize(self):
        policy = None
        key = None
        if self.desc.key:
            key = self.desc.key.to_string()

        keys = [k.to_string() for k in self.desc.keys]
        if self.desc.tapscript or self.desc.miniscript:
            policy = self.desc.storage_policy()

        sh = self.desc.sh
        wsh = self.desc.wsh
        wpkh = self.desc.wpkh
        taproot = self.desc.taproot
        return (
            self.name,
            self.chain_type,
            self.desc.addr_fmt,
            key,
            keys,
            policy,
            sh, wsh, wpkh, taproot
        )

    @classmethod
    def deserialize(cls, c, idx=-1):
        name, ct, af, key, keys, policy, sh, wsh, wpkh, taproot = c
        rv = cls(name=name, key=key, keys=keys, policy=policy, af=af,
                 taproot=taproot, sh=sh, wsh=wsh, wpkh=wpkh,
                 chain_type=ct)
        rv.storage_idx = idx
        return rv

    def xfp_paths(self):
        if self._desc is None:
            res = []
            if self._key:
                ik = Key.from_string(self.key)
                if ik.origin:
                    res.append(ik.origin.psbt_derivation())
                elif not isinstance(ik.node, bytes):
                    if ik.is_provably_unspendable:
                        res.append([swab32(ik.node.my_fp())])

            for k in self.keys:
                k = Key.from_string(k)
                if k.origin:
                    res.append(k.origin.psbt_derivation())
            return res
        return self.desc.xfp_paths()

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
        my_xfp_paths = self.xfp_paths()
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
        my_xfp_paths = self.desc.xfp_paths()
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

    def derive_desc(self, xfp_paths):
        branch, idx = self.subderivation_indexes(xfp_paths)
        derived_desc = self.desc.derive(branch).derive(idx)
        return derived_desc

    def validate_script(self, redeem_script, xfp_paths, script_pubkey=None):
        derived_desc = self.derive_desc(xfp_paths)
        assert derived_desc.miniscript.compile() == redeem_script, "script mismatch"
        if script_pubkey:
            assert script_pubkey == derived_desc.script_pubkey(), "spk mismatch"
        return derived_desc

    def validate_script_pubkey(self, script_pubkey, xfp_paths, merkle_root=None):
        derived_desc = self.derive_desc(xfp_paths)
        derived_spk = derived_desc.script_pubkey()
        assert derived_spk == script_pubkey, "spk mismatch"
        if merkle_root:
            assert derived_desc.tapscript.merkle_root == merkle_root, "psbt merkle root"
        return derived_desc

    def ux_policy(self):
        if self.taproot and self.policy:
            return "Tapscript:\n\n" + self.policy
        return self.policy

    async def _detail(self, new_wallet=False, is_duplicate=False, short=False):

        s = addr_fmt_label(self.addr_fmt) + "\n\n"
        if self.taproot:
            s += self.taproot_internal_key_detail(short=short)

        s += self.ux_policy()

        story = s + "\n\nPress (1) to see extended public keys"
        if new_wallet and not is_duplicate:
            story += ", OK to approve, X to cancel."
        return story

    async def show_detail(self, new_wallet=False, duplicates=None, short=False):
        title = self.name
        story = ""
        if duplicates:
            title = None
            story += "This wallet is a duplicate of already saved wallet %s\n\n" % duplicates[0].name
        elif new_wallet:
            title = None
            story += "Create new miniscript wallet?\n\nWallet Name:\n  %s\n\n" % self.name
        story += await self._detail(new_wallet, is_duplicate=duplicates, short=short)
        while True:
            ch = await ux_show_story(story, title=title, escape="1")
            if ch == "1":
                await self.show_keys()

            elif ch != "y":
                return None
            else:
                return True

    def taproot_internal_key_detail(self, short=False):
        if self.taproot:
            key = Key.from_string(self.key)
            s = "Taproot internal key:\n\n"
            if key.is_provably_unspendable:
                note = "provably unspendable"
                if short:
                    s += note
                else:
                    if isinstance(key.node, bytes):
                        s += b2a_hex(key.node).decode()
                        s += "\n (%s)" % note
                    else:
                        s += self.key
                        if type(key) is Key:
                            # it is unspendable, BUT not unspend(
                            s += "\n (%s)" % note
                s += "\n\n"
            else:
                xfp, deriv, xpub = key.to_cc_data()
                s += '%s:\n  %s\n\n%s/%s\n\n' % (xfp2str(xfp), deriv, xpub,
                                                 key.derivation.to_string())
            return s

    async def show_keys(self):
        msg = ""
        if self.taproot:
            msg = self.taproot_internal_key_detail()
            msg += "Taproot tree keys:\n\n"

        orig_keys = OrderedDict()
        for k in self.keys:
            if isinstance(k, str):
                k = Key.from_string(k)
            if k.origin not in orig_keys:
                orig_keys[k.origin] = []
            orig_keys[k.origin].append(k)

        for idx, k_lst in enumerate(orig_keys.values()):
            subderiv = True if len(k_lst) == 1 else False
            if idx:
                msg += '\n---===---\n\n'

            msg += '@%s:\n  %s\n\n' % (idx, k_lst[0].to_string(subderiv=subderiv))

        await ux_show_story(msg)

    @classmethod
    def from_file(cls, config, name=None):
        from descriptor import Descriptor
        if name is None:
            desc_obj, cs = Descriptor.from_string(config.strip(), checksum=True)
            name = cs
        else:
            name = to_ascii_printable(name)
            desc_obj = Descriptor.from_string(config.strip())
        assert not desc_obj.is_basic_multisig, "Use Settings -> Multisig Wallets"
        wal = cls(desc_obj, name=name, chain_type=desc_obj.keys[0].chain_type)
        return wal

    def find_duplicates(self):
        matches = []
        name_unique = True
        for rv in self.iter_wallets():
            if self.name == rv.name:
                name_unique = False
            if self.key != rv.key:
                continue
            if self.policy != rv.policy:
                continue
            if len(self.keys) != len(rv.keys):
                continue
            if self.keys != rv.keys:
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
            await ux_dramatic_pause("Saved.", 2)

        return ch

    def yield_addresses(self, start_idx, count, change=False, scripts=True, change_idx=0):
        ch = chains.current_chain()
        dd = self.desc.derive(None, change=change)
        idx = start_idx
        while count:
            # make the redeem script, convert into address
            d = dd.derive(idx)
            addr = ch.render_address(d.script_pubkey())

            script = ""
            if scripts:
                if d.tapscript:
                    script = d.tapscript.script_tree(d.tapscript.tree)
                else:
                    script = b2a_hex(ser_string(d.miniscript.compile())).decode()

            if d.tapscript:
                yield (idx,
                       addr,
                       ["[%s]" % str(k.origin) for k in d.keys],
                       script,
                       d.key.serialize(),
                       str(d.key.origin) if d.key.origin else "")
            else:
                yield (idx,
                       addr,
                       ["[%s]" % str(k.origin) for k in d.keys],
                       script,
                       None,
                       None)

            idx += 1
            count -= 1

    def make_addresses_msg(self, msg, start, n, change=0):
        from glob import dis

        addrs = []

        for idx, addr, paths, _, ik, _ in self.yield_addresses(start, n,
                                                             change=bool(change),
                                                             scripts=False):
            if idx == 0 and len(paths) <= 4 and not ik:
                msg += '\n'.join(paths) + '\n =>\n'
            else:
                change_idx = set([int(p.split("/")[-2]) for p in paths])
                if len(change_idx) == 1:
                    msg += '.../%d/%d =>\n' % (list(change_idx)[0], idx)
                else:
                    msg += '.../%d =>\n' % idx

            addrs.append(addr)
            msg += truncate_address(addr) + '\n\n'
            dis.progress_sofar(idx - start + 1, n)

        return msg, addrs

    def generate_address_csv(self, start, n, change):
        part = []
        if self.taproot:
            scr_h = "Taptree"
            if self.desc.key.is_provably_unspendable:
                part = ["Unspendable Internal Key"]
            else:
                part = ["Internal Key"]

        else:
            scr_h = "Script"

        yield '"' + '","'.join(
            ['Index', 'Payment Address', scr_h] + ['Derivation'] * len(self.keys)
            + part
        ) + '"\n'
        for (idx, addr, derivs, script, ik, ikp) in self.yield_addresses(start, n,
                                                                         change=bool(change)):
            ln = '%d,"%s","%s","' % (idx, addr, script)
            ln += '","'.join(derivs)
            if ik:
                # internal xonly key with its derivation (if any)
                if ikp:
                    ln += '","[%s]%s' % (ikp, b2a_hex(ik).decode())
                else:
                    ln += '","%s' % (b2a_hex(ik).decode())
            ln += '"\n'

            yield ln

    def bitcoin_core_serialize(self):
        # this will become legacy one day
        # instead use <0;1> descriptor format
        res = []
        for external in (True, False):
            desc_obj = {
                "desc": self.to_string(external, not external, unspend_compat=True),
                "active": True,
                "timestamp": "now",
                "internal": not external,
                "range": [0, 100],
            }
            res.append(desc_obj)
        return res

    def to_string(self, external=True, internal=True, checksum=True, unspend_compat=False):
        if self._key:
            key = self._key
            if "unspend(" in key and unspend_compat:
                # for bitcoin core that does not support 'unspend(' descriptor notation
                # serialize 'unspend(' as classic extended key
                k = Key.from_string(self.key)
                key = k.extended_public_key()
                if k.derivation:
                    key += "/" + k.derivation.to_string(external, internal)

            multipath_rgx = ure.compile(r"<\d+;\d+>")
            match = multipath_rgx.search(key)
            if match:
                mp = match.group(0)
                ext, int = mp[1:-1].split(";")
                if internal != external:
                    to_replace = ext if external else int
                    key = self._key.replace(mp, to_replace)
        if self._taproot:
            desc = "tr(%s" % key
            if self.policy:
                desc += ","
                tree = fill_policy(self._policy, self._keys,
                                   external, internal)
                desc += tree

            res = desc + ")"

        elif self._policy:
            res = fill_policy(self._policy, self._keys,
                              external, internal)
            if self._wsh:
                res = "wsh(%s)" % res
        else:
            if self._wpkh:
                res = "wpkh(%s)" % self._key
            else:
                res = "pkh(%s)" % self._key

        if self._sh:
            res = "sh(%s)" % res

        if checksum:
            res = append_checksum(res)
        return res

    async def export_wallet_file(self, mode="exported from", extra_msg=None, descriptor=False,
                                 core=False, desc_pretty=True):
        from glob import NFC, dis
        from ux import import_export_prompt

        if core:
            name = "Bitcoin Core miniscript"
            fname_pattern = 'bitcoin-core-%s' % self.name
        else:
            name = "Miniscript"
            fname_pattern = 'minsc-%s' % self.name

        fname_pattern = fname_pattern + ".txt"

        if core:
            msg = "importdescriptors cmd"
            dis.fullscreen('Wait...')
            core_obj = self.bitcoin_core_serialize()
            core_str = ujson.dumps(core_obj)
            res = "importdescriptors '%s'\n" % core_str
        # elif desc_pretty:
        #     pass TODO
        else:
            msg = self.name
            int_ext = True
            ch = await ux_show_story(
                "To export receiving and change descriptors in one descriptor (<0;1> notation) press OK, "
                "press (1) to export receiving and change descriptors separately.", escape='1')
            if ch == "1":
                int_ext = False
            elif ch != "y":
                return

            dis.fullscreen('Wait...')
            if int_ext:
                res = self.to_string()
            else:
                res = "%s\n%s" % (
                    self.to_string(internal=False),
                    self.to_string(external=False),
                )

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

    return await msc.show_detail(short=True)

async def import_miniscript(*a):
    # pick text file from SD card, import as multisig setup file
    from actions import file_picker
    from glob import dis
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
        maybe_enroll_xpub(config=data, name=possible_name, miniscript=True)
    except BaseException as e:
        await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

async def import_miniscript_nfc(*a):
    from glob import NFC
    try:
        return await NFC.import_miniscript_nfc()
    except Exception as e:
        await ux_show_story(title="ERROR", msg="Failed to import miniscript. %s" % str(e))

async def import_miniscript_qr(*a):
    from auth import maybe_enroll_xpub
    from ux_q1 import QRScannerInteraction
    data = await QRScannerInteraction().scan_text('Scan Miniscript from a QR code')
    if not data:
        # press pressed CANCEL
        return

    try:
        maybe_enroll_xpub(config=data, miniscript=True)
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

        exists, exists_other_chain = MiniScriptWallet.exists()
        if not exists:
            rv = [MenuItem(MiniScriptWallet.none_setup_yet(exists_other_chain), f=no_miniscript_yet)]
        else:
            rv = []
            for msc in MiniScriptWallet.get_all():
                rv.append(MenuItem('%s' % msc.name,
                                   menu=make_miniscript_wallet_menu,
                                   arg=msc.storage_idx))
        from glob import NFC
        rv.append(MenuItem('Import', f=import_miniscript))
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
        if self.taproot:
            return ngu.hash.hash160(self.node.pubkey()[1:33])
        return ngu.hash.hash160(self.node.pubkey())

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
        return sum(
            [arg.keys for arg in self.args if isinstance(arg, Miniscript)],
            [k for k in self.args if isinstance(k, Key) or isinstance(k, KeyHash)],
        )

    def is_sane(self, taproot=False):
        err = "multi mixin"
        # cannot have same keys in single miniscript
        forbiden = (Sortedmulti_a, Multi_a)
        keys = self.keys
        # provably unspendable taproot internal key is not covered here
        # all other keys (miniscript,tapscript) require key origin info
        assert all(k.origin for k in keys), "Key origin info is required"
        assert len(keys) == len(set(keys)), "Insane"
        if taproot:
            forbiden = (Sortedmulti, Multi)

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
            if hasattr(arg, "derive"):
                if isinstance(arg, Key) or isinstance(arg, KeyHash):
                    arg = self.key_derive(arg, idx, key_map, change=change)
                else:
                    arg = arg.derive(idx, change=change)

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
            raise MiniscriptException("Missing operator")
        if op not in OPERATOR_NAMES:
            raise MiniscriptException("Unknown operator '%s'" % op)
        # number of arguments, classes of arguments, compile function, type, validity checker
        MiniscriptCls = OPERATORS[OPERATOR_NAMES.index(op)]
        args = MiniscriptCls.read_arguments(s, taproot=taproot)
        miniscript = MiniscriptCls(*args, taproot=taproot)
        for w in reversed(wrappers):
            if w not in WRAPPER_NAMES:
                raise MiniscriptException("Unknown wrapper %s" % w)
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
                    raise MiniscriptException(
                        "Expected , or ), got: %s" % (char + s.read())
                    )
        else:
            for i in range(cls.NARGS):
                args.append(cls.ARGCLS.read_from(s, taproot=taproot))
                if i < cls.NARGS - 1:
                    char = s.read(1)
                    if char != b",":
                        raise MiniscriptException("Missing arguments, %s" % char)
            char = s.read(1)
            if char != b")":
                raise MiniscriptException("Expected ) got %s" % (char + s.read()))
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
            raise MiniscriptException(
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
            raise MiniscriptException("andor: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise MiniscriptException("andor: X should be 'du'")
        if self.args[1].type != self.args[2].type:
            raise MiniscriptException("andor: Y and Z should have the same types")
        if self.args[1].type not in "BKV":
            raise MiniscriptException("andor: Y and Z should be B K or V")

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
            raise MiniscriptException("and_v: X should be 'V'")
        if self.args[1].type not in "BKV":
            raise MiniscriptException("and_v: Y should be B K or V")

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
            raise MiniscriptException("and_b: X should be B")
        if self.args[1].type != "W":
            raise MiniscriptException("and_b: Y should be W")

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
            raise MiniscriptException("and_n: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise MiniscriptException("and_n: X should be 'du'")
        if self.args[1].type != "B":
            raise MiniscriptException("and_n: Y should be B")

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
            raise MiniscriptException("or_b: X should be B")
        if "d" not in self.args[0].properties:
            raise MiniscriptException("or_b: X should be d")
        if self.args[1].type != "W":
            raise MiniscriptException("or_b: Z should be W")
        if "d" not in self.args[1].properties:
            raise MiniscriptException("or_b: Z should be d")

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
            raise MiniscriptException("or_c: X should be B")
        if self.args[1].type != "V":
            raise MiniscriptException("or_c: Z should be V")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise MiniscriptException("or_c: X should be du")

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
            raise MiniscriptException("or_d: X should be B")
        if self.args[1].type != "B":
            raise MiniscriptException("or_d: Z should be B")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise MiniscriptException("or_d: X should be du")

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
            raise MiniscriptException("or_i: X and Z should be the same type")
        if self.args[0].type not in "BKV":
            raise MiniscriptException("or_i: X and Z should be B K or V")

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
            raise MiniscriptException(
                "thresh: Invalid k! Should be 1 <= k <= %d, got %d"
                % (len(self.args) - 1, self.args[0].num)
            )
        if self.args[1].type != "B":
            raise MiniscriptException("thresh: X1 should be B")
        px = self.args[1].properties
        if "d" not in px or "u" not in px:
            raise MiniscriptException("thresh: X1 should be du")
        for i, arg in enumerate(self.args[2:]):
            if arg.type != "W":
                raise MiniscriptException("thresh: X%d should be W" % (i + 1))
            p = arg.properties
            if "d" not in p or "u" not in p:
                raise MiniscriptException("thresh: X%d should be du" % (i + 1))

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
        return (
            b"".join([arg.compile() for arg in self.args])
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

    def inner_compile(self):
        return (
            self.args[0].compile()
            + b"".join(sorted([arg.compile() for arg in self.args[1:]]))
            + Number(len(self.args) - 1).compile()
            + b"\xae"
        )

class Multi_a(Multi):
    # <key1> CHECKSIG <key> CHECKSIGADD ... <keyn> CHECKSIGADD EQUALVERIFY
    NAME = "multi_a"
    PROPS = "du"
    N_MAX = MAX_TR_SIGNERS

    def inner_compile(self):
        from opcodes import OP_CHECKSIGADD, OP_NUMEQUAL, OP_CHECKSIG
        script = b""
        for i, key in enumerate(self.args[1:]):
            script += key.compile()
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

    def inner_compile(self):
        from opcodes import OP_CHECKSIGADD, OP_NUMEQUAL, OP_CHECKSIG
        script = b""
        for i, key in enumerate(sorted([arg.compile() for arg in self.args[1:]])):
            script += key
            if i == 0:
                script += bytes([OP_CHECKSIG])
            else:
                script += bytes([OP_CHECKSIGADD])
        script += self.args[0].compile()  # M (threshold)
        script += bytes([OP_NUMEQUAL])
        return script


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
            raise MiniscriptException("a: X should be B")

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
            raise MiniscriptException("s: X should be B")
        if "o" not in self.arg.properties:
            raise MiniscriptException("s: X should be o")

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
            raise MiniscriptException("c: X should be K")

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
            raise MiniscriptException("d: X should be V")
        if "z" not in self.arg.properties:
            raise MiniscriptException("d: X should be z")

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
            raise MiniscriptException("v: X should be B")

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
            raise MiniscriptException("j: X should be B")
        if "n" not in self.arg.properties:
            raise MiniscriptException("j: X should be n")

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
            raise MiniscriptException("n: X should be B")

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
            raise MiniscriptException("or_i: X and Z should be the same type")

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