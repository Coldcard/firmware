# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# wallet.py - A place you find UTXO, addresses and descriptors.
#

import ngu, ujson, uio, chains, ure, version, stash
from binascii import hexlify as b2a_hex
from serializations import ser_string
from desc_utils import bip388_wallet_policy_to_descriptor, append_checksum, bip388_validate_policy, Key
from public_constants import AF_P2TR, AF_P2WSH, AF_CLASSIC, AF_P2SH
from menu import MenuSystem, MenuItem, start_chooser
from ux import ux_show_story, ux_confirm, ux_dramatic_pause, OK, X, ux_enter_bip32_index
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

MAX_BIP32_IDX = (2 ** 31) - 1


class WalletOutOfSpace(RuntimeError):
    pass


class WalletABC:
    # How to make this ABC useful without consuming memory/code space??
    # - be more of an "interface" than a base class
    
    #   name
    #   addr_fmt
    #   chain

    def yield_addresses(self, start_idx, count, change_idx=0):
        # returns various tuples, with at least (idx, address, ...)
        pass

    def render_address(self, change_idx, idx):
        # make one single address as text.

        tmp = list(self.yield_addresses(idx, 1, change_idx=change_idx))

        assert len(tmp) == 1
        assert tmp[0][0] == idx

        return tmp[0][1]

    def to_descriptor(self):
        pass

class MasterSingleSigWallet(WalletABC):
    # Refers to current seed phrase, whichever is loaded master or temporary
    def __init__(self, addr_fmt, path=None, account_idx=0, chain_name=None):
        # Construct a wallet based on current master secret, and chain.
        # - path is optional, and then we use standard path for addr_fmt
        # - path can be overriden when we come here via address explorer

        n = chains.addr_fmt_label(addr_fmt)
        purpose = chains.af_to_bip44_purpose(addr_fmt)
        prefix = path or 'm/%dh/{coin_type}h/{account}h' % purpose

        if chain_name:
            self.chain = chains.get_chain(chain_name)
        else:
            self.chain = chains.current_chain()

        if account_idx != 0:
            n += ' Account#%d' % account_idx

        if self.chain.ctype == 'XTN':
            n += ' (Testnet)'
        if self.chain.ctype == 'XRT':
            n += ' (Regtest)'

        self.name = n
        self.addr_fmt = addr_fmt

        # Figure out the derivation path
        # - we want to store path w/o change and index part
        p = prefix.format(account=account_idx, coin_type=self.chain.b44_cointype,
                                                    change='C', idx='I')
        if p.endswith('/C/I'):
            p = p[:-4]
        if p.endswith('/I'):
            # custom path in addr explorer can get this
            p = p[:-2]

        self._path = p

    def yield_addresses(self, start_idx, count, change_idx=None):
        # Render a range of addresses. Slow to start, since accesses SE in general
        # - if count==1, don't derive any subkey, just do path.
        path = self._path
        if change_idx is not None:
            assert 0 <= change_idx <= 1
            path += '/%d' % change_idx

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(path)

            if count is None:  # special case - showing single, ignoring start_idx
                address = self.chain.address(node, self.addr_fmt)
                yield 0, address, path
                return

            path += '/'
            for idx in range(start_idx, start_idx+count):
                if idx > MAX_BIP32_IDX:
                    break
                try:
                    here = node.copy()
                    here.derive(idx, False)            # works in-place
                    address = self.chain.address(here, self.addr_fmt)
                finally:
                    here.blank()
                    del here

                yield idx, address, path+str(idx)

    def render_address(self, change_idx, idx):
        # Optimized for a single address.
        path = self._path + '/%d/%d' % (change_idx, idx)
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(path)
            return self.chain.address(node, self.addr_fmt)

    def render_path(self, change_idx, idx):
        # show the derivation path for an address
        return self._path + '/%d/%d' % (change_idx, idx)

    def to_descriptor(self):
        from glob import settings
        from descriptor import Descriptor, Key
        xfp = settings.get('xfp')
        xpub = settings.get('xpub')
        d = Descriptor(key=Key.from_cc_data(xfp, self._path, xpub), addr_fmt=self.addr_fmt)
        return d


class MiniScriptWallet(WalletABC):
    skey = "miniscript"
    disable_checks = False

    def __init__(self, name, desc_tmplt, keys_info, af, ik_u,
                 desc=None, m_n=None, bip67=None):

        assert len(name) <= 20, "name > 20"

        self.storage_idx = -1
        self.name = name
        self.desc_tmplt = desc_tmplt
        self.keys_info = keys_info
        self.desc = desc
        self.addr_fmt = af
        # internal key unspendable
        self.ik_u = ik_u
        # below are basic multisig meta
        # if m_n is not None, we are dealing with basic multisig
        self.m_n = m_n
        self.bip67 = bip67

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        return bool(settings.get(cls.skey, []))

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        return cls.iter_wallets()

    @classmethod
    def iter_wallets(cls):
        # - this is only place we should be searching this list, please!!
        lst = settings.get(cls.skey, [])
        for idx, rec in enumerate(lst):
            yield cls.deserialize(rec, idx)

    @classmethod
    def get_by_idx(cls, nth):
        # instance from index number (used in menu)
        lst = settings.get(cls.skey, [])
        try:
            obj = lst[nth]
        except IndexError:
            return None

        x = cls.deserialize(obj, nth)
        return x

    def commit(self):
        # data to save
        # - important that this fails immediately when nvram overflows
        obj = self.serialize()

        v = settings.get(self.skey, [])
        orig = v.copy()
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update in place
            v[self.storage_idx] = obj

        settings.set(self.skey, v)

        # save now, rather than in background, so we can recover
        # from out-of-space situation
        try:
            settings.save()
        except:
            # back out change; no longer sure of NVRAM state
            try:
                settings.set(self.skey, orig)
                settings.save()
            except: pass        # give up on recovery

            raise WalletOutOfSpace

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        assert self.storage_idx >= 0
        lst = settings.get(self.skey, [])
        try:
            del lst[self.storage_idx]
            if lst:
                settings.set(self.skey, lst)
            else:
                settings.remove_key(self.skey)

            settings.save()  # actual write
        except IndexError: pass
        self.storage_idx = -1

    def serialize(self):
        return (self.name, self.desc_tmplt, self.keys_info,
                self.addr_fmt, self.ik_u, self.m_n, self.bip67)

    @classmethod
    def deserialize(cls, c, idx=-1):
        # after deserialization - we lack loaded descriptor object
        # we do not need it for everything
        name, desc_tmplt, keys_info, af, ik_u, m_n, b67 = c
        rv = cls(name, desc_tmplt, keys_info, af, ik_u, m_n=m_n, bip67=b67)
        rv.storage_idx = idx
        return rv

    @classmethod
    def get_trust_policy(cls):
        which = settings.get('pms', None)
        if which is None:
            which = TRUST_VERIFY if cls.exists() else TRUST_OFFER

        return which

    @property
    def chain(self):
        return chains.current_chain()

    @classmethod
    def find_match(cls, xfp_paths, addr_fmt=None, M_N=None):
        for rv in cls.iter_wallets():
            if addr_fmt is not None:
                if rv.addr_fmt != addr_fmt:
                    continue

            if M_N:
                if not rv.m_n:
                    continue
                if rv.m_n != M_N:
                    continue

            if rv.matching_subpaths(xfp_paths):
                return rv
        return None

    def xfp_paths(self, skip_unspend_ik=False):
        if not self.desc:
            res = []
            for i, k_str in enumerate(self.keys_info):
                if not i and self.ik_u and skip_unspend_ik:
                    continue
                k = Key.from_string(k_str)
                res.append(k.origin.psbt_derivation())
            return res

        return self.desc.xfp_paths(skip_unspend_ik=skip_unspend_ik)

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
        assert derived_spk == script_pubkey, "spk mismatch\n%s\n%s" % (b2a_hex(derived_spk), b2a_hex(script_pubkey))
        if merkle_root:
            assert derived_desc.tapscript.merkle_root == merkle_root, "psbt merkle root"
        return derived_desc

    def detail(self):
        s = "Wallet Name:\n  %s\n\n" % self.name
        if self.m_n:
            # basic multisig
            s += "Policy: %d of %d\n\n" % self.m_n

        s += chains.addr_fmt_label(self.addr_fmt)
        s += "\n\n" + self.desc_tmplt
        return s

    async def show_detail(self, story="", allow_import=False):
        story += self.detail()
        story += "\n\nPress (1) to see extended public keys"

        if allow_import:
            story += ", OK to approve, X to cancel."

        while True:
            ch = await ux_show_story(story, escape="1")
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

    def to_descriptor(self):
        if self.desc is None:
            # actual descriptor is not loaded, but was asked for
            # fill policy - aka storage format - to actual descriptor
            import glob

            if self.name in glob.DESC_CACHE:
                # loaded descriptor from cache
                print("to_descriptor CACHE")
                self.desc = glob.DESC_CACHE[self.name]
            else:
                print("loading... policy --> descriptor !!!")
                # no need to validate already saved descriptor - was validated upon enroll
                self.desc = self._from_bip388_wallet_policy(self.desc_tmplt, self.keys_info,
                                                            validate=False)
                # cache len always 1
                glob.DESC_CACHE = {}
                glob.DESC_CACHE[self.name] = self.desc

        return self.desc

    @staticmethod
    def _from_bip388_wallet_policy(desc_template, keys_info, validate=True):
        desc_str = bip388_wallet_policy_to_descriptor(
            desc_template.replace("/<0;1>/*", "/**"),
            keys_info
        )
        from descriptor import Descriptor
        desc_obj = Descriptor.from_string(desc_str, validate=validate)
        return desc_obj

    @classmethod
    def from_bip388_wallet_policy(cls, name, desc_template, keys_info):
        bip388_validate_policy(desc_template, keys_info)
        desc_obj = cls._from_bip388_wallet_policy(desc_template, keys_info)
        msc = cls.from_descriptor_obj(name, desc_obj)
        return msc

    @classmethod
    def from_descriptor_obj(cls, name, desc_obj):
        # BIP388 wasn't generated yet - generating from descriptor upon import/enroll
        desc_tmplt, keys_info = desc_obj.bip388_wallet_policy()
        # self-validation
        bip388_validate_policy(desc_tmplt, keys_info)

        ik_u = desc_obj.key and desc_obj.key.is_provably_unspendable
        af = desc_obj.addr_fmt
        m_n = None
        bip67 = None
        if desc_obj.is_basic_multisig:
            m_n = desc_obj.miniscript.m_n()
            bip67 = desc_obj.is_sortedmulti

        return cls(name, desc_tmplt, keys_info, af, ik_u, desc_obj, m_n, bip67)

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

            wal = cls.from_descriptor_obj(name, desc_obj)

        return wal

    def find_duplicates(self):
        for rv in self.iter_wallets():
            assert self.name != rv.name, ("Miniscript wallet with name '%s'"
                                          " already exists. All wallets MUST"
                                          " have unique names.\n\n" % self.name)

            # optimization miniscript vs. multisig & different M/N multisigs
            if self.m_n != rv.m_n:
                # different M/N
                continue

            if self.m_n:
                # enrolling basic multisig wallet
                if self.addr_fmt == rv.addr_fmt and sorted(self.keys_info) == sorted(rv.keys_info):
                    err = "Duplicate wallet."
                    if self.bip67 != rv.bip67:
                        err += " BIP-67 clash."
                    err += "\n\n"
                    assert False, err

            assert self.desc_tmplt != rv.desc_tmplt \
                   and self.keys_info != rv.keys_info, ("This wallet is a duplicate "
                                                        "of already saved wallet "
                                                        "%s.\n\n" % rv.name)

    async def confirm_import(self):
        nope, yes = (KEY_CANCEL, KEY_ENTER) if version.has_qwerty else ("x", "y")
        try:
            self.find_duplicates()
            story, allow_import = "Create new miniscript wallet?\n\n", True
        except AssertionError as e:
            story, allow_import = str(e), False

        to_save = await self.show_detail(story, allow_import=allow_import)

        ch = yes if to_save else nope
        if to_save and allow_import:
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

    async def export_wallet_file(self, core=False, bip388=False, sign=True):
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
                               "desc_template": self.desc_tmplt,
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

                if sign:
                    # TODO need function to get my xpub from just policy
                    # sign with my key at the same path as first address of export
                    derive = self.get_my_deriv(settings.get('xfp')) + "/0/0"
                    from msgsign import write_sig_file
                    h = ngu.hash.sha256s(res.encode())
                    sig_nice = write_sig_file([(h, fname)], derive, AF_CLASSIC)

            msg = '%s file written:\n\n%s' % (name, nice)
            if sign:
                msg += '\n\n%s signature file written:\n\n%s' % (name, sig_nice)
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
        await ux_show_story('Failed to import miniscript.\n\n%s\n%s' % (e, problem_file_line(e)))

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
        from bsms import make_ms_wallet_bsms_menu
        from multisig import create_ms_step1

        if not MiniScriptWallet.exists():
            rv = [MenuItem("(none setup yet)")]
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
                    fp.write('  "%s_key_exp": "%s",\n' % (name, "[%s/%s]%s" % (xfp, dd.replace("m/", ""), xpub)))

                    # descriptor_template = multisig_descriptor_template(xpub, dd, xfp, fmt)
                    # if descriptor_template is None:
                    #     continue
                    # fp.write('  "%s_desc": "%s",\n' % (name, descriptor_template))

            fp.write('  "account": "%d",\n' % acct_num)
            fp.write('  "xfp": "%s"\n}\n' % xfp)
            return fp.getvalue(), sign_der, AF_CLASSIC

    from export import export_contents
    await export_contents(label, lambda: render(acct), fname_pattern,
                          force_bbqr=True, is_json=True)

# EOF
