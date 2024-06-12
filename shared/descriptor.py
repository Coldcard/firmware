# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/descriptor.py
#
import ngu, chains
from io import BytesIO
from collections import OrderedDict
from binascii import hexlify as b2a_hex
from utils import cleanup_deriv_path, check_xpub, xfp2str
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from public_constants import AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH, MAX_SIGNERS, MAX_TR_SIGNERS
from desc_utils import parse_desc_str, append_checksum, descriptor_checksum, Key
from desc_utils import taproot_tree_helper, fill_policy
from miniscript import Miniscript


class DescriptorException(ValueError):
    pass


class WrongCheckSumError(Exception):
    pass


class Tapscript:
    def __init__(self, tree=None, keys=None, policy=None):
        self.tree = tree
        self.keys = keys
        self.policy = policy
        self._merkle_root = None

    @staticmethod
    def iter_leaves(tree):
        if isinstance(tree, Miniscript):
            yield tree
        else:
            assert isinstance(tree, list)
            for lv in tree:
                yield from Tapscript.iter_leaves(lv)

    @property
    def merkle_root(self):
        if not self._merkle_root:
            self.process_tree()
        return self._merkle_root

    @staticmethod
    def _derive(tree, idx, key_map, change=False):
        if isinstance(tree, Miniscript):
            return tree.derive(idx, key_map, change=change)
        else:
            if len(tree) == 1 and isinstance(tree[0], Miniscript):
                return tree[0].derive(idx, key_map, change=change)
            l, r = tree
            return [Tapscript._derive(l, idx, key_map, change=change),
                    Tapscript._derive(r, idx, key_map, change=change)]

    def derive(self, idx=None, change=False):
        derived_keys = OrderedDict()
        for k in self.keys:
            derived_keys[k] = k.derive(idx, change=change)
        tree = Tapscript._derive(self.tree, idx, derived_keys, change=change)
        return type(self)(tree, policy=self.policy, keys=list(derived_keys.values()))

    def process_tree(self):
        info, mr = taproot_tree_helper(self.tree)
        self._merkle_root = mr
        return info, mr

    @classmethod
    def read_from(cls, s):
        num_leafs = 0
        depth = 0
        tapscript = []
        p0 = s.read(1)
        if p0 != b"{":
            # depth zero
            s.seek(-1, 1)
            alone = Miniscript.read_from(s, taproot=True)
            alone.is_sane(taproot=True)
            alone.verify()
            tapscript.append(alone)
            num_leafs += 1
        else:
            assert p0 == b"{"
            depth += 1
            itmp = None
            itmp_p = None
            while True:
                p1 = s.read(1)
                if p1 == b'':
                    break
                elif p1 == b")":
                    s.seek(-1, 1)
                    break
                elif p1 == b",":
                    continue
                elif p1 == b"{":
                    if itmp is None:
                        itmp = []
                    else:
                        if itmp_p:
                            itmp[itmp_p].append([])
                        else:
                            itmp.append(([]))
                        itmp_p = -1

                    depth += 1
                    continue
                elif p1 == b"}":
                    depth -= 1
                    if depth == 1:
                        tapscript.append(itmp)
                        itmp = None

                    if depth <= 2:
                        itmp_p = None
                    continue

                s.seek(-1, 1)
                item = Miniscript.read_from(s, taproot=True)
                item.is_sane(taproot=True)
                item.verify()
                num_leafs += 1
                if itmp is None:
                    tapscript.append(item)
                else:
                    if itmp_p and depth == 4:
                        itmp[itmp_p][itmp_p].append(item)
                    elif itmp_p:
                        itmp[itmp_p].append(item)
                    else:
                        itmp.append(item)

        assert num_leafs <= 8, "num_leafs > 8"
        ts = cls(tapscript)
        ts.parse_policy()
        return ts

    def parse_policy(self):
        self.policy, self.keys = self._parse_policy(self.tree, [])
        orig_keys = OrderedDict()
        for k in self.keys:
            if k.origin not in orig_keys:
                orig_keys[k.origin] = []
            orig_keys[k.origin].append(k)
        for i, k_lst in enumerate(orig_keys.values()):
            subderiv = True if len(k_lst) == 1 else False
            self.policy = self.policy.replace(k_lst[0].to_string(subderiv=subderiv), chr(64) + str(i))

    @staticmethod
    def _parse_policy(tree, all_keys):
        if isinstance(tree, Miniscript):
            keys, leaf_str = tree.keys, tree.to_string()
            for k in keys:
                if k not in all_keys:
                    all_keys.append(k)

            return leaf_str, all_keys
        else:
            assert isinstance(tree, list)
            if len(tree) == 1 and isinstance(tree[0], Miniscript):
                keys, leaf_str = tree[0].keys, tree[0].to_string()
                for k in keys:
                    if k not in all_keys:
                        all_keys.append(k)

                return leaf_str, all_keys
            else:
                l, r = tree
                ll, all_keys = Tapscript._parse_policy(l, all_keys)
                rr, all_keys = Tapscript._parse_policy(r, all_keys)
                return "{" + ll + "," + rr + "}", all_keys

    @staticmethod
    def script_tree(tree):
        if isinstance(tree, Miniscript):
            return b2a_hex(chains.tapscript_serialize(tree.compile())).decode()
        else:
            assert isinstance(tree, list)
            if len(tree) == 1 and isinstance(tree[0], Miniscript):
                return b2a_hex(chains.tapscript_serialize(tree[0].compile())).decode()
            else:
                l, r = tree
                ll = Tapscript.script_tree(l)
                rr = Tapscript.script_tree(r)
                return "{" + ll + "," + rr + "}"

    def to_string(self, external=True, internal=True):
        return fill_policy(self.policy, self.keys, external, internal)


class Descriptor:
    def __init__(self, miniscript=None, sh=False, wsh=True, key=None, wpkh=True,
                 taproot=False, tapscript=None):
        if key is None and miniscript is None:
            raise DescriptorException("Provide either miniscript or a key")

        self.sh = sh
        self.wsh = wsh
        self.key = key
        self.miniscript = miniscript
        self.wpkh = wpkh
        self.taproot = taproot
        self.tapscript = tapscript

        if taproot:
            if self.key:
                self.key.taproot = True
            for k in self.keys:
                k.taproot = taproot

    def legacy_ms_compat(self):
        if not (self.is_sortedmulti and self.addr_fmt in (AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH)):
            raise ValueError("Unsupported descriptor. Supported: sh(, sh(wsh(, wsh(. "
                             "MUST be sortedmulti.")

    def validate(self):
        from glob import settings
        if self.miniscript:
            if self.is_basic_multisig:
                assert len(self.keys) <= MAX_SIGNERS
            else:
                assert len(self.keys) <= 20
            self.miniscript.verify()
            if self.miniscript.type != "B":
                raise DescriptorException("Top level miniscript should be 'B'")

        has_mine = 0
        my_xfp = settings.get('xfp')
        to_check = self.keys.copy()
        if self.tapscript:
            assert len(self.keys) <= MAX_TR_SIGNERS
            assert self.key  # internal key (would fail during parse)
            if not isinstance(self.key.node, bytes):
                to_check += [self.key]
        else:
            assert self.key is None and self.miniscript, "not miniscript"

        c = chains.current_key_chain().ctype
        for k in to_check:
            assert k.chain_type == c, "wrong chain"
            xfp = k.origin.cc_fp
            deriv = k.origin.str_derivation()
            xpub = k.extended_public_key()
            deriv = cleanup_deriv_path(deriv)
            is_mine, _ = check_xpub(xfp, xpub, deriv, c, my_xfp, False)
            if is_mine:
                has_mine += 1

        assert has_mine != 0, 'My key %s missing in descriptor.' % xfp2str(my_xfp).upper()

    def storage_policy(self):
        if self.tapscript:
            return self.tapscript.policy

        s = self.miniscript.to_string()
        orig_keys = OrderedDict()
        for k in self.keys:
            if k.origin not in orig_keys:
                orig_keys[k.origin] = []
            orig_keys[k.origin].append(k)
        for i, k_lst in enumerate(orig_keys.values()):
            subderiv = True if len(k_lst) == 1 else False
            s = s.replace(k_lst[0].to_string(subderiv=subderiv), chr(64) + str(i))
        return s

    def ux_policy(self):
        if self.tapscript:
            return "Taproot tree keys:\n\n" + self.tapscript.policy

        return self.storage_policy()

    @property
    def script_len(self):
        if self.taproot:
            return 34 # OP_1 <32:xonly>
        if self.miniscript:
            return len(self.miniscript)
        if self.wpkh:
            return 22 # 00 <20:pkh>
        return 25 # OP_DUP OP_HASH160 <20:pkh> OP_EQUALVERIFY OP_CHECKSIG

    def xfp_paths(self):
        keys = self.keys
        if self.taproot and self.key.origin:
            # ignore provably unspendable
            keys += [self.key]

        return [
            key.origin.psbt_derivation()
            for key in keys
            if key.origin
        ]

    @property
    def is_wrapped(self):
        return self.sh and self.is_segwit

    @property
    def is_legacy(self):
        return not (self.is_segwit or self.is_taproot)

    @property
    def is_segwit(self):
        return (self.wsh and self.miniscript) or (self.wpkh and self.key) or self.taproot

    @property
    def is_pkh(self):
        return self.key is not None and not self.taproot

    @property
    def is_taproot(self):
        return self.taproot

    @property
    def is_basic_multisig(self):
        return self.miniscript and self.miniscript.NAME in ["multi", "sortedmulti"]

    @property
    def is_sortedmulti(self):
        return self.is_basic_multisig and self.miniscript.NAME == "sortedmulti"

    @property
    def keys(self):
        if self.tapscript:
            return self.tapscript.keys
        elif self.key:
            return [self.key]
        return self.miniscript.keys

    @property
    def addr_fmt(self):
        if self.sh and not self.wsh:
            af = AF_P2SH
        elif self.wsh and not self.sh:
            af = AF_P2WSH
        elif self.sh and self.wsh:
            af = AF_P2WSH_P2SH
        elif self.taproot:
            af = AF_P2TR
        elif self.sh and self.wpkh:
            af = AF_P2WPKH_P2SH
        elif self.wpkh and not self.sh:
            af = AF_P2WPKH
        else:
            af = AF_CLASSIC
        return af

    def set_from_addr_fmt(self, addr_fmt):
        self.taproot = False
        self.wsh = False
        self.wpkh = False
        self.sh = False
        if addr_fmt == AF_P2TR:
            self.taproot = True
            assert self.key
        elif addr_fmt == AF_P2WPKH:
            self.wpkh = True
            self.miniscript = None
            assert self.key
        elif addr_fmt == AF_P2WPKH_P2SH:
            self.wpkh = True
            self.sh = True
            self.miniscript = None
            assert self.key
        elif addr_fmt == AF_P2SH:
            self.sh = True
            assert self.miniscript
            assert not self.key
        elif addr_fmt == AF_P2WSH:
            self.wsh = True
            assert self.miniscript
            assert not self.key
        elif addr_fmt == AF_P2WSH_P2SH:
            self.wsh = True
            self.sh = True
            assert self.miniscript
            assert not self.key
        else:
            # AF_CLASSIC
            assert self.key
            assert not self.miniscript

    def scriptpubkey_type(self):
        if self.is_taproot:
            return "p2tr"
        if self.sh:
            return "p2sh"
        if self.is_pkh:
            if self.is_legacy:
                return "p2pkh"
            if self.is_segwit:
                return "p2wpkh"
        else:
            return "p2wsh"

    def derive(self, idx=None, change=False):
        if self.taproot:
            return type(self)(
                None,
                self.sh,
                self.wsh,
                self.key.derive(idx, change=change),
                self.wpkh,
                self.taproot,
                tapscript=self.tapscript.derive(idx, change=change),
            )
        if self.miniscript:
            return type(self)(
                self.miniscript.derive(idx, change=change),
                self.sh,
                self.wsh,
                None,
                self.wpkh,
                self.taproot,
                tapscript=None,
            )
        else:
            return type(self)(
                None, self.sh, self.wsh,
                self.key.derive(idx, change=change),
                self.wpkh, self.taproot, tapscript=None
            )

    def witness_script(self):
        if self.wsh and self.miniscript is not None:
            return self.miniscript.compile()

    def redeem_script(self):
        if not self.sh:
            return None
        if self.miniscript:
            if self.wsh:
                return b"\x00\x20" + ngu.hash.sha256s(self.miniscript.compile())
            else:
                return self.miniscript.compile()

        else:
            return b"\x00\x14" + ngu.hash.hash160(self.key.node.pubkey())

    def script_pubkey(self):
        if self.taproot:
            tweak = None
            if self.tapscript:
                tweak = self.tapscript.merkle_root
            output_pubkey = chains.taptweak(self.key.serialize(), tweak)
            return b"\x51\x20" + output_pubkey
        if self.sh:
            return b"\xa9\x14" + ngu.hash.hash160(self.redeem_script()) + b"\x87"
        if self.wsh:
            return b"\x00\x20" + ngu.hash.sha256s(self.witness_script())
        if self.miniscript:
            return self.miniscript.compile()
        if self.wpkh:
            return b"\x00\x14" + ngu.hash.hash160(self.key.serialize())
        return b"\x76\xa9\x14" + ngu.hash.hash160(self.key.serialize()) + b"\x88\xac"

    @classmethod
    def is_descriptor(cls, desc_str):
        """Quick method to guess whether this is a descriptor"""
        try:
            temp = parse_desc_str(desc_str)
        except:
            return False

        for prefix in ("pk(", "pkh(", "wpkh(", "tr(", "addr(", "raw(", "rawtr(", "combo(",
                       "sh(", "wsh(", "multi(", "sortedmulti(", "multi_a(", "sortedmulti_a("):
            if temp.startswith(prefix):
                return True
            if prefix in temp:
                # weaker case - needed for JSON wrapped imports
                # if descriptor is invalid or unsuitable for our purpose
                # we fail later (in parsing)
                return True
        return False

    @staticmethod
    def checksum_check(desc_w_checksum, csum_required=False):
        try:
            desc, checksum = desc_w_checksum.split("#")
        except ValueError:
            if csum_required:
                raise ValueError("Missing descriptor checksum")
            return desc_w_checksum, None
        calc_checksum = descriptor_checksum(desc)
        if calc_checksum != checksum:
            raise WrongCheckSumError("Wrong checksum %s, expected %s" % (checksum, calc_checksum))
        return desc, checksum

    @classmethod
    def from_string(cls, desc, checksum=False):
        desc = parse_desc_str(desc)
        desc, cs = cls.checksum_check(desc)
        s = BytesIO(desc.encode())
        res = cls.read_from(s)
        left = s.read()
        if len(left) > 0:
            raise ValueError("Unexpected characters after descriptor: %r" % left)
        if checksum:
            if cs is None:
                _, cs = res.to_string().split("#")
            return res, cs
        return res

    @classmethod
    def read_from(cls, s, taproot=False):
        start = s.read(7)
        sh = False
        wsh = False
        wpkh = False
        is_miniscript = True
        internal_key = None
        tapscript = None
        if start.startswith(b"tr("):
            is_miniscript = False  # miniscript vs. tapscript (that can contain miniscripts in tree)
            taproot = True
            s.seek(-4, 1)
            internal_key = Key.parse(s)  # internal key is a must
            internal_key.taproot = True
            sep = s.read(1)
            if sep == b")":
                s.seek(-1, 1)
            else:
                assert sep == b","
                tapscript = Tapscript.read_from(s)
        elif start.startswith(b"sh(wsh("):
            sh = True
            wsh = True
        elif start.startswith(b"wsh("):
            sh = False
            wsh = True
            s.seek(-3, 1)
        elif start.startswith(b"sh(wpkh"):
            is_miniscript = False
            sh = True
            wpkh = True
            assert s.read(1) == b"("
        elif start.startswith(b"wpkh("):
            is_miniscript = False
            wpkh = True
            s.seek(-2, 1)
        elif start.startswith(b"pkh("):
            is_miniscript = False
            s.seek(-3, 1)
        elif start.startswith(b"sh("):
            sh = True
            wsh = False
            s.seek(-4, 1)
        else:
            raise ValueError("Invalid descriptor")

        if is_miniscript:
            miniscript = Miniscript.read_from(s)
            miniscript.is_sane(taproot=False)
            key = internal_key
            nbrackets = int(sh) + int(wsh)
        elif taproot:
            miniscript = None
            key = internal_key
            nbrackets = 1
        else:
            miniscript = None
            key = Key.parse(s)
            nbrackets = 1 + int(sh)

        end = s.read(nbrackets)
        if end != b")" * nbrackets:
            raise ValueError("Invalid descriptor")
        o = cls(miniscript, sh=sh, wsh=wsh, key=key, wpkh=wpkh,
                taproot=taproot, tapscript=tapscript)
        o.validate()
        return o

    def to_string(self, external=True, internal=True, checksum=True):
        if self.taproot:
            desc = "tr(%s" % self.key.to_string(external, internal)
            if self.tapscript:
                desc += ","
                tree = self.tapscript.to_string(external, internal)
                desc += tree

            desc = desc + ")"
            return append_checksum(desc)

        if self.miniscript is not None:
            res = self.miniscript.to_string(external, internal)
            if self.wsh:
                res = "wsh(%s)" % res
        else:
            if self.wpkh:
                res = "wpkh(%s)" % self.key.to_string(external, internal)
            else:
                res = "pkh(%s)" % self.key.to_string(external, internal)
        if self.sh:
            res = "sh(%s)" % res

        if checksum:
            res = append_checksum(res)
        return res

    def bitcoin_core_serialize(self):
        # this will become legacy one day
        # instead use <0;1> descriptor format
        res = []
        for external, internal in [(True, False), (False, True)]:
            desc_obj = {
                "desc": self.to_string(external, internal),
                "active": True,
                "timestamp": "now",
                "internal": internal,
                "range": [0, 100],
            }
            res.append(desc_obj)

        return res

    def pretty_serialize(self):
        # TODO not enabled
        """Serialize in pretty and human-readable format"""
        inner_ident = 1
        res = "# Coldcard descriptor export\n"
        res += "# order of keys in the descriptor does not matter, will be sorted before creating script (BIP-67)\n"
        if self.addr_fmt == AF_P2SH:
            res += "# bare multisig - p2sh\n"
            res += "sh(sortedmulti(\n%s\n))"
        # native segwit
        elif self.addr_fmt == AF_P2WSH:
            res += "# native segwit - p2wsh\n"
            res += "wsh(sortedmulti(\n%s\n))"

        # wrapped segwit
        elif self.addr_fmt == AF_P2WSH_P2SH:
            res += "# wrapped segwit - p2sh-p2wsh\n"
            res += "sh(wsh(sortedmulti(\n%s\n)))"

        elif self.addr_fmt == AF_P2TR:
            inner_ident = 2
            res += "# taproot multisig - p2tr\n"
            res += "tr(\n"
            if isinstance(self.internal_key, str):
                res += "\t" + "# internal key (provably unspendable)\n"
                res += "\t" + self.internal_key + ",\n"
                res += "\t" + "sortedmulti_a(\n%s\n))"
            else:
                ik_ser = self.serialize_keys(keys=[self.internal_key])[0]
                res += "\t" + "# internal key\n"
                res += "\t" + ik_ser + ",\n"
                res += "\t" + "sortedmulti_a(\n%s\n))"
        else:
            raise ValueError("Malformed descriptor")

        assert len(self.keys) == self.N
        inner = ("\t" * inner_ident) + "# %d of %d (%s)\n" % (
                        self.M, self.N,
                        "requires all participants to sign" if self.M == self.N else "threshold")
        inner += ("\t" * inner_ident) + str(self.M) + ",\n"
        ser_keys = self.serialize_keys()
        for i, key_str in enumerate(ser_keys, start=1):
            if i == self.N:
                inner += ("\t" * inner_ident) + key_str
            else:
                inner += ("\t" * inner_ident) + key_str + ",\n"

        checksum = self.serialize().split("#")[1]

        return (res % inner) + "#" + checksum