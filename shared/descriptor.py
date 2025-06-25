# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/descriptor.py
#
import ngu, chains
from io import BytesIO
from collections import OrderedDict
from binascii import hexlify as b2a_hex
from utils import xfp2str
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from public_constants import AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH, MAX_SIGNERS, MAX_TR_SIGNERS
from desc_utils import parse_desc_str, append_checksum, descriptor_checksum, Key
from miniscript import Miniscript
from precomp_tag_hash import TAP_BRANCH_H


class Tapscript:
    def __init__(self, tree):
        self.tree = tree   # miniscript or (tapscript, tapscript)
        self._keys = None  # de-duped cached keys
        self._merkle_root = None

    def iter_leaves(self):
        if isinstance(self.tree, Miniscript):
            yield self.tree
        else:
            for ts in self.tree:
                yield from ts.iter_leaves()

    @property
    def keys(self):
        if self._keys:
            return self._keys

        keys = set()
        for lv in self.iter_leaves():
            for k in lv.keys:
                keys.add(k)

        self._keys = list(keys)  # cache for later
        return self._keys

    @property
    def merkle_root(self):
        if not self._merkle_root:
            _, mr = self.process_tree()
            self._merkle_root = mr
        return self._merkle_root

    def derive(self, idx, change=False):
        derived_keys = OrderedDict()
        for k in self.keys:
            dk = k.derive(idx, change=change)
            dk.taproot=True
            derived_keys[k] = dk

        return type(self)(self._derive(self.tree, idx, derived_keys, change))

    @staticmethod
    def _derive(tree, idx, key_map, change=False):
        if isinstance(tree, Miniscript):
            tree = tree.derive(idx, key_map, change=change)
        else:
            l, r = tree
            tree = [Tapscript(l._derive(l.tree, idx, key_map, change=change)),
                    Tapscript(r._derive(r.tree, idx, key_map, change=change))]

        return tree

    def process_tree(self):
        if isinstance(self.tree, Miniscript):
            script = self.tree.compile()
            h = chains.tapleaf_hash(script)
            return [(chains.TAPROOT_LEAF_TAPSCRIPT, script, bytes())], h

        l, r = self.tree
        left, left_h = l.process_tree()
        right, right_h = r.process_tree()
        left = [(version, script, control + right_h) for version, script, control in left]
        right = [(version, script, control + left_h) for version, script, control in right]
        if right_h < left_h:
            right_h, left_h = left_h, right_h

        h = ngu.hash.sha256t(TAP_BRANCH_H, left_h + right_h, True)
        return left + right, h

    @classmethod
    def read_from(cls, s):
        c = s.read(1)
        assert len(c)
        if c == b"{":  # more than one miniscript
            left = cls.read_from(s)
            c = s.read(1)
            if c == b"}":
                return left
            if c != b",":
                raise ValueError("Invalid tapscript: expected ','")

            right = cls.read_from(s)
            if s.read(1) != b"}":
                raise ValueError("Invalid tapscript: expected '}'")

            return cls((left, right))

        s.seek(-1, 1)
        ms = Miniscript.read_from(s, taproot=True)
        return cls(ms)

    def script_tree(self):
        if isinstance(self.tree, Miniscript):
            return b2a_hex(chains.tapscript_serialize(self.tree.compile())).decode()

        l, r = self.tree
        return "{" + l.script_tree() + "," +r.script_tree() + "}"

    def to_string(self, external=True, internal=True):
        if isinstance(self.tree, Miniscript):
            return self.tree.to_string(external, internal)

        l, r = self.tree
        return ("{" + l.to_string(external,internal) + ","
                + r.to_string(external, internal) + "}")


class Descriptor:
    def __init__(self, key=None, miniscript=None, tapscript=None, addr_fmt=None):
        if addr_fmt in [AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH]:
            assert miniscript
            assert not key
        else:
            # single-sig + taproot/tapscript
            assert miniscript is None
            assert key

        self.key = key
        self.miniscript = miniscript
        self.tapscript = tapscript
        self.addr_fmt = addr_fmt

    def validate(self):
        # should only be run once while importing wallet
        from glob import settings

        c = 0
        has_mine = 0
        err_top_B = "Top level miniscript should be 'B'"
        max_signers = 20

        if self.tapscript:
            assert self.key  # internal key (would fail during parse)
            max_signers = MAX_TR_SIGNERS
            for l in self.tapscript.iter_leaves():
                assert l.type == "B", err_top_B
                l.verify()
                l.is_sane(taproot=True)
                # cannot have same keys in single miniscript
                # provably unspendable taproot internal key is not covered here
                assert len(l.keys) == len(set(l.keys)), "Insane"

        elif self.miniscript:
            assert self.key is None
            assert self.miniscript.type == "B", err_top_B
            self.miniscript.verify()
            self.miniscript.is_sane(taproot=False)
            # cannot have same keys in single miniscript
            assert len(self.miniscript.keys) == len(set(self.miniscript.keys)), "Insane"

        my_xfp = settings.get('xfp')
        for k in self.keys:
            has_mine += k.validate(my_xfp)
            c += 1

        assert c <= max_signers, "max signers"

        assert has_mine != 0, 'My key %s missing in descriptor.' % xfp2str(my_xfp).upper()

    def bip388_wallet_policy(self):
        keys_info = OrderedDict()
        for k in self.keys:
            if k.origin not in keys_info:
                keys_info[k.origin] = k.to_string(subderiv=False)

        desc_tmplt = self.to_string(checksum=False)

        keys_info = list(keys_info.values())
        for i, k_str in enumerate(keys_info):
            desc_tmplt = desc_tmplt.replace(k_str, chr(64) + str(i))

        return desc_tmplt, keys_info

    @property
    def script_len(self):
        if self.is_taproot:
            return 34 # OP_1 <32:xonly>
        if self.miniscript:
            return len(self.miniscript)
        if self.addr_fmt == AF_P2WPKH:
            return 22 # 00 <20:pkh>
        return 25 # OP_DUP OP_HASH160 <20:pkh> OP_EQUALVERIFY OP_CHECKSIG

    def xfp_paths(self, skip_unspend_ik=False):
        res = []

        for k in self.keys:
            if self.is_taproot and k.is_provably_unspendable and skip_unspend_ik:
                continue

            res.append(k.origin.psbt_derivation())

        return res

    @property
    def is_segwit_v0(self):
        return self.addr_fmt in [AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2WSH, AF_P2WSH_P2SH]

    @property
    def is_segwit(self):
        return self.is_taproot or self.is_segwit_v0

    @property
    def is_taproot(self):
        return self.addr_fmt == AF_P2TR

    @property
    def is_legacy_sh(self):
        return self.addr_fmt in [AF_P2SH, AF_P2WSH_P2SH, AF_P2WPKH_P2SH]

    @property
    def is_basic_multisig(self):
        return self.miniscript and self.miniscript.NAME in ["multi", "sortedmulti"]

    @property
    def is_sortedmulti(self):
        return self.is_basic_multisig and self.miniscript.NAME == "sortedmulti"

    @property
    def keys(self):
        if self.tapscript:
            # internal is always first
            # otherwise order of keys is not preserved after set operations
            return [self.key] + self.tapscript.keys

        elif self.miniscript:
            return self.miniscript.keys

        # single-sig
        return [self.key]

    def derive(self, idx=None, change=False):
        if self.is_taproot:
            return type(self)(
                self.key.derive(idx, change=change),
                tapscript=self.tapscript.derive(idx, change=change),
                addr_fmt=self.addr_fmt,
            )
        if self.miniscript:
            return type(self)(
                None,
                self.miniscript.derive(idx, change=change),
                addr_fmt=self.addr_fmt,
            )

        # single-sig
        return type(self)(self.key.derive(idx, change=change))

    def script_pubkey(self, compiled_scr=None):
        if self.is_taproot:
            tweak = None
            if self.tapscript:
                tweak = self.tapscript.merkle_root
            output_pubkey = chains.taptweak(self.key.serialize(), tweak)
            return b"\x51\x20" + output_pubkey

        if self.is_legacy_sh:
            if self.miniscript:
                # caller may have already built a script
                scr = compiled_scr or self.miniscript.compile()
                redeem_scr = scr
                if self.addr_fmt == AF_P2WSH_P2SH:
                    redeem_scr = b"\x00\x20" + ngu.hash.sha256s(scr)
            else:
                redeem_scr = b"\x00\x14" + ngu.hash.hash160(self.key.node.pubkey())

            return b"\xa9\x14" + ngu.hash.hash160(redeem_scr) + b"\x87"

        if self.addr_fmt == AF_P2WSH:
            # witness script p2wsh only
            return b"\x00\x20" + ngu.hash.sha256s(compiled_scr or self.miniscript.compile())

        if self.addr_fmt == AF_P2WPKH:
            return b"\x00\x14" + ngu.hash.hash160(self.key.serialize())

        # p2pkh
        assert self.addr_fmt == AF_CLASSIC
        return b"\x76\xa9\x14" + ngu.hash.hash160(self.key.serialize()) + b"\x88\xac"

    @classmethod
    def is_descriptor(cls, desc_str):
        # Quick method to guess whether this is a descriptor
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
            raise ValueError("Wrong checksum %s, expected %s" % (checksum, calc_checksum))
        return desc, checksum

    @classmethod
    def from_string(cls, desc, checksum=False, validate=True):
        desc = parse_desc_str(desc)
        desc, cs = cls.checksum_check(desc)
        s = BytesIO(desc.encode())
        res = cls.read_from(s, validate)
        left = s.read()
        if len(left) > 0:
            raise ValueError("Unexpected characters after descriptor: %r" % left)
        if checksum:
            if cs is None:
                _, cs = res.to_string().split("#")
            return res, cs
        return res

    @classmethod
    def read_from(cls, s, validate=True):
        start = s.read(8)
        af = AF_CLASSIC
        internal_key = None
        tapscript = None
        if start.startswith(b"tr("):
            af = AF_P2TR
            s.seek(-5, 1)
            internal_key = Key.parse(s)
            internal_key.taproot = True
            sep = s.read(1)
            if sep == b")":
                s.seek(-1, 1)
            else:
                assert sep == b","
                tapscript = Tapscript.read_from(s)

        elif start.startswith(b"sh(wsh("):
            af = AF_P2WSH_P2SH
            s.seek(-1, 1)
        elif start.startswith(b"wsh("):
            af = AF_P2WSH
            s.seek(-4, 1)
        elif start.startswith(b"sh(wpkh("):
            af = AF_P2WPKH_P2SH
        elif start.startswith(b"wpkh("):
            af = AF_P2WPKH
            s.seek(-3, 1)
        elif start.startswith(b"pkh("):
            s.seek(-4, 1)
        elif start.startswith(b"sh("):
            af = AF_P2SH
            s.seek(-5, 1)
        else:
            raise ValueError("Invalid descriptor")

        miniscript = None
        if af == AF_P2TR:
            key = internal_key
            nbrackets = 1
        elif af in [AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH]:
            miniscript = Miniscript.read_from(s)
            key = internal_key
            nbrackets = 1 + int(af == AF_P2WSH_P2SH)
        else:
            key = Key.parse(s)
            nbrackets = 1 + int(af == AF_P2WPKH_P2SH)

        end = s.read(nbrackets)
        if end != b")" * nbrackets:
            raise ValueError("Invalid descriptor")

        desc = cls(key, miniscript, tapscript, af)
        if validate:
            desc.validate()
        return desc

    def to_string(self, external=True, internal=True, checksum=True, unspent_compat=False):
        if self.is_taproot:
            desc = "tr(%s" % self.key.to_string(external, internal)
            if self.tapscript:
                desc += ","
                tree = self.tapscript.to_string(external, internal)
                desc += tree

            desc = desc + ")"
            if checksum:
                desc =  append_checksum(desc)
            return desc

        if self.miniscript is not None:
            res = self.miniscript.to_string(external, internal)
            if self.addr_fmt in [AF_P2WSH, AF_P2WSH_P2SH]:
                res = "wsh(%s)" % res
        else:
            if self.addr_fmt == AF_P2WPKH:
                res = "wpkh(%s)" % self.key.to_string(external, internal)
            else:
                res = "pkh(%s)" % self.key.to_string(external, internal)

        if self.is_legacy_sh:
            res = "sh(%s)" % res

        if checksum:
            res = append_checksum(res)
        return res

    def bitcoin_core_serialize(self):
        # this will become legacy one day
        # instead use <0;1> descriptor format
        res = []
        for external in (True, False):
            desc_obj = {
                "desc": self.to_string(external, not external),
                "active": True,
                "timestamp": "now",
                "internal": not external,
                "range": [0, 100],
            }
            res.append(desc_obj)

        return res
