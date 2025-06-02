# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/arguments.py
#
import ngu, chains, ustruct
from io import BytesIO
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AF_CLASSIC, AF_P2TR
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from utils import keypath_to_str, str_to_keypath, swab32, xfp2str
from serializations import ser_compact_size
from precomp_tag_hash import TAP_BRANCH_H


WILDCARD = "*"
PROVABLY_UNSPENDABLE = b'\x02P\x92\x9bt\xc1\xa0IT\xb7\x8bK`5\xe9z^\x07\x8aZ\x0f(\xec\x96\xd5G\xbf\xee\x9a\xce\x80:\xc0'

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if (c0 & 1):
        c ^= 0xf5dee51989
    if (c0 & 2):
        c ^= 0xa9fdca3312
    if (c0 & 4):
        c ^= 0x1bab10e32d
    if (c0 & 8):
        c ^= 0x3706b1677a
    if (c0 & 16):
        c ^= 0x644d626ffd

    return c

def descriptor_checksum(desc):
    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            raise ValueError(ch)

        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod(c, cls)
            cls = 0
            clscount = 0

    if clscount > 0:
        c = polymod(c, cls)
    for j in range(0, 8):
        c = polymod(c, 0)
    c ^= 1

    rv = ''
    for j in range(0, 8):
        rv += CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31]

    return rv

def append_checksum(desc):
    return desc + "#" + descriptor_checksum(desc)


def parse_desc_str(string):
    """Remove comments, empty lines and strip line. Produce single line string"""
    res = ""
    for l in string.split("\n"):
        strip_l = l.strip()
        if not strip_l:
            continue
        if strip_l.startswith("#"):
            continue
        res += strip_l
    return res


def multisig_descriptor_template(xpub, path, xfp, addr_fmt):
    key_exp = "[%s%s]%s/0/*" % (xfp.lower(), path.replace("m", ''), xpub)
    if addr_fmt == AF_P2WSH_P2SH:
        descriptor_template = "sh(wsh(sortedmulti(M,%s,...)))"
    elif addr_fmt == AF_P2WSH:
        descriptor_template = "wsh(sortedmulti(M,%s,...))"
    elif addr_fmt == AF_P2SH:
        descriptor_template = "sh(sortedmulti(M,%s,...))"
    elif addr_fmt == AF_P2TR:
        # provably unspendable BIP-0341
        descriptor_template = "tr(" + b2a_hex(PROVABLY_UNSPENDABLE[1:]).decode() + ",sortedmulti_a(M,%s,...))"
    else:
        return None
    descriptor_template = descriptor_template % key_exp
    return descriptor_template


def read_until(s, chars=b",)(#"):
    # TODO potential infinite loop
    # what is the longest possible element? (proly some raw( but that is unsupported)
    #
    res = b""
    chunk = b""
    char = None
    while True:
        chunk = s.read(1)
        if len(chunk) == 0:
            return res, None
        if chunk in chars:
            return res, chunk
        res += chunk
    return res, None


class KeyOriginInfo:
    def __init__(self, fingerprint: bytes, derivation: list):
        self.fingerprint = fingerprint
        self.derivation = derivation
        self.cc_fp = swab32(int(b2a_hex(self.fingerprint).decode(), 16))

    def __eq__(self, other):
        return self.psbt_derivation() == other.psbt_derivation()

    def __hash__(self):
        return hash(tuple(self.psbt_derivation()))

    def str_derivation(self):
        return keypath_to_str(self.derivation, prefix='m/', skip=0)

    def psbt_derivation(self):
        res = [self.cc_fp]
        for i in self.derivation:
            res.append(i)
        return res

    @classmethod
    def from_string(cls, s: str):
        arr = s.split("/")
        xfp = a2b_hex(arr[0])
        assert len(xfp) == 4
        arr[0] = "m"
        path = "/".join(arr)
        derivation = str_to_keypath(xfp, path)[1:]  # ignoring xfp here, already stored
        return cls(xfp, derivation)

    def __str__(self):
        rv = "%s" % b2a_hex(self.fingerprint).decode()
        if self.derivation:
            rv += "/%s" % keypath_to_str(self.derivation, prefix='', skip=0).replace("'", "h")
        return rv


class KeyDerivationInfo:

    def __init__(self, indexes=None):
        self.indexes = indexes
        if self.indexes is None:
            self.indexes = [[0, 1], WILDCARD]
            self.multi_path_index = 0
        else:
            self.multi_path_index = None

    @property
    def is_int_ext(self):
        if self.multi_path_index is not None:
            return True
        return False

    @property
    def is_external(self):
        if self.is_int_ext:
            return True
        elif self.indexes[-2] % 2 == 0:
            return True

        return False

    @property
    def branches(self):
        if self.is_int_ext:
            return self.indexes[self.multi_path_index]
        else:
            return [self.indexes[-2]]

    @classmethod
    def from_string(cls, s):
        fail_msg = "Cannot use hardened sub derivation path"
        if not s:
            return cls()
        res = []
        mp = 0
        mpi = None
        for idx, i in enumerate(s.split("/")):
            start_i = i.find("<")
            if start_i != -1:
                end_i = s.find(">")
                assert end_i
                inner = s[start_i+1:end_i]
                assert ";" in inner
                inner_split = inner.split(";")
                assert len(inner_split) == 2, "wrong multipath"
                res.append([int(i) for i in inner_split])
                mp += 1
                mpi = idx
            else:
                if i == WILDCARD:
                    res.append(WILDCARD)
                else:
                    assert "'" not in i, fail_msg
                    assert "h" not in i, fail_msg
                    res.append(int(i))

        # only one <x;y> allowed in subderivation
        assert mp <= 1, "too many multipaths (%d)" % mp

        if res == [0, WILDCARD]:
            obj = cls()
        else:
            assert len(res) == 2, "Key derivation too long"
            assert res[-1] == WILDCARD, "All keys must be ranged"
            obj = cls(res)
            obj.multi_path_index = mpi
        return obj

    def to_string(self, external=True, internal=True):
        res = []
        for i in self.indexes:
            if isinstance(i, list):
                if internal is True and external is False:
                    i = str(i[1])
                elif internal is False and external is True:
                    i = str(i[0])
                else:
                    i = "<%d;%d>" % (i[0], i[1])
            else:
                i = str(i)
            res.append(i)
        return "/".join(res)

    def to_int_list(self, branch_idx, idx):
        assert branch_idx in self.indexes[0]
        return [branch_idx, idx]


class Key:
    def __init__(self, node, origin, derivation=None, taproot=False, chain_type=None):
        self.origin = origin
        self.node = node
        self.derivation = derivation
        self.taproot = taproot
        self.chain_type = chain_type

    def __eq__(self, other):
        return self.origin == other.origin \
                and self.derivation.indexes == other.derivation.indexes

    def __hash__(self):
        return hash(self.to_string())

    def __len__(self):
        return 34 - int(self.taproot) # <33:sec> or <32:xonly>

    @property
    def fingerprint(self):
        return self.origin.fingerprint

    def serialize(self):
        return self.key_bytes()

    def compile(self):
        d = self.serialize()
        return ser_compact_size(len(d)) + d

    @classmethod
    def parse(cls, s):
        first = s.read(1)
        origin = None
        if first == b"u":
            s.seek(-1, 1)
            return Unspend.parse(s)

        if first == b"[":
            prefix, char = read_until(s, b"]")
            if char != b"]":
                raise ValueError("Invalid key - missing ] in key origin info")
            origin = KeyOriginInfo.from_string(prefix.decode())
        else:
            s.seek(-1, 1)
        k, char = read_until(s, b",)/")
        der = b""
        if char == b"/":
            der, char = read_until(s, b"<,)")
            if char == b"<":
                der += b"<"
                branch, char = read_until(s, b">")
                if char is None:
                    raise ValueError("Failed reading the key, missing >")
                der += branch + b">"
                rest, char = read_until(s, b",)")
                der += rest
        if char is not None:
            s.seek(-1, 1)
        # parse key
        node, chain_type = cls.parse_key(k)
        der = KeyDerivationInfo.from_string(der.decode())
        if origin is None:
            origin = KeyOriginInfo(ustruct.pack('<I', swab32(node.my_fp())), [])
        return cls(node, origin, der, chain_type=chain_type)

    @classmethod
    def parse_key(cls, key_str):
        assert key_str[1:4].lower() == b"pub", "only extended keys allowed"
        # extended key
        # or xpub or tpub as we use descriptors (SLIP-132 NOT allowed)
        hint = key_str[0:1].lower()
        if hint == b"x":
            chain_type = "BTC"
        else:
            assert hint == b"t", "no slip"
            chain_type = "XTN"
        node = ngu.hdnode.HDNode()
        node.deserialize(key_str)

        return node, chain_type

    def derive(self, idx=None, change=False):
        if isinstance(idx, list):
            for i in idx:
                mp_i = self.derivation.multi_path_index or 0
                if i in self.derivation.indexes[mp_i]:
                    idx = i
                    break
            else:
                assert False

        elif idx is None:
            # derive according to key subderivation if any
            if self.derivation is None:
                idx = 1 if change else 0
            else:
                if self.derivation.multi_path_index is not None:
                    ext, inter = self.derivation.indexes[self.derivation.multi_path_index]
                    idx = inter if change else ext

        new_node = self.node.copy()
        new_node.derive(idx, False)
        if self.origin:
            origin = KeyOriginInfo(self.origin.fingerprint, self.origin.derivation + [idx])
        else:
            fp = ustruct.pack('<I', swab32(self.node.my_fp()))
            origin = KeyOriginInfo(fp, [idx])

        derivation = KeyDerivationInfo(self.derivation.indexes[1:])
        return type(self)(new_node, origin, derivation, taproot=self.taproot)

    @classmethod
    def read_from(cls, s, taproot=False):
        return cls.parse(s)

    @classmethod
    def from_cc_data(cls, xfp, deriv, xpub):
        koi = KeyOriginInfo.from_string("%s/%s" % (xfp2str(xfp), deriv.replace("m/", "")))
        node = ngu.hdnode.HDNode()
        node.deserialize(xpub)
        return cls(node, koi, KeyDerivationInfo())

    def to_cc_data(self):
        ch = chains.current_chain()
        return (self.origin.cc_fp,
                self.origin.str_derivation(),
                ch.serialize_public(self.node, AF_CLASSIC))

    @property
    def is_provably_unspendable(self):
        if PROVABLY_UNSPENDABLE == self.node.pubkey():
            return True
        return False

    @property
    def prefix(self):
        if self.origin and self.origin.derivation:
            return "[%s]" % self.origin
        # jut a bare [xfp]key - omit origin info (jut xfp)
        # or no origin at all
        return ""

    def key_bytes(self):
        kb = self.node.pubkey()
        if self.taproot:
            if len(kb) == 33:
                kb = kb[1:]
            assert len(kb) == 32
        return kb

    def extended_public_key(self):
        return chains.current_chain().serialize_public(self.node)

    def to_string(self, external=True, internal=True, subderiv=True):
        key = self.prefix
        key += self.extended_public_key()
        if self.derivation and subderiv:
            key += "/" + self.derivation.to_string(external, internal)

        return key

    @classmethod
    def from_string(cls, s):
        s = BytesIO(s.encode())
        return cls.parse(s)


class Unspend(Key):
    def __init__(self, node, origin=None, derivation=None, taproot=True, chain_type=None):
        super().__init__(node, origin, derivation, taproot, chain_type)
        assert self.taproot

    def __eq__(self, other):
        return self.node.chain_code() == other.node.chain_code() \
            and self.node.pubkey() == other.node.pubkey() \
            and self.derivation.indexes == other.derivation.indexes

    @classmethod
    def parse(cls, s):
        assert s.read(8) == b"unspend("
        chain_code, c = read_until(s, b")")
        chain_code = a2b_hex(chain_code)
        assert len(chain_code) == 32, "chain code length"
        assert c
        char = s.read(1)
        if char != b"/":
            raise ValueError("ranged unspend required")
        der, char = read_until(s, b"<,)")
        if char == b"<":
            der += b"<"
            branch, char = read_until(s, b">")
            if char is None:
                raise ValueError("Failed reading the key, missing >")
            der += branch + b">"
            rest, char = read_until(s, b",)")
            der += rest
        if char is not None:
            s.seek(-1, 1)

        node = ngu.hdnode.HDNode().from_chaincode_pubkey(chain_code,
                                                         PROVABLY_UNSPENDABLE)
        der = KeyDerivationInfo.from_string(der.decode())
        return cls(node, None, der, chain_type=None)

    def to_string(self, external=True, internal=True, subderiv=True):
        res = "unspend(%s)" % b2a_hex(self.node.chain_code()).decode()
        if self.derivation and subderiv:
            res += "/" + self.derivation.to_string(external, internal)

        return res

    @property
    def is_provably_unspendable(self):
        return True


def fill_policy(policy, keys, external=True, internal=True):
    orig_keys = []
    for k in keys:
        if not isinstance(k, str):
            k_orig = k.to_string(external, internal, subderiv=False)
        else:
            _idx = k.find("]")  # end of key origin info - no more / expected besides subderivation
            if _idx != -1:
                ek = k[_idx+1:].split("/")[0]
                k_orig = k[:_idx+1] + ek
            else:
                # no origin info
                k_orig = k.split("/")[0]

        if k_orig not in orig_keys:
            orig_keys.append(k_orig)

    for i in range(len(orig_keys) - 1, -1, -1):
        k = orig_keys[i]
        ph = "@%d" % i
        ph_len = len(ph)
        while True:
            ix = policy.find(ph)
            if ix == -1:
                break

            assert policy[ix+ph_len] == "/"
            # subderivation is part of the policy
            x = ix + ph_len
            substr = policy[x:x+26]  # 26 is the longest possible subderivation allowed "/<2147483647;2147483646>/*"
            mp_start = substr.find("<")
            assert mp_start != -1
            mp_end = substr.find(">")
            mp = substr[mp_start:mp_end + 1]
            _ext, _int = mp[1:-1].split(";")
            if external and not internal:
                sub = _ext
            elif internal and not external:
                sub = _int
            else:
                sub = None
            if sub is not None:
                policy = policy[:x + mp_start] + sub + policy[x + mp_end + 1:]

            x = policy[ix:ix + ph_len]
            assert x == ph
            policy = policy[:ix] + k + policy[ix + ph_len:]

    return policy


def taproot_tree_helper(scripts):
    from miniscript import Miniscript

    if isinstance(scripts, Miniscript):
        script = scripts.compile()
        h = chains.tapleaf_hash(script)
        return [(chains.TAPROOT_LEAF_TAPSCRIPT, script, bytes())], h

    left, left_h = taproot_tree_helper(scripts[0].tree)
    right, right_h = taproot_tree_helper(scripts[1].tree)
    left = [(version, script, control + right_h) for version, script, control in left]
    right = [(version, script, control + left_h) for version, script, control in right]
    if right_h < left_h:
        right_h, left_h = left_h, right_h

    h = ngu.hash.sha256t(TAP_BRANCH_H, left_h + right_h, True)
    return left + right, h