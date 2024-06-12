# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/arguments.py
#
import ngu, chains
from io import BytesIO
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AF_CLASSIC, AF_P2TR
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from utils import keypath_to_str, str_to_keypath, swab32, xfp2str
from serializations import ser_compact_size


WILDCARD = "*"
PROVABLY_UNSPENDABLE = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

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
        descriptor_template = "tr(" + PROVABLY_UNSPENDABLE + ",sortedmulti_a(M,%s,...))"
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
        return "%s/%s" % (b2a_hex(self.fingerprint).decode(),
                          keypath_to_str(self.derivation, prefix='', skip=0).replace("'", "h"))


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
        if not isinstance(self.node, bytes):
            assert self.origin, "Key origin info is required"

    def __eq__(self, other):
        return self.origin.psbt_derivation() == other.origin.psbt_derivation() \
                and self.derivation.indexes == other.derivation.indexes

    def __hash__(self):
        orig = tuple(self.origin.psbt_derivation())
        der = self.derivation.indexes.copy()
        if self.derivation.multi_path_index is not None:
            der[self.derivation.multi_path_index] = tuple(der[self.derivation.multi_path_index])
        der = tuple(der)
        return hash(orig+der)

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
        return cls(node, origin, der, chain_type=chain_type)

    @classmethod
    def parse_key(cls, key_str):
        chain_type = None
        if key_str[1:4].lower() == b"pub":
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
        else:
            # only unspendable keys can be bare pubkeys - for now
            # TODO
            # if b"unspend(" in key_str:
            #     node = ngu.hdnode.HDNode()
            #     chain_code = key_str.replace(b"unspend(", b"").replace(b")", b"")
            #     node.chaincode = a2b_hex(chain_code)
            #     node.pubkey = a2b_hex("02" + PROVABLY_UNSPENDABLE)
            H = a2b_hex(PROVABLY_UNSPENDABLE)
            if b"r=" in key_str:
                _, r = key_str.split(b"=")
                if r == b"@":
                    # pick a fresh integer r in the range 0...n-1 uniformly at random and use H + rG
                    kp = ngu.secp256k1.keypair()
                else:
                    # H + rG where r is provided from user
                    r = a2b_hex(r)
                    assert len(r) == 32, "r != 32"
                    kp = ngu.secp256k1.keypair(r)

                H_xo = ngu.secp256k1.xonly_pubkey(H)

                node = H_xo.tweak_add(kp.xonly_pubkey().to_bytes()).to_bytes()

            elif a2b_hex(key_str) == H:
                node = H
            else:
                node = a2b_hex(key_str)

            assert len(node) == 32, "invalid pk %d %s" % (len(node), node)

        return node, chain_type

    def derive(self, idx=None, change=False):
        if isinstance(self.node, bytes):
            return self
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
            origin = KeyOriginInfo(self.node.my_fp(), [idx])
        # empty derivation
        derivation = None
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
        if isinstance(self.node, bytes):
            return True
        return False

    @property
    def prefix(self):
        if self.origin:
            return "[%s]" % self.origin
        return ""

    def key_bytes(self):
        kb = self.node
        if not isinstance(kb, bytes):
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
        if isinstance(self.node, ngu.hdnode.HDNode):
            key += self.extended_public_key()
            if self.derivation and subderiv:
                key += "/" + self.derivation.to_string(external, internal)
        else:
            key += b2a_hex(self.node).decode()

        return key

    @classmethod
    def from_string(cls, s):
        s = BytesIO(s.encode())
        return cls.parse(s)


def fill_policy(policy, keys, external=True, internal=True):
    keys_len = len(keys)
    for i in range(keys_len - 1, -1, -1):
        k = keys[i]
        ph = "@%d" % i
        ph_len = len(ph)
        while True:
            subderiv = True
            ix = policy.find(ph)
            if ix == -1:
                break
            if policy[ix+ph_len] == "/":
                # subderivation is part of the policy
                subderiv = False
                x = ix + ph_len
                substr = policy[x:x+26]  # 26 is longest possible subderivation allowed "/<2147483647;2147483646>/*"
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

            if not isinstance(k, str):
                k_str = k.to_string(external, internal, subderiv=subderiv)
            else:
                k_str = k
                if not subderiv:
                    k_str = "/".join(k_str.split("/")[:-2])
                mp_start = k_str.find("<")
                if mp_start != -1:
                    mp_end = k_str.find(">")
                    mp = k_str[mp_start:mp_end+1]
                    ext, int = mp[1:-1].split(";")
                    if external and not internal:
                        k_str = k_str.replace(mp, ext)
                    if internal and not external:
                        k_str = k_str.replace(mp, int)

            x = policy[ix:ix + ph_len]
            assert x == ph
            policy = policy[:ix] + k_str + policy[ix + ph_len:]
    return policy


def taproot_tree_helper(scripts):
    from miniscript import Miniscript

    if isinstance(scripts, Miniscript):
        script = scripts.compile()
        assert isinstance(script, bytes)
        h = ngu.secp256k1.tagged_sha256(b"TapLeaf", chains.tapscript_serialize(script))
        return [(chains.TAPROOT_LEAF_TAPSCRIPT, script, bytes())], h
    if len(scripts) == 1:
        return taproot_tree_helper(scripts[0])

    split_pos = len(scripts) // 2
    left, left_h = taproot_tree_helper(scripts[0:split_pos])
    right, right_h = taproot_tree_helper(scripts[split_pos:])
    left = [(version, script, control + right_h) for version, script, control in left]
    right = [(version, script, control + left_h) for version, script, control in right]
    if right_h < left_h:
        right_h, left_h = left_h, right_h
    h = ngu.secp256k1.tagged_sha256(b"TapBranch", left_h + right_h)
    return left + right, h