# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/arguments.py
#
import ngu, chains, ustruct, stash
from io import BytesIO
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AF_CLASSIC, AF_P2TR
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from utils import keypath_to_str, str_to_keypath, swab32, xfp2str
from serializations import ser_compact_size


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
    res = b""
    while True:
        chunk = s.read(1)
        if len(chunk) == 0:
            return res, None
        if chunk in chars:
            return res, chunk
        res += chunk


class KeyOriginInfo:
    def __init__(self, fingerprint: bytes, derivation: list, cc_fp=None):
        self.fingerprint = fingerprint
        self.derivation = derivation
        self._cc_fp = cc_fp

    def __eq__(self, other):
        return self.psbt_derivation() == other.psbt_derivation()

    def __hash__(self):
        return hash(tuple(self.psbt_derivation()))

    @property
    def cc_fp(self):
        if self._cc_fp is None:
            self._cc_fp = ustruct.unpack('<I', self.fingerprint)[0]
        return self._cc_fp

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
            rv += "/%s" % keypath_to_str(self.derivation, prefix='', skip=0)
        return rv


class KeyDerivationInfo:

    def __init__(self, indexes=None):
        self.indexes = indexes
        if self.indexes is None:
            self.indexes = ((0, 1), WILDCARD)
            self.multi_path_index = 0
        else:
            self.multi_path_index = None

    def __hash__(self):
        return hash(self.indexes)

    @staticmethod
    def not_hardened(x):
        assert (b"'" not in x) and (b"h" not in x), "Cannot use hardened sub derivation path"

    @classmethod
    def parse(cls, s):
        err = "Malformed key derivation"
        multi_i = None
        idxs = []
        while True:
            got, char = read_until(s, b"<,)/")
            if char == b"<":
                assert multi_i is None, "too many multipaths"
                ext_num, char = read_until(s, b";")
                assert char, err
                cls.not_hardened(ext_num)
                int_num, char = read_until(s, b">")
                assert char, err
                cls.not_hardened(int_num)

                assert int_num != ext_num  # cannot be the same
                multi_i = len(idxs)
                idxs.append((int(ext_num.decode()), int(int_num.decode())))

            else:
                # char in "/),"
                if got == b"*":
                    # every derivation has to end with wildcard (only ranged keys allowed)
                    idxs.append(WILDCARD)
                    break
                elif got:
                    cls.not_hardened(got)
                    idxs.append(int(got.decode()))

            # comma and parenthesis not allowed in subderivation, marker of the end
            if char in b",)": break

        assert idxs[-1] == WILDCARD, "All keys must be ranged"
        if idxs == [0, WILDCARD]:
            # normalize and instead save as <0;1> as change derivation was not provided
            obj = cls()
        else:

            if multi_i is not None:
                assert len(idxs[multi_i]) == 2, "wrong multipath"

            obj = cls(tuple(idxs))
            obj.multi_path_index = multi_i

        return obj

    def to_string(self, external=True, internal=True):
        res = []
        for i in self.indexes:
            if isinstance(i, tuple):
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


class Key:
    def __init__(self, node, origin, derivation=None, taproot=False, chain_type=None):
        self.origin = origin
        self.node = node
        self.derivation = derivation or KeyDerivationInfo()
        self.taproot = taproot
        self.chain_type = chain_type

    def __eq__(self, other):
        return self.origin == other.origin \
                and self.derivation.indexes == other.derivation.indexes

    def __hash__(self):
        # return hash(self.to_string())
        return hash(self.origin) + hash(self.derivation)

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
        der = None
        if char == b"/":
            der = KeyDerivationInfo.parse(s)
        if char is not None:
            s.seek(-1, 1)

        # parse key
        node, chain_type = cls.parse_key(k)
        if origin is None:
            cc_fp = swab32(node.my_fp())
            origin = KeyOriginInfo(ustruct.pack('<I', cc_fp), [], cc_fp)
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

        try:
            assert node.privkey() is None
        except: pass

        return node, chain_type

    def validate(self, my_xfp):
        assert self.chain_type == chains.current_key_chain().ctype, "wrong chain"
        depth = self.node.depth()

        xfp = self.origin.cc_fp

        if depth == 1:
            target = swab32(self.node.parent_fp())
            assert xfp == target, 'xfp depth=1 wrong'

        if xfp == my_xfp:
            # it's supposed to be my key, so I should be able to generate pubkey
            # - might indicate collision on xfp value between co-signers,
            #   and that's not supported
            deriv = self.origin.str_derivation()
            with stash.SensitiveValues() as sv:
                chk_node = sv.derive_path(deriv)
                assert self.node.pubkey() == chk_node.pubkey(), \
                            "[%s/%s] wrong pubkey" % (xfp2str(xfp), deriv[2:])
            return 1
        return 0


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
            origin = KeyOriginInfo(self.origin.fingerprint, self.origin.derivation + [idx],
                                   self.origin.cc_fp)
        else:
            origin = KeyOriginInfo(self.origin.fingerprint, [idx], self.origin.cc_fp)

        return type(self)(new_node, origin, KeyDerivationInfo(self.derivation.indexes[1:]),
                          taproot=self.taproot)

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


def bip388_wallet_policy_to_descriptor(desc_tmplt, keys_info):
    for i in range(len(keys_info) - 1, -1, -1):
        k_str = keys_info[i]
        ph = "@%d" % i
        desc_tmplt = desc_tmplt.replace(ph, k_str)
    return desc_tmplt
