# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/arguments.py
#
import ngu, chains, ustruct, stash
from io import BytesIO
from public_constants import MAX_PATH_DEPTH
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
        assert len(derivation) <= MAX_PATH_DEPTH, "origin too deep"
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

    def get_ext_int(self):
        return self.indexes[self.multi_path_index]

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
                assert b";" not in int_num, "Solved cardinality > 2"
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

            assert multi_i is not None, "need multipath"
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
        return hash(self) == hash(other)

    def __hash__(self):
        # return hash(self.to_string())
        return hash(self.node.pubkey()) + hash(self.derivation)

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
        assert key_str[1:4].lower() == b"pub", "only extended pubkeys allowed"
        # extended key
        # or xpub or tpub as we use descriptors (SLIP-132 NOT allowed)
        hint = key_str[0:1].lower()
        if hint == b"x":
            chain_type = "BTC"
        elif hint == b"t":
            chain_type = "XTN"
        else:
            # slip (ignore any implied address format)
            chain_type = "BTC" if hint in b"yz" else "XTN"

        node = ngu.hdnode.HDNode()
        node.deserialize(key_str)
        try:
            assert node.privkey() is None, "no privkeys"
        except ValueError:
            # ValueError is thrown from libngu if key is public
            pass

        return node, chain_type

    def validate(self, my_xfp, disable_checks=False):
        assert self.chain_type == chains.current_key_chain().ctype, "wrong chain"

        # xfp is always available, even if key was serialized without origin info
        # upon parse root origin info is generated from key itself
        xfp = self.origin.cc_fp
        is_mine = (xfp == my_xfp)

        # raises ValueError on invalid pubkey (should be in libngu)
        # invalid public key not allowed even with disable checks
        ngu.secp256k1.pubkey(self.node.pubkey())

        if not disable_checks:
            depth = self.node.depth()
            # we now allow blinded keys that have depth X but derivation len is 0,
            # where only fingerprint constitutes key origin
            # only check if derivation length is greater than 0
            if self.origin.derivation:
                assert len(self.origin.derivation) == depth, \
                    "deriv len != xpub depth (xfp=%s)" % xfp2str(xfp)
            if depth == 0:
                # blinded keys allowed
                # assert not self.node.parent_fp()
                # assert self.node.child_number()[0] == 0
                assert swab32(self.node.my_fp()) == xfp, "master xfp mismatch"
            elif depth == 1:
                target = swab32(self.node.parent_fp())
                assert xfp == target, 'xfp depth=1 wrong'

            if is_mine:
                # it's supposed to be my key, so I should be able to generate pubkey
                # - might indicate collision on xfp value between co-signers,
                #   and that's not supported
                deriv = self.origin.str_derivation()
                with stash.SensitiveValues() as sv:
                    chk_node = sv.derive_path(deriv)
                    assert self.node.pubkey() == chk_node.pubkey(), \
                                "[%s/%s] wrong pubkey" % (xfp2str(xfp), deriv[2:])

        return is_mine

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
        xfp_str = xfp if isinstance(xfp, str) else xfp2str(xfp)
        koi = KeyOriginInfo.from_string("%s/%s" % (xfp_str, deriv.replace("m/", "")))
        node, chain_type = cls.parse_key(xpub.encode())

        return cls(node, koi, KeyDerivationInfo(), chain_type=chain_type)

    @classmethod
    def from_cc_json(cls, vals, af_str):
        key_exp = af_str + "_key_exp"
        if key_exp in vals:
            # new firmware, prefer key expression
            return cls.from_string(vals[key_exp])

        # TODO
        node, _, _, _ = chains.slip132_deserialize(vals[af_str])
        ek = chains.current_chain().serialize_public(node)
        return cls.from_cc_data(vals["xfp"], vals["%s_deriv" % af_str], ek)

    @classmethod
    def from_psbt_xpub(cls, ek_bytes, xfp_path):
        xfp, *path = xfp_path
        koi = KeyOriginInfo(a2b_hex(xfp2str(xfp)), path)
        # TODO this should be done by C code, no need to base58 encode/decode
        # byte-serialized key should be decodable
        ek = ngu.codecs.b58_encode(ek_bytes)
        node, chain_type = cls.parse_key(ek.encode())

        return cls(node, koi, KeyDerivationInfo(), chain_type=chain_type)

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
            # xonly
            kb = kb[1:]
        return kb

    def extended_public_key(self):
        return chains.current_chain().serialize_public(self.node)

    def to_string(self, external=True, internal=True):
        key = self.prefix
        key += self.extended_public_key()
        if self.derivation and (external or internal):
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
    return desc_tmplt.replace("/**", "/<0;1>/*")


def bip388_validate_policy(desc_tmplt, keys_info):
    from uio import BytesIO

    s = BytesIO(desc_tmplt)
    r = []
    while True:
        got, char = read_until(s, b"@")
        if not char:
            # no more - done
            break

        # key derivation info required for policy
        got, char = read_until(s, b"/")
        assert char, "key derivation missing"
        num = int(got.decode())
        if num not in r:
            r.append(num)

        assert s.read(1) in b"<*", "need multipath"


    assert len(r) == len(keys_info), "Invalid policy"
    assert r == list(range(len(r))), "Out of order"
