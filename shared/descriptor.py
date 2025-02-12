# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# descriptor.py - Bitcoin Core's descriptors and their specialized checksums.
#
# Based on: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
#
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH

MULTI_FMT_TO_SCRIPT = {
    AF_P2SH: "sh(%s)",
    AF_P2WSH_P2SH: "sh(wsh(%s))",
    AF_P2WSH: "wsh(%s)",
    None: "wsh(%s)",
    # hack for tests
    "p2sh": "sh(%s)",
    "p2sh-p2wsh": "sh(wsh(%s))",
    "p2wsh-p2sh": "sh(wsh(%s))",
    "p2wsh": "wsh(%s)",
}

SINGLE_FMT_TO_SCRIPT = {
    AF_P2WPKH: "wpkh(%s)",
    AF_CLASSIC: "pkh(%s)",
    AF_P2WPKH_P2SH: "sh(wpkh(%s))",
    None: "wpkh(%s)",
    "p2pkh": "pkh(%s)",
    "p2wpkh": "wpkh(%s)",
    "p2sh-p2wpkh": "sh(wpkh(%s))",
    "p2wpkh-p2sh": "sh(wpkh(%s))",
}

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

try:
    from utils import xfp2str, str2xfp
except ModuleNotFoundError:
    import struct
    from binascii import unhexlify as a2b_hex
    from binascii import hexlify as b2a_hex
    # assuming not micro python
    def xfp2str(xfp):
        # Standardized way to show an xpub's fingerprint... it's a 4-byte string
        # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
        return b2a_hex(struct.pack('<I', xfp)).decode().upper()

    def str2xfp(txt):
        # Inverse of xfp2str
        return struct.unpack('<I', a2b_hex(txt))[0]


class WrongCheckSumError(Exception):
    pass


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
    else:
        return None
    descriptor_template = descriptor_template % key_exp
    return descriptor_template


class Descriptor:
    __slots__ = (
        "keys",
        "addr_fmt",
    )

    def __init__(self, keys, addr_fmt):
        self.keys = keys
        self.addr_fmt = addr_fmt

    @staticmethod
    def checksum_check(desc_w_checksum , csum_required=False):
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

    @staticmethod
    def parse_key_orig_info(key):
        # key origin info is required for our MultisigWallet
        close_index = key.find("]")
        if key[0] != "[" or close_index == -1:
            raise ValueError("Key origin info is required for %s" % (key))
        key_orig_info = key[1:close_index]  # remove brackets
        key = key[close_index + 1:]
        return key_orig_info, key

    @staticmethod
    def parse_key_derivation_info(key):
        invalid_subderiv_msg = "Invalid subderivation path - only 0/* or <0;1>/* allowed"
        slash_split = key.split("/")
        assert len(slash_split) > 1, invalid_subderiv_msg
        if all(["h" not in elem and "'" not in elem for elem in slash_split[1:]]):
            assert slash_split[-1] == "*", invalid_subderiv_msg
            assert slash_split[-2] in ["0", "<0;1>", "<1;0>"], invalid_subderiv_msg
            assert len(slash_split[1:]) == 2, invalid_subderiv_msg
            return slash_split[0]
        else:
            raise ValueError("Cannot use hardened sub derivation path")

    def checksum(self):
        return descriptor_checksum(self._serialize())

    def serialize_keys(self, internal=False, int_ext=False):
        result = []
        for xfp, deriv, xpub in self.keys:
            if deriv[0] == "m":
                # get rid of 'm'
                deriv = deriv[1:]
            elif deriv[0] != "/":
                # input "84'/0'/0'" would lack slash separtor with xfp
                deriv = "/" + deriv
            if not isinstance(xfp, str):
                xfp = xfp2str(xfp)
            koi = xfp + deriv
            # normalize xpub to use h for hardened instead of '
            key_str = "[%s]%s" % (koi.lower(), xpub)
            if int_ext:
                key_str = key_str + "/" + "<0;1>" + "/" + "*"
            else:
                key_str = key_str + "/" + "/".join(["1", "*"] if internal else ["0", "*"])
            result.append(key_str.replace("'", "h"))
        return result

    def _serialize(self, internal=False, int_ext=False):
        """Serialize without checksum"""
        assert len(self.keys) == 1      # "Multiple keys for single signature script"
        desc_base = SINGLE_FMT_TO_SCRIPT[self.addr_fmt]
        inner = self.serialize_keys(internal=internal, int_ext=int_ext)[0]
        return desc_base % (inner)

    def serialize(self, internal=False, int_ext=False):
        """Serialize with checksum"""
        return append_checksum(self._serialize(internal=internal, int_ext=int_ext))

    @classmethod
    def parse(cls, desc_w_checksum):
        # remove garbage
        desc_w_checksum = parse_desc_str(desc_w_checksum)
        # check correct checksum
        desc, checksum = cls.checksum_check(desc_w_checksum)
        # legacy
        if desc.startswith("pkh("):
            addr_fmt = AF_CLASSIC
            tmp_desc = desc.replace("pkh(", "")
            tmp_desc = tmp_desc.rstrip(")")

        # native segwit
        elif desc.startswith("wpkh("):
            addr_fmt = AF_P2WPKH
            tmp_desc = desc.replace("wpkh(", "")
            tmp_desc = tmp_desc.rstrip(")")

        # wrapped segwit
        elif desc.startswith("sh(wpkh("):
            addr_fmt = AF_P2WPKH_P2SH
            tmp_desc = desc.replace("sh(wpkh(", "")
            tmp_desc = tmp_desc.rstrip("))")

        else:
            raise ValueError("Unsupported descriptor. Supported: pkh(), wpkh(), sh(wpkh()).")

        koi, key = cls.parse_key_orig_info(tmp_desc)
        if key[0:4] not in ["tpub", "xpub"]:
            raise ValueError("Only extended public keys are supported")

        xpub = cls.parse_key_derivation_info(key)
        xfp = str2xfp(koi[:8])
        origin_deriv = "m" + koi[8:]

        return cls(keys=[(xfp, origin_deriv, xpub)], addr_fmt=addr_fmt)

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

    def bitcoin_core_serialize(self, external_label=None):
        # this will become legacy one day
        # instead use <0;1> descriptor format
        res = []
        for internal in [False, True]:
            desc_obj = {
                "desc": self.serialize(internal=internal),
                "active": True,
                "timestamp": "now",
                "internal": internal,
                "range": [0, 100],
            }
            if internal is False and external_label:
                desc_obj["label"] = external_label
            res.append(desc_obj)

        return res


class MultisigDescriptor(Descriptor):
    # only supprt with key derivation info
    # only xpubs
    # can be extended when needed
    __slots__ = (
        "M",
        "N",
        "keys",
        "addr_fmt",
        "is_sorted"  # whether to use sortedmulti() or multi()
    )

    def __init__(self, M, N, keys, addr_fmt, is_sorted=True):
        self.M = M
        self.N = N
        self.is_sorted = is_sorted
        super().__init__(keys, addr_fmt)

    @classmethod
    def parse(cls, desc_w_checksum):
        # remove garbage
        desc_w_checksum = parse_desc_str(desc_w_checksum)
        # check correct checksum
        desc, checksum = cls.checksum_check(desc_w_checksum)
        is_sorted = "sortedmulti(" in desc
        rplc = "sortedmulti(" if is_sorted else "multi("

        # wrapped segwit
        if desc.startswith("sh(wsh("+rplc):
            addr_fmt = AF_P2WSH_P2SH
            tmp_desc = desc.replace("sh(wsh("+rplc, "")
            tmp_desc = tmp_desc.rstrip(")))")

        # native segwit
        elif desc.startswith("wsh("+rplc):
            addr_fmt = AF_P2WSH
            tmp_desc = desc.replace("wsh("+rplc, "")
            tmp_desc = tmp_desc.rstrip("))")

        # legacy
        elif desc.startswith("sh("+rplc):
            addr_fmt = AF_P2SH
            tmp_desc = desc.replace("sh("+rplc, "")
            tmp_desc = tmp_desc.rstrip("))")

        else:
            raise ValueError("Unsupported descriptor. Supported: sh(), sh(wsh()), wsh().")

        splitted = tmp_desc.split(",")
        M, keys = int(splitted[0]), splitted[1:]
        N = int(len(keys))
        if M > N:
            raise ValueError("M must be <= N: got M=%d and N=%d" % (M, N))

        res_keys = []
        for key in keys:
            koi, key = cls.parse_key_orig_info(key)
            if key[0:4] not in ["tpub", "xpub"]:
                raise ValueError("Only extended public keys are supported")

            xpub = cls.parse_key_derivation_info(key)
            xfp = str2xfp(koi[:8])
            origin_deriv = "m" + koi[8:]
            res_keys.append((xfp, origin_deriv, xpub))

        return cls(M=M, N=N, keys=res_keys, addr_fmt=addr_fmt, is_sorted=is_sorted)

    def _serialize(self, internal=False, int_ext=False):
        """Serialize without checksum"""
        desc_base = MULTI_FMT_TO_SCRIPT[self.addr_fmt]
        _type = "sortedmulti" if self.is_sorted else "multi"
        _type += "(%s)"
        desc_base = desc_base % _type
        assert len(self.keys) == self.N
        inner = str(self.M) + "," + ",".join(
                        self.serialize_keys(internal=internal, int_ext=int_ext))

        return desc_base % (inner)

    def pretty_serialize(self):
        """Serialize in pretty and human-readable format"""
        _type = "sortedmulti" if self.is_sorted else "multi"
        res = "# Coldcard descriptor export\n"
        if self.is_sorted:
            res += "# order of keys in the descriptor does not matter, will be sorted before creating script (BIP-67)\n"
        else:
            res += ("# !!! DANGER: order of keys in descriptor MUST be preserved. "
                    "Correct order of keys is required to compose valid redeem/witness script.\n")
        if self.addr_fmt == AF_P2SH:
            res += "# bare multisig - p2sh\n"
            res += "sh("+_type+"(\n%s\n))"
        # native segwit
        elif self.addr_fmt == AF_P2WSH:
            res += "# native segwit - p2wsh\n"
            res += "wsh("+_type+"(\n%s\n))"

        # wrapped segwit
        elif self.addr_fmt == AF_P2WSH_P2SH:
            res += "# wrapped segwit - p2sh-p2wsh\n"
            res += "sh(wsh(" + _type + "(\n%s\n)))"
        else:
            raise ValueError("Malformed descriptor")

        assert len(self.keys) == self.N
        inner = "\t" + "# %d of %d (%s)\n" % (
                        self.M, self.N,
                        "requires all participants to sign" if self.M == self.N else "threshold")
        inner += "\t" + str(self.M) + ",\n"
        ser_keys = self.serialize_keys()
        for i, key_str in enumerate(ser_keys, start=1):
            if i == self.N:
                inner += "\t" + key_str
            else:
                inner += "\t" + key_str + ",\n"

        checksum = self.serialize().split("#")[1]

        return (res % inner) + "#" + checksum

# EOF
