# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# BIP-93 Codex32 checksum and Shamir interpolation.
#

CODEX32_CONST = 0x10ce0795c2fd1e62a
CODEX32_LONG_CONST = 0x43381e570bf4798ab26
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

MS_HRP = "ms"
CW_HRP = "cw"                 # COLDCARD extension: English BIP-39 entropy
CX_HRP = "cx"                 # COLDCARD extension: chaincode + private key
SEPARATOR = "1"
SECRET = "s"
SECRET_ID = "seed"           # Fixed ID for standalone master-seed backups
UX_CHARSET = CHARSET + " " + SEPARATOR
IDX_ORDER = "sacdefghjklmnpqrtuvwxyz023456789"

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def codex32_polymod(values):
    generators = [
        0x19dc500ce73fde210, 0x1bfae00def77fe529, 0x1fbd920fffe7bee52,
        0x1739640bdeee3fdad, 0x07729a039cfc75f5a,
    ]
    residue = 1
    for value in values:
        top = residue >> 60
        residue = ((residue & 0x0fffffffffffffff) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                residue ^= generators[i]
    return residue

def codex32_long_polymod(values):
    generators = [
        0x3d59d273535ea62d897, 0x7a9becb6361c6c51507, 0x543f9b7e6c38d8a2a0e,
        0x0c577eaeccf1990d13c, 0x1887f74f8dc71b10651,
    ]
    residue = 1
    for value in values:
        top = residue >> 70
        residue = ((residue & 0x3fffffffffffffffff) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                residue ^= generators[i]
    return residue

# BIP-93 counts the expanded HRP and the complete data part, including checksum.
def codex32_verify_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    if 96 <= len(values) <= 1023:
        return codex32_long_polymod(values) == CODEX32_LONG_CONST
    if len(values) <= 93:
        return codex32_polymod(values) == CODEX32_CONST
    return False

def codex32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    if len(values) + 13 > 93:
        polymod = codex32_long_polymod(values + ([0] * 15)) ^ CODEX32_LONG_CONST
        return [(polymod >> (5 * (14 - i))) & 31 for i in range(15)]

    polymod = codex32_polymod(values + ([0] * 13)) ^ CODEX32_CONST
    return [(polymod >> (5 * (12 - i))) & 31 for i in range(13)]


BECH32_INV = [
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
]

def bech32_mul(a, b):
    result = 0
    for i in range(5):
        if (b >> i) & 1:
            result ^= a
        a *= 2
        if a >= 32:
            a ^= 41
    return result

def bech32_lagrange(indices, target):
    numerator = 1
    coefficients = []
    for i in indices:
        numerator = bech32_mul(numerator, i ^ target)
        denominator = 1
        for j in indices:
            denominator = bech32_mul(denominator, (target if i == j else i) ^ j)
        coefficients.append(denominator)
    return [bech32_mul(numerator, BECH32_INV[i]) for i in coefficients]

def codex32_interpolate(shares, target):
    weights = bech32_lagrange([share[5] for share in shares], target)
    result = []
    for i in range(len(shares[0])):
        value = 0
        for j in range(len(shares)):
            value ^= bech32_mul(weights[j], shares[j][i])
        result.append(value)
    return result

def bech32_to_array(value):
    return [CHARSET.index(ch) for ch in value.lower()]

def array_to_bech32(values):
    return "".join(CHARSET[value] for value in values)

def convertbits(data, frombits, tobits, pad=True, pad_val=0):
    accumulator = 0
    bits = 0
    result = []
    max_value = (1 << tobits) - 1
    max_accumulator = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        assert not (value < 0 or value >> frombits)  #, "invalid value"
        accumulator = ((accumulator << frombits) | value) & max_accumulator
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((accumulator >> bits) & max_value)
            accumulator &= (1 << bits) - 1

    if pad and bits:
        pad_len = tobits - bits
        assert 0 <= pad_val < (1 << pad_len)  #, "invalid padding"
        result.append(((accumulator << pad_len) | pad_val) & max_value)
    else:
        assert bits < frombits  #, "invalid padding"

    return result

def _normalize_case(encoded):
    assert encoded.lower() == encoded or encoded.upper() == encoded, "mixed case"
    return encoded.lower()

class Share:
    def __init__(self, hrp, uid, payload, index, threshold):
        hrp = hrp.lower()
        uid = uid.lower()
        payload = payload.lower()
        index = index.lower()

        assert hrp in (MS_HRP, CX_HRP, CW_HRP), "unsupported HRP"
        assert len(uid) == 4 and all(ch in CHARSET for ch in uid), "invalid identifier"
        assert len(index) == 1 and index in CHARSET, "invalid share index"
        assert payload and all(ch in CHARSET for ch in payload), "invalid payload"
        if threshold == 0:
            assert index == SECRET, "non-secret share with threshold 0"
        else:
            assert 1 < threshold < 10, "threshold %d out of bounds" % threshold
        assert (len(payload) * 5) % 8 <= 4, "incomplete group"

        self.hrp = hrp
        self.uid = uid
        self.payload = payload
        self.index = index
        self.threshold = threshold

    def __eq__(self, other):
        return isinstance(other, Share) and self.hrp == other.hrp and self.data() == other.data()

    def __hash__(self):
        return hash(self.hrp + self.data())

    def __len__(self):
        # Two-character HRP: 93 - 5 expanded HRP - 6 header - 13 checksum.
        return 9 + len(self.payload) + (15 if len(self.payload) > 69 else 13)

    def is_secret_share(self):
        return self.index == SECRET

    @classmethod
    def from_body(cls, encoded):
        # Header + payload only. Keep every payload symbol, including padding.
        encoded = _normalize_case(encoded)
        hrp, data = encoded.split(SEPARATOR)
        checksum = array_to_bech32(codex32_create_checksum(hrp, bech32_to_array(data)))
        return cls.parse(encoded + checksum)

    @classmethod
    def parse(cls, encoded):
        encoded = _normalize_case(encoded)
        assert encoded[:3] in (MS_HRP + SEPARATOR, CX_HRP + SEPARATOR, CW_HRP + SEPARATOR), "unsupported HRP"

        parts = encoded.split(SEPARATOR)
        assert len(parts) == 2, "invalid separator"
        hrp, data_and_checksum = parts

        if hrp == MS_HRP:
            assert len(encoded) in (48, 74, 127), "ms codex32 length"
        elif hrp == CW_HRP:
            assert len(encoded) in (48, 61, 74), "cw codex32 length"
        else:
            assert len(encoded) == 127, "cx codex32 length"

        threshold = data_and_checksum[0]
        assert threshold in "023456789", "invalid threshold"
        data = bech32_to_array(data_and_checksum)
        assert codex32_verify_checksum(hrp, data), "incorrect checksum"

        # All supported HRPs expand to five values.
        checksum_len = 13 if 5 + len(data_and_checksum) <= 93 else 15
        body = data_and_checksum[:-checksum_len]
        return cls(hrp, body[1:5], body[6:], body[5], int(threshold))

    @classmethod
    def from_seed(cls, seed, hrp, uid, idx, thres, pad_val=None):
        if pad_val is None:
            assert idx.lower() == SECRET, "padding required for non-secret share"
            pad_val = 0
        payload = array_to_bech32(convertbits(seed, 8, 5, True, pad_val))
        return cls(hrp, uid, payload, idx, thres)

    def to_seed_and_pad(self):
        values = bech32_to_array(self.payload)
        seed = bytes(convertbits(values, 5, 8, False))
        pad_len = (len(values) * 5) - (len(seed) * 8)
        pad_val = values[-1] & ((1 << pad_len) - 1) if pad_len else 0
        return seed, pad_val

    def data(self):
        return str(self.threshold) + self.uid + self.index + self.payload

    def data_values(self):
        return bech32_to_array(self.data())

    def checksum(self):
        return array_to_bech32(codex32_create_checksum(self.hrp, self.data_values()))

    def to_string(self, upper=True):
        value = self.hrp + SEPARATOR + self.data() + self.checksum()
        return value.upper() if upper else value

def generate_share(shares, share_index):
    assert shares, "no shares"
    share_index = share_index.lower()
    assert len(share_index) == 1 and share_index in CHARSET, "invalid share index"

    first = shares[0]
    indexes = set()
    for share in shares:
        assert share.hrp == first.hrp, "hrp not same"
        assert share.uid == first.uid, "id not same"
        assert share.threshold == first.threshold, "threshold not same"
        assert len(share.payload) == len(first.payload), "length not same"
        indexes.add(share.index)

    assert len(shares) == len(indexes), "indexes not unique"
    assert share_index not in indexes, "index already taken"
    assert len(shares) == first.threshold, "need exactly %d shares" % first.threshold

    data = [share.data_values() for share in shares]
    result = codex32_interpolate(data, CHARSET.index(share_index))
    return Share(first.hrp, first.uid, array_to_bech32(result[6:]),
                 share_index, first.threshold)

# EOF
