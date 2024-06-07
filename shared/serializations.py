# Additions Copyright 2018-2021 by Coinkite Inc. 
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin Object Python Serializations

Modified from the test/test_framework/mininode.py file from the
Bitcoin repository

CTransaction,CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives for transactions only
ser_*, deser_*: functions that handle serialization/deserialization
"""

from ubinascii import hexlify as b2a_hex
import ustruct as struct
import ngu
from opcodes import *

# single-shot hash functions
sha256 = ngu.hash.sha256s
ripemd160 = ngu.hash.ripemd160
hash256 = ngu.hash.sha256d
hash160 = ngu.hash.hash160

def bytes_to_hex_str(s):
    return str(b2a_hex(s), 'ascii')

SIGHASH_DEFAULT = const(0) # in taproot meaning same as SIGHASH_ALL (over whole TX)
SIGHASH_ALL = const(1)
SIGHASH_NONE = const(2)
SIGHASH_SINGLE = const(3)
SIGHASH_ANYONECANPAY = const(0x80)

# list containing all flags that we support signing for
ALL_SIGHASH_FLAGS = [
    SIGHASH_DEFAULT,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ALL|SIGHASH_ANYONECANPAY,
    SIGHASH_NONE|SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE|SIGHASH_ANYONECANPAY,
]

# Serialization/deserialization tools
def ser_compact_size(l):
    if l < 253:
        return struct.pack("B", l)
    elif l < 0x10000:
        return struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        return struct.pack("<BI", 254, l)
    else:
        return struct.pack("<BQ", 255, l)

def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)

def ser_string(s):
    return ser_compact_size(len(s)) + s

def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s):
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


def deser_vector(f, c):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(l, ser_function_name=None):
    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def deser_int_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = struct.unpack("<i", f.read(4))[0]
        r.append(t)
    return r


def ser_int_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += struct.pack("<i", i)
    return r

def ser_push_data(dd):
    # "compile" data to be pushed on the script stack
    # - will be minimal sized, but only supports size ranges we're likely to see
    ll = len(dd)
    assert 2 <= ll <= 255

    if ll <= 75:
        return bytes([ll]) + dd           # OP_PUSHDATAn + data
    else:
        return bytes([76, ll]) + dd       # 0x4c = 76 => OP_PUSHDATA1 + size + data

def ser_push_int(n):
    # push a small integer onto the stack
    from opcodes import OP_0, OP_1, OP_16, OP_PUSHDATA1

    if n == 0:
        return bytes([OP_0])
    elif 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    elif n <= 255:
        return bytes([1, n])

    raise ValueError(n)

def disassemble(script):
    # Very limited script disassembly
    # yeilds (int / bytes, opcode) for each part of the script
    # see <https://en.bitcoin.it/wiki/Script>

    try:
        offset = 0
        while 1:
            if offset >= len(script):
                #print('dis %d done' % offset)
                return
            c = script[offset]
            offset += 1

            if 1 <= c <= 75:
                #print('dis %d: bytes=%s' % (offset, b2a_hex(script[offset:offset+c])))
                yield (script[offset:offset+c], None)
                offset += c
            elif OP_1 <= c <= OP_16:
                # OP_1 thru OP_16
                #print('dis %d: number=%d' % (offset, (c - OP_1 + 1)))
                yield (c - OP_1 + 1, None)
            elif c == OP_PUSHDATA1:
                cnt = script[offset]; offset += 1
                yield (script[offset:offset+cnt], None)
                offset += cnt
            elif c == OP_PUSHDATA2:
                cnt = struct.unpack_from("H", script, offset)
                offset += 2
                yield (script[offset:offset+cnt], None)
                offset += cnt
            elif c == OP_PUSHDATA4:
                # no where to put so much data
                raise NotImplementedError
            elif c == OP_1NEGATE:
                yield (-1, None)
            else:
                # OP_0 included here
                #print('dis %d: opcode=%d' % (offset, c))
                yield (None, c)
    except:
        raise ValueError("bad script")
        

def ser_sig_der(r, s, sighash_type=1):
    # Take R and S values from a signature and encode into DER format.
    sig = b"\x30"

    # Make r and s as short as possible
    ri = 0
    for b in r:
        if b == 0:
            ri += 1
        else:
            break
    r = r[ri:]
    si = 0
    for b in s:
        if b == 0:
            si += 1
        else:
            break
    s = s[si:]

    # Make positive of neg
    if r[0] & (1 << 7) != 0:
        r = b"\x00" + r
    if s[0] & (1 << 7) != 0:
        s = b"\x00" + s

    # Write total length
    total_len = len(r) + len(s) + 4
    sig += struct.pack("B", total_len)

    # write r
    sig += b"\x02"
    sig += struct.pack("B", len(r))
    sig += r

    # write s
    sig += b"\x02"
    sig += struct.pack("B", len(s))
    sig += s

    sig += struct.pack("B", sighash_type)

    return sig

def ser_sig_compact(r, s, recid):
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 +rec)

    sig = prefix
    sig += r + s

    return sig

# Objects that map to bitcoind objects, which can be serialized/deserialized

MSG_WITNESS_FLAG = 1<<30

class COutPoint(object):
    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = ser_uint256(self.hash)
        r += struct.pack("<I", self.n)
        return r

    #def __repr__(self):
    #    return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn(object):
    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        return r

    #def __repr__(self):
    #    return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
    #        % (repr(self.prevout), bytes_to_hex_str(self.scriptSig),
    #           self.nSequence)


class CTxOut(object):
    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = struct.pack("<q", self.nValue)
        r += ser_string(self.scriptPubKey)
        return r

    def get_address(self):
        # Detect type of output from scriptPubKey, and return 3-tuple:
        #    (addr_type_code, addr, is_segwit)
        # 'addr' is byte string, either 20 or 32 long

        if len(self.scriptPubKey) == 22 and \
                self.scriptPubKey[0] == 0 and self.scriptPubKey[1] == 20:
            # aka. P2WPKH
            return 'p2pkh', self.scriptPubKey[2:2+20], True

        if len(self.scriptPubKey) == 34 and \
                self.scriptPubKey[0] == 81 and self.scriptPubKey[1] == 32:
            # aka. P2TR
            return 'p2tr', self.scriptPubKey[2:2+32], True

        if len(self.scriptPubKey) == 34 and \
                self.scriptPubKey[0] == 0 and self.scriptPubKey[1] == 32:
            # aka. P2WSH
            return 'p2sh', self.scriptPubKey[2:2+32], True

        if self.is_p2pkh():
            return 'p2pkh', self.scriptPubKey[3:3+20], False

        if self.is_p2sh():
            return 'p2sh', self.scriptPubKey[2:2+20], False

        if self.is_p2pk():
            # rare, pay to full pubkey
            return 'p2pk', self.scriptPubKey[2:2+33], False

        # If this is reached, we do not understand the output well
        # enough to allow the user to authorize the spend, so fail hard.
        raise ValueError('scriptPubKey template fail: ' + b2a_hex(self.scriptPubKey).decode())

    def is_p2sh(self):
        return len(self.scriptPubKey) == 23 and self.scriptPubKey[0] == 0xa9 \
                and self.scriptPubKey[1] == 0x14 and self.scriptPubKey[22] == 0x87

    def is_p2pkh(self):
        return len(self.scriptPubKey) == 25 and self.scriptPubKey[0] == 0x76 \
                and self.scriptPubKey[1] == 0xa9 and self.scriptPubKey[2] == 0x14 \
                and self.scriptPubKey[23] == 0x88 and self.scriptPubKey[24] == 0xac

    def is_p2pk(self):
        return (len(self.scriptPubKey) == 35 or len(self.scriptPubKey) == 67) \
                and (self.scriptPubKey[0] == 0x21 or self.scriptPubKey[0] == 0x41) \
                and self.scriptPubKey[-1] == 0xac

    #def __repr__(self):
    #    return "CTxOut(nValue=%d scriptPubKey=%s)" \
    #        % (self.nValue, b2a_hex(self.scriptPubKey))


class CScriptWitness(object):
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    #def __repr__(self):
    #    return "CScriptWitness(%s)" % \
    #           (",".join([bytes_to_hex_str(x) for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness(object):
    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    #def __repr__(self):
    #    return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness(object):
    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    #def __repr__(self):
    #    return "CTxWitness(%s)" % \
    #           (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction(object):
    def __init__(self, tx=None):
        if tx is None:
            self.nVersion = 1
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            import copy         # not supported
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = struct.unpack("<B", f.read(1))[0]
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags != 0:
            self.wit.vtxinwit = [CTxInWitness() for i in range(len(self.vin))]
            self.wit.deserialize(f)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def serialize_without_witness(self):
        r = struct.pack("<i", self.nVersion)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = struct.pack("<i", self.nVersion)
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += struct.pack("<B", flags)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for i in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += struct.pack("<I", self.nLockTime)
        return r

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self):
        return self.serialize_without_witness()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self):
        self.sha256 = None
        self.calc_sha256()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness=False):
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        tmp = hash256(self.serialize())
        self.hash = b2a_hex(bytes(tmp[i] for i in range(len(tmp)-1, -1, -1)))

    def is_valid(self):
        COIN = 100000000
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    #def __repr__(self):
    #    return "CTransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
    #        % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)


# EOF
