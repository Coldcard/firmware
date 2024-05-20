#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Bitcoin Object Python Serializations
************************************

Modified from the test/test_framework/mininode.py file from the
Bitcoin repository
"""

import struct
from struct import error as struct_err
from typing import List


# Serialization/deserialization tools
def ser_compact_size(size: int) -> bytes:
    """
    Serialize an integer using Bitcoin's compact size unsigned integer serialization.

    :param size: The int to serialize
    :returns: The int serialized as a compact size unsigned integer
    """
    r = b""
    if size < 253:
        r = struct.pack("B", size)
    elif size < 0x10000:
        r = struct.pack("<BH", 253, size)
    elif size < 0x100000000:
        r = struct.pack("<BI", 254, size)
    else:
        r = struct.pack("<BQ", 255, size)
    return r

def deser_compact_size(f):
    """
    Deserialize a compact size unsigned integer from the beginning of the byte stream.

    :param f: The byte stream
    :returns: The integer that was serialized
    """
    try:
        nit: int = struct.unpack("<B", f.read(1))[0]
    except struct_err:
        return None

    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def deser_string(f) -> bytes:
    """
    Deserialize a variable length byte string serialized with Bitcoin's variable length string serialization from a byte stream.

    :param f: The byte stream
    :returns: The byte string that was serialized
    """
    nit = deser_compact_size(f)
    return f.read(nit)

def ser_string(s: bytes) -> bytes:
    """
    Serialize a byte string with Bitcoin's variable length string serialization.

    :param s: The byte string to be serialized
    :returns: The serialized byte string
    """
    return ser_compact_size(len(s)) + s

def deser_uint256(f) -> int:
    """
    Deserialize a 256 bit integer serialized with Bitcoin's 256 bit integer serialization from a byte stream.

    :param f: The byte stream.
    :returns: The integer that was serialized
    """
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u: int) -> bytes:
    """
    Serialize a 256 bit integer with Bitcoin's 256 bit integer serialization.

    :param u: The integer to serialize
    :returns: The serialized 256 bit integer
    """
    rs = b""
    for _ in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s: bytes) -> int:
    """
    Deserialize a 256 bit integer serialized with Bitcoin's 256 bit integer serialization from a byte string.

    :param s: The byte string
    :returns: The integer that was serialized
    """
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def deser_vector(f, c) -> List:
    """
    Deserialize a vector of objects with Bitcoin's object vector serialization from a byte stream.

    :param f: The byte stream
    :param c: The class of object to deserialize for each object in the vector
    :returns: A list of objects that were serialized
    """
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


def ser_vector(v) -> bytes:
    """
    Serialize a vector of objects with Bitcoin's object vector serialzation.

    :param v: The list of objects to serialize
    :returns: The serialized objects
    """
    r = ser_compact_size(len(v))
    for i in v:
        r += i.serialize()
    return r


def deser_string_vector(f) -> List[bytes]:
    """
    Deserialize a vector of byte strings from a byte stream.

    :param f: The byte stream
    :returns: The list of byte strings that were serialized
    """
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v: List[bytes]) -> bytes:
    """
    Serialize a list of byte strings as a vector of byte strings.

    :param v: The list of byte strings to serialize
    :returns: The serialized list of byte strings
    """
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r

def ser_sig_der(r: bytes, s: bytes) -> bytes:
    """
    Serialize the ``r`` and ``s`` values of an ECDSA signature using DER.

    :param r: The ``r`` value bytes
    :param s: The ``s`` value bytes
    :returns: The DER encoded signature
    """
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
    first = r[0]
    if first & (1 << 7) != 0:
        r = b"\x00" + r
    first = s[0]
    if first & (1 << 7) != 0:
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

    sig += b"\x01"
    return sig

def ser_sig_compact(r: bytes, s: bytes, recid: bytes) -> bytes:
    """
    Serialize the ``r`` and ``s`` values of an ECDSA signature using the compact signature serialization scheme.

    :param r: The ``r`` value bytes
    :param s: The ``s`` value bytes
    :returns: The compact signature
    """
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 + rec)

    sig = b""
    sig += prefix
    sig += r + s

    return sig
