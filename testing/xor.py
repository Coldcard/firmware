# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import os, hashlib
from mnemonic import Mnemonic


def numwords_to_len(num_words):
    return (num_words * 8) // 6


def xor(*args):
    # bit-wise xor between all args
    vlen = len(args[0])
    # all have to be same length
    assert all(len(e) == vlen for e in args)
    rv = bytearray(vlen)
    for i in range(vlen):
        for a in args:
            rv[i] ^= a[i]
    return rv


def xor_split(secret, num_parts, deterministic=False):
    vlen = len(secret)
    parts = []
    for i in range(num_parts - 1):
        if deterministic:
            msg = b'Batshitoshi ' + secret + b'%d of %d parts' % (i, num_parts)
            part = hashlib.sha256(msg).digest()[:vlen]
        else:
            part = hashlib.sha256(os.urandom(vlen)).digest()[:vlen]

        parts.append(part)

    parts.append(xor(secret, *parts))
    assert xor(*parts) == secret  # selftest
    return parts


def prepare_test_pairs(num_parts, num_words=24, deterministic=False, mnemonic=None):
    if mnemonic is None:
        seed = os.urandom(numwords_to_len(num_words))
        mnemonic = Mnemonic('english').to_mnemonic(seed)
    else:
        seed = Mnemonic.to_seed(mnemonic=mnemonic)

    parts = xor_split(seed, num_parts=num_parts, deterministic=deterministic)
    return [Mnemonic('english').to_mnemonic(s) for s in parts], mnemonic
