# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test_psbt_witness_iter.py - regression test for input_witness_iter() NameError
#
# Covers: psbtObject.input_witness_iter() crashed with NameError when the
# PSBT's global unsigned transaction used witness serialization
# (had_witness=True), because the method referenced bare `fd` and `num_in`
# instead of `self.fd` / `self.num_inputs`. On device this broke finalize()
# after the user had already reviewed, approved and signed.
#
# This test is self-contained: it shims the MicroPython modules and
# extracts the REAL method source from shared/psbt.py via AST, so it always
# exercises the shipped code rather than a copy of it.
#
import ast
import binascii
import builtins
import hashlib
import io
import os
import struct
import sys
import types

# ---- MicroPython shims (CPython equivalents) ----
builtins.const = lambda x: x  # micropython.const -> identity on CPython

ubinascii = types.ModuleType("ubinascii")
ubinascii.hexlify = binascii.hexlify
ubinascii.unhexlify = binascii.unhexlify
sys.modules["ubinascii"] = ubinascii

sys.modules["ustruct"] = struct

uio = types.ModuleType("uio")
uio.BytesIO = io.BytesIO
sys.modules["uio"] = uio

uhashlib = types.ModuleType("uhashlib")
uhashlib.sha256 = hashlib.sha256
sys.modules["uhashlib"] = uhashlib

ngu = types.ModuleType("ngu")
ngu_hash = types.ModuleType("ngu.hash")
ngu_hash.sha256s = lambda d: hashlib.sha256(d).digest()
ngu_hash.sha256d = lambda d: hashlib.sha256(hashlib.sha256(d).digest()).digest()
ngu_hash.ripemd160 = lambda d: hashlib.new("ripemd160", d).digest()
ngu_hash.hash160 = lambda d: hashlib.new("ripemd160", hashlib.sha256(d).digest()).digest()
ngu.hash = ngu_hash
sys.modules["ngu"] = ngu
sys.modules["ngu.hash"] = ngu_hash

SHARED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared")
sys.path.insert(0, SHARED)

from serializations import CTxInWitness  # noqa: E402


def _real_input_witness_iter():
    # Extract the verbatim method from the shipped firmware source.
    src = open(os.path.join(SHARED, "psbt.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "input_witness_iter":
            seg = ast.get_source_segment(src, node)
            assert seg is not None, "could not extract input_witness_iter"
            ns = {"CTxInWitness": CTxInWitness}
            exec(compile(ast.parse(seg), "<psbt.py>", "exec"), ns)
            return ns["input_witness_iter"]
    raise RuntimeError("input_witness_iter not found in shared/psbt.py")


_real_fn = _real_input_witness_iter()


class FakePSBT:
    # Mimics the state parse_txn() builds for a witness-serialized PSBT:
    # had_witness=True, wit_start recorded, num_inputs set, fd staged.
    input_witness_iter = _real_fn

    def __init__(self, had_witness, num_inputs=2):
        self.had_witness = had_witness
        self.num_inputs = num_inputs
        self._expected = []
        if had_witness:
            blobs = b""
            for i in range(num_inputs):
                wit = CTxInWitness()
                wit.scriptWitness.stack = [b"\x30" * (70 + i), b"\x02" + bytes([i]) * 32]
                blobs += wit.serialize()
                self._expected.append(wit.serialize())
            self.wit_start = 64
            self.fd = io.BytesIO(b"\x00" * 64 + blobs)


def test_input_witness_iter_with_witness_data():
    # Regression: this raised NameError: name 'fd' is not defined
    # (and then name 'num_in') before the fix.
    psbt = FakePSBT(had_witness=True)
    out = list(psbt.input_witness_iter())
    assert len(out) == psbt.num_inputs
    for idx, wit in out:
        assert isinstance(wit, CTxInWitness)
    assert out[0][0] == 0 and out[1][0] == 1
    # witness data must round-trip byte-identical through fd
    assert out[0][1].serialize() == psbt._expected[0]
    assert out[1][1].serialize() == psbt._expected[1]


def test_input_witness_iter_without_witness_data():
    # Unchanged placeholder path: one empty witness per input.
    psbt = FakePSBT(had_witness=False)
    out = list(psbt.input_witness_iter())
    assert len(out) == psbt.num_inputs
    assert all(isinstance(w, CTxInWitness) for _, w in out)
    assert all(len(w.scriptWitness.stack) == 0 for _, w in out)


if __name__ == "__main__":
    test_input_witness_iter_with_witness_data()
    test_input_witness_iter_without_witness_data()
    print("test_psbt_witness_iter: all tests passed")
