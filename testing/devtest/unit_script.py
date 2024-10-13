# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
from uio import BytesIO
from serializations import ser_push_data, ser_string_vector, deser_string_vector
from serializations import ser_compact_size, deser_compact_size

test_data = [
    # data,  result
    (55*b"a", b'7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    (75*b"a", b'Kaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    (76*b"a", b'LLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    (77*b"a", b'LMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    (254*b"a", b'L\xfe' + (254 * b"a")),
    (255*b"a", b'L\xff' + (255 * b"a")),
    (256*b"a", b'M\x00\x01' + (256 * b"a")),
    (500*b"a", b'M\xf4\x01' + (500 * b"a")),
    (65535*b"a", b'M\xff\xff' + (65535 * b"a")),
]

c = 0
for i, (data, result) in enumerate(test_data):
    assert ser_push_data(data) == result, i

try:
    # PUSHDATA 4 not implemented
    ser_push_data(65536 * b"a")
    raise RuntimeError
except AssertionError: pass

# test serialization/deserialization
# all M/N combinations
V = range(1, 16)
for i, v1 in enumerate(V):
    for j in range(i+1, len(V)):
        M, N = v1, V[j]
        print(M, N)
        # number of pubkeys times 1 pushdata + 33 pubkey = 34 * N
        # +1 M
        # +1 N
        # +1 OP_CHECKMULTISIG
        ms_script_len = (34 * N) + 1 + 1 + 1
        vec = [b"\x00"] + (M * [71*b"s"]) + [ms_script_len*b"w"]
        assert vec == deser_string_vector(BytesIO(ser_string_vector(vec)))
        

for i in [253, 0x10000, 0x100000000, 0x10000000000000000]:
    for j in [-1, 0, 1]:
        num = i + j
        if i == 0x10000000000000000 and (j != -1):
            try:
                ser_compact_size(num)
                raise RuntimeError
            except AssertionError:
                continue
        else:
            x = ser_compact_size(num)

        assert num == deser_compact_size(BytesIO(x))

# EOF