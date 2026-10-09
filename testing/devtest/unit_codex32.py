# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
# https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki

import chains, ngu
from ubinascii import unhexlify as a2b_hex
from utils import B2A, deserialize_secret
from codex32 import (CHARSET, SECRET, Share, bech32_to_array, codex32_verify_checksum,
                     generate_share)
from stash import SecretStash


def xprv_from_bip32_seed(seed):
    import chains, ngu
    chain = chains.get_chain('BTC')
    node = ngu.hdnode.HDNode().from_master(seed)
    return chain.serialize_private(node)


# TEST VECTOR 1
v1 = Share.parse('ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw')
assert v1.threshold == 0
assert v1.index == SECRET
assert v1.payload == 'xxxxxxxxxxxxxxxxxxxxxxxxxx'
assert v1.checksum() == '4nzvca9cmczlw'
assert v1.to_string() == 'MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW'
assert v1.to_string(upper=False) == 'ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw'
assert B2A(v1.to_seed_and_pad()[0]) == '318c6318c6318c6318c6318c6318c631'
assert xprv_from_bip32_seed(v1.to_seed_and_pad()[0]) == \
    'xprv9s21ZrQH143K3taPNekMd9oV5K6szJ8ND7vVh6fxicRUMDcChr3bFFzuxY8qP3xFFBL6DWc2uEYCfBFZ2nFWbAqKPhtCLRjgv78EZJDEfpL'
print('Vector 1: OK')

# TEST VECTOR 2
v2_a = Share.parse('MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM')
v2_c = Share.parse('MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN')
v2_d = generate_share([v2_a, v2_c], 'd')
v2_secret = generate_share([v2_a, v2_d], SECRET)
assert B2A(v2_secret.to_seed_and_pad()[0]) == 'd1808e096b35b209ca12132b264662a5'
assert xprv_from_bip32_seed(v2_secret.to_seed_and_pad()[0]) == \
    'xprv9s21ZrQH143K2NkobdHxXeyFDqE44nJYvzLFtsriatJNWMNKznGoGgW5UMTL4fyWtajnMYb5gEc2CgaKhmsKeskoi9eTimpRv2N11THhPTU'
print('Vector 2: OK')

# TEST VECTOR 3
seed = 'ffeeddccbbaa99887766554433221100'
v3_secret = Share.from_seed(a2b_hex(seed), 'ms', 'cash', SECRET, 3, pad_val=0)
assert v3_secret.to_string() == \
    'MS13CASHSLLHDMN9M42VCSAMX24ZRXGS3QQJZQUD4M0D6NLN'
assert B2A(Share.parse(
    'ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln').to_seed_and_pad()[0]) == seed

v3_a = Share.parse('ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t')
v3_c = Share.parse('ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr')
v3_d = generate_share([v3_secret, v3_a, v3_c], 'd')
v3_e = generate_share([v3_secret, v3_a, v3_c], 'e')
v3_f = generate_share([v3_secret, v3_a, v3_c], 'f')

assert v3_d.to_string() == 'MS13CASHD0WSEDSTCDCTS64CD7WVY4M90LM28W4FFUPQS7RM'
assert v3_e.to_string() == 'MS13CASHEEKGPEMXZSHCRMQHAYDLP6YHMS3WS7320XYXSAR9'
assert v3_f.to_string() == 'MS13CASHF8JH6SDRKPYRSP5UT94PJ8KTEHHW2HFVYRJ48704'
assert B2A(generate_share([v3_a, v3_c, v3_d], SECRET).to_seed_and_pad()[0]) == seed
assert B2A(generate_share([v3_d, v3_e, v3_f], SECRET).to_seed_and_pad()[0]) == seed
assert B2A(generate_share([v3_a, v3_c, v3_f], SECRET).to_seed_and_pad()[0]) == seed
assert xprv_from_bip32_seed(v3_secret.to_seed_and_pad()[0]) == \
    'xprv9s21ZrQH143K266qUcrDyYJrSG7KA3A7sE5UHndYRkFzsPQ6xwUhEGK1rNuyyA57Vkc1Ma6a8boVqcKqGNximmAe9L65WsYNcNitKRPnABd'
print('Vector 3: OK')

# TEST VECTOR 4
seed = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'
target = 'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma'
assert Share.from_seed(a2b_hex(seed), 'ms', 'leet', SECRET, 0,
                       pad_val=0).to_string() == target.upper()
assert B2A(Share.parse(target).to_seed_and_pad()[0]) == seed

alt_encodings = [
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam',
]
for encoded in alt_encodings:
    share = Share.parse(encoded)
    assert B2A(share.to_seed_and_pad()[0]) == seed
    assert xprv_from_bip32_seed(share.to_seed_and_pad()[0]) == \
        'xprv9s21ZrQH143K3s41UCWxXTsU4TRrhkpD1t21QJETan3hjo8DP5LFdFcB5eaFtV8x6Y9aZotQyP8KByUjgLTbXCUjfu2iosTbMv98g8EQoqr'
print('Vector 4: OK')

# TEST VECTOR 5
seed = ('dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c011111'
        '04c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9')
target = ('CX100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6'
          'AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06GPUHWUSDF58Y65T8')
v5 = Share.from_seed(a2b_hex(seed), 'cx', '0c8v', SECRET, 0)
assert B2A(Share.parse(target).to_seed_and_pad()[0]) == seed
assert B2A(v5.to_seed_and_pad()[0]) == seed
assert xprv_from_bip32_seed(v5.to_seed_and_pad()[0]) == \
    'xprv9s21ZrQH143K4UYT4rP3TZVKKbmRVmfRqTx9mG2xCy2JYipZbkLV8rwvBXsUbEv9KQiUD7oED1Wyi9evZzUn2rqK9skRgPkNaAzyw3YrpJN'
print('Vector 5: OK')

# The unreleased former prefix is not an import alias.
try:
    Share.parse('cc' + v5.to_string().lower()[2:])
except AssertionError as exc:
    assert str(exc) == 'unsupported HRP'
else:
    assert False, 'accepted obsolete extended-key prefix'

# Only secret S is stored, without metadata or payload padding.
stored_shares = [v1, v2_a, v2_secret, Share.parse(target)]
for encoded in alt_encodings:
    stored_shares.append(Share.parse(encoded))
for original in stored_shares:
    if not original.is_secret_share():
        try:
            SecretStash.encode(codex32=original)
        except AssertionError:
            pass
        else:
            assert False, 'accepted non-secret share'
        continue
    encoded = SecretStash.encode(codex32=original)
    assert len(encoded) == 72
    assert encoded[65:] == bytes(7)
    assert deserialize_secret(SecretStash.storage_serialize(encoded)) == encoded
    assert encoded[0] == (1 if original.hrp == 'cx' else len(original.to_seed_and_pad()[0]))

    mode, raw, node = SecretStash.decode(encoded)
    assert raw == original.to_seed_and_pad()[0]
    assert mode == ('xprv' if original.hrp == 'cx' else 'master')
    node.blank()

padded = Share.parse(alt_encodings[5])
seed_bytes, pad = padded.to_seed_and_pad()
assert pad
assert Share.from_seed(seed_bytes, padded.hrp, padded.uid, padded.index,
                       padded.threshold).to_string() != padded.to_string()
assert Share.from_seed(seed_bytes, padded.hrp, padded.uid, padded.index,
                       padded.threshold, pad).to_string() == padded.to_string()
print('Native storage: OK')

invalid_checksum = [
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8',
    'cx10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x',
]
for encoded in invalid_checksum:
    try:
        Share.parse(encoded)
        raise RuntimeError
    except AssertionError as exc:
        assert 'incorrect checksum' in str(exc)
print('Invalid checksum: OK')

# These examples use the wrong checksum for their given data sizes. The current
# parser rejects non-standard lengths first, so also test the checksum primitive.
invalid_checksum_len = [
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxcsyppjkd8lz4hx3',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx3hmlrmpa4zl0v',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxrfggf88znkaup',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpt7l4aycv9qzj',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxus27z9xtyxyw3',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8',
]
for encoded in invalid_checksum_len:
    try:
        Share.parse(encoded)
        raise RuntimeError
    except AssertionError as exc:
        assert str(exc) in ('ms codex32 length', 'incorrect checksum')
    hrp, data = encoded.split('1')
    assert not codex32_verify_checksum(hrp, bech32_to_array(data))
print('Invalid checksum length: OK')

invalid_payload_length = [
    # Valid long checksums under the expanded-length rule, unsupported payload sizes.
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxu6hwvl5p0l9xf3c',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxv70wkzrjr4ntqet',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf',
]
for encoded in invalid_payload_length:
    try:
        Share.parse(encoded)
        raise RuntimeError
    except AssertionError as exc:
        assert 'ms codex32 length' in str(exc)
    hrp, data = encoded.split('1')
    assert codex32_verify_checksum(hrp, bech32_to_array(data))
print('Invalid Codex32 length: OK')

incomplete_group = [
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v',
    'ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9',
    'ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z',
]
for encoded in incomplete_group:
    try:
        Share.parse(encoded)
        raise RuntimeError
    except AssertionError as exc:
        assert 'ms codex32 length' in str(exc)

    hrp, data = encoded.split('1')
    values = bech32_to_array(data)
    assert codex32_verify_checksum(hrp, values)
    checksum_len = 15 if 5 + len(values) >= 96 else 13
    body = data[:-checksum_len]
    try:
        Share(hrp, body[1:5], body[6:], body[5], int(body[0]))
        raise RuntimeError
    except AssertionError as exc:
        assert 'incomplete group' in str(exc)
print('Incomplete group: OK')

try:
    Share.parse('ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p')
    raise RuntimeError
except AssertionError as exc:
    assert 'non-secret share with threshold 0' in str(exc)
print('Non-secret share with threshold 0: OK')

try:
    Share.parse('ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg')
    raise RuntimeError
except AssertionError as exc:
    assert 'invalid threshold' in str(exc)
print('Threshold is not digit: OK')

malformed_header = [
    '0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2',
    '10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2',
    'ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2',
    'm10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2',
    's10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2',
    '0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws',
    '10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws',
    'm10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l',
    's10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x',
]
for encoded in malformed_header:
    try:
        Share.parse(encoded)
        raise RuntimeError
    except AssertionError as exc:
        assert 'unsupported HRP' in str(exc)
print('Unsupported HRP: OK')

try:
    Share.from_seed(ngu.random.bytes(16), 'ms', 'cash', 'a', 2)
    raise RuntimeError
except AssertionError as exc:
    assert 'padding required for non-secret share' in str(exc)
print('Non-secret share padding: OK')

# Split 128-, 256- and 512-bit master secrets as 3-of-5 sets.
for secret_len in (16, 32, 64):
    seed_bytes = ngu.random.bytes(secret_len)
    secret = Share.from_seed(seed_bytes, 'ms', 'cash', SECRET, 3)
    pad_len = (-secret_len * 8) % 5
    share_a = Share.from_seed(ngu.random.bytes(secret_len), 'ms', 'cash', 'a', 3,
                              ngu.random.bytes(1)[0] & ((1 << pad_len) - 1))
    share_c = Share.from_seed(ngu.random.bytes(secret_len), 'ms', 'cash', 'c', 3,
                              ngu.random.bytes(1)[0] & ((1 << pad_len) - 1))
    share_d = generate_share([secret, share_a, share_c], 'd')
    share_e = generate_share([secret, share_a, share_c], 'e')
    share_f = generate_share([secret, share_a, share_c], 'f')

    for share in (secret, share_a, share_c, share_d, share_e, share_f):
        assert share.to_string()[:3] == 'MS1'

    try:
        generate_share([share_a, share_c], 'c')
        raise RuntimeError
    except AssertionError as exc:
        assert 'index already taken' in str(exc)

    try:
        generate_share([share_a, share_c, share_c], 'j')
        raise RuntimeError
    except AssertionError as exc:
        assert 'indexes not unique' in str(exc)

    mismatched = Share.from_seed(seed_bytes, 'ms', 'cass', 'w', 3, 0)
    try:
        generate_share([share_a, share_c, mismatched], 'j')
        raise RuntimeError
    except AssertionError as exc:
        assert 'id not same' in str(exc)

    mismatched = Share.from_seed(seed_bytes, 'ms', 'cash', 'w', 4, 0)
    try:
        generate_share([share_a, share_c, mismatched], 'j')
        raise RuntimeError
    except AssertionError as exc:
        assert 'threshold not same' in str(exc)

    try:
        generate_share([share_a, share_c], SECRET)
        raise RuntimeError
    except AssertionError as exc:
        assert 'need exactly 3 shares' in str(exc)

    recovered = generate_share([share_a, share_c, share_d], SECRET)
    assert recovered.to_seed_and_pad()[0] == seed_bytes
    assert recovered.to_string()[:3] == 'MS1'

    recovered = generate_share([share_d, share_e, share_f], SECRET)
    assert recovered.to_seed_and_pad()[0] == seed_bytes
    assert recovered.to_string()[:3] == 'MS1'

# Round-trip serialization/deserialization for MS and CC.
for secret_len in (16, 32, 64):
    seed_bytes = ngu.random.bytes(secret_len)
    original = Share.from_seed(seed_bytes, 'ms', 'k00l', 'c', 3, 0)
    restored = Share.from_seed(original.to_seed_and_pad()[0], 'ms', 'k00l', 'c', 3, 0)
    assert seed_bytes == original.to_seed_and_pad()[0] == restored.to_seed_and_pad()[0]
    assert original.to_string() == restored.to_string()

seed_bytes = ngu.random.bytes(64)
original = Share.from_seed(seed_bytes, 'cx', 'test', 'a', 3, 0)
restored = Share.from_seed(original.to_seed_and_pad()[0], 'cx', 'test', 'a', 3, 0)
assert seed_bytes == original.to_seed_and_pad()[0] == restored.to_seed_and_pad()[0]
assert original.to_string() == restored.to_string()

# Preserve the interpolation round-trip from
# https://github.com/coinkite/afirmware/pull/494 with the padding correction from
# https://github.com/coinkite/afirmware/pull/536.
originals = [
    Share.parse('ms13k00lacf8aycvqkftq456thdjm342ky8j5muppfqt97s4'),
    Share.parse('ms13k00lcdk0hxv6eprwujncmdx96fg9s9qqkgq3vn9hq9yv'),
    Share.parse('ms13k00lf7wwuv6xlcgltfgjeygul26lwqmgu9hnu65q3fj2'),
]
round_tripped = []
for original in originals:
    seed_bytes, pad = original.to_seed_and_pad()
    restored = Share.from_seed(seed_bytes, 'ms', 'k00l', original.index, 3, pad)
    assert restored.to_seed_and_pad() == (seed_bytes, pad)
    assert restored.to_string() == original.to_string()
    round_tripped.append(restored)

assert generate_share(originals, SECRET).to_string() == \
    generate_share(round_tripped, SECRET).to_string()

print('Codex32: OK')

# EOF
