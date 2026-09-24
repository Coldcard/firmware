# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
# Host-only checks for the published, fixed interoperability vectors.
# Run without simulator fixtures: pytest --noconftest testing/test_codex32_extensions.py

import itertools
import json
from pathlib import Path
import sys

import pytest
from mnemonic import Mnemonic
from bip32 import BIP32Node, PrvKeyNode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'shared'))
from codex32 import (Share, generate_share, bech32_to_array,
                     codex32_create_checksum, codex32_verify_checksum)

VECTORS = json.loads((ROOT / 'docs/codex32-extension-vectors.json').read_text())
SETS = VECTORS['valid_sets']


@pytest.mark.parametrize('body_length,checksum,valid', [
    (75, 'daqeydmnn8erj', True),       # Expanded length 93: last regular codeword.
    (76, 'gta055y8whlfr6l', True),     # Expanded length 96: first long codeword.
    (77, '86ylp05xy3rmumt', True),
    (78, '3773k4f8q367s6f', True),
    (79, 'c4nkwt4vc4swlj3', True),
    (80, 'ls6mre8thxl9486', True),
    (81, '7x2z8ksk6ex5esy', True),
    (1003, 'k5jmj358y6v4y0v', True),   # Expanded length 1023: last long codeword.
    (1004, 'kxyxut96dnfpnt0', False),  # Correct residue, but beyond the period.
])
def test_checksum_expanded_boundaries(body_length, checksum, valid):
    # Fixed outputs from the BIP-93 reference after bitcoin/bips#2258.
    # Exercise the checksum helpers independently of supported wallet sizes.
    body = [0] * body_length
    expected = bech32_to_array(checksum)
    assert codex32_create_checksum('ms', body) == expected
    assert codex32_verify_checksum('ms', body + expected) == valid


@pytest.mark.parametrize('body_length,checksum', [
    (76, 'zy2qlkz0nxqul'),            # Forbidden expanded length 94.
    (77, '366cy959nt6he'),            # Forbidden expanded length 95.
    (78, '2qjkhkmq2m8j6'),            # Long checksum required from here.
    (79, 'z9fzytvtqttl5'),
    (80, 'secretsk7qeue'),
])
def test_checksum_rejects_legacy_short_boundaries(body_length, checksum):
    assert not codex32_verify_checksum('ms', [0] * body_length + bech32_to_array(checksum))


@pytest.mark.parametrize('hrp', ['ms', 'cw', 'cx'])
@pytest.mark.parametrize('payload_length,checksum_length', [(69, 13), (71, 15), (74, 15), (76, 15)])
def test_share_length_at_checksum_boundary(hrp, payload_length, checksum_length):
    share = Share(hrp, 'test', 'q' * payload_length, 's', 0)
    encoded = share.to_string()
    assert len(share.checksum()) == checksum_length
    assert len(share) == len(encoded) == 9 + payload_length + checksum_length
    # Fixing checksum selection must not enable unsupported wallet sizes.
    with pytest.raises(AssertionError, match='codex32 length'):
        Share.parse(encoded)


@pytest.mark.parametrize('text', [
    'ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel',
    'ms10testsqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0j'
    'qgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu0ax3uvrcss9ddwnst',
    'MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88',
    *[text for vector in SETS
      for text in [vector['secret'], vector['standalone'], *vector['shares']]],
])
def test_calculate_checksum_vectors(text):
    checksum_len = 15 if len(text) == 127 else 13
    body = text[:-checksum_len]
    for value in (body.lower(), body.upper()):
        share = Share.from_body(value)
        assert share.to_string() == text.upper()
        assert share.payload == body[9:].lower()
        assert share.checksum() == text[-checksum_len:].lower()
    # Import still requires a complete, checksummed string.
    with pytest.raises((AssertionError, ValueError)):
        Share.parse(body)


@pytest.mark.parametrize('hrp,lengths', [('ms', (26, 52, 103)),
                                      ('cw', (26, 39, 52)), ('cx', (103,))])
@pytest.mark.parametrize('length', [0, 25, 26, 27, 32, 33, 38, 39, 40,
                                  45, 46, 47, 51, 52, 53, 74, 75, 80, 81, 102, 103, 104])
def test_calculate_checksum_lengths(hrp, lengths, length):
    body = hrp + '12tests' + 'q' * length
    if length in lengths:
        assert Share.from_body(body).payload == 'q' * length
    else:
        with pytest.raises((AssertionError, ValueError)):
            Share.from_body(body)


@pytest.mark.parametrize('header', ['', 'ms', 'ms1', 'ms12', 'ms12tes',
    'ms12test', 'zz12tests', 'ms02tests', 'ms112tests', 'ms12tes1s',
    'ms1xtests', 'ms11tests', 'ms1-tests', 'ms10testa', 'ms10testq',
    'ms12tebs', 'ms12testb', 'mS12tests', 'MS12testS'])
def test_calculate_checksum_invalid_header(header):
    with pytest.raises((AssertionError, ValueError)):
        Share.from_body(header + 'q' * 26)


@pytest.mark.parametrize('character', ['b', 'i', 'o', '1', '!', '\n', '\t', 'é', 'Q'])
def test_calculate_checksum_invalid_payload(character):
    with pytest.raises((AssertionError, ValueError)):
        Share.from_body('ms12tests' + 'q' * 25 + character)


@pytest.mark.parametrize('index', ['s', 'a', 'q', 'l'])
@pytest.mark.parametrize('threshold', [0, 2, 9])
def test_calculate_checksum_threshold_index(threshold, index):
    body = 'ms1%dtest%s' % (threshold, index) + 'q' * 25 + 'l'
    if threshold == 0 and index != 's':
        with pytest.raises(AssertionError, match='non-secret share with threshold 0'):
            Share.from_body(body)
    else:
        share = Share.from_body(body)
        assert (share.threshold, share.index) == (threshold, index)
        assert share.to_seed_and_pad()[1] == 3


@pytest.mark.parametrize('vector', SETS, ids=lambda v: v['id'])
def test_extension_encoding(vector):
    raw = bytes.fromhex(vector['payload_hex'])
    for field, threshold in (('secret', 2), ('standalone', 0)):
        for text in (vector[field], vector[field].lower()):
            share = Share.parse(text)
            assert (share.hrp, share.uid, share.index, share.threshold) == (
                vector['hrp'], 'test', 's', threshold)
            assert share.to_seed_and_pad() == (raw, vector['padding'])
            assert share.to_string() == vector[field]
            assert Share.from_seed(raw, vector['hrp'], 'test', 's', threshold,
                                   vector['padding']).to_string() == vector[field]


@pytest.mark.parametrize('vector', SETS, ids=lambda v: v['id'])
def test_extension_recovery(vector):
    shares = [Share.parse(text) for text in vector['shares']]
    for share, text in zip(shares, vector['shares']):
        assert share.to_string() == text
        assert not share.is_secret_share()
    for pair in itertools.combinations(shares, 2):
        for ordered in (pair, pair[::-1]):
            assert generate_share(ordered, 's').to_string() == vector['secret']
            missing = next(s for s in shares if s not in pair)
            assert generate_share(ordered, missing.index).to_string() == missing.to_string()


@pytest.mark.parametrize('vector', [v for v in SETS if v['hrp'] == 'cw'],
                         ids=lambda v: v['id'])
def test_extension_words_wallet(vector):
    entropy = bytes.fromhex(vector['payload_hex'])
    mnemonic = Mnemonic('english').to_mnemonic(entropy)
    assert mnemonic == vector['mnemonic']
    for expected in vector['wallets']:
        node = BIP32Node.from_master_secret(
            Mnemonic.to_seed(mnemonic, expected['passphrase']), netcode='BTC')
        assert node.hwif(as_private=True) == expected['xprv']
        assert node.fingerprint().hex().upper() == expected['fingerprint']


@pytest.mark.parametrize('vector', [v for v in SETS if v['hrp'] == 'cx'],
                         ids=lambda v: v['id'])
def test_extension_extended_key_wallet(vector):
    raw = bytes.fromhex(vector['payload_hex'])
    assert raw[:32].hex() == vector['chain_code_hex']
    assert raw[32:].hex() == vector['private_key_hex']
    node = BIP32Node(PrvKeyNode(key=raw[32:], chain_code=raw[:32]), netcode='BTC')
    assert node.hwif(as_private=True) == vector['xprv']
    assert node.fingerprint().hex().upper() == vector['fingerprint']


@pytest.mark.parametrize('vector', VECTORS['invalid_encodings'], ids=lambda v: v['id'])
def test_extension_invalid_encoding(vector):
    with pytest.raises((AssertionError, ValueError)):
        Share.parse(vector['encoded'])


@pytest.mark.parametrize('vector', VECTORS['invalid_wallets'], ids=lambda v: v['id'])
def test_extension_wallet_rejection_vectors(vector):
    # Check the vector classification. Actual firmware activation/state-preservation
    # is exercised by the simulator tests in test_codex32.py.
    share = Share.parse(vector['encoded'])
    assert share.to_string() == vector['encoded']
    if vector['reason'] == 'non-secret index':
        assert not share.is_secret_share()
    else:
        assert vector['reason'] == 'invalid private scalar'
        assert share.hrp == 'cx' and share.is_secret_share()
        raw = share.to_seed_and_pad()[0]
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert not 1 <= int.from_bytes(raw[32:], 'big') < order


@pytest.mark.parametrize('vector', VECTORS['invalid_recoveries'], ids=lambda v: v['id'])
def test_extension_invalid_recovery(vector):
    shares = [Share.parse(text) for text in vector['shares']]
    with pytest.raises(AssertionError):
        generate_share(shares, 's')


@pytest.mark.parametrize('target', ['s', 'j'])
@pytest.mark.parametrize('case', ['insufficient', 'excess_consistent', 'excess_inconsistent'])
def test_interpolation_requires_exact_threshold(target, case):
    a = Share.parse('MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88')
    c = Share.parse('MS12W7F2CFFFGRFURFZ6FJVFTLA4GU6AJL3SM7JJ23UZRHJU')
    assert generate_share([a, c], 's').to_string() == \
        'MS12W7F2SXXXXXXXXXXXXXXXXXXXXXXXXXY9ML44VCLR4TFD'

    if case == 'insufficient':
        shares = [a]
    elif case == 'excess_consistent':
        shares = [a, c, generate_share([a, c], 'd')]
    else:
        # Same metadata and valid checksum, but not on the original polynomial.
        extra = Share.from_seed(bytes(16), 'ms', a.uid, 'd', a.threshold, 0)
        shares = [a, c, Share.parse(extra.to_string())]

    with pytest.raises(AssertionError, match='need exactly 2 shares'):
        generate_share(shares, target)
