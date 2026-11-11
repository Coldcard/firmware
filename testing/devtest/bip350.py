# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Native SegWit address vectors from BIP-350 (Pieter Wuille, BSD-2-Clause):
# https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors-for-v0-v16-native-segregated-witness-addresses
# These test address codecs and output rendering, not input signing support.

import ngu
from ubinascii import unhexlify
from chains import BitcoinMain, BitcoinTestnet


valid = [
    ('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
     '0014751e76e8199196d454941c45d1b3a323f1433bd6'),
    ('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
     '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'),
    ('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
     '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'),
    ('BC1SW50QGDZ25J',
     '6002751e'),
    ('bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs',
     '5210751e76e8199196d454941c45d1b3a323'),
    ('tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
     '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'),
    ('tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c',
     '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
     '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
]

for address, script_hex in valid:
    script = unhexlify(script_hex)
    hrp, version, program = ngu.codecs.segwit_decode(address)
    assert hrp == address.lower().split('1')[0], address
    assert version == (script[0] - 0x50 if script[0] else 0), address
    assert program == script[2:], address
    assert ngu.codecs.segwit_encode(hrp, version, program) == address.lower(), address
    chain = BitcoinMain if hrp == 'bc' else BitcoinTestnet
    assert chain.render_address(script) == address.lower(), address


invalid = [
    ('tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
     True, 'Invalid human-readable part'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
     False, 'Invalid checksum (Bech32 instead of Bech32m)'),
    ('tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
     False, 'Invalid checksum (Bech32 instead of Bech32m)'),
    ('BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
     False, 'Invalid checksum (Bech32 instead of Bech32m)'),
    ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
     False, 'Invalid checksum (Bech32m instead of Bech32)'),
    ('tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
     False, 'Invalid checksum (Bech32m instead of Bech32)'),
    ('bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
     False, 'Invalid character in checksum'),
    ('BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
     False, 'Invalid witness version'),
    ('bc1pw5dgrnzv',
     False, 'Invalid program length (1 byte)'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
     False, 'Invalid program length (41 bytes)'),
    ('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
     False, 'Invalid program length for witness version 0 (per BIP141)'),
    ('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
     False, 'Mixed case'),
    ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
     False, 'zero padding of more than 4 bits'),
    ('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
     False, 'Non-zero padding in 8-to-5 conversion'),
    ('bc1gmk9yu',
     False, 'Empty data section'),
]

for address, wrong_hrp, reason in invalid:
    try:
        hrp, version, program = ngu.codecs.segwit_decode(address)
    except ValueError:
        assert not wrong_hrp, (address, reason)
    else:
        # Unlike the BIP's decode(expected_hrp, address), the ngu API returns
        # the actual HRP. The tc vector has a valid checksum but belongs to
        # neither Bitcoin network in these vectors.
        assert wrong_hrp, (address, reason)
        assert hrp == 'tc', address
        assert hrp not in (BitcoinMain.bech32_hrp, BitcoinTestnet.bech32_hrp), address
