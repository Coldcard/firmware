# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# unit test for address decoding from various types of CTxOuts
from h import a2b_hex, b2a_hex
from serializations import CTxOut
from uio import BytesIO


cases = [
    # TxOut, type, is_segwit, hash160/pubkey, 
    ( 'c4f33d0000000000160014ad46a001d55bd55d157e716bf17c02f8964b5a19',
        'p2pkh', True,
        'ad46a001d55bd55d157e716bf17c02f8964b5a19' ),
    ( '202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac',
        'p2pkh', False,
        '8280b37df378db99f66f85c95a783a76ac7a6d59' ),

    # from legendary txid: 40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8
    ( '301b0f000000000017a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87',
        'p2sh', False,
        'e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a'),

    # from testnet: a4c89e0ffb84d06a1e62f0f9f0f5974db250878caa1f71f9992a1f865b8ff2fa
    # via <https://github.com/bitcoinjs/bitcoinjs-lib/issues/856>
    ( 'b88201000000000017a914f0ca58dc8e539421a3cb4a9c22c059973075287c87',
        'p2sh', False,
        'f0ca58dc8e539421a3cb4a9c22c059973075287c'),

    # XXX missing: P2SH segwit, 1of1 and N of M
    ( 'd0f13d0000000000160014f2369bac6d24ed11313fa65adda1971d10e17bff',
        'p2pkh', True,
        'f2369bac6d24ed11313fa65adda1971d10e17bff')
]

for raw_txo, expect_type, expect_sw, expect_hash in cases:
    expect_hash = a2b_hex(expect_hash)

    out = CTxOut()
    out.deserialize(BytesIO(a2b_hex(raw_txo)))

    print("Case: %s... " % raw_txo[0:30])
    addr_type, addr_or_pubkey, is_segwit = out.get_address()

    assert is_segwit == expect_sw, 'wrong segwit'
    assert addr_or_pubkey == expect_hash, 'wrong pubkey/addr'
    assert addr_type == expect_type, addr_type


