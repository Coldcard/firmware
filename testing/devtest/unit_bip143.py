# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# work thru the first example given in BIP-143
from h import a2b_hex, b2a_hex
from psbt import psbtObject, psbtInputProxy, psbtOutputProxy
from serializations import CTxIn, ser_compact_size
from uio import BytesIO
from sffile import SFFile
from struct import unpack


# test vectors from BIP masqueraded as "examples"
BIP143_DATA = [
    (
        "Native P2WPKH",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
        '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000',
        '1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac',  # scriptCode
        0,  # input index
        'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff',  # outpoint
        0x01,  # sigHash typr
        '0046c32300000000',  # amount
        'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670',  # sighash (result)
    ),
    (
        "P2SH-P2WPKH",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        '0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000',
        '1976a91479091972186c449eb1ded22b78e40d009bdf008988ac',  # scriptCode
        0,  # input index
        'db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff',  # outpoint
        0x01,  # sigHash typr
        '00ca9a3b00000000',  # amount
        '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6',  # sighash (result)
    ),
    # (
    #     "Native P2WSH (scriptCode 0) SINGLE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
    #     '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000',
    #     # unsigned tx
    #     '4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac',
    #     # scriptCode
    #     1,  # input index
    #     '0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff',  # outpoint
    #     0x03,  # sigHash typr
    #     '0011102401000000',  # amount
    #     '82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391',  # sighash (result)
    # ),
    # (
    #     "Native P2WSH (scriptCode 1) SINGLE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
    #     '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000',
    #     '23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac',  # scriptCode
    #     1,  # input index
    #     '0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff',  # outpoint
    #     0x03,  # sigHash typr
    #     '0011102401000000',  # amount
    #     'fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47',  # sighash (result)
    # ),
    (
        "Native P2WSH (input 0) SINGLE|ANYONECANPAY",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
        '0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000',
        '270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac',  # scriptCode
        0,  # input index
        'e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff',  # outpoint
        0x83,  # sigHash typr
        'ffffff0000000000',  # amount
        'e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a',  # sighash (result)
    ),
    (
        "Native P2WSH (input 1) SINGLE|ANYONECANPAY",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
        '0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000',
        '2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac',  # scriptCode
        1,  # input index
        '80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff',  # outpoint
        0x83,  # sigHash typr
        'ffffff0000000000',  # amount
        'cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  ALL",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x01,  # sigHash typr
        'b168de3a00000000',  # amount
        '185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  NONE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x02,  # sigHash typr
        'b168de3a00000000',  # amount
        'e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  SIGNLE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x03,  # sigHash typr
        'b168de3a00000000',  # amount
        '1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  ANYONECANPAY|SIGNLE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x81,  # sigHash typr
        'b168de3a00000000',  # amount
        '2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  ANYONECANPAY|NONE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x82,  # sigHash typr
        'b168de3a00000000',  # amount
        '781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a',  # sighash (result)
    ),
    (
        "P2SH-P2WSH  AYONECANPAY|SIGNLE",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',  # scriptCode
        0,  # input index
        '36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff',  # outpoint
        0x83,  # sigHash typr
        'b168de3a00000000',  # amount
        '511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b',  # sighash (result)
    ),
    (
        "No FindAndDelete",  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#no-findanddelete
        '010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff0101000000000000000000000000',
        '4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01',
        # scriptCode
        0,  # input index
        '69c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff',  # outpoint
        0x01,  # sigHash typr
        '400d030000000000',  # amount
        '71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23',  # sighash (result)
    ),
]
for name, unsigned_tx, scriptCode, idx, outpoint, sighash_type, amount, sighash in BIP143_DATA:
    unsigned = a2b_hex(unsigned_tx)
    fd = SFFile(0, max_size=65536)
    fd.write(b'psbt\xff\x01\x00' + ser_compact_size(len(unsigned)) + unsigned + (b'\0'*8))
    psbt_len = fd.tell()
    rfd = SFFile(0, psbt_len)
    p = psbtObject.read_psbt(rfd)
    #p.validate()  # failed because no subpaths; don't care
    amt = unpack("<q", a2b_hex(amount))[0]
    sc = a2b_hex(scriptCode)
    outpt = a2b_hex(outpoint)
    replacement = CTxIn()
    replacement.deserialize(BytesIO(outpt))
    digest = p.make_txn_segwit_sighash(idx, replacement, amt, sc, sighash_type)
    got = b2a_hex(digest).decode('ascii')
    assert digest == a2b_hex(sighash), "%s\nExpected %s\nGot      %s" % (name, sighash, got)
    print(name, "OK")

