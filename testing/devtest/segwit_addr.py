# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/segwit_addr.py')
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

import tcc
bech32_decode = tcc.codecs.bech32_decode
bech32_encode = tcc.codecs.bech32_encode

#from tcc.codecs import bech32_decode, bech32_encode

# from <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
# - these are valid bech32, but invalid segwit addresses, and so they fail
confused = [
    'A12UEL5L',
    'a12uel5l',
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
    '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
    'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
    '\x801ezyfcl'
]

for v in confused:
    try:
        hrp, version, data = bech32_decode(v)
        assert False, ("%s => %s,%d,%r" % (v, hrp, version, data))
    except ValueError:
        pass


# examples, and their segwit programs

decode = [

 ( 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
        '0014751e76e8199196d454941c45d1b3a323f1433bd6', 0),
 ( 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
        '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262', 0),
 ( 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
        '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6', 1),
 ( 'BC1SW50QA3JX3S',
        '6002751e', 16),
 ( 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
        '5210751e76e8199196d454941c45d1b3a323', 2),
 ( 'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
        '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433', 0),
]

for addr, expect, v in decode:
    hrp, version, data = bech32_decode(addr)
    assert version == v, (addr, version, v)
    assert hrp == addr.lower()[0:2]
    assert expect.endswith(b2a_hex(data)), (expect, data)
    #print("%s ok" % addr)


# some bad checksums

chk = [
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
    'li1dgmt3',
    'de1lg7wt\xff',
    'A1G7SGD8',
]

for v in chk:
    try:
        hrp, version, data = bech32_decode(v)
        assert False, ("%s => %s,%d,%r" % (v, hrp, version, data))
    except ValueError:
        pass
