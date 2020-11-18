# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# work thru the first example given in BIP-143
from h import a2b_hex, b2a_hex
from psbt import psbtObject, psbtInputProxy, psbtOutputProxy
from serializations import CTxIn
from uio import BytesIO
from sffile import SFFile

# NOTE: not a psbt, just a txn
# - 2 ins, 2 outs
unsigned = a2b_hex('0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000')


fd = SFFile(0, max_size=65536)
list(fd.erase())
fd.write(b'psbt\xff\x01\x00' + bytes([len(unsigned)]) + unsigned + (b'\0'*8))
psbt_len = fd.tell()

rfd = SFFile(0, psbt_len)

p = psbtObject.read_psbt(rfd)

#p.validate()       # failed because no subpaths; don't care

amt = 600000000
sc = a2b_hex('1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac')

outpt2 = a2b_hex('ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff')

replacement = CTxIn()
replacement.deserialize(BytesIO(outpt2))

digest = p.make_txn_segwit_sighash(0, replacement, amt, sc, 0x01)

print('Got: ' + b2a_hex(digest).decode('ascii'))
assert digest == a2b_hex('c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')
