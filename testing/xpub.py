#!/usr/bin/env python3
#
# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Dump a few tihngs about random xpub. Can't handle SLIP-132 yet.
#
import sys
from bip32 import BIP32Node

kk = BIP32Node.from_wallet_key(sys.argv[-1])

pfp = kk.parent_fingerprint()
print(f'parent = {pfp.hex().upper()}')

print(f'depth = {kk.node.depth}')

fp = kk.fingerprint()
print(f'fingerprint = {fp.hex().upper()}')

print(f'chain = {kk.chain_code().hex()}')
print(f'sec = {kk.sec().hex()}')

