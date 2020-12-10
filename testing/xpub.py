#!/usr/bin/env python3
#
# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Dump a few tihngs about random xpub. Can't handle SLIP-132 yet.
#
import os, sys
from pycoin.key.BIP32Node import BIP32Node

kk = BIP32Node.from_wallet_key(sys.argv[-1])

pfp = kk.parent_fingerprint()
print(f'parent = {pfp.hex().upper()}')

print(f'depth = {kk.tree_depth()}')

fp = kk.fingerprint()
print(f'fingerprint = {fp.hex().upper()}')

print(f'chain = {kk.chain_code().hex()}')
print(f'pub pair = {kk.public_pair()}')

