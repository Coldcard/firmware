#! /usr/bin/env python3
cr='''\
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
'''
import os, sys, pprint, zlib

version, input_file = sys.argv[1:]

data = open(input_file, 'rb').read()

zdata = zlib.compress(data)

print(f"{cr}# Binary for Q1 GPU co-processor")
print("# ")
print("# see misc/gpu for source")
print("# ")
print(f"VERSION = '{version}'\n")
print(f"LENGTH = const({len(data)})  # bytes (after decompression)\n")
print(f"# len(BINARY) = {len(zdata)}")
print(f"BINARY = {pprint.pformat(zdata)}\n\n# EOF")

