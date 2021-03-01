# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
from glob import dis
from ubinascii import hexlify as b2a_hex

RV.write(b2a_hex(dis.dis.buffer))

