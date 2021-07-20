# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Unit test for fancy QR stuff
#

from qrs import QRDisplayMega
import main, ngu
from ubinascii import hexlify as b2a_hex

msg_size, as_hex, offset = main.MSG_DETS

msg = ngu.random.bytes(msg_size)
#msg = bytes(i%256 for i in range(msg_size))

q = QRDisplayMega.setup(msg, as_hex)
q.idx = offset
assert q
q.redraw()

# can't comprehend a list here.
RV.write("[");
for n, p in enumerate(q.parts):
    if n:
        RV.write(", ")
    RV.write("'")
    RV.write(b2a_hex(p[0:25]))
    RV.write("'")
RV.write(']');

