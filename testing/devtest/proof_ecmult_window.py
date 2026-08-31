# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import utime, ngu, uio
from ubinascii import unhexlify as x

N = 50
b = ngu.hdnode.HDNode()
b.from_chaincode_pubkey(x("22b29dd3ce203995fd130aab8341c1c0c70b7a3f0e64e2875c1eb664418f8e5f"),
                        x("039822622cf330b98e52e7357135bc93e1e5606a57a9819408734598fe5677b134"))
priv = bytes(range(1, 33))
msg = b"\x42" * 32

_c = b.copy(); _c.derive(7, False)
assert _c.pubkey() == x("025a0337d4beae25ab19d21b71dee98a43e95e64dad9c50cfb29345464a56df107")

b.copy().derive(0, False)
_t = utime.ticks_ms()
for i in range(N): b.copy().derive(i, False)
md = utime.ticks_diff(utime.ticks_ms(), _t)

ngu.secp256k1.sign(priv, msg, 0)
_t = utime.ticks_ms()
for i in range(N): ngu.secp256k1.sign(priv, msg, i)
ms = utime.ticks_diff(utime.ticks_ms(), _t)

o = "ECMULT_WINDOW bench, %d iters\n" % N
o += "  pub derive (ecmult)      %5d ms  %7.1f us/op\n" % (md, md * 1000.0 / N)
o += "  sign (ecmult_gen, ctrl)  %5d ms  %7.1f us/op\n" % (ms, ms * 1000.0 / N)
o += "  derive/sign = %.3f\n" % (md / ms)
RV.write(o.encode())
