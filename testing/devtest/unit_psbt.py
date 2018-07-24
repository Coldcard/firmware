# unit test for code in shared/psbt.py
#
# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/unit_psbt.py')

from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

import tcc, ustruct
from main import settings
from public_constants import MAX_TXN_LEN

# load PSBT into simulated SPI Flash
from sffile import SFFile

wr_fd = SFFile(0, max_size=MAX_TXN_LEN)
list(wr_fd.erase())
out_fd = SFFile(MAX_TXN_LEN, max_size=MAX_TXN_LEN)
list(out_fd.erase())

# read from into MacOS filesystem
import main
fname = getattr(main, 'FILENAME', '../../testing/data/2-of-2.psbt')
print("Input PSBT: " + fname)

is_hex = False
tl = 0
with open(fname, 'rb') as orig:
    while 1:
        here = orig.read(256)
        if not here: break

        if here[0:10] == b'70736274ff':
            is_hex = True

        if is_hex:
            here = a2b_hex(here)

        wr_fd.write(here)
        tl += len(here)

from psbt import psbtObject, FatalPSBTIssue

rd_fd = SFFile(0, tl)
obj = psbtObject.read_psbt(rd_fd)

# all these trival test cases now fail validation for various reasons...
try:
    obj.validate()
    print("should fail")
except AssertionError:
    pass
except FatalPSBTIssue:
    pass

obj.serialize(out_fd)
out_tl = out_fd.tell()

# copy back into MacOS filesystem
with open('readback.psbt', 'wb') as rb:
    out_fd.seek(0)
    while 1:
        here = out_fd.read(256)
        if not here: break

        rb.write(here)
