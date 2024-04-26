# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# unit test for code in shared/psbt.py
#
# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/unit_psbt.py')

from ubinascii import unhexlify as a2b_hex
from psbt import psbtObject, FatalPSBTIssue
from version import MAX_TXN_LEN
from sffile import SFFile
import main


fname = getattr(main, 'FILENAME', '../../testing/data/2-of-2.psbt')
print("Input PSBT: " + fname)

is_hex = False
tl = 0

with SFFile(0, max_size=MAX_TXN_LEN) as wr_fd:
    list(wr_fd.erase())
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

rd_fd = SFFile(0, tl)
obj = psbtObject.read_psbt(rd_fd)

# Many of these trival PSBT test cases now fail validation for various reasons,
# and that's correct thing to do.
try:
    obj.validate()
    print("parsed and validated ok")
except AssertionError as exc:
    print("hits assertion: %s" % exc)
    pass
except FatalPSBTIssue as exc:
    print("hits FatalPSBTIssue: %s" % exc)
    pass

with SFFile(MAX_TXN_LEN, max_size=MAX_TXN_LEN) as out_fd:
    list(out_fd.erase())
    obj.serialize(out_fd)
    out_fd.seek(0)
    # copy back into filesystem
    with open('readback.psbt', 'wb') as rb:
        while 1:
            here = out_fd.read(256)
            if not here:
                break
            rb.write(here)

rd_fd.close()