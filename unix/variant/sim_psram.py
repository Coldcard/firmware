# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psram.py -- access PSRAM chip on Mk4
#
import version, psram

class SimulatedPSRAMWrapper(psram.PSRAMWrapper):

    def __init__(self):
        # note: need heapsize=X with big number to get object so big on the heap
        self._wr = bytearray(self.length)

    def read_at(self, offset, ln):
        # one-copy byte-wise access
        return bytes(self._wr[offset:offset+ln])

psram.PSRAMWrapper = SimulatedPSRAMWrapper

# EOF
