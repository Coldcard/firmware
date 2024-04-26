# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_psram.py -- SIMULATED access PSRAM chip on Mk4
#
import version, psram

class SimulatedPSRAMWrapper(psram.PSRAMWrapper):

    def __init__(self):
        # note: need heapsize=X with big number to get object so big on the heap
        self._wr = bytearray(self.length)

        # help to find un-init memory bugs faster
        for i in range(self.length):
            self._wr[i] = 0x65

    def read_at(self, offset, ln):
        # one-copy byte-wise access
        return bytes(self._wr[offset:offset+ln])

psram.PSRAMWrapper = SimulatedPSRAMWrapper

# EOF
