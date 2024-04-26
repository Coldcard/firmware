# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Replace NFC tag chip w/ emulation
from nfc import NFCHandler

global TAG_DATA
TAG_DATA = bytearray(8196)

# unix/work/nfc-dump.ndef
DATA_FILE = 'nfc-dump.ndef'

class SimulatedNFCHandler(NFCHandler):
    def __init__(self):
        self.rf_on = False
        self.i2c = NotImplementedError
        self.uid = bytes(range(8))
        self.mem_size = len(TAG_DATA)

    # flash memory access (fixed tag data): 0x0 to 0x2000
    def read(self, offset, count):
        return bytes(TAG_DATA[offset:offset+count])

    def write(self, offset, data):
        TAG_DATA[offset:offset+len(data)] = data

    async def big_write(self, data):
        import os
        self.write(0, data)
        #n = open('nfc-dump.ndef', 'wb').write(self.dump_ndef())
        with open(DATA_FILE, 'wb') as ff:
            n = ff.write(data)
        atime, mtime, ctime = os.stat(DATA_FILE)[-3:]
        self._mtime = mtime
        self._atime = atime
        print("%d bytes of NDEF written to work/nfc-dump.ndef .. Ctrl-N or touch or read that file to simulate taps" % n)

    async def wipe(self, full_wipe):
        print("NFC chip wiped (full=%d)" % int(full_wipe))

    def is_rf_disabled(self):
        return not self.rf_on

    def set_rf_disable(self, val):
        self.rf_on = not val
        
    def firsttime_setup(self):
        print("simNFC: first time (skip)")
        return

    def setup(self):
        # check if present, alive
        print("simNFC: setup")

    def read_dyn(self, reg):
        IT_STS_Dyn = 0x2005   # Interrupt Status
        if reg == IT_STS_Dyn:
            import os
            # polled during wait for NFC
            self.last_edge = 1      # force come-back
            atime, mtime, ctime = os.stat(DATA_FILE)[-3:]
            if mtime != self._mtime:
                self._mtime = mtime
                got = open(DATA_FILE, 'rb').read(8196)
                TAG_DATA[:len(got)] = got
                return 0x80        # written by outside process
            if atime != self._atime:
                self._atime = atime
                return 0x02        # read
        return 0

    async def wait_ready(self):
        pass

    async def setup_gpio(self):
        self.last_edge = 1
        return
        

# close door behind ourselves
NFCHandler = SimulatedNFCHandler

# EOF
