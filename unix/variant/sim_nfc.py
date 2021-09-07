# Replace NFC tag chip w/ emulation
from nfc import NFCHandler

global TAG_DATA
TAG_DATA = bytearray(8196)

class SimulatedNFCHandler(NFCHandler):
    def __init__(self):
        self.rf_on = False
        self.i2c = NotImplementedError
        self.mem_size = len(TAG_DATA)

    # flash memory access (fixed tag data): 0x0 to 0x2000
    def read(self, offset, count):
        return bytes(TAG_DATA[offset:offset+count])

    def write(self, offset, data):
        TAG_DATA[offset:offset+len(data)] = data

    def big_write(self, data):
        self.write(0, data)
        n = open('nfc-dump.ndef', 'wb').write(self.dump_ndef())
        print("%d bytes of NDEF written to work/nfc-dump.ndef" % n)

    def is_rf_disabled(self):
        # not checking if disable/sleep vs. off
        return not self.rf_on

    def set_rf_disable(self, val):
        # using stronger "off" rather than sleep/disable
        self.rf_on = not val
        
    def firsttime_setup(self):
        print("simNFC: first time (skip)")
        return

    def setup(self):
        # check if present, alive
        print("simNFC: setup")

# EOF
