# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# scanner.py - QR scanner submodule on Q1 (only)
#
import utime
from struct import pack
from utils import B2A

def wrap(body, fid=0):
    # wrap w/ their weird framing
    # LATER: USB? serial port doesn't need this! just send the string!
    body = body if isinstance(body, bytes) else body.encode('ascii')
    rv = pack(b'>bH', fid, len(body)) + body
    bcc = 0
    for c in rv:
        bcc ^= c
    return b'\x5A' + rv + bytes([bcc]) + b'\xA5'       # STX ... ETX

class QRScanner:

    def __init__(self):
        from machine import UART, Pin
        self.serial = UART(2, 9600)
        self.reset = Pin('QR_RESET', Pin.OUT_OD)
        self.trigger = Pin('QR_TRIG', Pin.OUT_OD)

        # trigger/reset are active low (open drain)
        self.trigger(1)

        self.reset(0)
        utime.sleep_ms(10)
        self.reset(1)

    def scan(self):
        if q.trigger() == 0:
            # need to release/re-press
            q.trigger(1)
            utime.sleep_ms(100)
        q.trigger(0);

    def rx(self):
        # untested
        return self.serial.read()

    def tx(self, m):
        # not working
        x = wrap(m)
        print('Sending: ' + B2A(x))
        self.serial.write(x)

    def test(self):
        m = bytes([90, 0, 0, 10, 95, 67, 77, 68, 95, 48, 48, 48, 49, 18, 165])
        self.serial.write(m)
        return self.serial.read()
    
q = QRScanner()

# EOF
