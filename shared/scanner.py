# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# scanner.py - QR scanner submodule on Q1
#
import utime
import uasyncio as asyncio
from struct import pack, unpack
from utils import B2A
from imptask import IMPT

def calc_bcc(msg):
    bcc = 0
    for c in msg:
        bcc ^= c
    return bytes([bcc])

def wrap(body, fid=0):
    # wrap w/ their weird serial framing
    # - serial port doesn't always need this! just send the string, but
    #   then response is unwrapped as well, so no checksums.
    body = body if isinstance(body, bytes) else body.encode('ascii')
    rv = pack('>bH', fid, len(body)) + body
    return b'\x5A' + rv + calc_bcc(rv) + b'\xA5'       # STX ... ETX

def unwrap(packed):
    # read back values
    stx, fid, mlen = unpack('>bbH', packed[0:4])
    assert stx == 0x5A, 'framing: STX'
    assert fid == 1, 'not resp'

    body = packed[4:4+mlen]
    got_bcc, etx = packed[4+mlen:4+mlen+2]

    assert etx == 0xA5, 'framing: ETX'
    expect = calc_bcc(packed[1:4+mlen])
    assert got_bcc == expect[0], 'bad BCC'

    # return decoded body, and any extra bytes following it
    return body, packed[4+mlen+2:]

# this is wrap(b'\x90\x00', fid=1) ... 9000 is ACK. silence is NACK
OKAY = b'Z\x01\x00\x02\x90\x00\x93\xa5'

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

        self.sr = asyncio.StreamReader(self.serial)

        # needs 2+ seconds of recovery time after reset
        self.version = None
        asyncio.create_task(self.setup_task())

    async def setup_task(self):
        # setup device, and then stop
        await asyncio.sleep(2)

        while self.serial.read():
            pass        # ignore old data

        try:
            # get b'V2.3.0.7\r\n' or similar
            rx = await self.tx('T_OUT_CVER')
            self.version = rx.decode().strip()
            print("QR Scanner: " + self.version)
        except:
            raise
            print("QR Scanner: missing")

        # configure it like we want it
        #self.tx('T_CMD...'
        await self.tx('S_CMD_MTRS5000')     # 5s to read before fail
        await self.tx('S_CMD_MT10')         # trigger is level-based (not edge)
        await self.tx('S_CMD_MT30')         # Same code reading withou delay
        await self.tx('S_CMD_MT20')         # Enable automatic sleep when idle

    def scan(self):
        if self.trigger() == 0:
            # need to release/re-press
            self.trigger(1)
            utime.sleep_ms(100)
        self.trigger(0);

    def rx(self):
        # untested
        return self.serial.read()

    async def tx(self, msg):
        # send a command, get response
        # - has a long timeout, collects rx based on framing
        self.sr.write(wrap(msg))
        await self.sr.drain()

        # read until ETX=0xA5 is seen
        rx = bytearray()
        while 1:
            try:
                h = await asyncio.wait_for_ms(self.sr.read(-1), 500)
            except asyncio.TimeoutError:
                raise RuntimeError("rx timeout")

            if h:
                rx.extend(h)
            if h[-1] == 0xA5:
                break

        if rx == OKAY:
            return

        try:
            body, extra = unwrap(rx)
            if extra:
                raise RuntimeError("extra at end")
            return body
        except:
            print("Bad Rx: " + B2A(rx))

    async def torch(self, on):
        # be an expensive flashlight
        # - S_CMD_03L1 => always light
        # - S_CMD_03L2 => when needed
        if not self.version: return
        await self.tx('S_CMD_03L%d' % (1 if on else 2))

# EOF
