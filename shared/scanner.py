# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# scanner.py - QR scanner submodule on Q1
#
import utime
import uasyncio as asyncio
from struct import pack, unpack
from utils import B2A
from imptask import IMPT
from queues import Queue

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
        self.q = None
        self._scan_task = None

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
        await self.tx('S_CMD_MT11')         # trigger is edge-based (not level)
        await self.tx('S_CMD_MT30')         # Same code reading without delay
        await self.tx('S_CMD_MT20')         # Enable automatic sleep when idle
        await self.tx('S_CMD_MTRF500')      # Idle time: 500ms

        await self.sleep()

    def hw_scan(self):
        if self.trigger() == 0:
            # need to release/re-press
            self.trigger(1)
            utime.sleep_ms(100)
        self.trigger(0);

    async def _read_results(self):
        # be a task that reads incoming QR codes from scanner (already in operation)
        # - will be canceled when done/stopping
        while 1:
            ln = await self.sr.read(200)
            if not ln: continue
            print(repr(ln))
            await self.q.put(ln)
            
    async def scan_start(self, test=15):
        # returns a Q we append to as results come in
        await self.wakeup()
        await self.tx('S_CMD_020D')

        self.q = rv = Queue()
        self._scan_task = asyncio.create_task(self._read_results())

        # begin scan
        await self.tx('SR030301')

        if test:
            await asyncio.sleep(test)
            await self.scan_stop()

        return rv

    async def scan_stop(self):
        # stop scanning
        if self._scan_task:
            self._scan_task.cancel()
            self._scan_task = None

        self.q = None

        await self.tx('SR030300')
        await self.sleep()

    def rx(self):
        # untested
        return self.serial.read()

    async def wakeup(self):
        # send specific command until it responds
        # - it will wake on any command, but not instant
        for retry in range(3):
            try:
                await self.tx('SRDF0051')
                return
            except: pass

        print("unable to wake QR")

    async def sleep(self):
        # Had to decode hex to get this command! Does work tho, current consumption
        # is near zero, and wakeup is instant
        await self.tx('SRDF0050')

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
        if not self.version:
            return

        await self.wakeup()

        await self.tx('S_CMD_03L%d' % (1 if on else 2))

        if not on:
            # sleep module too
            await self.sleep()

# EOF
