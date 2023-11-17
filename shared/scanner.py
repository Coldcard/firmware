# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# scanner.py - QR scanner submodule. Low level hardware stuff only.
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

def unwrap_hdr(packed):
    # just get out the length
    stx, fid, mlen = unpack('>bbH', packed[0:4])
    if stx != 0x5A or fid not in (1, 2):
        return -1
    return mlen + 6

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
RAW_OKAY = b'\x90\x00'
LEN_OKAY = const(8)

# TODO: constructor should leave it in reset for simple lower-power usage; then after
#       login we can do full setup (2+ seconds) and then sleep again until needed.

class QRScanner:

    def __init__(self):
        self.lock = asyncio.Lock()

        self.busy_scanning = False

        from machine import UART, Pin
        self.serial = UART(2, 9600)
        self.reset = Pin('QR_RESET', Pin.OUT_OD, value=0)
        self.trigger = Pin('QR_TRIG', Pin.OUT_OD, value=1)      # wasn't needed

        # from https://github.com/peterhinch/micropython-async/blob/master/v3/as_demos/auart_hd.py
        self.stream = asyncio.StreamReader(self.serial, {})

        # NOTE: reset is active low (open drain)
        self.reset(0)
        utime.sleep_ms(10)
        self.reset(1)

        self.version = None

        # needs 2+ seconds of recovery time after reset, so watch that
        self.setup_done = False
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
        except:
            raise
            #print("QR Scanner: missing")

        # configure it like we want it
        await self.tx('S_CMD_FFFF')         # factory reset of settings
        await self.tx('S_CMD_MTRS5000')     # 5s to read before fail
        await self.tx('S_CMD_MT11')         # trigger is edge-based (not level)
        await self.tx('S_CMD_MT30')         # Same code reading without delay
        await self.tx('S_CMD_MT20')         # Enable automatic sleep when idle
        await self.tx('S_CMD_MTRF500')      # Idle time: 500ms
        await self.tx('S_CMD_059A')         # add CR LF after QR data

        self.setup_done = True

        await self.goto_sleep()
            
    async def scan_once(self):
        # blocks until something is scanned. returns it

        # wait for reset process to complete (can be an issue right after boot)
        while not self.setup_done:
            await asyncio.sleep(.25)

        async with self.lock: 
            self.busy_scanning = True

            await self.wakeup()
            await self.tx('S_CMD_020D')

            # these aren't useful (yet?)
            #await self.tx('S_CMD_05F1')         # add all information on
            #await self.tx('S_CMD_05L1')         # output decoding length info on
            #await self.tx('S_CMD_05S1')         # STX start char
            #await self.tx('S_CMD_05C1')         # CodeID+prefix
            #await self.tx('S_CMD_0501')         # prefix on
            #await self.tx('S_CMD_0506')         # suffix
            #await self.tx('S_CMD_05D0')         # tx total data

            # begin scan
            await self.tx('SR030301')

            try:
                rv = await self.stream.readline()
            except asyncio.CancelledError:
                rv = None
            finally:
                await self.tx('SR030300')
                await self.goto_sleep()

        self.busy_scanning = False

        return rv

    async def wakeup(self):
        # send specific command until it responds
        # - it will wake on any command, but not instant
        # - first one seems to fail 100%
        for retry in range(5):
            try:
                await self.tx('SRDF0051', timeout=50)       # 50 ok, 20 too short
                return
            except: 
                # first try usually fails, that's okay... its asleep and groggy
                pass

    async def goto_sleep(self):
        # Had to decode hex to get this command! Does work tho, current consumption
        # is near zero, and wakeup is instant
        await self.tx('SRDF0050')

    async def tx(self, msg, timeout=250):
        # Send a command, get the response.
        # - has a long timeout, collects rx based on framing
        # - but optimized for normal case, which is just "ok" back
        # - out going messages are text, and we wrap that w/ binary framing
        if msg is not None:

            # fix framing problems by clearing anything already there before command
            while n := self.stream.s.any():
                junk = await self.stream.readexactly(n)
                #print('Scan << (junk)  ' + B2A(junk))

            #print('Scan >> ' + msg)
            self.stream.write(wrap(msg))
            await self.stream.drain()

        # read until ETX=0xA5 is seen
        expect = LEN_OKAY
        rx = b''
        while 1:
            try:
                rx += await asyncio.wait_for_ms(self.stream.readexactly(expect), timeout)
            except asyncio.TimeoutError:
                if timeout is None:
                    continue
                raise RuntimeError("no rx")

            #print('Scan << ' + B2A(rx))

            if rx == OKAY:
                # - can get scan data ahead of OK msg sometimes, so ignore any prefix
                return

            if rx == RAW_OKAY:
                # - sometimes? get this bare (unwrapped), in response to SRDF0051 (wakeup)
                return

            mlen = unwrap_hdr(rx)
            if mlen < 0:
                # framing issue
                #print('Framing prob: %s=%s' % (rx, B2A(rx)))
                break

            more = mlen - len(rx)
            if more <= 0: break
            expect = more

        try:
            body, extra = unwrap(rx)
            if extra:
                raise RuntimeError("extra at end")
            return body
        except Exception as exc:
            #print("Bad Rx: " + B2A(rx))
            #print("   exc: %s" % exc)
            raise

    def torch_control_sync(self, on):
        # sync wrapper
        asyncio.create_task(self.torch_control(on))

    async def torch_control(self, on):
        # be an expensive flashlight
        # - S_CMD_03L1 => always light
        # - S_CMD_03L2 => when needed
        if not self.version:
            return

        if self.busy_scanning:
            # do nothing if scanning already
            return

        async with self.lock: 

            await self.wakeup()
            await self.tx('S_CMD_03L%d' % (1 if on else 2))

            if not on:
                # sleep module too
                await self.goto_sleep()

# EOF
