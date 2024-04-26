# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Replace QR Scanner module interface.
#
# - also supports local real scanner over USB serial.
#
import os, sys
import uasyncio as asyncio
from scanner import QRScanner
from queues import Queue

# unix/working/...
DATA_FILE = 'qrdata.txt'

class SimulatedQRScanner(QRScanner):
    def __init__(self):
        self.setup_done = True
        self.version = 'V2.3.420'
        self.lock = asyncio.Lock()
        # returns a Q we append to as results come in
        self._q = Queue()

    async def _read_results(self):
        # be a task that reads incoming QR codes from scanner (already in operation)
        # - will be canceled when done/stopping
        try:
            _, orig_mtime, _ = os.stat(DATA_FILE)[-3:]
        except OSError:
            orig_mtime = None

        from ckcc import data_pipe

        while 1:
            try:
                got = await asyncio.wait_for_ms(data_pipe.readline(), 250)
                print("Got pasted QR data.")
                self._q.put_nowait(got)
                continue
            except asyncio.TimeoutError:
                pass

            try:
                _, mtime, _ = os.stat(DATA_FILE)[-3:]
            except OSError:
                mtime = None

            if mtime == orig_mtime:
                continue

            print("Got new QR scan data from file.")
            for ln in open(DATA_FILE, 'rb').readlines():
                self._q.put_nowait(ln)

            orig_mtime = mtime
            
    async def _readline(self):
        rv = await self._q.get()
        return rv.rstrip().decode()

    async def wakeup(self):
        print("Click screen to paste QR data from clipboard,\nor write data into file: work/%s" % DATA_FILE)
        self._task = asyncio.create_task(self._read_results())

    async def tx(self, msg):
        return

    async def txrx(self, msg, timeout=250):
        return

    async def goto_sleep(self):
        self._task.cancel()

    async def torch_control(self, on):
        print("Torch is: " + ('ON' if on else 'off'))

    async def flush_junk(self):
        # clear Q
        try:
            while self._q.get_nowait():
                pass
        except:
            return

class AttachedQRScanner(QRScanner):
    def hardware_setup(self):
        print("Using real attached scanner!")
        pos = sys.argv.index('--scan')
        assert pos > 0
        fd = int(sys.argv[pos+1])
        self.serial = open(fd, 'wb')

        return 0

    def set_baud(self, br=None):
        # change serial port baud rate
        import termios
        attr = termios.tcgetattr(self.serial.fileno())
        # [4][5] are the baud rate
        was = int(attr[4])
        attr[4] = br         # assuming termios.B9600 = 9600 etc
        attr[5] = br
        if br is not None:
            termios.tcsetattr(self.serial.fileno(), 0, attr)
        return was

    async def flush_junk(self):
        # I am in lack of .any() member on my serial port
        while 1:
            try:
                junk = await asyncio.wait_for_ms(self.stream.read(0), 10)
                if not junk: break
                print("flush_junk: " + repr(junk))
            except asyncio.TimeoutError:
                break


# close door behind ourselves
if '--scan' in sys.argv:
    QRScanner = AttachedQRScanner
else:
    QRScanner = SimulatedQRScanner

# EOF
