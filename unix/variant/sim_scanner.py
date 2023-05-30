# Replace QR Scanner module interface.
# TODO: support (optional) local real scanner over USB serial.
#
import os
import uasyncio as asyncio
from scanner import QRScanner

# unix/working/...
DATA_FILE = 'qrdata.txt'

class SimulatedQRScanner(QRScanner):
    def __init__(self):
        self.q = None

    def hw_scan(self):
        # trigger a scan
        pass

    async def _read_results(self):
        # be a task that reads incoming QR codes from scanner (already in operation)
        # - will be canceled when done/stopping
        try:
            _, orig_mtime, _ = os.stat(DATA_FILE)[-3:]
        except OSError:
            orig_mtime = None

        while 1:
            await asyncio.sleep_ms(250)

            try:
                _, mtime, _ = os.stat(DATA_FILE)[-3:]
            except OSError:
                mtime = None

            if mtime == orig_mtime:
                continue

            print("Got new QR scan data.")
            got = open(DATA_FILE, 'rb').read(8196)
            self.q.push(got)

            orig_mtime = mtime
            
    async def scan_start(self, test=15):
        # returns a Q we append to as results come in
        self.q = rv = Queue()

        self._scan_task = asyncio.create_task(self._read_results())

        return rv

    async def scan_stop(self):
        self._scan_task.cancel()
        self._scan_task = None
        self.q = None

    async def wakeup(self):
        return

    async def sleep(self):
        return

    async def tx(self, msg):
        return

    async def torch(self, on):
        print("Torch is: " + 'ON' if on else 'off')

# close door behind ourselves
QRScanner = SimulatedQRScanner

# EOF
