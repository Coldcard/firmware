# Replace QR Scanner module interface.
# TODO: support (optional) local real scanner over USB serial.
#
import os
import uasyncio as asyncio
from scanner import QRScanner
from queues import Queue

# unix/working/...
DATA_FILE = 'qrdata.txt'

class SimulatedQRScanner(QRScanner):
    def __init__(self):
        self.version = '4.20'

    async def _read_results(self, q):
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
            got = open(DATA_FILE, 'rt').read(8196).strip()
            q.put_nowait(got)

            orig_mtime = mtime
            
    async def scan_once(self):
        # returns a Q we append to as results come in
        q = Queue()

        print("Put QR data into file: work/%s" % DATA_FILE)

        task = asyncio.create_task(self._read_results(q))

        rv = await q.get()

        task.cancel()

        return rv

    async def wakeup(self):
        return

    async def goto_sleep(self):
        return

    async def torch_control(self, on):
        print("Torch is: " + ('ON' if on else 'off'))

# close door behind ourselves
QRScanner = SimulatedQRScanner

# EOF
