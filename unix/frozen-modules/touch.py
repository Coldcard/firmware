import sys
from uasyncio.core import get_event_loop
from uasyncio import StreamReader

class Touch:

    # emulate modtouch.c but with the simulator

    # XXX doesn't do key repeat well

    def __init__(self, *a, **kw):

        fileno = int(sys.argv[2])
        if fileno == -1: return

        loop = get_event_loop()
        loop.create_task(self.worker())

        self.pipe = open(fileno, 'rb')

    async def worker(self):
        # use a pipe to the simulator.

        s = StreamReader(self.pipe)

        # hack!
        from main import numpad

        while 1:
            ln = await s.readline()

            key = ln[:-1].decode()
            #numpad.key_pressed = key if key else ''
            await numpad._changes.put(key)

    def discharge(self):
        pass

    def start_sample(self, *a, **k):
        pass
