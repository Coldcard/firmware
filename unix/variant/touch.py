import sys
from uasyncio.core import get_event_loop
from uasyncio import StreamReader

class Touch:

    # Misnomer: emulating a membrane now, not a touch interface
    # NOTE: doesn't do key repeat well

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
        from glob import numpad

        while 1:
            # rx's any key that is pressed and now released
            key = await s.read(1)
            print("Sim: %s" % key)
            if key == b'\0':
                await numpad._changes.put('')       # all up
            else:
                await numpad._changes.put(key.decode())

    def discharge(self):
        pass

    def start_sample(self, *a, **k):
        pass
