import sys, version
from uasyncio.core import get_event_loop
from uasyncio import StreamReader

NUM_ROWS = const(6)
NUM_COLS = const(10)

class Touch:

    # Misnomer: emulating a membrane numpad or qwerty keyboard, not a touch interface
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
            if version.has_qwerty:
                # NOTE: numpad # will be FullKeyboard instance

                # sends 2 keynums, might be few meta+specific keys
                # - pad with -1
                pressed = await s.read(5)

                if 0xfe in pressed:
                    # see PLUGGER in simulator.py
                    from sim_battery import sim_plug_toggler
                    sim_plug_toggler()
                    continue

                try:
                    new_presses = set(kn for kn in pressed if kn!=255 and not numpad.is_pressed[kn])
                except IndexError:
                    # some bugs bring us here
                    print("wrong kn: %r" % kn)
                    continue

                for kn in range(NUM_ROWS * NUM_COLS):
                    numpad.is_pressed[kn] = (0 if kn not in pressed else 1)

                # Q1 simulator sends keynumbers, from shared/charcodes.py
                numpad.process_chg_state(new_presses)
            else:
                # rx's any key that is pressed and now released
                key = await s.read(1)
                #print("Sim: %s" % key)
                if key == b'\0':
                    numpad.inject('')       # all up
                else:
                    numpad.inject(key.decode())

    def discharge(self):
        pass

    def start_sample(self, *a, **k):
        pass
