# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# numpad.py - Numeric keypad. Touch button matrix.
#
import array, utime
from uasyncio.queues import Queue
from machine import Pin
from random import shuffle
import touch

_singleton = None

NUM_PINS = const(7)

# the critical "threshold" .. remember, values below this are
# might be "light" touches or proximity. 
THRESHOLD = const(170)

class Numpad:

    KEYS = '0123456789xy'


    # (row, col) => keycode
    DECODER = {
            (3,2): '1',
            (3,1): '2',
            (3,0): '3',

            (2,2): '4',
            (2,1): '5',
            (2,0): '6',

            (1,2): '7',
            (1,1): '8',
            (1,0): '9',

            (0,2): 'x',
            (0,1): '0',
            (0,0): 'y',
        }

    #ENCODER = dict((v, k) for k,v in DECODER.items())

    # this signals a need to stop user interaction and re-look at ux stack
    ABORT_KEY = '\xff'

    def __init__(self, loop):
        # once pressed, and released; keys show up in this queue
        self._changes = Queue(24)
        self.key_pressed = ''
        self._disabled = False

        # hook needed for IRQ
        global _singleton
        assert not _singleton
        _singleton = self

        self.cols = [Pin(i) for i in ('COL0', 'COL1', 'COL2')]
        self.rows = [Pin(i) for i in ('ROW0', 'ROW1', 'ROW2', 'ROW3')]
        self.pins = self.cols + self.rows

        # Lots of tuning here:
        # - higher CTPH (high pulse length) helps w/ sensitivity and reliability
        # - decrease prescale to speed up acq, but to a point.
        # - CTPH+CTPL has big impact on overal sample time
        #
        self.tsc = touch.Touch(channels=self.pins, caps=['CS0', 'CS1', 'CS2'],
                        handler=self.irq, float_unused=0,
                        CTPH=2, CTPL=2, pulse_prescale=8, max_count=16383)

        self.debug = 0          # or 1 or 2
        self.baseline = None
        self.count = 0
        self.levels = array.array('I', (0 for i in range(NUM_PINS)))
        self.scan_pin = 0

        self.last_event_time = utime.ticks_ms()

        self.trigger_baseline = False

        # Scan in random order, because tempest.
        # But Tempest? Scan order, when we scan completely, everytime,
        # doesn't reveal anything, and the difference between touch
        # vs no touch is a few millivolts anyway... but harmless?
        self.scan_order = list(range(7))
        shuffle(self.scan_order)

        # begin scanning sequence
        self.loop = loop
        self.start()

    @property
    def disabled(self):
        return self._disabled

    async def get(self):
        # Get keypad events. Single-character strings.
        return await self._changes.get()

    def get_nowait(self):
        # Poll if anything ready: not async!
        return self._changes.get_nowait()

    def empty(self):
        return self._changes.empty()

    def capture_baseline(self):
        # call this at a time when we feel no keys are pressed (during boot up)
        self.trigger_baseline = True

    @staticmethod
    def irq(tsc):
        # done sampling a Row or Column; store result and continue scan
        self = _singleton
        assert tsc == self.tsc

        val = tsc.finished()
        if val == 0:
            # serious hardware fault? How to report it?
            # also seeing as noise signal when microsd runs
            print("maxcount on %r" % self.scan_pin)
        else:
            self.levels[self.scan_pin] = val

        # must let lines dischange for 1ms
        self.tsc.discharge()

        # do next step, after 1ms delay
        self.loop.call_later_ms(1, self.irq_step2)

    def irq_step2(self):
        # Sample next pin / maybe look at results.
        if self._disabled:
            return
    
        # move to next pin
        self.scan_idx += 1
        if self.scan_idx == NUM_PINS:
            self.scan_idx = 0

            # been around once now; we have some data
            self.calc()

        self.scan_pin = self.scan_order[self.scan_idx]

        # start the next scan
        self.tsc.start_sample(self.pins[self.scan_pin])

    def stop(self):
        # Stop scanning
        self._disabled = True

    def start(self):
        # Begin scanning for events
        self._disabled = False

        self.scan_idx = 0
        self.scan_pin = self.scan_order[0]

        # prime the irq pump
        self.tsc.start_sample(self.pins[self.scan_pin])


    def abort_ux(self):
        # pretend a key was pressed, in order to unblock things
        self.inject(self.ABORT_KEY)

    def inject(self, key):
        # fake a key press and release
        if not self._changes.full():
            self.key_pressed = ''
            self._changes.put_nowait(key)
            self._changes.put_nowait('')

    def calc(self):
        # average history, apply threshold to know which are "down"
        if self.debug == 1:
            print('\x1b[H\x1b[2J\n')
            LABELS = [('col%d' % n) for n in range(3)] + [('row%d' % n) for n in range(4)]
        if self.debug == 2:
            from main import dis
            dis.clear()

        pressed = set()
        now = []
        diffs = []
        for idx in range(NUM_PINS):
            avg = self.levels[idx]      # not an average anymore
            now.append(avg)

            if self.baseline:
                diff = self.baseline[idx] - avg

                # the critical "threshold" .. remember, values below this are
                # might be "light" touches or proximity. 
                if diff > THRESHOLD:
                    pressed.add(idx)

                if self.debug == 1:
                    print('%s: %5d   %4d   %d' % (LABELS[idx], avg, diff, idx in pressed))
                    diffs.append(diff)

                if self.debug == 2:
                    from main import dis
                    y = (idx * 6)+ 3

                    if 0:
                        x = int((avg * 128) / 16384.)
                        bx = int((self.baseline[idx] * 128) / 16384.)

                        for j in range(4):
                            dis.dis.line(0, y+j, 128, y+j, 0)

                        dis.dis.pixel(x, y, 1)
                        dis.dis.pixel(bx, y+1, 1)

                    dx = 64 + int(diff/8)
                    dx = min(max(0, dx), 127)
                    dis.dis.pixel(dx, y+2, 1)
                    dis.dis.pixel(dx, y+3, 1)

                    if idx == 0:
                        dx = 64 + int(THRESHOLD/8)
                        dis.dis.vline(dx, 60, 64, 1)

                    dis.show()

        if self.debug == 1:
            print('\n')
            if diffs:
                print('min_diff = %d' % min(diffs))
                print('avg_diff = %d' % (sum(diffs) / len(diffs)))

        # should we remember this as a reference point (of no keys pressed)
        if self.trigger_baseline:
            self.baseline = now.copy()
            self.trigger_baseline = False
            pressed.clear()

        if self.debug == 2: return

        # Consider only single-pressed here; we can detect
        # many 2-key combo's but no plan to support that so they
        # are probably noise from that PoV.
        col_down = [i for i in range(3) if i in pressed]
        row_down = [i-3 for i in range(3, 7) if i in pressed]

        if len(col_down) == 1 and len(row_down) == 1:
            # determine what key
            key = self.DECODER[(row_down[0], col_down[0])]
        else:
            # not sure, or all up
            key = ''

        if key != self.key_pressed:
            # annouce change
            self.key_pressed = key

            if self._changes.full():
                # no space, but do a "all up" and the new event
                print('numpad Q overflow')
                self._changes.get_nowait()
                self._changes.get_nowait()
                if key != '':
                    self._changes.put_nowait('')

            self._changes.put_nowait(key)

            self.last_event_time = utime.ticks_ms()


    
# EOF
