# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# touchpad.py - Numeric keypad. Touch button matrix. Mark 1 only.
#
import array, utime
from uasyncio.queues import Queue
from machine import Pin
from random import shuffle
from numpad import NumpadBase
import touch

_singleton = None

NUM_PINS = const(7)

# The critical "threshold" .. remember, values below this
# might be "light" touches or proximity. 
THRESHOLD = const(200)

class TouchNumpad(NumpadBase):

    def __init__(self, loop):
        super(TouchNumpad, self).__init__(loop)

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
        # - larger pulse prescale => more noise margin, MAYBE; but too slow to do own averaging
        #
        self.tsc = touch.Touch(channels=self.pins, caps=['CS0', 'CS1', 'CS2'],
                        handler=self.irq, float_unused=0,
                        CTPH=12, CTPL=12, pulse_prescale=4, max_count=16383)

        self.baseline = None
        self.levels = array.array('I', (0 for i in range(NUM_PINS)))
        self.prev_levels = array.array('I', (0 for i in range(NUM_PINS)))
        self.scan_pin = 0

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

        # must let lines discharge for 1ms
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

    def start(self):
        # Begin scanning for events
        self._disabled = False

        self.scan_idx = 0
        self.scan_pin = self.scan_order[0]

        # prime the irq pump
        self.tsc.start_sample(self.pins[self.scan_pin])

    def calc(self):
        # average history, apply threshold to know which are "down"
        if self.debug == 1:
            print('\x1b[H\x1b[2J\n')
            LABELS = [('col%d' % n) for n in range(3)] + [('row%d' % n) for n in range(4)]
        if self.debug == 2:
            from main import dis
            dis.clear()

        # should we remember this as a reference point (of no keys pressed)
        if self.trigger_baseline:
            self.baseline = array.array('I', self.prev_levels)
            self.trigger_baseline = False

            if 0:
                LABELS = [('col%d' % n) for n in range(3)] + [('row%d' % n) for n in range(4)]
                print("Baselines:")
                for idx in range(NUM_PINS):
                    print('%s: %5d' % (LABELS[idx], self.baseline[idx]))

            return

        pressed = set()
        diffs = array.array('I')

        for idx in range(NUM_PINS):
            # track a running average, using different weights depending on sensitivity mode
            if self.sensitivity == 0:       # "sensitive"
                avg = self.levels[idx]
            elif self.sensitivity == 1:     # "normal"
                avg = (self.prev_levels[idx] + self.levels[idx]) // 2
            elif self.sensitivity == 2:     # "less sensitive"
                avg = ((self.prev_levels[idx]*3) + self.levels[idx]) // 4
            elif self.sensitivity == 3:     # "med. sensitive"
                avg = ((self.prev_levels[idx]*2) + self.levels[idx]) // 3
            else:   #elif self.sensitivity == 4:     # more sensitive
                avg = int((self.prev_levels[idx]*0.25) + (self.levels[idx] * 0.75))

            self.prev_levels[idx] = avg

            if self.baseline:
                diff = self.baseline[idx] - avg
                diffs.append(diff)

                # the critical "threshold" .. remember, values below this are
                # might be "light" touches or proximity. 
                if diff > THRESHOLD:
                    pressed.add(idx)

                # handle baseline drift, in one direction at least
                if diff < 0:
                    self.baseline[idx] = avg

                if self.debug == 1:
                    print('%s: %5d   %4d   %d' % (LABELS[idx], avg, diff, idx in pressed))

                if self.debug == 2:
                    from main import dis
                    y = (idx * 6)+ 3

                    dx = 64 + int(diff/8)
                    dx = min(max(0, dx), 127)
                    dis.dis.pixel(dx, y+1, 1)
                    dis.dis.pixel(dx, y+2, 1)

                    dx = 64 + int(THRESHOLD/8)
                    dis.dis.pixel(dx, y, 1)
                    dis.dis.pixel(dx, y+3, 1)

                    dis.show()

        if max(diffs, default=0) < -10 or (len(pressed) > 4):
            print("auto recal")
            self.baseline = array.array('I', self.prev_levels)

        if self.debug == 1:
            print('\n')
            if diffs:
                print('min_diff = %5d / %5d / %5d' % (
                    min(diffs),
                    (sum(diffs) / len(diffs)),
                    max(diffs)
                ))

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

        sel._key_event(key)
    
# EOF
