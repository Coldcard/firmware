# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# numpad.py - Numeric keypad implemented with Membrane tech, not touch.
#
import array, utime, pyb
from uasyncio.queues import Queue
from machine import Pin
from random import shuffle
from numpad import NumpadBase

NUM_ROWS = const(4)
HISTORY_LEN = const(5)
SAMPLE_RATE = const(5)        # ms
NUM_SAMPLES = const(NUM_ROWS * HISTORY_LEN)

class MembraneNumpad(NumpadBase):

    def __init__(self, loop):
        super(MembraneNumpad, self).__init__(loop)

        # we can handle faster key-repeat start
        self.repeat_delay = 250

        # No idea how to pick a safe timer number.
        self.timer = pyb.Timer(7)

        self.cols = [Pin(i, Pin.IN, pull=Pin.PULL_UP) 
                        for i in ('M2_COL0', 'M2_COL1', 'M2_COL2')]
        self.rows = [Pin(i, Pin.OUT_OD, value=0) 
                        for i in ('M2_ROW0', 'M2_ROW1', 'M2_ROW2', 'M2_ROW3')]

        self.scan_order = array.array('i', list(range(NUM_ROWS)) * HISTORY_LEN)
        self.history = array.array('i', (-1 for i in range(NUM_SAMPLES)))

        # We scan in random order, because Tempest.
        # - scanning only starts when something pressed
        # - complete scan is done before acting on what was measured
        shuffle(self.scan_order)

        self.scan_idx = 0
        self.waiting_for_any = True

        for c in self.cols:
            c.irq(self.anypress_irq, Pin.IRQ_FALLING|Pin.IRQ_RISING)

        # ready to start 
        self.loop = loop

    def anypress_irq(self, pin):
        # come here for any change, high or low
        if self.waiting_for_any:
            # something was pressed, but we don't know what.. start a scan+debounce
            self._start_scan()

    def start(self):
        # Begin scanning for events
        self._disabled = False
        self._wait_any()

    def _wait_any(self):
        # wait for any press.
        self.timer.deinit()

        for r in self.rows:
            r.off()
        self.waiting_for_any = True

    def _start_scan(self):
        # reset and start a new scan
        if self._disabled: return

        self.waiting_for_any = False
        self.scan_idx = NUM_SAMPLES-1

        self._scan_next()
        self.timer.init(freq=1000//SAMPLE_RATE, callback=self._measure_irq)
        self.loop.call_later_ms(SAMPLE_RATE * (NUM_SAMPLES + 2), self._finish_scan)

    def _scan_next(self):
        # enable detection on one row
        active_row = self.scan_order[self.scan_idx]

        # unrolled because called during irq, no memory alloc
        self.rows[0].value(active_row != 0)
        self.rows[1].value(active_row != 1)
        self.rows[2].value(active_row != 2)
        self.rows[3].value(active_row != 3)

    def _measure_irq(self, _timer):
        # CAUTION: Called at high rate, and cannot do memory alloc.

        # sample the column values
        if self.cols[0].value() == 0:
            col_press = 0
        elif self.cols[1].value() == 0:
            col_press = 1
        elif self.cols[2].value() == 0:
            col_press = 2
        else:
            col_press = -1

        # track sample data
        self.history[self.scan_idx] = col_press

        # move to next column, or stop
        if self.scan_idx == 0:
            # we are done a full scan
            _timer.deinit()
        else:
            self.scan_idx -= 1
            self._scan_next()

    def _finish_scan(self):
        # we're done a full scan (mulitple times: HISTORY_LEN)
        down = set()

        for i in range(NUM_ROWS * HISTORY_LEN):
            # anything down?
            col_press = self.history[i]
            if col_press != -1:
                key = self.DECODER[(self.scan_order[i], col_press)]
                down.add(key)

        if not down:
            # all keys are up.
            self._key_event('')

            # stop scanning for now
            self._wait_any()

        else:
            # do nothing if abiguous or in transition (bounce).
            if len(down) == 1:
                self._key_event(down.pop())

            self._start_scan()
    
# EOF
