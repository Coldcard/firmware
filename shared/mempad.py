# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# numpad.py - Numeric keypad. Touch button matrix.
#
import array, utime
from uasyncio.queues import Queue
from machine import Pin
from random import shuffle
from numpad import NumpadBase

_singleton = None

NUM_ROWS = const(4)
HISTORY_LEN = const(3)

class MembraneNumpad(NumpadBase):

    def __init__(self, loop):
        super(MembraneNumpad, self).__init__(loop)

        global _singleton
        assert not _singleton
        _singleton = self

        self.cols = [Pin(i, Pin.IN, pull=Pin.PULL_UP) 
                        for i in ('M2_COL0', 'M2_COL1', 'M2_COL2')]
        self.rows = [Pin(i, Pin.OUT_OD, value=0) 
                        for i in ('M2_ROW0', 'M2_ROW1', 'M2_ROW2', 'M2_ROW3')]

        # Scan in random order, because Tempest.
        # However, we only scan where there is a touch, and we mustn't
        # reveal which one by doing anything differently (in terms of scan).
        self.scan_order = list(range(NUM_ROWS)) * HISTORY_LEN
        shuffle(self.scan_order)
        self.scan_idx = 0

        self.history = []
        self.wait_any = True

        for c in self.cols:
            c.irq(self.irq_handler, Pin.IRQ_FALLING|Pin.IRQ_RISING)

        # ready to start 
        self.loop = loop

    def irq_handler(self, pin):
        # come here for any change, high or low
        if self.wait_any:
            # something was pressed, but we don't know what.. start a scan+debounce
            self._start_scan()

    def start(self):
        # Begin scanning for events
        self._disabled = False
        self._wait_any()

    def _wait_any(self):
        # wait for any press.
        for r in self.rows:
            r.off()
        self.wait_any = True

    def _start_scan(self):
        # reset and start a new scan
        if self._disabled: return

        self.history.clear()
        self.wait_any = False
        self.scan_idx = len(self.scan_order)-1
        self._scan_next()

    def _scan_next(self):
        # enable detection on one row
        active_row = self.scan_order[self.scan_idx]

        for r, pin in enumerate(self.rows):
            if r == active_row:
                pin.off()
            else:
                pin.on()

        # schedule an event for a little later
        self.loop.call_later_ms(20, self._measure)

    def _measure(self):

        # sample the column values (unroll for simple)
        if self.cols[0].value() == 0:
            col_press = 0
        elif self.cols[1].value() == 0:
            col_press = 1
        elif self.cols[2].value() == 0:
            col_press = 2
        else:
            col_press = -1

        if col_press != -1:
            # anything down?
            active_row = self.scan_order[self.scan_idx]
            key = self.DECODER[(active_row, col_press)]
            self.history.append(key)
            print('+ ' + key)

        if self.scan_idx:
            self.scan_idx -= 1
            self._scan_next()
            return

        # we're done a full scan (mulitple times: HISTORY_LEN)
        if not self.history:
            # all keys are up.
            print('+quiet')
            self._key_event('')

            # stop scanning for now
            self._wait_any()

        else:
            # perform debounce
            # - do nothing if abiguous or in transition.
            s = set(self.history)
            if len(s) == 1:
                self._key_event(self.history[0])
            else:
                print('bounce: ' + ' '.join(s))

            self._start_scan()
    
# EOF
