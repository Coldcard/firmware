# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# mempad.py - Numeric keypad implemented with membrane metal-dome, not touch.
#
import array, utime, pyb
from uasyncio.queues import Queue
from machine import Pin
from random import shuffle
from numpad import NumpadBase

NUM_ROWS = const(4)
NUM_COLS = const(3)
SAMPLE_RATE = const(5)          # ms
NUM_SAMPLES = const(10)         # this many matching samples required for debounce

class MembraneNumpad(NumpadBase):
    # (row, col) => keycode
    DECODER = 'y0x987654321'

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

        self.scan_order = array.array('b', list(range(NUM_ROWS)))
        self.history = bytearray(NUM_ROWS * NUM_COLS)

        # We scan in random order, because Tempest.
        # - scanning only starts when something pressed
        # - complete scan is done before acting on what was measured
        shuffle(self.scan_order)

        self.scan_count = 0
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

        assert self.scan_count == 0
        self.scan_count = NUM_SAMPLES-1
        self.history = bytearray(NUM_ROWS * NUM_COLS)
        self.timer.init(freq=1000//SAMPLE_RATE, callback=self._measure_irq)
        self.loop.call_later_ms(SAMPLE_RATE * (NUM_SAMPLES + 2), self._finish_scan)

    def _measure_irq(self, _timer):
        # CHALLENGE: Called at high rate, and cannot do memory alloc.
        # - sample all keys once, record any that are pressed

        if self.scan_count == NUM_SAMPLES:
            # First irq may be a runt of unknown length, so don't collect data 
            # until after first time called.
            pass
        else:
            for i in range(NUM_ROWS):
                row = self.scan_order[i]

                self.rows[0].value(row != 0)
                self.rows[1].value(row != 1)
                self.rows[2].value(row != 2)
                self.rows[3].value(row != 3)

                # sample the column values
                if self.cols[0].value() == 0:
                    col = 0
                elif self.cols[1].value() == 0:
                    col = 1
                elif self.cols[2].value() == 0:
                    col = 2
                else:
                    continue

                # track any press observed
                self.history[(row * NUM_COLS) + col] += 1

        # should we do that again in a bit?
        if self.scan_count == 0:
            # we are done a full scan
            _timer.deinit()
        else:
            self.scan_count -= 1

    def _finish_scan(self):
        # we're done a full scan (mulitple times: NUM_SAMPLES)
        # - not trying to support multiple presses, just one
        from main import dis
        from display import FontTiny

        assert self.scan_count == 0

        if sum(self.history) == 0:
            # all keys are 100% up.
            self._key_event('')

            # stop scanning for now
            self._wait_any()
            #print('=> all up')
            return

        #print(' '.join(str(i) for i in self.history), end='')

        # handle debounce, which happens in both directions: press and release
        # - all samples must be in agreement to count as either
        for rc, count in enumerate(self.history):
            key = self.DECODER[rc]

            if count == 0 and key == self.key_pressed:
                # key up
                self._key_event('')
                #print(' => %s UP' % key)
                break
            elif count == NUM_SAMPLES:
                self._key_event(key)
                #print(' => %s down' % key)
                break

        # do another scan
        self._start_scan()
    
# EOF
