# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# mempad.py - Numeric keypad implemented with membrane metal-dome, not touch.
#
import array, utime, pyb
from ucollections import deque
from machine import Pin
from random import shuffle
from numpad import NumpadBase
from utils import call_later_ms

NUM_ROWS = const(4)
NUM_COLS = const(3)         
SAMPLE_FREQ = const(60)         # (Hz) how fast to do each scan
NUM_SAMPLES = const(3)          # this many matching samples required for debounce
Q_CHECK_RATE = const(5)         # (ms) how fast to check event Q

# (row, col) => keycode
DECODER = 'y0x987654321'

class MembraneNumpad(NumpadBase):

    def __init__(self):
        super(MembraneNumpad, self).__init__()

        # No idea how to pick a safe timer number.
        self.timer = pyb.Timer(7)

        self.cols = [Pin(i, Pin.IN, pull=Pin.PULL_UP) 
                        for i in ('M2_COL0', 'M2_COL1', 'M2_COL2')]
        self.rows = [Pin(i, Pin.OUT_OD, value=0) 
                        for i in ('M2_ROW0', 'M2_ROW1', 'M2_ROW2', 'M2_ROW3')]


        # We scan in random order, because Tempest.
        # - scanning only starts when something pressed
        # - complete scan is done before acting on what was measured
        self.scan_order = array.array('b', list(range(NUM_ROWS)))

        # each full scan is pushed onto this, only last one kept if overflow
        self.scans = deque((), 50, 0)

        # have we given this specific key to higher layers yet?
        self._char_reported = set()

        # internal state for timer irq handler
        self._history = bytearray(NUM_ROWS * NUM_COLS)
        self._scan_count = 0
        self._cycle = 0
        self._finish_scan_active = False

        self.waiting_for_any = True

        # time of last press
        self.lp_time = 0

        for c in self.cols:
            c.irq(self.anypress_irq, Pin.IRQ_FALLING|Pin.IRQ_RISING)

        # ready to start 

    def anypress_irq(self, pin):
        # come here for any change on column inputs, high or low
        if self.waiting_for_any:
            # something was pressed, but we don't know what.. start a scan+debounce
            self._start_scan()

    def start(self):
        # begin scanning for events
        self._wait_any()

    def start_mash(self):
        super(MembraneNumpad, self).start_mash()
        self.timer.deinit()
        self._wait_any()
        for c in self.cols:
            c.irq(self._mash_press_irq, Pin.IRQ_FALLING, hard=True)
        self.timer.init(freq=SAMPLE_FREQ, callback=self._measure_irq)
        self._ensure_finish_scan()

    def stop_mash(self):
        super(MembraneNumpad, self).stop_mash()
        for c in self.cols:
            c.irq(self.anypress_irq, Pin.IRQ_FALLING|Pin.IRQ_RISING)

    def _ensure_finish_scan(self):
        if not self._finish_scan_active:
            self._finish_scan_active = True
            call_later_ms(Q_CHECK_RATE, self._finish_scan)

    def _wait_any(self):
        # wait for any press but stop continuously scanning for now
        if not self._mash_mode:
            self.timer.deinit()

        self._mash_press_timestamp = None
        self._scan_count = 0
        for i in range(NUM_ROWS * NUM_COLS):
            self._history[i] = 0

        if self._mash_mode:
            try:
                shuffle(self.scan_order)
            except OSError:
                pass

        for r in self.rows:
            r.off()

        self.waiting_for_any = True

    def _start_scan(self):
        # reset and re-start scanning keys
        self.waiting_for_any = False
        self.lp_time = utime.ticks_ms()
        try:
            shuffle(self.scan_order)
        except OSError:
            # An RNG fault may reduce scan-order randomization, but must not
            # leave the keypad disabled before the user can log in.
            pass

        self._scan_count = 0
        self.timer.init(freq=SAMPLE_FREQ, callback=self._measure_irq)
        self._ensure_finish_scan()

    def _measure_irq(self, _timer):
        # CHALLENGE: Called at high rate, and cannot do memory alloc.
        # - sample all keys once, record any that are pressed

        if self.waiting_for_any:
            if not self._mash_mode:
                # stop
                _timer.deinit()
                return
            if self._mash_press_timestamp is None:
                return

            # A hard column IRQ already captured the physical edge. Begin the
            # existing slow scan only to debounce and identify that key.
            self.waiting_for_any = False
            self.lp_time = utime.ticks_ms()
            self._scan_count = 0

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
            self._history[(row * NUM_COLS) + col] += 1

        self._scan_count += 1
        if self._scan_count == NUM_SAMPLES:
            self._scan_count = 0

            # handle debounce, which happens in both directions: press and release
            # - all samples must be in agreement to count as either up or down
            if sum(self._history) == 0:
                # all are up, and debounced as such
                self.scans.append(0xff)
            else:
                for i in range(NUM_ROWS * NUM_COLS):
                    if self._history[i] == NUM_SAMPLES:
                        # down
                        self.scans.append(i)

                    self._history[i] = 0

    async def _finish_scan(self):
        # we're done a full scan (mulitple times: NUM_SAMPLES)
        # - not trying to support multiple presses, just one
        while self.scans:
            event = self.scans.popleft()

            if event == 0xff:
                # all keys are now up
                if self._char_reported:
                    self._char_reported.clear()
                    self._key_event('')
            else:
                # indicated key was found to be down
                ch = DECODER[event]
                if self._mash_mode and self._mash_press_timestamp is None:
                    continue
                if ch not in self._char_reported:
                    self._char_reported.add(ch)
                    timestamp = self._mash_press_timestamp if self._mash_mode else None
                    self._key_event(ch, timestamp)
                    self._mash_press_timestamp = None

                    self.lp_time = utime.ticks_ms()

        if not self._char_reported:
            idle = utime.ticks_diff(utime.ticks_ms(), self.lp_time)
            if self._mash_mode:
                if (not self.waiting_for_any and
                        (self._mash_press_timestamp is None or idle > 250)):
                    # Release completed, or a raw edge failed to debounce.
                    self._wait_any()
            elif idle > 250:
                # stop scanning now... nothing happening
                self._finish_scan_active = False
                self._wait_any()
                return

        call_later_ms(Q_CHECK_RATE, self._finish_scan)
    
# EOF
