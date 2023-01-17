# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# keyboard.py - Full keyboard found on the Q1 product.
#
import array, utime, pyb, sys
from ucollections import deque
from machine import Pin
from random import shuffle
from numpad import NumpadBase
from utils import call_later_ms

NUM_ROWS = const(6)
NUM_COLS = const(10)
SAMPLE_FREQ = const(60)         # (Hz) how fast to do each scan
NUM_SAMPLES = const(3)          # this many matching samples required for debounce
Q_CHECK_RATE = const(5)         # (ms) how fast to check event Q

# ascii key codes;
KEY_NFC = '\x0e'        # ctrl-N
KEY_QR = '\x11'         # ctrl-Q
KEY_TAB = '\t'          # tab = ctrl-I
KEY_SELECT = '\r'       # = CR
KEY_CANCEL = '\x1b'     # ESC = Cancel
KEY_LEFT = '\x15'           # ^U = left (incompatible)
KEY_UP = '\x0b'             # ^K = up on ADM-3A
KEY_RIGHT = '\x0c'          # ^L = right on ADM-3A
KEY_DOWN = '\x0a'           # ^J = LF = down on ADM-3A

# these meta keys might not be visible to higher layers:
KEY_LIGHT = '\x07'           # BELL = ^G
KEY_SHIFT = '\x01'
KEY_SPACE = ' '
KEY_SYMBOL = '\x01'
KEY_BS = '\x08'           # ^H = backspace

# (row, col) => keycode
# - unused spots are \0
# - these are unshifted values
DECODER = (KEY_NFC + KEY_QR + KEY_TAB 
            + KEY_LEFT + KEY_UP + KEY_DOWN + KEY_RIGHT + KEY_SELECT + KEY_CANCEL + '\0'
    + '1234567890'
    + 'qwertyuiop'
    + 'asdfghjkl`'
    + 'zxcvbnm,./'
    + KEY_LIGHT + KEY_SHIFT + KEY_SPACE + KEY_SYMBOL + KEY_BS + '\0\0\0\0\0')

class FullKeyboard(NumpadBase):

    def __init__(self):
        super().__init__()

        self.cols = [Pin('Q1_COL%d' % i, Pin.IN, pull=Pin.PULL_UP) for i in range(NUM_COLS)]
        self.rows = [Pin('Q1_ROW%d' % i, Pin.OUT_OD, value=0) for i in range(NUM_ROWS)]

        # We scan in random order, because Tempest.
        # - scanning only starts when something pressed
        # - complete scan is done before acting on what was measured
        self.scan_order = array.array('b', list(range(NUM_ROWS)))

        # after full scan, these flags are set for each key
        self.is_pressed = bytearray(NUM_ROWS * NUM_COLS)

        # internal to irq handler
        self._history = bytearray(NUM_ROWS * NUM_COLS)
        self._scan_count = 0

        self.waiting_for_any = True

        # time of last press
        self.lp_time = 0

        for c in self.cols:
            if c.pin() == 15: continue     # D15 conflicts with LCD_TEAR's irq pin
            c.irq(self.anypress_irq, Pin.IRQ_FALLING|Pin.IRQ_RISING)

        # power btn
        self.pwr_btn = Pin('PWR_BTN', Pin.IN, pull=Pin.PULL_UP)
        self.pwr_btn.irq(self.power_press, Pin.IRQ_FALLING)

        # LCD generates a nice 61Hz signal we can use
        self.lcd_tear = Pin('LCD_TEAR', Pin.IN)
        self.lcd_tear.irq(self._measure_irq, trigger=Pin.IRQ_RISING, hard=False)

        # ready to start 

    def power_press(self, pin):
        # power btn has been pressed, probably by accident but maybe not?
        # - enforce some hold-down time, but not much
        call_later_ms(250, self.power_press_held)

    async def power_press_held(self):
        if self.pwr_btn() == 1:
            # released in time: cancel
            return

        # shutdown now.
        import callgate
        callgate.show_logout(3)

    def anypress_irq(self, pin):
        # come here for any change, high or low
        if self.waiting_for_any:
            # something was pressed, but we don't know what.. start a scan+debounce
            self._start_scan()

    def start(self):
        # Begin scanning for events
        self._wait_any()

    def _wait_any(self):
        # wait for any press.
        #self.timer.deinit()
        self.waiting_for_any = True

        for r in self.rows:
            r.off()

    def _start_scan(self):
        # reset and re-start scanning keys
        self.lp_time = utime.ticks_ms()
        shuffle(self.scan_order)

        self._scan_count = 0
        self.waiting_for_any = False

    def _measure_irq(self, _timer):
        # CHALLENGE: Called at high rate, and cannot do memory alloc.
        # - sample all keys once, record any that are pressed
        if self.waiting_for_any:
            # do nothing in that mode
            return

        for i in range(NUM_ROWS):
            row = self.scan_order[i]

            for r in range(NUM_ROWS):
                self.rows[r].value(row != r)

            # sample the column values
            for c in range(NUM_COLS):
                if self.cols[c].value() == 0:
                    self._history[(row * NUM_COLS) + c] += 1

        self._scan_count += 1
        if self._scan_count != NUM_SAMPLES:
            return

        # collect results
        self._scan_count = 0

        # handle debounce, which happens in both directions: press and release
        # - all samples must be in agreement to count as either up or down
        for kn in range(NUM_ROWS * NUM_COLS):
            if self._history[kn] == NUM_SAMPLES:
                self.is_pressed[kn] = 1
            elif self._history[i] == 0:
                self.is_pressed[kn] = 0
            self._history[kn] = 0

        # we're done a full scan (mulitple times: NUM_SAMPLES)
        # - not trying to support multiple presses, just one
        for kn in range(NUM_ROWS * NUM_COLS):
            if self.is_pressed[kn]:
                # indicated key was found to be down and then back up
                key = DECODER[kn]
                if key != self.key_pressed:
                    print("KEY: event=%d => %c=0x%x" % (kn, key, ord(key)))
                    self._key_event(key)

                self.lp_time = utime.ticks_ms()

        none_active = (sum(self.is_pressed) == 0)
        if none_active:
            if self.key_pressed:
                self._key_event('')

            if utime.ticks_diff(utime.ticks_ms(), self.lp_time) > 250:
                # stop scanning now... nothing happening
                self._wait_any()
    
# EOF
