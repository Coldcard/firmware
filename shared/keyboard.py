# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# keyboard.py - Full qwerty keyboard found on the Q1 product.
#
import array, utime, pyb, sys
import uasyncio
from machine import Pin
from random import shuffle
from numpad import NumpadBase
from utils import call_later_ms
from charcodes import *

SAMPLE_FREQ = const(60)         # (Hz) how fast to do each scan
NUM_SAMPLES = const(3)          # this many matching samples required for debounce

META_KEYS = { KEY_LAMP, KEY_SHIFT, KEY_SYMBOL }

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
        self._char_reported = set()

        # what meta keys are currently pressed 
        self.active_meta_keys = set()

        # internal to irq handler
        self._history = bytearray(NUM_ROWS * NUM_COLS)
        self._scan_count = 0

        self.waiting_for_any = True

        # time of last press
        self.lp_time = 0

        for c in self.cols:
            c.irq(self.anypress_irq, Pin.IRQ_FALLING|Pin.IRQ_RISING)

        # power btn
        self.pwr_btn = Pin('PWR_BTN', Pin.IN, pull=Pin.PULL_UP)
        self.pwr_btn.irq(self.power_press, Pin.IRQ_FALLING)

        # LCD generates a nice 61Hz signal we can use
        self.lcd_tear = Pin('LCD_TEAR', Pin.IN)
        self.lcd_tear.irq(self._measure_irq, trigger=Pin.IRQ_RISING, hard=False)

        # meta state
        self.torch_on = False
        self.caps_lock = False
        self.shift_down = False
        self.symbol_down = False

        # ready to start 

    def power_press(self, pin):
        # power btn has been pressed, probably by accident but maybe not?
        # - enforce some hold-down time, but not much
        call_later_ms(500, self.power_press_held)

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
        self.waiting_for_any = True

        for r in self.rows:
            r.off()

    def _start_scan(self):
        # reset and re-start scanning keys
        self.lp_time = utime.ticks_ms()
        shuffle(self.scan_order)

        self._scan_count = 0
        self.waiting_for_any = False

    def _measure_irq(self, _unused):
        # CHALLENGE: Called at high rate (61Hz), but can do memory alloc.
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
        new_presses = set()

        # handle debounce, which happens in both directions: press and release
        # - all samples must be in agreement to count as either up or down
        for kn in range(NUM_ROWS * NUM_COLS):
            if self._history[kn] == NUM_SAMPLES:
                self.is_pressed[kn] = 1
                new_presses.add(kn)
            elif self._history[i] == 0:
                self.is_pressed[kn] = 0
            self._history[kn] = 0

        self.process_chg_state(new_presses)

    def process_chg_state(self, new_presses):
        # we've done a full scan (mulitple times: NUM_SAMPLES)
        # - convert that into ascii-like events in a Q for rest of system
        # - during multiple presses, each reported once, then when "all up", another event
        shift_down = self.is_pressed[KEYNUM_SHIFT]
        symbol_down = self.is_pressed[KEYNUM_SYMBOL]
        status_chg = dict()

        if self.caps_lock:
            decoder = DECODER_CAPS
        elif symbol_down:
            decoder = DECODER_SYMBOL
        elif shift_down:
            decoder = DECODER_SHIFT
        else:
            decoder = DECODER

        for kn in new_presses:
            #assert self.is_pressed[kn]:
            if kn == KEYNUM_SHIFT:
                continue
            elif kn == KEYNUM_SYMBOL:
                continue
            elif kn == KEYNUM_LAMP:
                if not self.torch_on:
                    # handle light button right here and now
                    self.torch_on = True
                    from glob import SCAN
                    SCAN.torch_control_sync(True)
                continue

            # indicated key was found to be down and then back up
            # - now it is a character, not a key anymore
            ch = decoder[kn]
            if ch == '\0':
                # dead/unused key: do nothing - like SYM+D
                #print("KEYNUM %d is no-op (in this state)" % kn)
                continue

            if ch not in self._char_reported:
                #print("KEY: event=%d => %c=0x%x" % (kn, ch, ord(ch)))
                self._char_reported.add(ch)
                self._key_event(ch)

                self.lp_time = utime.ticks_ms()

        if self.torch_on and not self.is_pressed[KEYNUM_LAMP]:
            self.torch_on = False
            from glob import SCAN
            SCAN.torch_control_sync(False)

        # state change detect for SYM, SHIFT
        meta_chg = False
        if self.shift_down != shift_down:
            self.shift_down = shift_down
            status_chg['shift'] = int(self.shift_down)
            meta_chg = True
        if self.symbol_down != symbol_down:
            self.symbol_down = symbol_down
            status_chg['symbol'] = int(self.symbol_down)
            meta_chg = True

        if meta_chg and symbol_down and shift_down:
            # press SYM+SHIFT to toggle CAPS
            self.caps_lock = not self.caps_lock
            status_chg['caps'] = int(self.caps_lock)

        if status_chg:
            from glob import dis
            uasyncio.create_task(dis.async_draw_status(**status_chg))

        if self._char_reported:
            # Is any key still pressed right now, with the exception of shift/sym?
            # If "all up" then report that.
            any_non_meta_pressed = any(True for kn,dn in enumerate(self.is_pressed)
                                    if dn and kn not in {KEYNUM_SHIFT, KEYNUM_SYMBOL, KEYNUM_LAMP})

            if not any_non_meta_pressed:
                self._char_reported.clear()
                self._key_event('')

        if (utime.ticks_diff(utime.ticks_ms(), self.lp_time) > 250) and not any(self.is_pressed):
            # stop scanning now... nothing happening
            self._wait_any()
    
# EOF
