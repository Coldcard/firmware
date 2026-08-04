# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# numpad.py - Base class for numeric keypads. Touch or membrane matrix.
#
import utime, uasyncio
import ckcc
from queues import Queue

class NumpadBase:

    KEYS = '0123456789xy'

    # this signals a need to stop user interaction and re-look at ux stack
    ABORT_KEY = '\xff'

    def __init__(self):
        # Once pressed and released, keys show up in this queue. Timestamp at
        # the event source so consumers are not measuring their own UX delays.
        self._changes = Queue(64)
        self.key_pressed = ''         # internal to ABC, should not be used by subclasses
        self._mash_mode = False
        self._mash_press_timestamp = None

        self.debug = 0                # 0..2

        self.last_event_time = utime.ticks_ms()

    async def get(self):
        # Get keypad events. Single-character strings.
        key, _ = await self._changes.get()
        return key

    async def get_with_timestamp(self):
        # Get an event and its source timestamp (raw edge during key mashing).
        return await self._changes.get()

    def get_nowait(self):
        # Poll if anything ready: not async!
        key, _ = self._changes.get_nowait()
        return key

    def empty(self):
        return self._changes.empty()

    def abort_ux(self):
        # pretend a key was pressed, in order to unblock things
        self.inject(self.ABORT_KEY)

    def inject(self, key):
        # fake a key press and release
        if self._changes.qsize() <= self._changes.maxsize - 2:
            self.key_pressed = ''
            self._changes.put_nowait((key, utime.ticks_us()))
            self._changes.put_nowait(('', utime.ticks_us()))

    def clear_pressed(self):
        # clear any key that is down right now, but don't generate
        # a key-up event for it either
        self.key_pressed = ''

    def start_mash(self):
        # Subclasses arrange for _mash_press_irq to be called as a hard IRQ.
        self._mash_press_timestamp = None
        self._mash_mode = True

    def stop_mash(self):
        self._mash_mode = False
        self._mash_press_timestamp = None

    def mash_ticks(self):
        # Timestamp for mash entropy: CPU cycle counter (DWT CYCCNT, ~8.33ns
        # at 120MHz) via utime.ticks_cpu(), which auto-enables the DWT the
        # first time and masks to 30 bits like the other utime ticks. It wraps
        # in about 8.95s; ticks_diff is unambiguous for gaps under about 4.47s,
        # well above normal mash intervals. It always returns a small int, so
        # this is safe inside the hard IRQ below. The unix simulator's
        # ticks_cpu is a constant zero, so fall back to microseconds there.
        if ckcc.is_simulator():
            return utime.ticks_us()
        return utime.ticks_cpu()

    def _mash_press_irq(self, _pin):
        # Hard IRQ: no allocation. Latch only the first edge until debounce
        # either accepts the press or rearms after an all-up state.
        if (self._mash_mode and self.waiting_for_any and
                self._mash_press_timestamp is None):
            self._mash_press_timestamp = self.mash_ticks()

    def _key_event(self, key, timestamp=None):
        if key == self.key_pressed:
            return

        # annouce change
        self.key_pressed = key
        now = utime.ticks_us() if timestamp is None else timestamp

        if self._changes.full():
            # no space, but do a "all up" and the new event
            self._changes.get_nowait()
            self._changes.get_nowait()
            if key != '':
                self._changes.put_nowait(('', now))

        self._changes.put_nowait((key, now))

        self.last_event_time = utime.ticks_ms()

# EOF
