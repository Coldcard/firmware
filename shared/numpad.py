# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# numpad.py - Base class for numeric keypads. Touch or membrane matrix.
#
import utime, uasyncio
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

        self.debug = 0                # 0..2

        self.last_event_time = utime.ticks_ms()

    async def get(self):
        # Get keypad events. Single-character strings.
        key, _ = await self._changes.get()
        return key

    async def get_with_timestamp(self):
        # Get a keypad event and its debounced arrival time in microseconds.
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

    def _key_event(self, key):
        if key == self.key_pressed:
            return

        # annouce change
        self.key_pressed = key
        now = utime.ticks_us()

        if self._changes.full():
            # no space, but do a "all up" and the new event
            self._changes.get_nowait()
            self._changes.get_nowait()
            if key != '':
                self._changes.put_nowait(('', now))

        self._changes.put_nowait((key, now))

        self.last_event_time = utime.ticks_ms()

# EOF
