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
        # once pressed, and released; keys show up in this queue
        self._changes = Queue(64)
        self.key_pressed = ''         # internal to ABC, should not be used by subclasses

        self.debug = 0                # 0..2

        self.last_event_time = utime.ticks_ms()

    async def get(self):
        # Get keypad events. Single-character strings.
        return await self._changes.get()

    def get_nowait(self):
        # Poll if anything ready: not async!
        return self._changes.get_nowait()

    def empty(self):
        return self._changes.empty()

    def abort_ux(self):
        # pretend a key was pressed, in order to unblock things
        self.inject(self.ABORT_KEY)

    def inject(self, key):
        # fake a key press and release
        if not self._changes.full():
            self.key_pressed = ''
            self._changes.put_nowait(key)
            self._changes.put_nowait('')

    def clear_pressed(self):
        # clear any key that is down right now, but don't generate
        # a key-up event for it either
        self.key_pressed = ''

    def _key_event(self, key):
        if key == self.key_pressed:
            return

        # annouce change
        self.key_pressed = key

        if self._changes.full():
            # no space, but do a "all up" and the new event
            self._changes.get_nowait()
            self._changes.get_nowait()
            if key != '':
                self._changes.put_nowait('')

        self._changes.put_nowait(key)

        self.last_event_time = utime.ticks_ms()

# EOF
