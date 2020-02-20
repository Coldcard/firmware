# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# numpad.py - Base class for numeric keypads. Touch or membrane matrix.
#
import utime
from uasyncio.queues import Queue

class NumpadBase:

    KEYS = '0123456789xy'

    # this signals a need to stop user interaction and re-look at ux stack
    ABORT_KEY = '\xff'

    def __init__(self, loop):
        # once pressed, and released; keys show up in this queue
        self._changes = Queue(24)
        self.key_pressed = ''
        self._disabled = False

        self.debug = 0                # 0..2
        self.repeat_delay = 450       # (ms) time to wait before first key-repeat

        self.last_event_time = utime.ticks_ms()

    @property
    def disabled(self):
        return self._disabled

    async def get(self):
        # Get keypad events. Single-character strings.
        return await self._changes.get()

    def get_nowait(self):
        # Poll if anything ready: not async!
        return self._changes.get_nowait()

    def empty(self):
        return self._changes.empty()

    def capture_baseline(self):
        # call this at a time when we feel no keys are pressed (during boot up)
        pass

    def stop(self):
        # Stop scanning
        self._disabled = True

    def abort_ux(self):
        # pretend a key was pressed, in order to unblock things
        self.inject(self.ABORT_KEY)

    def inject(self, key):
        # fake a key press and release
        if not self._changes.full():
            self.key_pressed = ''
            self._changes.put_nowait(key)
            self._changes.put_nowait('')

    def _key_event(self, key):
        if key != self.key_pressed:
            # annouce change
            self.key_pressed = key

            if self._changes.full():
                # no space, but do a "all up" and the new event
                print('Q overflow')
                self._changes.get_nowait()
                self._changes.get_nowait()
                if key != '':
                    self._changes.put_nowait('')

            self._changes.put_nowait(key)

            self.last_event_time = utime.ticks_ms()
    
# EOF
