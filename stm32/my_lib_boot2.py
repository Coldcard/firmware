# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# This is my personal /lib/boot2.py which enables easier USB access.
#
print("/lib/boot2: runs")

# start the REPL very early
import uasyncio.core as asyncio
from usb import enable_usb

loop = asyncio.get_event_loop()
enable_usb(loop, True)

from dev_helper import usb_keypad_emu
loop.create_task(usb_keypad_emu())

print("/lib/boot2: done")
