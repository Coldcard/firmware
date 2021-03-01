# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# This is my personal /lib/boot2.py which enables easier USB access. For v4+ firmware.
#
print("/lib/boot2: runs")

# start the REPL very early
from usb import enable_usb      # very slow, noticable in boot sequence
enable_usb(True)

import uasyncio
from dev_helper import usb_keypad_emu
uasyncio.create_task(usb_keypad_emu())

print("/lib/boot2: done")
