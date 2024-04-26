# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# use: 
#   from h import *

from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from callgate import enter_dfu as dfu

import uasyncio
arun = uasyncio.run
