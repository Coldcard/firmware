# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# glob.py
#
# - simple module w/ handle for larger objects/singletons
# - used to be "from main import dis" and so on

# the display
dis = None

# the numpad
numpad = None

# global ptr to HSM policy, if any (supported on Mk3+ only)
hsm_active = None

# setup by main.py, expected to always be present
settings = None

# PSRAM
PSRAM = None

# Virtual Disk
VD = None

# NFC interface (Mk4, can be disabled)
NFC = None

# QR scanner (Q1 only)
SCAN = None

# Miniscript descriptor cache
# mapping from unique miniscript wallet name to Descriptor object
# cache size = 1
DESC_CACHE = {}

# EOF
