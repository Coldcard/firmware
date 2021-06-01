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

# PSRAM (on Mk4 only)
PSRAM = None

# setup by main.py, expected to always be present
settings = None

# EOF
