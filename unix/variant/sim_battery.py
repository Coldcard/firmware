# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_battery.py - Simulate Q specific code related to batteries.
#
import battery, sys

battery.setup_battery = lambda: None

battery.setup_adc = lambda: None

def mock_get_batt_level():
    if '--plugged' in sys.argv:
        return None
    return 3.3

battery.get_batt_level = mock_get_batt_level

# EOF
