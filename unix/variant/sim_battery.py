# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_battery.py - Simulate Q specific code related to batteries.
#
import battery, sys

fake_voltage = 4.0 if ('--battery' in sys.argv) else 0

def mock_get_batt_level():
    return fake_voltage if fake_voltage != 0 else None

def sim_plug_toggler():
    # user clicked on simulator's plug, so show different voltages
    global fake_voltage

    # defined by battery.get_batt_threshold()
    levels = [0, 4.5, 4.0, 3.5, 2.9 ]

    fake_voltage = levels[(levels.index(fake_voltage) + 1) % len(levels)]

    battery.nbat_pin.simulate_irq()

battery.get_batt_level = mock_get_batt_level

# EOF
