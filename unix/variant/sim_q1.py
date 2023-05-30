# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_q14.py - Simulate Q1 specific code, not needed on other devices.
#
# - shared/q1.py calls mk4.init0 so no need to replace that
#
import q1

q1.setup_adc = lambda: None

def mock_get_batt_level():
    return 3.69

q1.get_batt_level = mock_get_batt_level

# EOF
