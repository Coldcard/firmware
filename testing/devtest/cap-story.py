# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import sim_display

if sim_display.story:
    RV.write('\0'.join(sim_display.story))
    sim_display.story = None
else:
    RV.write('\0')

