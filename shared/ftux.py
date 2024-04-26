# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ftux.py - First Time User Experience! A new ride at the waterpark.
#
import version, ckcc
from glob import settings
from ux import ux_show_story, the_ux
from actions import change_usb_disable

class FirstTimeUX:
    async def interact(self, title="Welcome!"):
        # Force USB to be disabled by default, but also warn/tell user
        # how to enable it, plus NFC and VirtDisk (already disabled by default)
        if settings.get('du', None) is None:

            if not ckcc.is_simulator():
                settings.set('du', 1)       # disable USB
                await change_usb_disable(1)

            #settings.set('nfc', 0)     # default already
            #settings.set('vidsk', 0)   # same as default

            await ux_show_story('''\
Your COLDCARD has been configured for \
best security practices: 

- USB disabled
- NFC disabled
- VirtDisk disabled

You can change these under Settings > Hardware On/Off.''', title=title)

        # done, clear UX
        the_ux.pop()

# EOF
