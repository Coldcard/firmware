# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ftux.py - First Time User Experience! A new ride at the waterpark.
#
import version, ckcc
from glob import settings
from ux import ux_show_story, the_ux
from actions import change_usb_disable

class FirstTimeUX:
    async def interact(self):
        # Help them enable the good stuff.
        # - they might have already enabled things

        await ux_show_story('''
Your COLDCARD has been configured for \
best security practises: 

- USB disabled
- NFC disabled
- VDisk disabled

You can change these under Settings > Hardware On/Off.''', title="Welcome!")

        if not ckcc.is_simulator():
            settings.set('du', 1)       # disable USB
            await change_usb_disable(1)

        #settings.set('nfc', 0)     # default already
        #settings.set('vidsk', 0)   # same as default

        # done
        the_ux.pop()

# EOF
