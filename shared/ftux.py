# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ftux.py - First Time User Experience! A new ride at the waterpark.
#
import version
from glob import settings
from ux import ux_show_story, the_ux, ux_dramatic_pause
from actions import change_nfc_enable, change_virtdisk_enable, change_usb_disable

COMMON = '''\
\n
You can change this later under Settings > Hardware On/Off.'''

class FirstTimeUX:
    async def interact(self):
        # Help them enable the good stuff.
        # - they might have already enabled things
        # - some features not on mk3

        if version.has_nfc and not settings.get('nfc', 0):
            msg = '''Enable NFC/Tap?\n\n\
Lets you Tap your mobile phone on the COLDCARD and \
transfer data easily via NFC.''' + COMMON
            ch = await ux_show_story(msg)
            if ch == 'y':
                settings.set('nfc', 1)
                await change_nfc_enable(1)
                await ux_dramatic_pause('Enabled.', 1)
                
        # Disabled for now, because limited audience and
        # extra barrier to "just getting started"
        if 0:       #  version.has_psram and not settings.get('vidsk', 0):
            msg = '''Enable USB Drive?\n\n\
Connect your COLDCARD directly as a USB flash drive \
to your phone or desktop. You will be able to drag-n-drop or \
save PSBT files like other drives/volumes.''' + COMMON
            ch = await ux_show_story(msg)
            if ch == 'y':
                # put them into full-auto mode: 2
                settings.set('vidsk', 2)
                await change_virtdisk_enable(2)
                await ux_dramatic_pause('Enabled.', 1)
                
        if not settings.get('vidsk', 0) and not settings.get('du', 0):
            msg = '''Disable USB port?\n\n\
If you intend to operate in Air-Gap mode, where this COLDCARD \
is never connected to anything but power, then this will disable the USB port.''' + COMMON
            ch = await ux_show_story(msg)

            if ch == 'y':
                settings.set('du', 1)
                await change_usb_disable(1)
                await ux_dramatic_pause('Disabled.', 1)

        # done
        the_ux.pop()

# EOF
