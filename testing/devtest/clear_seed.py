# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# quickly main wipe seed; don't install anything new
from glob import numpad, dis
from pincodes import pa
from glob import settings
from pincodes import AE_SECRET_LEN, PA_IS_BLANK
from sim_settings import sim_defaults

if not pa.is_secret_blank():
    # clear settings associated with this key, since it will be no more
    settings.current = dict(sim_defaults)
    settings.overrides.clear()

    # save a blank secret (all zeros is a special case, detected by bootloader)
    dis.fullscreen('Wipe Seed!')
    nv = bytes(AE_SECRET_LEN)
    pa.change(new_secret=nv)

    rv = pa.setup(pa.pin)
    pa.login()

    assert pa.is_secret_blank()

# reset top menu and go there
from actions import goto_top_menu
goto_top_menu()

numpad.abort_ux()
