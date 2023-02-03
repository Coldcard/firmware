# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# quickly clear all miniscript wallets installed
from glob import settings
from ux import restore_menu

if settings.get('miniscript'):
    del settings.current['miniscript']
    settings.save()

    print("cleared miniscript")

restore_menu()