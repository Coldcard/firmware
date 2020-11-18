# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# quickly clear all multisig wallets installed
from main import settings
from ux import restore_menu

if settings.get('multisig'):
    del settings.current['multisig']
    settings.save()

    print("cleared multisigs")

restore_menu()
