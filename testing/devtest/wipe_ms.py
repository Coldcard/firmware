# quickly clear all multisig wallets installed
from main import settings

if settings.get('multisig'):
    del settings.current['multisig']
    settings.save()

    print("cleared multisigs")

