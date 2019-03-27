# load up the simulator w/ indicated list of seed words
import tcc, main
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from main import settings, pa
import stash
from seed import set_seed_value

tn = chains.BitcoinTestnet

if 1:
    stash.bip39_passphrase = ''
    settings.current = sim_defaults
    settings.overrides.clear()
    settings.set('chain', 'XTN')

    set_seed_value(main.WORDS)

    print("New key in effect: %s" % settings.get('xpub', 'MISSING'))
    print("Fingerprint: 0x%08x" % settings.get('xfp', 0))

