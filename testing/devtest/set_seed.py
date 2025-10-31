# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Load up the simulator w/ indicated list of seed words
#
from sim_settings import sim_defaults
import stash, chains
from pincodes import pa
from glob import settings
import stash
from seed import set_seed_value, PassphraseMenu
from utils import xfp2str
from actions import goto_top_menu
from nvstore import SettingsObject

tn = chains.BitcoinTestnet

stash.bip39_passphrase = ''
settings.current = sim_defaults

import main
pa.tmp_value = None
PassphraseMenu.pp_sofar = ''
SettingsObject.master_sv_data = {}
SettingsObject.master_nvram_key = None
set_seed_value(main.WORDS)
stash.SensitiveValues.clear_cache()

settings.set('chain', 'XTN')
settings.set('words', len(main.WORDS))
settings.set('terms_ok', True)
settings.set('idle_to', 0)

print("TESTING: New key in effect [%s]: %s..%s = %s" % (
    xfp2str(settings.get('xfp', 0)), main.WORDS[0], main.WORDS[-1],
    settings.get('xpub', 'MISSING')))

# impt: if going from xprv => seed words, main menu needs updating
goto_top_menu()

