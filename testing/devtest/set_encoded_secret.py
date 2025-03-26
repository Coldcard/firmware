# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# load up the simulator w/ indicated encoded secret. could be xprv/words/etc.
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from pincodes import pa
from glob import settings
from stash import SecretStash, SensitiveValues
from utils import xfp2str

settings.current = dict(sim_defaults)

import main
raw = main.ENCODED_SECRET
pa.change(new_secret=raw)
pa.new_main_secret(raw)

print("New key in effect (encoded): %s" % settings.get('xpub', 'MISSING'))
print(".. w/ XFP= %s" % xfp2str(settings.get('xfp', 0)))

