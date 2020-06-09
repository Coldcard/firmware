# load up the simulator w/ indicated encoded secret. could be xprv/words/etc.
import tcc, main
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from main import settings, pa
from stash import SecretStash, SensitiveValues
from utils import xfp2str

settings.current = sim_defaults
settings.overrides.clear()

raw = main.ENCODED_SECRET
pa.change(new_secret=raw)
pa.new_main_secret(raw)

print("New key in effect: %s" % settings.get('xpub', 'MISSING'))
print("Fingerprint: %s" % xfp2str(settings.get('xfp', 0)))

