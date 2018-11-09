# load up the simulator w/ indicated test master key
import tcc, main
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from main import settings, pa
from stash import SecretStash, SensitiveValues

tn = chains.BitcoinTestnet

b32_version_pub  = 0x043587cf
b32_version_priv = 0x04358394

node = tcc.bip32.deserialize(main.TPRV, b32_version_pub, b32_version_priv)
assert node

if settings.get('xfp') == node.my_fingerprint():
    print("right xfp already")

else:
    settings.current = sim_defaults
    settings.set('chain', 'XTN')

    raw = SecretStash.encode(xprv=node)
    pa.change(new_secret=raw)
    pa.new_main_secret(raw)

    print("New key in effect: %s" % settings.get('xpub', 'MISSING'))
    print("Fingerprint: 0x%08x" % settings.get('xfp', 0))

    assert settings.get('xfp', 0) == node.my_fingerprint()

