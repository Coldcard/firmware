# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# load up the simulator w/ indicated test master key
import main, ngu
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from pincodes import pa
from glob import settings
from stash import SecretStash, SensitiveValues
from utils import xfp2str, swab32

tn = chains.BitcoinTestnet

b32_version_pub  = 0x043587cf
b32_version_priv = 0x04358394

node = ngu.hdnode.HDNode()
v = node.deserialize(main.TPRV)
assert v == b32_version_priv
assert node

if settings.get('xfp') == swab32(node.my_fp()):
    print("right xfp already")

else:
    settings.current = sim_defaults
    settings.overrides.clear()
    settings.set('chain', 'XTN')

    raw = SecretStash.encode(xprv=node)
    pa.change(new_secret=raw)
    pa.new_main_secret(raw)

    print("New key in effect: %s" % settings.get('xpub', 'MISSING'))
    print("Fingerprint: %s" % xfp2str(settings.get('xfp', 0)))

    assert settings.get('xfp', 0) == swab32(node.my_fp())

