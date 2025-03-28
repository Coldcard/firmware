# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# load up the simulator w/ indicated test master key in TPRV format.
#
import main, ngu
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from pincodes import pa
from glob import settings
from nvstore import SettingsObject
from stash import SecretStash, SensitiveValues
from utils import xfp2str, swab32

tn = chains.BitcoinTestnet

b32_version_pub  = 0x043587cf
b32_version_priv = 0x04358394

node = ngu.hdnode.HDNode()
v = node.deserialize(main.TPRV)
assert v == b32_version_priv
assert node

settings.current = sim_defaults
settings.set('chain', 'XTN')
settings.set('words', False)

pa.tmp_value = None
SettingsObject.master_sv_data = {}
SettingsObject.master_nvram_key = None

raw = SecretStash.encode(xprv=node)
pa.change(new_secret=raw)
pa.new_main_secret(raw)
settings.set('words', False)

assert settings.get('xfp', 0) == swab32(node.my_fp())

print("TESTING: New tprv in effect [%s]: %s" % (
        settings.get('xpub', 'MISSING'),
        xfp2str(settings.get('xfp', 0))))

