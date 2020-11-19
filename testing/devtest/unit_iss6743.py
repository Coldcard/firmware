# check Upub... SLIP132 generation
#
from h import a2b_hex, b2a_hex
from chains import BitcoinTestnet
from stash import SensitiveValues
from public_constants import AF_P2WSH_P2SH

with SensitiveValues() as sv:
    node = sv.derive_path("m/48'/1'/0'/1'")
    RV.write(BitcoinTestnet.serialize_public(node, AF_P2WSH_P2SH))


