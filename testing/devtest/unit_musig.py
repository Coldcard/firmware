# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import chains, ngu
from glob import settings
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from desc_utils import musig_synthetic_node
from descriptor import Descriptor

settings.set("chain", "BTC")
chain = chains.get_chain("BTC")

# BIP-328 test vectors https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki
bip_328_test_vectors = [
    [
        ["03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
         "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"],
        "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",

    ],
    [
        ["02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
         "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
         "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"],
        "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k"
    ],
    [
        ["02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
         "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
         "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
         "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"],
        "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ"
    ],
]

for musig_keys, aggregate_key, synthetic_xpub in bip_328_test_vectors:
    keyagg_cache = ngu.secp256k1.MusigKeyAggCache()
    keys = []
    for k in musig_keys:
        keys.append(a2b_hex(k))

    secp_keys = []
    for k in keys:
        secp_keys.append(ngu.secp256k1.pubkey(k))

    # aggregate without sorting (last arg False)
    ngu.secp256k1.musig_pubkey_agg(secp_keys, keyagg_cache, False)
    agg_pubkey = keyagg_cache.agg_pubkey().to_bytes()
    agg_pubkey_target = a2b_hex(aggregate_key)
    assert agg_pubkey == agg_pubkey_target
    node = musig_synthetic_node(agg_pubkey)
    assert chain.serialize_public(node) == synthetic_xpub

# EOF