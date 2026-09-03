# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

# Simulator normally powers up with this 'wallet'
simulator_fixed_tprv = "tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4"
simulator_fixed_tpub = "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh"

# same wallet but mainnet BTC
simulator_fixed_xprv = "xprv9s21ZrQH143K3i4kfV4tE2qAvhys9WDCpHJXKz2biqWkZwLKma1dzWaqin8CxCKPF3tX2fVRD9tBggJtxvdAxTpKfz8zRUoJZa3S7MtMgwy"
simulator_fixed_xpub = "xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7"

simulator_fixed_words = "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify"

simulator_fixed_xfp = 0x4369050f

simulator_serial_number = 'F1F1F1F1F1F1'

from ckcc_protocol.constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from ckcc_protocol.constants import AFC_WRAPPED, AFC_PUBKEY, AFC_SEGWIT, AFC_BECH32M, AFC_SCRIPT

unmap_addr_fmt = {
    'p2sh': AF_P2SH,
    'p2wsh': AF_P2WSH,
    'p2wsh-p2sh': AF_P2WSH_P2SH,
    'p2sh-p2wsh': AF_P2WSH_P2SH,
}

msg_sign_unmap_addr_fmt = {
    'p2pkh': AF_CLASSIC,
    'p2wpkh': AF_P2WPKH,
    'p2sh-p2wpkh': AF_P2WPKH_P2SH,
    'p2wpkh-p2sh': AF_P2WPKH_P2SH,
}

addr_fmt_names = {
    AF_CLASSIC: 'p2pkh',
    AF_P2SH: 'p2sh',
    AF_P2WPKH: 'p2wpkh',
    AF_P2WSH: 'p2wsh',
    AF_P2WPKH_P2SH: 'p2wpkh-p2sh',
    AF_P2WSH_P2SH: 'p2wsh-p2sh',
    AF_P2TR: "p2tr",
}
    

# all possible addr types, including multisig/scripts
ADDR_STYLES = ['p2wpkh', 'p2wsh', 'p2sh', 'p2pkh', 'p2wsh-p2sh', 'p2wpkh-p2sh']

# single-signer
ADDR_STYLES_SINGLE = ['p2wpkh', 'p2pkh', 'p2wpkh-p2sh']

# multi signer
ADDR_STYLES_MS = ['p2sh', 'p2wsh', 'p2wsh-p2sh']

# SIGHASH
SIGHASH_MAP = {
    "ALL": 1,
    "NONE": 2,
    "SINGLE": 3,
    "ALL|ANYONECANPAY": 1 | 0x80,
    "NONE|ANYONECANPAY": 2 | 0x80,
    "SINGLE|ANYONECANPAY": 3 | 0x80,
}

# Unified opt-in. Kept out of SIGHASH_MAP on purpose: a node without the
# deployment cannot produce or verify these, so folding them in would expand
# every matrix built from that map and fail those runs rather than skip them.
# Spelled exactly as bitcoind's SighashFromStr spells it, so the names can be
# handed straight to walletprocesspsbt for the co-signing side.
SIGHASH_MAP_UNIFIED = {
    "ALL|UNIFIED": 1 | 0x20,
    "NONE|UNIFIED": 2 | 0x20,
    "SINGLE|UNIFIED": 3 | 0x20,
    "ALL|ANYONECANPAY|UNIFIED": 1 | 0x80 | 0x20,
    "NONE|ANYONECANPAY|UNIFIED": 2 | 0x80 | 0x20,
    "SINGLE|ANYONECANPAY|UNIFIED": 3 | 0x80 | 0x20,
}

SIGHASH_MAP_ALL = {**SIGHASH_MAP, **SIGHASH_MAP_UNIFIED}

# The output type a hash type names, with the opt-in bit stripped. The opt-in
# selects a signature hash algorithm; it does not change what the signature
# covers, so policy and modifiable-flag checks compare on this.
def sh_base(name):
    # tests also pass raw ints for hash types that have no name
    if not isinstance(name, str):
        return name
    return name.replace("|UNIFIED", "")

# (2**31) - 1 --> max unhardened, but we handle hardened via h elsewhere
MAX_BIP32_IDX = 2147483647