# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

SIM_PATH = '/tmp/ckcc-simulator.sock'

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
    "p2tr": AF_P2TR,
}

msg_sign_unmap_addr_fmt = {
    'p2tr': AF_P2TR,  # not supported for msg signign tho
    'p2pkh': AF_CLASSIC,
    'p2wpkh': AF_P2WPKH,
    'p2sh-p2wpkh': AF_P2WPKH_P2SH,
    'p2wpkh-p2sh': AF_P2WPKH_P2SH,
}

addr_fmt_names = {
    AF_P2TR: 'p2tr',
    AF_CLASSIC: 'p2pkh',
    AF_P2SH: 'p2sh',
    AF_P2WPKH: 'p2wpkh',
    AF_P2WSH: 'p2wsh',
    AF_P2WPKH_P2SH: 'p2wpkh-p2sh',
    AF_P2WSH_P2SH: 'p2wsh-p2sh',
}
    

# all possible addr types, including multisig/scripts
ADDR_STYLES = ['p2wpkh', 'p2wsh', 'p2sh', 'p2pkh', 'p2wsh-p2sh', 'p2wpkh-p2sh', 'p2tr']

# single-signer
ADDR_STYLES_SINGLE = ['p2wpkh', 'p2pkh', 'p2wpkh-p2sh', 'p2tr']

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

# (2**31) - 1 --> max unhardened, but we handle hardened via h elsewhere
MAX_BIP32_IDX = 2147483647