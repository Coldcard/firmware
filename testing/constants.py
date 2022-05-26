# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

SIM_PATH = '/tmp/ckcc-simulator.sock'

# Simulator normally powers up with this 'wallet'
simulator_fixed_xprv = "tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4"

simulator_fixed_xpub = "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh"

simulator_fixed_words = "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify"

simulator_fixed_xfp = 0x4369050f

simulator_serial_number = 'F1F1F1F1F1F1'

from ckcc_protocol.constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH

unmap_addr_fmt = {
    'p2sh': AF_P2SH,
    'p2wsh': AF_P2WSH,
    'p2wsh-p2sh': AF_P2WSH_P2SH,
    'p2sh-p2wsh': AF_P2WSH_P2SH,
}

# all possible addr types, including multisig/scripts
ADDR_STYLES = ['p2wpkh', 'p2wsh', 'p2sh', 'p2pkh', 'p2wsh-p2sh', 'p2wpkh-p2sh']

# single-signer
ADDR_STYLES_SINGLE = ['p2wpkh', 'p2pkh', 'p2wpkh-p2sh']

# multi signer
ADDR_STYLES_MS = ['p2sh', 'p2wsh', 'p2wsh-p2sh']
