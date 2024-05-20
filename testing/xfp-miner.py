#!/usr/bin/env python
#
# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Search for an XFP collision. Needs to be much faster.
#
import os, hmac, hashlib
from pycoin.key.BIP32Node import BIP32Node
from pycoin.serialize import b2h_rev, h2b_rev
from pycoin.encoding import public_pair_to_hash160_sec
from pycoin import ecdsa

def search(target_xfp):
    k = BIP32Node.from_hwif("tprv8ZgxMBicQKsPeXJHL3vPPgTAEqQ5P2FD9qDeCQT4Cp1EMY5QkwMPWFxHdxHrxZhhcVRJ2m7BNWTz9Xre68y7mX5vCdMJ5qXMUfnrZ2si2X4")

    pid = os.getpid()
    target_xfp = h2b_rev(target_xfp)

    # test by going -33 here.
    #sec_exp = k._secret_exponent - 33
    sec_exp = k._secret_exponent + (pid * int(1e40))
    
    i = 0
    last_xfp = None
    while 1:
        i += 1
        sec_exp += 1

        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, sec_exp)

        xfp = public_pair_to_hash160_sec(public_pair, compressed=True)[:4]

        if i <= 5:
            # checking code (slow)
            b = BIP32Node(netcode='BTC', chain_code=bytes(32), secret_exponent=sec_exp)
            chk = b.fingerprint()
            assert b._secret_exponent == sec_exp
            assert xfp == chk, (xfp,chk)

        assert xfp != last_xfp, 'repeat xfp!'
        last_xfp = xfp

        if xfp == target_xfp:
            print(f"\n\nFOUND: sec_exp = {sec_exp}\n")
            b = BIP32Node(netcode='BTC', chain_code=bytes(32), secret_exponent=sec_exp)
            chk = b.fingerprint()
            assert b._secret_exponent == sec_exp
            assert xfp == chk, (xfp,chk)
            print(b.hwif(), end='\n\n')
            return

        if not (i % 27):
            print('  %6d %9d' % (pid, i), end='\r')

if __name__ == '__main__':
    search('4369050f')

# EOF
