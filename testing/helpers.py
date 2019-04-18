# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# stuff I need sometimes
from io import BytesIO
from binascii import b2a_hex
from decimal import Decimal

def B2A(s):
    return str(b2a_hex(s), 'ascii')
    
def U2SAT(v):
    return int(v * Decimal('1E8'))

# use like this:
#
#       with into_hex() as a:
#           a.write('sdlkfjsdflkj')
#
# ... will print hex of whatever was streamed.
#
class into_hex(BytesIO):
    def __exit__(self, *a):
        print('hex: %s' % str(b2a_hex(self.getvalue()), 'ascii'))
        return super().__exit__(*a)

'''
    >>> from binascii import *
    >>> from helpers import into_hex
    >>> from pycoin.tx.Tx import Tx
    >>> t = Tx.from_hex('010000....')
    >>> with into_hex() as fd:
    >>>     t.txs_out[0].stream(fd)
'''

def dump_txos(hx, out_num=0):
    from binascii import b2a_hex
    from helpers import into_hex
    from pycoin.tx.Tx import Tx

    t = Tx.from_hex(hx)
    with into_hex() as fd:
        t.txs_out[out_num].stream(fd)

    print('hash160: %s' % b2a_hex(t.txs_out[out_num].hash160()))

    return t

# EOF
