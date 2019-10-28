# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Message signing.
#
import pytest, time
from pycoin.key.BIP32Node import BIP32Node
from pycoin.contrib.msg_signing import verify_message
from base64 import b64encode
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *

@pytest.mark.parametrize('msg', [ 'a', 'hello', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'", 'm/23H/22p'])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_sign_msg_good(dev, need_keypress, master_xpub, msg, path, addr_fmt, addr_vs_path):

    msg = msg.encode('ascii')
    dev.send_recv(CCProtocolPacker.sign_message(msg, path, addr_fmt=addr_fmt), timeout=None)

    need_keypress('y')

    done = None
    while done == None:
        time.sleep(0.050)
        done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

    assert len(done) == 2, done
    
    addr, raw = done
    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    assert 40 <= len(raw) <= 65

    if addr_fmt != AF_CLASSIC:
        # TODO
        # - need bech32 decoder here
        # - pycoin can't do signature decode
        if addr_fmt & AFC_BECH32:
            assert '1' in addr
        return

    if "'" not in path and 'p' not in path:
        # check expected addr was used
        mk = BIP32Node.from_wallet_key(master_xpub)
        sk = mk.subkey_for_path(path[2:])

        addr_vs_path(addr, path, addr_fmt)
    
        # verify signature
        assert verify_message(sk, sig, message=msg.decode('ascii')) == True
    else:
        # just verify signature
        assert verify_message(addr, sig, message=msg.decode('ascii')) == True


@pytest.mark.parametrize('msg', [ 
    '',         # zero length not supported
    'a'*1000,   # too big
    'a'*300,    # too big
    'a'*241,    # too big
    'hello%20sworld'%'',        # spaces
    'hello%10sworld'%'',        # spaces
    'hello%5sworld'%'',        # spaces
    ])
def test_sign_msg_fails(dev, msg, path='m'):

    msg = msg.encode('ascii')

    with pytest.raises(CCProtoError):
        dev.send_recv(CCProtocolPacker.sign_message(msg, path), timeout=None)

def test_sign_msg_refused(dev, need_keypress, msg=b'testing 123', path='m'):
    # user can refuse to sign (cancel)

    dev.send_recv(CCProtocolPacker.sign_message(msg, path), timeout=None)

    need_keypress('x')

    with pytest.raises(CCUserRefused):
        done = None
        while done == None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)


@pytest.mark.parametrize('path,expect', [ 
    ('1/1hard/2', 'invalid characters'), 
    ('m/m/m/1/1hard/2', 'invalid characters'),
    ('m/', 'empty path component'),
    ('m/m', 'invalid characters'),
    ('34p/m', 'invalid characters'),
    ('234234hh', 'bad component'),
    ('23234pp', 'bad component'),
    ("23234p'", 'bad component'),
    ("m/1p/3455343434443534543345p", 'bad component'),
    ("m/\n34p", 'invalid characters'),
    ("2147483648/1/2/3", 'bad component'),    # 2**31 = 0x80000000 not allowed (because that's 0')
    ("214748364800/1/2/3", 'bad component'),
    ('/'.join('0' for i in range(13)), 'too deep'),
    ('///', 'empty path'),
    ])
def test_bad_paths(dev, path, expect):

    with pytest.raises(CCProtoError) as ee:
        dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    assert expect in str(ee)

# EOF
