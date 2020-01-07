# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Message signing.
#
import pytest, time, os
from pycoin.key.BIP32Node import BIP32Node
from pycoin.contrib.msg_signing import verify_message
from base64 import b64encode, b64decode
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
from constants import simulator_fixed_xprv

@pytest.mark.parametrize('msg', [ 'aB', 'hello', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'", 'm/23H/22p'])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_sign_msg_good(dev, need_keypress, msg, path, addr_fmt, addr_vs_path):

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

    # check expected addr was used
    sk = addr_vs_path(addr, path, addr_fmt)
    
    # verify signature
    assert verify_message(sk, sig, message=msg.decode('ascii')) == True
    assert verify_message(addr, sig, message=msg.decode('ascii')) == True


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

@pytest.fixture
def sign_on_microsd(open_microsd, cap_story, pick_menu_item, goto_home, need_keypress, microsd_path):

    # sign a file on the microSD card

    def doit(msg, subpath=None, expect_fail=False):

        fname = 't-msgsign.txt'
        result_fname = 't-msgsign-signed.txt'

        # cleanup
        try: os.unlink(microsd_path(result_fname))
        except OSError: pass

        with open_microsd(fname, 'wt') as sd:
            sd.write(msg + '\n')
            if subpath is not None:
                sd.write(subpath + '\n')

        goto_home()
        pick_menu_item('Advanced')
        pick_menu_item('MicroSD Card')
        pick_menu_item('Sign Text File')

        time.sleep(.1)
        _, story = cap_story()
        assert 'Choose text file to be signed' in story
        need_keypress('y')
        time.sleep(.1)
            
        try:
            pick_menu_item(fname)
        except KeyError:
            if expect_fail:
                return 'NO-FILE'
            raise

        title, story = cap_story()
        if expect_fail:
            assert not story.startswith('Ok to sign this?')
            return story

        assert story.startswith('Ok to sign this?')

        assert msg in story
        assert 'Using the key associated' in story
        if not subpath:
            assert 'm =>' in story
        else:
            x_subpath = subpath.lower().replace('p', "'").replace('h', "'")
            assert ('%s =>' % x_subpath) in story

        need_keypress('y')

        # wait for it to finish
        for r in range(10):
            time.sleep(0.1)
            title, story = cap_story()
            if title == 'File Signed': break
        else:
            assert False, 'timed out'

        lines = [i.strip() for i in open_microsd(result_fname, 'rt').readlines()]

        assert lines[0] == '-----BEGIN BITCOIN SIGNED MESSAGE-----'
        assert lines[1:-4] == [msg]
        assert lines[-4] == '-----BEGIN SIGNATURE-----'
        addr = lines[-3]
        sig = lines[-2]
        assert lines[-1] == '-----END BITCOIN SIGNED MESSAGE-----'

        return sig, addr

    return doit

@pytest.mark.parametrize('msg', [ 'ab', 'hello', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path,addr_fmt', [
        ( "m/84p/0'/22p", AF_P2WPKH),
        (None, AF_CLASSIC),
        ( 'm', AF_CLASSIC),
        ( "m/1/2", AF_CLASSIC),
        ( "m/1'/100'", AF_CLASSIC),
        ( 'm/23H/22p', AF_CLASSIC),
    ])
def test_sign_msg_microsd_good(sign_on_microsd, msg, path, addr_vs_path, addr_fmt):

    # cases we expect to work
    sig, addr = sign_on_microsd(msg, path)

    raw = b64decode(sig)
    assert 40 <= len(raw) <= 65

    if addr_fmt != AF_CLASSIC:
        # TODO
        # - need bech32 decoder here
        # - pycoin can't do signature decode
        if addr_fmt & AFC_BECH32:
            assert '1' in addr
        return

    if path is None:
        path = 'm'

    # check expected addr was used
    sk = addr_vs_path(addr, path, addr_fmt)

    if addr_fmt == AF_P2WPKH:
        assert addr.startswith('tb1q')

    # verify signature
    assert verify_message(sk, sig, message=msg) == True

@pytest.mark.parametrize('msg,concern,no_file', [ 
    ('', 'too short', 0),         # zero length not supported
    ('a'*1000, 'too long', 1),   # too big, won't even be offered as a file
    ('a'*300, 'too long', 0),    # too big
    ('a'*241, 'too long', 0),    # too big
    ('hello%20sworld'%'', 'many spaces', 0),        # spaces
    ('hello%10sworld'%'', 'many spaces', 0),        # spaces
    ('hello%5sworld'%'', 'many spaces', 0),        # spaces
    ('test\ttest', "bad char: 0x09", 0),
    ])
@pytest.mark.parametrize('transport', ['sd', 'usb'])
def test_sign_msg_microsd_fails(dev, sign_on_microsd, msg, concern, no_file, transport, path='m/12/34'):

    if transport == 'usb':
        with pytest.raises(CCProtoError) as ee:
            dev.send_recv(CCProtocolPacker.sign_message(msg.encode('ascii'), path), timeout=None)
        story = ee.value.args[0]
    else:
        story = sign_on_microsd(msg, path, expect_fail=True)

        if no_file:
            assert story == 'NO-FILE'
            return
        assert story.startswith('Problem: ')

    assert concern in story

# EOF
