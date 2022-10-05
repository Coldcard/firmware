# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Message signing.
#
import pytest, time, os
from pycoin.contrib.msg_signing import verify_message, parse_signed_message
from base64 import b64encode, b64decode
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
from constants import addr_fmt_names, msg_sign_unmap_addr_fmt

@pytest.mark.parametrize('msg', [ 'aZ', 'hello', 'abc def eght', "x"*140, 'a'*240])
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

    # check expected addr was used
    sk = addr_vs_path(addr, path, addr_fmt)

    if addr_fmt != AF_CLASSIC:
        # - pycoin can't do signature decode XXX
        return
    
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

    def doit(msg, subpath=None, addr_fmt=None, expect_fail=False):
        fname = 't-msgsign.txt'
        result_fname = 't-msgsign-signed.txt'

        # cleanup
        try: os.unlink(microsd_path(result_fname))
        except OSError: pass

        with open_microsd(fname, 'wt') as sd:
            sd.write(msg + '\n')
            if subpath is not None:
                sd.write(subpath + '\n')
            if addr_fmt is not None:
                sd.write(addr_fmt_names[addr_fmt] + '\n')

        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('File Management')
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
@pytest.mark.parametrize('path', [
        "m/84p/0'/22p",
        None,
        'm',
        "m/1/2",
        "m/1'/100'",
        'm/23H/22p',
    ])
@pytest.mark.parametrize('addr_fmt', [
        None ,
        AF_P2WPKH,
        AF_CLASSIC,
        AF_P2WPKH_P2SH,
    ])
def test_sign_msg_microsd_good(sign_on_microsd, msg, path, addr_vs_path, addr_fmt):

    if (path is None) and (addr_fmt is not None):
        # must give path if addr fmt is to be specified
        return

    # cases we expect to work
    sig, addr = sign_on_microsd(msg, path, addr_fmt)

    raw = b64decode(sig)
    assert 40 <= len(raw) <= 65

    if path is None:
        path = 'm'

    # check expected addr was used
    sk = addr_vs_path(addr, path, addr_fmt)

    if addr_fmt != AF_CLASSIC:
        # - pycoin can't do signature decode XXX
        return

    # verify signature
    assert verify_message(sk, sig, message=msg) == True

@pytest.fixture
def sign_using_nfc(goto_home, pick_menu_item, nfc_write_text, cap_story):
    def doit(body, expect_fail=True):
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Sign Message')
        nfc_write_text(body)
        time.sleep(0.5)
        if expect_fail:
            return cap_story()
        raise NotImplementedError

    return doit

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
@pytest.mark.parametrize('transport', ['sd', 'usb', 'nfc'])
def test_sign_msg_fails(dev, sign_on_microsd, msg, concern, no_file, transport, sign_using_nfc, path='m/12/34'):

    if transport == 'usb':
        with pytest.raises(CCProtoError) as ee:
            dev.send_recv(CCProtocolPacker.sign_message(msg.encode('ascii'), path), timeout=None)
        story = ee.value.args[0]
    elif transport == 'sd':
        try:
            story = sign_on_microsd(msg, path, expect_fail=True)
            assert story.startswith('Problem: ')
        except AssertionError as e:
            if no_file:
                assert ("No suitable files found" in str(e)) or story == 'NO-FILE'
                return
    elif transport == 'nfc':
        title, story = sign_using_nfc(msg, expect_fail=True)
        assert title == 'ERROR' or "Problem" in story
    else:
        raise ValueError(transport)

    assert concern in story

@pytest.mark.parametrize('msg,num_iter,expect', [ 
    ('Test2', 1, 'IHra0jSywF1TjIJ5uf7IDECae438cr4o3VmG6Ri7hYlDL+pUEXyUfwLwpiAfUQVqQFLgs6OaX0KsoydpuwRI71o='),
    ('Test', 2, 'IDgMx1ljPhLHlKUOwnO/jBIgK+K8n8mvDUDROzTgU8gOaPDMs+eYXJpNXXINUx5WpeV605p5uO6B3TzBVcvs478='),
    ('Test1', 3, 'IEt/v9K95YVFuRtRtWaabPVwWOFv1FSA/e874I8ABgYMbRyVvHhSwLFz0RZuO87ukxDd4TOsRdofQwMEA90LCgI='),
])
def test_low_R_cases(msg, num_iter, expect, dev, set_seed_words, use_mainnet, need_keypress):
    # Thanks to @craigraw of Sparrow for this test case, copied from:
    # <https://github.com/sparrowwallet/drongo/blob/master/src/test/java/com/sparrowwallet/drongo/crypto/ECKeyTest.java>

    set_seed_words('absent essay fox snake vast pumpkin height crouch silent bulb excuse razor')
    use_mainnet()
    path = "m/44'/0'/0'/0/0"            # first address, P2PKH
    addr_fmt = AF_CLASSIC

    #addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)
    #assert addr == '14JmU9a7SzieZNEtBnsZo688rt3mGrw6hr'

    msg = msg.encode('ascii')
    dev.send_recv(CCProtocolPacker.sign_message(msg, path, addr_fmt=addr_fmt), timeout=None)

    need_keypress('y')

    done = None
    while done == None:
        time.sleep(0.050)
        done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

    assert len(done) == 2, done
    got_addr, raw = done

    assert got_addr == '14JmU9a7SzieZNEtBnsZo688rt3mGrw6hr'
    assert 40 <= len(raw) <= 65

    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    if num_iter != 1:
        # I have gotten these cases to pass, but I didn't want to keep the code
        # that grinded for low R in message signing... Ok for txn signing, but
        # needless delay for message signing.
        raise pytest.xfail('no code')

    assert sig == expect

@pytest.mark.parametrize("body", [
    "coinkite\nm\np2wsh",  # invalid address format
    "coinkite\nm\np2sh-p2wsh",  # invalid address format
    "coinkite\nm\np2tr",  # invalid address format
    "coinkite\nm/0/0/0/0/0/0/0/0/0/0/0/0/0\np2pkh",  # invalid path
    "coinkite\nm/0/0/0/0/0/q/0/0/0\np2pkh",  # invalid path
    "coinkite    yes!\nm\np2pkh",  # invalid msg - too many spaces
    "c\nm\np2pkh",  # invalid msg - too short
    "coinkite \nm\np2pkh",  # invalid msg - trailing space
    " coinkite\nm\np2pkh",  # invalid msg - leading space
])
def test_nfc_msg_signing_invalid(body, goto_home, pick_menu_item, nfc_write_text, cap_story):
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Sign Message')
    nfc_write_text(body)
    time.sleep(0.5)
    title, story = cap_story()
    assert title == 'ERROR' or "Problem" in story

@pytest.mark.parametrize("msg", ["coinkite", "Coldcard Signing Device!", 200 * "a"])
@pytest.mark.parametrize("path", ["", "m/84'/0'/0'/300/0", "m/800'", "m/0/0/0/0/1/1/1"])
@pytest.mark.parametrize("str_addr_fmt", ["p2pkh", "", "p2wpkh", "p2wpkh-p2sh", "p2sh-p2wpkh"])
def test_nfc_msg_signing(msg, path, str_addr_fmt, nfc_write_text, nfc_read_text, pick_menu_item, goto_home, cap_story,
                         need_keypress, addr_vs_path):
    # import pdb;pdb.set_trace()
    for _ in range(5):
        # need to wait for ApproveMessageSign to be popped from ux stack
        try:
            goto_home()
            break
        except:
            time.sleep(0.5)

    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Sign Message')
    if str_addr_fmt != "":
        addr_fmt = msg_sign_unmap_addr_fmt[str_addr_fmt]
        body = "\n".join([msg, path, str_addr_fmt])
    else:
        addr_fmt = AF_CLASSIC
        body = "\n".join([msg, path])

    nfc_write_text(body)
    time.sleep(0.5)
    _, story = cap_story()
    assert "Ok to sign this?" in story
    assert msg in story
    assert path in story
    need_keypress("y")
    signed_msg = nfc_read_text()
    if "BITCOIN SIGNED MESSAGE" not in signed_msg:
        # missed it? again
        signed_msg = nfc_read_text()
    need_keypress("y")  # exit NFC animation
    pmsg, addr, sig = parse_signed_message(signed_msg)
    assert pmsg == msg
    sk = addr_vs_path(addr, path, addr_fmt)
    if addr_fmt == AF_CLASSIC:
        assert verify_message(addr, sig, message=msg) is True
        assert verify_message(sk, sig, message=msg) is True
    time.sleep(0.5)
    _, story = cap_story()
    assert "Press Y to share again" in story
    need_keypress("y")
    signed_msg_again = nfc_read_text()
    assert signed_msg == signed_msg_again
    need_keypress("x")  # exit NFC animation
    need_keypress("x")  # do not want to share again

# EOF
