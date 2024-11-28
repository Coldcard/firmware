# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Message signing.
#
import pytest, time, os, itertools, hashlib
from bip32 import BIP32Node
from msg import verify_message, RFC_SIGNATURE_TEMPLATE, sign_message, parse_signed_message
from base64 import b64encode, b64decode
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
from constants import addr_fmt_names, msg_sign_unmap_addr_fmt


@pytest.mark.parametrize('msg', [ 'aZ', 'hello', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'", 'm/23h/22h'])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_sign_msg_good(dev, press_select, msg, path, addr_fmt, addr_vs_path):

    msg = msg.encode('ascii')
    dev.send_recv(CCProtocolPacker.sign_message(msg, path, addr_fmt=addr_fmt), timeout=None)

    press_select()

    done = None
    while done == None:
        time.sleep(0.050)
        done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

    assert len(done) == 2, done
    
    addr, raw = done
    sig = str(b64encode(raw), 'ascii').replace('\n', '')

    assert 40 <= len(raw) <= 65

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)
    assert verify_message(addr, sig, msg.decode("ascii")) is True


def test_sign_msg_refused(dev, press_cancel):
    # user can refuse to sign (cancel)

    msg = b'testing 123'
    path = 'm'
    dev.send_recv(CCProtocolPacker.sign_message(msg, path), timeout=None)

    press_cancel()

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
    ("m/\n34p", 'must be ascii printable'),
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
def sign_on_microsd(open_microsd, cap_story, pick_menu_item, goto_home,
                    press_select, microsd_path):

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
            x_subpath = subpath.lower().replace("'", "h")
            assert ('%s =>' % x_subpath) in story

        press_select()

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
        assert lines[-4] == '-----BEGIN BITCOIN SIGNATURE-----'
        addr = lines[-3]
        sig = lines[-2]
        assert lines[-1] == '-----END BITCOIN SIGNATURE-----'

        return sig, addr

    return doit

@pytest.mark.parametrize('msg', [ 'ab', 'hello', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path', [
        "m/84'/0'/22'",
        None,
        'm',
        "m/1/2",
        "m/1'/100'",
        'm/23h/22h',
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
    addr_vs_path(addr, path, addr_fmt)
    assert verify_message(addr, sig, msg) is True


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
    ('test\ttest', "must be ascii printable", 0),
    ('testêtest', "must be ascii printable", 0),
])
@pytest.mark.parametrize('transport', ['sd', 'usb', 'nfc'])
def test_sign_msg_fails(dev, sign_on_microsd, msg, concern, no_file, transport, sign_using_nfc, path='m/12/34'):

    if transport == 'usb':
        with pytest.raises(CCProtoError) as ee:
            try:
                encoded_msg = msg.encode('ascii')
            except UnicodeEncodeError:
                encoded_msg = msg.encode()
            dev.send_recv(CCProtocolPacker.sign_message(encoded_msg, path), timeout=None)
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
def test_low_R_cases(msg, num_iter, expect, dev, set_seed_words, use_mainnet,
                     press_select):
    # Thanks to @craigraw of Sparrow for this test case, copied from:
    # <https://github.com/sparrowwallet/drongo/blob/master/src/test/java/com/sparrowwallet/drongo/crypto/ECKeyTest.java>

    set_seed_words('absent essay fox snake vast pumpkin height crouch silent bulb excuse razor')
    use_mainnet()
    path = "m/44h/0h/0h/0/0"            # first address, P2PKH
    addr_fmt = AF_CLASSIC

    #addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)
    #assert addr == '14JmU9a7SzieZNEtBnsZo688rt3mGrw6hr'

    msg = msg.encode('ascii')
    dev.send_recv(CCProtocolPacker.sign_message(msg, path, addr_fmt=addr_fmt), timeout=None)

    press_select()

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
@pytest.mark.parametrize("path", ["", "m/84'/0'/0'/300/0", "m/800h/0h", "m/0/0/0/0/1/1/1"])
@pytest.mark.parametrize("str_addr_fmt", ["p2pkh", "", "p2wpkh", "p2wpkh-p2sh", "p2sh-p2wpkh"])
def test_nfc_msg_signing(msg, path, str_addr_fmt, nfc_write_text, nfc_read_text, pick_menu_item,
                         goto_home, cap_story, press_select, press_cancel, addr_vs_path, OK):

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
    assert path.replace("'", "h") in story
    press_select()
    signed_msg = nfc_read_text()
    if "BITCOIN SIGNED MESSAGE" not in signed_msg:
        # missed it? again
        signed_msg = nfc_read_text()
    press_select()  # exit NFC animation
    pmsg, addr, sig = parse_signed_message(signed_msg)
    assert pmsg == msg
    addr_vs_path(addr, path, addr_fmt)
    assert verify_message(addr, sig, msg) is True
    time.sleep(0.5)
    _, story = cap_story()
    assert f"Press {OK} to share again" in story
    press_select()
    signed_msg_again = nfc_read_text()
    assert signed_msg == signed_msg_again
    press_cancel()  # exit NFC animation
    press_cancel()  # do not want to share again

@pytest.fixture
def verify_armored_signature(pick_menu_item, nfc_write_text, press_select,
                             cap_story, goto_home):
    def doit(way, fname=None, signed_msg=None):
        goto_home()
        pick_menu_item('Advanced/Tools')
        if way == "nfc":
            pick_menu_item('NFC Tools')
        else:
            pick_menu_item('File Management')

        pick_menu_item('Verify Sig File'),
        if way == "nfc":
            nfc_write_text(signed_msg)
        else:
            time.sleep(.1)
            pick_menu_item(fname)

        time.sleep(0.3)
        title, story = cap_story()
        return title, story
    return doit

@pytest.mark.bitcoind
@pytest.mark.parametrize("chain", ["XRT", "BTC", "XTN"])
@pytest.mark.parametrize("way", ("sd", "nfc"))
@pytest.mark.parametrize("addr_fmt", ["p2pkh", "p2sh-p2wpkh", "p2wpkh"])
@pytest.mark.parametrize("path", ("m/1'", "m/3h/2h/1h", "m/1000'/100'/10'/1"))
@pytest.mark.parametrize("msg", ("coldcard", 240 * "a"))
def test_verify_signature_file(way, addr_fmt, path, msg, sign_on_microsd, goto_home, pick_menu_item,
                               cap_story, bitcoind, microsd_path, nfc_write_text,
                               verify_armored_signature, chain, settings_set):
    settings_set("chain", chain)
    sig, addr = sign_on_microsd(msg, path, msg_sign_unmap_addr_fmt[addr_fmt])
    fname = 't-msgsign-signed.txt'
    should = RFC_SIGNATURE_TEMPLATE.format(addr=addr, sig=sig, msg=msg)
    with open(microsd_path(fname), "r") as f:
        got = f.read()
    assert should == got
    title, story = verify_armored_signature(way, fname, should)
    assert title == "CORRECT"
    assert "Good signature" in story
    assert addr in story
    if (addr_fmt == "p2pkh") and (chain != "BTC"):
        res = bitcoind.rpc.verifymessage(addr, sig, msg)
        assert res is True

@pytest.mark.parametrize("way", ("sd", "nfc"))
@pytest.mark.parametrize("addr_sig", list(itertools.product(
    ["mwhrUneshkXh8yUw2L2T16UYCoF3ouy4L2",
     "2MudcM4zWNf2rsR1RxvPaMgk5EssH7TXTH8",
     "tb1qkxgmh66fdthecudx042feulz3ymzkyuf7gma0x"],
    ["H3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=",
     "I3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=",
     "J3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0="]
)))
def test_verify_signature_file_header_warning(way, addr_sig, microsd_path, verify_armored_signature,
                                              cap_story):
    warning = "Specified address format does not match signature header byte format."
    text = "Correctly signed, but not by this Coldcard"
    fname = "warn-signed.sig"
    addr, sig = addr_sig
    tmplt = RFC_SIGNATURE_TEMPLATE.format(addr=addr, sig=sig, msg="aaaaaaaaaaaaaaaaaa")
    if way != "nfc":
        with open(microsd_path(fname), "w") as f:
            f.write(tmplt)
    title, story = verify_armored_signature(way, fname, tmplt)
    assert title == "CORRECT"
    if (addr[0] + sig[0]) not in ("mH", "2I", "tJ"):  # not in correct pair
        assert text in story
        assert warning in story

@pytest.mark.parametrize("way", ("sd", "nfc"))
@pytest.mark.parametrize("addr_sig", [
    # bad signature - signature not base64
    ("tb1qk3vdwdewzqkmagakdxfga3nrqgxnpw74h4w5p4", "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$", 0),
    ("tb1qk3vdwdewzqkmagakdxfga3nrqgxnpw74h4w5p4", "fsdfsfsd97887989s7dfs8d7f8s7d8f7sd8f78sddgf8fg8*^&#^$@&dgfgdfgdfgdfgdfgdf#N&^%@$%N(@#==", 0),
    # bad signature - signature from different secret
    ("tb1qk3vdwdewzqkmagakdxfga3nrqgxnpw74h4w5p4", "KPxCN2edt9w5ukd0feOlFS6PJjsKwm6ii/erZErKDIApIxjHqxBzoDvVqcTX0mtecNTGCkJPhxjRKCjNtdnTAp0=", 3),
    # bad signature length
    ("mwxYMLpcbLjBdtbVdb1kKxHiR4rcAzqPxR", "H3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4", 2),
    ("mwxYMLpcbLjBdtbVdb1kKxHiR4rcAzqPxR", "H3l5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eQ==", 2),
    # p2tr
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "KPxCN2edt9w5ukd0feOlFS6PJjsKwm6ii/erZErKDIApIxjHqxBzoDvVqcTX0mtecNTGCkJPhxjRKCjNtdnTAp0=", 1),
    # p2wsh
    ("bc1q2c8pym4m755pq4n4shu2wgzr7s58pygz8x6pg0mj0l6netq8am8qw69kss", "KPxCN2edt9w5ukd0feOlFS6PJjsKwm6ii/erZErKDIApIxjHqxBzoDvVqcTX0mtecNTGCkJPhxjRKCjNtdnTAp0=", 1),
])
def test_verify_signature_file_fail(way, addr_sig, microsd_path, cap_story, goto_home, nfc_write_text,
                                    pick_menu_item, verify_armored_signature):
    fname = "fail-signed.txt"
    addr, sig, err_no = addr_sig

    error_map = {
        0: "Parsing signature failed",
        1: "Invalid address format - must be one of p2pkh, p2sh-p2wpkh, or p2wpkh.",
        2: "Parsing signature failed - invalid encoding.",
        3: "Invalid signature for message."
    }
    tmplt = RFC_SIGNATURE_TEMPLATE.format(msg="aaaaaaaaa", addr=addr, sig=sig)

    try:
        os.unlink(microsd_path(fname))
    except OSError:
        pass

    with open(microsd_path(fname), "wt") as f:
        f.write(tmplt)

    title, story = verify_armored_signature(way, fname, tmplt)
    assert title == "ERROR"
    assert error_map[err_no] in story


@pytest.mark.parametrize("binary", [True, False])
def test_verify_signature_file_digest_prob(binary, microsd_path, cap_story, pick_menu_item,
                                           need_keypress, goto_home, press_select, press_cancel):

    fpattern = "to_sign"
    if binary:
        suffix = ".pdf"
        mode = "wb"
        contents = bytes(100)
        orig_digest = hashlib.sha256(contents).digest().hex()
    else:
        suffix = ".txt"
        mode = "w"
        contents = "0" * 100
        orig_digest = hashlib.sha256(contents.encode()).digest().hex()

    fname = fpattern + suffix
    sig_name = fpattern + ".sig"
    fpath = microsd_path(fname)
    with open(fpath, mode) as f:
        f.write(contents)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("List Files")
    time.sleep(.1)
    pick_menu_item(fname)
    need_keypress("4")  # create detached sig
    press_select()
    press_cancel()
    pick_menu_item("Verify Sig File")
    time.sleep(.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "CORRECT"
    assert "Good signature" in story
    press_select()  # back in File Management

    # modify contents of the file
    with open(fpath, mode) as f:
        mod_contents = contents + contents
        f.write(mod_contents)

    mod_digest = hashlib.sha256(mod_contents if binary else mod_contents.encode()).digest().hex()
    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "ERROR"
    assert "Good signature" in story # sig is still correct
    assert ("'%s' has wrong contents" % fname) in story
    assert ("Got:\n%s" % orig_digest) in story
    assert ("Expected:\n%s" % mod_digest) in story
    press_select()  # back in File Management

    # remove file
    os.remove(fpath)
    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "WARNING"
    assert "Good signature" in story # sig is still correct
    assert ("'%s' is not present" % fname) in story
    assert 'Contents verification not possible' in story
    press_select()  # back in File Management


@pytest.mark.parametrize("f_num", [2, 10, 20])
def test_verify_signature_file_digest_prob_multi(f_num, microsd_path, cap_story, pick_menu_item,
                                                 press_select, goto_home):
    files = []
    msg = ""
    for i in range(f_num):
        fpattern = "to_sign_%d" % i
        even = i % 2 == 0
        mode = "wb" if even else "w"
        suffix = ".pdf" if even else ".txt"
        fname = fpattern + suffix
        fpath = microsd_path(fname)
        contents = ("a%s" % i) * 50
        contents_encoded = contents.encode()
        digest = hashlib.sha256(contents_encoded).digest().hex()
        msg += "%s  %s\n" % (digest, fname)
        c = contents_encoded if even else contents
        with open(fpath, mode) as f:
            f.write(c)
        files.append((fname, digest, fpath, mode, c))

    wallet = BIP32Node.from_master_secret(os.urandom(32))
    addr = wallet.address()
    sk = bytes(wallet.node.private_key)
    sig = sign_message(sk, msg.strip().encode())
    armored = RFC_SIGNATURE_TEMPLATE.format(addr=addr, sig=sig, msg=msg)
    sig_name = "sigs.sig"
    with open(microsd_path(sig_name), "w") as f:
        f.write(armored)

    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("File Management")
    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "CORRECT"
    assert "Good signature" in story
    press_select()  # back in File Management

    # change contents of 0th file
    fname, orig_digest, fpath, _, _ = files[0]
    with open(fpath, "w") as f:
        new_contetns = "changed"
        mod_digest = hashlib.sha256(new_contetns.encode()).digest().hex()
        f.write(new_contetns)

    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "ERROR"
    assert "Good signature" in story # sig is still correct
    assert ("'%s' has wrong contents" % fname) in story
    assert ("Got:\n%s" % orig_digest) in story
    assert ("Expected:\n%s" % mod_digest) in story
    press_select()  # back in File Management

    # change contents of 1st file remove 0th file
    # both warnings must be visible
    fname0, _, fpath, _, _ = files[0]
    os.remove(fpath)
    fname1, orig_digest, fpath, _, _ = files[1]
    with open(fpath, "w") as f:
        new_contetns = "changed5555"
        mod_digest = hashlib.sha256(new_contetns.encode()).digest().hex()
        f.write(new_contetns)

    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "ERROR"
    assert "Good signature" in story # sig is still correct
    assert ("'%s' has wrong contents" % fname1) in story
    assert ("Got:\n%s" % orig_digest) in story
    assert ("Expected:\n%s" % mod_digest) in story
    assert ("'%s' is not present" % fname0) in story
    assert 'Contents verification not possible' in story
    press_select()  # back in File Management

    # remove 1st file too
    os.remove(fpath)
    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "WARNING"
    assert "Good signature" in story  # sig is still correct
    warn_msg = "Files:\n" + "\n".join("> %s" % fname for fname in (fname0, fname1))
    assert warn_msg in story
    assert 'Contents verification not possible' in story
    press_select()  # back in File Management

    # reboult valid signed files
    for tup in files:
        _, _, fpath, mode, conts = tup
        with open(fpath, mode) as f:
            f.write(conts)

    pick_menu_item("Verify Sig File")
    time.sleep(0.1)
    pick_menu_item(sig_name)
    time.sleep(0.1)
    title, story = cap_story()
    assert title == "CORRECT"
    assert "Good signature" in story
    press_select()  # back in File Management

@pytest.mark.parametrize("way", ("sd", "nfc"))
@pytest.mark.parametrize("truncation_len", (0, 1))
def test_verify_signature_file_truncated(way, microsd_path, cap_story, verify_armored_signature,
                                         truncation_len):
    # test: handle missing leading dash (at least)
    prob_file = '-----BEGIN BITCOIN SIGNED MESSAGE-----\nfb9b0c78e60d57434ad0914a075e9fcb7cfe81ba9cad9cbfa1207b3bc5fbdf98  n4Boam6gCNq281bNAd3MqETpExMNPzCi8z.txt\n-----BEGIN BITCOIN SIGNATURE-----\nn4Boam6gCNq281bNAd3MqETpExMNPzCi8z\nIIITr0zBmC65ZSn+2RFvQCegpfq07TxRuGVkggh+ehL3chgEBmcCDH5D5z6INvCQ7PrHLIWkGEw1JSMdbiBKRX4=\n-----END BITCOIN SIGNATURE-----'[truncation_len:]

    fname = 'filename.txt'
    if way != "nfc":
        with open(microsd_path(fname), "w") as f:
            f.write(prob_file)

    title, story = verify_armored_signature(way, fname, prob_file)
    if not truncation_len:
        # warning for SD as file is not present on filesystem
        # correct for NFC as it does not care (digest_check=False)
        assert title == ("CORRECT" if way == 'nfc' else 'WARNING')
    else:
        assert title == "FAILURE"
        assert "Armor text MUST be surrounded by exactly five (5) dashes" in story
        assert "auth.py" in story

# EOF
