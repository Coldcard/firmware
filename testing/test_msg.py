# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Message signing.
#
import pytest, time, os, itertools, hashlib, json
from bip32 import BIP32Node
from msg import verify_message, RFC_SIGNATURE_TEMPLATE, sign_message, parse_signed_message
from base64 import b64encode, b64decode
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, CCUserRefused
from ckcc_protocol.constants import *
from constants import addr_fmt_names, msg_sign_unmap_addr_fmt
from charcodes import KEY_QR, KEY_NFC


def default_derivation_by_af(addr_fmt, testnet=True):
    b44ct = "1" if testnet else "0"
    if addr_fmt == AF_CLASSIC:
        path = "m/44h/{chain}h/0h/0/0"
    elif addr_fmt == AF_P2WPKH_P2SH:
        path = "m/49h/{chain}h/0h/0/0"
    elif addr_fmt == AF_P2WPKH:
        path = "m/84h/{chain}h/0h/0/0"
    else:
        assert False, "unsupported address format"

    return path.format(chain=b44ct)


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


@pytest.fixture
def verify_msg_sign_story():
    def doit(story, msg, subpath=None, addr_fmt=None, testnet=True, addr=None):
        assert story.startswith('Ok to sign this?')
        assert msg in story
        assert 'Using the key associated' in story

        if addr:
            assert addr in story

        if not subpath:
            assert 'm =>' not in story
            subpath = default_derivation_by_af(addr_fmt or AF_CLASSIC, testnet)
        else:
            subpath = subpath.lower().replace("'", "h")

        assert ('%s =>' % subpath) in story
        return subpath

    return doit


@pytest.fixture
def msg_sign_export(cap_story, press_nfc, nfc_read_text, press_select, press_cancel,
                    readback_bbqr, cap_screen_qr, need_keypress, microsd_path,
                    virtdisk_path, is_q1, OK):
    def doit(way, qr_only=False):
        time.sleep(.1)
        title, story = cap_story()

        if way == "sd":
            if "Press (1) to save Signed Msg" in story:
                need_keypress("1")

        elif way == "nfc":
            if f"press {KEY_NFC if is_q1 else '(3)'} to share via NFC" not in story:
                pytest.xfail("NFC disabled")
            else:
                press_nfc()
                time.sleep(0.2)
                signed_msg = nfc_read_text()
                time.sleep(0.3)
                press_cancel()
                time.sleep(.1)
                title, story = cap_story()
                assert f"Press {OK} to share again" in story
                press_cancel()

        elif way == "qr":
            if not is_q1:
                pytest.xfail("QR disabled")

            if not qr_only:
                need_keypress(KEY_QR)

            time.sleep(.1)
            title, story = cap_story()
            assert "Press ENTER to export signature QR only" in story
            assert "(0) to export full RFC template" in story
            press_select()
            time.sleep(.1)
            sig_only = cap_screen_qr().decode('ascii')
            press_select()
            time.sleep(.1)
            need_keypress("0")
            time.sleep(.1)
            file_type, signed_msg = readback_bbqr()
            signed_msg = signed_msg.decode()
            assert file_type == "U"
            assert sig_only in signed_msg
            press_select()
            press_cancel()

        else:
            # virtual disk
            if "press (2) to save to Virtual Disk" not in story:
                pytest.xfail("Vdisk disabled")
            else:
                need_keypress("2")

        if way in ("sd", "vdisk"):
            path_f = microsd_path if way == "sd" else virtdisk_path
            time.sleep(.1)
            title, story = cap_story()
            fname = story.split("\n\n")[-1]
            with open(path_f(fname), "r") as f:
                signed_msg = f.read()

        return signed_msg

    return doit


@pytest.fixture
def sign_msg_from_text(pick_menu_item, enter_number, press_select,
                       cap_story, need_keypress, settings_set, is_q1,
                       addr_vs_path, bitcoind, msg_sign_export,
                       verify_msg_sign_story, OK):
    # used when signing note/passwords misc content
    # used after simple text QR scan
    # expects to start at menu which offers different single sig address formats

    def doit(msg, addr_fmt, acct, change, idx, way, chain="XTN", qr_only=False):
        settings_set("chain", chain)
        path = "m"
        # pick address format from menu
        if addr_fmt == AF_CLASSIC:
            path += "/44h"
            af_label = "Classic P2PKH"
        elif addr_fmt == AF_P2WPKH:
            path += "/84h"
            af_label = "Segwit P2WPKH"
        else:
            path += "/49h"
            af_label = "P2SH-Segwit"

        pick_menu_item(af_label)

        # chain - no user input - depends on current active settings
        if chain == "BTC":
            path += "/0h"
        else:
            path += "/1h"

        # pick account
        if acct is None:
            path += "/0h"
            press_select()
        else:
            path += ("/%dh" % acct)
            enter_number(acct)

        time.sleep(.1)
        title, story = cap_story()
        assert title == "Change?"
        assert "Press (0) to use internal/change address" in story
        assert f"{OK} to use external/receive address" in story
        if change:
            path += "/1"
            need_keypress("0")
        else:
            path += "/0"
            press_select()

        # index num
        if idx is None:
            path += "/0"
            press_select()
        else:
            path += ("/%d" % idx)
            enter_number(idx)

        time.sleep(.1)
        title, story = cap_story()
        path = verify_msg_sign_story(story, msg, path, addr_fmt, testnet=True if chain == "XTN" else False)
        press_select()

        signed_msg = msg_sign_export(way, qr_only)

        ret_msg, addr, sig = parse_signed_message(signed_msg)
        addr_vs_path(addr, path, addr_fmt, testnet=True if chain == "XTN" else False)
        assert verify_message(addr, sig, ret_msg) is True
        if addr_fmt == AF_CLASSIC and chain == "XTN":
            res = bitcoind.rpc.verifymessage(addr, sig, ret_msg)
            assert res is True

    return doit


@pytest.fixture
def sign_msg_from_address(need_keypress, scan_a_qr, press_select, enter_complex, cap_story,
                          addr_vs_path, verify_msg_sign_story, msg_sign_export):
    def doit(msg, addr, subpath, addr_fmt, way=None, testnet=True):
        if way == 'qr':
            # scan text via QR
            need_keypress(KEY_QR)
            scan_a_qr(msg)
            time.sleep(1)
            press_select()
        else:
            enter_complex(msg, b39pass=False)

        time.sleep(.1)
        title, story = cap_story()
        verify_msg_sign_story(story, msg, subpath, addr_fmt, testnet, addr)
        press_select()
        time.sleep(.1)
        signed_msg = msg_sign_export(way)
        ret_msg, addr, sig = parse_signed_message(signed_msg)
        addr_vs_path(addr, subpath, addr_fmt, testnet=testnet)

    return doit


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
                    press_select, microsd_path, verify_msg_sign_story):

    # sign a file on the microSD card

    def doit(msg, subpath="", addr_fmt=None, expect_fail=False, testnet=True,
             use_json=False):

        suffix = "json" if use_json else "txt"
        fname = f't-msgsign.{suffix}'
        result_fname = 't-msgsign-signed.txt'

        # cleanup
        try: os.unlink(microsd_path(result_fname))
        except OSError: pass


        with open_microsd(fname, 'wt') as sd:
            if use_json:
                res = {"msg": msg}
                if subpath:
                    res["subpath"] = subpath
                if addr_fmt is not None:
                    res["addr_fmt"] = addr_fmt_names[addr_fmt]
                sd.write(json.dumps(res))
            else:
                sd.write(msg + '\n')
                if subpath or addr_fmt:
                    sd.write((subpath or "") + '\n')
                    if addr_fmt is not None:
                        sd.write(addr_fmt_names[addr_fmt])

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

        verify_msg_sign_story(story, msg, subpath, addr_fmt, testnet)
        press_select()  # confirm msg sign

        # wait for it to finish
        for r in range(10):
            time.sleep(0.1)
            title, story = cap_story()
            if title == 'File Signed': break
        else:
            assert False, 'timed out'

        with open_microsd(result_fname, 'rt') as f:
            res = f.read()

        ret_msg, addr, sig = parse_signed_message(res)
        assert ret_msg == msg
        return sig, addr, msg

    return doit

@pytest.mark.bitcoind  # only for testnet and p2pkh
@pytest.mark.parametrize("use_json", [True, False])
@pytest.mark.parametrize('msg', [ 'ab', 'abc def eght', "x"*140, 'a'*240])
@pytest.mark.parametrize('path', [
        "m/84'/0'/22'",
        None,
        'm',
        "m/1/2",
        'm/23h/22h',
    ])
@pytest.mark.parametrize('addr_fmt', [
        None ,
        AF_P2WPKH,
        AF_CLASSIC,
        AF_P2WPKH_P2SH,
    ])
@pytest.mark.parametrize("testnet", [True, False])
def test_sign_msg_microsd_good(sign_on_microsd, msg, path, addr_vs_path,
                               addr_fmt, testnet, settings_set, bitcoind,
                               use_json):

    settings_set("chain", "XTN" if testnet else "BTC")
    # cases we expect to work
    sig, addr, ret_msg = sign_on_microsd(msg, path, addr_fmt, testnet=testnet,
                                use_json=use_json)
    assert msg == ret_msg

    raw = b64decode(sig)
    assert 40 <= len(raw) <= 65

    if addr_fmt is None:
        addr_fmt = AF_CLASSIC

    if not path:
        path = default_derivation_by_af(addr_fmt, testnet=testnet)

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt, testnet=testnet)
    assert verify_message(addr, sig, msg) is True
    if addr_fmt == AF_CLASSIC and testnet:
        res = bitcoind.rpc.verifymessage(addr, sig, ret_msg)
        assert res is True


@pytest.fixture
def sign_using_nfc(goto_home, pick_menu_item, nfc_write_text, cap_story, press_select,
                   nfc_read_text, addr_vs_path, press_cancel, OK, verify_msg_sign_story):
    def doit(msg, subpath=None, addr_fmt=None, expect_fail=False, use_json=False,
             testnet=True):
        if use_json:
            res = {"msg": msg}
            if subpath:
                res["subpath"] = subpath
            if addr_fmt is not None:
                res["addr_fmt"] = addr_fmt_names[addr_fmt]
            body = json.dumps(res)
        else:
            body = msg + "\n"
            if subpath or addr_fmt:
                body += ((subpath or "") + '\n')
                if addr_fmt is not None:
                    body += addr_fmt_names[addr_fmt]

        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Sign Message')
        nfc_write_text(body)
        time.sleep(0.5)
        if expect_fail:
            return cap_story()

        if not addr_fmt:
            addr_fmt = AF_CLASSIC

        if not subpath:
            subpath = default_derivation_by_af(addr_fmt, testnet=testnet)

        _, story = cap_story()
        subpath = verify_msg_sign_story(story, msg, subpath, addr_fmt, testnet)
        press_select()
        signed_msg = nfc_read_text()
        if "BITCOIN SIGNED MESSAGE" not in signed_msg:
            # missed it? again
            signed_msg = nfc_read_text()
        press_select()  # exit NFC animation
        pmsg, addr, sig = parse_signed_message(signed_msg)
        assert pmsg == msg
        addr_vs_path(addr, subpath, addr_fmt, testnet=testnet)
        assert verify_message(addr, sig, msg) is True
        time.sleep(0.5)
        _, story = cap_story()
        assert f"Press {OK} to share again" in story
        press_select()
        signed_msg_again = nfc_read_text()
        assert signed_msg == signed_msg_again
        press_cancel()  # exit NFC animation
        press_cancel()  # do not want to share again

        return sig, addr, msg

    return doit


@pytest.mark.bitcoind
@pytest.mark.parametrize("way", ["nfc", "sd"])
@pytest.mark.parametrize("msg", ['test\ttest', "\n\n\tmsg\n\n\tsigning"])
def test_sign_msg_with_ascii_non_printable_chars(msg, way, sign_on_microsd, addr_vs_path,
                                                 settings_set, bitcoind, sign_using_nfc):
    # only works with the JSON format
    settings_set("chain", "XTN")
    if way == "sd":
        sig, addr, ret_msg = sign_on_microsd(msg, "", None, use_json=True)
    else:
        sig, addr, ret_msg = sign_using_nfc(msg, "", None, use_json=True)

    assert ret_msg == msg
    raw = b64decode(sig)
    assert 40 <= len(raw) <= 65

    addr_fmt = AF_CLASSIC
    path = default_derivation_by_af(addr_fmt, testnet=True)

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)
    assert verify_message(addr, sig, msg) is True
    res = bitcoind.rpc.verifymessage(addr, sig, msg)
    assert res is True


@pytest.mark.parametrize('msg,subpath,addr_fmt,concern,no_file,no_json', [
    ('', "m", AF_CLASSIC, 'too short', 0, 0),  # zero length not supported
    ('a'*1000, "m/1", AF_P2WPKH,'too long', 1, 0),  # too big, won't even be offered as a file
    ('a'*241, "m/400", AF_P2WPKH_P2SH, 'too long', 0, 0),  # too big
    ('hello%20sworld'%'', "m", AF_CLASSIC, 'many spaces', 0, 0),  # spaces
    ('hello%10sworld'%'', "m/1h/3h", AF_P2WPKH_P2SH, 'many spaces', 0, 0),  # spaces
    ('hello%5sworld'%'', "m", AF_CLASSIC, 'many spaces', 0, 0),  # spaces
    ("coinkite", "m", AF_P2WSH, "Invalid address format", 0, 0),  # invalid address format
    ("coinkite", "m", AF_P2WSH_P2SH, "Invalid address format", 0, 0),  # invalid address format
    ("coinkite", " m", AF_P2TR, "Invalid address format", 0, 0),  # invalid address format
    ("coinkite", "m/0/0/0/0/0/0/0/0/0/0/0/0/0", AF_CLASSIC, "too deep", 0, 0),  # invalid path
    ("coinkite", "m/0/0/0/0/0/q/0/0/0", AF_P2WPKH, "invalid characters in path", 0, 0),  # invalid path
    ("coinkite ", "m", AF_CLASSIC, "trailing space(s)", 0, 0),  # invalid msg - trailing space
    (" coinkite", "m", AF_P2WPKH_P2SH, "leading space(s)", 0, 0),  # invalid msg - leading space
    ('testêtest', "m", AF_P2WPKH, "must be ascii", 0, 0),
    # below works only with the JSON format
    ('test\ttest', "m", AF_CLASSIC, "must be ascii printable", 0, 1),
])
@pytest.mark.parametrize("use_json", [True, False])
@pytest.mark.parametrize('transport', ['sd', 'usb', 'nfc'])
def test_sign_msg_fails(dev, sign_on_microsd, msg, subpath, addr_fmt, concern,
                        no_file, no_json, transport, sign_using_nfc, use_json):
    if use_json and no_json:
        # special cases with ascii non printable characters - can be present in json
        raise pytest.skip("json can contain ASCII non-printable in msg")
    if transport == 'usb':
        with pytest.raises(CCProtoError) as ee:
            try:
                encoded_msg = msg.encode('ascii')
            except UnicodeEncodeError:
                encoded_msg = msg.encode()
            dev.send_recv(CCProtocolPacker.sign_message(encoded_msg, subpath, addr_fmt), timeout=None)
        story = ee.value.args[0]
    elif transport == 'sd':
        try:
            story = sign_on_microsd(msg, subpath, addr_fmt, expect_fail=True, use_json=use_json)
            assert story.startswith('Problem: ')
        except AssertionError as e:
            if no_file:
                assert ("No suitable files found" in str(e)) or story == 'NO-FILE'
                return
    elif transport == 'nfc':
        title, story = sign_using_nfc(msg, subpath, addr_fmt, expect_fail=True, use_json=use_json)
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


@pytest.mark.bitcoind  # only for testnet and p2pkh
@pytest.mark.parametrize("testnet", [True, False])
@pytest.mark.parametrize("use_json", [True, False])
@pytest.mark.parametrize("msg", ["Coldcard Signing Device!", 200 * "a"])
@pytest.mark.parametrize("path", ["", "m/84'/0'/0'/300/0", "m/0/0/0/0/1/1/1"])
@pytest.mark.parametrize("addr_fmt", [AF_CLASSIC, None, AF_P2WPKH, AF_P2WPKH_P2SH])
def test_nfc_msg_signing(msg, path, addr_fmt, testnet, settings_set, bitcoind, use_json,
                         sign_using_nfc, goto_home):
    settings_set("chain", "XTN" if testnet else "BTC")

    for _ in range(5):
        # need to wait for ApproveMessageSign to be popped from ux stack
        try:
            goto_home()
            break
        except:
            time.sleep(0.5)

    addr, sig, ret_msg = sign_using_nfc(msg, path, addr_fmt, testnet=testnet, use_json=use_json)
    assert msg == ret_msg
    if addr_fmt == AF_CLASSIC and testnet:
        res = bitcoind.rpc.verifymessage(sig, addr, ret_msg)
        assert res is True

@pytest.fixture
def verify_armored_signature(pick_menu_item, nfc_write_text,
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
    sig, addr, ret_msg = sign_on_microsd(msg, path, msg_sign_unmap_addr_fmt[addr_fmt])
    assert ret_msg == msg
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


@pytest.mark.parametrize("msg", ["this is the message to sign", "this is meessage to sign\n with newline", "a"*200])
@pytest.mark.parametrize("addr_fmt", [AF_CLASSIC, AF_P2WPKH])
@pytest.mark.parametrize("acct", [None, 5555])
def test_sign_scanned_text(msg, addr_fmt, acct, goto_home, need_keypress, scan_a_qr,
                           sign_msg_from_text, cap_story, skip_if_useless_way):
    skip_if_useless_way("qr")
    goto_home()
    need_keypress(KEY_QR)
    scan_a_qr(msg)
    time.sleep(1)
    title, story = cap_story()
    assert title == "Simple Text"
    assert "Press (0) to sign the text" in story
    need_keypress("0")
    sign_msg_from_text(msg, addr_fmt, acct, False, 999, "qr", "XTN", True)


@pytest.mark.parametrize("data", [
    {"msg": "msg to be signed via QR"},
    {"msg": "msg with some\n\t\n control characters", "addr_fmt": "p2sh-p2wpkh"},
    {"msg": 100*"CC", "addr_fmt": "p2wpkh", "subpath": "m/900h/0"},
])
@pytest.mark.parametrize("way", ["sd", "nfc", "qr"])
def test_sign_scanned_json(data, way, goto_home, need_keypress, scan_a_qr,
                           cap_story, msg_sign_export, press_select,
                           addr_vs_path, bitcoind, skip_if_useless_way,
                           verify_msg_sign_story):
    skip_if_useless_way(way)
    goto_home()
    af = data.get("addr_fmt", None)
    if not af:
        addr_fmt = AF_CLASSIC
    else:
        addr_fmt = msg_sign_unmap_addr_fmt[af]

    need_keypress(KEY_QR)
    scan_a_qr(json.dumps(data))
    time.sleep(1)
    title, story = cap_story()

    subpath = verify_msg_sign_story(story, data["msg"], data.get("subpath", None), addr_fmt)
    press_select()

    signed_msg = msg_sign_export(way)
    ret_msg, addr, sig = parse_signed_message(signed_msg)
    assert ret_msg == data["msg"]
    # check expected addr was used
    addr_vs_path(addr, subpath, addr_fmt)
    assert verify_message(addr, sig, ret_msg) is True
    if addr_fmt == AF_CLASSIC:
        res = bitcoind.rpc.verifymessage(addr, sig, ret_msg)
        assert res is True


@pytest.mark.parametrize("msg", [(50*"a")+"\n\n"+(100*"b"), "Balance replenish 564565456254"])
def test_verify_scanned_signed_msg(msg, scan_a_qr, need_keypress, goto_home, cap_story,
                                   skip_if_useless_way):
    skip_if_useless_way("qr")
    wallet = BIP32Node.from_master_secret(os.urandom(32))
    addr = wallet.address()
    sk = bytes(wallet.node.private_key)
    sig = sign_message(sk, msg.encode())
    armored = RFC_SIGNATURE_TEMPLATE.format(addr=addr, sig=sig, msg=msg)

    goto_home()
    need_keypress(KEY_QR)
    scan_a_qr(armored)
    time.sleep(1)
    title, story = cap_story()
    assert title == "CORRECT"
    assert "Good signature by address" in story

# EOF
