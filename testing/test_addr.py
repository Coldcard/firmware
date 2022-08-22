# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test "show address" feature
#
# - these only work well on the simulator
# - must put real device into testnet mode first
#
import pytest, time
from pycoin.contrib.msg_signing import verify_message
from ckcc_protocol.protocol import CCProtocolPacker
from ckcc_protocol.constants import *
from constants import msg_sign_unmap_addr_fmt

@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_show_addr_usb(dev, need_keypress, addr_vs_path, path, addr_fmt, is_simulator):

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    need_keypress('y')

    if "'" in path and not is_simulator():
        raise pytest.skip('we cant confirm hardened-derived keypaths')

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)

@pytest.mark.qrcode
@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
@pytest.mark.parametrize('show_qr', [ False, True ])
def test_show_addr_displayed(dev, need_keypress, addr_vs_path, path, addr_fmt, cap_story, show_qr, cap_screen_qr, qr_quality_check):
    time.sleep(0.1)

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    time.sleep(0.1)
    title, story = cap_story()

    #need_keypress('x')

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)

    print('addr_fmt = 0x%x' % addr_fmt)

    assert title == 'Address:'
    assert path in story
    assert addr in story
    assert addr in story.split('\n')

    if show_qr:
        need_keypress('4')
        time.sleep(0.1)
        qr = cap_screen_qr().decode('ascii')

        assert qr == addr or qr == addr.upper()

@pytest.mark.bitcoind
def test_addr_vs_bitcoind(use_regtest, match_key, need_keypress, dev, bitcoind_d_sim_sign):
    # check our p2wpkh wrapped in p2sh is right
    use_regtest()
    for i in range(5):
        core_addr = bitcoind_d_sim_sign.getnewaddress(f"{i}-addr", "p2sh-segwit")
        assert core_addr[0] == '2'
        resp = bitcoind_d_sim_sign.getaddressinfo(core_addr)
        assert resp['embedded']['iswitness'] == True
        assert resp['isscript'] == True
        path = resp['hdkeypath']

        addr = dev.send_recv(CCProtocolPacker.show_address(path, AF_P2WPKH_P2SH), timeout=None)
        need_keypress('y')
        assert addr == core_addr

@pytest.mark.parametrize("body_err", [
    ("m\np2wsh", "Invalid address format specified p2wsh"),
    ("m\np2sh-p2wsh", "Invalid address format specified p2sh-p2wsh"),
    ("m\np2tr", "Invalid address format specified p2tr"),
    ("m/0/0/0/0/0/0/0/0/0/0/0/0/0\np2pkh", "too deep"),
    ("m/0/0/0/0/0/q/0/0/0\np2pkh", "invalid characters"),
])
def test_show_addr_nfc_invalid(body_err, goto_home, pick_menu_item, nfc_write_text, cap_story):
    body, err = body_err
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Show Address')
    nfc_write_text(body)
    time.sleep(0.5)
    _, story = cap_story()
    assert err in story

@pytest.mark.parametrize("path", ["m/84'/0'/0'/300/0", "m/800'", "m/0/0/0/0/1/1/1"])
@pytest.mark.parametrize("str_addr_fmt", ["p2pkh", "", "p2wpkh", "p2wpkh-p2sh", "p2sh-p2wpkh"])
def test_show_addr_nfc(path, str_addr_fmt, nfc_write_text, nfc_read_text, pick_menu_item, goto_home, cap_story,
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
    pick_menu_item('Show Address')
    if str_addr_fmt != "":
        addr_fmt = msg_sign_unmap_addr_fmt[str_addr_fmt]
        body = "\n".join([path, str_addr_fmt])
    else:
        addr_fmt = AF_CLASSIC
        body = path

    nfc_write_text(body)
    time.sleep(0.5)
    _, story = cap_story()
    split_story = story.split("\n\n")
    story_addr = split_story[0]
    story_path = split_story[1][2:]  # remove "= "
    assert "Press 3 to share over NFC" in story
    assert story_path == path
    need_keypress("3")  # share over NFC
    addr = nfc_read_text()
    if addr == body:
        # missed it - again
        addr = nfc_read_text()
    need_keypress("y")  # exit NFC animation
    assert story_addr == addr
    addr_vs_path(addr, path, addr_fmt)

# EOF
