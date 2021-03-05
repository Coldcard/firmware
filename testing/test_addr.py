# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test "show address" feature
#
# - these only work well on the simulator
# - must put real device into testnet mode first
#
import pytest, time
from pycoin.contrib.msg_signing import verify_message
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError
from ckcc_protocol.constants import *

@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
def test_show_addr_usb(dev, need_keypress, addr_vs_path, path, addr_fmt, is_simulator):

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    need_keypress('y')

    if "'" in path and not is_simulator():
        raise pytest.skip('we cant confirm hardened-derived keypaths')

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)

@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH ])
@pytest.mark.parametrize('show_qr', [ False, True ])
def test_show_addr_displayed(dev, need_keypress, addr_vs_path, path, addr_fmt, cap_story, show_qr, cap_screen_qr):
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
        qr = cap_screen_qr()

        assert qr == addr or qr == addr.upper()

@pytest.mark.parametrize('example_addr', [
        '2N2VBntgcoY4wN7H6VfrhH8an1BwieRMZCF', '2N551pf65tPS7VthC1rvwFDbLA1EUDYkTg9'])
def test_addr_vs_bitcoind(bitcoind, match_key, need_keypress, example_addr, dev):
    # check our p2wpkh wrapped in p2sh is right
    
    # PROBLEM: your bitcoind probably needs same transaction history as mine, so it knows
    # about this address and its contents/key path.

    assert example_addr[0] == '2'
    resp = bitcoind.getaddressinfo(example_addr)

    assert resp['embedded']['iswitness'] == True
    assert resp['isscript'] == True
    path = resp['hdkeypath']

    addr = dev.send_recv(CCProtocolPacker.show_address(path, AF_P2WPKH_P2SH), timeout=None)
    need_keypress('y')

    assert addr == example_addr
        

# EOF
