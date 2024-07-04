# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test "show address" feature
#
# - these only work well on the simulator
# - must put real device into testnet mode first
#
import pytest, time
from ckcc_protocol.protocol import CCProtocolPacker
from ckcc_protocol.constants import *
from charcodes import KEY_QR
from constants import msg_sign_unmap_addr_fmt

@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR ])
def test_show_addr_usb(dev, press_select, addr_vs_path, path, addr_fmt, is_simulator):

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    press_select()

    if "'" in path and not is_simulator():
        raise pytest.skip('we cant confirm hardened-derived keypaths')

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)

@pytest.mark.qrcode
@pytest.mark.parametrize('path', [ 'm', "m/1/2", "m/1'/100'", "m/0h/500h"])
@pytest.mark.parametrize('addr_fmt', [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR ])
def test_show_addr_displayed(dev, need_keypress, addr_vs_path, path, addr_fmt,
                             cap_story, cap_screen_qr, qr_quality_check,
                             press_cancel, is_q1):
    time.sleep(0.1)

    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)

    time.sleep(0.1)
    title, story = cap_story()

    assert title == 'Address:'
    if "'" in path:
        assert path not in story  # we normalize to h
        assert path.replace("'", "h") in story
    else:
        assert path in story

    assert addr in story
    assert addr in story.split('\n')

    # check expected addr was used
    addr_vs_path(addr, path, addr_fmt)

    print('addr_fmt = 0x%x' % addr_fmt)

    need_keypress(KEY_QR if is_q1 else '4')
    time.sleep(0.1)
    qr = cap_screen_qr().decode('ascii')

    assert qr == addr or qr == addr.upper()

@pytest.mark.bitcoind
@pytest.mark.parametrize("addr_fmt", [
    (AF_CLASSIC, "legacy"),
    (AF_P2WPKH_P2SH, "p2sh-segwit"),
    (AF_P2WPKH, "bech32"),
    (AF_P2TR, "bech32m")
])
def test_addr_vs_bitcoind(addr_fmt, use_regtest, press_select, dev, bitcoind_d_sim_sign):
    # check our p2wpkh wrapped in p2sh is right
    use_regtest()
    addr_fmt, addr_fmt_bitcoind = addr_fmt
    for i in range(5):
        core_addr = bitcoind_d_sim_sign.getnewaddress(f"{i}-addr", addr_fmt_bitcoind)
        resp = bitcoind_d_sim_sign.getaddressinfo(core_addr)
        assert resp["ismine"] is True
        if addr_fmt in (AF_P2TR, AF_P2WPKH):
            wit_ver = resp["witness_version"]
            if addr_fmt == AF_P2TR:
                assert wit_ver == 1
            else:
                assert wit_ver == 0
            assert resp["iswitness"] is True
        if addr_fmt == AF_P2WPKH_P2SH:
            assert resp['embedded']['iswitness'] is True
            assert resp['isscript'] is True
            assert resp['embedded']['witness_version'] == 0
        path = resp['hdkeypath']

        addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt), timeout=None)
        press_select()
        assert addr == core_addr

@pytest.mark.parametrize("body_err", [
    ("m\np2wsh", "Unsupported address format: 'p2wsh'"),
    ("m\np2sh-p2wsh", "Unsupported address format: 'p2sh-p2wsh'"),
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

@pytest.mark.parametrize("path", ["m/84'/0'/0'/300/0", "m/800h/0h", "m/0/0/0/0/1/1/1"])
@pytest.mark.parametrize("str_addr_fmt", ["p2pkh", "", "p2wpkh", "p2wpkh-p2sh", "p2sh-p2wpkh", "p2tr"])
def test_show_addr_nfc(path, str_addr_fmt, nfc_write_text, nfc_read_text, pick_menu_item,
                       goto_home, cap_story, press_nfc, addr_vs_path, press_select, is_q1,
                       cap_screen):
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
    if not is_q1:
        assert "Press (3) to share via NFC" in story

    if "'" in path:
        assert path != story_path  # normalized to h
        assert path.replace("'", "h") == story_path
    else:
        assert story_path == path

    press_nfc()  # share over NFC
    addr = nfc_read_text()
    if addr == body:
        # missed it - again
        addr = nfc_read_text()
    press_select()  # exit NFC animation
    assert story_addr == addr
    addr_vs_path(addr, path, addr_fmt)

def test_bip86(dev, set_seed_words, use_mainnet, need_keypress):
    # https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    set_seed_words(mnemonic)
    use_mainnet()

    path = "m/86'/0'/0'"
    xp = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    # xprv = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk"
    xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
    assert xp == xpub

    # Account 0, first receiving
    path = "m/86'/0'/0'/0/0"
    addr = dev.send_recv(CCProtocolPacker.show_address(path, AF_P2TR), timeout=None)
    need_keypress('y')
    xp = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)

    # xprv = "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T"
    xpub = "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B"
    # internal_key = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    # output_key = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    # scriptPubKey = "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    address = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    assert xp == xpub
    assert addr == address

    # Account 0, second receiving
    path = "m/86'/0'/0'/0/1"
    addr = dev.send_recv(CCProtocolPacker.show_address(path, AF_P2TR), timeout=None)
    need_keypress('y')
    xp = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    # xprv = "xxprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ"
    xpub = "xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX"
    # internal_key = "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"
    # output_key = "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
    # scriptPubKey = "5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
    address = "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
    assert xp == xpub
    assert addr == address

    # Account 0, first change
    path = "m/86'/0'/0'/1/0"
    addr = dev.send_recv(CCProtocolPacker.show_address(path, AF_P2TR), timeout=None)
    need_keypress('y')
    xp = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    # xprv = "xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP"
    xpub = "xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3"
    # internal_key = "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"
    # output_key = "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
    # scriptPubKey = "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
    address = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
    assert xp == xpub
    assert addr == address

# EOF