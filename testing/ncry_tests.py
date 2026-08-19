# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest
from hashlib import sha256

from ckcc_protocol.client import ColdcardDevice
from ckcc_protocol.constants import USB_NCRY_V1, USB_NCRY_V2, USB_NCRY_V3, USB_V3_TAG_LEN
from ckcc_protocol.protocol import (
    MAX_MSG_LEN,
    CCFramingError,
    CCProtocolPacker,
    CCProtocolUnpacker,
)
from run_sim_tests import ColdcardSimulator, clean_sim_data, remove_all_client_sockets


def xor_bytes(left, right):
    assert len(left) == len(right)
    return bytes(a ^ b for a, b in zip(left, right))


@pytest.fixture
def ncry_v3_dev(request):
    clean_sim_data()
    remove_all_client_sockets()

    sim_args = ["--eff", "--set", "nfc=1"]
    if request.config.getoption("--Q"):
        sim_args.append("--q1")

    sim = ColdcardSimulator(
        args=sim_args,
        headless=request.config.getoption("--headless"))
    dev = None

    try:
        sim.start(start_wait=3)
        dev = ColdcardDevice(
            sn=sim.socket,
            is_simulator=True,
            ncry_ver=USB_NCRY_V3)

        yield dev
    finally:
        if dev is not None:
            dev.close()
        if sim.proc is not None:
            sim.stop()
        clean_sim_data()
        remove_all_client_sockets()


def send_wire(dev, wire, encrypted=True, timeout=3000):
    left = len(wire)
    offset = 0
    while left > 0:
        here = min(63, left)
        buf = bytearray(65)
        buf[2:2+here] = wire[offset:offset+here]
        if here == left:
            buf[1] = here | 0x80 | (0x40 if encrypted else 0x00)
        else:
            buf[1] = here

        assert dev.dev.write(buf) == len(buf)
        offset += here
        left -= here

    resp = b''
    while True:
        buf = dev.dev.read(64, timeout_ms=timeout)
        assert buf, "timeout reading USB EP"

        flag = buf[0]
        resp += bytes(buf[1:1+(flag & 0x3f)])
        if flag & 0x80:
            return flag, resp


def send_encrypted(dev, msg):
    wire = dev.encrypt_request(msg)
    flag, resp = send_wire(dev, wire, encrypted=True)
    assert flag & 0x40
    return wire, resp


def decode_encrypted_response(dev, wire):
    return CCProtocolUnpacker.decode(dev.decrypt_response(wire))


def assert_encrypted_framing_error(dev, wire, reason):
    plaintext = dev.decrypt_response(wire)
    assert plaintext == b'fram' + reason.encode()
    with pytest.raises(CCFramingError, match=reason):
        CCProtocolUnpacker.decode(plaintext)


def test_ncry_v3_single_client_multiple_commands(ncry_v3_dev):
    dev = ncry_v3_dev

    assert dev.ncry_ver == USB_NCRY_V3
    assert dev.session_key

    rb = dev.send_recv(CCProtocolPacker.ping(b'\x5a' * 32))
    assert rb == b'\x5a' * 32

    version = dev.send_recv(CCProtocolPacker.version())
    assert '\n' in version

    chain = dev.send_recv(CCProtocolPacker.block_chain())
    assert chain in {'BTC', 'XTN', 'XRT'}

    xpub = dev.send_recv(CCProtocolPacker.get_xpub('m'), timeout=None)
    assert xpub[1:4] == 'pub'

    data = b'ncry-v3-single-client'
    assert dev.send_recv(CCProtocolPacker.upload(0, len(data), data)) == 0
    assert dev.send_recv(CCProtocolPacker.sha256()) == sha256(data).digest()

    rb = dev.send_recv(CCProtocolPacker.ping(bytes(MAX_MSG_LEN-4)))
    assert set(rb) == {0} and len(rb) == MAX_MSG_LEN-4


def test_ncry_v3_fixed_vectors(ncry_v3_dev, src_root_dir):
    hook = 'execfile("%s/testing/devtest/unit_ncry_v3.py")' % src_root_dir
    assert ncry_v3_dev.send_recv(b'EXEC' + hook.encode()) == b''


def test_ncry_v3_overlong_response_rejected(ncry_v3_dev):
    # EXEC adds the four-byte "biny" response prefix. Exceed the maximum
    # authenticated v3 wire response by exactly one byte.
    cmd = "RV.write(b'x' * %d)" % (MAX_MSG_LEN - 3)

    with pytest.raises(CCFramingError, match="Response too long"):
        ncry_v3_dev.send_recv(b'EXEC' + cmd.encode())
    assert ncry_v3_dev._v3_failed


def test_ncry_v3_directional_streams_cannot_be_xored_to_decrypt(ncry_v3_dev):
    dev = ncry_v3_dev
    payload = b'\x33' * 32
    request_plaintext = CCProtocolPacker.ping(payload)
    response_plaintext = b'biny' + payload

    request_wire, response_wire = send_encrypted(dev, request_plaintext)
    request_ciphertext = request_wire[:-USB_V3_TAG_LEN]
    response_ciphertext = response_wire[:-USB_V3_TAG_LEN]

    assert xor_bytes(request_ciphertext, response_ciphertext) != xor_bytes(
        request_plaintext, response_plaintext)
    recovered_response_plaintext = xor_bytes(
        response_ciphertext,
        xor_bytes(request_ciphertext, request_plaintext))
    assert recovered_response_plaintext != response_plaintext
    assert decode_encrypted_response(dev, response_wire) == payload


def test_ncry_v3_response_replay_rejected(ncry_v3_dev):
    dev = ncry_v3_dev
    payload = b'\x44' * 16

    _, response_wire = send_encrypted(dev, CCProtocolPacker.ping(payload))
    assert decode_encrypted_response(dev, response_wire) == payload

    with pytest.raises(CCFramingError):
        dev.decrypt_response(response_wire)


def test_ncry_v3_response_tamper_rejected_before_sequence_increment(ncry_v3_dev):
    dev = ncry_v3_dev
    payload = b'\x55' * 16

    _, response_wire = send_encrypted(dev, CCProtocolPacker.ping(payload))
    tampered_response = bytearray(response_wire)
    tampered_response[0] ^= 1

    rx_seq = dev.rx_seq
    with pytest.raises(CCFramingError):
        dev.decrypt_response(bytes(tampered_response))
    assert dev.rx_seq == rx_seq
    assert dev._v3_failed
    with pytest.raises(CCFramingError, match='session failed'):
        dev.decrypt_response(response_wire)


def test_ncry_v3_request_mac_auth_failure_rejected(ncry_v3_dev):
    dev = ncry_v3_dev
    bad_request = bytearray(dev.encrypt_request(
        CCProtocolPacker.ping(b'\x66' * 16)))
    bad_request[-1] ^= 1

    flag, response_wire = send_wire(dev, bytes(bad_request), encrypted=True)
    assert flag & 0x40
    assert_encrypted_framing_error(dev, response_wire, 'auth')

    # Firmware terminates its USB receive task after the authenticated error.
    next_request = dev.encrypt_request(CCProtocolPacker.ping(b'after-auth-failure'))
    with pytest.raises(AssertionError, match='timeout reading USB EP'):
        send_wire(dev, next_request, encrypted=True, timeout=100)


def test_ncry_v3_request_replay_rejected(ncry_v3_dev):
    dev = ncry_v3_dev
    request_wire, response_wire = send_encrypted(
        dev, CCProtocolPacker.ping(b'\x77' * 16))
    assert decode_encrypted_response(dev, response_wire) == b'\x77' * 16

    flag, replay_response_wire = send_wire(dev, request_wire, encrypted=True)
    assert flag & 0x40
    assert_encrypted_framing_error(dev, replay_response_wire, 'auth')


def test_ncry_v3_short_encrypted_request_rejected(ncry_v3_dev):
    dev = ncry_v3_dev

    flag, response_wire = send_wire(dev, bytes(USB_V3_TAG_LEN), encrypted=True)
    assert flag & 0x40
    assert_encrypted_framing_error(dev, response_wire, 'auth')


def test_ncry_v3_short_ciphertext_request_rejected(ncry_v3_dev):
    dev = ncry_v3_dev

    flag, response_wire = send_wire(
        dev, bytes(USB_V3_TAG_LEN + 1), encrypted=True)
    assert flag & 0x40
    assert_encrypted_framing_error(dev, response_wire, 'badsz')
@pytest.fixture
def ncry_legacy_dev(request):
    # Same simulator boot as ncry_v3_dev, but with a legacy (v1/v2) session.
    clean_sim_data()
    remove_all_client_sockets()

    sim_args = ["--eff", "--set", "nfc=1"]
    if request.config.getoption("--Q"):
        sim_args.append("--q1")

    sim = ColdcardSimulator(
        args=sim_args,
        headless=request.config.getoption("--headless"))
    dev = None

    try:
        sim.start(start_wait=3)
        dev = ColdcardDevice(
            sn=sim.socket,
            is_simulator=True,
            ncry_ver=request.param)

        yield dev
    finally:
        if dev is not None:
            dev.close()
        if sim.proc is not None:
            sim.stop()
        clean_sim_data()
        remove_all_client_sockets()


def test_ncry_legacy_wire_format_unchanged():
    # Legacy v1/v2 wire format must be exactly the pre-v3 format:
    # bare AES-CTR keystream output, no authentication tag appended.
    # (pure client-side; calling encrypt_request on a live session would
    # advance the CTR stream and desync the link)
    import pyaes

    session_key = sha256(b'ncry-legacy-format').digest()
    msg = CCProtocolPacker.ping(b'\x5a' * 32)

    dev = ColdcardDevice.__new__(ColdcardDevice)
    dev.aes_setup(session_key)

    wire = dev.encrypt_request(msg)
    assert len(wire) == len(msg), "legacy wire format must not carry a tag"

    # device side decrypts with an independent counter-0 CTR on the same key
    dev_ctr = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0))
    assert dev_ctr.decrypt(wire) == msg


@pytest.mark.parametrize('ncry_legacy_dev', [USB_NCRY_V1, USB_NCRY_V2], indirect=True)
def test_ncry_legacy_encryption_unchanged(ncry_legacy_dev):
    # Legacy v1/v2 sessions must keep working end-to-end against firmware
    # that also supports ncry v3.
    dev = ncry_legacy_dev

    assert dev.ncry_ver in (USB_NCRY_V1, USB_NCRY_V2)

    rb = dev.send_recv(CCProtocolPacker.ping(b'\x5a' * 32))
    assert rb == b'\x5a' * 32

    version = dev.send_recv(CCProtocolPacker.version())
    assert '\n' in version

    xpub = dev.send_recv(CCProtocolPacker.get_xpub('m'), timeout=None)
    assert xpub[1:4] == 'pub'

    data = b'ncry-legacy-compat'
    assert dev.send_recv(CCProtocolPacker.upload(0, len(data), data)) == 0
    assert dev.send_recv(CCProtocolPacker.sha256()) == sha256(data).digest()
