# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# A few USB link layer tests.
# 
# - not working well on simulator right now, but that's not key
#
import pytest, struct, hashlib, os
from bip32 import BIP32Node
from binascii import b2a_hex
from constants import simulator_fixed_tprv
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from ckcc_protocol.constants import MSG_SIGNING_MAX_LENGTH

@pytest.mark.skip
def test_usb_fuzz(dev):
    # test framing logic
    # - expect a few console errors

    def llread():
        # unify unix socket vs. USB pipe differences
        rv = dev.dev.read(64, timeout_ms=100)
        if rv == None: return
        return bytes(rv) or None

    # do-nothing msg
    dev.dev.write(b'\x80' + (b'\x01'*63))
    resp = llread()
    assert resp == None, repr(resp)

    if 0:
        # leverage bug(?) in HIDapi to test short EP writes
        dev.dev.write(b'\x00'*64)
        resp = llread()
        assert resp[1:].startswith(b'framshort'), resp

    # get out of sync. and recover
    dev.dev.write(b'\x3f' + b'ping'+ (b'a'*(64-4-1)))
    resp = llread()
    assert resp == None
    dev.dev.write(b'\x00' + b'ping'+ (b'b'*(64-4-1)))
    assert resp == None
    resp = llread()

    dev.dev.write(bytes([0x80 + 0x3f]) +b'ping'+ (b'-'*(64-4-1)))
    resp = llread()
    assert resp[1:] == b'biny'+(b'-' * (0x3f-4)), resp

    # various length junk messages (single packet)
    for n in [1, 2, 3, 4, 5, 50, 63]:
        dev.dev.write(bytes([n | 0x80]) + b'abcd' + bytes(64-4-1)) 
        resp = llread()
        msg = resp[1:1+(resp[0] & 0x3f)]
        print("Bad length test: %2d => %r" % (n, msg.decode('ascii')))
        if n < 4:
            assert msg[0:4] == b'fram', repr(resp)
        else:
            assert msg[0:4] == b'err_', repr(resp)

    # too long
    print("Long msg test, start.")
    for n in range(2000):
        dev.dev.write(b'\x3f' + b'\xff' + bytes(62))
        resp = llread()
        if resp == None: continue
        print("stopped @ %d msgs" % n)
        assert resp[1:1+4] == b'fram', resp
        break
    

# note: 0x80000000 = 2147483648

@pytest.mark.parametrize('path', [
    '', 'm', 'm/1', "m/1'", "m/1'/0/1'", "m/2147483647", "m/2147483647'", 'm/1/2/3/4/5/6/7/8/9/10',
    "m/1h", "m/1h/0/1h", "m/2147483647", "m/2147483647h", 'm/1/2/3/4/5/6/7/8/9/10',
])
def test_xpub_good(dev, master_xpub, path):
    # get some xpubs and validate the derivations

    xpub = dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)

    assert xpub[1:4] == 'pub'
    assert len(xpub) > 100

    k = BIP32Node.from_wallet_key(xpub)

    assert k.hwif() == xpub

    is_hard = ("'" in path) or ("h" in path)
    if not is_hard or dev.is_simulator:
        mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if is_hard else master_xpub)
        sk = mk.subkey_for_path(path)
        assert sk.hwif() == xpub

    if len(path) <= 2:
        assert mk.fingerprint() == struct.pack('<I', dev.master_fingerprint)

@pytest.mark.parametrize('path', [ 'x/1/2', "m'", "m/"])
def test_xpub_invalid(dev, path):
    # some bad paths

    with pytest.raises(CCProtoError):
        dev.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
    

def test_version(dev, is_q1):
    # read the version, yawn.
    v = dev.send_recv(CCProtocolPacker.version())
    assert '\n' in v
    date, label, bl, build_date, hw_label, *extras = v.split('\n')
    assert '-' in date
    assert '.' in label
    assert '.' in bl
    if is_q1:
        assert "q1" in hw_label
    else:
        assert 'mk' in hw_label
    print("date=%s" % date)
    assert build_date.startswith(date[2:].replace('-', ''))
    assert not extras

@pytest.mark.parametrize('data_len', [1, 24, 60, 61, 62, 63, 64, 1000])
def test_upload_short(dev, data_len):
    # upload a few really short files

    data = b'a'*data_len

    v = dev.send_recv(CCProtocolPacker.upload(0, len(data), data))
    assert v == 0
    chk = dev.send_recv(CCProtocolPacker.sha256())

    assert chk == hashlib.sha256(data).digest(), 'bad hash'

    # clear screen / test a degerate case
    dev.send_recv(CCProtocolPacker.upload(256, 256, b''))

@pytest.mark.parametrize('pkt_len', [256, 1024, 2048])
def test_upload_long(dev, pkt_len, count=5, data=None):
    # upload a larger "file"

    data = data or os.urandom(pkt_len * count)

    for pos in range(0, len(data), pkt_len):
        v = dev.send_recv(CCProtocolPacker.upload(pos, len(data), data[pos:pos+pkt_len]))
        assert v == pos
        chk = dev.send_recv(CCProtocolPacker.sha256())
        assert chk == hashlib.sha256(data[0:pos+pkt_len]).digest(), 'bad hash'

    # clear screen / test a degerate case
    dev.send_recv(CCProtocolPacker.upload(256, 256, b''))

def test_upload_fails(dev):
    # incorrect file upload cases

    data = b'3'*60

    with pytest.raises(CCProtoError):
        # misaligned
        v = dev.send_recv(CCProtocolPacker.upload(23, 23, data))

    with pytest.raises(CCProtoError):
        # bad position
        v = dev.send_recv(CCProtocolPacker.upload(1000, 3, data))

def test_encryption(dev):
    "Setup session key and test link encryption works"

    #dev = ColdcardDevice(sn=force_serial, encrypt=False)
    #dev.start_encryption()

    print("Session key: " + str(b2a_hex(dev.session_key), 'utf'))

    for blen in [4, 8, 60, 128, 256, MAX_MSG_LEN-4]:
        rb = dev.send_recv(CCProtocolPacker.ping(bytes(blen)), encrypt=1)
        assert set(rb) == {0} and len(rb) == blen

        rb = dev.send_recv(CCProtocolPacker.ping(bytes(blen)), encrypt=0)
        assert set(rb) == {0} and len(rb) == blen

    was = dev.session_key
    assert len(was) == 32
    assert len(set(was)) > 8

    # rekey
    dev.start_encryption()
    assert dev.session_key != was
    assert len(set(dev.session_key)) > 8

def test_mitm(dev):
    
    # simple check
    dev.check_mitm()

    # do again
    sig2 = dev.send_recv(CCProtocolPacker.check_mitm(), timeout=5000)
    
    old_key = dev.session_key
    dev.check_mitm(sig=sig2)

    dev.start_encryption()
    assert old_key != dev.session_key

    assert dev.mitm_verify(sig2, dev.master_xpub) == False

def test_remote_upload(dev):
    dev.upload_file(b'testing')
    dev.upload_file(os.urandom(3000))

@pytest.mark.veryslow
@pytest.mark.parametrize('f_len', [256, 1024, 2048, 8196, 384*1024, 2*1024*1024])
def test_remote_up_download(f_len, dev, mk_num):
    if f_len > (384*1024) and mk_num <= 3:
        raise pytest.skip('mk4+ only case')

    data = os.urandom(f_len)
    ll, sha = dev.upload_file(data, verify=True)
    assert ll == len(data) == f_len

    rb = dev.download_file(ll, sha, file_number=0)
    assert rb == data


def test_dwld_offset_at_max(dev, mk_num):
    max_txn = 2*1024*1024
    msg = struct.pack('<4sIII', b'dwld', max_txn, 1, 1)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'bad offset' in str(e.value)

def test_dwld_offset_one_past_max(dev, mk_num):
    max_txn = 2*1024*1024
    msg = struct.pack('<4sIII', b'dwld', max_txn + 1, 1, 1)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'bad offset' in str(e.value)

def test_smsg_zero_length_message(dev):
    subpath = b'm'
    msg = struct.pack('<4sIII', b'smsg', 0x01, len(subpath), 0) + subpath
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'msg too short (min. 2)' in str(e.value)

def test_smsg_oversized_message(dev):
    subpath = b'm'
    raw_msg = b'a' * (MSG_SIGNING_MAX_LENGTH + 1)
    msg = struct.pack('<4sIII', b'smsg', 0x01, len(subpath), len(raw_msg)) + subpath + raw_msg
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'msg too long (max. 240)' in str(e.value)

def test_ncry_invalid_pubkey(dev):
    msg = struct.pack('<4sI64s', b'ncry', 0x01, bytes(64))
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'secp256k1_ec_pubkey_parse' in str(e.value)

@pytest.mark.parametrize("file_no", [0, 1])
def test_dwld_oob_psram_read(file_no, dev, mk_num):
    max_txn = 2*1024*1024
    msg = struct.pack('<4sIII', b'dwld', max_txn - 1, 2, file_no)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'bad offset' in str(e.value)

def test_p2sh_truncated_xfp_paths(dev):
    AF_P2SH = 0x08
    header = struct.pack('<IBBH', AF_P2SH, 1, 2, 30)
    script = bytes(30)
    xfp0 = struct.pack('<BI', 1, 0xDEADBEEF)   # one uint32
    msg = b'p2sh' + header + script + xfp0
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_p2sh_xfp_path_data_too_short(dev):
    AF_P2SH = 0x08
    header = struct.pack('<IBBH', AF_P2SH, 1, 2, 30)
    script = bytes(30)
    xfp0 = struct.pack('<BI', 1, 0xDEADBEEF)
    xfp1_ln = struct.pack('<B', 2)
    msg = b'p2sh' + header + script + xfp0 + xfp1_ln
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_rest_zero_file_len(dev):
    empty_sha = hashlib.sha256(b'').digest()
    msg = b'rest' + struct.pack('<I32sB', 0, empty_sha, 0)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_rest_oversized_file_len(dev):
    empty_sha = hashlib.sha256(b'').digest()
    max_txn_len = 2 * 1024 * 1024
    msg = b'rest' + struct.pack('<I32sB', max_txn_len + 1, empty_sha, 0)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_upld_zero_total_size(dev):
    msg = struct.pack('<4sII', b'upld', 0, 0)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'long' in str(e.value)

def test_upld_short_args(dev):
    msg = b'upld' + struct.pack('<I', 0)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_ncry_short_args(dev):
    msg = b'ncry' + struct.pack('<I', 1)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_stxn_short_args(dev):
    msg = b'stxn' + struct.pack('<II', 100, 0)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_smsg_short_args(dev):
    msg = b'smsg' + struct.pack('<II', 0, 5)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_enrl_short_args(dev):
    msg = b'enrl' + struct.pack('<I', 200)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_rest_short_args(dev):
    msg = b'rest' + struct.pack('<I', 100)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_show_short_args(dev):
    msg = b'show'
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_p2sh_short_args(dev):
    msg = b'p2sh' + struct.pack('<I', 0x08)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)


def test_dwld_short_args(dev):
    msg = b'dwld' + struct.pack('<II', 0, 256)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_msck_short_args(dev):
    msg = b'msck' + struct.pack('<II', 1, 2)
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'buffer too small' in str(e.value)

def test_dwld_trailing_garbage(dev):
    msg = b'dwld' + struct.pack('<III', 0, 256, 0) + b'\xff'  # 13 bytes, need exactly 12
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_ncry_trailing_garbage(dev):
    msg = b'ncry' + struct.pack('<I', 1) + bytes(64) + b'\xff'  # 69 bytes, need exactly 68
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_enrl_trailing_garbage(dev):
    msg = b'enrl' + struct.pack('<I', 200) + bytes(32) + b'\xff'  # 37 bytes, need exactly 36
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_msck_trailing_garbage(dev):
    msg = b'msck' + struct.pack('<III', 1, 2, 0xAB) + b'\xff'  # 13 bytes, need exactly 12
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_stxn_trailing_garbage(dev):
    msg = b'stxn' + struct.pack('<II', 100, 0) + bytes(32) + b'\xff'  # 41 bytes, need exactly 40
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

def test_rest_trailing_garbage(dev):
    empty_sha = hashlib.sha256(b'').digest()
    msg = b'rest' + struct.pack('<I32sB', 100, empty_sha, 0) + b'\xff'  # 38 bytes, need exactly 37
    with pytest.raises(CCProtoError) as e:
        dev.send_recv(msg, encrypt=False)
    assert 'badlen' in str(e.value)

# EOF
