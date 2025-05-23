# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Key Teleport protocol re-implementation.
#
import os, pyaes, hashlib, base64
from bip32 import BIP32Node, PrvKeyNode
from mnemonic import Mnemonic
from pysecp256k1 import ec_seckey_verify, ec_pubkey_serialize, ec_pubkey_parse
from pysecp256k1.extrakeys import keypair_create, keypair_sec, keypair_pub
from pysecp256k1.ecdh import ecdh, ECDH_HASHFP_CLS


wordlist = Mnemonic('english').wordlist

def py_ckcc_hashfp(output, x, y, data=None):
    try:
        m = hashlib.sha256()
        m.update(x.contents.raw)
        m.update(y.contents.raw)
        output.contents.raw = m.digest()
        return 1
    except:
        return 0

ckcc_hashfp = ECDH_HASHFP_CLS(py_ckcc_hashfp)


def txt_grouper(txt):
    # split into 2-char groups and add spaces -- to make it easier to read/remember
    return ' '.join(txt[n:n+2] for n in range(0, len(txt), 2))

def stash_encode_secret(words=None, xprv=None):
    nv = bytearray(72)
    if words:
        wlen = len(words.split(" "))
        assert wlen in [12, 18, 24]
        entropy = Mnemonic('english').to_entropy(words)
        nv[0] = (0x80 | ((len(entropy) // 8) - 2))
        nv[1:1 + wlen] = entropy

    elif xprv:
        node = BIP32Node.from_wallet_key(xprv)
        nv[0] = 0x01
        nv[1:33] = node.chain_code()
        nv[33:65] = node.privkey()

    # trim zeros
    while nv[-1] == 0:
        nv = nv[0:-1]

    return nv

def stash_decode_secret(secret_bytes):
    marker = secret_bytes[0]

    if marker == 0x01:
        ch, pk = secret_bytes[1:33], secret_bytes[33:65]
        n = PrvKeyNode(pk, ch)
        node = BIP32Node(netcode='BTC', node=n)
        return "xprv", node.hwif(as_private=True)

    elif marker & 0x80:
        # seed phrase
        ll = ((marker & 0x3) + 2) * 8
        assert ll in [16, 24, 32]

        # make master secret, using the memonic words, and passphrase (or empty string)
        seed_bits = secret_bytes[1:1 + ll]

        return "words", Mnemonic('english').to_mnemonic(seed_bits)


def generate_rx_code(kp):
    # Receiver-side password: given a pubkey (33 bytes, compressed format)
    # - construct an 8-digit decimal "password"
    # - it's an AES key, but only 26 bits worth
    pubkey = bytearray(ec_pubkey_serialize(keypair_pub(kp), compressed=True))

    # - want the code to be deterministic, but I also don't want to save it
    # - double sha256 TODO why ? single sha is imo enough and twice as fast
    nk = hashlib.sha256(hashlib.sha256(keypair_sec(kp) + b'COLCARD4EVER').digest()).digest()

    # first byte will be 0x02 or 0x03 (Y coord) -- remove those known 7 bits
    pubkey[0] ^= nk[20] & 0xfe

    num = '%08d' % (int.from_bytes(nk[4:8], 'big') % 1_0000_0000)

    # encryption after baby key stretch
    kk = hashlib.sha256(num.encode()).digest()

    enc = pyaes.AESModeOfOperationCTR(kk, pyaes.Counter(0)).encrypt
    ciphertext = enc(bytes(pubkey))

    return num, ciphertext


def decrypt_rx_pubkey(code, payload):
    # given an 8-digit numeric code, make the key and then decrypt/checksum check
    # - every value works, there is no fail.
    kk = hashlib.sha256(code.encode()).digest()
    dec = pyaes.AESModeOfOperationCTR(kk, pyaes.Counter(0)).decrypt
    rx_pubkey = bytearray(dec(payload))

    # first byte will be 0x02 or 0x03 but other 7 bits are noise
    rx_pubkey[0] &= 0x01
    rx_pubkey[0] |= 0x02

    pubkey = bytes(rx_pubkey)

    # validate that it's on the curve... otherwise the code is wrong
    try:
        ec_pubkey_parse(pubkey)
        return pubkey
    except:
        return None


def pick_noid_key():
    # pick an 40 bit password, shown as base32
    # - on rx, libngu base32 decoder will convert '018' into 'OLB'
    # - but a little tempted to removed vowels here?
    # TODO what about base64.b32encode
    k = os.urandom(5)
    txt = base64.b32encode(k).decode()
    return k, txt


def noid_stretch(session_key, noid_key):
    return hashlib.pbkdf2_hmac('sha512', session_key, noid_key, 5000)[0:32]


def encode_payload(my_keypair, his_pubkey, noid_key, body, for_psbt=False):
    assert len(his_pubkey) == 33
    assert len(noid_key) == 5

    session_key = ecdh(keypair_sec(my_keypair), ec_pubkey_parse(his_pubkey), hashfp=ckcc_hashfp)

    # stretch noid key out -- will be slow
    pk = noid_stretch(session_key, noid_key)

    enc = pyaes.AESModeOfOperationCTR(pk, pyaes.Counter(0)).encrypt
    b1 = enc(body)
    b1 += hashlib.sha256(body).digest()[-2:]

    enc = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).encrypt
    b2 = enc(b1)
    b2 += hashlib.sha256(b1).digest()[-2:]

    if for_psbt:
        # no need to share pubkey for PSBT files
        return b2

    return ec_pubkey_serialize(keypair_pub(my_keypair)) +  b2

def decode_step1(my_keypair, his_pubkey, body):
    # Do ECDH and remove top layer of encryption
    try:
        session_key = ecdh(keypair_sec(my_keypair), ec_pubkey_parse(his_pubkey), hashfp=ckcc_hashfp)
        dec = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).decrypt
        rv = dec(body[:-2])
        chk = hashlib.sha256(rv).digest()[-2:]
        assert chk == body[-2:]         # likely means wrong rx key, or truncation
    except:
        return None, None

    return session_key, rv

def decode_step2(session_key, noid_key, body):
    assert len(noid_key) == 5
    pk = noid_stretch(session_key, noid_key)
    dec = pyaes.AESModeOfOperationCTR(pk, pyaes.Counter(0)).decrypt
    msg = dec(body[:-2])
    chk = hashlib.sha256(msg).digest()[-2:]
    return msg if chk == body[-2:] else None

def receiver_step1(secret=None):
    if secret is None:
        secret = os.urandom(32)
    ec_seckey_verify(secret)
    kpr = keypair_create(secret)
    num, payload = generate_rx_code(kpr)
    return num, payload, kpr

def sender_step1(num_pwd, encrypted_pubkey, to_send, secret=None):
    pkr = decrypt_rx_pubkey(num_pwd, encrypted_pubkey)

    # Pick and show noid key to sender
    noid_key, noid_txt = pick_noid_key()

    if secret is None:
        secret = os.urandom(32)

    ec_seckey_verify(secret)
    kps = keypair_create(secret)

    # "to_send" has to be properly encoded (dtype + what)
    payload = encode_payload(kps, pkr, noid_key, to_send)
    return noid_txt, payload, kps, pkr

def receiver_step2(teleport_pwd, payload, keypair):
    assert len(teleport_pwd) == 8
    noid_key = base64.b32decode(teleport_pwd)
    his_pubkey = payload[0:33]
    body = payload[33:]

    session_key, body = decode_step1(keypair, his_pubkey, body)
    final = decode_step2(session_key, noid_key, body)
    if final:
        return chr(final[0]), final[1:]
    else:
        return None, None


def selftest():
    # WORDS
    # RECEIVER INIT
    number_pass, enc_pubkey, kp_receiver = receiver_step1()

    # SENDER
    # what are we sending ?
    words = "talk retire wisdom poet actress hood goose case amateur zebra analyst radar"
    cleartext = b"s" + stash_encode_secret(words=words)
    noid_txt, encrypted_payload, kp_sender, pk_rec = sender_step1(number_pass, enc_pubkey, cleartext)

    # check we properly decrypted receiver pubkey
    assert pk_rec == ec_pubkey_serialize(keypair_pub(kp_receiver))

    # RECEIVER STEP2
    _, received = receiver_step2(noid_txt, encrypted_payload, kp_receiver)
    assert words == stash_decode_secret(received)[1]
    # ===

    # XPRV
    # RECEIVER INIT
    number_pass, enc_pubkey, kp_receiver = receiver_step1()

    # SENDER
    # what are we sending ?
    xprv = "xprv9s21ZrQH143K4BwRCYKSEPwcAMYweWkfKLURabnnv2GLNhJN1LSCgDQyGWyNcat72najQKwyshCBXWfHHVbcdxPAZPqByMyWDbWp5SjCfEa"
    cleartext = b"s" + stash_encode_secret(xprv=xprv)
    noid_txt, encrypted_payload, kp_sender, pk_rec = sender_step1(number_pass, enc_pubkey, cleartext)

    # check we properly decrypted receiver pubkey
    assert pk_rec == ec_pubkey_serialize(keypair_pub(kp_receiver))

    # RECEIVER STEP2
    _, received = receiver_step2(noid_txt, encrypted_payload, kp_receiver)
    assert xprv == stash_decode_secret(received)[1]
    # ===

    print("Selftest passed.")

if __name__ == "__main__":
    selftest()

# EOF
