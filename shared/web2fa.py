# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# web2fa.py -- Bounce a shared secret off a Coinkite server to allow mobile app 2FA.
#
#
import ngu, ndef, aes256ctr
from ustruct import pack, unpack
from utils import b2a_base64url, url_quote, B2A
from version import has_qr
from ux import show_qr_code, ux_show_story, X, OK

# Only Coldcard.com server knows private key for this pubkey. It protects
# the privacy of the values we send to the server.
#
# = 0231301ec4acec08c1c7d0181f4ffb8be70d693acccc86cccb8f00bf2e00fcabfd
SERVER_PUBKEY = b'\x02\x31\x30\x1e\xc4\xac\xec\x08\xc1\xc7\xd0\x18\x1f\x4f\xfb\x8b\xe7\x0d\x69\x3a\xcc\xcc\x86\xcc\xcb\x8f\x00\xbf\x2e\x00\xfc\xab\xfd'

def encrypt_details(qs):
    # encryption and base64 here
    # - pick single-use ephemeral secp256k1 keypair
    # - do ECDH to generate a shared secret based on known pubkey of server
    # - AES-256-CTR encryption based on that
    # - base64url encode result

    # pick a random key pair, just for this session
    pair = ngu.secp256k1.keypair()
    my_pubkey = pair.pubkey().to_bytes(False)        # compressed format

    session_key = pair.ecdh_multiply(SERVER_PUBKEY)
    del pair

    enc = aes256ctr.new(session_key).cipher

    return b2a_base64url(my_pubkey + enc(qs.encode('ascii')))

async def perform_web2fa(label, shared_secret):

    # send them to web, prompt for valid response. Return True if it all worked.
    expect = await nfc_share_2fa_link(label, shared_secret)
    if not expect:
        # aborted at NFC step
        return False

    if has_qr:
        # Make them scan the result, for example:
        # 
        #   CCC-AUTH:E902B3DAF2D98040F3A5F556D7CCC7C22BF3D455C146C4D4C0F7CF8B7937C530
        #
        from ux_q1 import QRScannerInteraction
        from exceptions import QRDecodeExplained

        prefix = 'CCC-AUTH:'
        scanner = QRScannerInteraction()

        def validate(got):
            if not got.startswith(prefix):
                raise QRDecodeExplained("QR isn't from our site")
            if got != prefix+expect:
                # probably attempted replay
                raise QRDecodeExplained("Incorrect code?")
            return got

        data = await scanner.scan_general('Scan QR shown from Web', validate)
        if not data:
            return False    # pressed cancel

        # only one legal response possible, and already validated above
        return (data == prefix+expect)

    else:
        #
        # Mk4 and other devices w/o QR scanner, require user to enter 8 digits
        #
        from ux_mk4 import ux_input_digits

        def limit_len(n):
            ll = len(n)
            if ll == 8:
                return n
            if ll > 8:
                return n[0:8]
            return ''

        while 1:
            got = await ux_input_digits('', limit_len, maxlen=8, prompt="8-digits From Web")

            if not got:
                # abort if empty entry
                return False

            if got == expect:
                # good match
                return True

            ch = await ux_show_story("You entered an incorrect code. You must enter the digits shown after the correct 2FA code is provided to the website. Try again or (X) to stop.")
            if ch == 'x':
                return False

    # not reached
    return False
    

async def web2fa_enroll(label, ss=None):
    #
    # Enroll: Pick a secret and test they have loaded it into their phone.
    #

    # must have NFC tho
    from flow import feature_requires_nfc
    if not await feature_requires_nfc():
        # they don't want to proceed
        return None

    # Pick a shared secret; 10 bytes, so encodes to 16 base32 chars
    ss = ss or ngu.codecs.b32_encode(ngu.random.bytes(10))

    # show a QR that app know how to use
    # - problem: on Mk4, not really enough space:
    #  - can only show up to 42 chars, and secret is 16, required overhead is 23 => 39 min
    #  - can't fit any meta data, like username or our serial # in there
    # - better on Q1 where no limitations for this size of QR

    qr = 'otpauth://totp/{nm}?secret={ss}'.format(ss=ss, 
                nm=url_quote(label if has_qr else label[0:4]))

    while 1:
        # show QR for enroll
        await show_qr_code(qr, is_alnum=False, msg="Import into 2FA Mobile App")

        # important: force them to prove they store it correctly
        ok = await perform_web2fa('Enroll: ' + label, ss)
        if ok: break

        ch = await ux_show_story("That isn't correct. Please re-import and/or "\
                                    "try again or %s to give up." % X)
        if ch == 'x':
            # mk4 only?
            return None

    return ss

def make_web2fa_url(wallet_name, shared_secret):
    # Build complex URL into our server w/ encrypted data
    # - picking a nonce in the process
    prefix = 'coldcard.com/2fa?'

    # random nonce: if we get this back, then server approves of TOTP answer
    if has_qr:
        # data for a QR
        nonce = B2A(ngu.random.bytes(32)).upper()
    else:
        # 8 digits for human entry
        nonce = '%08d' % ngu.random.uniform(1_0000_0000)

    # compose URL
    qs = 'g=%s&ss=%s&nm=%s&q=%d' % (nonce, shared_secret, url_quote(wallet_name), has_qr)

    # encrypt that
    qs = encrypt_details(qs)

    return nonce, prefix + qs

async def nfc_share_2fa_link(wallet_name, shared_secret):
    #
    # Share complex NFC deeplink into 2fa backend; returns expected response-code.
    # Next step is to prompt for that 8-digit code (mk4) or scan QR (Q)
    #
    from glob import NFC
    assert NFC

    nonce, url = make_web2fa_url(wallet_name, shared_secret)

    n = ndef.ndefMaker()
    n.add_url(url, https=True)

    aborted = await NFC.share_start(n, prompt="Tap for 2FA Authentication", 
                                            line2="Wallet: " + wallet_name)

    return None if aborted else nonce

# EOF
