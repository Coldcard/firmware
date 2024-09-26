# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests related to CCC feature
#
#
import pytest, requests, re, time, random
from binascii import a2b_hex, b2a_hex
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, parse_qs
from onetimepass import get_totp
from helpers import prandom

# TODO: we will rotate the server key before release.
SERVER_PUBKEY = '036d0f95c3aaf5cd3e8be561b07814fbb1c9ee2171ed301828151975411472a2fd'

def make_session_key(his_pubkey=None):
    # - second call: given the pubkey of far side, calculate the shared pt on curve
    # - creates session key based on that
    from ecdsa.curves import SECP256k1
    from ecdsa import VerifyingKey, SigningKey
    from ecdsa.util import number_to_string
    from hashlib import sha256

    my_key = SigningKey.generate(curve=SECP256k1, hashfunc=sha256)

    his_pubkey = VerifyingKey.from_string(bytes.fromhex(SERVER_PUBKEY),
                                                curve=SECP256k1, hashfunc=sha256)

    # do the D-H thing
    pt = my_key.privkey.secret_multiplier * his_pubkey.pubkey.point

    # final key is sha256 of that point, serialized (64 bytes).
    order = SECP256k1.order
    kk = number_to_string(pt.x(), order) + number_to_string(pt.y(), order)

    return sha256(kk).digest(), my_key.get_verifying_key().to_string('compressed')


@pytest.fixture
def make_2fa_url():
    def doit(shared_secret=b'A'*16, nonce='12345678',
                wallet='Example wallet name', is_q=0, prod=True, encrypted=False):

        base = 'http://127.0.0.1:5070/2fa?' if not prod else 'https://coldcard.com/2fa?'

        assert is_q in {0, 1}
        assert len(shared_secret) == 16     # base32
        assert isinstance(nonce, str)       # hex digits or 8 dec digits in Mk4 mode

        from urllib.parse import quote

        qs = f'ss={shared_secret}&q={is_q}&g={nonce}&nm={quote(wallet)}'

        print(f'2fa URL: {qs}')

        if not encrypted:
            return base + qs

        # pick eph key
        ses_key, pubkey = make_session_key()

        import pyaes
        enc = pyaes.AESModeOfOperationCTR(ses_key, pyaes.Counter(0)).encrypt

        qs = urlsafe_b64encode(pubkey + enc(qs.encode('ascii')))

        return base + qs.decode('ascii')

    return doit

@pytest.fixture
def roundtrip_2fa():
    def doit(url, shared_secret, local=False):
        if local:
            url = url.replace('https://coldcard.com/', 'http://127.0.0.1:5070/')

        if int(time.time() % 30) > 29:
            # avoid end of time period
            time.sleep(3)

        answer = '%06d' % get_totp(shared_secret)
        assert len(answer) == 6

        resp = requests.post(url, data=dict(answer=answer))

        # server HTML will have this line in response for our use
        #   <!--TESTING CCC-AUTH:00000FFF -->

        if '<!--TESTING' not in resp.text:
            raise RuntimeError("server did not accept code")

        ans = re.search('<!--TESTING (\S*)', resp.text).group(1)

        #print(f'Got answer: {ans}')

        return ans

        
    return doit

@pytest.mark.parametrize('shared_secret', [ '6SPAJXWD3XJTUQWO', 'TU3QZ7VFMTJCPSS6' ])
@pytest.mark.parametrize('q_mode', [ True, False] )
@pytest.mark.parametrize('enc', [ True] )
def test_2fa_server(shared_secret, q_mode, make_2fa_url, enc, roundtrip_2fa):

    nonce = prandom(32).hex() if q_mode else str(random.randint(1000_0000, 9999_9999))

    # TODO command line flag to select local coldcard.com or production version

    url = make_2fa_url(shared_secret, nonce, is_q=int(q_mode), encrypted=enc, prod=True)

    #print(url)

    ans = roundtrip_2fa(url, shared_secret)

    assert ans == f'CCC-AUTH:{nonce}'.upper() if q_mode else nonce

    # NOTE: cannot re-start same test until next 30-second period because of rate limiting
    # check on server side.

# EOF
