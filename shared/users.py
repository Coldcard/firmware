# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# users.py
#
# Users, passwords and management of same. Primarily for HSM feature.
#

import ustruct, hmac, tcc
from public_constants import USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_HMAC
from public_constants import MAX_USERNAME_LEN, PBKDF2_ITER_COUNT

# accepting strings and strings, returning bytes when decoding, str when encoding (ie. correct)
b32encode = tcc.codecs.b32_encode
b32decode = tcc.codecs.b32_decode

def calc_hotp(secret, counter):
    '''
    Get HMAC-based one-time password on the basis of given secret and
    interval number (counter).

    [RFC4226](https://tools.ietf.org/html/rfc4226)

    >>> get_hotp(b'abcdefghij', counter=1)
    765705
    >>> get_hotp(b'abcdefghij', counter=2)
    816065
    '''

    assert len(secret) >= 10
    assert counter >= 0

    msg = ustruct.pack('>Q', counter)

    hmac_digest = hmac.new(secret, msg, tcc.sha1).digest()

    o = hmac_digest[19] & 15
    token = ustruct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff

    # return lowest 6 digits
    return '%06d' % (token % 1000000)

def calc_hmac_key(text_password):
    # Calculate a 32-byte key based on user's text password, PBKDF2_ITER_COUNT,
    # and device serial number as salt.
    import version

    salt = tcc.sha256(b'pepper'+version.serial_number().encode()).digest()
    p = tcc.pbkdf2('hmac-sha256', text_password, salt, PBKDF2_ITER_COUNT)

    return p.key()

# settings key
KEY = 'usr'


class Users:
    '''Track users and thier TOTP secrets or hashed passwords'''    
    # - storing: [authmode, base32(secret), last_counter] in map from username

    @classmethod
    def get(cls):
        from main import settings
        rv = settings.get(KEY)
        return rv or dict()

    @classmethod
    def lookup(cls, username):
        return cls.get().get(username, None)

    @classmethod
    def list(cls):
        return list(sorted(cls.get().keys()))
        
    @classmethod
    def create(cls, username, auth_mode, secret=b''):
        # create new user:
        # - username must be unique
        # - if secret is empty, we pick it and return choice
        from main import settings

        assert auth_mode in {USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_HMAC}

        # validate username; don't care if it exists, because then it's an update?
        assert 1 < len(username) <= MAX_USERNAME_LEN, 'badlen'
        # ... but don't let them reset the counter/totp level

        if not secret:
            secret, picked = cls.pick_secret(auth_mode)
        else:
            picked = ''
            if auth_mode == USER_AUTH_HMAC:
                assert len(secret) == 32
            else:
                assert len(secret) in {10, 20}

        # save
        u = cls.get()
        u[username] = [auth_mode, b32encode(secret), 0]
        settings.put(KEY, u)

        return picked
        
    @classmethod
    def delete(cls, username):
        # remove a user. simple. no checking
        from main import settings

        u = cls.get()
        u.pop(username, None)
        settings.put(KEY, u)

    @classmethod
    def pick_secret(cls, auth_mode):
        # always 10 bytes for no reason => 80 bits of entropy
        # return binary secret, and encode value for new user to see
        import ckcc
        b = bytearray(10)
        ckcc.rng_bytes(b)
        picked = b32encode(b)

        if auth_mode == USER_AUTH_HMAC:
            b = calc_hmac_key(picked.encode('ascii'))

        return b, picked

    @classmethod
    def auth_okay(cls, username, token, totp_time=None, psbt_hash=None):
        # check a password/totp
        # - where a hash of a PSBT is needed, we use zero; if unknown
        # - return empty string if ok, else problem string
        from main import settings

        u = cls.lookup(username)
        if not u:
            return 'unknown'

        auth_mode, secret, last_counter = u
        secret = b32decode(secret)

        if auth_mode == USER_AUTH_HMAC:
            expect = hmac.new(secret, psbt_hash or bytes(32), tcc.sha256).digest()
            return 'mismatch' if  expect != token else ''

        if len(token) != 6:
            return 'expect otp'

        if auth_mode == USER_AUTH_HOTP:
            # totp_time provided is ignored; use own counter; but perhaps
            # they fumbled a bit and wasted a few codes
            candidates = [last_counter+i for i in range(1, 10)]

            if not last_counter:
                candidates.append(0)
        else:
            # time based: try back a few slots, but only if not already used
            if totp_time < 52622505:
                # above is time when I wrote the code, so but be after that
                return 'range'

            candidates = [(totp_time-i) for i in range(0, 3)
                                    if (totp_time-i) > last_counter]
            if not candidates:
                return 'replay'

        for c in candidates:
            expect = calc_hotp(secret, c).encode('ascii')

            if expect == token:
                # success, need to update last counter level seen (especially for HOTP,
                # but also to resist replay for TOTP)
                u[2] = c
                settings.changed()
                return ''
        
            print('expect=%r got=%r cnt=%d' % (expect, token, c))

        return 'mismatch'
        

# EOF
