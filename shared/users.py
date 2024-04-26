# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# users.py
#
# Users, passwords and management of same. Primarily for HSM feature.
#

import ustruct, ngu
from public_constants import USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_HMAC, USER_AUTH_SHOW_QR
from public_constants import MAX_USERNAME_LEN, PBKDF2_ITER_COUNT
from menu import MenuSystem, MenuItem
from ucollections import namedtuple
from ux import ux_dramatic_pause, ux_show_story, ux_confirm
from glob import settings

# accepting strings and strings, returning bytes when decoding, str when encoding (ie. correct)
b32encode = ngu.codecs.b32_encode
b32decode = ngu.codecs.b32_decode

hmac_sha256 = ngu.hmac.hmac_sha256

# to keep menus and such to a reasonable size
MAX_NUMBER_USERS = const(30)

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

    md = ngu.hmac.hmac_sha1(secret, msg)

    o = md[19] & 15
    token = ustruct.unpack('>I', md[o:o + 4])[0] & 0x7fffffff

    # return lowest 6 digits
    return '%06d' % (token % 1000000)

def calc_hmac_key(text_password):
    # Calculate a 32-byte key based on user's text password, PBKDF2_ITER_COUNT,
    # and device serial number as salt.
    # - before v4, this was pbkdf2_sha256
    import version

    salt = ngu.hash.sha256s(b'pepper' + version.serial_number().encode())
    pw = ngu.hash.pbkdf2_sha512(text_password, salt, PBKDF2_ITER_COUNT)

    return pw[0:32]

def calc_local_pincode(psbt_sha, hmac_secret):
    # Given a b64 encoded secret (shared from CC over USB) and the PSBT
    # being authorized, cook up 6 digits for local PIN code
    from ubinascii import a2b_base64
    key = a2b_base64(hmac_secret)
    assert len(psbt_sha) == 32
    digest = hmac_sha256(key, psbt_sha)

    num = ustruct.unpack('>I', digest[-4:])[0] & 0x7fffffff
    return '%06d' % (num % 1000000)
    

# settings key
KEY = 'usr'

# - storing: [authmode, base32(secret), last_counter] in a map keyed by username
UserInfo = namedtuple('UserInfo', 'auth_mode secret last_counter')

class Users:
    '''Track users and thier TOTP secrets or hashed passwords'''    

    @classmethod
    def get(cls):
        rv = settings.get(KEY)
        return rv or dict()

    @classmethod
    def lookup(cls, username):
        # find by username, and return details.
        rv = cls.get().get(username, None)
        return UserInfo(*rv) if rv else None

    @classmethod
    def update_counter(cls, username, cnt):
        t = cls.get()
        assert username in t
        t[username][2] = cnt
        settings.changed()

    @classmethod
    def valid_username(cls, username):
        return bool(cls.get().get(username, False))

    @classmethod
    def list(cls):
        return list(sorted(cls.get().keys()))
        
    @classmethod
    def create(cls, username, auth_mode, secret):
        # create new user:
        # - username must be unique
        # - if secret is empty, we pick it and return choice
        # - show QR of secret (for TOTP/HOTP) if 
        qr_mode = bool(auth_mode & USER_AUTH_SHOW_QR)
        if qr_mode:
            auth_mode &= ~USER_AUTH_SHOW_QR
            assert not secret

        assert auth_mode in {USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_HMAC}

        # validate username; 
        assert 1 < len(username) <= MAX_USERNAME_LEN, 'badlen'
        assert username[0] != '_', 'reserved'

        # We don't care if it exists, because then it's an update?
        # - but can safely let them reset the counter/totp level??
        # - not sure, so force them to delete on-device first
        # - this check does not allow brute-force search for names (because 
        existing = cls.lookup(username)
        assert not existing, "exists"

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
        assert len(u) < MAX_NUMBER_USERS, 'too many'
        u[username] = [auth_mode, b32encode(secret), 0]
        settings.put(KEY, u)

        if qr_mode:
            # can only show up to 42 chars, and secret is 16, required overhead is 23 => 39 min
            # - can't fit any meta data, like username or our serial # in there
            # - HOTP not compliant because 'counter=0' not included (works in FreeOTP)
            # - XXX could be better on Q1 but HSM not supported at release anyway?
            from ux import abort_and_push, the_ux
            from qrs import QRDisplaySingle

            if auth_mode == USER_AUTH_HMAC:
                qr = picked
            else:
                qr = 'otpauth://{m}otp/CC?secret={s}'.format(s=picked,
                        m=('t' if auth_mode==USER_AUTH_TOTP else 'h'))

            o = QRDisplaySingle([qr], False, sidebar=(picked, 4))
            abort_and_push(o)

            picked = ''

        return picked
        
    @classmethod
    def delete(cls, username):
        # remove a user. simple. no checking
        u = cls.get()
        u.pop(username, None)
        settings.put(KEY, u)

    @classmethod
    def pick_secret(cls, auth_mode):
        # always 10 bytes for no reason => 80 bits of entropy
        # return binary secret, and encoded value for new user to see
        import ckcc
        b = bytearray(10)
        ckcc.rng_bytes(b)
        picked = b32encode(b)

        if auth_mode == USER_AUTH_HMAC:
            picked = picked.lower()
            b = calc_hmac_key(picked.encode('ascii'))

        return b, picked

    @classmethod
    def auth_okay(cls, username, token, totp_time=None, psbt_hash=None):
        # check a password/totp
        # - where a hash of a PSBT is needed, we use zero; if unknown
        # - return empty string if ok, else problem string
        # - Important SIDE-EFFECT: updates last-counter/totp timestamp if successful

        u = cls.lookup(username)
        if not u:
            return 'unknown user'

        auth_mode, secret, last_counter = u
        secret = b32decode(secret)

        if auth_mode == USER_AUTH_HMAC:
            expect = hmac_sha256(secret, psbt_hash or bytes(32))
            if expect != token:
                return 'mismatch'

            if last_counter == 0:
                # using this as marker that they have successfully used the code once
                cls.update_counter(username, 1)

            return ''

        if len(token) != 6:
            return 'expect otp'

        if auth_mode == USER_AUTH_HOTP:
            # totp_time provided is ignored; use own counter; but perhaps
            # they fumbled a bit and wasted a few codes, so give forward leeway
            candidates = [last_counter+i for i in range(1, 10)]

            if not last_counter:
                candidates.append(0)
        else:
            # time based: try back a few slots, but only if not already used up
            if totp_time < 52622505:
                # above is time when I wrote the code, so must be after that
                return 'range'

            if totp_time <= last_counter:
                return 'replay'

            candidates = [(totp_time-i) for i in range(0, 3)
                                    if (totp_time-i) > last_counter]
            if not candidates:
                return 'replay'

        for c in candidates:
            expect = calc_hotp(secret, c).encode('ascii')

            #print('expect=%r got=%r cnt=%d last=%d' % (expect, token, c, last_counter))

            if expect == token:
                # success, need to update last counter level seen (especially for HOTP,
                # but also to resist replay for TOTP)
                cls.update_counter(username, c)
                return ''

        return 'mismatch'

##
## Menu Stuff
##

class UsersMenu(MenuSystem):

    @classmethod
    def construct(cls):
        # Dynamic menu with user-defined user names
        async def no_users_yet(*a):
            # action for 'no wallets yet' menu item
            await ux_show_story("You don't have any user accounts defined yet. USB is used to define new users, and their associated secrets.")

        users = Users.list()
        if not users:
            rv = [MenuItem('(no users yet)', f=no_users_yet)]
        else:
            rv = [MenuItem('%d user%s:' % (len(users), 's' if len(users) != 1 else ''))]
            for u in users:
                rv.append(MenuItem('"%s"' % u, menu=make_user_sub_menu, arg=u))

        return rv

    def update_contents(self):
        # Reconstruct the list of users on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)


async def make_users_menu(*a):
    # list of all users, and maybe high-level settings/actions
    rv = UsersMenu.construct()
    return UsersMenu(rv)

async def make_user_sub_menu(menu, label, item):
    # details, actions on single multisig wallet
    user = item.arg

    async def delete_user(menu, label, item):
        if not await ux_confirm('Delete user:\n %s\n' % item.arg):
            return

        Users.delete(item.arg)
        await ux_dramatic_pause('Deleted.', 3)

        from ux import the_ux
        the_ux.pop()
        m = the_ux.top_of_stack()
        m.update_contents()

    # get details: not much
    info = Users.lookup(user)
    if not info:
        return

    if info.auth_mode == USER_AUTH_TOTP:
        dets = "TOTP: " + ('unused' if not info.last_counter else 'active')
    elif info.auth_mode == USER_AUTH_HOTP:
        dets = "HOTP: count=%d" % info.last_counter
    elif info.auth_mode == USER_AUTH_HMAC:
        dets = "Password: " + ('unused' if not info.last_counter else 'active')

    rv = [
        MenuItem('"%s"' % user),        # does nothing, it's a title
        MenuItem(dets),
        MenuItem('Delete User', f=delete_user, arg=user),
    ]

    return rv

# EOF
