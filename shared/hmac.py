# HMAC (Keyed-Hashing for Message Authentication) Python module.
#
# Implements the HMAC algorithm as described by RFC 2104.
#
# from: https://github.com/micropython/micropython-lib/blob/master/hmac/hmac.py @ 96c981b
# license: https://github.com/micropython/micropython-lib/blob/master/LICENSE

class HMAC:
    """RFC 2104 HMAC class.  Also complies with RFC 4231.

    This supports the API for Cryptographic Hash Functions (PEP 247).
    """
    blocksize = 64  # 512-bit HMAC; can be changed in subclasses.

    def __init__(self, key, msg = None, digestmod = None):
        """Create a new HMAC object.

        key:       key for the keyed hash object.
        msg:       Initial input for the hash, if provided.
        digestmod: A module supporting PEP 247.  *OR*
                   A hashlib constructor returning a new hash object. *OR*

        Note: key and msg must be a bytes or bytearray objects.
        """

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError()

        self.outer = digestmod()
        self.inner = digestmod()
        self.digest_size = self.inner.digest_size

        blocksize = self.inner.block_size
        assert blocksize >= 16

        # self.blocksize is the default blocksize. self.block_size is
        # effective block size as well as the public API attribute.
        self.block_size = blocksize

        if len(key) > blocksize:
            key = digestmod(key).digest()

        def translate(d, t):
            return bytes(t[x] for x in d)

        trans_5C = bytes((x ^ 0x5C) for x in range(256))
        trans_36 = bytes((x ^ 0x36) for x in range(256))

        key = key + bytes(blocksize - len(key))
        self.outer.update(translate(key, trans_5C))
        self.inner.update(translate(key, trans_36))

        if msg is not None:
            self.update(msg)

    def update(self, msg):
        """Update this hashing object with the string msg.
        """
        self.inner.update(msg)

    def _current(self):
        """Return a hash object for the current state.

        To be used only internally with digest() and hexdigest().
        """
        h = self.outer
        h.update(self.inner.digest())
        del self.outer
        del self.inner
        return h

    def digest(self):
        """Return the hash value of this hashing object.

        This returns a string containing 8-bit data.
        Single use only!
        """
        return self._current().digest()

def new(key, msg = None, digestmod = None):
    """Create a new hashing object and return it.

    key: The starting key for the hash.
    msg: if available, will immediately be hashed into the object's starting
    state.

    You can now feed arbitrary strings into the object using its update()
    method, and can ask for the hash value at any time by calling its digest()
    method.
    """
    return HMAC(key, msg, digestmod)

# Useful ones for this project
#import tcc
#hmac_sha256 = lambda key, msg=None: HMAC(key, msg, tcc.sha256)
#hmac_sha1 = lambda key, msg=None: HMAC(key, msg, tcc.sha1)
#hmac_sha512 = lambda key, msg=None: HMAC(key, msg, tcc.sha512)
