# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# stash.py - encoding the ultrasecrets: bip39 seeds and words
#
# references:
# - <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
# - <https://iancoleman.io/bip39/#english>
# - zero values:
#    - 'abandon' * 23 + 'art'
#    - 'abandon' * 17 + 'agent'
#    - 'abandon' * 11 + 'about'
#
import ngu, uctypes, gc, bip39, utime
from uhashlib import sha256
from utils import swab32, call_later_ms, B2A


class ZeroSecretException(ValueError):
    # raised when there is no secret or secret is zero
    pass

def blank_object(item):
    # Use/abuse uctypes to blank objects under python. Will likely
    # even work on immutable types, so be careful. Also works
    # well to kill references to sensitive values (but not copies).
    #
    if isinstance(item, (bytearray, bytes, str)):
        addr, ln = uctypes.addressof(item), len(item)
        buf = uctypes.bytearray_at(addr, ln)
        for i in range(ln):
            buf[i] = 0
    elif isinstance(item, ngu.hdnode.HDNode):
        item.blank()
    elif item is None:
        pass
    else:
        raise TypeError(item)

def len_to_numwords(vlen):
    # map length of binary secret to number of BIP-39 seed words
    assert vlen in [16, 24, 32]
    return 6 * (vlen // 8)

def numwords_to_len(num_words):
    # map number of BIP-39 seed words to length of binary secret
    assert num_words in [12, 18, 24]
    return (num_words * 8) // 6

class SecretStash:
    # Chip can hold 72-bytes as a secret: we need to store either
    # a list of seed words (packed), of various lengths, or maybe
    # a raw master secret, and so on.

    @staticmethod
    def encode(seed_phrase=None, master_secret=None, xprv=None):
        nv = bytearray(72)      # AE_SECRET_LEN

        if seed_phrase:
            # typical: packed version of memonic phrase
            vlen = len(seed_phrase)

            assert vlen in [16, 24, 32]
            nv[0] = 0x80 | ((vlen // 8) - 2)
            nv[1:1+vlen] = seed_phrase

        elif master_secret:
            # between 128 and 512 bits of master secret for BIP-32 key derivation
            vlen = len(master_secret)
            assert 16 <= vlen <= 64
            nv[0] = vlen
            nv[1:1+vlen] = master_secret

        elif xprv:
            # master xprivkey, which could be a subkey of something we don't know
            # - we record only the minimum
            assert isinstance(xprv, ngu.hdnode.HDNode)
            nv[0] = 0x01
            nv[1:33] = xprv.chain_code()
            nv[33:65] = xprv.privkey()

        return nv

    @staticmethod
    def decode(secret, _bip39pw=''):
        # expecting 72-bytes of secret payload; decode contents into objects
        # returns:
        #    type, secrets bytes, HDNode(root)
        #
        marker = secret[0]

        hd = ngu.hdnode.HDNode()

        if marker == 0x01:
            # xprv => BIP-32 private key values
            ch, pk = secret[1:33], secret[33:65]
            assert not _bip39pw

            hd.from_chaincode_privkey(ch, pk)
            return 'xprv', ch+pk, hd

        elif marker & 0x80:
            # seed phrase
            ll = ((marker & 0x3) + 2) * 8

            # note: 
            # - byte length > number of words
            # - not storing checksum
            assert ll in [16, 24, 32]

            # make master secret, using the memonic words, and passphrase (or empty string)
            seed_bits = secret[1:1+ll]

            # slow: 2+ seconds
            ms = bip39.master_secret(bip39.b2a_words(seed_bits), _bip39pw)

            hd.from_master(ms)

            return 'words', seed_bits, hd

        elif marker == 0x00:
            # probably all zeros, which we don't normally store, and represents "no secret"
            raise ZeroSecretException
        else:
            # variable-length master secret for BIP-32
            vlen = secret[0]
            assert 16 <= vlen <= 64
            assert not _bip39pw

            ms = secret[1:1+vlen]
            hd = hd.from_master(ms)

            return 'master', ms, hd

    @staticmethod
    def storage_serialize(secret):
        # make it a JSON-compatible field
        return B2A(bytes(secret).rstrip(b"\x00"))

    @staticmethod
    def summary(marker):
        # decode enough to explain what we have in a text form
        # - give us the first byte of the stored, encoded secret
        if marker == 0x01:
            # xprv => BIP-32 private key values
            return 'xprv'

        if marker & 0x80:
            # seed phrase
            ll = ((marker & 0x3) + 2) * 8
            return '%d words' % len_to_numwords(ll)

        if marker == 0x00:
            # probably all zeros, which we don't normally store, and represents "no secret"
            return 'zeros'

        # variable-length master secret for BIP-32
        return '%d bytes' % marker

# optional global value: user-supplied passphrase to salt BIP-39 seed process
# just a boolean flag from version 5.2.0
bip39_passphrase = False

CACHE_CHECK_RATE = const(10*1000)   # 10 seconds
CACHE_MAX_LIFE = const(60*1000)     # one minute

class SensitiveValues:
    # be a context manager, and holder of secrets in-memory

    # class-level cache
    _cache_secret = None
    _cache_used = None

    def __init__(self, secret=None, bip39pw='', bypass_tmp=False):
        self.spots = []

        self._bip39pw = bip39pw

        if secret is not None:
            # sometimes we already know the secret
            self.secret = secret
            self.deltamode = False

            self.mode, self.raw, self.node = SecretStash.decode(self.secret, self._bip39pw)
        else:
            # More typical: fetch the secret from bootloader and SE
            # - but that's real slow, so avoid if possible
            from pincodes import pa

            if not pa.has_secrets():
                raise ZeroSecretException
            self.deltamode = pa.is_deltamode()

            if self._cache_secret and not bypass_tmp:
                # they are using new BIP39 passphrase but we already have raw secret
                self.secret = bytearray(self._cache_secret)
            else:
                # slow: read from secure element(s)
                self.secret = pa.fetch(bypass_tmp=bypass_tmp)

            # slow: do bip39 key stretching (typically)
            self.mode, self.raw, self.node = SecretStash.decode(self.secret, self._bip39pw)

            if not bypass_tmp:
                # DO NOT save to cache if we are bypassing tmp
                # we mostly just need it for some  specific
                # operation after which we go back to tmp
                self.save_to_cache()

            self.spots.append(self.secret)

        self.spots.append(self.raw)
        self.spots.append(self.node)

        import chains
        self.chain = chains.current_chain()

    @classmethod
    def clear_cache(cls):
        # clear cached secrets we have
        # - call any time, certainly when main secret changes
        # - will be called after 2 minutes of idle keypad
        blank_object(cls._cache_secret)
        cls._cache_secret = None
        cls._cache_used = None

    def save_to_cache(self):
        # add to cache, must copy here to avoid wipe
        if not self._cache_secret:
            SensitiveValues._cache_secret = bytearray(self.secret)
        else:
            assert SensitiveValues._cache_secret == self.secret

        SensitiveValues._cache_used = utime.ticks_ms()

        call_later_ms(CACHE_CHECK_RATE, self.cache_check)

    @classmethod
    def cache_secret(cls, main_secret):
        # During login we learn the main secret so we can decrypt
        # the settings, so want to catch that in cache since user is likely
        # to do something useful immediately after login
        SensitiveValues._cache_used = utime.ticks_ms()

        if cls._cache_secret:
            assert SensitiveValues._cache_secret == main_secret
            return

        SensitiveValues._cache_secret = bytearray(main_secret)
        call_later_ms(CACHE_CHECK_RATE, cls.cache_check)

    @classmethod
    async def cache_check(cls):
        # verify the cache has been used recently, else clear it.

        if not cls._cache_used:
            # called after already cleared
            return

        now = utime.ticks_ms() 
        dt = utime.ticks_diff(now, cls._cache_used)

        if dt >= CACHE_MAX_LIFE:
            # clear cached secrets after 1 minute if unused
            cls.clear_cache()
        else:
            # keep waiting
            call_later_ms(CACHE_CHECK_RATE, cls.cache_check)

    def __enter__(self):
        # complexity moved to __init__
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clear secrets from memory ... yes, they could have been
        # copied elsewhere, but in normal case, at least we blanked them.
        for item in self.spots:
            blank_object(item)

        if hasattr(self, 'secret'):
            # will be blanked from above
            del self.secret

        if hasattr(self, 'node'):
            # specialized blanking code already above
            del self.node

        # just in case this holds some pointers?
        del self.spots

        # .. and some GC will help too!
        gc.collect()

        if exc_val:
            # An exception happened, but we've done cleanup already now, so 
            # not a big deal. Cause it be raised again.
            return False

        return True

    def capture_xpub(self):
        # track my xpubkey fingerprint & xpub value in settings (not sensitive really)
        # - we share these on any USB connection
        from glob import settings

        # Implicit in the values is the BIP-39 encryption passphrase,
        # which we not want to actually store.
        xfp = swab32(self.node.my_fp())
        xpub = self.chain.serialize_public(self.node)

        settings.put('xfp', xfp)
        settings.put('xpub', xpub)
        settings.put('chain', self.chain.ctype)

        # calc num words in seed, or zero
        nw = 0
        if self.mode == 'words':
            nw = len_to_numwords(len(self.raw))
        settings.put('words', nw)

        return xfp

    def register(self, item):
        # Caller can add his own sensitive (derived?) data to our wiper
        # typically would be byte arrays or byte strings, but also
        # supports bip32 nodes
        self.spots.append(item)

    def derive_path(self, path, master=None, register=True):
        # Given a string path, derive the related subkey
        rv = (master or self.node).copy()

        if register:
            self.register(rv)

        for i in path.split('/'):
            if i == 'm': continue
            if not i: continue      # trailing or duplicated slashes

            if i[-1] in "h'":
                assert len(i) >= 2
                is_hard = True
                here = int(i[:-1])
            else:
                here = int(i)
                is_hard = False

            assert 0 <= here < 0x80000000
            rv.derive(here, is_hard)

        return rv

    def duress_root(self):
        # Return a bip32 node for the duress wallet linked to this wallet.
        # 0x80000000 - 0xCC10 = 2147431408
        # Obsoleted in Mk4: use BIP-85 instead
        p = "m/2147431408h/0h/0h"
        dirty = self.derive_path(p)

        # clear the parent linkage by rebuilding it.
        cc, pk = dirty.chain_code(), dirty.privkey()
        self.register(cc)
        self.register(pk)

        rv = ngu.hdnode.HDNode()
        rv.from_chaincode_privkey(cc, pk)
        self.register(rv)

        return rv, p

    def encryption_key(self, salt):
        # Return a 32-byte derived secret to be used for our own internal encryption purposes
        # 0x80000000 - 0xCC30 = 2147431376
        node = self.derive_path("m/2147431408h/0h")     # plan: 0h will be an index for other apps

        acc = sha256(salt)
        acc.update(node.privkey())
        acc.update(salt)

        pk = ngu.hash.sha256s(acc.digest())

        self.register(pk)
        return pk

    def encoded_secret(self):
        # we do not support master as secret - only extended keys and mnemonics
        if self.mode == "xprv":
            nv = SecretStash.encode(xprv=self.node)
        else:
            assert self.mode == "words"
            nv = SecretStash.encode(seed_phrase=self.raw)
        return nv

# EOF
