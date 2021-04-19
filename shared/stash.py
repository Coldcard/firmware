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
import ngu, uctypes, gc, bip39
from uhashlib import sha256
from pincodes import AE_SECRET_LEN
from utils import swab32

def blank_object(item):
    # Use/abuse uctypes to blank objects until python. Will likely
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
    else:
        raise TypeError(item)


# Chip can hold 72-bytes as a secret: we need to store either
# a list of seed words (packed), of various lengths, or maybe
# a raw master secret, and so on

class SecretStash:

    @staticmethod
    def encode(seed_phrase=None, master_secret=None, xprv=None):
        nv = bytearray(AE_SECRET_LEN)

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

        if marker & 0x80:
            # seed phrase
            ll = ((marker & 0x3) + 2) * 8

            # note: 
            # - byte length > number of words
            # - not storing checksum
            assert ll in [16, 24, 32]

            # make master secret, using the memonic words, and passphrase (or empty string)
            seed_bits = secret[1:1+ll]
            ms = bip39.master_secret(bip39.b2a_words(seed_bits), _bip39pw)

            hd.from_master(ms)

            return 'words', seed_bits, hd

        else:
            # variable-length master secret for BIP-32
            vlen = secret[0]
            assert 16 <= vlen <= 64
            assert not _bip39pw

            ms = secret[1:1+vlen]
            hd = hd.from_master(ms)

            return 'master', ms, hd

# optional global value: user-supplied passphrase to salt BIP-39 seed process
bip39_passphrase = ''

class SensitiveValues:
    # be a context manager, and holder to secrets in-memory

    def __init__(self, secret=None, bypass_pw=False):
        if secret is None:
            # fetch the secret from bootloader/atecc508a
            from pincodes import pa

            if pa.is_secret_blank():
                raise ValueError('no secrets yet')

            self.secret = pa.fetch()
            self.spots = [ self.secret ]
        else:
            # sometimes we already know it
            #assert set(secret) != {0}
            self.secret = secret
            self.spots = []

        # backup during volatile bip39 encryption: do not use passphrase
        self._bip39pw = '' if bypass_pw else str(bip39_passphrase)

    def __enter__(self):
        import chains

        self.mode, self.raw, self.node = SecretStash.decode(self.secret, self._bip39pw)

        self.spots.append(self.node)
        self.spots.append(self.raw)

        self.chain = chains.current_chain()

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
        # track my xpubkey fingerprint & value in settings (not sensitive really)
        # - we share these on any USB connection
        from nvstore import settings

        # Implicit in the values is the BIP-39 encryption passphrase,
        # which we might not want to actually store.
        xfp = swab32(self.node.my_fp())
        xpub = self.chain.serialize_public(self.node)

        if self._bip39pw:
            settings.put_volatile('xfp', xfp)
            settings.put_volatile('xpub', xpub)
        else:
            settings.overrides.clear()
            settings.put('xfp', xfp)
            settings.put('xpub', xpub)

        settings.put('chain', self.chain.ctype)
        settings.put('words', (self.mode == 'words'))

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

            if i[-1] == "'":
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
        dirty = self.derive_path("m/2147431408'/0'/0'")

        # clear the parent linkage by rebuilding it.
        cc, pk = dirty.chain_code(), dirty.privkey()
        self.register(cc)
        self.register(pk)

        rv = ngu.hdnode.HDNode()
        rv.from_chaincode_privkey(cc, pk)
        self.register(rv)

        return rv

    def encryption_key(self, salt):
        # Return a 32-byte derived secret to be used for our own internal encryption purposes
        # 0x80000000 - 0xCC30 = 2147431376
        node = self.derive_path("m/2147431408'/0'")     # plan: 0' will be an index for other apps

        acc = sha256(salt)
        acc.update(node.privkey())
        acc.update(salt)

        pk = ngu.hash.sha256s(acc.digest())

        self.register(pk)
        return pk
    

# EOF
