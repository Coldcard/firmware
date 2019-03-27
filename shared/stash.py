# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
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
import tcc, uctypes, gc
from pincodes import AE_SECRET_LEN

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
    elif isinstance(item, tcc.bip32.HDNode):
        item.blank()
        assert item.private_key() == bytes(32)
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
            # between 128 and 512 bits of master secret for BIP32 key derivation
            vlen = len(master_secret)
            assert 16 <= vlen <= 64
            nv[0] = vlen
            nv[1:1+vlen] = master_secret

        elif xprv:
            # master xprivkey, which could be a subkey of something we don't know
            # - we record only the minimum from 
            assert isinstance(xprv, tcc.bip32.HDNode)
            nv[0] = 0x01
            nv[1:33] = xprv.chain_code()
            nv[33:65] = xprv.private_key()

        return nv

    @staticmethod
    def decode(secret, _bip39pw=''):
        # expecting 72-bytes of secret payload; decode meaning
        # returns:
        #    type, secrets bytes, HDNode(root)
        #
        marker = secret[0]

        if marker == 0x01:
            # xprv => BIP32 private key values
            ch, pk = secret[1:33], secret[33:65]

            return 'xprv', ch+pk, tcc.bip32.HDNode(chain_code=ch, private_key=pk,
                                                child_num=0, depth=0, fingerprint=0)

        if marker & 0x80:
            # seed phrase
            ll = ((marker & 0x3) + 2) * 8

            # note: 
            # - byte length > number of words
            # - not storing checksum
            assert ll in [16, 24, 32]

            # make master secret, using the memonic words, and passphrase (or empty string)
            seed_bits = secret[1:1+ll]
            ms = tcc.bip39.seed(tcc.bip39.from_data(seed_bits), _bip39pw)

            hd = tcc.bip32.from_seed(ms, 'secp256k1')

            return 'words', seed_bits, hd

        else:
            # variable-length master secret for BIP32
            vlen = secret[0]
            assert 16 <= vlen <= 64

            ms = secret[1:1+vlen]
            hd = tcc.bip32.from_seed(ms, 'secp256k1')

            return 'master', ms, hd

# optional global value: user-supplied passphrase to salt BIP39 seed process
bip39_passphrase = ''

class SensitiveValues:
    # be a context manager, and holder to secrets in-memory

    def __init__(self, secret=None, for_backup=False):
        if secret is None:
            # fetch the secret from bootloader/atecc508a
            from main import pa

            if pa.is_secret_blank():
                raise ValueError('no secrets yet')

            self.secret = pa.fetch()
        else:
            # sometimes we already know it
            assert set(secret) != {0}
            self.secret = secret

        # backup during volatile bip39 encryption: do not use passphrase
        self._bip39pw = '' if for_backup else str(bip39_passphrase)

    def __enter__(self):
        import chains

        self.mode, self.raw, self.node = SecretStash.decode(self.secret, self._bip39pw)

        self.chain = chains.current_chain()

        self.spots = [ self.secret, self.node, self.raw ]

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clear secrets from memory ... yes, they could have been
        # copied elsewhere, but in normal case, at least we blanked them.
        for item in self.spots:
            blank_object(item)

        if hasattr(self, 'secret'):
            # will be blanked from above
            assert self.secret == bytes(AE_SECRET_LEN)
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
        from main import settings

        # Implicit in the values is the BIP39 encryption passphrase,
        # which we might not want to actually store.
        xfp = self.node.my_fingerprint()
        xpub = self.chain.serialize_public(self.node)

        if self._bip39pw:
            settings.put_volatile('xfp', xfp)
            settings.put_volatile('xpub', xpub)
        else:
            settings.overrides.clear()
            settings.put('xfp', xfp)
            settings.put('xpub', xpub)

        settings.put('chain', self.chain.ctype)


    def register(self, item):
        # Caller can add his own sensitive (derived?) data to our wiper
        # typically would be byte arrays or byte strings, but also
        # supports bip32 nodes
        self.spots.append(item)

    def derive_path(self, path, master=None):
        # given a string path, derive the related subkey
        rv = (master or self.node).clone()
        self.register(rv)

        for i in path.split('/'):
            if i == 'm': continue
            if not i: continue      # trailing or duplicated slashes

            if i[-1] == "'":
                assert len(i) >= 2, i
                here = int(i[:-1]) | 0x80000000
            else:
                here = int(i)
                assert 0 <= here < 0x80000000, here

            rv.derive(here)

        return rv

    def duress_root(self):
        # Return a bip32 node for the duress wallet linked to this wallet.
        # 0x80000000 - 0xCC10 = 2147431408
        dirty = self.derive_path("m/2147431408'/0'/0'")

        # clear the parent linkage by rebuilding it.
        cc, pk = dirty.chain_code(), dirty.private_key()
        self.register(cc)
        self.register(pk)

        rv = tcc.bip32.HDNode(chain_code=cc, private_key=pk,
                                                child_num=0, depth=0, fingerprint=0)
        self.register(rv)

        return rv
    

# EOF
