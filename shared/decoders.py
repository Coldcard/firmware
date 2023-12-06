# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# decoders.py - Convert QR (or text) values into useful bitcoin-related objects.
#
import uasyncio as asyncio
import ngu, bip39
from ubinascii import unhexlify as a2b_hex
from exceptions import QRDecodeExplained
from bbqr import TYPE_LABELS

def txn_decoding_taster(txt):
    # look at first 4 bytes, and assume it's txn version number (LE32 0x1 or 0x2), then decode 
    # - working in normal RAM, won't handle full sized txn
    # - will not be binary
    # - not a very conclusive test, maybe should decode it more here?
    from ubinascii import a2b_base64

    if txt[0:8] in { '01000000', '02000000'}:
        # transaction in hex format
        return a2b_hex(txt)
    elif txt[0:4] in { 'AQAA', 'AgAA' }:
        # Base64 encoded
        return a2b_base64(txt)
    else:
        raise ValueError("not txn")
    

def decode_secret(got):
    # Decode a few different ways to store a master secret (in a QR), or raise
    # - xprv / tprv
    # - words (either full or prefixes, case insensitive)
    # - SeedQR (github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md)

    if len(got) > 300:
        raise ValueError("Too big.")

    # remove bitcoin: if present (unlikely)
    if ':' in got:
        _, got = got.split(':', 1)

    if got[1:4] == 'prv':
        # xprv or tprv: private key import for sure
        # - verify checksum is right
        try:
            raw = ngu.codecs.b58_decode(got)  
        except:
            raise ValueError('corrupt xprv?')

        return 'xprv', got
    
    taste = got.strip().lower()

    if taste.isdigit():
        # SeedQR: 4 digit groups of index into word list
        parts = [taste[pos:pos+4] for pos in range(0, len(taste), 4)]
        try:
            assert len(parts) in (12, 18, 24)
            words = [bip39.wordlist_en[int(n)] for n in parts]
        except:
            raise ValueError('corrupt SeedQR?')
        return 'words', words

    words = taste.strip().split(' ')
    if len(words) in [ 12, 18, 24]:
        # looks like bip-39 words, decode and re-expand
        idx = [bip39.get_word_index(w) for w in words]
        return 'words', [bip39.wordlist_en[n] for n in idx]

    raise ValueError('no idea')

def decode_qr_result(got, expect_secret=False):
    # Could be BBQr or text

    if hasattr(got, 'storage'):
        # BBQr object
        try:
            ty, final_size, got = got.storage.finalize()
        except BaseException as exc:
            import sys; sys.print_exception(exc)
            raise QRDecodeExplained("BBQr decode failed: " + str(exc))

        if expect_secret and ty in 'PT':
            raise QRDecodeExplained('Expected secrets not PSBT/TXN')

        if ty == 'P':
            # may already be in PSRAM, avoid a copy here
            from glob import PSRAM
            if PSRAM.is_at(got, 0):
                got = 'PSRAM'       # see qr_psbt_sign()

            return 'psbt', (None, final_size, got)

        elif ty == 'T':

            return 'txn', (got,)

        elif ty == 'U':
            # continue thru code below for TEXT
            pass

        else:
            msg = TYPE_LABELS.get(ty, 'Unknown FileType')
            raise QRDecodeExplained("Sorry, %s not useful." % msg)

    # First can we decode a master secret of some type?

    try:
        mode, value = decode_secret(got)
        return mode, (value,)
    except QRDecodeExplained:
        raise
    except BaseException as exc:
        #import sys; sys.print_exception(exc)
        if expect_secret:
            raise QRDecodeExplained("Unable to decode as secret")

    if expect_secret:
        raise QRDecodeExplained("Not a secret?")

    return decode_qr_text(got)

def decode_qr_text(got):
    # Study text received over QR, for useful things.
    # - case may be "wrong" but some values are case-sensitive (base58)
    # - not binary, but might be some other encoding than BBQr
    # - if bad checksum on bitcoin addr, we treat as text... since might be
    # return: what-it-is, (tuple)
    orig_got = got

    # might be a PSBT?
    if len(got) > 100:
        from auth import psbt_encoding_taster
        try: 
            decoder, _, psbt_len = psbt_encoding_taster(got[0:10].encode(), len(got))
            return 'psbt', (decoder, psbt_len, got)
        except QRDecodeExplained:
            raise
        except:
            pass

        # might be txn, as hex or base64
        try:
            return 'txn', (txn_decoding_taster(got), )
        except:
            # was something else.
            pass

    # Might be an address or pubkey?

    # remove URL protocol: if present
    proto, args, addr = None, None, None
    if ':' in got:
        proto, got = got.split(':', 1)

    # looks like BIP-21 payment URL
    if '?' in got:
        addr, args = got.split('?', 1)

        # weak URL decode here.
        args = args.split('&')
        args = dict(a.split('=', 1) for a in args)

    # assume it's an bare address for now
    if not addr:
        addr = got

    # old school
    try:
        raw = ngu.codecs.b58_decode(addr)

        # it's valid base58
        # an address, P2PKH or xpub (xprv checked above)
        if addr[1:4] == 'pub':
            return 'xpub', (addr,)

        return 'addr', (proto, addr, args)
    except:
        pass

    # new school: bech32 or bech32m
    try:
        hrp, version, data = ngu.codecs.segwit_decode(addr)
        return 'addr', (proto, addr, args)
    except:
        pass

    # catch-all ... was text. Can still show on-screen perhaps useful for other applications
    return 'text', (orig_got,)

# EOF
