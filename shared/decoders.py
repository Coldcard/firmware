# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# decoders.py - Convert QR (or text) values into useful bitcoin-related objects.
#
#  included in Q builds only, not Mk4 --> manifest_q1.py
#
import ngu, bip39, ure, stash
from ubinascii import unhexlify as a2b_hex
from exceptions import QRDecodeExplained
from bbqr import TYPE_LABELS
from utils import decode_bip21_text


def decode_seed_qr(data):
    # SeedQR: 4 digit groups of index into word list
    parts = [data[pos:pos + 4] for pos in range(0, len(data), 4)]
    words = [bip39.wordlist_en[int(n)] for n in parts]
    return words

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

    if len(got) in (51, 52):
        try:
            raw = ngu.codecs.b58_decode(got)
            if raw[0] in (0xef, 0x80):
                testnet = True if raw[0] == 0xef else False
                if len(raw) in (33, 34):  # uncompressed pubkey
                    compressed = False
                    if len(raw) == 34:  # compressed pubkey
                        assert raw[33] == 0x01
                        compressed = True
                    sk = raw[1:33]
                    kp = ngu.secp256k1.keypair(sk)
                    return 'wif', (got, kp, compressed, testnet)
        except: pass
    
    taste = got.strip().lower()

    if taste.isdigit():
        try:
            words = decode_seed_qr(taste)
        except:
            raise ValueError('corrupt SeedQR?')
        assert len(words) in stash.SEED_LEN_OPTS, "seed len"
        return 'words', words

    words = taste.strip().split(' ')
    if len(words) in stash.SEED_LEN_OPTS:
        # looks like bip-39 words, decode and re-expand
        idx = [bip39.get_word_index(w) for w in words]
        return 'words', [bip39.wordlist_en[n] for n in idx]

    raise ValueError('no idea')

def decode_qr_result(got, expect_secret=False, expect_text=False, expect_bbqr=False):
    # Could be BBQr or text
    # - if expect_text, just give us unparsed text back; after BBQr decode
    # - if expect_bbqr, always return tuple: (file_type, len, data)
    # - otherwise, returns a tuple: (type, (*parsed_data))

    if hasattr(got, 'storage'):
        # BBQr object
        try:
            ty, final_size, got = got.storage.finalize()
        except BaseException as exc:
            import sys; sys.print_exception(exc)
            raise QRDecodeExplained("BBQr decode failed: " + str(exc))

        if expect_bbqr:
            return (ty, final_size, got)

        if expect_secret and ty in 'PT':
            raise QRDecodeExplained('Expected secrets not PSBT/TXN')

        if expect_text:
            if ty != 'U':
                raise QRDecodeExplained('Expected text, got ' + TYPE_LABELS.get(ty, ty))
            return got.decode()

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

        elif ty == 'J':
            return 'json', (got,)
        else:
            msg = TYPE_LABELS.get(ty, 'Unknown FileType')
            raise QRDecodeExplained("Sorry, %s not useful." % msg)

    elif expect_bbqr:
        # convert as if it was BBQr of text
        return ('U', len(got), got)

    elif expect_text:
        # caller just wants text anyway, so we are done
        return got

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

    # try to recognize various bitcoin-related text strings...
    return decode_short_text(got)

def decode_short_text(got):
    # Study short text received over QR or NFC, for useful things.
    # - case may be "wrong" but some values are case-sensitive (base58)
    # - not binary, but might be some other encoding than BBQr
    # - if bad checksum on bitcoin addr, we treat as text... since might be
    # return: what-it-is, (tuple)

    if not isinstance(got, str):
        # decode utf-8
        try:
            got = got.decode()
        except UnicodeError:
            raise QRDecodeExplained('UTF-8 decode failed')

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

    if ("\n" in got) and ('pub' in got):
        # legacy multisig import/export format
        # [0-9a-fA-F]{8}\s*:\s*[xtyYzZuUvV]pub[1-9A-HJ-NP-Za-km-z]{107}
        # above is more precise BUT counted repetitions not supported in mpy
        cc_ms_pat = r"[0-9a-fA-F]+\s*:\s*[xtyYzZuUvV]pub[1-9A-HJ-NP-Za-km-z]+"
        rgx = ure.compile(cc_ms_pat)
        # go line by line and match above, once 2 matches observed - considered multisig
        # important to not use ure.search for big strings (can run out of stack)
        c = 0  # match count
        for l in got.split("\n"):
            if rgx.search(l):
                c += 1
            if c > 1:
                return 'multi', (got,)

    from descriptor import Descriptor
    if Descriptor.is_descriptor(got):
        return 'minisc', (got,)

    # Things with newlines in them are not URL's
    # - working URLs are not >4k
    # - might be a story in text, etc.
    if (len(got) > 4096) or ('\n' in got):
        return 'text', (got,)

    # Might be an address or pubkey?
    try:
        return decode_bip21_text(got)
    except:
        # keep looking
        pass

    # catch-all as text. Can still show on-screen perhaps useful for other applications
    return 'text', (got,)


# EOF
