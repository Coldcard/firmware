# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# teleport.py - Magically transport extremely sensitive data between the
#               secure environment of two Q's.
#
import utime, uzlib, ngu, aes256ctr, bip39
from utils import problem_file_line, xor
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex
from glob import settings
from ux import ux_show_story, ux_confirm, show_qr_code
from ux_q1 import show_bbqr_codes, QRScannerInteraction, seed_word_entry, ux_render_words
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL
from bbqr import int2base36, b32encode

KT_DOMAIN = 'keyteleport.com'

'''
- `w` - 12/18/24 words - 16/24/32 bytes follow
- `m` - (one byte of length) + (up to 71 bytes) - BIP-32 raw master secret [rare]
- `r` - raw XPRV mode - 64 bytes follow which are the chain code then master privkey 
- `x` - XPRV mode, full details - 4 bytes (XPRV) + base58 *decoded* binary-XPRV follows
- `n` - secure note or password (JSON)
- `e` - full notes export (JSON array)
- `v` - seed vault export (JSON: one secret key but includes includes name, source of key)
- `p` - binary PSBT to be signed
- `P` - a more-signed binary PSBT being returned back to sender
'''


def short_bbqr(type_code, data):
    # Short-circuit basic BBQr encoding here: always Base32, single part: 1 of 1
    #hdr = 'B$' + encoding + type_code + int2base36(num_parts) + int2base36(pkt)
    hdr = 'B$2' + type_code + int2base36(1) + int2base36(0)

    return hdr + b32encode(data)

async def nfc_push_kt(qrdata):
    # NFC push to send them to our QR-rendering website
    import ndef

    url = KT_DOMAIN + '#' + qrdata

    n = ndef.ndefMaker()
    n.add_url(url, https=True)

    from glob import NFC
    await NFC.share_loop(n, prompt=KT_DOMAIN, line2="View QR on web")

async def kt_start_rx(*a):
    # menu item to "start a receive" operation

    rx_key = settings.get("ktrx")

    if rx_key:
        # Maybe re-use same one? Vaguely risky? Concern is they are confused and
        # we don't want to lose the pubkey if they should be scanning not here.
        ch = await ux_show_story('''Looks like last attempt wasn't completed. \
You need to do QR scan of data from the sender to move to the next step. \
We will re-use same values as last try, unless you press (R) for new values to be picked.''',
                    title='Reuse Pubkey?', escape='r'+KEY_QR, hint_icons=KEY_QR)

        if ch == KEY_QR:
            # help them scan now!
            x = QRScannerInteraction()
            await x.scan_anything(expect_secret=False, tmp=False)
            return
        elif ch == 'r':
            # wipe and restart; sender's work might be lost
            rx_key = None
        else:
            # keep old keypair -- they might be confused
            kp = ngu.secp256k1.keypair(a2b_hex(rx_key))

    if not rx_key:
        # pick a random key pair, just for this session
        kp = ngu.secp256k1.keypair()

        settings.set("ktrx", b2a_hex(kp.privkey()))
        settings.save()

    pubkey = kp.pubkey().to_bytes(False)        # compressed format

    msg = '''You are starting a teleport of sensitive data from another COLDCARD.\n
It will be double-encrypted with AES-256-CTR using ECDH for one-time key and also \
an optional passphrase.\n
You must show this QR code to the sender somehow. %s to show now''' % KEY_QR

    await tk_show_payload('R', pubkey, 'Key Teleport: Receive', 'Show to Sender', msg)

async def tk_show_payload(type_code, pubkey, title, cta=None, msg=None):
    # show the QR and/or NFC
    from glob import NFC

    # XXX proper BBQr for sending data?
    # - make easier to pick NFC from QR
    qr = short_bbqr(type_code, pubkey)

    hints = KEY_QR
    if NFC:
        hints += KEY_NFC
        if msg:
            msg += ' or %s to view on your phone' % KEY_NFC

    if msg:
        msg += '. CANCEL to stop.'

    # simply show the QR
    while 1:
        if msg:
            ch = await ux_show_story(msg, title=title, hint_icons=hints)
        else:
            ch = KEY_QR

        if ch == KEY_NFC and NFC:
            await nfc_push_kt(qr)
        elif ch == KEY_QR or ch == 'y':
            await show_qr_code(qr, is_alnum=True, msg=cta, force_msg=True, allow_nfc=False)

        elif ch == 'x':
            return

async def kt_start_send(rx_pubkey):
    # they want to send to this guy, ask them what to send, etc
    msg = '''You can now teleport secrets. You can select from seed words, temporary keys, 
secure notes and passwords. \

WARNING: \
The other COLDCARD will have full access to all Bitcoin controlled by these keys!
'''

    ch = await ux_show_story(msg, title="Key Teleport: Send")

    # TODO: pick what to send, somehow ... 

    body = b'w'+ (b'A'*16)

    # Pick and show noid key to sender
    noid_key = ngu.random.bytes(16)
    
    msg = "Share passphrase with receiver, via some different channel:"
    msg += ux_render_words(bip39.b2a_words(noid_key).split())
    await ux_show_story(msg, 'Paranoid Key')

    # throw away entropy
    my_keypair = ngu.secp256k1.keypair()

    words = bip39.b2a_words(noid_key).split(' ')

    payload = encode_payload(my_keypair, rx_pubkey, noid_key, body)

    await tk_show_payload('S', payload, None, 'Show to Receiver')
    

async def kt_decode_rx(is_psbt, payload):
    # we are getting data back from a sender, decode it.

    if not is_psbt:
        rx_key = settings.get("ktrx")
        if not rx_key:
            await ux_show_story("Not expecting any teleports. You need to start over.")
            return

        his_pubkey = payload[0:33]
        body = payload[33:]
        pair = ngu.secp256k1.keypair(a2b_hex(rx_key))
    else:
        randint = payload[0:4]
        body = payload[4:]

        # may need to iterate over a few wallets?

    ses_key, body = await decode_step1(pair, his_pubkey, body)

    if not ses_key:
        await ux_show_story("QR code is damaged or incorrect.\n\n" + body, title="Decode Fail")
        return

    while 1:
        # ask for noid key
        words = await seed_word_entry('Paranoid Key', 12, has_checksum=True)
        if not words:
            noid_key = b'\x5a' * 16
        noid_key = bip39.a2b_words(words)

        final = decode_step2(ses_key, noid_key, body)
        if final is not None: 
            break

        ch = await ux_show_story("Incorrect Paranoid Key. You can try again or CANCEL to stop.")
        if ch == 'x': return
        # will ask again

    await kt_accept_values(final[0].decode(), final[1:])

async def kt_accept_values(dtype, raw):
    # got the secret, decode it more
    '''
- `w` - 12/18/24 words - 16/24/32 bytes follow
- `m` - (one byte of length) + (up to 71 bytes) - BIP-32 raw master secret [rare]
- `r` - raw XPRV mode - 64 bytes follow which are the chain code then master privkey 
- `x` - XPRV mode, full details - 4 bytes (XPRV) + base58 *decoded* binary-XPRV follows
- `n` - one or many notes export (JSON array)
- `v` - seed vault export (JSON: one secret key but includes includes name, source of key)
- `p` - binary PSBT to be signed
- `P` - a more-signed binary PSBT being returned back to sender
'''
    from stash import SecretStash
    from chains import current_chain, slip32_deserialize

    enc = None
    meta = 'Teleported'

    if dtype == 'w':
        # words.
        assert len(raw) in { 16, 24, 32 }
        enc = SecretStash.encode(seed_phrase=raw)
    elif dtype == 'm':
        enc = SecretStash.encode(master_secret=raw)
    elif dtype == 'r':
        assert len(raw) == 64
        enc = b'\x01' + raw
    elif dtype == 'x':
        # it's an XPRV, but in binary.. some extra data we throw away here; sigh

        txt = ngu.codecs.b58_encode(raw)
        node, ch, _, _ = slip32_deserialize(txt)
        assert ch.name == chains.current_chain.name, 'wrong chain'
        enc = SecretStash.encode(node=node)

    elif dtype in 'pP':
        # raw PSBT -- bigger
        from auth import sign_transaction
        psbt_len = len(raw)

        with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
            out.write(raw)

        # this will take over UX w/ the signing process
        sign_transaction(psbt_len, flags=0x0)
        return

    elif dtype in 'nv':
        # all are JSON things
        js = loads(raw)

        if dtype == 'v':
            # one key export from a seed vault
            enc = a2b_hex(js[1])
            meta = js[2]
        elif dtype == 'n':
            # secure note(s)
            from notes import import_from_json

            await import_from_json(dict(coldcard_notes=js))
            
            await ux_dramatic_pause('Imported.', 3)

            # TODO: force them into notes submenu so they see result?

            return
    else:
        raise ValueError(dtype)

    # key material is arriving; offer to use as main secret or tmp or seed vault
    assert enc
    #summary = SecretStash.summary(enc[0])

    from flow import has_se_secrets, goto_top_menu
    from seed import set_ephemeral_seed, set_seed_value

    if not has_se_secrets():
        # unit has nothing, so this will be the master seed
        set_seed_value(encoded=enc)
        ok = True
    else:
        ok = await set_ephemeral_seed(enc, meta=meta)

    if ok:
        goto_top_menu()


def encode_payload(my_keypair, his_pubkey, noid_key, body):
    # do all the encryption
    assert len(his_pubkey) == 33
    assert len(noid_key) == 16

    session_key = my_keypair.ecdh_multiply(his_pubkey)

    b1 = aes256ctr.new(session_key).cipher(body)
    b1 += ngu.hash.sha256s(b1)[-2:]

    b2 = aes256ctr.new(noid_key + session_key[16:]).cipher(b1)
    b2 += ngu.hash.sha256s(b2)[-2:]

    return my_keypair.pubkey().to_bytes(True) +  b2

def decode_step1(my_keypair, his_pubkey, body):
    # Do ECDH and get out next layer of encryption
    try:
        assert len(his_pubkey) == 33
        assert len(body) >= 10

        session_key = my_keypair.ecdh_multiply(his_pubkey)

        body = aes256ctr.new(session_key).cipher(payload[:-2])
        chk = sha256s(body)[-2:]
        assert chk == payload[-2:], 'first checksum'
    except Exception as exc:
        ln = problem_file_line(exc)
        return None, ln

    return session_key, body

def decode_step2(session_key, noid_key, body):
    tk = noid_key + session_key[16:]
    msg = aes256ctr.new(noid_key + session_key[16:]).cipher(body[:-2])
    chk = sha256(msg)[:-2]

    return msg if chk == msg[-2:] else None
    

async def kt_incoming(type_code, payload):
    # incoming BBQr was scanned (via main menu, etc)

    if type_code == 'R':
        # they want to send to this guy
        return await kt_start_send(payload)

    elif type_code == 'S':
        # we are receiving something, let's try to decode
        return await kt_decode_rx(False, payload)

    elif type_code == 'E':
        # incoming PSBT!
        return await kt_decode_rx(True, payload)

        

# EOF
