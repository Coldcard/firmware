# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# teleport.py - Magically transport extremely sensitive data between the
#               secure environment of two Q's.
#
import sys, uzlib, ngu, aes256ctr, bip39, json, stash
from utils import problem_file_line, B2A, xfp2str, deserialize_secret
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex
from glob import settings
from ux import ux_show_story, ux_confirm, show_qr_code, the_ux, ux_dramatic_pause
from ux_q1 import show_bbqr_codes, QRScannerInteraction, ux_input_text
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL
from bbqr import b32encode, b32decode
from menu import MenuItem, MenuSystem

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
    # XXX generalize
    hdr = 'B$2%s0100' % type_code

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

    pubkey = kp.pubkey().to_bytes()        # default: compressed format
    assert pubkey[0] in { 2, 3}

    msg = '''You are starting a teleport of sensitive data from another COLDCARD. \
It will be double-encrypted with AES-256-CTR using ECDH for one-time key and also \
a password.\n
Show the QR on next screen to the sender somehow. ENTER or %s to show here''' % KEY_QR

    await tk_show_payload('R', pubkey, 'Key Teleport: Receive', cta='Show to Sender', msg=msg)

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
            if not msg: break
        elif ch == 'x':
            return

def valid_looking_pubkey(rx_pubkey):
    try:
        assert rx_pubkey[0] in { 2, 3}
        assert len(rx_pubkey) == 33
        assert len(set(rx_pubkey)) > 3
        # check on curve? secp256k1.ecdh_multiply does that ?
        return True
    except:
        # dont waste bytes on error messages for hackers
        return False

async def kt_start_send(rx_pubkey):
    # a QR was scanned and it held a pubkey
    # they want to send to this guy, ask them what to send, etc
    
    if not valid_looking_pubkey(rx_pubkey): return

    msg = '''You can now teleport secrets. You can select from seed words, temporary keys, \
secure notes and passwords. \

WARNING: Receiver will have full access to all Bitcoin controlled by these keys!
'''

    ch = await ux_show_story(msg, title="Key Teleport: Send")

    # TODO: pick what to send, somehow ... 
    menu = SecretPickerMenu(rx_pubkey)

    the_ux.push(menu)

async def kt_do_send(rx_pubkey, dtype, raw=None, obj=None):
    # Example: cleartext = b'w'+ (b'A'*16)
    cleartext = dtype.encode() + (raw or json.dumps(obj).encode())

    # Pick and show noid key to sender
    noid_key, txt = pick_noid_key()
    
    msg = "Share this password with the receiver, via some different channel:"\
                "\n\n   %s  =  %s\n\n" % (txt, ' '.join(txt))
    msg += "ENTER to view QR"

    # all new EC key
    my_keypair = ngu.secp256k1.keypair()

    payload = encode_payload(my_keypair, rx_pubkey, noid_key, cleartext)

    await tk_show_payload('S', payload, 'Teleport Password', cta='Show to Receiver', msg=msg)

    from flow import goto_top_menu
    goto_top_menu()
    
def pick_noid_key():
    # pick an 40 bit password, shown as base32
    # - on rx, libngu base32 decoder will convert '018' into 'OLB'
    # - but a little tempted to removed vowels here?
    k = ngu.random.bytes(5)
    txt = b32encode(k).upper()

    return k, txt

async def kt_decode_rx(is_psbt, payload):
    # we are getting data back from a sender, decode it.

    if not is_psbt:
        rx_key = settings.get("ktrx")
        if not rx_key:
            await ux_show_story("Not expecting any teleports. You need to start over.")

            await kt_start_rx()         # help them to start over? idk maybe not.
            return

        his_pubkey = payload[0:33]
        body = payload[33:]
        pair = ngu.secp256k1.keypair(a2b_hex(rx_key))

    else:
        randint = payload[0:4]
        body = payload[4:]

        # may need to iterate over a few wallets?

    ses_key, body = decode_step1(pair, his_pubkey, body)

    if not ses_key:
        # when ECDH fails, it's truncation or wrong RX key (due to sender using old rx key, etc)
        await ux_show_story("QR code is damaged, or was sent to a different user. "
            "Sender should start again.", title="Teleport Fail")
        return

    from glob import dis
    while 1:
        # ask for noid key
        pw = await ux_input_text('', confirm_exit=False, hex_only=False, max_len=8,
                prompt='Teleport Password', min_len=8, b39_complete=False, scan_ok=False,
                placeholder='********', funct_keys=None, force_xy=None)

        dis.progress_bar_show(0)
        try:
            assert len(pw) == 8
            noid_key = b32decode(pw)       # case insenstive, and smart about confused chars
            final = decode_step2(ses_key, noid_key, body)
            if final is not None: 
                break
        except:
            pass
        finally:
            dis.progress_bar_show(1)

        ch = await ux_show_story(
                "Incorrect Teleport Password. You can try again or CANCEL to stop.")
        if ch == 'x': return
        # will ask again

    # success w/ decoding. but maybe something goes wrong or they reject a confirm step
    # so keep the rx key alive still

    await kt_accept_values(chr(final[0]), final[1:])

async def kt_accept_values(dtype, raw):
    # We got some secret, decode it more, and save it.
    '''
- `s` - secret, encoded per stash.py
- `m` - (up to 72 bytes?) - BIP-32 raw master secret [rare]
- `r` - raw XPRV mode - 64 bytes follow which are the chain code then master privkey 
- `x` - XPRV mode, full details - 4 bytes (XPRV) + base58 *decoded* binary-XPRV follows
- `n` - one or many notes export (JSON array)
- `v` - seed vault export (JSON: one secret key but includes includes name, source of key)
- `p` - binary PSBT to be signed
- `P` - a more-signed binary PSBT being returned back to sender
'''
    from chains import current_chain, slip32_deserialize
    from flow import has_se_secrets, goto_top_menu

    enc = None
    origin = 'Teleported'
    label = None

    if dtype == 's':
        # words / bip 32 master / xprv, etc
        enc = bytearray(72)
        enc[0:len(raw)] = raw

    elif dtype == 'x':
        # it's an XPRV, but in binary.. some extra data we throw away here; sigh
        # XXX no way to send this .. but was thinking of address explorer
        txt = ngu.codecs.b58_encode(raw)
        node, ch, _, _ = slip32_deserialize(txt)
        assert ch.name == chains.current_chain.name, 'wrong chain'
        enc = stash.SecretStash.encode(node=node)

    elif dtype in 'pP':
        # raw PSBT -- bigger
        from auth import sign_transaction
        psbt_len = len(raw)

        # copy into PSRAM
        with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
            out.write(raw)

        # This will take over UX w/ the signing process
        sign_transaction(psbt_len, flags=0x0)
        return

    elif dtype in 'nv':
        # all are JSON things
        js = json.loads(raw)

        if dtype == 'v':
            # one key export from a seed vault
            # - watch for incompatibility here if we ever change VaultEntry
            from seed import VaultEntry
            rec = VaultEntry(*js)
            enc = deserialize_secret(rec.encoded)
            origin = rec.origin
            label = rec.label
        elif dtype == 'n':
            # import secure note(s)
            from notes import import_from_json, make_notes_menu, NoteContent

            settings.remove_key("ktrx")     # force new rx key after this point
            await import_from_json(dict(coldcard_notes=js))
            
            await ux_dramatic_pause('Imported.', 2)

            # force them into notes submenu so they can see result right away
            # - highlight to last note, which should be the just-added one(s)
            goto_top_menu()
            nm = await make_notes_menu()
            nm.goto_idx(NoteContent.count()-1)
            the_ux.push(nm)

            return
    else:
        raise ValueError(dtype)

    # key material is arriving; offer to use as main secret, or tmp, or seed vault?
    assert enc

    from seed import set_ephemeral_seed, set_seed_value

    if not has_se_secrets():
        # unit has nothing, so this will be the master seed
        set_seed_value(encoded=enc)
        ok = True
    else:
        ok = await set_ephemeral_seed(enc, origin=origin, label=label)

    if ok:
        settings.remove_key("ktrx")     # force new rx key after this point
        goto_top_menu()

def noid_stretch(session_key, noid_key):
    return ngu.hash.pbkdf2_sha512(session_key, noid_key, 5000)[0:32]

def encode_payload(my_keypair, his_pubkey, noid_key, body):
    # do all the encryption
    assert len(his_pubkey) == 33
    assert len(noid_key) == 5

    session_key = my_keypair.ecdh_multiply(his_pubkey)

    # stretch noid key out -- will be slow
    pk = noid_stretch(session_key, noid_key)

    b1 = aes256ctr.new(pk).cipher(body)
    b1 += ngu.hash.sha256s(body)[-2:]

    b2 = aes256ctr.new(session_key).cipher(b1)
    b2 += ngu.hash.sha256s(b1)[-2:]

    return my_keypair.pubkey().to_bytes() +  b2

def decode_step1(my_keypair, his_pubkey, body):
    # Do ECDH and remove top layer of encryption
    try:
        assert valid_looking_pubkey(his_pubkey)
        assert len(body) >= 10

        session_key = my_keypair.ecdh_multiply(his_pubkey)

        rv = aes256ctr.new(session_key).cipher(body[:-2])
        chk = ngu.hash.sha256s(rv)[-2:]

        assert chk == body[-2:]         # likely means wrong rx key, or truncation
    except:
        return None, None

    return session_key, rv

def decode_step2(session_key, noid_key, body):
    # After we have the noid key, can decode true payload
    assert len(noid_key) == 5

    pk = noid_stretch(session_key, noid_key)

    msg = aes256ctr.new(pk).cipher(body[:-2])
    chk = ngu.hash.sha256s(msg)[-2:]

    return msg if chk == body[-2:] else None
    

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

    else:
        raise ValueError(type_code)


class SecretPickerMenu(MenuSystem):
    def __init__(self, rx_pubkey):
        self.rx_pubkey = rx_pubkey

        from flow import word_based_seed, is_tmp
        from stash import bip39_passphrase
        has_notes = bool(settings.get('secnap', False))
        has_ms = bool(settings.get('multisig', False))
        has_sv = bool(settings.get('seedvault', False))

        # Q-only feature, so menu can be W I D E 
        # - in increasing order of important / sensitivity!
        m = [
            MenuItem('Multisig PSBT for Signing', predicate=has_ms),
            MenuItem('Single Note / Password', predicate=has_notes, menu=self.pick_note_submenu),
            MenuItem('Export All Notes & Passwords', predicate=has_notes, f=self.picked_note),
        ]

        if has_sv:
            m.append( MenuItem('From Seed Vault',  menu=self.pick_vault_submenu) )

        if is_tmp():
            # tmp seed, or maybe bip39 is in effect 
            # - all are the current master secret
            msg = 'Temp Secret (words)' if word_based_seed() else (
                        'XPRV from Words+Passphrase' if bip39_passphrase else 'Temp XPRV Secret')

        else:
            # real master secret
            msg = 'Master Seed Words' if word_based_seed() else 'Master XPRV'

        m.append( MenuItem(msg, f=self.share_master_secret) )
        
        super().__init__(m)

    async def pick_vault_submenu(self, *a):
        # pick a secret from seed vault
        from seed import SeedVaultChooserMenu
        rec = await SeedVaultChooserMenu.pick()
        if rec:
            await kt_do_send(self.rx_pubkey, 'v', obj=list(rec))

    async def pick_note_submenu(self, *a):
        # Make a submenu to select a single note/password
        from notes import NoteContent

        rv = []
        for note in NoteContent.get_all():
            rv.append(MenuItem('%d: %s' % (note.idx+1, note.title), f=self.picked_note, arg=note))

        return rv

    async def picked_note(self, _, _2, item):
        # exporting note(s)
        from notes import NoteContent

        if item.arg is None:
            # export all
            body = [n.serialize() for n in NoteContent.get_all()]
        else:
            # single note/password
            body = [item.arg.serialize()]

        await kt_do_send(self.rx_pubkey, 'n', obj=body)

    async def share_master_secret(self, _, _2, item):
        # altho menu items look different we are sharing same thing:
        # - up to 72 bytes from secure elements
        from stash import SensitiveValues, SecretStash, blank_object

        with stash.SensitiveValues(bypass_tmp=False, enforce_delta=True) as sv:
            raw = bytearray(sv.secret)
            xfp = xfp2str(sv.get_xfp())

        # rtrim zeros
        while raw[-1] == 0:
            raw = raw[0:-1]

        summary = SecretStash.summary(raw[0])

        from pincodes import pa
        scale = 'your MASTER secret' if not pa.tmp_value else 'a temporary secret'

        msg = "Sharing %s [%s] (%s)." % (scale, xfp, summary)
        msg += "\n\nWARNING: Allows full control over all associated Bitcoin!"

        if not await ux_confirm(msg):
            blank_object(raw)
            return

        await kt_do_send(self.rx_pubkey, 's', raw=raw)
    
# EOF
