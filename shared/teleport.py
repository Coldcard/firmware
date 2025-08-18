# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# teleport.py - Magically transport extremely sensitive data between the
#               secure environment of two Q's.
#
import ngu, aes256ctr, bip39, json, ndef, chains
from utils import xfp2str, deserialize_secret
from ubinascii import unhexlify as a2b_hex
from ubinascii import hexlify as b2a_hex
from glob import settings, dis
from ux import ux_show_story, ux_confirm, the_ux, ux_dramatic_pause
from ux_q1 import show_bbqr_codes, QRScannerInteraction, ux_input_text
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL
from bbqr import b32encode, b32decode
from menu import MenuItem, MenuSystem
from notes import NoteContentBase
from sffile import SFFile
from multisig import MultisigWallet
from stash import SensitiveValues, SecretStash, blank_object, bip39_passphrase

# One page github-hosted static website that shows QR based on URL contents pushed by NFC
KT_DOMAIN = 'keyteleport.com'

# No length/size worries with simple secrets, but massive notes and big PSBT,
# with lots of UTXO, cannot be passed via NFC URL, because we are limited by
# NFC chip (8k) and URL length (4k or less) inside. BBQr is not limited however.
# - but the website is ready to make animated BBQr nicely
NFC_SIZE_LIMIT = const(4096)

def short_bbqr(type_code, data):
    # Short-circuit basic BBQr encoding here: always Base32, single part: 1 of 1
    # - used only for NFC link, where website may split again into parts
    hdr = 'B$2%s0100' % type_code

    return hdr + b32encode(data)

def txt_grouper(txt):
    # split into 2-char groups and add spaces -- to make it easier to read/remember
    return ' '.join(txt[n:n+2] for n in range(0, len(txt), 2))

async def nfc_push_kt(qrdata):
    # NFC push to send them to our QR-rendering website

    url = KT_DOMAIN + '/#' + qrdata

    n = ndef.ndefMaker()
    n.add_url(url, https=True)

    from glob import NFC
    await NFC.share_loop(n, prompt="View QR on web", line2=KT_DOMAIN)

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

    short_code, payload = generate_rx_code(kp)

    msg = '''To receive sensitive data from another COLDCARD, \
share this Receiver Password with sender:

   %s  =  %s

and show the QR on next screen to the sender. ENTER or %s to show here''' % (
        short_code, txt_grouper(short_code), KEY_QR)

    await tk_show_payload('R', payload, 'Key Teleport: Receive', msg, cta='Show to Sender')

def generate_rx_code(kp):
    # Receiver-side password: given a pubkey (33 bytes, compressed format)
    # - construct an 8-digit decimal "password"
    # - it's a AES key, but only 26 bits worth
    pubkey = bytearray(kp.pubkey().to_bytes())        # default: compressed format
    #assert len(pubkey) == 33

    # - want the code to be deterministic, but I also don't want to save it
    nk = ngu.hash.sha256d(kp.privkey() + b'COLCARD4EVER')

    # first byte will be 0x02 or 0x03 (Y coord) -- remove those known 7 bits
    pubkey[0] ^= nk[20] & 0xfe

    num = '%08d' % (int.from_bytes(nk[4:8], 'big') % 1_0000_0000)

    # encryption after baby key stretch
    kk = ngu.hash.sha256s(num.encode())
    enc = aes256ctr.new(kk).cipher(pubkey)

    return num, enc

def decrypt_rx_pubkey(code, payload):
    # given a 8-digit numeric code, make the key and then decrypt/checksum check
    # - every value works, there is no fail.
    kk = ngu.hash.sha256s(code.encode())
    rx_pubkey = bytearray(aes256ctr.new(kk).cipher(payload))

    # first byte will be 0x02 or 0x03 but other 7 bits are noise
    rx_pubkey[0] &= 0x01
    rx_pubkey[0] |= 0x02

    # validate that it's on the curve... otherwise the code is wrong
    try:
        ngu.secp256k1.pubkey(rx_pubkey)

        return rx_pubkey
    except:
        return None

async def tk_show_payload(type_code, payload, title, msg, cta=None):
    # show the QR and/or NFC
    # - MAYBE: make easier/faster to pick NFC from QR screen and vice-versa
    from glob import NFC

    hints = KEY_QR
    if NFC and len(payload) < NFC_SIZE_LIMIT:
        hints += KEY_NFC
        msg += ' or %s to view on your phone' % KEY_NFC

    msg += '. CANCEL to stop.'

    # simply show the QR
    while 1:
        ch = await ux_show_story(msg, title=title, hint_icons=hints)

        if ch == KEY_NFC and NFC:
            await nfc_push_kt(short_bbqr(type_code, payload))
        elif ch == KEY_QR or ch == 'y':
            # NOTE: CTA rarely seen, but maybe sometimes?
            await show_bbqr_codes(type_code, payload, msg=cta)
        elif ch == 'x':
            return

async def kt_start_send(rx_data):
    # a QR was scanned and it held (most of) a pubkey
    # - they want to send to this guy
    # - ask them what to send, etc

    while 1:
        # - ask for the sender's password -- nearly any value will be accepted
        code = await ux_input_text('', confirm_exit=False, hex_only=True, max_len=8,
            prompt='Teleport Password (number)', min_len=8, b39_complete=False, scan_ok=False,
            placeholder='########', funct_keys=None, force_xy=None)
        if not code: return

        rx_pubkey = decrypt_rx_pubkey(code, rx_data)

        if rx_pubkey:
            break

        # I think only about 50% odds of catching an incorrect code. Not sure.
        ch = await ux_show_story(
                "Incorrect Teleport Password. You can try again or CANCEL to stop.")
        if ch == 'x': return

    msg = '''You can now Key Teleport secrets! Choose what to share on next screen.\
\n
WARNING: Receiver will have full access to all Bitcoin controlled by these keys!'''

    ch = await ux_show_story(msg, title="Key Teleport: Send")
    if ch != 'y': return

    # pick what to send from a series of submenus
    menu = SecretPickerMenu(rx_pubkey)
    the_ux.push(menu)

async def kt_do_send(rx_pubkey, dtype, raw=None, obj=None, prefix=b'', rx_label='the receiver', kp=None):
    # We are rendering a QR and showing it to them for sending to another Q
    dis.fullscreen("Wait...")
    cleartext = dtype.encode() + (raw or json.dumps(obj).encode())
    dis.progress_bar_show(0.1)

    # Pick and show noid key to sender
    noid_key, txt = pick_noid_key()

    dis.progress_bar_show(0.25)

    # all new EC key
    my_keypair = kp or ngu.secp256k1.keypair()

    dis.progress_bar_show(0.75)

    payload = prefix + encode_payload(my_keypair, rx_pubkey, noid_key, cleartext,
                                                for_psbt=bool(prefix))

    dis.progress_bar_show(1)

    msg = "Share this password with %s, via some different channel:"\
                "\n\n   %s  =  %s\n\n" % (rx_label, txt, txt_grouper(txt))
    msg += "ENTER to view QR"

    await tk_show_payload('S' if not prefix else 'E', payload,
                          'Teleport Password', msg, cta='Show to Receiver')

    if not prefix:
        # not PSBT case ... reset menus, we are deep!
        from actions import goto_top_menu
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

    prompt = 'Teleport Password (text)'

    if not is_psbt:
        rx_key = settings.get("ktrx")
        if not rx_key:
            await ux_show_story("Not expecting any teleports. You need to start over.")

            await kt_start_rx()         # help them to start over? idk maybe not.
            return

        his_pubkey = payload[0:33]
        body = payload[33:]
        pair = ngu.secp256k1.keypair(a2b_hex(rx_key))

        ses_key, body = decode_step1(pair, his_pubkey, body)
    else:
        # Multisig PSBT: will need to iterate over a few wallets and each N-1 possible senders
        if not MultisigWallet.exists():
            await ux_show_story("Incoming PSBT requires multisig wallet(s) to be already setup, but you have none.")
            return

        ses_key, body, sender_xfp = MultisigWallet.kt_search_rxkey(payload)

        if sender_xfp is not None:
            prompt = 'Teleport Password from [%s]' % xfp2str(sender_xfp)

    if not ses_key:
        # when ECDH fails, it's truncation or wrong RX key (due to sender using old rx key,
        # or the numeric code the sender entered was wrong, etc)
        await ux_show_story("QR code was damaged, "+
                ("numeric password was wrong, " if not is_psbt else "")+
                "or it was sent to a different user. "
                "Sender must start again.", title="Teleport Fail")
        return

    while 1:
        # ask for noid key
        pw = await ux_input_text('', confirm_exit=False, hex_only=False, max_len=8,
                prompt=prompt, min_len=8, b39_complete=False, scan_ok=False,
                placeholder='********', funct_keys=None, force_xy=None)
        if not pw: return

        dis.fullscreen("Wait...")
        try:
            assert len(pw) == 8
            noid_key = b32decode(pw)       # case insenstive, and smart about confused chars
            final = decode_step2(ses_key, noid_key, body)
            if final is not None: 
                break
        except: pass

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
    - `r` - raw XPRV mode - 64 bytes follow which are the chain code then master privkey 
    - `x` - XPRV mode, full details - 4 bytes (XPRV) + base58 *decoded* binary-XPRV follows
    - `n` - one or many notes export (JSON array)
    - `v` - seed vault export (JSON: one secret key but includes includes name, source of key)
    - `p` - binary PSBT to be signed
    - `b` - complete system backup file (text, internal format)
    '''
    from flow import has_se_secrets, goto_top_menu
    from pincodes import pa

    enc = None
    origin = 'Teleported'
    label = None

    if pa.hobbled_mode and dtype != 'p':
        await ux_show_story('Only PSBT for multisig accepted in this mode.', title='FAILED')
        return
    

    if dtype == 's':
        # words / bip 32 master / xprv, etc
        enc = bytearray(72)
        enc[0:len(raw)] = raw

    elif dtype == 'x':
        # it's an XPRV, but in binary.. some extra data we throw away here; sigh
        # XXX no way to send this .. but was thinking of address explorer
        txt = ngu.codecs.b58_encode(raw)
        node, ch, _, _ = chains.slip32_deserialize(txt)
        assert ch.name == chains.current_chain().name, 'wrong chain'
        enc = SecretStash.encode(xprv=node)

    elif dtype == 'p':
        # raw PSBT -- much bigger more complex
        from auth import sign_transaction, TXN_INPUT_OFFSET

        psbt_len = len(raw)

        # copy into PSRAM
        with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
            out.write(raw)

        # This will take over UX w/ the signing process
        # flags=None --> whether to finalize is decided based on psbt.is_complete
        sign_transaction(psbt_len, flags=None)
        return

    elif dtype == 'b':
        # full system backup, including master: text lines
        from backups import text_bk_parser, restore_tmp_from_dict_ll, restore_from_dict

        vals = text_bk_parser(raw)
        assert vals         # empty?

        from flow import has_secrets

        if has_secrets():
            # restores as tmp secret and/or offers to save to SeedVault
            # need to remove key before I get into tmp seed settings
            # so even if this errors out, new ktrx is needed
            settings.remove_key("ktrx")
            prob = await restore_tmp_from_dict_ll(vals)
        else:
            # we have no secret, so... reboot if it works, else errors shown, etc.
            prob = await restore_from_dict(vals)

        if prob:
            await ux_show_story(prob, title='FAILED')
        else:
            # force new rx key because this tfr worked
            # only has effect if in master seed settings
            settings.remove_key("ktrx")         
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
    settings.remove_key("ktrx")     # force new rx key after this point
    assert enc

    from seed import set_ephemeral_seed, set_seed_value

    if not has_se_secrets():
        # unit has nothing, so this will be the master seed
        set_seed_value(encoded=enc)
        ok = True
    else:
        ok = await set_ephemeral_seed(enc, origin=origin, label=label)

    if ok:
        goto_top_menu()

def noid_stretch(session_key, noid_key):
    # TODO: measure timing of this on real Q
    return ngu.hash.pbkdf2_sha512(session_key, noid_key, 5000)[0:32]

def encode_payload(my_keypair, his_pubkey, noid_key, body, for_psbt=False):
    # do all the encryption for sender
    assert len(his_pubkey) == 33
    assert len(noid_key) == 5

    # this can fail with ValueError: secp256k1_ec_pubkey_parse
    # if the user has provided the wrong value for numeric password
    # - better to catch this sooner in decrypt_rx_pubkey
    session_key = my_keypair.ecdh_multiply(his_pubkey)

    # stretch noid key out -- will be slow
    pk = noid_stretch(session_key, noid_key)

    b1 = aes256ctr.new(pk).cipher(body)
    b1 += ngu.hash.sha256s(body)[-2:]

    b2 = aes256ctr.new(session_key).cipher(b1)
    b2 += ngu.hash.sha256s(b1)[-2:]

    if for_psbt:
        # no need to share pubkey for PSBT files
        return b2

    return my_keypair.pubkey().to_bytes() +  b2

def decode_step1(my_keypair, his_pubkey, body):
    # Do ECDH and remove top layer of encryption
    try:
        assert len(body) >= 3

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

    from pincodes import pa
    if pa.hobbled_mode and type_code != 'E':
        # only PSBT rx is supported in hobbled mode
        # TODO: fail silently? good enough?
        return

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

        # this menu should be unreachable in hobbled mode.
        from pincodes import pa
        assert not pa.hobbled_mode

        from flow import word_based_seed, is_tmp, has_se_secrets
        has_notes = bool(NoteContentBase.count())
        has_sv = bool(settings.get('seedvault', False))

        # Q-only feature, so menu can be W I D E 
        # - in increasing order of importance & sensitivity!
        # - pinned-virgin mode is supported, so might not have any secrets to share yet,
        #   but can do secret notes still
        m = [
            MenuItem('Quick Text Message', f=self.quick_note),
            MenuItem('Single Note / Password', predicate=has_notes, menu=self.pick_note_submenu),
            MenuItem('Export All Notes & Passwords', predicate=has_notes, f=self.picked_note),
        ]

        if has_sv:
            m.append( MenuItem('From Seed Vault',  menu=self.pick_vault_submenu) )

        msg = None
        if is_tmp():
            # tmp seed, or maybe bip39 is in effect 
            # - share the current master secret, not the real master
            msg = 'Temp Secret (words)' if word_based_seed() else (
                        'XPRV from Words+Passphrase' if bip39_passphrase else 'Temp XPRV Secret')
        elif has_se_secrets():
            # sharing real master secret
            msg = 'Master Seed Words' if word_based_seed() else 'Master XPRV'

        if msg:
            m.append( MenuItem(msg, f=self.share_master_secret) )
            m.append( MenuItem("Full COLDCARD Backup", f=self.share_full_backup) )
        
        super().__init__(m)

    async def pick_vault_submenu(self, *a):
        # pick a secret from seed vault
        from seed import SeedVaultChooserMenu
        rec = await SeedVaultChooserMenu.pick()
        if rec:
            await kt_do_send(self.rx_pubkey, 'v', obj=list(rec))

    async def pick_note_submenu(self, *a):
        # Make a submenu to select a single note/password
        rv = []
        for note in NoteContentBase.get_all():
            rv.append(MenuItem('%d: %s' % (note.idx+1, note.title), f=self.picked_note, arg=note))

        return rv

    async def quick_note(self, _, _2, item):
        # accept a text string, and send as a note
        from notes import NoteContent
        txt = await ux_input_text('', max_len=100,
            prompt='Enter your message', min_len=1, b39_complete=True, scan_ok=True,
            placeholder='Attack at dawn.')

        if not txt: return

        n = NoteContent(dict(title="Quick Note", misc=txt))
        await kt_do_send(self.rx_pubkey, 'n', obj=[n.serialize()])

    async def picked_note(self, _, _2, item):
        # exporting note(s)

        if item.arg is None:
            # export all
            body = [n.serialize() for n in NoteContentBase.get_all()]
        else:
            # single note/password
            body = [item.arg.serialize()]

        await kt_do_send(self.rx_pubkey, 'n', obj=body)

    async def share_full_backup(self, *a):
        # context, and warn them
        ch = await ux_show_story("Sending complete backup, including master secret, "
            "seed vault (if any), multisig wallets, notes/passwords, and all settings! "
            "The receiving "
            "COLDCARD must already have the master seed wiped to be able to install "
            "everything, otherwise only master secret and multisig are saved into a tmp seed. "
            "OK to proceed?")
        if ch != 'y': return

        from backups import render_backup_contents

        dis.fullscreen("Buiding Backup...")

        # renders a text file, with rather a lot of comments; strip them
        bkup = render_backup_contents(bypass_tmp=True)
        out = []
        for ln in bkup.split('\n'):
            if not ln: continue
            if ln[0] == '#': continue
            out.append(ln)

        await kt_do_send(self.rx_pubkey, 'b', raw=b'\n'.join(ln.encode() for ln in out))

    async def share_master_secret(self, _, _2, item):
        # altho menu items look different we are sharing same thing:
        # - up to 72 bytes from secure elements

        dis.fullscreen("Wait...")

        with SensitiveValues(bypass_tmp=False, enforce_delta=True) as sv:
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


async def kt_send_psbt(psbt, psbt_len):
    # We just finished adding our signature to an incomplete PSBT.
    # User wants to send to one or more other senders for them to complete signing.

    # who remains to sign? look at inputs
    ms = psbt.active_multisig
    all_xfps = [x for x,*p in ms.get_xfp_paths()]
    need = [x for x in psbt.multisig_xfps_needed() if x in all_xfps]

    # maybe it's not really a PSBT where we know the other signers? might be
    # a weird coinjoin we don't fully understand
    if not need:
        await ux_show_story("No more signers?")
        return

    # move out of PSRAM
    from auth import TXN_OUTPUT_OFFSET

    with SFFile(TXN_OUTPUT_OFFSET, psbt_len) as fd:
        bin_psbt = fd.read(psbt_len)

    my_xfp = settings.get('xfp')

    # if my_xfp in need:
    # - we haven't signed yet? let's do that now .. except we've lost some of the
    #   data we need such as filename to save back into.
    # - so just keep going instead... maybe they want to be last signer?

    # Make them pick a single next signer. It's not helpful to do multiple at once
    # here, since we need signatures to be added serially so that last
    # signer can do finalization. We don't have a general purpose combiner.

    async def done_cb(m, idx, item):
        m.next_xfp = item.arg
        the_ux.pop()

    ci = []
    next_signer = None
    for idx, x in enumerate(all_xfps):
        txt = '[%s] Co-signer #%d' % (xfp2str(x), idx+1)
        f = done_cb
        if x == my_xfp:
            txt += ': YOU'
            f = None
            if x in need:
                # we haven't signed ourselves yet, so allow that
                from auth import sign_transaction, TXN_INPUT_OFFSET

                async def sign_now(*a):
                    # this will reset the UX stack:
                    # flags=None --> whether to finalize is decided based on psbt.is_complete
                    sign_transaction(psbt_len, flags=None)
                
                f = sign_now

        elif x not in need:
            txt += ': DONE'
            f = None

        mi = MenuItem(txt, f=f, arg=x)

        if x not in need:
            # show check if we've got sig
            mi.is_chosen = lambda: True
        elif next_signer is None:
            next_signer = idx

        ci.append(mi)

    m = MenuSystem(ci)
    m.next_xfp = None
    m.goto_idx(next_signer)     # position cursor on next candidate
    the_ux.push(m)
    await m.interact()
    
    if m.next_xfp:
        assert m.next_xfp != my_xfp
        ri, rx_pubkey, kp = ms.kt_make_rxkey(m.next_xfp)
        await kt_do_send(rx_pubkey, 'p', raw=bin_psbt, prefix=ri, kp=kp,
                        rx_label='[%s] co-signer' % xfp2str(m.next_xfp))

        return True, ms.M - (ms.N - len(need))

async def kt_send_file_psbt(*a):
    # Menu item: choose a PSBT file from SD card, and send to co-signers.
    # Heavy code re-use here. Need to find the multisig wallet associated w/ file,
    # so we need to parse it and we must be one of the co-signers.

    from actions import is_psbt, file_picker
    from auth import sign_psbt_file, TXN_INPUT_OFFSET
    from version import MAX_TXN_LEN
    from ux import import_export_prompt
    from psbt import psbtObject

    # choose any PSBT from SD
    picked = await import_export_prompt("PSBT", is_import=True, no_nfc=True, no_qr=True)
    if picked == KEY_CANCEL:
        return
    choices = await file_picker(suffix='psbt', min_size=50, ux=False,
                                  max_size=MAX_TXN_LEN, taster=is_psbt, **picked)
    if not choices:
        # error msg already shown
        return

    if len(choices) == 1:
        # single - skip the menu
        label,path,fn = choices[0]
        input_psbt = path + '/' + fn
    else:
        # multiples - make them pick one
        input_psbt = await file_picker(choices=choices)
        if not input_psbt:
            return

    # read into PSRAM from wherever
    psbt_len = await sign_psbt_file(input_psbt, just_read=True, **picked)

    dis.fullscreen("Validating...")
    try:
        dis.progress_sofar(1, 4)
        with SFFile(TXN_INPUT_OFFSET, length=psbt_len, message='Reading...') as fd:
            # NOTE: psbtObject captures the file descriptor and uses it later
            psbt = psbtObject.read_psbt(fd)

        await psbt.validate()      # might do UX: accept multisig import

        dis.progress_sofar(2, 4)
        psbt.consider_inputs()
        dis.progress_sofar(3, 4)

        psbt.consider_keys()

    except Exception as exc:
        # not going to do full reporting here, use our other code for that!
        await ux_show_story("Cannot validate PSBT?\n\n"+str(exc), "PSBT Load Failed")
        return
    finally:
        dis.progress_bar_show(1)

    if not psbt.active_multisig:
        await ux_show_story("We are not part of this multisig wallet.", "Cannot Teleport PSBT")
        return

    await kt_send_psbt(psbt, psbt_len=psbt_len)
    
# EOF
