# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Signatures over text ... not transactions.
#
import stash, chains, sys, gc, ngu, ujson, version
from ubinascii import b2a_base64, a2b_base64
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from uhashlib import sha256
from public_constants import MSG_SIGNING_MAX_LENGTH
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from charcodes import KEY_QR, KEY_NFC, KEY_ENTER, KEY_CANCEL
from ux import ux_show_story, OK, X, ux_enter_bip32_index
from utils import problem_file_line, to_ascii_printable, show_single_address
from files import CardSlot, CardMissingError, needs_microsd

def rfc_signature_template(msg, addr, sig):
    # RFC2440 <https://www.ietf.org/rfc/rfc2440.txt> style signatures, popular
    # since the genesis block, but not really part of any BIP as far as I know.
    #
    return [
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n",
        "%s\n" % msg,
        "-----BEGIN BITCOIN SIGNATURE-----\n",
        "%s\n" % addr,
        "%s\n" % sig,
        "-----END BITCOIN SIGNATURE-----\n"
    ]

def parse_armored_signature_file(contents):
    # XXX limited parser: will fail w/ messages containing dashes
    sep = "-----"
    assert contents.count(sep) == 6, "Armor text MUST be surrounded by exactly five (5) dashes."

    temp = contents.split(sep)
    msg = temp[2].strip()
    addr_sig = temp[4].strip()
    addr, sig_str = addr_sig.split()

    return msg, addr, sig_str

def verify_signature(msg, addr, sig_str):
    # Look at a base64 signature, and given address. Do full verification.
    # - raise on errors
    # - return warnings as string: can only be mismatch between addr format encoded in recid
    warnings = ""
    script = None
    hash160 = None
    invalid_addr_fmt_msg = "Invalid address format - must be one of p2pkh, p2sh-p2wpkh, or p2wpkh."
    invalid_addr = "Invalid signature for message."

    if addr[0] in "1mn":
        addr_fmt = AF_CLASSIC
        decoded_addr = ngu.codecs.b58_decode(addr)
        hash160 = decoded_addr[1:]  # remove prefix
    elif addr.startswith("bc1q") or addr.startswith("tb1q") or addr.startswith("bcrt1q"):
        if len(addr) > 44:  # testnet/mainnet max singlesig len 42, regtest 44
            # p2wsh
            raise ValueError(invalid_addr_fmt_msg)
        addr_fmt = AF_P2WPKH
        _, _, hash160 = ngu.codecs.segwit_decode(addr)
    elif addr[0] in "32":
        addr_fmt = AF_P2WPKH_P2SH
        decoded_addr = ngu.codecs.b58_decode(addr)
        script = decoded_addr[1:]  # remove prefix
    else:
        raise ValueError(invalid_addr_fmt_msg)

    try:
        sig_bytes = a2b_base64(sig_str)
        if not sig_bytes or len(sig_bytes) != 65:
            # can return b'' in case of wrong, can also raise
            raise ValueError("invalid encoding")

        header_byte = sig_bytes[0]
        header_base = chains.current_chain().sig_hdr_base(addr_fmt)
        if (header_byte - header_base) not in (0, 1, 2, 3):
            # wrong header value only - this can still verify OK
            warnings += "Specified address format does not match signature header byte format."

        # least two significant bits
        rec_id = (header_byte - 27) & 0x03
        # need to normalize it to 31 base for ngu
        new_header_byte = 31 + rec_id
        sig = ngu.secp256k1.signature(bytes([new_header_byte]) + sig_bytes[1:])
    except ValueError as e:
        raise ValueError("Parsing signature failed - %s." % str(e))

    digest = chains.current_chain().hash_message(msg.encode('ascii'))
    try:
        rec_pubkey = sig.verify_recover(digest)
    except ValueError as e:
        raise ValueError("Invalid signature for msg - %s." % str(e))

    rec_pubkey_bytes = rec_pubkey.to_bytes()
    rec_hash160 = ngu.hash.hash160(rec_pubkey_bytes)

    if script:
        target = bytes([0, 20]) + rec_hash160
        target = ngu.hash.hash160(target)
        if target != script:
            raise ValueError(invalid_addr)
    else:
        if rec_hash160 != hash160:
            raise ValueError(invalid_addr)

    return warnings

async def verify_armored_signed_msg(contents, digest_check=True):
    # Verify on-disk checksums of files listed inside a signed file.
    # - digest_check=False for NFC cases, where we do not have filesystem
    from glob import dis

    dis.fullscreen("Verifying...")

    try:
        msg, addr, sig_str = parse_armored_signature_file(contents)
    except Exception as e:
        e_line = problem_file_line(e)
        await ux_show_story("Malformed signature file. %s %s" % (str(e), e_line), title="FAILURE")
        return

    try:
        sig_warn = verify_signature(msg, addr, sig_str)
    except Exception as e:
        await ux_show_story(str(e), title="ERROR")
        return

    title = "CORRECT"
    warn_msg = ""
    err_msg = ""
    story = "Good signature by address:\n%s" % show_single_address(addr)

    if digest_check:
        digest_prob = verify_signed_file_digest(msg)
        if digest_prob:
            err, digest_warn = digest_prob
            if digest_warn:
                title = "WARNING"
                wmsg_base = "not present. Contents verification not possible."
                if len(digest_warn) == 1:
                    fname = digest_warn[0][0]
                    warn_msg += "'%s' is %s" % (fname, wmsg_base)
                else:
                    warn_msg += "Files:\n" + "\n".join("> %s" % fname for fname, _ in digest_warn)
                    warn_msg += "\nare %s" % wmsg_base

            if err:
                title = "ERROR"
                for fname, calc, got in err:
                    err_msg += ("Referenced file '%s' has wrong contents.\n"
                                "Got:\n%s\n\nExpected:\n%s" % (fname, got, calc))

    if sig_warn:
        # we know not ours only because wrong recid header used & not BIP-137 compliant
        story = "Correctly signed, but not by this Coldcard. %s" % sig_warn

    await ux_show_story('\n\n'.join(m for m in [err_msg, story, warn_msg] if m), title=title)

async def verify_txt_sig_file(filename):
    # copy message into memory
    try:
        with CardSlot() as card:
            with card.open(filename, 'rt') as fd:
                text = fd.read()
    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Error: ' + str(e))
        return

    await verify_armored_signed_msg(text)

async def msg_sign_ux_get_subpath(addr_fmt):
    # Ask for account number, and maybe change component of path for signature.
    # - return full derivation path to be used.
    purpose = chains.af_to_bip44_purpose(addr_fmt)
    chain_n = chains.current_chain().b44_cointype

    acct = await ux_enter_bip32_index('Account Number:') or 0

    ch = await ux_show_story(title="Change?",
                             msg="Press (0) to use internal/change address,"
                                 " %s to use external/receive address." % OK, escape="0")
    change = 1 if ch == '0' else 0

    idx = await ux_enter_bip32_index('Index Number:') or 0

    return "m/%dh/%dh/%dh/%d/%d" % (purpose, chain_n, acct, change, idx)


def sign_export_contents(content_list, deriv, addr_fmt, pk=None):
    # Return signed message over hashes of files.
    msg2sign = make_signature_file_msg(content_list)
    bitcoin_digest = chains.current_chain().hash_message(msg2sign)
    sig_bytes, addr = sign_message_digest(bitcoin_digest, deriv, "Signing...", addr_fmt, pk=pk)
    sig = b2a_base64(sig_bytes).decode().strip()

    return rfc_signature_template(addr=addr, msg=msg2sign.decode(), sig=sig)

def verify_signed_file_digest(msg):
    # Look inside a list of hashs and file names, and
    # verify at their actual hashes and return list of issues if any.
    from files import CardSlot

    parsed_msg = parse_signature_file_msg(msg)
    if not parsed_msg:
        # not our format
        return

    try:
        err, warn = [], []
        with CardSlot() as card:
            for digest, fname in parsed_msg:
                path = card.abs_path(fname)
                if not card.exists(path):
                    warn.append((fname, None))
                    continue
                path = card.abs_path(fname)

                md = sha256()
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(1024)
                        if not chunk:
                            break
                        md.update(chunk)

                h = b2a_hex(md.digest()).decode().strip()
                if h != digest:
                    err.append((fname, h, digest))
    except:
        # fail silently if issues with reading files or SD issues
        # no digest checking
        return

    return err, warn

def write_sig_file(content_list, derive=None, addr_fmt=AF_CLASSIC, pk=None, sig_name=None):
    from glob import dis

    if derive is None:
        ct = chains.current_chain().b44_cointype
        derive = "m/44'/%d'/0'/0/0" % ct

    fpath = content_list[0][1]
    if len(content_list) > 1:
        # we're signing contents of more files - need generic name for sig file
        assert sig_name
        sig_nice = sig_name + ".sig"
        sig_fpath = fpath.rsplit("/", 1)[0] + "/" + sig_nice
    else:
        sig_fpath = fpath.rsplit(".", 1)[0] + ".sig"
        sig_nice = sig_fpath.split("/")[-1]

    sig_gen = sign_export_contents([(h, f.split("/")[-1]) for h, f in content_list],
                                   derive, addr_fmt, pk=pk)

    with open(sig_fpath, 'wt') as fd:
        for i, part in enumerate(sig_gen):
            fd.write(part)

    return sig_nice

def validate_text_for_signing(text, only_printable=True):
    # Check for some UX/UI traps in the message itself.
    # - messages must be short and ascii only. Our charset is limited
    # - too many spaces, leading/trailing can be an issue
    # MSG_MAX_SPACES = 4      # impt. compared to -=- positioning

    result = to_ascii_printable(text, only_printable=only_printable)

    length = len(result)
    assert length >= 2, "msg too short (min. 2)"
    assert length <= MSG_SIGNING_MAX_LENGTH, "msg too long (max. %d)" % MSG_SIGNING_MAX_LENGTH
    assert "   " not in result, 'too many spaces together in msg(max. 3)'
    # other confusion w/ whitepace
    assert result[0] != ' ', 'leading space(s) in msg'
    assert result[-1] != ' ', 'trailing space(s) in msg'

    # looks ok
    return result

def addr_fmt_from_subpath(subpath):
    if not subpath:
        af = "p2pkh"
    elif subpath[:4] == "m/84":
        af = "p2wpkh"
    elif subpath[:4] == "m/49":
        af = "p2sh-p2wpkh"
    else:
        af = "p2pkh"
    return af

def parse_msg_sign_request(data):
    subpath = ""
    addr_fmt = None
    is_json = False

    # sparrow compat
    if "signmessage" in data:
        try:
            mark, subpath, *msg_line = data.split(" ", 2)
            assert mark == "signmessage"
            # subpath will be verified & cleaned later
            assert msg_line[0][:6] == "ascii:"
            text = msg_line[0][6:]
            return text, subpath, addr_fmt_from_subpath(subpath), is_json
        except:pass
    # ===

    try:
        data_dict = ujson.loads(data.strip())
        text = data_dict.get("msg", None)
        if text is None:
            raise AssertionError("MSG required")
        subpath = data_dict.get("subpath", subpath)
        addr_fmt = data_dict.get("addr_fmt", addr_fmt)
        is_json = True
    except ValueError:
        lines = data.split("\n")
        assert len(lines) >= 1, "min 1 line"
        assert len(lines) <= 3, "max 3 lines"

        if len(lines) == 1:
            text = lines[0]
        elif len(lines) == 2:
            text, subpath = lines
        else:
            text, subpath, addr_fmt = lines

    if not addr_fmt:
        addr_fmt = addr_fmt_from_subpath(subpath)

    if not subpath:
        subpath = chains.STD_DERIVATIONS[addr_fmt]
        subpath = subpath.format(
            coin_type=chains.current_chain().b44_cointype,
            account=0, change=0, idx=0
        )

    return text, subpath, addr_fmt, is_json


def make_signature_file_msg(content_list):
    # list of tuples consisting of (hash, file_name)
    return b"\n".join([
        b2a_hex(h) + b"  " + fname.encode()
        for h, fname in content_list
    ])

def parse_signature_file_msg(msg):
    # only succeed for our format digest + 2 spaces + fname
    try:
        res = []
        lines = msg.split('\n')
        for ln in lines:
            d, fn = ln.split('  ')
            # should not need to strip if our file format, so dont
            # is hex? is 32 bytes long?
            assert len(a2b_hex(d)) == 32
            res.append((d, fn))

        return res
    except:
        return

def sign_message_digest(digest, subpath, prompt, addr_fmt=AF_CLASSIC, pk=None):
    # do the signature itself!
    from glob import dis

    ch = chains.current_chain()

    if prompt:
        dis.fullscreen(prompt, percent=.25)

    if pk is None:
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            dis.progress_sofar(50, 100)
            pk = node.privkey()
            addr = ch.address(node, addr_fmt)
    else:
        # if private key is provided, derivation subpath is ignored
        # and given private key is used for signing.
        node = ngu.hdnode.HDNode().from_chaincode_privkey(bytes(32), pk)
        dis.progress_sofar(50, 100)
        addr = ch.address(node, addr_fmt)

    dis.progress_sofar(75, 100)

    rv = ngu.secp256k1.sign(pk, digest, 0).to_bytes()

    # AF_CLASSIC header byte base 31 is returned by default from ngu - NOOP
    if addr_fmt != AF_CLASSIC:
        # ngu only produces header base for compressed p2pkh, anyways get only rec_id
        rv = bytearray(rv)
        rec_id = (rv[0] - 27) & 0x03
        rv[0] = rec_id + ch.sig_hdr_base(addr_fmt=addr_fmt)

    dis.progress_bar_show(1)

    return rv, addr

async def ux_sign_msg(txt, approved_cb=None, kill_menu=True):
    from menu import MenuSystem, MenuItem
    from ux import the_ux

    async def done(_1, _2, item):
        from auth import approve_msg_sign

        text, af = item.arg
        subpath = await msg_sign_ux_get_subpath(af)

        await approve_msg_sign(text, subpath, af, approved_cb=approved_cb,
                               kill_menu=kill_menu, only_printable=False)

    # pick address format
    rv = [
        MenuItem(chains.addr_fmt_label(af), f=done, arg=(txt, af))
        for af in chains.SINGLESIG_AF
    ]
    the_ux.push(MenuSystem(rv))

async def msg_signing_done(signature, address, text):
    from ux import import_export_prompt

    ch = await import_export_prompt("Signed Msg", is_import=False,
                                    no_qr=not version.has_qwerty)
    if ch == KEY_CANCEL:
        return

    if isinstance(ch, dict):
        await sd_sign_msg_done(signature, address, text, "msg_sign", **ch)
    elif version.has_qr and ch == KEY_QR:
        from ux_q1 import qr_msg_sign_done
        await qr_msg_sign_done(signature, address, text)
    elif ch in KEY_NFC+"3":
        from glob import NFC
        if NFC:
            await NFC.msg_sign_done(signature, address, text)


async def sign_with_own_address(subpath, addr_fmt):
    # used for cases where we already have the key picked, but need the message:
    #     * address_explorer custom path
    #     * positive ownership test
    from glob import dis

    to_sign = await ux_input_text("", scan_ok=True, prompt="Enter MSG")  # max len is 100 only here
    if not to_sign: return

    await approve_msg_sign(to_sign, subpath, addr_fmt, approved_cb=msg_signing_done, kill_menu=True)

async def sd_sign_msg_done(signature, address, text, base=None, orig_path=None,
                           slot_b=None, force_vdisk=False):
    from glob import dis
    dis.fullscreen('Generating...')

    out_fn = None
    sig = b2a_base64(signature).decode('ascii').strip()

    while 1:
        # try to put back into same spot
        # add -signed to end.
        target_fname = base + '-signed.txt'
        lst = [orig_path]
        if orig_path:
            lst.append(None)

        for path in lst:
            try:
                with CardSlot(readonly=True, slot_b=slot_b, force_vdisk=force_vdisk) as card:
                    out_full, out_fn = card.pick_filename(target_fname, path)
                    out_path = path
                    if out_full: break
            except CardMissingError:
                prob = 'Missing card.\n\n'
                out_fn = None

        if not out_fn:
            # need them to insert a card
            prob = ''
        else:
            # attempt write-out
            try:
                dis.fullscreen("Saving...")

                with CardSlot(slot_b=slot_b, force_vdisk=force_vdisk) as card:
                    with card.open(out_full, 'wt') as fd:
                        # save in full RFC style
                        # gen length is 6
                        gen = rfc_signature_template(addr=address, msg=text, sig=sig)
                        for i, part in enumerate(gen):
                            fd.write(part)

                # success and done!
                break

            except OSError as exc:
                prob = 'Failed to write!\n\n%s\n\n' % exc
                sys.print_exception(exc)
                # fall through to try again

        # prompt them to input another card?
        ch = await ux_show_story(prob + "Please insert an SDCard to receive signed message, "
                                        "and press %s." % OK, title="Need Card")
        if ch == 'x':
            await ux_aborted()
            return

    # done.
    msg = "Created new file:\n\n%s" % out_fn
    await ux_show_story(msg, title='File Signed')



# EOF
