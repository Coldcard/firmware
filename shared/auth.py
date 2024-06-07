# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, ux, chains, sys, gc, uio, version, ngu, ujson
from ubinascii import b2a_base64, a2b_base64
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from uhashlib import sha256
from public_constants import MSG_SIGNING_MAX_LENGTH, SUPPORTED_ADDR_FORMATS, AF_P2TR
from public_constants import AFC_SCRIPT, AF_CLASSIC, AFC_BECH32, AF_P2WPKH, AF_P2WPKH_P2SH
from public_constants import STXN_FLAGS_MASK, STXN_FINALIZE, STXN_VISUALIZE, STXN_SIGNED
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys
from ux import show_qr_code, OK, X
from usb import CCBusyError
from utils import HexWriter, xfp2str, problem_file_line, cleanup_deriv_path
from utils import B2A, parse_addr_fmt_str, to_ascii_printable
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from files import CardSlot
from exceptions import HSMDenied
from version import MAX_TXN_LEN
from charcodes import KEY_QR, KEY_NFC, KEY_ENTER, KEY_CANCEL, KEY_LEFT, KEY_RIGHT

# Where in SPI flash/PSRAM the two PSBT files are (in and out)
TXN_INPUT_OFFSET = 0
TXN_OUTPUT_OFFSET = MAX_TXN_LEN

class UserAuthorizedAction:
    active_request = None

    def __init__(self):
        self.refused = False
        self.failed = None
        self.result = None
        self.ux_done = False

    def done(self, redraw=True):
        # drop them back into menu system, but at top.
        self.ux_done = True
        from actions import goto_top_menu
        m = goto_top_menu()
        if redraw:
            m.show()

    def pop_menu(self):
        # drop them back into menu system, but try not to affect
        # menu position.
        from actions import goto_top_menu
        from ux import the_ux, restore_menu

        self.ux_done = True
        if the_ux.top_of_stack() == self:
            empty = the_ux.pop()
            if empty:
                goto_top_menu()

        restore_menu()

    @classmethod
    def cleanup(cls):
        # user has collected the results/errors and no need for objs
        cls.active_request = None
        gc.collect()

    @classmethod
    def check_busy(cls, allowed_cls=None):
        # see if we're busy. don't interrupt that... unless it's of allowed_cls
        # - also handle cleanup of stale actions
        if not cls.active_request:
            return
        if allowed_cls and isinstance(cls.active_request, allowed_cls):
            return

        # check if UX actally was cleared, and we're not really doing that anymore; recover
        # - happens if USB caller never comes back for their final results
        from ux import the_ux
        top_ux = the_ux.top_of_stack()
        if not isinstance(top_ux, cls) and cls.active_request.ux_done:
            # do cleaup
            print('recovery cleanup')
            cls.cleanup()
            return

        raise CCBusyError()

    async def failure(self, msg, exc=None, title='Failure'):
        self.failed = msg
        self.done()

        # show line number and/or simple text about error
        if exc:
            print("%s:" % msg)
            sys.print_exception(exc)

            msg += '\n\n'
            em = str(exc)
            if em:
                msg += em
                msg += '\n\n'
            msg += problem_file_line(exc)
        
        from glob import hsm_active, dis

        # do nothing more for HSM case: msg will be available over USB
        if hsm_active:
            dis.progress_bar_show(1)     # finish the Validating... or whatever was up
            return

        # may be a user-abort waiting, but we want to see error msg; so clear it
        ux_clear_keys(True)

        return await ux_show_story(msg, title)

# Confirmation text for user when signing text messages.
#
MSG_SIG_TEMPLATE = '''\
Ok to sign this?
      --=--
{msg}
      --=--

Using the key associated with address:

{subpath} =>
{addr}

Press %s to continue, otherwise %s to cancel.''' % (OK, X)

# RFC2440 <https://www.ietf.org/rfc/rfc2440.txt> style signatures, popular
# since the genesis block, but not really part of any BIP as far as I know.
#
def rfc_signature_template_gen(msg, addr, sig):
    template = [
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n",
        "%s\n" % msg,
        "-----BEGIN BITCOIN SIGNATURE-----\n",
        "%s\n" % addr,
        "%s\n" % sig,
        "-----END BITCOIN SIGNATURE-----\n"
    ]
    for part in template:
        yield part

def parse_armored_signature_file(contents):
    sep = "-----"
    assert contents.count(sep) == 6, "Armor text MUST be surrounded by exactly five (5) dashes."
    temp = contents.split(sep)
    msg = temp[2].strip()
    addr_sig = temp[4].strip()
    addr, sig_str = addr_sig.split()
    return msg, addr, sig_str

def sign_message_digest(digest, subpath, prompt, addr_fmt=AF_CLASSIC, pk=None):
    # do the signature itself!
    from glob import dis

    ch = chains.current_chain()

    if prompt:
        dis.fullscreen(prompt, percent=.25)

    if pk is None:
        with stash.SensitiveValues() as sv:
        # if private key is provided, derivation subpath is ignored
        # and provided private key is used for signing
            node = sv.derive_path(subpath)
            dis.progress_bar_show(.50)
            pk = node.privkey()
            addr = ch.address(node, addr_fmt)
    else:
        node = ngu.hdnode.HDNode().from_chaincode_privkey(bytes(32), pk)
        dis.progress_bar_show(.50)
        addr = ch.address(node, addr_fmt)

    dis.progress_bar_show(.75)
    rv = ngu.secp256k1.sign(pk, digest, 0).to_bytes()
    # AF_CLASSIC header byte base 31 is returned by default from ngu - NOOP
    if addr_fmt != AF_CLASSIC:
        header_byte, rs = rv[0], rv[1:]
        # ngu only produces header base for compressed p2pkh, anyways get only rec_id
        rec_id = (header_byte - 27) & 0x03
        new_header_byte = rec_id + ch.sig_hdr_base(addr_fmt=addr_fmt)
        rv = bytes([new_header_byte]) + rs

    dis.progress_bar_show(1)

    return rv, addr

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

def sign_export_contents(content_list, deriv, addr_fmt, pk=None):
    msg2sign = make_signature_file_msg(content_list)
    bitcoin_digest = chains.current_chain().hash_message(msg2sign)
    sig_bytes, addr = sign_message_digest(bitcoin_digest, deriv, "Signing...", addr_fmt, pk=pk)
    sig = b2a_base64(sig_bytes).decode().strip()
    gen = rfc_signature_template_gen(addr=addr, msg=msg2sign.decode(), sig=sig)
    return gen

def verify_signed_file_digest(msg):
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
            # rfc template generator has length of 6
            dis.progress_bar_show(i / 6)
    return sig_nice

def validate_text_for_signing(text):
    # Check for some UX/UI traps in the message itself.
    # - messages must be short and ascii only. Our charset is limited
    # - too many spaces, leading/trailing can be an issue

    MSG_MAX_SPACES = 4      # impt. compared to -=- positioning

    result = to_ascii_printable(text)

    length = len(result)
    assert length >= 2, "msg too short (min. 2)"
    assert length <= MSG_SIGNING_MAX_LENGTH, "msg too long (max. %d)" % MSG_SIGNING_MAX_LENGTH
    assert "   " not in result, 'too many spaces together in msg(max. 3)'
    # other confusion w/ whitepace
    assert result[0] != ' ', 'leading space(s) in msg'
    assert result[-1] != ' ', 'trailing space(s) in msg'

    # looks ok
    return result

class ApproveMessageSign(UserAuthorizedAction):
    def __init__(self, text, subpath, addr_fmt, approved_cb=None):
        super().__init__()
        self.text = validate_text_for_signing(text)
        self.subpath = cleanup_deriv_path(subpath)
        self.addr_fmt = parse_addr_fmt_str(addr_fmt)
        self.approved_cb = approved_cb

        # temporary - no p2tr support
        if self.addr_fmt == AF_P2TR:
            raise ValueError("Unsupported address format: 'p2tr'")

        from glob import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(self.subpath)
            self.address = sv.chain.address(node, self.addr_fmt)

        dis.progress_bar_show(1)

    async def interact(self):
        # Prompt user w/ details and get approval
        from glob import dis, hsm_active

        if hsm_active:
            ch = await hsm_active.approve_msg_sign(self.text, self.address, self.subpath)
        else:
            story = MSG_SIG_TEMPLATE.format(msg=self.text, addr=self.address, subpath=self.subpath)
            ch = await ux_show_story(story)

        if ch != 'y':
            # they don't want to!
            self.refused = True
        else:

            # perform signing (progress bar shown)
            digest = chains.current_chain().hash_message(self.text.encode())
            self.result = sign_message_digest(digest, self.subpath, "Signing...", self.addr_fmt)[0]

            if self.approved_cb:
                # for micro sd case
                await self.approved_cb(self.result, self.address, self.text)

        if self.approved_cb:
            # don't kill menu depth for file case
            UserAuthorizedAction.cleanup()
            self.pop_menu()
        else:
            self.done()
    

def sign_msg(text, subpath, addr_fmt):
    subpath = cleanup_deriv_path(subpath)
    UserAuthorizedAction.check_busy()
    UserAuthorizedAction.active_request = ApproveMessageSign(text, subpath, addr_fmt)
    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)


async def sign_txt_file(filename):
    # sign a one-line text file found on a MicroSD card
    # - not yet clear how to do address types other than 'classic'
    from files import CardSlot, CardMissingError

    from ux import the_ux

    UserAuthorizedAction.cleanup()

    # copy message into memory
    with CardSlot() as card:
        with card.open(filename, 'rt') as fd:
            text = fd.readline().strip()
            subpath = fd.readline().strip()
            addr_fmt = fd.readline().strip()

    if not subpath:
        # default: top of wallet.
        subpath = 'm'

    if not addr_fmt:
        addr_fmt = AF_CLASSIC

    async def done(signature, address, text):
        # complete. write out result
        from glob import dis

        orig_path, basename = filename.rsplit('/', 1)
        orig_path += '/'
        base = basename.rsplit('.', 1)[0]
        out_fn = None

        sig = b2a_base64(signature).decode('ascii').strip()

        while 1:
            # try to put back into same spot
            # add -signed to end.
            target_fname = base+'-signed.txt'

            for path in [orig_path, None]:
                try:
                    with CardSlot(readonly=True) as card:
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
                    with CardSlot() as card:
                        with card.open(out_full, 'wt') as fd:
                            # save in full RFC style
                            # gen length is 6
                            gen = rfc_signature_template_gen(addr=address, msg=text, sig=sig)
                            for i, part in enumerate(gen):
                                fd.write(part)
                                dis.progress_bar_show(i / 6)

                    # success and done!
                    break

                except OSError as exc:
                    prob = 'Failed to write!\n\n%s\n\n' % exc
                    sys.print_exception(exc)
                    # fall through to try again

            # prompt them to input another card?
            ch = await ux_show_story(prob+"Please insert an SDCard to receive signed message, "
                                        "and press %s." % OK, title="Need Card")
            if ch == 'x':
                await ux_aborted()
                return

        # done.
        msg = "Created new file:\n\n%s" % out_fn
        await ux_show_story(msg, title='File Signed')

    UserAuthorizedAction.check_busy()
    try:
        UserAuthorizedAction.active_request = ApproveMessageSign(text, subpath, addr_fmt, approved_cb=done)
        # do not kill the menu stack!
        the_ux.push(UserAuthorizedAction.active_request)
    except AssertionError as exc:
        await ux_show_story("Problem: %s\n\nMessage to be signed must be a single line of ASCII text." % exc)
        return

def verify_signature(msg, addr, sig_str):
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
    # digest_check=False for NFC cases, where we do not have filesystem
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
    story = "Good signature by address:\n %s" % addr

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
    from files import CardSlot, CardMissingError, needs_microsd
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


async def try_push_tx(data, txid, txn_sha=None):
    from glob import settings, PSRAM, NFC
    # if NFC PushTx is enabled, do that w/o questions.
    url = settings.get('ptxurl', False)
    if NFC and url:
        try:
            if isinstance(data, int):
                data = PSRAM.read_at(TXN_OUTPUT_OFFSET, data)
            if txn_sha is None:
                txn_sha = ngu.hash.sha256s(data)[-8:]
            await NFC.share_push_tx(url, txid, data, txn_sha)
            return True
        except: pass  # continue normally if it fails, perhaps too big?
    return False


class ApproveTransaction(UserAuthorizedAction):
    def __init__(self, psbt_len, flags=0x0, approved_cb=None, psbt_sha=None, is_sd=None):
        super().__init__()
        self.psbt_len = psbt_len
        self.do_finalize = bool(flags & STXN_FINALIZE)
        self.do_visualize = bool(flags & STXN_VISUALIZE)
        self.stxn_flags = flags
        self.psbt = None
        self.psbt_sha = psbt_sha
        self.approved_cb = approved_cb
        self.result = None      # will be (len, sha256) of the resulting PSBT
        self.is_sd = is_sd
        self.chain = chains.current_chain()

    def render_output(self, o):
        # Pretty-print a transactions output. 
        # - expects CTxOut object
        # - gives user-visible string
        # 
        val = ' '.join(self.chain.render_value(o.nValue))
        try:
            dest = self.chain.render_address(o.scriptPubKey)

            return '%s\n - to address -\n%s\n' % (val, dest)
        except ValueError:
            pass

        # check for OP_RETURN
        data = self.chain.op_return(o.scriptPubKey)
        if data:
            data_hex, data_ascii = data
            to_ret = '%s\n - OP_RETURN -\n%s' % (val, data_hex)
            if data_ascii:
                return to_ret + " (ascii: %s)\n" % data_ascii
            return to_ret + "\n"

        # Handle future things better: allow them to happen at least.
        self.psbt.warnings.append(
            ('Output?', 'Sending to a script that is not well understood.'))
        dest = B2A(o.scriptPubKey)

        return '%s\n - to script -\n%s\n' % (val, dest)

    async def interact(self):
        # Prompt user w/ details and get approval
        from glob import dis, hsm_active

        # step 1: parse PSBT from PSRAM into in-memory objects.

        try:
            with SFFile(TXN_INPUT_OFFSET, length=self.psbt_len, message='Reading...') as fd:
                # NOTE: psbtObject captures the file descriptor and uses it later
                self.psbt = psbtObject.read_psbt(fd)
        except BaseException as exc:
            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex"
                exc = None
            else:
                msg = "PSBT parse failed"

            return await self.failure(msg, exc)

        dis.fullscreen("Validating...")

        # Do some analysis/ validation
        try:
            await self.psbt.validate()      # might do UX: accept multisig import
            dis.progress_bar_show(0.10)
            self.psbt.consider_inputs()

            dis.progress_bar_show(0.33)
            self.psbt.consider_keys()

            dis.progress_bar_show(0.66)
            self.psbt.consider_outputs()
            self.psbt.consider_dangerous_sighash()

            dis.progress_bar_show(0.85)
        except FraudulentChangeOutput as exc:
            print('FraudulentChangeOutput: ' + exc.args[0])
            return await self.failure(exc.args[0], title='Change Fraud')
        except FatalPSBTIssue as exc:
            print('FatalPSBTIssue: ' + exc.args[0])
            return await self.failure(exc.args[0])
        except BaseException as exc:
            del self.psbt
            gc.collect()

            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex"
                exc = None
            else:
                msg = "Invalid PSBT"

            return await self.failure(msg, exc)

        # step 2: figure out what we are approving, so we can get sign-off
        # - outputs, amounts
        # - fee 
        #
        # notes: 
        # - try to handle lots of outputs
        # - cannot calc fee as sat/byte, only as percent
        # - somethings are 'warnings':
        #       - fee too big
        #       - inputs we can't sign (no key)
        #
        try:
            msg = uio.StringIO()

            # mention warning at top
            wl= len(self.psbt.warnings)
            if wl == 1:
                msg.write('(1 warning below)\n\n')
            elif wl >= 2:
                msg.write('(%d warnings below)\n\n' % wl)

            if self.psbt.consolidation_tx:
                # consolidating txn that doesn't change balance of account.
                msg.write("Consolidating %s %s\nwithin wallet.\n\n" %
                          self.chain.render_value(self.psbt.total_value_out))
            else:
                msg.write("Sending %s %s\n" % self.chain.render_value(
                    self.psbt.total_value_out - self.psbt.total_change_value))

            fee = self.psbt.calculate_fee()
            if fee is not None:
                msg.write("Network fee %s %s\n\n" % self.chain.render_value(fee))

            msg.write(" %d %s\n %d %s\n\n" % (
                self.psbt.num_inputs,
                "input" if self.psbt.num_inputs == 1 else "inputs",
                self.psbt.num_outputs,
                "output" if self.psbt.num_outputs == 1 else "outputs",
            ))

            # outputs + change story created here
            needs_txn_explorer = self.output_summary_text(msg)
            gc.collect()

            if self.psbt.ux_notes:
                # currently we only have locktimes in ux_notes
                msg.write('TX LOCKTIMES\n\n')

                for label, m in self.psbt.ux_notes:
                    msg.write('- %s: %s\n' % (label, m))
                msg.write("\n")

            if self.psbt.warnings:
                msg.write('---WARNING---\n\n')

                for label, m in self.psbt.warnings:
                    msg.write('- %s: %s\n\n' % (label, m))

            if self.do_visualize:
                # stop here and just return the text of approval message itself
                self.result = await self.save_visualization(msg, (self.stxn_flags & STXN_SIGNED))
                del self.psbt
                self.done()
                return

            ux_clear_keys(True)
            dis.progress_bar_show(1)  # finish the Validating...
            if not hsm_active:
                msg.write("\nPress %s to approve and sign transaction." % OK)
                if needs_txn_explorer:
                    msg.write(" Press (2) to explore txn.")
                if self.is_sd and CardSlot.both_inserted():
                    msg.write(" (B) to write to lower SD slot.")
                msg.write(" X to abort.")
                while True:
                    ch = await ux_show_story(msg, title="OK TO SEND?", escape="2b")
                    if ch == "2" and needs_txn_explorer:
                        await self.txn_explorer()
                        continue
                    else:
                        msg.close()
                        del msg
                        break
            else:
                ch = await hsm_active.approve_transaction(self.psbt, self.psbt_sha, msg.getvalue())
                dis.progress_bar_show(1)     # finish the Validating...

        except MemoryError:
            # recovery? maybe.
            try:
                del self.psbt
                del msg
            except: pass        # might be NameError since we don't know how far we got
            gc.collect()

            msg = "Transaction is too complex"
            return await self.failure(msg)

        if ch not in 'yb':
            # they don't want to!
            self.refused = True

            await ux_dramatic_pause("Refused.", 1)

            del self.psbt

            self.done()
            return

        # do the actual signing.
        try:
            dis.fullscreen('Wait...')
            gc.collect()           # visible delay caused by this but also sign_it() below
            self.psbt.sign_it()
        except FraudulentChangeOutput as exc:
            return await self.failure(exc.args[0], title='Change Fraud')
        except MemoryError:
            msg = "Transaction is too complex"
            return await self.failure(msg)
        except BaseException as exc:
            return await self.failure("Signing failed late", exc)

        if self.approved_cb:
            # for NFC, micro SD cases
            kws = dict(psbt=self.psbt)
            if self.is_sd and (ch == "b"):
                kws["slot_b"] = True
            await self.approved_cb(**kws)
            self.done()
            return

        txid = None
        try:
            # re-serialize the PSBT back out
            with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as fd:
                if self.do_finalize:
                    txid = self.psbt.finalize(fd)
                else:
                    self.psbt.serialize(fd)

                self.result = (fd.tell(), fd.checksum.digest())

            self.done(redraw=(not txid))

        except BaseException as exc:
            return await self.failure("PSBT output failed", exc)

        from glob import NFC

        if self.do_finalize and txid and not hsm_active:

            if await try_push_tx(self.result[0], txid, self.result[1]):
                return  # success, exit

            kq, kn = "(1)", "(3)"
            if version.has_qwerty:
                kq, kn = KEY_QR, KEY_NFC
            while 1:
                # Show txid when we can; advisory
                # - maybe even as QR, hex-encoded in alnum mode
                tmsg = txid + '\n\nPress %s for QR Code of TXID. ' % kq

                if NFC:
                    tmsg += 'Press %s to share signed txn via NFC.' % kn

                ch = await ux_show_story(tmsg, "Final TXID", escape='13'+KEY_NFC+KEY_QR)

                if ch in '1'+KEY_QR:
                    await show_qr_code(txid, True)
                    continue

                if ch in KEY_NFC+"3" and NFC:
                    await NFC.share_signed_txn(txid, TXN_OUTPUT_OFFSET,
                                               self.result[0], self.result[1])
                    continue
                break

    async def txn_explorer(self):
        # Page through unlimited-sized transaction details
        # - shows all outputs (including change): their address and amounts.
        from glob import dis

        def make_msg(offset, count):
            dis.fullscreen('Wait...')
            rv = ""
            end = min(offset + count, self.psbt.num_outputs)

            for idx, out in self.psbt.output_iter(offset, end):
                outp = self.psbt.outputs[idx]
                item = "Output %d%s:\n\n" % (idx, " (change)" if outp.is_change else "")
                item += self.render_output(out)
                item += "\n"
                rv += item
                dis.progress_sofar(idx-offset+1, count)

            rv += 'Press RIGHT to see next group'
            if offset:
                rv += ', LEFT to go back'
            rv += '. X to quit.'

            return rv

        start = 0
        n = 10
        msg = make_msg(start, n)
        while True:
            ch = await ux_show_story(msg, escape='79'+KEY_RIGHT+KEY_LEFT)
            if ch == 'x':
                del msg
                return
            elif (ch in KEY_LEFT+"7"):
                if (start - n) < 0:
                    continue
                else:
                    # go backwards in explorer
                    start -= n
            elif (ch in KEY_RIGHT+"9"):
                if (start + n) >= self.psbt.num_outputs:
                    continue
                else:
                    # go forwards
                    start += n
            else:
                # nothing changed - do not recalc msg
                continue

            msg = make_msg(start, n)

    async def save_visualization(self, msg, sign_text=False):
        # write text into spi flash, maybe signing it as we go
        # - return length and checksum
        txt_len = msg.seek(0, 2)
        msg.seek(0)

        chk = self.chain.hash_message(msg_len=txt_len) if sign_text else None

        with SFFile(TXN_OUTPUT_OFFSET, max_size=txt_len+300, message="Visualizing...") as fd:
            while 1:
                blk = msg.read(256).encode('ascii')
                if not blk: break
                if chk:
                    chk.update(blk)
                fd.write(blk)

            if chk:
                # append the signature
                digest = ngu.hash.sha256s(chk.digest())
                sig = sign_message_digest(digest, 'm', None, AF_CLASSIC)[0]
                fd.write(b2a_base64(sig).decode('ascii').strip())
                fd.write('\n')

            return (fd.tell(), fd.checksum.digest())

    def output_summary_text(self, msg):
        # Produce text report of where their cash is going. This is what
        # they use to decide if correct transaction is being signed.

        # Produce text report of where all outputs, both normal and "change" are going.
        # - we do expect all users to verify these outputs completely; do not hide details
        # - show larger outputs first, total-up the not-shown values if any
        # - change shown as such, only because we've done all the check/validations already
        # - when too much to show now, offer to page user through all the ouputs (txn explorer)
        MAX_VISIBLE_OUTPUTS = const(10)
        MAX_VISIBLE_CHANGE = const(20)

        needs_txn_explorer = False
        largest_outs = []
        largest_change = []
        total_change = 0

        for idx, tx_out in self.psbt.output_iter():
            outp = self.psbt.outputs[idx]
            if outp.is_change:
                total_change += tx_out.nValue
                if len(largest_change) < MAX_VISIBLE_CHANGE:
                    largest_change.append((tx_out.nValue, self.chain.render_address(tx_out.scriptPubKey)))
                    if len(largest_change) == MAX_VISIBLE_CHANGE:
                        largest_change = sorted(largest_change, key=lambda x: x[0], reverse=True)
                    continue

            else:
                if len(largest_outs) < MAX_VISIBLE_OUTPUTS:
                    largest_outs.append((tx_out.nValue, self.render_output(tx_out)))
                    if len(largest_outs) == MAX_VISIBLE_OUTPUTS:
                        # descending sort from the biggest value to lowest (sort on out.nValue)
                        largest_outs = sorted(largest_outs, key=lambda x: x[0], reverse=True)
                    continue

            # insertion sort
            here = tx_out.nValue
            largest = largest_change if outp.is_change else largest_outs
            for li, (nv, txt) in enumerate(largest):
                if here > nv:
                    keep = li
                    break
            else:
                continue        # too small

            largest.pop(-1)
            if outp.is_change:
                ret = (here, self.chain.render_address(tx_out.scriptPubKey))
            else:
                ret = (here, self.render_output(tx_out))
            largest.insert(keep, ret)

        # foreign outputs (soon to be other people's coins)
        visible_out_sum = 0
        for val, txt in largest_outs:
            visible_out_sum += val
            msg.write(txt)  # txt is result of render_output
            msg.write('\n')

        left = self.psbt.num_outputs - len(largest_outs) - self.psbt.num_change_outputs
        if left > 0:
            needs_txn_explorer = True
            msg.write('.. plus %d smaller output(s), not shown here, which total: ' % left)

            # calculate left over value
            msg.write('%s %s\n' % self.chain.render_value(
                self.psbt.total_value_out - total_change - visible_out_sum))

            msg.write("\n")

        # change outputs - verified to be coming back to our wallet
        if total_change > 0:
            msg.write("Change back:\n%s %s\n" % self.chain.render_value(total_change))
            visible_change_sum = 0
            if len(largest_change) == 1:
                visible_change_sum += largest_change[0][0]
                msg.write(' - to address -\n%s\n' % largest_change[0][1])
            else:
                msg.write(' - to addresses -\n')
                for val, addr in largest_change:
                    visible_change_sum += val
                    msg.write(addr)
                    msg.write('\n')

            left_c = self.psbt.num_change_outputs - len(largest_change)
            if left_c:
                needs_txn_explorer = True
                msg.write('.. plus %d smaller change output(s), not shown here, which total: ' % left_c)
                msg.write('%s %s\n' % self.chain.render_value(total_change - visible_change_sum))

            msg.write("\n")

        # if we didn't already show all outputs, then give user a chance to 
        # view them individually
        return needs_txn_explorer


def sign_transaction(psbt_len, flags=0x0, psbt_sha=None):
    # transaction (binary) loaded into PSRAM already, checksum checked
    UserAuthorizedAction.check_busy(ApproveTransaction)
    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, flags, psbt_sha=psbt_sha)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

def psbt_encoding_taster(taste, psbt_len):
    # look at first 10 bytes, and detect file encoding (binary, hex, base64)
    # - return len is upper bound on size because of unknown whitespace
    from utils import HexStreamer, Base64Streamer, HexWriter, Base64Writer
    taste = bytes(taste)
    if taste[0:5] == b'psbt\xff':
        decoder = None
        output_encoder = lambda x: x
    elif taste[0:10].lower() == b'70736274ff':
        decoder = HexStreamer()
        output_encoder = HexWriter
        psbt_len //= 2
    elif taste[0:6] == b'cHNidP':
        decoder = Base64Streamer()
        output_encoder = Base64Writer
        psbt_len = (psbt_len * 3 // 4) + 10
    else:
        raise ValueError("not psbt")

    return decoder, output_encoder, psbt_len
    
async def sign_psbt_file(filename, force_vdisk=False, slot_b=None):
    # sign a PSBT file found on a MicroSD card
    # - or from VirtualDisk (mk4)
    from files import CardSlot, CardMissingError
    from glob import dis
    from ux import the_ux

    tmp_buf = bytearray(1024)

    # copy file into PSRAM
    # - can't work in-place on the card because we want to support writing out to different card
    # - accepts hex or base64 encoding, but binary prefered
    with CardSlot(force_vdisk, readonly=True, slot_b=slot_b) as card:
        with card.open(filename, 'rb') as fd:
            dis.fullscreen('Reading...')

            # see how long it is
            psbt_len = fd.seek(0, 2)
            fd.seek(0)

            # determine encoding used, altho we prefer binary
            taste = fd.read(10)
            fd.seek(0)

            decoder, output_encoder, psbt_len = psbt_encoding_taster(taste, psbt_len)

            total = 0
            with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
                while 1:
                    n = fd.readinto(tmp_buf)
                    if not n: break

                    if n == len(tmp_buf):
                        abuf = tmp_buf
                    else:
                        abuf = memoryview(tmp_buf)[0:n]

                    if not decoder:
                        out.write(abuf)
                        total += n
                    else:
                        for here in decoder.more(abuf):
                            out.write(here)
                            total += len(here)

                    dis.progress_bar_show(total / psbt_len)

            # might have been whitespace inflating initial estimate of PSBT size
            assert total <= psbt_len
            psbt_len = total

    async def done(psbt, slot_b=None):
        dis.fullscreen("Wait...")
        orig_path, basename = filename.rsplit('/', 1)
        orig_path += '/'
        base = basename.rsplit('.', 1)[0]
        out2_fn = None
        out_fn = None
        txid = None

        from glob import settings
        import os
        del_after = settings.get('del', 0)

        while 1:
            # try to put back into same spot, but also do top-of-card
            is_comp = psbt.is_complete()
            if not is_comp:
                # keep the filename under control during multiple passes
                target_fname = base.replace('-part', '')+'-part.psbt'
            else:
                # add -signed to end. We won't offer to sign again.
                target_fname = base+'-signed.psbt'

            for path in [orig_path, None]:
                try:
                    with CardSlot(force_vdisk, readonly=True, slot_b=slot_b) as card:
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
                    with CardSlot(force_vdisk, slot_b=slot_b) as card:
                        if is_comp and del_after:
                            # don't write signed PSBT if we'd just delete it anyway
                            out_fn = None
                        else:
                            with output_encoder(card.open(out_full, 'wb')) as fd:
                                # save as updated PSBT
                                psbt.serialize(fd)

                        if is_comp:
                            # write out as hex too, if it's final
                            out2_full, out2_fn = card.pick_filename(
                                base+'-final.txn' if not del_after else 'tmp.txn', out_path)

                            with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as fd0:
                                txid = psbt.finalize(fd0)
                                fd0.flush_out()  # need to flush here as we are probably not gona call .read( again
                                tx_len, tx_sha = fd0.tell(), fd0.checksum.digest()
                                if txid and await try_push_tx(tx_len, txid, tx_sha):
                                    return  # success, exit

                                if out2_full:
                                    fd0.seek(0)

                                    with HexWriter(card.open(out2_full, 'w+t')) as fd:
                                        # save transaction, in hex
                                        tmp_buf = bytearray(4096)
                                        while True:
                                            rv = fd0.readinto(tmp_buf)
                                            if not rv: break
                                            fd.write(memoryview(tmp_buf)[:rv])

                                    if del_after:
                                        # rename it now that we know the txid
                                        after_full, out2_fn = card.pick_filename(
                                                                txid+'.txn', out_path, overwrite=True)
                                        os.rename(out2_full, after_full)

                        if del_after:
                            # this can do nothing if they swapped SDCard between steps, which is ok,
                            # but if the original file is still there, this blows it away.
                            # - if not yet final, the foo-part.psbt file stays
                            try:
                                card.securely_blank_file(filename)
                            except: pass

                    # success and done!
                    break

                except OSError as exc:
                    prob = 'Failed to write!\n\n%s\n\n' % exc
                    sys.print_exception(exc)
                    # fall thru to try again

            if force_vdisk:
                await ux_show_story(prob, title='Error')
                return

            # prompt them to input another card?
            ch = await ux_show_story(prob+"Please insert an SDCard to receive signed transaction, "
                                        "and press %s." % OK, title="Need Card")
            if ch == 'x':
                await ux_aborted()
                return

        # done.
        if out_fn:
            msg = "Updated PSBT is:\n\n%s" % out_fn
            if out2_fn:
                msg += '\n\n'
        else:
            # del_after is probably set
            msg = ''

        if out2_fn:
            msg += 'Finalized transaction (ready for broadcast):\n\n%s' % out2_fn
            if txid and not del_after:
                msg += '\n\nFinal TXID:\n'+txid

        await ux_show_story(msg, title='PSBT Signed')

        UserAuthorizedAction.cleanup()

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, approved_cb=done,
                                                             is_sd=not force_vdisk)
    the_ux.push(UserAuthorizedAction.active_request)

class RemoteBackup(UserAuthorizedAction):
    def __init__(self):
        super().__init__()
        # self.result ... will be (len, sha256) of the resulting file at zero

    async def interact(self):
        try:
            # Lead the user thru a complex UX.
            from backups import make_complete_backup

            r = await make_complete_backup(write_sflash=True)

            if r:
                # expect (length, sha)
                self.result = r
            else:
                self.refused = True

        except BaseException as exc:
            self.failed = "Error during backup process."
            print("Backup failure: ")
            sys.print_exception(exc)
        finally:
            self.done()


def start_remote_backup():
    # tell the local user the secret words, and then save to SPI flash
    # USB caller has to come back and download encrypted contents.

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = RemoteBackup()

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)


class NewPassphrase(UserAuthorizedAction):
    def __init__(self, pw):
        super().__init__()
        self._pw = pw
        # self.result ... will be (len, sha256) of the resulting file at zero

    async def interact(self):
        # prompt them
        from glob import settings
        from pincodes import pa

        title = "Passphrase"
        escape = "yx2" + KEY_CANCEL + KEY_ENTER
        while 1:
            msg = ('BIP-39 passphrase (%d chars long) has been provided over '
                   'USB connection. Should we switch to that wallet now?\n\n'
                   'Press %s to add passphrase ' % (len(self._pw), OK))
            if pa.tmp_value:
                msg += "to current active temporary seed. "
            else:
                msg += "to master seed. "

            msg += ('Press (2) to view the provided passphrase. %s to cancel.' % X)

            ch = await ux_show_story(msg=msg, title=title, escape=escape,
                                     strict_escape=True)
            if ch == '2':
                await ux_show_story('Provided:\n\n%s\n\n' % self._pw, title=title)
                continue
            else: break

        try:
            if ch not in ('y'+ KEY_ENTER):
                # they don't want to!
                self.refused = True
                await ux_dramatic_pause("Refused.", 1)
            else:
                from seed import set_bip39_passphrase

                # full screen message shown: "Working..."
                await set_bip39_passphrase(self._pw, summarize_ux=False)
                self.result = settings.get('xpub')

        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            self.done()

        if self.result:
            new_xfp = settings.get('xfp')
            await ux_show_story('Above is the master key fingerprint '
                                'of the current wallet.',
                                title="[%s]" % xfp2str(new_xfp))


def start_bip39_passphrase(pw):
    # new passphrase has come in via USB. offer to switch to it.

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = NewPassphrase(pw)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)


class ShowAddressBase(UserAuthorizedAction):
    title = 'Address:'

    def __init__(self, *args, **kwargs):
        self.restore_menu = kwargs.get("restore_menu", False)
        super().__init__()

        from glob import dis
        dis.fullscreen('Wait...')

        # this must set self.address and do other slow setup
        self.setup(*args)

    async def interact(self):
        # Just show the address... no real confirmation needed.
        from glob import hsm_active, dis, NFC

        if not hsm_active:
            msg = self.get_msg()
            msg += '\n\nCompare this payment address to the one shown on your other, less-trusted, software.'

            if not version.has_qwerty:
                if NFC:
                    msg += ' Press %s to share via NFC.' % (KEY_NFC if version.has_qwerty else "(3)")
                msg += ' Press (4) to view QR Code.'

            while 1:
                ch = await ux_show_story(msg, title=self.title, escape='34',
                                        hint_icons=KEY_QR+(KEY_NFC if NFC else ''))

                if ch in '4'+KEY_QR:
                    await show_qr_code(self.address, (self.addr_fmt & AFC_BECH32))
                    continue

                if NFC and (ch in '3'+KEY_NFC):
                    await NFC.share_text(self.address)
                    continue

                break

        else:
            # finish the Wait...
            dis.progress_bar_show(1)     

        if self.restore_menu:
            self.pop_menu()
        else:
            self.done()

        UserAuthorizedAction.cleanup()      # because no results to store

    
class ShowPKHAddress(ShowAddressBase):

    def setup(self, addr_fmt, subpath):
        self.subpath = subpath
        self.addr_fmt = addr_fmt

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            self.address = sv.chain.address(node, addr_fmt)

    def get_msg(self):
        return '''{addr}\n\n= {sp}''' .format(addr=self.address, sp=self.subpath)


class ShowP2SHAddress(ShowAddressBase):

    def setup(self, ms, addr_fmt, xfp_paths, witdeem_script):

        self.witdeem_script = witdeem_script
        self.addr_fmt = addr_fmt
        self.ms = ms

        # calculate all the pubkeys involved.
        self.subpath_help = ms.validate_script(witdeem_script, xfp_paths=xfp_paths)

        self.address = ms.chain.p2sh_address(addr_fmt, witdeem_script)

    def get_msg(self):
        return '''\
{addr}

Wallet:

  {name}
  {M} of {N}

Paths:

{sp}'''.format(addr=self.address, name=self.ms.name,
                        M=self.ms.M, N=self.ms.N, sp='\n\n'.join(self.subpath_help))

def start_show_p2sh_address(M, N, addr_format, xfp_paths, witdeem_script):
    # Show P2SH address to user, also returns it.
    # - first need to find appropriate multisig wallet associated
    # - they must provide full redeem script, and we will re-verify it and check pubkeys inside it

    from multisig import MultisigWallet

    try:
        assert addr_format in SUPPORTED_ADDR_FORMATS
        assert addr_format & AFC_SCRIPT
    except:
        raise AssertionError('Unknown/unsupported addr format')

    # Search for matching multisig wallet that we must already know about
    xs = list(xfp_paths)
    xs.sort()

    ms = MultisigWallet.find_match(M, N, xs)
    assert ms, 'Multisig wallet with those fingerprints not found'
    assert ms.M == M
    assert ms.N == N

    UserAuthorizedAction.check_busy(ShowAddressBase)
    UserAuthorizedAction.active_request = ShowP2SHAddress(ms, addr_format, xfp_paths, witdeem_script)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

    # provide the value back to attached desktop
    return UserAuthorizedAction.active_request.address

def show_address(addr_format, subpath, restore_menu=False):
    try:
        assert addr_format in SUPPORTED_ADDR_FORMATS
        assert not (addr_format & AFC_SCRIPT)
    except:
        raise AssertionError('Unknown/unsupported addr format')

    # require a path to a key
    subpath = cleanup_deriv_path(subpath)

    from glob import hsm_active
    if hsm_active and not hsm_active.approve_address_share(subpath):
        raise HSMDenied

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.check_busy(ShowAddressBase)
    UserAuthorizedAction.active_request = ShowPKHAddress(addr_format, subpath, restore_menu=restore_menu)
    return UserAuthorizedAction.active_request

def usb_show_address(addr_format, subpath):
    active_request = show_address(addr_format, subpath)
    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)
    # provide the value back to attached desktop
    return active_request.address


class NewEnrollRequest(UserAuthorizedAction):
    def __init__(self, ms):
        super().__init__()
        self.wallet = ms
        # self.result ... will be re-serialized xpub

    async def interact(self):
        from multisig import MultisigOutOfSpace

        ms = self.wallet
        try:
            ch = await ms.confirm_import()

            if ch != 'y':
                # they don't want to!
                self.refused = True
                await ux_dramatic_pause("Refused.", 2)

        except MultisigOutOfSpace:
            return await self.failure('No space left')
        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            UserAuthorizedAction.cleanup()      # because no results to store
            self.pop_menu()

def maybe_enroll_xpub(sf_len=None, config=None, name=None, ux_reset=False):
    # Offer to import (enroll) a new multisig wallet. Allow reject by user.
    from glob import dis
    from multisig import MultisigWallet

    UserAuthorizedAction.cleanup()
    dis.fullscreen('Wait...')  # needed
    dis.busy_bar(True)

    try:
        if sf_len:
            with SFFile(TXN_INPUT_OFFSET, length=sf_len) as fd:
                config = fd.read(sf_len).decode()

        try:
            j_conf = ujson.loads(config)
            assert "desc" in j_conf, "'desc' key required"
            config = j_conf["desc"]
            assert config, "'desc' empty"

            if "name" in j_conf:
                # name from json has preference over filenames and desc checksum
                name = j_conf["name"]
                assert 2 <= len(name) <= 40, "'name' length"
        except ValueError: pass

        # this call will raise on parsing errors, so let them rise up
        # and be shown on screen/over usb
        ms = MultisigWallet.from_file(config, name=name)

        UserAuthorizedAction.active_request = NewEnrollRequest(ms)

        if ux_reset:
            # for USB case, and import from PSBT
            # kill any menu stack, and put our thing at the top
            abort_and_goto(UserAuthorizedAction.active_request)
        else:
            # menu item case: add to stack
            from ux import the_ux
            the_ux.push(UserAuthorizedAction.active_request)
    finally:
        # always finish busy bar
        dis.busy_bar(False)

class FirmwareUpgradeRequest(UserAuthorizedAction):
    def __init__(self, hdr, length, hdr_check=False, psram_offset=None):
        super().__init__()
        self.hdr = hdr
        self.length = length
        self.hdr_check = hdr_check
        self.psram_offset = psram_offset

    async def interact(self):
        from version import decode_firmware_header
        from utils import check_firmware_hdr

        # check header values
        if self.hdr_check:
            # when coming in via USB, this part already done
            # so the error can be sent back over USB port
            failed = check_firmware_hdr(self.hdr, self.length)
            if failed:
                await ux_show_story(failed, 'Sorry!')

                UserAuthorizedAction.cleanup()
                self.pop_menu()
                return

        # Get informed consent to upgrade.
        date, version, _ = decode_firmware_header(self.hdr)

        msg = '''\
Install this new firmware?

  {version}
  {built}

Binary checksum and signature will be further verified before any changes are made.
'''.format(version=version, built=date)

        try:
            ch = await ux_show_story(msg)

            if ch == 'y':
                # Accepted:
                # - write final file header, so bootloader will see it
                # - reboot to start process
                from glob import dis
                dis.fullscreen('Upgrading...', percent=1)
                dis.bootrom_takeover()

                # Mk4 copies from PSRAM to flash inside bootrom, we have
                # nothing to do here except start that process.
                from pincodes import pa
                pa.firmware_upgrade(self.psram_offset, self.length)
                # not reached, unless issue?
                raise RuntimeError("bootrom fail")
            else:
                # they don't want to!
                self.refused = True
                await ux_dramatic_pause("Refused.", 2)

        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            UserAuthorizedAction.cleanup()      # because no results to store
            self.pop_menu()

def authorize_upgrade(hdr, length, **kws):
    # final USB write has come in, get buy-in

    # Do some verification before we even show to the local user
    UserAuthorizedAction.check_busy()
    UserAuthorizedAction.active_request = FirmwareUpgradeRequest(hdr, length, **kws)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)


# EOF
