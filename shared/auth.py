# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, ux, chains, sys, gc, uio, version, ngu
from ubinascii import b2a_base64
from public_constants import MSG_SIGNING_MAX_LENGTH, SUPPORTED_ADDR_FORMATS
from public_constants import AFC_SCRIPT, AF_CLASSIC, AFC_BECH32
from public_constants import STXN_FLAGS_MASK, STXN_FINALIZE, STXN_VISUALIZE, STXN_SIGNED
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys
from ux import show_qr_code
from usb import CCBusyError
from utils import HexWriter, xfp2str, problem_file_line, cleanup_deriv_path
from utils import B2A, parse_addr_fmt_str
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from exceptions import HSMDenied
from version import has_psram, has_fatram, MAX_TXN_LEN

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
        self.ux_done = True

        from actions import goto_top_menu
        from ux import the_ux, restore_menu
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
            dis.progress_bar(1)     # finish the Validating... or whatever was up
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

Press OK to continue, otherwise X to cancel.'''

# RFC2440 <https://www.ietf.org/rfc/rfc2440.txt> style signatures, popular
# since the genesis block, but not really part of any BIP as far as I know.
#
RFC_SIGNATURE_TEMPLATE = '''\
-----BEGIN {blockchain} SIGNED MESSAGE-----
{msg}
-----BEGIN SIGNATURE-----
{addr}
{sig}
-----END {blockchain} SIGNED MESSAGE-----
'''

def sign_message_digest(digest, subpath, prompt):
    # do the signature itself!
    from glob import dis

    if prompt:
        dis.fullscreen(prompt, percent=.25)

    with stash.SensitiveValues() as sv:
        dis.progress_bar_show(.50)

        node = sv.derive_path(subpath)
        pk = node.privkey()
        sv.register(pk)

        dis.progress_bar_show(.75)
        rv = ngu.secp256k1.sign(pk, digest, 0).to_bytes()

    dis.progress_bar_show(1)

    return rv

def validate_text_for_signing(text):
    # Check for some UX/UI traps in the message itself.
    # - messages must be short and ascii only. Our charset is limited
    # - too many spaces, leading/trailing can be an issue

    MSG_CHARSET = range(32, 127)
    MSG_MAX_SPACES = 4      # impt. compared to -=- positioning

    try:
        result = str(text, 'ascii')
    except UnicodeError:
        raise AssertionError('must be ascii')

    length = len(result)
    assert length >= 2, "msg too short (min. 2)"
    assert length <= MSG_SIGNING_MAX_LENGTH, "msg too long (max. %d)" % MSG_SIGNING_MAX_LENGTH
    run = 0
    for ch in result:
        assert ord(ch) in MSG_CHARSET, "bad char: 0x%02x in msg" % ord(ch)

        if ch == ' ':
            run += 1
            assert run < MSG_MAX_SPACES, 'too many spaces together in msg(max. 4)'
        else:
            run = 0

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
            self.result = sign_message_digest(digest, self.subpath, "Signing...")

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


def sign_txt_file(filename):
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

    def done(signature, address, text):
        # complete. write out result
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
                    with CardSlot() as card:
                        with card.open(out_full, 'wt') as fd:
                            # save in full RFC style
                            fd.write(RFC_SIGNATURE_TEMPLATE.format(addr=address, msg=text,
                                                blockchain='BITCOIN', sig=sig))

                    # success and done!
                    break

                except OSError as exc:
                    prob = 'Failed to write!\n\n%s\n\n' % exc
                    sys.print_exception(exc)
                    # fall through to try again

            # prompt them to input another card?
            ch = await ux_show_story(prob+"Please insert an SDCard to receive signed message, "
                                        "and press OK.", title="Need Card")
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


class ApproveTransaction(UserAuthorizedAction):
    def __init__(self, psbt_len, flags=0x0, approved_cb=None, psbt_sha=None):
        super().__init__()
        self.psbt_len = psbt_len
        self.do_finalize = bool(flags & STXN_FINALIZE)
        self.do_visualize = bool(flags & STXN_VISUALIZE)
        self.stxn_flags = flags
        self.psbt = None
        self.psbt_sha = psbt_sha
        self.approved_cb = approved_cb
        self.result = None      # will be (len, sha256) of the resulting PSBT
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

        # step 1: parse PSBT from sflash into in-memory objects.

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
            self.psbt.consider_inputs()

            dis.fullscreen("Validating...", percent=0.33)
            self.psbt.consider_keys()

            dis.progress_bar(0.66)
            self.psbt.consider_outputs()

            dis.progress_bar(0.85)
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

            # self.output_summary_text(msg)
            # gc.collect()

            fee = self.psbt.calculate_fee()
            if fee is not None:
                msg.write("\nNetwork fee:\n%s %s\n" % self.chain.render_value(fee))

            # NEW: show where all the change outputs are going
            # self.output_change_text(msg)
            gc.collect()

            if self.psbt.warnings:
                msg.write('\n---WARNING---\n\n')

                for label, m in self.psbt.warnings:
                    msg.write('- %s: %s\n\n' % (label, m))

            if self.do_visualize:
                # stop here and just return the text of approval message itself
                self.result = await self.save_visualization(msg, (self.stxn_flags & STXN_SIGNED))
                del self.psbt
                self.done()

                return

            if not hsm_active:
                msg.write("\nPress OK to approve and sign transaction. X to abort.")
                ch = await ux_show_story(msg, title="OK TO SEND?")
            else:
                ch = await hsm_active.approve_transaction(self.psbt, self.psbt_sha, msg.getvalue())
                dis.progress_bar(1)     # finish the Validating...

        except MemoryError:
            # recovery? maybe.
            try:
                del self.psbt
                del msg
            except: pass        # might be NameError since we don't know how far we got
            gc.collect()

            msg = "Transaction is too complex"
            return await self.failure(msg)

        if ch != 'y':
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
            # for micro sd case
            await self.approved_cb(self.psbt)
            self.done()
            return

        txid = None
        try:
            # re-serialize the PSBT back out
            with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as fd:
                await fd.erase()

                if self.do_finalize:
                    txid = self.psbt.finalize(fd)
                else:
                    self.psbt.serialize(fd)

                fd.close()
                self.result = (fd.tell(), fd.checksum.digest())

            self.done(redraw=(not txid))

        except BaseException as exc:
            return await self.failure("PSBT output failed", exc)

        from glob import NFC

        if self.do_finalize and txid and not hsm_active:
            while 1:
                # Show txid when we can; advisory
                # - maybe even as QR, hex-encoded in alnum mode
                tmsg = txid + '\n\n'

                if has_fatram:
                    tmsg += 'Press 1 for QR Code of TXID. '
                if NFC:
                    tmsg += 'Press 3 to share signed txn over NFC.'

                ch = await ux_show_story(tmsg, "Final TXID", escape='13')

                if ch=='1' and has_fatram:
                    await show_qr_code(txid, True)
                    continue

                if ch == '3' and NFC:
                    await NFC.share_signed_txn(txid, TXN_OUTPUT_OFFSET,
                                                            self.result[0], self.result[1])
                    continue
                break

        # TODO ofter to share / or auto-share over NFC if that seems appropraite
        #if NFC:
            #NFC.share_signed_psbt(TXN_OUTPUT_OFFSET, self.result[0], self.result[1])

    def save_visualization(self, msg, sign_text=False):
        # write text into spi flash, maybe signing it as we go
        # - return length and checksum
        txt_len = msg.seek(0, 2)
        msg.seek(0)

        chk = self.chain.hash_message(msg_len=txt_len) if sign_text else None

        with SFFile(TXN_OUTPUT_OFFSET, max_size=txt_len+300, message="Visualizing...") as fd:
            await fd.erase()

            while 1:
                blk = msg.read(256).encode('ascii')
                if not blk: break
                if chk:
                    chk.update(blk)
                fd.write(blk)

            if chk:
                from ubinascii import b2a_base64
                # append the signature
                digest = ngu.hash.sha256s(chk.digest())
                sig = sign_message_digest(digest, 'm', None)
                fd.write(b2a_base64(sig).decode('ascii').strip())
                fd.write('\n')

            return (fd.tell(), fd.checksum.digest())

    def output_change_text(self, msg):
        # Produce text report of what the "change" outputs are (based on our opinion).
        # - we don't really expect all users to verify these outputs, but just in case.
        # - show the total amount, and list addresses

        total = 0
        addrs = []
        for outp in self.psbt.outputs:
            if not outp.is_change:
                continue
            total += outp.amount
            addrs.append(outp.address)

        if not addrs:
            return

        total_val = ' '.join(self.chain.render_value(total))

        msg.write("\nChange back:\n%s\n" % total_val)

        if len(addrs) == 1:
            msg.write(' - to address -\n%s\n' % addrs[0])
        else:
            msg.write(' - to addresses -\n')
            for a in addrs:
                msg.write('%s\n' % a)

    def output_summary_text(self, msg):
        # Produce text report of where their cash is going. This is what
        # they use to decide if correct transaction is being signed.
        # - does not show change outputs, by design.
        MAX_VISIBLE_OUTPUTS = const(10)

        num_change = sum(1 for o in self.psbt.outputs if o.is_change)

        if num_change == self.psbt.num_outputs:
            # consolidating txn that doesn't change balance of account.
            msg.write("Consolidating\n%s %s\nwithin wallet.\n\n" %
                            self.chain.render_value(self.psbt.total_value_out))
            msg.write("%d ins - fee\n = %d outs\n" % (
                        self.psbt.num_inputs, self.psbt.num_outputs))

            return

        if self.psbt.num_outputs - num_change <= MAX_VISIBLE_OUTPUTS:
            # simple, common case: don't sort outputs, and do show all of them
            first = True
            for idx, tx_out in self.psbt.output_iter():
                outp = self.psbt.outputs[idx]
                if outp.is_change:
                    continue

                if first:
                    first = False
                else:
                    msg.write('\n')

                msg.write(self.render_output(tx_out))

            return

        # Too many to show them all, so
        # find largest N outputs, and track total amount
        largest = []
        for idx, tx_out in self.psbt.output_iter():
            outp = self.psbt.outputs[idx]
            if outp.is_change:
                continue

            if len(largest) < MAX_VISIBLE_OUTPUTS:
                largest.append( (tx_out.nValue, self.render_output(tx_out)) )
                continue

            # insertion sort
            here = tx_out.nValue
            for li, (nv, txt) in enumerate(largest):
                if here > nv:
                    keep = li
                    break
            else:
                continue        # too small 

            largest.pop(-1)
            largest.insert(keep, (here, self.render_output(tx_out)))

        for val, txt in largest:
            msg.write(txt)
            msg.write('\n')

        left = self.psbt.num_outputs - len(largest) - num_change
        if left > 0:
            msg.write('.. plus %d smaller output(s), not shown here, which total: ' % left)

            # calculate left over value
            mtot = self.psbt.total_value_out - sum(v for v,t in largest)
            mtot -= sum(o.nValue for i, o in self.psbt.output_iter() 
                                        if self.psbt.outputs[i].is_change)

            msg.write('%s %s\n' % self.chain.render_value(mtot))


def sign_transaction(psbt_len, flags=0x0, psbt_sha=None):
    # transaction (binary) loaded into sflash/PSRAM already, checksum checked
    UserAuthorizedAction.check_busy(ApproveTransaction)
    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, flags, psbt_sha=psbt_sha)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

def psbt_encoding_taster(taste, psbt_len):
    # look at first 10 bytes, and detect file encoding (binary, hex, base64)
    # - return len is upper bound on size because of unknown whitespace
    from utils import HexStreamer, Base64Streamer, HexWriter, Base64Writer

    if taste[0:5] == b'psbt\xff':
        decoder = None
        output_encoder = lambda x: x
    elif taste[0:10] == b'70736274ff' or taste[0:10] == b'70736274FF':
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
    
async def sign_psbt_file(filename, force_vdisk=False):
    # sign a PSBT file found on a MicroSD card
    # - or from VirtualDisk (mk4)
    from files import CardSlot, CardMissingError
    from glob import dis
    from sram2 import tmp_buf

    UserAuthorizedAction.cleanup()

    #print("sign: %s" % filename)

    # copy file into our spiflash
    # - can't work in-place on the card because we want to support writing out to different card
    # - accepts hex or base64 encoding, but binary prefered
    with CardSlot(force_vdisk, readonly=True) as card:
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
                # blank flash
                await out.erase()

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

    async def done(psbt):
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
                    with CardSlot(force_vdisk, readonly=True) as card:
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
                    with CardSlot(force_vdisk) as card:
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

                            if out2_full:
                                with HexWriter(card.open(out2_full, 'w+t')) as fd:
                                    # save transaction, in hex
                                    txid = psbt.finalize(fd)

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
                                        "and press OK.", title="Need Card")
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

    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, approved_cb=done)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

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

        showit = False
        while 1:
            if showit:
                ch = await ux_show_story('''Given:\n\n%s\n\nShould we switch to that wallet now?

OK to continue, X to cancel.''' % self._pw, title="Passphrase")
            else:
                ch = await ux_show_story('''BIP-39 passphrase (%d chars long) has been provided over USB connection. Should we switch to that wallet now?

Press 2 to view the provided passphrase.\n\nOK to continue, X to cancel.''' % len(self._pw), title="Passphrase", escape='2')

            if ch == '2':
                showit = True
                continue
            break

        try:
            if ch != 'y':
                # they don't want to!
                self.refused = True
                await ux_dramatic_pause("Refused.", 1)
            else:
                from seed import set_bip39_passphrase

                # full screen message shown: "Working..."
                set_bip39_passphrase(self._pw)

                self.result = settings.get('xpub')


        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            self.done()

        if self.result:
            new_xfp = settings.get('xfp')
            await ux_show_story('''Above is the master key fingerprint of the current wallet.''',
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
            if NFC:
                msg += ' Press 3 to share over NFC.'
            if has_fatram:
                msg += ' Press 4 to view QR Code.'

            while 1:
                ch = await ux_show_story(msg, title=self.title, escape='34')

                if ch == '4' and has_fatram:
                    await show_qr_code(self.address, (self.addr_fmt & AFC_BECH32))
                    continue
                if ch == '3' and NFC:
                    await NFC.share_text(self.address)
                    continue
                break
        else:
            # finish the Wait...
            dis.progress_bar(1)     
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

    import ustruct
    from multisig import MultisigWallet, MultisigOutOfSpace

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
    def __init__(self, ms, auto_export=False):
        super().__init__()
        self.wallet = ms
        self.auto_export = auto_export

        # self.result ... will be re-serialized xpub

    async def interact(self):
        from multisig import MultisigOutOfSpace

        ms = self.wallet
        try:
            ch = await ms.confirm_import()

            if ch == 'y':
                if self.auto_export:
                    # save cosigner details now too 
                    await ms.export_wallet_file('created on', 
    "\n\nImport that file onto the other Coldcards involved with this multisig wallet.")
                    await ms.export_electrum()

            else:
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
    from multisig import MultisigWallet

    UserAuthorizedAction.cleanup()

    if sf_len:
        with SFFile(TXN_INPUT_OFFSET, length=sf_len) as fd:
            config = fd.read(sf_len).decode()

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

                if not has_psram:
                    from sflash import SF
                    import callgate
                    SF.write(self.length, self.hdr)

                    callgate.show_logout(2)
                else:
                    # Mk4 copies from PSRAM to flash inside bootrom, we have
                    # nothing to do here except start that process.
                    from pincodes import pa
                    pa.firmware_upgrade(self.psram_offset, self.length)
                    # not reached, unless issue?
                    raise RuntimeError("bootrom fail")
            else:
                # they don't want to!
                self.refused = True
                if not has_psram:
                    from sflash import SF
                    SF.block_erase(0)           # just in case, but not required
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
