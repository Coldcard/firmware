# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, chains, sys, gc, uio, version, ngu, ujson
from ubinascii import b2a_base64, a2b_base64
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from uhashlib import sha256
from public_constants import AFC_SCRIPT, AF_CLASSIC, AFC_BECH32, SUPPORTED_ADDR_FORMATS
from public_constants import STXN_FINALIZE, STXN_VISUALIZE, STXN_SIGNED, AF_P2SH, AF_P2WPKH_P2SH
from sffile import SFFile
from menu import MenuSystem, MenuItem
from serializations import ser_uint256, SIGHASH_ALL
from ux import ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys, ux_confirm, the_ux
from ux import show_qr_code, OK, X, abort_and_push, AbortInteraction, ux_input_text, ux_enter_number
from usb import CCBusyError
from utils import (HexWriter, xfp2str, problem_file_line, cleanup_deriv_path, B2A,
                   show_single_address, keypath_to_str, seconds2human_readable)
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from files import CardSlot, CardMissingError
from exceptions import HSMDenied, QRTooBigError
from version import MAX_TXN_LEN
from charcodes import KEY_QR, KEY_NFC, KEY_ENTER, KEY_CANCEL, KEY_LEFT, KEY_RIGHT
from msgsign import sign_message_digest

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

        # check if UX actually was cleared, and we're not really doing that anymore; recover
        # - happens if USB caller never comes back for their final results
        from ux import the_ux
        top_ux = the_ux.top_of_stack()
        if not isinstance(top_ux, cls) and cls.active_request.ux_done:
            # do cleaup
            cls.cleanup()
            return

        raise CCBusyError()

    async def failure(self, msg, exc=None, title='Failure'):
        self.failed = msg
        self.done()

        # show line number and/or simple text about error
        if exc:
            #print("%s:" % msg)
            #sys.print_exception(exc)

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

class ApproveMessageSign(UserAuthorizedAction):
    def __init__(self, text, subpath, addr_fmt, approved_cb=None,
                 msg_sign_request=None, only_printable=True):
        super().__init__()
        is_json = False

        from msgsign import validate_text_for_signing, parse_msg_sign_request

        if msg_sign_request:
            text, subpath, addr_fmt, is_json = parse_msg_sign_request(msg_sign_request)

        self.text = validate_text_for_signing(
            text, only_printable=not is_json and only_printable
        )
        self.subpath = cleanup_deriv_path(subpath)
        self.addr_fmt = chains.parse_addr_fmt_str(addr_fmt)
        self.approved_cb = approved_cb

        from glob import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(self.subpath)
            self.address = sv.chain.address(node, self.addr_fmt)

        dis.progress_bar_show(1)

    async def interact(self):
        # Prompt user w/ details and get approval
        from glob import hsm_active

        if hsm_active:
            ch = await hsm_active.approve_msg_sign(self.text, self.address, self.subpath)
        else:
            story = MSG_SIG_TEMPLATE.format(msg=self.text, addr=show_single_address(self.address),
                                            subpath=self.subpath)
            ch = await ux_show_story(story)

        if ch != 'y':
            # they don't want to!
            self.refused = True
        else:
            # perform signing (progress bar shown)
            digest = chains.current_chain().hash_message(self.text.encode())
            self.result, _ = sign_message_digest(digest, self.subpath, "Signing...", self.addr_fmt)

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
    # Start the approval process for message signing.
    UserAuthorizedAction.check_busy()
    UserAuthorizedAction.active_request = ApproveMessageSign(text, subpath, addr_fmt)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

async def approve_msg_sign(text, subpath, addr_fmt, approved_cb=None,
                           msg_sign_request=None, kill_menu=False,
                           only_printable=True):

    # Ask user if they want to sign some short text message.
    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.check_busy(ApproveMessageSign)
    try:
        UserAuthorizedAction.active_request = ApproveMessageSign(
            text, subpath, addr_fmt,
            approved_cb=approved_cb,
            msg_sign_request=msg_sign_request,
            only_printable=only_printable,
        )

        if kill_menu:
            abort_and_goto(UserAuthorizedAction.active_request)
        else:
            # do not kill the menu stack! just push
            from ux import the_ux
            the_ux.push(UserAuthorizedAction.active_request)

    except (AssertionError, ValueError) as exc:
        await ux_show_story("Problem: %s\n\nMessage to be signed must be a single line of ASCII text." % exc)

async def sign_txt_file(filename):
    # sign a one-line text file found on a MicroSD card
    # - not yet clear how to do address types other than 'classic'
    from ux import the_ux
    from msgsign import sd_sign_msg_done

    async def done(signature, address, text):
        # complete. write out result
        from glob import dis

        orig_path, basename = filename.rsplit('/', 1)
        orig_path += '/'
        base = basename.rsplit('.', 1)[0]

        await sd_sign_msg_done(signature, address, text, base, orig_path)

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.check_busy()

    # copy message into memory
    with CardSlot() as card:
        with card.open(filename, 'rt') as fd:
            res = fd.read()

    await approve_msg_sign(None, None, None, approved_cb=done,
                           msg_sign_request=res)

async def try_push_tx(data, txid, txn_sha=None):
    # if NFC PushTx is enabled, do that w/o questions.
    from glob import settings, PSRAM, NFC

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
    def __init__(self, psbt_len, flags=None, psbt_sha=None, input_method=None,
                 output_encoder=None, filename=None):
        super().__init__()
        self.psbt_len = psbt_len

        # do finalize is None if not USB, None = decide based on is_complete
        if flags is None:
            self.do_finalize = self.do_visualize = None
        else:
            self.do_finalize = bool(flags & STXN_FINALIZE)
            self.do_visualize = bool(flags & STXN_VISUALIZE)

        self.stxn_flags = flags
        self.psbt = None
        self.psbt_sha = psbt_sha
        self.input_method = input_method
        self.output_encoder = output_encoder
        self.filename = filename
        self.result = None      # will be (len, sha256) of the resulting PSBT
        self.chain = chains.current_chain()

    async def por322_msg_verify(self):
        # https://gist.github.com/orangesurf/0c1d0a31d3ebe7e48335a34d56788d4c
        from glob import NFC
        from ux import import_export_prompt
        from actions import file_picker
        ch = await import_export_prompt("message", is_import=True, force_prompt=True,
                                        intro="Import msg that hashes to 'to_spend' msg hash.",
                                        key0="to input message manually", title="BIP-322 MSG",
                                        no_qr=not version.has_qwerty)

        # TODO move elswhere
        bip322_tag_hash = b'te\x84\xa1\x87/\xa1\x00AUN\xff\xa08\xd6\x12IB\xddy\xb4\xe5\x8aL\xda\x18N\x13\xdb\xe6,I'

        if ch == KEY_CANCEL:
            return
        elif ch == "0":
            msg = await ux_input_text("")
        elif ch == KEY_NFC:
            msg = await NFC.read_bip322_msg()
        elif ch == KEY_QR:
            from ux_q1 import QRScannerInteraction
            msg = await QRScannerInteraction().scan_text('Scan MSG from a QR code')
        else:
            choices = await file_picker(suffix='.txt', ux=False)
            target = "%s.txt" % b2a_hex(self.psbt.por322_msg_hash).decode()

            for fname, dir, _ in choices:
                if target == fname:
                    fn = dir + "/" + fname
                    break
            else:
                fn = await file_picker(choices=choices)

            if not fn: return

            with CardSlot(readonly=True, **ch) as card:
                with open(fn, 'rt') as fd:
                    msg = fd.read()

        # TODO needs newer libngu with sha256t
        assert msg, "need msg"
        msg_hash = ngu.hash.sha256s(bip322_tag_hash+bip322_tag_hash+msg)
        assert msg_hash == self.psbt.por322_msg_hash, "hash verification failed"
        ch = await ux_show_story(
            msg+"\n\nPress %s to approve message, otherwise %s to exit." % (OK, X),
            title="MSG:"
        )
        return True if ch == "y" else False


    def render_output(self, o):
        # Pretty-print a transactions output. 
        # - expects CTxOut object
        # - gives user-visible string
        # returns: tuple(ux_output_rendition, address_or_script_str_for_qr_display)
        # 
        val = ' '.join(self.chain.render_value(o.nValue))
        try:
            dest = self.chain.render_address(o.scriptPubKey)
            # known script types are short enough that we can display QR on both hw versions
            return '%s\n - to address -\n%s\n' % (val, show_single_address(dest)), dest
        except ValueError:
            pass

        # Handle future things better: allow them to happen at least.
        # sending to some unknown script, possibly very long
        # but full-show required for verification
        # OP_RETURN dest contains also OP_RETURN itself (for PSBT qr explorer)
        dest = B2A(o.scriptPubKey)

        # check for OP_RETURN
        data = self.chain.op_return(o.scriptPubKey)
        # In UX story only data are shown as OP_RETURN is part of base msg
        if data is None:
            rv = '%s\n - to script -\n%s\n' % (val, dest)
        else:
            base = '%s\n - OP_RETURN -\n%s'
            if not data:
                dest = ""
                rv = base % (val, "null-data\n")
            else:
                data_ascii = None
                if len(data) > 160:
                    # completely arbitrary limit, prevents huge stories
                    # anchor data are not relevant for verification - can be hidden
                    ss = b2a_hex(data[:80]).decode() + "\n ⋯\n" + b2a_hex(data[-80:]).decode()
                    # but we show empty QR in txn explorer for these big, modified data
                else:
                    ss = b2a_hex(data).decode()
                    if (min(data) >= 32) and (max(data) < 127):  # printable & not huge
                        try:
                            data_ascii = data.decode("ascii")
                        except: pass

                rv = base % (val, ss)
                if data_ascii:
                    rv += " (ascii: %s)" % data_ascii
                rv += "\n"

        return rv, dest

    async def interact(self):
        # Prompt user w/ details and get approval
        from glob import dis, hsm_active
        from ccc import CCCFeature, SSSPFeature

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
            await self.psbt.validate()  # might do UX: accept multisig import
            dis.progress_sofar(10, 100)

            # consider_keys only needs num_our_keys to be set
            # it set during psbt.validate()
            self.psbt.consider_keys()
            dis.progress_sofar(20, 100)

            ccc_c_xfp = CCCFeature.get_xfp()  # can be None
            self.psbt.consider_inputs(cosign_xfp=ccc_c_xfp)
            dis.progress_sofar(50, 100)

            self.psbt.consider_outputs()
            dis.progress_sofar(75, 100)

            self.psbt.consider_dangerous_sighash()
            dis.progress_sofar(90, 100)

        except FraudulentChangeOutput as exc:
            #print('FraudulentChangeOutput: ' + exc.args[0])
            return await self.failure(exc.args[0], title='Change Fraud')
        except FatalPSBTIssue as exc:
            #print('FatalPSBTIssue: ' + exc.args[0])
            return await self.failure(exc.args[0])
        except BaseException as exc:
            # sys.print_exception(exc)
            del self.psbt
            gc.collect()

            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex"
                exc = None
            else:
                msg = "Invalid PSBT"

            return await self.failure(msg, exc)

        # early test for spending policy; not an error if violates policy
        # - might add warnings
        could_ccc_sign, ccc_needs_2fa = CCCFeature.could_cosign(self.psbt)

        # test for allowing any signature when in single-signer mode
        # - but CCC will override it.
        should_block, ss_needs_2fa = SSSPFeature.can_allow(self.psbt)
        if should_block and not could_ccc_sign:
            return await self.failure('Spending Policy violation.')

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

            if self.psbt.por322:

                try:
                    if not await self.por322_msg_verify():
                        self.refused = True
                        await ux_dramatic_pause("Refused.", 1)
                        self.done()
                        return
                except Exception as exc:
                    return await self.failure("Msg verification failed.", exc)

                msg.write("Proof of Reserves\n\n")
                msg.write("Amount %s %s\n\n" % self.chain.render_value(self.psbt.total_value_in))
                msg.write("Message Hash:\n%s\n\n" % b2a_hex(self.psbt.por322_msg_hash).decode())
                msg.write("Message Challenge:\n%s\n\n" % b2a_hex(self.psbt.por322_msg_challenge).decode())
            else:
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
            self.output_summary_text(msg)
            gc.collect()

            if self.psbt.ux_notes:
                # currently we only have locktimes in ux_notes
                msg.write('TX LOCKTIMES\n\n')

                for label, m in self.psbt.ux_notes:
                    msg.write('- %s: %s\n' % (label, m))

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
                esc = "2"
                msg.write("Press %s to approve and sign transaction."
                          " Press (2) to explore transaction." % OK)
                if (self.input_method == "sd") and CardSlot.both_inserted():
                    esc += "b"
                    msg.write(" (B) to write to lower SD slot.")
                msg.write(" %s to abort." % X)

                title = "OK TO %s?" % ("SIGN" if self.psbt.por322 else "SEND")
                while True:
                    ch = await ux_show_story(msg, title=title, escape=esc)
                    if ch == "2":
                        await TXExplorer.start(self)
                        continue
                    else:
                        msg.close()
                        del msg
                        break
            else:
                # get approval (maybe) from the HSM
                ch = await hsm_active.approve_transaction(self.psbt, self.psbt_sha, msg.getvalue())

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
            # they don't want to sign!
            self.refused = True

            await ux_dramatic_pause("Refused.", 1)

            del self.psbt

            self.done()
            return

        if ccc_needs_2fa and could_ccc_sign:
            # They still need to pass web2fa challenge (but it meets other specs ok)
            try:
                await CCCFeature.web2fa_challenge()
            except:
                could_ccc_sign = False
                ch2 = await ux_show_story("Will not add CCC signature. Proceed anyway?")
                if ch2 != 'y':
                    return await self.failure("2FA Failed")

        elif ss_needs_2fa:
            # Need 2FA for single-sig case .. refuse to sign if it fails.
            try:
                await SSSPFeature.web2fa_challenge()
            except:
                return await self.failure("2FA Failed")

        # do the actual signing.
        try:
            dis.fullscreen('Wait...')
            gc.collect()           # visible delay caused by this but also sign_it() below
            self.psbt.sign_it()

            if could_ccc_sign:
                # this is where the CCC co-signing happens.
                dis.fullscreen('Co-Signing...')
                gc.collect()
                CCCFeature.sign_psbt(self.psbt)

            if SSSPFeature.is_enabled():
                # capture new min-height for velocity limit
                SSSPFeature.update_last_signed(self.psbt)

        except FraudulentChangeOutput as exc:
            return await self.failure(exc.args[0], title='Change Fraud')
        except MemoryError:
            msg = "Transaction is too complex"
            return await self.failure(msg)
        except BaseException as exc:
            return await self.failure("Signing failed late", exc)

        try:
            await done_signing(self.psbt, self, self.input_method,
                                self.filename, self.output_encoder,
                                slot_b=(ch == "b"), finalize=self.do_finalize)
            self.done()
        except AbortInteraction:
            # user might have sent new sign cmd, while we still at export prompt
            pass
        except BaseException as exc:
            # sys.print_exception(exc)
            return await self.failure("PSBT output failed", exc)

    async def save_visualization(self, msg, sign_text=False):
        # write story text out, maybe signing it as we go
        # - return length and checksum
        from charcodes import OUT_CTRL_ADDRESS

        txt_len = msg.seek(0, 2)
        msg.seek(0)

        chk = self.chain.hash_message(msg_len=txt_len) if sign_text else None

        with SFFile(TXN_OUTPUT_OFFSET, max_size=txt_len+300, message="Visualizing...") as fd:
            while 1:
                # replace with empty space, to keep correct txt_len - already hashed
                blk = msg.read(256).replace(OUT_CTRL_ADDRESS, ' ').encode('ascii')
                if not blk: break
                if chk:
                    chk.update(blk)
                fd.write(blk)

            if chk:
                # append the signature
                digest = ngu.hash.sha256s(chk.digest())
                sig, _ = sign_message_digest(digest, 'm', None, AF_CLASSIC)
                fd.write(b2a_base64(sig).decode('ascii').strip())
                fd.write('\n')

            return fd.tell(), fd.checksum.digest()

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

        largest_outs = []
        largest_change = []
        total_change = 0
        has_change = False

        for idx, tx_out in self.psbt.output_iter():
            outp = self.psbt.outputs[idx]
            if outp.is_change:
                has_change = True
                total_change += tx_out.nValue
                if len(largest_change) < MAX_VISIBLE_CHANGE:
                    largest_change.append((tx_out.nValue, self.chain.render_address(tx_out.scriptPubKey)))
                    if len(largest_change) == MAX_VISIBLE_CHANGE:
                        largest_change = sorted(largest_change, key=lambda x: x[0], reverse=True)
                    continue

            else:
                if len(largest_outs) < MAX_VISIBLE_OUTPUTS:
                    rendered, _ = self.render_output(tx_out)
                    largest_outs.append((tx_out.nValue, rendered))
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
                rendered, _ = self.render_output(tx_out)
                ret = (here, rendered)
            largest.insert(keep, ret)

        # foreign outputs (soon to be other people's coins)
        visible_out_sum = 0
        for val, txt in largest_outs:
            visible_out_sum += val
            msg.write(txt)  # txt is result of render_output
            msg.write('\n')

        left = self.psbt.num_outputs - len(largest_outs) - self.psbt.num_change_outputs
        if left > 0:
            msg.write('.. plus %d smaller output(s), not shown here, which total: ' % left)

            # calculate left over value
            msg.write('%s %s\n' % self.chain.render_value(
                self.psbt.total_value_out - total_change - visible_out_sum))

            msg.write("\n")

        # change outputs - verified to be coming back to our wallet
        if has_change:
            msg.write("Change back:\n%s %s\n" % self.chain.render_value(total_change))
            visible_change_sum = 0
            if len(largest_change) == 1:
                visible_change_sum += largest_change[0][0]
                msg.write(' - to address -\n%s\n\n' % show_single_address(largest_change[0][1]))
            else:
                msg.write(' - to addresses -\n')
                for val, addr in largest_change:
                    visible_change_sum += val
                    msg.write(show_single_address(addr))
                    msg.write('\n\n')

            left_c = self.psbt.num_change_outputs - len(largest_change)
            if left_c:
                msg.write('.. plus %d smaller change output(s), not shown here, which total: ' % left_c)
                msg.write('%s %s\n\n' % self.chain.render_value(total_change - visible_change_sum))


def sign_transaction(psbt_len, flags=0x0, psbt_sha=None):
    # transaction (binary) loaded into PSRAM already, checksum checked
    UserAuthorizedAction.check_busy(ApproveTransaction)
    UserAuthorizedAction.active_request = ApproveTransaction(
        psbt_len, flags, psbt_sha=psbt_sha, input_method="usb",
    )

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


async def done_signing(psbt, tx_req, input_method=None, filename=None,
                       output_encoder=None, slot_b=False, finalize=None):
    # User authorized PSBT for signing, and we added signatures.
    # - allow PushTX if enabled (first thing)
    # - can save final TXN out to SD card/VirtDisk, share by NFC, QR.

    from glob import PSRAM, hsm_active
    from sffile import SFFile
    from ux import show_qr_code, import_export_prompt

    first_time = True
    msg = None
    title = None

    is_complete = psbt.is_complete()
    if finalize is not None:
        # USB case - user can choose whether to attempt finalization
        is_complete = finalize

    with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as psram:
        if is_complete:
            txid = psbt.finalize(psram)
            noun = "Finalized TX ready for broadcast"
        else:
            psbt.serialize(psram)
            noun = "Partly Signed PSBT"
            txid = None

        data_len = psram.tell()
        data_sha2 = psram.checksum.digest()

    if input_method == "usb":
        # return result over USB before going to all options
        tx_req.result = data_len, data_sha2
        if hsm_active:
            # it is enough to just return back via USB, other options
            # are pointless
            return

        first_time = False
        msg = noun + " shared via USB."
        title = "PSBT Signed"

    if txid and await try_push_tx(data_len, txid, data_sha2):
        # go directly to reexport menu after pushTX
        first_time = False
        title = "TX Pushed"

    # for specific cases, key teleport is an option
    offer_kt = False
    if not is_complete and psbt.active_multisig and version.has_qwerty:
        offer_kt = 'use Key Teleport to send PSBT to other co-signers'

    while True:
        ch = None
        if first_time:
            # first time, assume they want to send out same way it came in -- don't prompt
            if input_method == "qr":
                ch = KEY_QR
            elif input_method == "nfc":
                ch = KEY_NFC
            elif input_method == "kt":
                ch = 't'
            else:
                # SD/VDisk
                ch = {"force_vdisk": input_method == "vdisk", "slot_b": slot_b}

        if not ch:
            # show all possible export options (based on hardware enabled, features)
            intro = []
            if msg:
                intro.append(msg)
            if txid:
                intro.append('TXID:\n' + txid)

            # "force_prompt" is needed after first iteration as we can be Mk4, with NFC,Vdisk off,
            # no QR support & not finalizing (no option to show txid provided).
            # In that case this would just return dict and keep producing signed
            # files on SD infinitely (would never actually prompt).
            ch = await import_export_prompt(noun, intro="\n\n".join(intro), offer_kt=offer_kt,
                                            key6="for QR Code of TXID", title=title,
                                            force_prompt=not first_time,
                                            no_qr=not version.has_qwerty)
        if ch == KEY_CANCEL:
            UserAuthorizedAction.cleanup()
            break

        elif txid and (ch == '6'):
            await show_qr_code(txid, is_alnum=True, force_msg=True)
            continue

        elif ch == KEY_QR:
            here = PSRAM.read_at(TXN_OUTPUT_OFFSET, data_len)
            msg = txid or 'Partly Signed PSBT'
            try:
                if len(here) > 920:
                    # too big for simple QR - use BBQr instead
                    raise QRTooBigError
                hex_here = b2a_hex(here).upper().decode()
                await show_qr_code(hex_here, is_alnum=True, msg=msg)
            except QRTooBigError:
                from ux_q1 import show_bbqr_codes
                await show_bbqr_codes('T' if txid else 'P', here, msg)

            msg = noun + " shared via QR."
            del here

        elif ch == KEY_NFC:
            from glob import NFC
            if is_complete:
                await NFC.share_signed_txn(txid, TXN_OUTPUT_OFFSET, data_len, data_sha2)
            else:
                await NFC.share_psbt(TXN_OUTPUT_OFFSET, data_len, data_sha2)

            msg = noun + " shared via NFC."

        elif (ch == 't') and not is_complete:
            # they might want to teleport it, but only if we have PSBT
            # there is no need to teleport PSBT if txn is already complete & ready to be broadcast
            from teleport import kt_send_psbt
            ok = await kt_send_psbt(psbt, data_len)
            if ok is None:
                title = "Failed to Teleport"
            else:
                title = "Sent by Teleport"
                _, num_sigs_needed = ok
                if num_sigs_needed > 0:
                    s, aux = ("", "is") if num_sigs_needed == 1 else ("s", "are")
                    msg = "%d more signature%s %s still required." % (num_sigs_needed, s, aux)
            continue

        else:
            # typical case: save to SD card, show filenames we used
            assert isinstance(ch, dict)
            msg = await _save_to_disk(psbt, txid, ch, is_complete, data_len,
                                      output_encoder, filename)

        input_method = None
        first_time = False
        title = "PSBT Signed"

async def _save_to_disk(psbt, txid, save_options, is_complete, data_len, output_encoder, filename=None):
    # Saving a PSBT from PSRAM to something disk-like.
    # - handle save-to-SD/VirtDisk cases. With re-attempt when no card, etc.
    assert isinstance(save_options, dict)       # from import_export_prompt

    from glob import dis, settings, PSRAM
    import os

    dis.fullscreen("Wait...")

    if filename:
        _, basename = filename.rsplit('/', 1)
        base = basename.rsplit('.', 1)[0]
    else:
        base = 'recent-txn'

    # default encoding is binary
    output_encoder = output_encoder or (lambda x:x)

    out2_fn = None
    out_fn = None

    del_after = settings.get('del', 0)

    def _chunk_write(file_d, ofs, chunk=4096):
        written = 0
        while written < data_len:
            if (written + chunk) > data_len:
                chunk = data_len - written

            file_d.write(PSRAM.read_at(ofs, chunk))
            written += chunk
            ofs += chunk

    while 1:
        # try to put back into same spot, but also do top-of-card
        if not is_complete:
            # keep the filename under control during multiple passes
            target_fname = base.replace('-part', '') + '-part.psbt'
        else:
            # add -signed to end. We won't offer to sign again.
            target_fname = base + '-signed.psbt'

        # attempt write-out
        try:
            with CardSlot(**save_options) as card:
                out_full, out_fn = card.pick_filename(target_fname)
                out_path = out_full.rsplit("/", 1)[0] + "/"

                if is_complete and del_after:
                    # don't write signed PSBT if we'd just delete it anyway
                    out_fn = None
                else:
                    with output_encoder(card.open(out_full, 'wb')) as fd:
                        # save as updated PSBT
                        if not is_complete:
                            _chunk_write(fd, TXN_OUTPUT_OFFSET)
                        else:
                            psbt.serialize(fd)

                if is_complete:
                    # write out as hex too, if it's final
                    out2_full, out2_fn = card.pick_filename(
                        base + '-final.txn' if not del_after else 'tmp.txn',
                        out_path)

                    if out2_full:
                        with HexWriter(card.open(out2_full, 'w+t')) as fd:
                            # save transaction, in hex
                            if is_complete:
                                _chunk_write(fd, TXN_OUTPUT_OFFSET)
                            else:
                                txid = psbt.finalize(fd)

                        if del_after:
                            # rename it now that we know the txid
                            after_full, out2_fn = card.pick_filename(
                                txid + '.txn', out_path, overwrite=True)
                            os.rename(out2_full, after_full)

                if del_after and filename:
                    # this can do nothing if they swapped SDCard between steps, which is ok,
                    # but if the original file is still there, this blows it away.
                    # - if not yet final, the foo-part.psbt file stays
                    try:
                        card.securely_blank_file(filename)
                    except: pass

            # success and done!
            break

        except CardMissingError:
            prob = 'Need a card!\n\n'

        except OSError as exc:
            prob = 'Failed to write!\n\n%s\n\n' % exc
            # sys.print_exception(exc)
            # fall through to try again

        # If this point reached, some problem, we could not write.

        if save_options.get('force_vdisk'):
            await ux_show_story(prob, title='Error')
            # they can't fix here, so give up
            return

        # prompt them to input another card?
        ch = await ux_show_story(
            prob + "Please insert a card to receive signed transaction, "
                   "and press OK.", title="Need Card")
        if ch == 'x':
            return

    # Done, show the filenames we used.
    if out_fn:
        msg = "Updated PSBT is:\n\n%s" % out_fn
        if out2_fn:
            msg += '\n\n'
    else:
        # del_after is probably set
        msg = ''

    if out2_fn:
        msg += 'Finalized transaction (ready for broadcast):\n\n%s' % out2_fn

    return msg

    
async def sign_psbt_file(filename, force_vdisk=False, slot_b=None, just_read=False, ux_abort=False):
    # sign a PSBT file found on a MicroSD card
    # - or from VirtualDisk (mk4)
    # - to re-use reading/decoding logic, pass just_read
    from glob import dis
    from ux import the_ux

    tmp_buf = bytearray(4096)

    # copy file into PSRAM
    # - can't work in-place on the card because we want to support writing out to different card
    # - accepts hex or base64 encoding, but binary preferred
    with CardSlot(force_vdisk, readonly=True, slot_b=slot_b) as card:
        with card.open(filename, 'rb') as fd:
            dis.fullscreen('Reading...', 0)

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

                    dis.progress_sofar(total, psbt_len)

            # might have been whitespace inflating initial estimate of PSBT size
            assert total <= psbt_len
            psbt_len = total

    if just_read:
        return psbt_len

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = ApproveTransaction(
        psbt_len, input_method="vdisk" if force_vdisk else "sd",
        filename=filename, output_encoder=output_encoder,
    )
    if ux_abort:
        # needed for auto vdisk mode
        abort_and_push(UserAuthorizedAction.active_request)
    else:
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
            #print("Backup failure: ")
            #sys.print_exception(exc)
        finally:
            self.done()


class RemoteRestoreBackup(UserAuthorizedAction):
    def __init__(self, file_len, bitflag):
        super().__init__()
        self.file_len = file_len
        self.custom_pwd = bitflag & 1
        self.plaintext = bitflag & 2
        self.force_tmp = bitflag & 4

    def to_words(self):
        # conversion to "words" argument of "restore_complete" function
        if self.plaintext:
            return None
        elif self.custom_pwd:
            return False
        return True

    def to_tmp(self):
        # conversion to "temporary" argument of "restore_complete" function
        from pincodes import pa
        if pa.is_secret_blank() and not self.force_tmp:
            # no master secret & not forcing tmp
            # will load backup as master seed
            return False, "master"

        # has master secret --> load backup as tmp
        # secret is blank but user forcing tmp
        return True, "temporary"

    async def interact(self):
        try:
            # requires confirm from user
            tmp, noun = self.to_tmp()
            if await ux_confirm("Restore uploaded backup as a %s seed?" % noun):
                from backups import restore_complete
                await restore_complete(self.file_len, tmp, self.to_words(), usb=True)
            else:
                self.refused = True

        except BaseException as exc:
            self.failed = "Error during backup restore."
            # sys.print_exception(exc)
        finally:
            self.done()


def start_remote_backup():
    # tell the local user the secret words, and then save to SPI flash
    # USB caller has to come back and download encrypted contents.

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = RemoteBackup()

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

def start_remote_restore_backup(file_len, bitflag):
    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = RemoteRestoreBackup(file_len, bitflag)
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
            # sys.print_exception(exc)
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

            esc = "4"
            if not version.has_qwerty:
                if NFC:
                    msg += ' Press (3) to share via NFC.'
                    esc += "3"
                msg += ' Press (4) to view QR Code.'

            while 1:
                ch = await ux_show_story(msg, title=self.title, escape=esc,
                                         hint_icons=KEY_QR+(KEY_NFC if NFC else ''))

                if ch in '4'+KEY_QR:
                    await show_qr_code(self.address, (self.addr_fmt & AFC_BECH32), is_addrs=True)
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
        return '''{addr}\n\n= {sp}''' .format(addr=show_single_address(self.address),
                                              sp=self.subpath)


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

{sp}'''.format(addr=show_single_address(self.address), name=self.ms.name,
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
            # sys.print_exception(exc)
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
            # sys.print_exception(exc)
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


class TXExplorer:
    def __init__(self, n, user_auth_action, max_items):
        self.n = n
        self.user_auth_action = user_auth_action
        self.max_items = max_items
        self.chain = chains.current_chain()
        self.qr_msgs = []
        self.title = None

    @classmethod
    async def start(cls, user_auth_action):
        rv = [
            MenuItem("Inputs", f=TXInpExplorer(user_auth_action).explore),
            MenuItem("Outputs", f=TXOutExplorer(user_auth_action).explore),
        ]
        the_ux.push(MenuSystem(rv))
        await the_ux.interact()

    def make_ux_msg(self, offset, count):
        from glob import dis
        dis.fullscreen('Wait...')
        rv = ""
        qrs = []
        change = []
        end = min(offset + count, self.max_items)
        for idx, item in self.yield_item(offset, end, qrs, change):
            rv += item
            dis.progress_sofar(idx-offset+1, count)

        rv += 'Press RIGHT to see next group'
        if offset:
            rv += ', LEFT to go back'

        rv += ", (2) to go to index"

        if not version.has_qwerty:
            # Q has hint key
            rv += ", (4) to show QR code"
        rv += ('. %s to quit.' % X)

        return rv, qrs, change, end


    async def explore(self, *a):
        # Page through unlimited-sized transaction details
        # - shows all outputs (including change): their address and amounts.
        # - shows all inputs: utxo amount and address, txid & tx index.

        start = 0
        msg, addrs, change, end = self.make_ux_msg(start, self.n)

        while True:
            ch = await ux_show_story(msg, title=self.title, escape='2479'+KEY_RIGHT+KEY_LEFT+KEY_QR,
                                     hint_icons=KEY_QR)
            if ch == 'x':
                del msg
                return
            elif (ch in "4"+KEY_QR) and addrs:
                from ux import show_qr_codes
                # showing addresses from PSBT, no idea what is in there
                # handle QR code failures gracefully
                await show_qr_codes(addrs, False, start, is_addrs=True,
                                    change_idxs=change, can_raise=False,
                                    qr_msgs=self.qr_msgs, no_index=bool(self.qr_msgs))
                continue
            elif ch in (KEY_LEFT+"7"):
                if not start: continue # 0
                start = max(start - self.n, 0)

            elif ch in (KEY_RIGHT+"9"):
                if (start + self.n) >= self.max_items:
                    continue
                else:
                    # go forwards
                    start += self.n
            elif ch == "2":
                max_v = self.max_items - 1
                res = await ux_enter_number("Start Idx (0-%d):" % max_v, max_value=max_v,
                                            can_cancel=True)
                if res is None: continue
                start = res
            else:
                # nothing changed - do not recalc msg
                continue

            msg, addrs, change, end = self.make_ux_msg(start, self.n)


class TXOutExplorer(TXExplorer):
    def __init__(self, user_auth_action):
        super().__init__(10, user_auth_action, user_auth_action.psbt.num_outputs)

    def yield_item(self, offset, end, qr_items, change_idxs):
        # showing 10 outputs per UX page (just address/script + whether change)
        self.title = "%d-%d" % (offset, end - 1)
        for i, (idx, out) in enumerate(self.user_auth_action.psbt.output_iter(offset, end)):
            outp = self.user_auth_action.psbt.outputs[idx]
            item = "Output %d%s:\n\n" % (idx, " (change)" if outp.is_change else "")
            msg, addr_or_script = self.user_auth_action.render_output(out)
            item += msg
            qr_items.append(addr_or_script)
            if outp.is_change:
                change_idxs.append(i)
            item += "\n"
            yield idx, item


class TXInpExplorer(TXExplorer):
    def __init__(self, user_auth_action):
        super().__init__(1, user_auth_action, user_auth_action.psbt.num_inputs)
        self.qr_msgs = ["TXID", "UTXO ADDR"]

    def yield_item(self, offset, end, qr_items, change_idxs):
        # showing just one input per UX page
        i, (idx, txin) = next(enumerate(self.user_auth_action.psbt.input_iter(offset, offset+1)))
        self.title = "Input %d" % idx
        inp = self.user_auth_action.psbt.inputs[idx]

        txid = b2a_hex(ser_uint256(txin.prevout.hash)).decode()
        qr_items.append(txid)
        item = "%s:%d\n\n" % (txid, txin.prevout.n)

        has_utxo = inp.has_utxo()
        if has_utxo:
            utxo = inp.get_utxo(txin.prevout.n)
            spk = b2a_hex(utxo.scriptPubKey).decode()
            try:
                addr = self.chain.render_address(utxo.scriptPubKey)
            except:
                # some script we do not understand
                addr = None

            val, unit = self.chain.render_value(utxo.nValue)
            item += "=== UTXO ===\n\n%s %s\n\n%s\n\n" % (val, unit, spk)
            if addr:
                item += show_single_address(addr) + "\n\n"
                item += "Address Format: %s\n\n" % chains.addr_fmt_str(inp.addr_fmt)
                qr_items.append(addr)

        if self.user_auth_action.psbt.txn_version >= 2:
            has_rtl = inp.has_relative_timelock(txin)
            if has_rtl:
                if has_rtl[0]:
                    val = seconds2human_readable(has_rtl[1])
                    msg = "time-based timelock of:\n %s" % val
                else:
                    msg = "block height timelock of %d blocks" % (has_rtl[1])

                item += "Input has relative %s\n\n" % msg


        psbt_item = ""
        if inp.required_key:
            our = [inp.required_key] if isinstance(inp.required_key, bytes) else inp.required_key
            psbt_item += "Our key%s:\n\n" % ("s" if len(our) > 1 else "")
            for k in our:
                pth = inp.subpaths[k]
                psbt_item += "%s:\n%s\n\n" % (keypath_to_str(pth, prefix="%s/" % xfp2str(pth[0])),
                                         b2a_hex(k).decode())

        M = None
        if inp.is_multisig:
            ks_coord = inp.witness_script or inp.redeem_script
            if ks_coord:
                ks = self.user_auth_action.psbt.get(ks_coord)

                from multisig import disassemble_multisig_mn
                try:
                    M, N = disassemble_multisig_mn(ks)
                    psbt_item += "Multisig: %dof%d\n\n" % (M, N)
                except: pass

        if inp.part_sigs:
            # do not show XFPs in case input is fully signed --> elif
            # only part_sig should be available, as we haven't signed yet so added_sigs empty
            done = []
            for pk, pth in inp.subpaths.items():
                if pk in inp.part_sigs:
                    done.append(xfp2str(pth[0]))

            if inp.fully_signed or (M and (len(done) >= M)):
                psbt_item += "Input fully signed.\n\n"
            else:
                psbt_item += "Already signed:\n"
                for xfp in done:
                    psbt_item += "  %s\n" % xfp
                psbt_item += "\n"

        if inp.sighash and (inp.sighash != SIGHASH_ALL):
            # only show sighash value to the user if it is non-standard
            psbt_item += "sighash: %s\n\n" % {
                1: "ALL", 2: "NONE", 3: "SINGLE",
                1 | 0x80: "ALL|ANYONECANPAY",
                2 | 0x80: "NONE|ANYONECANPAY",
                3 | 0x80: "SINGLE|ANYONECANPAY",
            }[inp.sighash]

        if psbt_item:
            psbt_item = "=== PSBT ===\n\n" + psbt_item
            item += psbt_item

        yield idx, item

# EOF
