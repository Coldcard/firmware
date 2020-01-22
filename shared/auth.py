# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, tcc, ux, chains, sys, gc, uio, version
from public_constants import MAX_TXN_LEN, MSG_SIGNING_MAX_LENGTH, SUPPORTED_ADDR_FORMATS
from public_constants import AFC_SCRIPT, AF_CLASSIC
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys
from usb import CCBusyError
from utils import HexWriter, xfp2str, problem_file_line, cleanup_deriv_path
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from exceptions import HSMDenied

# Where in SPI flash the two transactions are (in and out)
TXN_INPUT_OFFSET = 0
TXN_OUTPUT_OFFSET = MAX_TXN_LEN

class UserAuthorizedAction:
    active_request = None

    def __init__(self):
        self.refused = False
        self.failed = None
        self.result = None
        self.ux_done = False

    def done(self):
        # drop them back into menu system, but at top.
        self.ux_done = True
        from actions import goto_top_menu
        m = goto_top_menu()
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

        if exc:
            print("%s:" % msg)
            sys.print_exception(exc)
            msg += "\n\n(%s)" % problem_file_line(exc)

        
        from main import hsm_active, dis

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

Press Y if OK, otherwise X to cancel.'''

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

class ApproveMessageSign(UserAuthorizedAction):
    def __init__(self, text, subpath, addr_fmt, approved_cb=None):
        super().__init__()
        self.text = text
        self.subpath = subpath
        self.approved_cb = approved_cb

        from main import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            self.address = sv.chain.address(node, addr_fmt)

        dis.progress_bar_show(1)

    async def interact(self):
        # Prompt user w/ details and get approval
        from main import dis, hsm_active

        if hsm_active:
            ch = await hsm_active.approve_msg_sign(self.text, self.address, self.subpath)
        else:
            story = MSG_SIG_TEMPLATE.format(msg=self.text, addr=self.address, subpath=self.subpath)
            ch = await ux_show_story(story)

        if ch != 'y':
            # they don't want to!
            self.refused = True
        else:
            dis.fullscreen('Signing...', percent=.25)

            # do the signature itself!
            with stash.SensitiveValues() as sv:
                dis.progress_bar_show(.50)

                node = sv.derive_path(self.subpath)
                pk = node.private_key()
                sv.register(pk)

                digest = sv.chain.hash_message(self.text.encode())

                dis.progress_bar_show(.75)
                self.result = tcc.secp256k1.sign(pk, digest)

            dis.progress_bar_show(1)

            if self.approved_cb:
                # for micro sd case
                await self.approved_cb(self.result, self.address)

        if self.approved_cb:
            # don't kill menu depth for file case
            UserAuthorizedAction.cleanup()
            self.pop_menu()
        else:
            self.done()

    @staticmethod
    def validate(text):
        # check for some UX/UI traps in the message itself.

        # Messages must be short and ascii only. Our charset is limited
        MSG_CHARSET = range(32, 127)
        MSG_MAX_SPACES = 4      # impt. compared to -=- positioning

        assert len(text) >= 2, "too short"
        assert len(text) <= MSG_SIGNING_MAX_LENGTH, "too long"
        run = 0
        for ch in text:
            assert ord(ch) in MSG_CHARSET, "bad char: 0x%02x" % ord(ch)

            if ch == ' ':
                run += 1
                assert run < MSG_MAX_SPACES, 'too many spaces together'
            else:
                run = 0

        # other confusion w/ whitepace
        assert text[0] != ' ', 'leading space(s)'
        assert text[-1] != ' ', 'trailing space(s)'

        # looks ok
        return
    

def sign_msg(text, subpath, addr_fmt):
    # Convert to strings
    try:
        text = str(text,'ascii')
    except UnicodeError:
        raise AssertionError('must be ascii')

    subpath = cleanup_deriv_path(subpath)

    try:
        assert addr_fmt in SUPPORTED_ADDR_FORMATS
        assert not (addr_fmt & AFC_SCRIPT)
    except:
        raise AssertionError('Unknown/unsupported addr format')

    # Do some verification before we even show to the local user
    ApproveMessageSign.validate(text)

    UserAuthorizedAction.check_busy()
    UserAuthorizedAction.active_request = ApproveMessageSign(text, subpath, addr_fmt)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

def sign_txt_file(filename):
    # sign a one-line text file found on a MicroSD card
    # - not yet clear how to do address types other than 'classic'
    from files import CardSlot, CardMissingError
    from sram2 import tmp_buf

    UserAuthorizedAction.cleanup()

    # copy message into memory
    with CardSlot() as card:
        with open(filename, 'rt') as fd:
            text = fd.readline().strip()
            subpath = fd.readline().strip()

    if subpath:
        try:
            assert subpath[0:1] == 'm'
            subpath = cleanup_deriv_path(subpath)
        except:
            await ux_show_story("Second line of file, if included, must specify a subkey path, like: m/44'/0/0")
            return
            
    else:
        # default: top of wallet.
        subpath = 'm'

    try:
        try:
            text = str(text, 'ascii')
        except UnicodeError:
            raise AssertionError('non-ascii characters')

        ApproveMessageSign.validate(text)
    except AssertionError as exc:
        await ux_show_story("Problem: %s\n\nMessage to be signed must be a single line of ASCII text." % exc)
        return

    def done(signature, address):
        # complete. write out result
        from ubinascii import b2a_base64
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
                    with CardSlot() as card:
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
                        with open(out_full, 'wt') as fd:
                            # save in full RFC style
                            fd.write(RFC_SIGNATURE_TEMPLATE.format(addr=address, msg=text,
                                                blockchain='BITCOIN', sig=sig))

                    # success and done!
                    break

                except OSError as exc:
                    prob = 'Failed to write!\n\n%s\n\n' % exc
                    sys.print_exception(exc)
                    # fall thru to try again

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
    UserAuthorizedAction.active_request = ApproveMessageSign(text, subpath, AF_CLASSIC, approved_cb=done)

    # do not kill the menu stack!
    from ux import the_ux
    the_ux.push(UserAuthorizedAction.active_request)


class ApproveTransaction(UserAuthorizedAction):
    def __init__(self, psbt_len, do_finalize=False, approved_cb=None, psbt_sha=None):
        super().__init__()
        self.psbt_len = psbt_len
        self.do_finalize = do_finalize
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
        dest = self.chain.render_address(o.scriptPubKey)

        return '%s\n - to address -\n%s\n' % (val, dest)


    async def interact(self):
        # Prompt user w/ details and get approval
        from main import dis, hsm_active

        # step 1: parse PSBT from sflash into in-memory objects.
        dis.fullscreen("Validating...")

        try:
            with SFFile(TXN_INPUT_OFFSET, length=self.psbt_len) as fd:
                self.psbt = psbtObject.read_psbt(fd)
        except BaseException as exc:
            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex"
                exc = None
            else:
                msg = "PSBT parse failed"

            return await self.failure(msg, exc)

        # Do some analysis/ validation
        try:
            await self.psbt.validate()      # might do UX: accept multisig import
            self.psbt.consider_inputs()
            self.psbt.consider_keys()
            self.psbt.consider_outputs()
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

            self.output_summary_text(msg)
            gc.collect()

            fee = self.psbt.calculate_fee()
            if fee is not None:
                msg.write("\nNetwork fee:\n%s %s\n" % self.chain.render_value(fee))

            # NEW: show where all the change outputs are going
            self.output_change_text(msg)
            gc.collect()

            if self.psbt.warnings:
                msg.write('\n---WARNING---\n\n')

                for label, m in self.psbt.warnings:
                    msg.write('- %s: %s\n\n' % (label, m))

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
            gc.collect()
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

        try:
            # re-serialize the PSBT back out
            with SFFile(TXN_OUTPUT_OFFSET, max_size=MAX_TXN_LEN, message="Saving...") as fd:
                await fd.erase()

                if self.do_finalize:
                    self.psbt.finalize(fd)
                else:
                    self.psbt.serialize(fd)

                self.result = (fd.tell(), fd.checksum.digest())

            self.done()

        except BaseException as exc:
            return await self.failure("PSBT output failed", exc)

    def output_change_text(self, msg):
        # Produce text report of what the "change" outputs are (based on our opinion).
        # - we don't really expect all users to verify these outputs, but just in case.
        # - show the total amount, and list addresses

        total = 0
        addrs = []
        for idx, tx_out in self.psbt.output_iter():
            outp = self.psbt.outputs[idx]
            if not outp.is_change:
                continue
            total += tx_out.nValue
            addrs.append(self.chain.render_address(tx_out.scriptPubKey))

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
            msg.write('.. plus %d more smaller output(s), not shown here, which total: ' % left)

            # calculate left over value
            mtot = self.psbt.total_value_out - sum(v for v,t in largest)
            mtot -= sum(o.nValue for i, o in self.psbt.output_iter() 
                                        if self.psbt.outputs[i].is_change)

            msg.write('%s %s\n' % self.chain.render_value(mtot))


def sign_transaction(psbt_len, do_finalize=False, psbt_sha=None):
    # transaction (binary) loaded into sflash already, checksum checked
    UserAuthorizedAction.check_busy(ApproveTransaction)
    UserAuthorizedAction.active_request = ApproveTransaction(psbt_len, do_finalize,
                                                                        psbt_sha=psbt_sha)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

    
def sign_psbt_file(filename):
    # sign a PSBT file found on a MicroSD card
    from files import CardSlot, CardMissingError
    from main import dis
    from sram2 import tmp_buf
    from utils import HexStreamer, Base64Streamer, HexWriter, Base64Writer

    UserAuthorizedAction.cleanup()

    #print("sign: %s" % filename)


    # copy file into our spiflash
    # - can't work in-place on the card because we want to support writing out to different card
    # - accepts hex or base64 encoding, but binary prefered
    with CardSlot() as card:
        with open(filename, 'rb') as fd:
            dis.fullscreen('Reading...')

            # see how long it is
            psbt_len = fd.seek(0, 2)
            fd.seek(0)

            # determine encoding used, altho we prefer binary
            taste = fd.read(10)
            fd.seek(0)

            if taste[0:5] == b'psbt\xff':
                decoder = None
                output_encoder = lambda x: x
            elif taste[0:10] == b'70736274ff':
                decoder = HexStreamer()
                output_encoder = HexWriter
                psbt_len //= 2
            elif taste[0:6] == b'cHNidP':
                decoder = Base64Streamer()
                output_encoder = Base64Writer
                psbt_len = (psbt_len * 3 // 4) + 10

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
                    with CardSlot() as card:
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
                        with output_encoder(open(out_full, 'wb')) as fd:
                            # save as updated PSBT
                            psbt.serialize(fd)

                        if is_comp:
                            # write out as hex too, if it's final
                            out2_full, out2_fn = card.pick_filename(base+'-final.txn', out_path)
                            if out2_full:
                                with HexWriter(open(out2_full, 'wt')) as fd:
                                    # save transaction, in hex
                                    psbt.finalize(fd)

                    # success and done!
                    break

                except OSError as exc:
                    prob = 'Failed to write!\n\n%s\n\n' % exc
                    sys.print_exception(exc)
                    # fall thru to try again

            # prompt them to input another card?
            ch = await ux_show_story(prob+"Please insert an SDCard to receive signed transaction, "
                                        "and press OK.", title="Need Card")
            if ch == 'x':
                await ux_aborted()
                return

        # done.
        msg = "Updated PSBT is:\n\n%s" % out_fn
        if out2_fn:
            msg += '\n\nFinalized transaction (ready for broadcast):\n\n%s' % out2_fn

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
        from main import settings

        showit = False
        while 1:
            if showit:
                ch = await ux_show_story('''Given:\n\n%s\n\nShould we switch to that wallet now?

OK to continue, X to cancel.''' % self._pw, title="Passphrase")
            else:
                ch = await ux_show_story('''BIP39 passphrase (%d chars long) has been provided over USB connection. Should we switch to that wallet now?

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
                err = set_bip39_passphrase(self._pw)

                if err:
                    await self.failure(err)
                else:
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
    # tell the local user the secret words, and then save to SPI flash
    # USB caller has to come back and download encrypted contents.

    UserAuthorizedAction.cleanup()
    UserAuthorizedAction.active_request = NewPassphrase(pw)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)


class ShowAddressBase(UserAuthorizedAction):
    title = 'Address:'

    def __init__(self, *args):
        super().__init__()

        from main import dis
        dis.fullscreen('Wait...')

        # this must set self.address and do other slow setup
        self.setup(*args)

    async def interact(self):
        # Just show the address... no real confirmation needed.
        from main import hsm_active, dis

        if not hsm_active:
            msg = self.get_msg()
            msg += '\n\nCompare this payment address to the one shown on your other, less-trusted, software.'
            ch = await ux_show_story(msg, title=self.title)
        else:
            # finish the Wait...
            dis.progress_bar(1)     

        self.done()
        UserAuthorizedAction.cleanup()      # because no results to store

    
class ShowPKHAddress(ShowAddressBase):

    def setup(self, addr_fmt, subpath):
        self.subpath = subpath

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            self.address = sv.chain.address(node, addr_fmt)

    def get_msg(self):
        return '''{addr}\n\n= {sp}''' .format(addr=self.address, sp=self.subpath)


class ShowP2SHAddress(ShowAddressBase):

    def setup(self, ms, addr_fmt, xfp_paths, witdeem_script):

        self.witdeem_script = witdeem_script
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
    xfps = [i[0] for i in xfp_paths]

    idx = MultisigWallet.find_match(M, N, xfps)
    assert idx >= 0, 'Multisig wallet with those fingerprints not found'

    ms = MultisigWallet.get_by_idx(idx)
    assert ms
    assert ms.M == M
    assert ms.N == N


    UserAuthorizedAction.check_busy(ShowAddressBase)
    UserAuthorizedAction.active_request = ShowP2SHAddress(ms, addr_format, xfp_paths, witdeem_script)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

    # provide the value back to attached desktop
    return UserAuthorizedAction.active_request.address

def start_show_address(addr_format, subpath):
    try:
        assert addr_format in SUPPORTED_ADDR_FORMATS
        assert not (addr_format & AFC_SCRIPT)
    except:
        raise AssertionError('Unknown/unsupported addr format')

    # require a path to a key
    subpath = cleanup_deriv_path(subpath)

    from main import hsm_active
    if hsm_active and not hsm_active.approve_address_share(subpath):
        raise HSMDenied

    UserAuthorizedAction.check_busy(ShowAddressBase)
    UserAuthorizedAction.active_request = ShowPKHAddress(addr_format, subpath)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(UserAuthorizedAction.active_request)

    # provide the value back to attached desktop
    return UserAuthorizedAction.active_request.address


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

# EOF
