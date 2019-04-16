# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, tcc, ux, chains, sys, gc
from public_constants import MAX_TXN_LEN, MSG_SIGNING_MAX_LENGTH, SUPPORTED_ADDR_FORMATS
from public_constants import AFC_SCRIPT
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, problem_file_line
from usb import CCBusyError
from utils import HexWriter
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput

global active_request
active_request = None

MSG_SIG_TEMPLATE = '''\
Ok to sign this?
      --=--
{msg}
      --=--

Using the key associated with address:

{subpath}

= {addr}


Press Y if OK, otherwise X to cancel.'''

# Where in SPI flash the two transactions are (in and out)
TXN_INPUT_OFFSET = 0
TXN_OUTPUT_OFFSET = MAX_TXN_LEN

class UserAuthorizedAction:
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

    @classmethod
    def cleanup(cls):
        # user has collected the results/errors and no need for objs
        global active_request
        active_request = None
        gc.collect()

    @classmethod
    def check_busy(cls, allowed_cls=None):
        # see if we're busy. don't interrupt that... unless it's of allowed_cls
        # - also handle cleanup of stale actions
        global active_request

        if not active_request:
            return
        if allowed_cls and isinstance(active_request, allowed_cls):
            return

        # check if UX actally was cleared, and we're not really doing that anymore; recover
        # - happens if USB caller never comes back for their final results
        from ux import the_ux
        top_ux = the_ux.top_of_stack()
        if not isinstance(top_ux, cls) and active_request.ux_done:
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

        return await ux_show_story(msg, title)

class ApproveMessageSign(UserAuthorizedAction):
    def __init__(self, text, subpath, addr_fmt):
        super().__init__()
        self.text = text
        self.subpath = subpath

        from main import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            self.address = sv.chain.address(node, addr_fmt)

    async def interact(self):
        # Prompt user w/ details and get approval
        from main import dis

        ch = await ux_show_story(MSG_SIG_TEMPLATE.format(msg=self.text, 
                            addr=self.address, subpath=self.subpath))

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

            dis.progress_bar_show(1.0)

        self.done()

    @staticmethod
    def validate(text):
        # check for some UX/UI traps in the message itself.

        # Messages must be short and ascii only. Our charset is limited
        MSG_MAX_LENGTH = MSG_SIGNING_MAX_LENGTH
        MSG_CHARSET = range(32, 127)
        MSG_MAX_SPACES = 4      # impt. compared to -=- positioning

        assert 1 <= len(text) <= MSG_MAX_LENGTH, "too long"
        run = 0
        for ch in text:
            assert ord(ch) in MSG_CHARSET, "bad char: 0x%02x=%c" % (ch, ch)

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
        subpath = str(subpath, 'ascii')
    except UnicodeError:
        raise AssertionError('must be ascii')

    try:
        assert addr_fmt in SUPPORTED_ADDR_FORMATS
        assert not (addr_fmt & AFC_SCRIPT)
    except:
        raise AssertionError('Unknown/unsupported addr format')

    # Do some verification before we even show to the local user
    ApproveMessageSign.validate(text)

    global active_request
    UserAuthorizedAction.check_busy()
    active_request = ApproveMessageSign(text, subpath, addr_fmt)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)



class ApproveTransaction(UserAuthorizedAction):
    def __init__(self, psbt_len, do_finalize=False, approved_cb=None):
        super().__init__()
        self.psbt_len = psbt_len
        self.do_finalize = do_finalize
        self.psbt = None
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
        from main import dis

        # step 1: parse PSBT from sflash into in-memory objects.
        dis.fullscreen("Validating...")

        try:
            with SFFile(TXN_INPUT_OFFSET, length=self.psbt_len) as fd:
                self.psbt = psbtObject.read_psbt(fd)
        except BaseException as exc:
            sys.print_exception(exc)
            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex."
            else:
                msg = "PSBT parse failed"

            return await self.failure(msg)

        # Do some analysis/ validation
        try:
            self.psbt.validate()
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
            sys.print_exception(exc)
            del self.psbt
            gc.collect()

            if isinstance(exc, MemoryError):
                msg = "Transaction is too complex."
            else:
                msg = "Invalid PSBT: " + (str(exc) or problem_file_line(exc))

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
        msg = ''
        try:
            outs_msg = self.output_summary_text()
            gc.collect()

            # mention warning at top
            wl= len(self.psbt.warnings)
            if wl == 1:
                msg += '(1 warning below)\n\n'
            elif wl >= 2:
                msg += '(%d warnings below)\n\n' % wl

            msg += outs_msg

            fee = self.psbt.calculate_fee()
            if fee is not None:
                msg += "\nNetwork fee:\n%s %s\n" % self.chain.render_value(fee)

            if self.psbt.warnings:
                warn = '\n---WARNING---\n\n'

                for label,m in self.psbt.warnings:
                    warn += '- %s: %s\n\n' % (label, m)

                print(warn)
                msg += warn

            msg += "\nPress OK to approve and sign transaction. X to abort."

            ch = await ux_show_story(msg, title="OK TO SEND?")
        except MemoryError as exc:
            # recovery? maybe.
            del self.psbt
            del msg
            del outs_msg
            gc.collect()

            msg = "Transaction is too complex."
            return await self.failure(msg, exc)

        if ch != 'y':
            # they don't want to!
            self.refused = True
            await ux_dramatic_pause("Refused.", 1)

            del self.psbt

            self.done()
            return

        # do the actual signing.
        try:
            self.psbt.sign_it()
        except FraudulentChangeOutput as exc:
            print('FraudulentChangeOutput: ' + exc.args[0])
            return await self.failure(exc.args[0], title='Change Fraud')
        except MemoryError as exc:
            msg = "Transaction is too complex."
            return await self.failure(msg, exc)
        except BaseException as exc:
            sys.print_exception(exc)
            return await self.failure("Signing failed late: %s" % exc)

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
            self.failed = "PSBT output failed"
            print("PSBT output failure: ")
            sys.print_exception(exc)
            self.done()
            return

    def output_summary_text(self):
        # Produce text report of where their cash is going. This is what
        # they use to decide if correct transaction is being signed.
        MAX_VISIBLE_OUTPUTS = const(10)
        msg = ''

        if self.psbt.num_outputs <= MAX_VISIBLE_OUTPUTS+1:
            # simple, common case: don't sort outputs, and do show all of them
            for idx, tx_out in self.psbt.output_iter():
                outp = self.psbt.outputs[idx]
                if outp and outp.is_change:
                    continue
                if msg:
                    msg += '\n'
                msg += self.render_output(tx_out)

            return msg

        # Too many to show them all, so
        # find largest N outputs, and track total amount
        largest = []
        for idx, tx_out in self.psbt.output_iter():
            outp = self.psbt.outputs[idx]
            if outp and outp.is_change:
                continue

            largest.append(tx_out)
            if len(largest) < MAX_VISIBLE_OUTPUTS:
                continue

            largest.sort(key=lambda x: -x.nValue)
            if len(largest) > MAX_VISIBLE_OUTPUTS:
                largest.pop(-1)

        for idx, tx_out in enumerate(largest):
            if idx:
                msg += '\n'
            msg += self.render_output(tx_out)

        left = self.psbt.num_outputs - len(largest)
        if left > 0:
            # typically, left >= 2, but with change outputs, not so clear.
            msg += '\n.. plus %d more smaller outputs, not shown here, which total: ' % left

            mtot = self.psbt.total_value_out - sum(t.nValue for t in largest)
            msg += ' '.join(self.chain.render_value(mtot))

        return msg


def sign_transaction(psbt_len, do_finalize=False):
    # transaction (binary) loaded into sflash already, checksum checked
    global active_request
    UserAuthorizedAction.check_busy(ApproveTransaction)
    active_request = ApproveTransaction(psbt_len, do_finalize)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)
    
def sign_psbt_file(filename):
    # sign a PSBT file found on a MicroSD card
    from files import CardSlot, CardMissingError
    from main import dis
    from sram2 import tmp_buf
    global active_request

    UserAuthorizedAction.cleanup()

    #print("sign: %s" % filename)

    # copy file into our spiflash
    # - can't work in-place on the card because we want to support writing out to different card
    with CardSlot() as card:
        with open(filename, 'rb') as fd:
            dis.fullscreen('Reading...')

            # see how long it is
            psbt_len = fd.seek(0, 2)
            fd.seek(0)

            total = 0
            with SFFile(TXN_INPUT_OFFSET, max_size=psbt_len) as out:
                # blank flash
                await out.erase()

                while 1:
                    n = fd.readinto(tmp_buf)
                    if not n: break

                    if n == len(tmp_buf):
                        out.write(tmp_buf)
                    else:
                        out.write(memoryview(tmp_buf)[0:n])

                    total += n
                    dis.progress_bar_show(total / psbt_len)

            assert total == psbt_len, repr([total, psbt_len])

    async def done(psbt):
        orig_path, basename = filename.rsplit('/', 1)
        orig_path += '/'
        base = basename.rsplit('.', 1)[0]
        out2_fn = None
        out_fn = None

        while 1:
            # try to put back into same spot, but also do top-of-card
            for path in [orig_path, None]:
                try:
                    with CardSlot() as card:
                        out_full, out_fn = card.pick_filename(base+'-signed.psbt', path)
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
                        print("out: %s" % out_full)
                        with open(out_full, 'wb') as fd:
                            # save as updated PSBT
                            psbt.serialize(fd)

                        if psbt.is_complete():
                            # write out as hex too, if it's final
                            out2_full, out2_fn = card.pick_filename(base+'-final.txn', out_path)
                            if out2_full:
                                print("out2: %s" % out2_full)
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

    active_request = ApproveTransaction(psbt_len, approved_cb=done)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)

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
    global active_request

    UserAuthorizedAction.cleanup()

    active_request = RemoteBackup()

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)


class NewPassphrase(UserAuthorizedAction):
    def __init__(self, pw):
        super().__init__()
        self._pw = pw
        # self.result ... will be (len, sha256) of the resulting file at zero

    async def interact(self):
        # prompt them

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
                from main import settings

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


def start_bip39_passphrase(pw):
    # tell the local user the secret words, and then save to SPI flash
    # USB caller has to come back and download encrypted contents.
    global active_request

    UserAuthorizedAction.cleanup()

    active_request = NewPassphrase(pw)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)

    
SHOW_ADDR_TEMPLATE = '''\
{addr}

= {subpath}

Compare this payment address to the one shown on your other, less-trusted, software.'''

class ShowAddress(UserAuthorizedAction):
    def __init__(self, subpath, addr_fmt):
        super().__init__()
        self.subpath = subpath

        from main import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            self.address = sv.chain.address(node, addr_fmt)

    async def interact(self):
        # Just show the address... no real confirmation needed.
        ch = await ux_show_story(SHOW_ADDR_TEMPLATE.format(
                            addr=self.address, subpath=self.subpath), title='Address:')

        self.done()
        UserAuthorizedAction.cleanup()      # because no results to store

def start_show_address(subpath, addr_format):
    # Show address to user, also returns it.

    try:
        subpath = str(subpath, 'ascii')
    except UnicodeError:
        raise AssertionError('must be ascii')

    try:
        assert addr_format in SUPPORTED_ADDR_FORMATS
    except:
        raise AssertionError('Unknown/unsupported addr format')

    global active_request
    UserAuthorizedAction.check_busy(ShowAddress)
    active_request = ShowAddress(subpath, addr_format)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)

    # provide the value back to attached desktop too!
    return active_request.address

# EOF
