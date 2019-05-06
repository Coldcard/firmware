# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Operations that require user authorization, like our core features: signing messages
# and signing bitcoin transactions.
#
import stash, ure, tcc, ux, chains, sys, gc, uio
from public_constants import MAX_TXN_LEN, MSG_SIGNING_MAX_LENGTH, SUPPORTED_ADDR_FORMATS
from public_constants import AFC_SCRIPT
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, problem_file_line
from usb import CCBusyError
from utils import HexWriter, xfp2str
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

            if self.psbt.warnings:
                msg.write('\n---WARNING---\n\n')

                for label,m in self.psbt.warnings:
                    msg.write('- %s: %s\n\n' % (label, m))

            msg.write("\nPress OK to approve and sign transaction. X to abort.")

            ch = await ux_show_story(msg, title="OK TO SEND?")
        except MemoryError as exc:
            # recovery? maybe.
            try:
                del self.psbt
                del msg
            except: pass        # might be NameError since we don't know how far we got
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
            gc.collect()
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

    def output_summary_text(self, msg):
        # Produce text report of where their cash is going. This is what
        # they use to decide if correct transaction is being signed.
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
                    msg.write('\n')
                    first = False

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

    

class ShowAddress(UserAuthorizedAction):
    def __init__(self, addr_fmt, subpath, ms, subpaths, witdeem_script):
        super().__init__()
        self.subpath = subpath
        self.witdeem_script = witdeem_script
        self.ms = ms
        self.unknown_scr = None

        from main import dis
        dis.fullscreen('Wait...')

        if addr_fmt & AFC_SCRIPT:
            actual_scr, self.subpath = ms.generate_script(subpaths, witdeem_script)
            self.address = ms.chain.p2sh_address(addr_fmt, actual_scr)
        else:
            with stash.SensitiveValues() as sv:
                node = sv.derive_path(subpath)
                self.address = sv.chain.address(node, addr_fmt)

    async def interact(self):
        # Just show the address... no real confirmation needed.
        title = 'Address:'
        if self.ms:
            msg = '(%d of %d needed)\n' % (self.ms.M, self.ms.N)
            title = 'Multisig:'

            msg = '''\
{addr}

Wallet Name:

  {name}

Policy: {M} of {N}

Paths:

{sp}

Compare this payment address to the one shown on your other, less-trusted, software.'''\
            .format(addr=self.address, name=self.ms.name,
                        M=self.ms.M, N=self.ms.N, sp='\n'.join(self.subpath))

        else:
            msg = '''\
{addr}

= {sp}

Compare this payment address to the one shown on your other, less-trusted, software.\
''' .format(addr=self.address, sp=self.subpath)

        ch = await ux_show_story(msg, title=title)

        self.done()
        UserAuthorizedAction.cleanup()      # because no results to store

def start_show_address(addr_format, subpath=None, subpaths=None, witdeem_script=None, m_of_n=None):
    # Show address to user, also returns it.

    try:
        assert addr_format in SUPPORTED_ADDR_FORMATS
    except:
        raise AssertionError('Unknown/unsupported addr format')

    if (addr_format & AFC_SCRIPT):
        import ustruct
        from multisig import MultisigWallet
        
        # script is optional/not needed.
        #if not witdeem_script
        #    raise AssertionError('Redeem/witness script is required')

        # Search for matching multisig wallet that we must already know about
        xfps = {}
        for p in subpaths:
            k, *v = ustruct.unpack_from('>%dI' % (len(p)//4), p) 
            xfps[k] = v

        del subpaths
        M, N = m_of_n

        assert len(xfps) == N, 'dup xfp'

        idx = MultisigWallet.find_match(M, N, xfps.keys())
        if idx < 0:
            raise AssertionError('Multisig wallet with those fingerprints not found')

        ms = MultisigWallet.get_by_idx(idx)
        assert ms, "load wallet fail"

    else:
        # text path expected
        try:
            subpath = str(subpath, 'ascii')
            ms = None
            xfps = None
        except UnicodeError:
            raise AssertionError('must be ascii')

    global active_request
    UserAuthorizedAction.check_busy(ShowAddress)
    active_request = ShowAddress(addr_format, subpath, ms, xfps, witdeem_script)

    # kill any menu stack, and put our thing at the top
    abort_and_goto(active_request)

    # provide the value back to attached desktop too!
    return active_request.address


class NewEnrollRequest(UserAuthorizedAction):
    def __init__(self, ms):
        super().__init__()
        self.wallet = ms

        # self.result ... will be re-serialized xpub

    async def interact(self):
        # prompt them
        ms = self.wallet

        if ms.M == ms.N:
            exp = 'All %d co-signers must approve spends.' % ms.N
        elif ms.M == 1:
            exp = 'Any signature from %d co-signers will approve spends.' % ms.N
        else:
            exp = '{M} signatures from {N} possible co-signers, will be required to approve spends.'.format(M=ms.M, N=ms.N)

        story = '''Create new multisig wallet?

Wallet Name:
  {name}

Policy: {M} of {N}

{exp}

Press 2 to see extended public keys, \
OK to approve, X to cancel.'''.format(M=ms.M, N=ms.N, name=ms.name, exp=exp)

        try:
            chain = chains.current_chain()
            while 1:
                ch = await ux_show_story(story, escape='2')

                if ch == '2':
                    # Show the xpubs; might be 2k or more rendered.
                    msg = uio.StringIO()

                    for idx, xfp in enumerate(ms.xpubs):
                        if idx:
                            msg.write('\n\n')

                        msg.write('#%d: %s =\n' % (idx+1, xfp2str(xfp)))
                        msg.write(ms.xpubs[xfp])

                    await ux_show_story(msg, title='%d of %d' % (ms.M, ms.N))

                    continue

                if ch == 'y':
                    # save to nvram
                    ms.commit()

                    await ux_dramatic_pause("Saved.", 2)
                else:
                    # they don't want to!
                    self.refused = True
                    await ux_dramatic_pause("Refused.", 2)

                break

        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            UserAuthorizedAction.cleanup()      # because no results to store
            self.done()


def maybe_enroll_xpub(sf_len=None, config=None, name=None):
    # offer to accept an xpub for cosigning over USB. Allow reject.
    global active_request
    from multisig import MultisigWallet

    UserAuthorizedAction.cleanup()

    if sf_len:
        with SFFile(TXN_INPUT_OFFSET, length=sf_len) as fd:
            config = fd.read(sf_len).decode()

    # this call will raise on parsing errors, so let them rise up
    # and be shown on screen/over usb
    ms = MultisigWallet.from_file(config, name=name)

    active_request = NewEnrollRequest(ms)

    # kill any menu stack, and put our thing at the top
    if sf_len:
        abort_and_goto(active_request)

# EOF
