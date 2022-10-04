# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# backups.py - Save and restore backup data.
#
import compat7z, stash, ckcc, chains, gc, sys, bip39, uos, ngu
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from utils import imported, xfp2str
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
import version, ujson
from uio import StringIO
import seed
from glob import settings
from pincodes import pa, AE_SECRET_LEN

# we make passwords with this number of words
num_pw_words = const(12)

# max size we expect for a backup data file (encrypted or cleartext)
MAX_BACKUP_FILE_SIZE = const(10000)     # bytes

def render_backup_contents():
    # simple text format: 
    #   key = value
    # or #comments
    # but value is JSON

    rv = StringIO()

    def COMMENT(val=None):
        if val:
            rv.write('\n# %s\n' % val)
        else:
            rv.write('\n')

    def ADD(key, val):
        rv.write('%s = %s\n' % (key, ujson.dumps(val)))

    rv.write('# Coldcard backup file! DO NOT CHANGE.\n')

    chain = chains.current_chain()

    COMMENT('Private key details: ' + chain.name)

    with stash.SensitiveValues(bypass_pw=True) as sv:
        if sv.deltamode:
            # die rather than give up our secrets
            import callgate
            callgate.fast_wipe()

        if sv.mode == 'words':
            ADD('mnemonic', bip39.b2a_words(sv.raw))

        if sv.mode == 'master':
            ADD('bip32_master_key', b2a_hex(sv.raw))

        ADD('chain', chain.ctype)
        ADD('xprv', chain.serialize_private(sv.node))
        ADD('xpub', chain.serialize_public(sv.node))

        # BTW: everything is really a duplicate of this value
        ADD('raw_secret', b2a_hex(sv.secret).rstrip(b'0'))

        if version.has_608:
            # save the so-called long-secret
            ADD('long_secret', b2a_hex(pa.ls_fetch()))

        # Duress wallets (somewhat optional, since derived)
        if version.mk_num <= 3:
            if pa.has_duress_pin():
                COMMENT('Duress Wallet (informational)')
                dpk, p = sv.duress_root()
                COMMENT('path = %s' % p)
                ADD('duress_xprv', chain.serialize_private(dpk))
                ADD('duress_xpub', chain.serialize_public(dpk))
        else:
            from trick_pins import tp
            for label, path, pairs in tp.backup_duress_wallets(sv):
                COMMENT()
                COMMENT(label + ' (informational)')
                COMMENT(path)
                for k,v in pairs:
                    ADD(k, v)
    
    COMMENT('Firmware version (informational)')
    date, vers, timestamp = version.get_mpy_version()[0:3]
    ADD('fw_date', date)
    ADD('fw_version', vers)
    ADD('fw_timestamp', timestamp)
    ADD('serial', version.serial_number())

    COMMENT('User preferences')

    # user preferences
    for k,v in settings.current.items():
        if k[0] == '_': continue        # debug stuff in simulator
        if k == 'xpub': continue        # redundant, and wrong if bip39pw
        if k == 'xfp': continue         # redundant, and wrong if bip39pw
        ADD('setting.' + k, v)

    if version.has_fatram:
        import hsm
        if hsm.hsm_policy_available():
            ADD('hsm_policy', hsm.capture_backup())

    rv.write('\n# EOF\n')

    return rv.getvalue()

def restore_from_dict_ll(vals):
    # Restore from a dict of values. Already JSON decoded.
    # Need a Reboot on success, return string on failure
    # - low-level version, factored out for better testing
    from glob import dis

    #print("Restoring from: %r" % vals)

    # step1: the private key
    # - prefer raw_secret over other values
    # - TODO: fail back to other values
    try:
        chain = chains.get_chain(vals.get('chain', 'BTC'))

        assert 'raw_secret' in vals
        raw = bytearray(AE_SECRET_LEN)
        rs = vals.pop('raw_secret')
        if len(rs) % 2:
            rs += '0'
        x = a2b_hex(rs)
        raw[0:len(x)] = x

        # check we can decode this right (might be different firmare)
        opmode, bits, node = stash.SecretStash.decode(raw)
        assert node

        # verify against xprv value (if we have it)
        if 'xprv' in vals:
            check_xprv = chain.serialize_private(node)
            assert check_xprv == vals['xprv'], 'xprv mismatch'

    except Exception as e:
        return ('Unable to decode raw_secret and '
                                'restore the seed value!\n\n\n'+str(e))

    ls = None
    if ('long_secret' in vals) and version.has_608:
        try:
            ls = a2b_hex(vals.pop('long_secret'))
        except Exception as exc:
            sys.print_exception(exc)
            # but keep going.

    dis.fullscreen("Saving...")
    dis.progress_bar_show(.25)

    # clear (in-memory) settings and change also nvram key
    # - also captures xfp, xpub at this point
    pa.change(new_secret=raw)

    # force the right chain
    pa.new_main_secret(raw, chain)         # updates xfp/xpub


    # NOTE: don't fail after this point... they can muddle thru w/ just right seed

    if ls is not None:
        try:
            pa.ls_change(ls)
        except Exception as exc:
            sys.print_exception(exc)
            # but keep going

    # restore settings from backup file

    for idx, k in enumerate(vals):
        dis.progress_bar_show(idx / len(vals))
        if not k.startswith('setting.'):
            continue

        if k == 'xfp' or k == 'xpub': continue

        if k == 'tp':
            # restore trick pins, which may involve many ops
            if version.mk_num >= 4:
                from trick_pins import tp
                try:
                    tp.restore_backup(vals[k])
                except Exception as exc:
                    sys.print_exception(exc)
            continue

        settings.set(k[8:], vals[k])

    # write out
    settings.save()

    if version.has_fatram and ('hsm_policy' in vals):
        import hsm
        hsm.restore_backup(vals['hsm_policy'])


async def restore_from_dict(vals):
    # Restore from a dict of values. Already JSON decoded (ie. dict object).
    # Need a Reboot on success, return string on failure

    prob = restore_from_dict_ll(vals)
    if prob: return prob

    await ux_show_story('Everything has been successfully restored. '
            'We must now reboot to install the '
            'updated settings and seed.', title='Success!')

    from machine import reset
    reset()


async def make_complete_backup(fname_pattern='backup.7z', write_sflash=False):

    if pa.tmp_value:
        if not await ux_confirm("An ephemeral seed is in effect, so backup will be of that seed."):
            return

    # pick a password: like bip39 but no checksum word
    #
    b = bytearray(32)
    while 1:
        ckcc.rng_bytes(b)
        words = bip39.b2a_words(b).split(' ')[0:num_pw_words]

        ch = await seed.show_words(words,
                        prompt="Record this (%d word) backup file password:\n", escape='6')

        if ch == '6' and not write_sflash:
            # Secret feature: plaintext mode
            # - only safe for people living in faraday cages inside locked vaults.
            if await ux_confirm("The file will **NOT** be encrypted and "
                                "anyone who finds the file will get all of your money for free!"):
                words = []
                fname_pattern = 'backup.txt'
                break
            continue

        if ch == 'x':
            return

        break


    if words:
        # quiz them, but be nice and do a shorter test.
        ch = await seed.word_quiz(words, limited=(num_pw_words//3))
        if ch == 'x': return

    return await write_complete_backup(words, fname_pattern, write_sflash=write_sflash)

async def write_complete_backup(words, fname_pattern, write_sflash=False, allow_copies=True):
    # Just do the writing
    from glob import dis
    from files import CardSlot, CardMissingError

    # Show progress:
    dis.fullscreen('Encrypting...' if words else 'Generating...')
    body = render_backup_contents().encode()

    gc.collect()

    if words:
        # NOTE: Takes a few seconds to do the key-streching, but little actual
        # time to do the encryption.

        pw = ' '.join(words)
        zz = compat7z.Builder(password=pw, progress_fcn=dis.progress_bar_show)
        zz.add_data(body)

        # pick random filename, but ending in .txt
        word = bip39.wordlist_en[ngu.random.uniform(2048)]
        num = ngu.random.uniform(1000)
        fname = '%s%d.txt' % (word, num)

        hdr, footer = zz.save(fname)

        filesize = len(body) + MAX_BACKUP_FILE_SIZE

        del body

        gc.collect()
    else:
        # cleartext dump
        zz = None
        filesize = len(body)+10

    if write_sflash:
        # for use over USB and unit testing: commit file into SPI flash
        from sffile import SFFile

        with SFFile(0, max_size=filesize, message='Saving...') as fd:
            await fd.erase()

            if zz:
                fd.write(hdr)
                fd.write(zz.body)
                fd.write(footer)
            else:
                fd.write(body)

            return fd.tell(), fd.checksum.digest()

    for copy in range(25):
        # choose a filename

        try:
            with CardSlot() as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with card.open(fname, 'wb') as fd:
                    if zz:
                        fd.write(hdr)
                        fd.write(zz.body)
                        fd.write(footer)
                    else:
                        fd.write(body)

        except Exception as e:
            # includes CardMissingError
            import sys
            sys.print_exception(e)
            # catch any error
            ch = await ux_show_story('Failed to write! Please insert formated MicroSD card, '
                                    'and press OK to try again.\n\nX to cancel.\n\n\n'+str(e))
            if ch == 'x': break
            continue

        if not allow_copies:
            return

        if copy == 0:
            while 1:
                msg = '''Backup file written:\n\n%s\n\n\
To view or restore the file, you must have the full password.\n\n\
Insert another SD card and press 2 to make another copy.''' % (nice)
    
                ch = await ux_show_story(msg, escape='2')

                if ch == 'y': return
                if ch == '2': break

        else:
            ch = await ux_show_story('''File (#%d) written:\n\n%s\n\n\
Press OK for another copy, or press X to stop.''' % (copy+1, nice), escape='2')
            if ch == 'x': break

async def verify_backup_file(fname):
    # read 7z header, and measure checksums
    # - no password is wanted/required
    # - really just checking CRC32, but that's enough against truncated files
    from files import CardSlot, CardMissingError, needs_microsd
    prob = None
    fd = None

    # filename already picked, open it.
    try:
        with CardSlot(readonly=True) as card:
            prob = 'Unable to open backup file.'
            fd = card.open(fname, 'rb')

            prob = 'Unable to read backup file headers. Might be truncated.'
            compat7z.check_file_headers(fd)

            prob = 'Unable to verify backup file contents.'
            zz = compat7z.Builder()
            files = zz.verify_file_crc(fd, MAX_BACKUP_FILE_SIZE)

            assert len(files) == 1
            fname, fsize = files[0]
            assert fname.endswith('.txt')
            assert 400 < fsize < MAX_BACKUP_FILE_SIZE, 'size'

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story(prob + '\n\nError: ' + str(e))
        return
    finally:
        if fd is not None:
            try:
                fd.close()
            except OSError:
                # might be already closed on vdisk case due to filesystem unmount/mount
                pass

    await ux_show_story("Backup file CRC checks out okay.\n\nPlease note this is only a check against accidental truncation and similar. Targeted modifications can still pass this test.")


async def restore_complete(fname_or_fd):
    from ux import the_ux

    async def done(words):
        # remove all pw-picking from menu stack
        seed.WordNestMenu.pop_all()

        prob = await restore_complete_doit(fname_or_fd, words)

        if prob:
            await ux_show_story(prob, title='FAILED')

    # give them a menu to pick from, and start picking
    m = seed.WordNestMenu(num_words=num_pw_words, has_checksum=False, done_cb=done)

    the_ux.push(m)

async def restore_complete_doit(fname_or_fd, words, file_cleanup=None):
    # Open file, read it, maybe decrypt it; return string if any error
    # - some errors will be shown, None return in that case
    # - no return if successful (due to reboot)
    from glob import dis
    from files import CardSlot, CardMissingError, needs_microsd

    # build password
    password = ' '.join(words)

    prob = None

    try:
        with CardSlot(readonly=True) as card:
            # filename already picked, taste it and maybe consider using its data.
            try:
                fd = open(fname_or_fd, 'rb') if isinstance(fname_or_fd, str) else fname_or_fd
            except:
                return 'Unable to open backup file.\n\n' + str(fname_or_fd)

            try:
                if not words:
                    contents = fd.read()
                else:
                    try:
                        compat7z.check_file_headers(fd)
                    except Exception as e:
                        return 'Unable to read backup file. Has it been touched?\n\nError: ' \
                                            + str(e)

                    dis.fullscreen("Decrypting...")
                    try:
                        zz = compat7z.Builder()
                        fname, contents = zz.read_file(fd, password, MAX_BACKUP_FILE_SIZE,
                                                progress_fcn=dis.progress_bar_show)

                        # simple quick sanity checks
                        assert fname.endswith('.txt')       # was == 'ckcc-backup.txt'
                        assert contents[0:1] == b'#' and contents[-1:] == b'\n'

                    except Exception as e:
                        # assume everything here is "password wrong" errors
                        #print("pw wrong?  %s" % e)

                        return ('Unable to decrypt backup file. Incorrect password?'
                                                '\n\nTried:\n\n' + password)
            finally:
                fd.close()

                if file_cleanup:
                    file_cleanup(fname_or_fd)

    except CardMissingError:
        await needs_microsd()
        return

    vals = {}
    for line in contents.decode().split('\n'):
        if not line: continue
        if line[0] == '#': continue

        try:
            k,v = line.split(' = ', 1)
            #print("%s = %s" % (k, v))

            vals[k] = ujson.loads(v)
        except:
            print("unable to decode line: %r" % line)
            # but keep going!

    # this leads to reboot if it works, else errors shown, etc.
    return await restore_from_dict(vals)

async def clone_start(*a):
    # Begins cloning process, on target device.
    from files import CardSlot, CardMissingError, needs_microsd

    ch = await ux_show_story('''Insert a MicroSD card and press OK to start. A small \
file with an ephemeral public key will be written.''')
    if ch != 'y': return

    # pick a random key pair, just for this cloning session
    pair = ngu.secp256k1.keypair()
    my_pubkey = pair.pubkey().to_bytes(False)

    # write to SD Card, fixed filename for ease of use
    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename('ccbk-start.json', overwrite=True)

            with card.open(fname, 'wb') as fd:
                fd.write(ujson.dumps(dict(pubkey=b2a_hex(my_pubkey))))
            
    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Error: ' + str(e))
        return
    
    # Wait for incoming clone file, allow retries
    ch = await ux_show_story('''Keep power on this Coldcard, and take MicroSD card \
to source Coldcard. Select Advanced > MicroSD > Clone Coldcard to write to card. Bring that card \
back and press OK to complete clone process.''')

    while 1:
        if ch != 'y': 
            # try to clean up, but card probably not there? No errors.
            try:
                with CardSlot() as card:
                    uos.remove(fname)
            except:
                pass 

            await ux_dramatic_pause('Aborted.', 2)
            return

        # Hopefully we have a suitable 7z file now. Pubkey in the filename
        incoming = None
        try:
            with CardSlot() as card:
                for path in card.get_paths():
                    for fn, ftype, *var in uos.ilistdir(path):
                        if fn.endswith('-ccbk.7z'):
                            incoming = path + '/' + fn
                            his_pubkey = a2b_hex(fn[0:66])

                            assert len(his_pubkey) == 33
                            assert 2 <= his_pubkey[0] <= 3
                            break

        except CardMissingError:
            await needs_microsd()
            continue
        except Exception as e:
            pass

        if incoming:
            break

        ch = await ux_show_story("Clone file not found. OK to try again, X to stop.")

    # calculate point
    session_key = pair.ecdh_multiply(his_pubkey)

    # "password" is that hex value
    words = [b2a_hex(session_key).decode()]

    def delme(xfn):
        # Callback to delete file after its read; could still fail but
        # need to start over in that case anyway.
        uos.remove(xfn)
        uos.remove(fname)       # ccbk-start.json

    # this will reset in successful case, no return (but delme is called)
    prob = await restore_complete_doit(incoming, words, file_cleanup=delme)

    if prob:
        await ux_show_story(prob, title='FAILED')

async def clone_write_data(*a):
    # Write encrypted backup file, for cloning purposes, based on a public key
    # found on the SD Card.
    # - input file must already exist on inserted card
    from files import CardSlot, CardMissingError

    try:
        with CardSlot() as card:
            path = card.get_sd_root()
            with open(path + '/ccbk-start.json', 'rb') as fd:
                d = ujson.load(fd)
                his_pubkey = a2b_hex(d.get('pubkey'))
                # expect compress pubkey
                assert len(his_pubkey) == 33
                assert 2 <= his_pubkey[0] <= 3

            # remove any other clone-files on this card, so no confusion
            # on receiving end; unlikely they can work anyway since new key each time
            for path in card.get_paths():
                for fn, ftype, *var in uos.ilistdir(path):
                    if fn.endswith('-ccbk.7z'):
                        try:
                            uos.remove(path + '/' + fn)
                        except:
                            pass

    except (CardMissingError, OSError) as exc:
        # Standard msg shown if no SD card detected when we need one.
        await ux_show_story("Start this process on the other Coldcard, which will write a file onto MicroSD card as the first step.\n\nInsert that card and try again here.")
        return

    # pick our own temp keys for this encryption
    pair = ngu.secp256k1.keypair()
    my_pubkey = pair.pubkey().to_bytes(False)
    session_key = pair.ecdh_multiply(his_pubkey)

    words = [b2a_hex(session_key).decode()]

    fname = b2a_hex(my_pubkey).decode() + '-ccbk.7z'

    await write_complete_backup(words, fname, allow_copies=False)

    await ux_show_story("Done.\n\nTake this MicroSD card back to other Coldcard and continue from there.")

# EOF
