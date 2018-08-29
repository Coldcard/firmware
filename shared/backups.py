# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# backups.py - Save and restore backup data.
#
import compat7z, stash, tcc, ckcc, chains, gc
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from utils import imported
from ux import ux_show_story, ux_confirm
import version, ujson
from uio import StringIO

# we make passwords with this number of words
num_pw_words = const(12)

def render_backup_contents():
    # simple text format:
    #   key = value
    # or #comments
    # but value is JSON
    from main import settings, pa

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

    with stash.SensitiveValues() as sv:

        if sv.mode == 'words':
            ADD('mnemonic', tcc.bip39.from_data(sv.raw))

        if sv.mode == 'master':
            ADD('bip32_master_key', b2a_hex(sv.raw))

        ADD('chain', chain.ctype)
        ADD('xprv', chain.serialize_private(sv.node))
        ADD('xpub', chain.serialize_public(sv.node))

        # BTW: everything is really a duplicate of this value
        ADD('raw_secret', b2a_hex(sv.secret).rstrip(b'00'))

        if pa.has_duress_pin():
            COMMENT('Duress Wallet (informational)')
            dpk = sv.duress_root()
            ADD('duress_xprv', chain.serialize_private(dpk))
            ADD('duress_xpub', chain.serialize_public(dpk))

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
        if k == 'xpub': continue        # redundant
        ADD('setting.' + k, v)

    rv.write('\n# EOF\n')

    return rv.getvalue()

async def restore_from_dict(vals):
    # Restore from a dict of values. Already JSON decoded.
    from main import pa, dis, settings
    from pincodes import AE_SECRET_LEN

    #print("Restoring from: %r" % vals)

    # step1: the private key
    # - prefer raw_secret over other values
    # - TODO: fail back to other values
    try:
        chain = chains.get_chain(vals.get('chain', 'BTC'))

        assert 'raw_secret' in vals
        raw = bytearray(AE_SECRET_LEN)
        x = a2b_hex(vals.pop('raw_secret'))
        raw[0:len(x)] = x

        # check we can decode this right (might be different firmare)
        opmode, bits, node = stash.SecretStash.decode(raw)
        assert node

        # verify against xprv value (if we have it)
        if 'xprv' in vals:
            check_xprv = chain.serialize_private(node)
            assert check_xprv == vals['xprv'], 'xprv mismatch'

    except Exception as e:
        raise
        await ux_show_story('Unable to decode raw_secret and '
                                'restore the seed value!\n\n\n'+str(e), title='FAILED')
        return

    dis.fullscreen("Saving...")
    dis.progress_bar_show(.25)

    # clear (in-memory) settings and change also nvram key
    # - also captures xfp, xpub at this point
    pa.change(new_secret=raw)

    # force the right chain
    pa.new_main_secret(raw, chain)         # updates xfp/xpub

    # NOTE: don't fail after this point... they can muddle thru w/ just right seed

    # restore settings from backup file

    for idx, k in enumerate(vals):
        dis.progress_bar_show(idx / len(vals))
        if not k.startswith('setting.'):
            continue

        if k == 'xfp' or k == 'xpub': continue

        settings.set(k[8:], vals[k])

    # write out
    settings.save()

    await ux_show_story('Everything has been successfully restored. '
            'We must now reboot to install the '
            'updated settings and/or seed.', title='Success!')

    from machine import reset
    reset()


async def make_complete_backup(fname_pattern='backup.7z', write_sflash=False):
    import seed

    # pick a password: like bip39 but no checksum word
    #
    b = bytearray(32)
    while 1:
        ckcc.rng_bytes(b)
        words = tcc.bip39.from_data(b).split(' ')[0:num_pw_words]

        #print('File pw: ' + ' '.join(words))

        ch = await seed.show_words(words,
                        prompt="Record this (%d word) backup file password:\n", respin=1)
        if ch == '2':
            # respin
            continue

        if ch == '6' and not write_sflash:
            # Secret feature: plaintext mode
            # - only safe for people living in faraday cages inside vaults.
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

    return await write_complete_backup(words, fname_pattern, write_sflash)

async def write_complete_backup(words, fname_pattern, write_sflash):
    # Just do the writing
    from main import dis, pa, settings
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    # Show progress:
    dis.fullscreen('Encrypting...' if words else 'Generating...')
    body = render_backup_contents().encode()

    if words:
        # NOTE: Takes a few seconds to do the key-streching, but little actual
        # time to do the encryption.

        pw = ' '.join(words)
        zz = compat7z.Builder(password=pw, progress_fcn=dis.progress_bar_show)
        zz.add_data(body)

        hdr, footer = zz.save('ckcc-backup.txt')
    else:
        # cleartext dump
        zz = None

    if write_sflash:
        # for use over USB and unit testing: commit file into SPI flash
        from sffile import SFFile

        with SFFile(0, max_size=len(body)+2000, message='Saving...') as fd:
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
                with open(fname, 'wb') as fd:
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

async def verify_backup_file(fname_or_fd):
    # read 7z header, and measure checksums
    # - no password is wanted/required
    # - really just checking CRC32, but that's enough against truncated files
    from files import CardSlot, CardMissingError
    from actions import needs_microsd
    prob = None
    fd = None

    # filename already picked, open it.
    try:
        with CardSlot() as card:
            prob = 'Unable to open backup file.'
            fd = open(fname_or_fd, 'rb') if isinstance(fname_or_fd, str) else fname_or_fd

            prob = 'Unable to read backup file headers. Might be truncated.'
            compat7z.check_file_headers(fd)

            prob = 'Unable to verify backup file contents.'
            zz = compat7z.Builder()
            files = zz.verify_file_crc(fd)

            assert len(files) == 1
            fname, fsize = files[0]
            assert fname == 'ckcc-backup.txt'
            assert 400 < fsize < 2000

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story(prob + '\n\nError: ' + str(e))
        return
    finally:
        if fd:
            fd.close()

    await ux_show_story("Backup file CRC checks out okay.\n\nPlease note this is only a check against accidental truncation and similar. Targeted modifications can still pass this test.")


async def restore_complete(fname_or_fd):
    from ux import the_ux

    with imported('seed') as seed:

        async def done(words):
            # remove all pw-picking from menu stack
            seed.WordNestMenu.pop_all()

            await restore_complete_doit(fname_or_fd, words)

        # give them a menu to pick from
        m = seed.WordNestMenu(num_words=num_pw_words, has_checksum=False, done_cb=done)

    the_ux.push(m)

async def restore_complete_doit(fname_or_fd, words):
    from main import dis

    # build password
    password = ' '.join(words)

    # filename already picked, taste it and maybe consider using its data.
    try:
        fd = open(fname_or_fd, 'rb') if isinstance(fname_or_fd, str) else fname_or_fd
    except:
        await ux_show_story('Unable to open backup file. \n\n' + str(fname_or_fd))
        return

    try:
        if not words:
            contents = fd.read()
        else:
            try:
                compat7z.check_file_headers(fd)
            except Exception as e:
                await ux_show_story('Unable to read backup file. Has it been touched?'
                                        '\n\nError: ' + str(e))
                return

            dis.fullscreen("Decrypting...")
            try:
                zz = compat7z.Builder()
                fname, contents = zz.read_file(fd, password, progress_fcn=dis.progress_bar_show)

                assert fname == 'ckcc-backup.txt', "Wrong filename in archive"

                # simple quick sanity check
                assert contents[0:1] == b'#' and contents[-1:] == b'\n', "Corrupted after decrypt"

            except Exception as e:
                # assume everything here is "password wrong" errors
                print("pw wrong?  %s" % e)

                await ux_show_story('Unable to decrypt backup file. Incorrect password?'
                                        '\n\nTried:\n\n' + password)

                return
    finally:
        fd.close()

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

    await restore_from_dict(vals)

def generate_public_contents():
    # Generate public details about wallet.
    #
    # simple text format:
    #   key = value
    # or #comments
    # but value is JSON
    from main import settings

    num_rx = 5

    chain = chains.current_chain()

    with stash.SensitiveValues() as sv:

        yield ('''\
# Coldcard Wallet Summary File

## Wallet operates on blockchain: {nb}

For BIP44, this is coin_type '{ct}', and internally we use symbol {sym} for this blockchain.

## Top-level, 'master' extended public key ('m/'):

{xpub}

Derived public keys, as may be needed for different systems:


'''.format(nb=chain.name, xpub=chain.serialize_public(sv.node),
            sym=chain.ctype, ct=chain.b44_cointype))

        for name, path, addr_fmt in chains.CommonDerivations:

            if '{coin_type}' in path:
                path = path.replace('{coin_type}', str(chain.b44_cointype))

            yield ('''## For {name}: {path}\n\n'''.format(name=name, path=path))

            submaster, kids = path.split('/{', 1)
            kids = '{'+kids

            node = sv.derive_path(submaster)

            yield ("%s => %s\n" % (submaster, chain.serialize_public(node)))

            yield ('''\n... first %d receive addresses (account=0, change=0):\n\n''' % num_rx)

            for i in range(num_rx):
                subpath = kids.format(account=0, change=0, idx=i)
                kid = sv.derive_path(subpath, node)
                yield ('%s/%s => %s\n' % (submaster, subpath, chain.address(kid, addr_fmt)))

            yield ('\n\n')

async def make_summary_file(fname_pattern='public.txt'):
    # record **public** values and helpful data into a text file
    from main import dis, pa, settings
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    dis.fullscreen('Generating...')

    # generator function:
    body = generate_public_contents()

    # choose a filename

    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wb') as fd:
                for part in body:
                    fd.write(part.encode())

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''Summary file written:\n\n%s''' % nice
    await ux_show_story(msg)

def generate_electrum_wallet(is_segwit):
    # Generate line-by-line JSON details about wallet.
    #
    # Much reverse enginerring of Electrum here. It's a complex
    # legacy file format.
    from main import settings

    chain = chains.current_chain()

    xfp = settings.get('xfp')

    if is_segwit:
        derive = "m/84'/{coin_type}'/{account}'".format(account=0, coin_type=chain.b44_cointype)
    else:
        derive = "m/44'/{coin_type}'/{account}'".format(account=0, coin_type=chain.b44_cointype)

    with stash.SensitiveValues() as sv:

        top = chain.serialize_public(sv.derive_path(derive))

    # most values are nicely defaulted, and for max forward compat, don't want to set
    # anything more than I need to

    rv = dict(seed_version=17, use_encryption=False, wallet_type='standard')

    # the important stuff.
    rv['keystore'] = dict(  ckcc_xfp=xfp,
                            ckcc_xpub=settings.get('xpub'),
                            hw_type='coldcard',
                            label='Coldcard Import 0x%08x' % xfp,
                            type='hardware',
                            derivation=derive, xpub=top)

    return rv

async def make_electrum_wallet(fname_pattern='new-wallet.json', is_segwit=False):
    # Record **public** values and helpful data into a JSON file

    from main import dis, pa, settings
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    dis.fullscreen('Generating...')

    body = generate_electrum_wallet(is_segwit)

    # choose a filename

    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wt') as fd:
                ujson.dump(body, fd)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''New Electrum wallet file written:\n\n%s''' % nice
    await ux_show_story(msg)

# EOF
