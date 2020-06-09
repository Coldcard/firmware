# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# paper.py - generate paper wallets, based on random values (not linked to wallet)
#
from utils import imported
from actions import needs_microsd
from ux import ux_show_story, ux_dramatic_pause
from files import CardSlot, CardMissingError
from actions import file_picker
from menu import MenuSystem, MenuItem

background_msg = '''\
Coldcard will pick a random private key (which has no relation to your seed words), \
and record the corresponding payment address and private key (WIF) into a text file, \
creating a so-called "paper wallet".
{can_qr}

Another option is to roll a D6 die many times to generate the key.

CAUTION: Paper wallets carry MANY RISKS and should only be used for SMALL AMOUNTS.'''

no_templates_msg = '''\
You don't have any PDF templates to choose from, but plain text wallet files \
can still be made. Visit the Coldcard website to get some interesting templates.\
'''

SECP256K1_ORDER = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41"

# Aprox. time of this feature release (Nov 20/2019) so no need to scan
# blockchain earlier than this during "importmulti"
FEATURE_RELEASE_TIME = const(1574277000)

# These very-specific text values are matched on the Coldcard; cannot be changed.
class placeholders:
    addr = b'ADDRESS_XXXXXXXXXXXXXXXXXXXXXXXXXXXXX'                      # 37 long
    privkey = b'PRIVKEY_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'     # 51 long

    # rather than Tokyo, I chose Chiba Prefecture in ShiftJIS encoding...
    header = b'%PDF-1.3\n%\x90\xe7\x97t\x8c\xa7 Coldcard Paper Wallet Template\n'

def template_taster(fn):
    # check if file looks like our special PDF templates... must have right header bits
    hdr = open(fn, 'rb').read(len(placeholders.header))
    return hdr == placeholders.header

class PaperWalletMaker:
    def __init__(self, my_menu):
        self.my_menu = my_menu
        self.template_fn = None
        self.is_segwit = False

    async def pick_template(self, *a):
        fn = await file_picker('Pick PDF template to use, or X for none.',
                                suffix='.pdf', min_size=20000,
                                taster=template_taster, none_msg=no_templates_msg)
        self.template_fn = fn

        self.update_menu()

    def addr_format_chooser(self, *a):
        # simple bool choice
        def set(idx, text):
            self.is_segwit = bool(idx)
            self.update_menu()
        return int(self.is_segwit), ['Classic', 'Segwit/Bech32'], set

    @staticmethod
    def can_do_qr():
        import version
        return version.has_fatram

    def update_menu(self):
        # Reconstruct the menu contents based on our state.
        self.my_menu.replace_items([
            MenuItem("Don't make PDF" if not self.template_fn else 'Making PDF',
                        f=self.pick_template, predicate=self.can_do_qr),
            MenuItem('Classic Address' if not self.is_segwit else 'Segwit Address',
                        chooser=self.addr_format_chooser),
            MenuItem('Use Dice', f=self.use_dice),
            MenuItem('GENERATE WALLET', f=self.doit),
        ], keep_position=True)

    async def doit(self, *a, have_key=None):
        # make the wallet.
        from main import dis

        try:
            from chains import current_chain
            import tcc
            from serializations import hash160
            from stash import blank_object

            if not have_key:
                # get some random bytes
                await ux_dramatic_pause("Picking key...", 2)
                privkey = tcc.secp256k1.generate_secret()
            else:
                # caller must range check this already: 0 < privkey < order
                privkey = have_key

            # calculate corresponding public key value
            pubkey = tcc.secp256k1.publickey(privkey, True)       # always compressed style

            dis.fullscreen("Rendering...")

            # make payment address
            digest = hash160(pubkey)
            ch = current_chain()
            if self.is_segwit:
                addr = tcc.codecs.bech32_encode(ch.bech32_hrp, 0, digest)
            else:
                addr = tcc.codecs.b58_encode(ch.b58_addr + digest)

            wif = tcc.codecs.b58_encode(ch.b58_privkey + privkey + b'\x01')

            if self.can_do_qr():
                with imported('uqr') as uqr:
                    # make the QR's now, since it's slow
                    is_alnum = self.is_segwit 
                    qr_addr = uqr.make(addr if not is_alnum else addr.upper(), 
                                min_version=4, max_version=4,
                                encoding=(uqr.Mode_ALPHANUMERIC if is_alnum else 0))

                    qr_wif = uqr.make(wif, min_version=4, max_version=4, encoding=uqr.Mode_BYTE)
            else:
                qr_addr = None
                qr_wif = None

            # Use address as filename. clearly will be unique, but perhaps a bit
            # awkward to work with.
            basename = addr

            dis.fullscreen("Saving...")
            with CardSlot() as card:
                fname, nice_txt = card.pick_filename(basename + 
                                        ('-note.txt' if self.template_fn else '.txt'))

                with open(fname, 'wt') as fp:
                    self.make_txt(fp, addr, wif, privkey, qr_addr, qr_wif)

                if self.template_fn:
                    fname, nice_pdf = card.pick_filename(basename + '.pdf')

                    with open(fname, 'wb') as fp:
                        self.make_pdf(fp, addr, wif, qr_addr, qr_wif)
                else:
                    nice_pdf = ''

            # Half-hearted attempt to cleanup secrets-contaminated memory
            # - better would be force user to reboot
            # - and yet, we just output the WIF to SDCard anyway
            blank_object(privkey)
            blank_object(wif)
            del qr_wif

        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n\n'+str(e))
            return

        await ux_show_story('Done! Created file(s):\n\n%s\n\n%s' % (nice_txt, nice_pdf))

    async def use_dice(self, *a):
        # Use lots of (D6) dice rolls to create privkey entropy.
        privkey = b''
        with imported('seed') as seed:
            count, privkey = await seed.add_dice_rolls(0, privkey, True)
            if count == 0: return

        if privkey >= SECP256K1_ORDER or privkey == bytes(32):
            # lottery won! but not going to waste bytes here preparing to celebrate
            return

        return await self.doit(have_key=privkey)


    def make_txt(self, fp, addr, wif, privkey, qr_addr=None, qr_wif=None):
        # Generate the "simple" text file version, includes private key.
        from ubinascii import hexlify as b2a_hex
        from descriptor import append_checksum
        import ujson

        fp.write('Coldcard Generated Paper Wallet\n\n')

        fp.write('Deposit address:\n\n  %s\n\n' % addr)
        fp.write('Private key (WIF=Wallet Import Format):\n\n  %s\n\n' % wif)
        fp.write('Private key (Hex, 32 bytes):\n\n  %s\n\n' % b2a_hex(privkey).decode('ascii'))
        fp.write('Bitcoin Core command:\n\n')

        # new hotness: output descriptors
        desc = ('wpkh(%s)' if self.is_segwit else 'pkh(%s)') % wif
        multi = ujson.dumps(dict(timestamp=FEATURE_RELEASE_TIME, desc=append_checksum(desc)))
        fp.write("  bitcoin-cli importmulti '[%s]'\n\n" % multi)
        fp.write('# OR (more compatible, but slower)\n\n  bitcoin-cli importprivkey "%s"\n\n' % wif)

        if qr_addr and qr_wif:
            fp.write('\n\n--- QR Codes ---   (requires UTF-8, unicode, white background)\n\n\n\n')

            for idx, (qr, val) in enumerate([(qr_addr, addr), (qr_wif, wif)]):
                fp.write(('Private key' if idx else 'Deposit address') + ':\n\n')

                w = qr.width()
                for y in range(w):
                    fp.write('        ')
                    ln = ''.join('\u2588\u2588' if qr.get(x,y) else '' for x in range(w))
                    fp.write(ln)
                    fp.write('\n')

                fp.write('\n        %s\n\n\n\n' % val)

        fp.write('\n\n\n')

    def insert_qr_hex(self, out_fp, qr, width):
        # render QR as binary data: 1 bit per pixel 33x33
        # - aways 8:1 expansion ratio here
        assert qr.width() == width == 33        # only version==4 supported
        for y in range(width):
            ln = b''.join(b'00' if qr.get(x,y) else b'FF' for x in range(width))
            ln += b'\n'
            out_fp.write(ln * 8)
        
    def make_pdf(self, out_fp, addr, wif, qr_addr, qr_wif):
        qr_armed, qr_skip = False, False
        addr = addr.encode('ascii')
        wif = wif.encode('ascii')

        with open(self.template_fn, 'rb') as inp:
            for ln in inp:
                if qr_skip:
                    if ln == b'endstream\n':
                        qr_skip = False
                    else:
                        continue

                if b'Coldcard Paper Wallet Template' in ln:
                    # remove ' Template\n' part at end .. so we won't offer this
                    # file as a template, next round.
                    ln = ln.replace(b' Template', b'')
                elif ln == b'stream\n':
                    qr_armed = True
                elif qr_armed:
                    if  ln[0:6] == b'51523A':     # 'QR:' in hex
                        # it's the first line of QR hex data
                        # - QR:addr vs QR:pk, in hex..
                        is_addr = (ln[0:14] == b'51523A61646472')
                        self.insert_qr_hex(out_fp, qr_addr if is_addr else qr_wif, (len(ln)-1)//2)
                        qr_skip = True
                        continue
                    else:
                        qr_armed = False

                # replace these text values if they occur
                if b'XXXXXXXXXX' in ln:
                    ln = ln.replace(placeholders.addr, addr)
                    ln = ln.replace(placeholders.privkey, wif)

                # typical case: echo the line back out
                out_fp.write(ln)

async def make_paper_wallet(*a):

    msg = background_msg.format(can_qr=('\nIf you have a special PDF template file, it can also make a pretty version of the same data.' if PaperWalletMaker.can_do_qr() else ''))

    if await ux_show_story(msg) != 'y':
        return

    # show a menu with some settings, and a GO button

    menu = MenuSystem([])
    rv = PaperWalletMaker(menu)

    # annoying?
    # always have them pick the template, because that's mostly required
    #if rv.can_do_qr():
    #    await rv.pick_template()

    rv.update_menu()

    return menu
    

# EOF
