# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# paper.py - generate paper wallets, based on random values (not linked to wallet)
#
import ujson, ngu, chains
from ubinascii import hexlify as b2a_hex
from utils import imported
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2TR
from ux import ux_show_story, ux_dramatic_pause
from files import CardSlot, CardMissingError, needs_microsd
from actions import file_picker
from menu import MenuSystem, MenuItem
from stash import blank_object

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
        self.is_taproot = False

    def atype(self):
        if self.is_taproot: return 2, 'Taproot P2TR'
        if self.is_segwit: return 1, 'Segwit P2WPKH'
        return 0, 'Classic P2PKH'

    async def pick_template(self, *a):
        fn = await file_picker(suffix='.pdf', min_size=20000, taster=template_taster,
                               none_msg=no_templates_msg)
        self.template_fn = fn

        self.update_menu()

    def addr_format_chooser(self, *a):
        # simple bool choice
        def set(idx, text):
            self.is_segwit = idx == 1
            self.is_taproot = idx == 2
            self.update_menu()
        return self.atype()[0], ['Classic P2PKH', 'Segwit P2WPKH', 'Taproot P2TR'], set

    def update_menu(self):
        # Reconstruct the menu contents based on our state.
        self.my_menu.replace_items([
            MenuItem("Don't make PDF" if not self.template_fn else 'Making PDF',
                     f=self.pick_template),
            MenuItem(self.atype()[1], chooser=self.addr_format_chooser),
            MenuItem('Use Dice', f=self.use_dice),
            MenuItem('GENERATE WALLET', f=self.doit),
        ], keep_position=True)

    async def doit(self, *a, have_key=None):
        # make the wallet.
        from glob import dis, VD

        try:
            if not have_key:
                # get some random bytes
                await ux_dramatic_pause("Picking key...", 2)
                pair = ngu.secp256k1.keypair()
            else:
                # caller must range check this already: 0 < privkey < order
                # - actually libsecp256k1 will check it again anyway
                pair = ngu.secp256k1.keypair(have_key)

            # pull out binary versions (serialized) as we need
            privkey = pair.privkey()
            pubkey = pair.pubkey().to_bytes(False)       # always compressed style

            dis.fullscreen("Rendering...")

            # make payment address
            ch = chains.current_chain()
            if self.is_segwit:
                af = AF_P2WPKH
            elif self.is_taproot:
                af = AF_P2TR
                pubkey = pubkey[1:]
            else:
                af = AF_CLASSIC

            addr = ch.pubkey_to_address(pubkey, af)

            wif = ngu.codecs.b58_encode(ch.b58_privkey + privkey + b'\x01')

            with imported('uqr') as uqr:
                # make the QR's now, since it's slow
                is_alnum = self.is_segwit
                qr_addr = uqr.make(addr if not is_alnum else addr.upper(),
                            min_version=4, max_version=4,
                            encoding=(uqr.Mode_ALPHANUMERIC if is_alnum else 0))

                qr_wif = uqr.make(wif, min_version=4, max_version=4, encoding=uqr.Mode_BYTE)

            # Use address as filename. clearly will be unique, but perhaps a bit
            # awkward to work with.
            basename = addr
            force_vdisk = False
            if VD:
                prompt = "Press (1) to save paper wallet file to SD Card"
                escape = "1"
                if VD is not None:
                    prompt += ", press (2) to save to VDisk"
                    escape += "2"
                prompt += "."
                ch = await ux_show_story(prompt, escape=escape)
                if ch == "2":
                    force_vdisk = True
                elif ch == '1':
                    force_vdisk = False
                else:
                    return
            dis.fullscreen("Saving...")
            with CardSlot(force_vdisk=force_vdisk) as card:
                fname, nice_txt = card.pick_filename(basename + 
                                        ('-note.txt' if self.template_fn else '.txt'))
                sig_cont = []
                with card.open(fname, 'wt+') as fp:
                    self.make_txt(fp, addr, wif, privkey, qr_addr, qr_wif)
                    fp.seek(0)
                    contents0 = fp.read()

                h = ngu.hash.sha256s(contents0.encode())
                sig_cont.append((h, fname))
                if self.template_fn:
                    fname, nice_pdf = card.pick_filename(basename + '.pdf')

                    with open(fname, 'wb+') as fp:
                        self.make_pdf(fp, addr, wif, qr_addr, qr_wif)
                        fp.seek(0)
                        contents1 = fp.read()
                    h = ngu.hash.sha256s(contents1)
                    sig_cont.append((h, fname))
                else:
                    nice_pdf = ''

                nice_sig = None
                if af != AF_P2TR:
                    from auth import write_sig_file
                    nice_sig = write_sig_file(sig_cont, pk=privkey, sig_name=basename,
                                              addr_fmt=AF_P2WPKH if self.is_segwit else AF_CLASSIC)

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
            from utils import problem_file_line
            await ux_show_story('Failed to write!\n\n\n'+problem_file_line(e))
            return

        story = "Done! Created file(s):\n\n%s" % nice_txt
        if nice_pdf:
            story += "\n\n%s" % nice_pdf
        if nice_sig:
            story += "\n\n%s" % nice_sig
        await ux_show_story(story)

    async def use_dice(self, *a):
        # Use lots of (D6) dice rolls to create privkey entropy.
        privkey = b''
        with imported('seed') as seed:
            count, privkey = await seed.add_dice_rolls(0, privkey, True, enforce=True)
            if count == 0: return

        if privkey >= SECP256K1_ORDER or privkey == bytes(32):
            # lottery won! but not going to waste bytes here preparing to celebrate
            return

        return await self.doit(have_key=privkey)


    def make_txt(self, fp, addr, wif, privkey, qr_addr=None, qr_wif=None):
        # Generate the "simple" text file version, includes private key.
        from descriptor import append_checksum

        fp.write('Coldcard Generated Paper Wallet\n\n')

        fp.write('Deposit address:\n\n  %s\n\n' % addr)
        fp.write('Private key (WIF=Wallet Import Format):\n\n  %s\n\n' % wif)
        fp.write('Private key (Hex, 32 bytes):\n\n  %s\n\n' % b2a_hex(privkey).decode('ascii'))
        fp.write('Bitcoin Core command:\n\n')

        # new hotness: output descriptors
        if self.is_taproot:
            desc = 'tr(%s)'
        elif self.is_segwit:
            desc = 'wpkh(%s)'
        else:
            desc = 'pkh(%s)'
        desc = desc % wif
        descriptor = ujson.dumps(dict(timestamp="now", desc=append_checksum(desc)))
        fp.write("  bitcoin-cli importdescriptors '[%s]'\n\n" % descriptor)
        if not self.is_taproot:
            fp.write('# OR (only supported with legacy wallets)\n\n  bitcoin-cli importprivkey "%s"\n\n' % wif)

        if qr_addr and qr_wif:
            fp.write('\n\n--- QR Codes ---   (requires UTF-8, unicode, white background)\n\n\n\n')

            for idx, (qr, val) in enumerate([(qr_addr, addr), (qr_wif, wif)]):
                fp.write(('Private key' if idx else 'Deposit address') + ':\n\n')

                w = qr.width()
                for y in range(w):
                    fp.write('        ')
                    ln = ''.join('\u2588\u2588' if qr.get(x,y) else '  ' for x in range(w))
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

    msg = background_msg.format(can_qr='\nIf you have a special PDF template file, '
                                       'it can also make a pretty version of the same data.')

    if await ux_show_story(msg) != 'y':
        return

    # show a menu with some settings, and a GO button

    menu = MenuSystem([])
    rv = PaperWalletMaker(menu)

    rv.update_menu()

    return menu
    

# EOF
