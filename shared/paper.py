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
Paper Wallets

Coldcard will pick a completely random private key (which has no relation to your seed words), \
and record the corresponding payment address and private key (WIF) into a text file. If you have a \
special PDF template, it can also make a pretty version of the same data.

CAUTION: Paper wallets carry many risks and should only be used for small amounts.'''

no_templates_msg = '''\
You don't have any PDF templates to choose from, but plain text wallet files \

can still be made. Visit the Coldcard website to get some interesting templates.\
'''

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
        return int(self.is_segwit), ['Classic', 'Segwit/BECH32'], set
        

    def update_menu(self):
        # Reconstruct the menu contents based on our state.
        self.my_menu.replace_items([
            MenuItem('No PDF Template' if not self.template_fn else 'Will Make PDF',
                        f=self.pick_template),
            MenuItem('Classic Address' if not self.is_segwit else 'Segwit Address',
                        chooser=self.addr_format_chooser),

            MenuItem('GENERATE WALLET', f=self.doit),
        ], keep_position=True)

    async def doit(self, *a):
        # make the wallet.
        from main import dis

        try:
            from chains import current_chain
            import tcc
            from serializations import hash160
            from uQR import QRCode

            await ux_dramatic_pause("Picking key...", 4)

            # get some random bytes
            privkey = tcc.secp256k1.generate_secret()
            pubkey = tcc.secp256k1.publickey(privkey)       # compressed
            ch = current_chain()

            dis.fullscreen("Saving...")

            digest = hash160(pubkey)

            if self.is_segwit:
                addr = tcc.codecs.bech32_encode(ch.bech32_hrp, 0, digest).upper()
            else:
                addr = tcc.codecs.b58_encode(ch.b58_addr + digest)

            wif = tcc.codecs.b58_encode(ch.b58_privkey + privkey)

            # make the QR's now, since it's slow
            q = QRCode(version=4, box_size=1, border=0)
            q.add_data(addr, optimize=0)
            q.make(fit=False)
            qr_addr = q.get_matrix()
            del q

            q = QRCode(version=4, box_size=1, border=0)
            q.add_data(wif, optimize=0)
            q.make(fit=False)
            qr_wif = q.get_matrix()
            del q

            basename = 'paper-%s' % addr[:8]

            with CardSlot() as card:
                fname, nice_txt = card.pick_filename(basename + '-note.txt')

                with open(fname, 'wt') as fp:
                    self.make_txt(fp, addr, wif, qr_addr, qr_wif)

                if self.template_fn:
                    fname, nice_pdf = card.pick_filename(basename + '.pdf')

                    with open(fname, 'wb') as fp:
                        self.make_pdf(fp, addr, wif, qr_addr, qr_wif)
                else:
                    nice_pdf = ''

        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            raise       #XXX
            await ux_show_story('Failed to write!\n\n\n'+str(e))
            return

        await ux_show_story('Done! Created file(s):\n\n%s\n%s' % (nice_txt, nice_pdf))

    def make_txt(self, fp, addr, wif, qr_addr, qr_wif):
        fp.write('Coldcard Generated Paper Wallet\n\n')

        fp.write('Deposit address:\n\n  %s\n\n' % addr)
        fp.write('Private key:\n\n  %s\n\n' % wif)
        fp.write('Bitcoin Core command:\n\n  bitcoin-cli importprivkey "%s"\n\n' % wif)

        fp.write('\n\n--- QR Codes ---   (requires UTF-8, unicode, white background)\n\n\n\n')

        for idx, (qr, val) in enumerate([(qr_addr, addr), (qr_wif, wif)]):
            fp.write(('Private key' if idx else 'Deposit address') + ':\n\n')

            for ln in qr:
                fp.write('        ')
                fp.write(''.join('\u2588\u2588' if n else '  ' for n in ln))
                fp.write('\n')

            fp.write('\n        %s\n\n\n\n' % val)

        fp.write('\n\n\n')

    def insert_qr_hex(self, out_fp, qr, width):
        # render QR as binary data: 1 bit per pixel 33x33
        # - aways 8:1 expansion ratio here
        assert len(qr) == len(qr[0]) == width == 33
        for row in qr:
            ln = b''.join(b'00' if x else b'FF' for x in row) + b'\n'
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

    if await ux_show_story(background_msg) != 'y':
        return

    # show a menu with some settings, and a GO button

    menu = MenuSystem([])
    rv = PaperWalletMaker(menu)

    # always have them pick the template, because that's mostly required
    await rv.pick_template()
    rv.update_menu()

    return menu
    

# EOF
