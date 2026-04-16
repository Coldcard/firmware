# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import chains, ngu, version
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from ux import ux_show_story, ux_confirm, the_ux, import_export_prompt, ux_input_text, show_qr_code
from menu import MenuSystem, MenuItem
from utils import problem_file_line, show_single_address, node_from_pubkey
from files import CardSlot, CardMissingError, needs_microsd
from glob import settings
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL
from public_constants import AF_P2WPKH
from msgsign import msg_signing_done


def decode_wif(wif):
    # Decode base58 encoded WIF string, return keypair and metadata
    raw = ngu.codecs.b58_decode(wif)
    assert raw[0] in (0xef, 0x80)

    testnet = True if raw[0] == 0xef else False

    assert len(raw) in (33, 34)

    compressed = False
    if len(raw) == 34:  # compressed pubkey
        assert raw[33] == 0x01
        compressed = True

    sk = raw[1:33]
    kp = ngu.secp256k1.keypair(sk)  # catches wrong private keys

    return kp, testnet, compressed


def iter_wif_store_addresses(chain, addr_fmt):
    # nothing found among singlesig & registered multisig wallets
    # check WIF store
    wifs = settings.get("wifs", [])
    if not wifs: return

    for i, (pk, sk) in enumerate(wifs):
        node = node_from_pubkey(a2b_hex(pk))
        yield i, chain.address(node, addr_fmt)


async def ux_visualize_wif(wif_str, kp, compressed, testnet):
    ch_str = ("XTN" if testnet else "BTC")
    sk = b2a_hex(kp.privkey()).decode()
    pk = b2a_hex(kp.pubkey().to_bytes(not compressed)).decode()
    msg = "%s\n\nchain: %s\n\nPrivkey:\n%s\n\nPubkey:\n%s" % (wif_str, ch_str, sk, pk)
    esc = ""

    if compressed and (testnet == (chains.current_chain().ctype != "BTC")):
        # we only support compressed in WIF store
        msg += "\n\nPress (1) to import to WIF Store."
        esc += "1"

    ch = await ux_show_story(msg, title="WIF Key", escape=esc)
    if ch == "1":
        saved = settings.get("wifs", [])
        if (pk, sk) in saved:
            await ux_show_story("Already saved in WIF Store.", title="Failure")
            return

        saved.append((pk, sk))
        settings.set('wifs', saved)
        settings.save()

        await ux_show_story("Saved to WIF Store.", title="Success")


class WIFStore(MenuSystem):
    MAX_ITEMS = 30

    def __init__(self):
        items = self.construct()
        super().__init__(items)

    @classmethod
    async def make_menu(cls, *a):
        if not settings.get("wifs", None):
            intro = ("Individual private keys, encoded as WIF (Wallet Import Format) keys"
                     " can be imported and used for signing. Any PSBT that uses a WIF stored here"
                     " will be signed as normal, but warning is shown."
                     " Remove all imported keys to disable WIF store signing")

            ch = await ux_show_story(intro, title="WIF Store")
            if ch != 'y': return
        return cls()

    def update_contents(self):
        tmp = self.construct()
        self.replace_items(tmp)

    def construct(self):
        from glob import dis
        from seed import not_hobbled_mode

        dis.fullscreen("Wait...")

        ch = chains.current_chain()
        wifs = settings.get('wifs', [])

        items = []

        if len(wifs) < self.MAX_ITEMS:
            items.append(MenuItem('Import WIF', f=self.import_wif, predicate=not_hobbled_mode))

        a_items = []
        export_all = []
        for i, (pk, sk) in enumerate(wifs):
            wif = ngu.codecs.b58_encode(ch.b58_privkey + a2b_hex(sk) + b'\x01')
            export_all.append(wif)

            submenu = [
                MenuItem("Detail", f=self.detail, arg=(wif,pk,sk)),
                MenuItem("Addresses", f=self.show_addr_step1, arg=pk),
                MenuItem("Sign MSG", f=self.sign_msg_step1, arg=sk),
                MenuItem('Delete', f=self.delete, arg=(i, pk), predicate=not_hobbled_mode),
            ]

            # cannot use truncate_address here, as it does nto fit on Mk4 (because padded numbering)
            clen = 12 if version.has_qwerty else 5
            a_items.append(MenuItem("%2d: %s" % (i+1, wif[0:clen] + '⋯' + wif[-clen:]),
                                    menu=MenuSystem(submenu)))

        if a_items:
            items += a_items
            if len(a_items) > 1:
                items.append(MenuItem("Export All", f=self.export_all, arg=export_all))
                items.append(MenuItem("Clear All", f=self.clear_all, predicate=not_hobbled_mode))
        else:
            items.append(MenuItem("(none yet)"))

        return items

    async def detail(self, a, b, item):
        wif, pk, sk = item.arg
        msg = "%s\n\nPrivkey:\n%s\n\nPubkey:\n%s" % (wif, sk, pk)

        from export import export_contents
        title = "WIF"
        await export_contents(title, wif, "wif.txt", None, None,
                              force_prompt=True, intro=msg, ux_title=title)

    async def show_addr_step1(self, a, b, item):
        pubkey = a2b_hex(item.arg)
        rv = [
            MenuItem(chains.addr_fmt_label(af), f=self.show_addr_step2, arg=(pubkey, af))
            for af in chains.SINGLESIG_AF
        ]
        the_ux.push(MenuSystem(rv))

    async def show_addr_step2(self, a, b, item):
        from glob import NFC
        pubkey, af = item.arg
        node = node_from_pubkey(pubkey)
        addr = chains.current_chain().address(node, af)
        msg = show_single_address(addr) + "\n\n"

        escape = ""
        # Q only hint keys
        if not version.has_qwerty:
            msg += "Press (1) to show address QR code."
            escape += "1"
            if NFC:
                msg += "(3) to share via NFC."
                escape += "3"

        title = chains.addr_fmt_label(af) if version.has_qwerty else None
        while True:
            ch = await ux_show_story(msg, title=title, escape=escape,
                                     hint_icons=KEY_QR+(KEY_NFC if NFC else ''))
            if ch == "x": return
            if ch in "1"+KEY_QR:
                await show_qr_code(addr, is_alnum=af == AF_P2WPKH)

            elif NFC and (ch in "3"+KEY_NFC):
                await NFC.share_text(addr)

    async def sign_msg_step1(self, a, b, item):
        privkey = a2b_hex(item.arg)
        rv = [
            MenuItem(chains.addr_fmt_label(af), f=self.sign_msg_step2, arg=(privkey, af))
            for af in chains.SINGLESIG_AF
        ]
        the_ux.push(MenuSystem(rv))

    async def sign_msg_step2(self, a, b, item):
        from glob import NFC
        from actions import file_picker
        from auth import approve_msg_sign

        ch = await import_export_prompt("message", is_import=True, force_prompt=True,
                                        key0="to input message manually",
                                        no_qr=not version.has_qwerty)
        if ch == KEY_CANCEL:
            return
        elif ch == "0":
            msg = await ux_input_text("", confirm_exit=False)
        elif ch == KEY_NFC:
            msg = await NFC.read_bip322_msg()
        elif ch == KEY_QR:
            from ux_q1 import QRScannerInteraction
            msg = await QRScannerInteraction().scan_text('Scan message from a QR code')
        else:
            fn = await file_picker(suffix='.txt')
            if not fn: return

            with CardSlot(readonly=True, **ch) as card:
                with open(fn, 'rt') as fd:
                    msg = fd.read()

        if not msg: return
        privkey, af = item.arg

        await approve_msg_sign(msg, "", af, privkey=privkey, approved_cb=msg_signing_done)


    async def delete(self, a, b, item):
        # no confirm, stakes are low
        if not await ux_confirm("Delete WIF key?"):
            return

        idx, pubkey = item.arg
        wifs = settings.get('wifs', [])
        if not wifs: return

        try:
            entry = wifs[idx]
            assert entry[0] == pubkey
            del wifs[idx]
            settings.set('wifs', wifs)
            settings.save()
        except IndexError:
            return

        the_ux.pop()  # pop submenu
        self.update_contents()

    async def clear_all(self, *a):
        if await ux_confirm("Remove all saved WIF keys?", confirm_key='4'):
            settings.remove_key("wifs")
            settings.save()
            self.update_contents()

    async def export_all(self, a, b, item):
        wifs = item.arg
        from export import export_contents
        title = "WIF Store"
        await export_contents(title, "\n".join(wifs), "wif_store.txt",
                              None, None, force_prompt=True, ux_title=title)


    async def import_wif(self, *a):
        from glob import NFC, dis
        from actions import file_picker

        label = "WIF private key"
        ch = await import_export_prompt(label, is_import=True, key0="to input WIF manually")

        if ch == KEY_CANCEL:
            return
        elif ch == KEY_NFC:
            got = await NFC.read_wif()

        elif ch == KEY_QR:
            from ux_q1 import QRScannerInteraction
            got = await QRScannerInteraction().scan_text(label)

        elif ch == "0":
            got = await ux_input_text("", confirm_exit=False, max_len=52)  # compressed WIF key str length is 52

        else:
            # pick a likely-looking file: just looking at size and extension
            # - kinda big so we can import paper wallet directly
            fn = await file_picker(suffix=['.csv', '.txt'], min_size=51, max_size=11000,
                                    none_msg="Must contain WIF(s)", **ch)

            if not fn: return

            try:
                with CardSlot(readonly=True, **ch) as card:
                    with open(fn, 'rt') as fd:
                        got = fd.read()
            except CardMissingError:
                await needs_microsd()
                return
            except Exception as e:
                await ux_show_story('Failed to read file!\n\n%s' % e)
                return

        if not got:
            return

        dis.fullscreen("Wait...")

        # allow commas, spaces, and newlines as separators
        got = got.replace(',', ' ').split()

        saved = settings.get("wifs", [])
        len_saved = len(saved)

        try:
            new_wifs = []
            dups = 0

            for here in got:
                here = here.strip()
                if not here:
                    continue

                try:
                    kp, testnet, compressed = decode_wif(here)
                except Exception:
                    # ignore garbage text, headers, addresses, etc.
                    continue

                assert compressed, "compressed only"
                assert testnet == (chains.current_chain().ctype != "BTC"), "chain"

                sk = b2a_hex(kp.privkey()).decode()
                pk = b2a_hex(kp.pubkey().to_bytes()).decode()

                item = (pk, sk)
                if item in new_wifs:
                    # duplicate in import content
                    continue

                if item in saved:       # ignore dups
                    dups += 1
                else:
                    new_wifs.append(item)

            assert new_wifs, 'no valid WIF found' if not dups else 'duplicate WIF(s)'

            if (len_saved + len(new_wifs)) > self.MAX_ITEMS:
                await ux_show_story("Max %d items allowed in WIF Store.\n\nAttempted to import %d keys,"
                                    " while remaining WIF store capacity is only %d. Please, make room"
                                    " first." % (self.MAX_ITEMS, len(new_wifs), self.MAX_ITEMS - len_saved),
                                    title="Failure")
                return

            saved.extend(new_wifs)
            settings.set('wifs', saved)
            settings.save()
            self.update_contents()

        except Exception as e:
            await ux_show_story('Failed to import WIF.\n\n%s\n%s' % (e, problem_file_line(e)),
                                title="Failure")


def init_wif_store():
    # stored as hex strings, need load to bytes
    wifs = settings.get('wifs', [])
    if not wifs: return {}
    res = {}
    for pk, sk in wifs:
        res[a2b_hex(pk)] = a2b_hex(sk)
    return res

# EOF
