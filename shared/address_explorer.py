# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# address_explorer.py
#
# Address Explorer menu functionality
#
import chains, stash, version
from ux import ux_show_story, the_ux, ux_enter_bip32_index
from ux import export_prompt_builder, import_export_prompt_decode
from menu import MenuSystem, MenuItem
from public_constants import AFC_BECH32, AFC_BECH32M, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from multisig import MultisigWallet
from uasyncio import sleep_ms
from uhashlib import sha256
from ubinascii import hexlify as b2a_hex
from glob import settings
from auth import write_sig_file
from utils import addr_fmt_label, censor_address
from charcodes import KEY_QR, KEY_NFC, KEY_PAGE_UP, KEY_PAGE_DOWN, KEY_HOME, KEY_LEFT, KEY_RIGHT
from charcodes import KEY_CANCEL

def truncate_address(addr):
    # Truncates address to width of screen, replacing middle chars
    if not version.has_qwerty:
        # - 16 chars screen width
        # - but 2 lost at left (menu arrow, corner arrow)
        # - want to show not truncated on right side
        return addr[0:6] + '⋯' + addr[-6:]
    else:
        # tons of space on Q1
        return addr[0:12] + '⋯' + addr[-12:]

class KeypathMenu(MenuSystem):
    def __init__(self, path=None, nl=0):
        self.prefix = None

        if path is None:
            # Top level menu; useful shortcuts, and special case just "m"
            items = [
                MenuItem("m/⋯", f=self.deeper),
                MenuItem("m/44h/⋯", f=self.deeper),
                MenuItem("m/49h/⋯", f=self.deeper),
                MenuItem("m/84h/⋯", f=self.deeper),
                MenuItem("m/86h/⋯", f=self.deeper),
                MenuItem("m/0/{idx}", menu=self.done),
                MenuItem("m/{idx}", menu=self.done),
                MenuItem("m", f=self.done),
            ]
        else:
            # drill down one layer: (nl) is the current leaf
            # - hardened choice first
            p = '%s/%d' % (path, nl)
            items = [ 
                MenuItem(p+"h/⋯", menu=self.deeper),
                MenuItem(p+"/⋯",  menu=self.deeper),
                MenuItem(p+"h", menu=self.done),
                MenuItem(p, menu=self.done),
                MenuItem(p+"h/0/{idx}", menu=self.done),
                MenuItem(p+"/0/{idx}", menu=self.done),      #useful shortcut?
                MenuItem(p+"h/{idx}", menu=self.done),
                MenuItem(p+"/{idx}", menu=self.done),
            ]

        # simple consistent truncation when needed
        max_wide = max(len(mi.label) for mi in items)
        if max_wide >= (32 if version.has_qwerty else 16):
            if version.has_qwerty:
                pl = p[0:p.rfind('/')].rfind('/')
            else:
                self.prefix = p         # displayed on mk4 only
                pl = len(p)-2
            for mi in items:
                mi.arg = mi.label
                mi.label = '⋯'+mi.label[pl:]

        super().__init__(items)

    def late_draw(self, dis):
        # replace bottom partial menu line w/ tiny text
        if not self.prefix: return
        if dis.has_lcd: return      # no tiny font

        from display import FontTiny
        y = 64 - 8
        dis.clear_rect(0, y, dis.WIDTH, 8)
        dis.text(-1, y+4, self.prefix, FontTiny, invert=False)

    async def done(self, _1, menu_idx, item):
        final_path = item.arg or item.label
        self.chosen = menu_idx
        self.show()
        await sleep_ms(100)     # visual feedback that we changed it

        # pop entire stack of path choosing
        while 1:
            top = the_ux.top_of_stack()
            if isinstance(top, KeypathMenu):
                the_ux.pop()
                continue
            assert isinstance(top, AddressListMenu)
            break

        return PickAddrFmtMenu(final_path, top)

    async def deeper(self, _1, _2, item):
        val = item.arg or item.label
        assert val.endswith('/⋯')
        cpath = val[:-2]
        nl = await ux_enter_bip32_index('%s/' % cpath, unlimited=True)
        return KeypathMenu(cpath, nl)

class PickAddrFmtMenu(MenuSystem):
    def __init__(self, path, parent):
        self.parent = parent
        items = [
            MenuItem(addr_fmt_label(af), f=self.done, arg=(path, af))
            for af in [AF_CLASSIC, AF_P2WPKH, AF_P2TR, AF_P2WPKH_P2SH]
        ]
        super().__init__(items)
        if path.startswith("m/84h"):
            self.goto_idx(1)
        if path.startswith("m/49h"):
            self.goto_idx(2)

    async def done(self, _1, _2, item):
        the_ux.pop()
        await self.parent.got_custom_path(*item.arg)


class ApplicationsMenu(MenuSystem):
    def __init__(self, parent):
        self.parent = parent
        self.chain = str(chains.current_chain().b44_cointype) + "h"
        items = [
            MenuItem("Samourai", menu=SamouraiAppMenu(self)),
            MenuItem("Wasabi", f=self.done,
                     arg=("m/84h/" + self.chain + "/0h/{change}/{idx}", AF_P2WPKH)),
        ]
        super().__init__(items)

    async def done(self, _1, _2, item):
        path = item.arg[0]
        addr_fmt = item.arg[1]
        await self.parent.show_n_addresses(path, addr_fmt, None, n=10, allow_change=True)


class SamouraiAppMenu(MenuSystem):
    def __init__(self, parent):
        self.parent = parent
        chain = self.parent.chain
        items = [
            MenuItem("Post-mix", f=self.parent.done,
                     arg=("m/84h/" + chain + "/2147483646h/{change}/{idx}", AF_P2WPKH)),
            MenuItem("Pre-mix", f=self.parent.done,
                     arg=("m/84h/" + chain + "/2147483645h/{change}/{idx}", AF_P2WPKH)),
            # MenuItem("Bad Bank", f=self.done,         # not released yet
            #          arg=("m/84h/" + hardened_chain + "/2147483644h/{change}/{idx}", AF_P2WPKH)),
        ]
        super().__init__(items)


class AddressListMenu(MenuSystem):

    def __init__(self):
        self.account_num = 0
        self.start = 0
        super().__init__([])

    async def render(self):
        # Choose from a truncated list of index 0 common addresses, remember
        # the last address the user selected and use it as the default
        from glob import dis, settings
        chain = chains.current_chain()

        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:

            # Create list of choices (address_index_0, path, addr_fmt)
            choices = []
            for name, path, addr_fmt in chains.CommonDerivations:
                if '{coin_type}' in path:
                    path = path.replace('{coin_type}', str(chain.b44_cointype))

                if self.account_num != 0 and '{account}' not in path:
                    # skip derivations that are not affected by account number
                    continue

                deriv = path.format(account=self.account_num, change=0, idx=self.start)
                node = sv.derive_path(deriv, register=False)
                address = chain.address(node, addr_fmt)
                choices.append( (truncate_address(address), path, addr_fmt) )

                dis.progress_sofar(len(choices), len(chains.CommonDerivations))

            stash.blank_object(node)

        items = []
        indent = ' ↳ ' if version.has_qwerty else '↳'
        for i, (address, path, addr_fmt) in enumerate(choices):
            axi = address[-4:]  # last 4 address characters
            items.append(MenuItem(addr_fmt_label(addr_fmt), f=self.pick_single,
                                  arg=(path, addr_fmt, axi)))
            items.append(MenuItem(indent+address, f=self.pick_single,
                                  arg=(path, addr_fmt, axi)))

        # some other choices
        if self.account_num == 0:
            items.append(MenuItem("Applications", menu=ApplicationsMenu(self)))
            items.append(MenuItem("Account Number", f=self.change_account))
            items.append(MenuItem("Custom Path", menu=self.make_custom))

            # if they have MS wallets, add those next
            for ms in MultisigWallet.iter_wallets():
                if not ms.addr_fmt: continue
                items.append(MenuItem(ms.name, f=self.pick_multisig, arg=ms))
        else:
            items.append(MenuItem("Account: %d" % self.account_num, f=self.change_account))

        if settings.get('aei', False) or self.start:
            # optional feature: allow override of starting index
            _mtxt = 'Start Idx: ' if version.has_qwerty or self.start < 100000 else 'Start:'
            _mtxt += str(self.start)
            items.append(MenuItem(_mtxt, f=self.change_start_idx))

        self.replace_items(items)
        axi = settings.get('axi', 0)
        if isinstance(axi, str):
            ok = self.goto_label(axi)
            if not ok:
                self.goto_idx(0)
        else:
            self.goto_idx(axi)

    async def change_account(self, *a):
        self.account_num = await ux_enter_bip32_index('Account Number:') or 0
        await self.render()

    async def change_start_idx(self, *a):
        self.start = await ux_enter_bip32_index("Start index:", unlimited=True)
        await self.render()

    async def pick_single(self, _1, _2, item):
        path, addr_fmt, axi = item.arg
        settings.put('axi', axi)  # update last clicked address
        await self.show_n_addresses(path, addr_fmt, None)

    async def pick_multisig(self, _1, _2, item):
        ms_wallet = item.arg
        settings.put('axi', item.label)       # update last clicked address
        await self.show_n_addresses(None, None, ms_wallet)

    async def make_custom(self, *a):
        # picking a custom derivation path: makes a tree of menus, with chance
        # to enter number at each level, plus hard/not hardened
        return KeypathMenu()

    async def got_custom_path(self, path, addr_fmt):
        # going to show addrs from a fully custom path, risky.
        ch = await ux_show_story('''\
Now you will see the address for custom derivation path:\n\n%s\n\n\
DO NOT DEPOSIT to this address unless you are 100%% certain that some other software will \
be able to generate a valid PSBT for signing the UTXO, \
and also that specific path details will not get lost.\n
This is for gurus only! You may have created a Bitcoin blackhole.\n
Press (3) if you really understand and accept these risks.
''' % path, title='MUCH DANGER', escape='3')

        if ch != '3': return

        n = 10 if 'idx' in path else None
        await self.show_n_addresses(path, addr_fmt, None, n=n, allow_change=False)

    async def show_n_addresses(self, path, addr_fmt, ms_wallet, start=0, n=10, allow_change=True):
        # Displays n addresses by replacing {idx} in path format.
        # - also for other {account} numbers
        # - or multisig case
        from glob import dis, NFC
        from wallet import MAX_BIP32_IDX

        start = self.start

        def make_msg(change=0):
            # Build message and CTA about export, plus the actual addresses.
            if n:
                msg = "Addresses %d⋯%d:\n\n" % (start, min(start + n - 1, MAX_BIP32_IDX))
            else:
                # single address, from deep path given by user
                msg = "Showing single address.\n\n"

            addrs = []

            dis.fullscreen('Wait...')

            if ms_wallet:
                # IMPORTANT safety feature: never show complete address
                # but show enough they can verify addrs shown elsewhere.
                # - makes a redeem script
                # - converts into addr
                # - assumes 0/0 is first address.
                for idx, addr, paths, script in ms_wallet.yield_addresses(start, n, change):
                    addrs.append(censor_address(addr))

                    if idx == 0 and ms_wallet.N <= 4:
                        msg += '\n'.join(paths) + '\n =>\n'
                    else:
                        msg += '⋯/%d/%d =>\n' % (change, idx)

                    msg += truncate_address(addr) + '\n\n'
                    dis.progress_sofar(idx-start+1, n)

            else:
                # single-signer wallets
                from wallet import MasterSingleSigWallet
                main = MasterSingleSigWallet(addr_fmt, path, self.account_num)

                from ownership import OWNERSHIP
                OWNERSHIP.note_wallet_used(addr_fmt, self.account_num)

                for idx, addr, deriv in main.yield_addresses(start, n, change if allow_change else None):
                    addrs.append(addr)
                    msg += "%s =>\n%s\n\n" % (deriv, addr)
                    dis.progress_sofar(idx-start+1, n or 1)

            # export options
            k0 = 'to show change addresses' if allow_change and change == 0 else None
            export_msg, escape = export_prompt_builder('address summary file',
                                                       no_qr=bool(ms_wallet), key0=k0,
                                                       force_prompt=True)
            if version.has_qwerty:
                escape += KEY_LEFT+KEY_RIGHT+KEY_HOME+KEY_PAGE_UP+KEY_PAGE_DOWN
            else:
                escape += "79"

            if export_msg and start == self.start:
                # Show CTA about export at bottom, and only for first page -- it can be huge!
                msg += export_msg
                if n:
                    msg += '\n\n'
            if n:
                msg += "Press RIGHT to see next group, LEFT to go back. X to quit."

            return msg, addrs, escape

        msg, addrs, escape = make_msg()
        change = 0
        while 1:
            ch = await ux_show_story(msg, escape=escape)

            choice = import_export_prompt_decode(ch)

            if choice == KEY_CANCEL:
                return

            if isinstance(choice, dict):
                # save addresses to MicroSD/VirtDisk
                c = n if n is None else 250
                if c and (self.start + c) > MAX_BIP32_IDX:
                    c = MAX_BIP32_IDX - self.start + 1
                await make_address_summary_file(path, addr_fmt, ms_wallet,
                                        self.account_num, count=c, start=self.start,
                                        change=change if allow_change else None, **choice)

                # continue on same screen in case they want to write to multiple cards

            elif choice == KEY_QR:
                # switch into a mode that shows them as QR codes
                if ms_wallet:
                    # requires not multisig
                    continue

                from ux import show_qr_codes
                is_alnum = bool(addr_fmt & (AFC_BECH32 | AFC_BECH32M))
                await show_qr_codes(addrs, is_alnum, start)

                continue

            elif NFC and (choice == KEY_NFC):
                # share table over NFC
                if len(addrs) == 1:
                    await NFC.share_text(addrs[0])
                else:
                    await NFC.share_text('\n'.join(addrs))

                continue

            elif choice == '0' and allow_change:
                change = 1
            elif n is None:
                # makes no sense to do any of below, showing just single address
                continue
            elif ch in (KEY_LEFT+"7"):
                # go backwards in explorer
                if start - n < 0:
                    if start == 0:
                        continue
                    start = 0
                else:
                    start -= n
            elif ch in (KEY_RIGHT+"9"):
                # go forwards
                if start + n > MAX_BIP32_IDX:
                    continue
                else:
                    start += n
            elif ch == KEY_HOME:
                start = 0
            else:
                continue        # 3 in non-NFC mode

            msg, addrs, escape = make_msg(change)

def generate_address_csv(path, addr_fmt, ms_wallet, account_num, n, start=0, change=0):
    # Produce CSV file contents as a generator
    # - maybe cache internally
    from ownership import OWNERSHIP

    if ms_wallet:
        # For multisig, include redeem script and derivation for each signer
        yield '"' + '","'.join(['Index', 'Payment Address', 'Redeem Script']
                    + ['Derivation (%d of %d)' % (i+1, ms_wallet.N) for i in range(ms_wallet.N)]
                    ) + '"\n'

        if (start == 0) and (n > 100) and change in (0, 1):
            saver = OWNERSHIP.saver(ms_wallet, change, start)
        else:
            saver = None

        for (idx, addr, derivs, script) in ms_wallet.yield_addresses(start, n, change_idx=change):
            if saver:
                saver(addr)

            # policy choice: never provide a complete multisig address to user.
            addr = censor_address(addr)

            ln = '%d,"%s","%s","' % (idx, addr, b2a_hex(script).decode())
            ln += '","'.join(derivs)
            ln += '"\n'

            yield ln

        if saver:
            saver(None)     # close file

        return

    # build the "master" wallet based on indicated preferences
    from wallet import MasterSingleSigWallet
    main = MasterSingleSigWallet(addr_fmt, path, account_num)

    if n and (start == 0) and (n > 100) and change in (0, 1):
        saver = OWNERSHIP.saver(main, change, start)
    else:
        saver = None

    yield '"Index","Payment Address","Derivation"\n'
    for (idx, addr, deriv) in main.yield_addresses(start, n, change_idx=change):
        if saver:
            saver(addr)

        yield '%d,"%s","%s"\n' % (idx, addr, deriv)

    if saver:
        saver(None)     # close

async def make_address_summary_file(path, addr_fmt, ms_wallet, account_num,
                                    start=0, count=250, change=0, **save_opts):

    # write addresses into a text file on the MicroSD/VirtDisk
    from glob import dis
    from files import CardSlot, CardMissingError, needs_microsd

    # simple: always set number of addresses.
    # - takes 60 seconds to write 250 addresses on actual hardware

    dis.fullscreen('Saving 0-%d' % (count or 1))
    fname_pattern='addresses.csv'

    # generator function
    body = generate_address_csv(path, addr_fmt, ms_wallet, account_num, count,
                                start=start, change=change)

    # pick filename and write
    try:
        with CardSlot(**save_opts) as card:
            fname, nice = card.pick_filename(fname_pattern)
            h = sha256()
            # do actual write
            with open(fname, 'wb') as fd:
                for idx, part in enumerate(body):
                    ep = part.encode()
                    fd.write(ep)
                    if not ms_wallet:
                        h.update(ep)

                    dis.progress_sofar(idx, count or 1)

            sig_nice = None
            if not ms_wallet and addr_fmt != AF_P2TR:
                derive = path.format(account=account_num, change=change, idx=start)  # first addr
                sig_nice = write_sig_file([(h.digest(), fname)], derive, addr_fmt)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        from utils import problem_file_line
        await ux_show_story('Failed to write!\n\n\n%s\n%s' % (e, problem_file_line(e)))
        return

    msg = '''Address summary file written:\n\n%s''' % nice
    if sig_nice:
        msg += "\n\nAddress signature file written:\n\n%s" % sig_nice
    await ux_show_story(msg)

async def address_explore(*a):
    # explore addresses based on derivation path chosen
    # by proxy external index=0 address

    while not settings.get('axskip', False):
        ch = await ux_show_story('''\
The following menu lists the first payment address \
produced by various common wallet systems.

Choose the address that your desktop or mobile wallet \
has shown you as the first receive address.

WARNING: Please understand that exceeding the gap limit \
of your wallet, or choosing the wrong address on the next screen \
may make it very difficult to recover your funds.

Press (4) to start or (6) to hide this message forever.''', escape='46')

        if ch == '4': break
        if ch == '6':
            settings.set('axskip', True)
            break
        if ch == 'x': return

    m = AddressListMenu()
    await m.render()        # slow
    return m


# EOF
