# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# address_explorer.py
#
# Address Explorer menu functionality
#
import chains, stash
from ux import ux_show_story, the_ux, ux_confirm, ux_enter_number
from actions import goto_top_menu
from menu import MenuSystem, MenuItem, start_chooser
from public_constants import AFC_BECH32, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from multisig import MultisigWallet
from uasyncio import sleep_ms
from glob import settings

def truncate_address(addr):
    # Truncates address to width of screen, replacing middle chars
    # - 16 chars screen width, so show 8 prefix, dash, and 7 of end of address
    return addr[0:8] + '-' + addr[-7:]

class KeypathMenu(MenuSystem):
    def __init__(self, path=None, nl=0):
        self.prefix = None

        if path is None:
            # Top level menu; useful shortcuts, and special case just "m"
            items = [
                     MenuItem("m/..", f=self.deeper),
                     MenuItem("m/49'/..", f=self.deeper),
                     MenuItem("m/84'/..", f=self.deeper),
                     MenuItem("m/44'/..", f=self.deeper),
                     MenuItem("m/0/{idx}", menu=self.done),
                     MenuItem("m/{idx}", menu=self.done),
                     MenuItem("m", f=self.done),
                    ]
        else:
            # drill down one layer: (nl) is the current leaf
            # - hardened choice first
            p = '%s/%d' % (path, nl)
            items = [ 
                MenuItem(p+"'/..", menu=self.deeper),
                MenuItem(p+"/..",  menu=self.deeper),
                MenuItem(p+"'", menu=self.done),
                MenuItem(p, menu=self.done),
                MenuItem(p+"'/0/{idx}", menu=self.done),
                MenuItem(p+"/0/{idx}", menu=self.done),      #useful shortcut?
                MenuItem(p+"'/{idx}", menu=self.done),
                MenuItem(p+"/{idx}", menu=self.done),
            ]

        # simple consistent truncation when needed
        max_wide = max(len(mi.label) for mi in items)
        if max_wide >= 16:
            self.prefix = p
            pl = len(p)-2
            for mi in items:
                mi.arg = mi.label
                mi.label = '-'+mi.label[pl:]

        super().__init__(items)

    def late_draw(self, dis):
        # replace bottom partial menu line w/ tiny text
        if not self.prefix: return
        from display import FontTiny
        y = 64 - 8
        dis.clear_rect(0, y, dis.WIDTH, 8)
        dis.text(-1, y+4, self.prefix, FontTiny, invert=False)

    def done(self, _1, menu_idx, item):
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

    def deeper(self, _1, _2, item):
        val = item.arg or item.label
        assert val.endswith('/..')
        cpath = val[:-3]
        nl = await ux_enter_number('%s/' % cpath, 0x7fffffff)
        return KeypathMenu(cpath, nl)

class PickAddrFmtMenu(MenuSystem):
    def __init__(self, path, parent):
        self.parent = parent
        items = [
            MenuItem("Classic P2PKH", f=self.done, arg=(path, AF_CLASSIC)), 
            MenuItem("Segwit P2WPKH", f=self.done, arg=(path, AF_P2WPKH)), 
            MenuItem("P2SH-P2WPKH", f=self.done, arg=(path, AF_P2WPKH_P2SH)), 
        ]
        super().__init__(items)
        if path.startswith("m/84'"):
            self.goto_idx(1)
        if path.startswith("m/49'"):
            self.goto_idx(2)

    def done(self, _1, _2, item):
        the_ux.pop()
        await self.parent.got_custom_path(*item.arg)


class AddressListMenu(MenuSystem):

    def __init__(self):
        self.account_num = 0
        super().__init__([])

    async def render(self):
        # Choose from a truncated list of index 0 common addresses, remember
        # the last address the user selected and use it as the default
        from glob import dis
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

                deriv = path.format(account=self.account_num, change=0, idx=0)
                node = sv.derive_path(deriv, register=False)
                address = chain.address(node, addr_fmt)
                choices.append( (truncate_address(address), path, addr_fmt) )

                dis.progress_bar_show(len(choices) / len(chains.CommonDerivations))

            stash.blank_object(node)

        items = [MenuItem(address, f=self.pick_single, arg=(path, addr_fmt)) 
                        for i, (address, path, addr_fmt) in enumerate(choices)]

        # some other choices
        if self.account_num == 0:
            items.append(MenuItem("Account Number", f=self.change_account))
            items.append(MenuItem("Custom Path", menu=self.make_custom))

            # if they have MS wallets, add those next
            for ms in MultisigWallet.iter_wallets():
                if not ms.addr_fmt: continue
                items.append(MenuItem(ms.name, f=self.pick_multisig, arg=ms))
        else:
            items.append(MenuItem("Account: %d" % self.account_num, f=self.change_account))

        self.goto_idx(settings.get('axi', 0))      # weak

        self.replace_items(items)

    async def change_account(self, *a):
        self.account_num = await ux_enter_number('Account Number:', 9999) or 0
        await self.render()

    async def pick_single(self, _1, menu_idx, item):
        settings.put('axi', menu_idx)       # update last clicked address
        path, addr_fmt = item.arg
        await self.show_n_addresses(path, addr_fmt, None)

    async def pick_multisig(self, _1, menu_idx, item):
        ms_wallet = item.arg
        settings.put('axi', menu_idx)       # update last clicked address
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
Press 3 if you really understand and accept these risks.
''' % path, title='MUCH DANGER', escape='3')

        if ch != '3': return

        n = 10 if 'idx' in path else 1
        await self.show_n_addresses(path, addr_fmt, None, n=n)

    async def show_n_addresses(self, path, addr_fmt, ms_wallet, start=0, n=10):
        # Displays n addresses by replacing {idx} in path format.
        # - also for other {account} numbers
        # - or multisig case
        from glob import dis, NFC
        import version

        def make_msg():
            msg = ''
            if n > 1:
                if start == 0:
                    msg = "Press 1 to save into a file."
                    if version.has_fatram and not ms_wallet:
                        msg += " 2 to view QR Codes."
                    if NFC:
                        msg += " Press 3 to share over NFC."
                    msg += '\n\n'
                msg += "Addresses %d..%d:\n\n" % (start, start + n - 1)
            else:
                # single address, from deep path given by user
                msg += "Showing single address."
                if version.has_fatram:
                    msg += " Press 2 to view QR Codes."
                if NFC:
                    msg += " Press 3 to share over NFC."
                msg += '\n\n'


            addrs = []
            chain = chains.current_chain()

            dis.fullscreen('Wait...')

            if ms_wallet:
                # IMPORTANT safety feature: never show complete address
                # but show enough they can verify addrs shown elsewhere.
                # - makes a redeem script
                # - converts into addr
                # - assumes 0/0 is first address.
                for (i, paths, addr, script) in ms_wallet.yield_addresses(start, n):
                    if i == 0 and ms_wallet.N <= 4:
                        msg += '\n'.join(paths) + '\n =>\n'
                    else:
                        msg += '.../0/%d =>\n' % i

                    addrs.append(addr)
                    msg += truncate_address(addr) + '\n\n'
                    dis.progress_bar_show(i/n)

            else:
                # single-singer wallets

                with stash.SensitiveValues() as sv:

                    for idx in range(start, start + n):
                        deriv = path.format(account=self.account_num, change=0, idx=idx)
                        node = sv.derive_path(deriv, register=False)
                        addr = chain.address(node, addr_fmt)
                        addrs.append(addr)

                        msg += "%s =>\n%s\n\n" % (deriv, addr)

                        dis.progress_bar_show(idx/n)

                    stash.blank_object(node)

            if n > 1:
                msg += "Press 9 to see next group, 7 to go back. X to quit."

            return msg, addrs

        msg, addrs = make_msg()

        while 1:
            ch = await ux_show_story(msg, escape='12379')

            if ch == 'x':
                return

            elif ch == '1':
                # save addresses to MicroSD/VirtDisk
                await make_address_summary_file(path, addr_fmt, ms_wallet, self.account_num,
                                                            count=(250 if n!=1 else 1))
                # .. continue on same screen in case they want to write to multiple cards
                continue

            elif ch == '2':
                # switch into a mode that shows them as QR codes
                if not version.has_fatram or ms_wallet:
                    # requires mk3 and not multisig
                    continue

                from ux import show_qr_codes
                await show_qr_codes(addrs, bool(addr_fmt & AFC_BECH32), start)
                continue

            elif ch == '3' and NFC:
                # share table over NFC
                if n > 1:
                    await NFC.share_text('\n'.join(addrs))
                else:
                    await NFC.share_deposit_address(addrs[self.idx])
                continue

            elif ch == '7' and start>0:
                # go backwards in explorer
                start -= n
            elif ch == '9':
                # go forwards
                start += n
            else:
                continue        # 3 in non-NFC mode

            msg, addrs = make_msg()

def generate_address_csv(path, addr_fmt, ms_wallet, account_num, n, start=0):
    # Produce CSV file contents as a generator

    if ms_wallet:
        from ubinascii import hexlify as b2a_hex

        # For multisig, include redeem script and derivation for each signer
        yield '"' + '","'.join(['Index', 'Payment Address',
                                    'Redeem Script (%d of %d)' % (ms_wallet.M, ms_wallet.N)] 
                                    + (['Derivation'] * ms_wallet.N)) + '"\n'

        for (idx, derivs, addr, script) in ms_wallet.yield_addresses(start, n):
            ln = '%d,"%s","%s","' % (idx, addr, b2a_hex(script).decode())
            ln += '","'.join(derivs)
            ln += '"\n'

            yield ln

        return

    yield '"Index","Payment Address","Derivation"\n'
    ch = chains.current_chain()

    with stash.SensitiveValues() as sv:
        for idx in range(start, start+n):
            deriv = path.format(account=account_num, change=0, idx=idx)
            node = sv.derive_path(deriv, register=False)

            yield '%d,"%s","%s"\n' % (idx, ch.address(node, addr_fmt), deriv)

        stash.blank_object(node)

async def make_address_summary_file(path, addr_fmt, ms_wallet, account_num, count=250):
    # write addresses into a text file on the MicroSD/VirtDisk
    from glob import dis
    from files import CardSlot, CardMissingError, needs_microsd

    # simple: always set number of addresses.
    # - takes 60 seconds to write 250 addresses on actual hardware

    dis.fullscreen('Saving 0-%d' % count)
    fname_pattern='addresses.csv'

    # generator function
    body = generate_address_csv(path, addr_fmt, ms_wallet, account_num, count)

    # pick filename and write
    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wb') as fd:
                for idx, part in enumerate(body):
                    fd.write(part.encode())

                    if idx % 5 == 0:
                        dis.progress_bar_show(idx / count)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''Address summary file written:\n\n%s''' % nice
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

Press 4 to start or 6 to hide this message forever.''', escape='46')

        if ch == '4': break
        if ch == '6':
            settings.set('axskip', True)
            break
        if ch == 'x': return

    m = AddressListMenu()
    await m.render()        # slow

    the_ux.push(m)


# EOF
