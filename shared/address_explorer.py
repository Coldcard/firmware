# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# address_explorer.py
#
# Address Explorer menu functionality
#
import chains, stash
from ux import ux_show_story, the_ux, ux_confirm
from actions import goto_top_menu
from menu import MenuSystem, MenuItem, start_chooser
from public_constants import AFC_BECH32

SCREEN_CHAR_WIDTH = const(16)

async def choose_first_address(*a):
    # Choose from a truncated list of index 0 common addresses, remember
    # the last address the user selected and use it as the default
    from main import settings, dis
    chain = chains.current_chain()

    dis.fullscreen('Wait...')

    with stash.SensitiveValues() as sv:

        def truncate_address(addr):
            # Truncates address to width of screen, replacing middle chars
            middle = "-"
            leftover = SCREEN_CHAR_WIDTH - len(middle)
            start = addr[0:(leftover+1) // 2]
            end = addr[len(addr) - (leftover // 2):]
            return start + middle + end

        # Create list of choices (address_index_0, path, addr_fmt)
        choices = []
        for name, path, addr_fmt in chains.CommonDerivations:
            if '{coin_type}' in path:
                path = path.replace('{coin_type}', str(chain.b44_cointype))
            subpath = path.format(account=0, change=0, idx=0)
            node = sv.derive_path(subpath, register=False)
            address = chain.address(node, addr_fmt)
            choices.append( (truncate_address(address), path, addr_fmt) )

            dis.progress_bar_show(len(choices) / len(chains.CommonDerivations))

        stash.blank_object(node)

    picked = None

    async def clicked(_1,_2,item):
        if picked is None:
            picked = item.arg
        the_ux.pop()

    items = [MenuItem(address, f=clicked, arg=i) for i, (address, path, addr_fmt)
                                in enumerate(choices)]
    menu = MenuSystem(items)
    menu.goto_idx(settings.get('axi', 0))
    the_ux.push(menu)

    await menu.interact()

    if picked is None:
        return None

    # update last clicked address
    settings.put('axi', picked)
    address, path, addr_fmt = choices[picked]

    return (path, addr_fmt)

async def show_n_addresses(start, n, addr_fmt, get_addresses):
    # Displays n addresses from start
    from main import dis
    import version

    def make_msg(start):
        msg = ''
        if start == 0:
            msg = "Press 1 to save to MicroSD."
            if version.has_fatram:
                msg += " 4 to view QR Codes."
            msg += '\n\n'
        msg += "Addresses %d..%d:\n\n" % (start, start + n - 1)

        addrs = []
        chain = chains.current_chain()

        dis.fullscreen('Wait...')

        for i, (subpath, address) in enumerate(get_addresses(start, start + n - 1)):
            msg += "%s =>\n%s\n\n" % (subpath, address)
            idx = i + start
            dis.progress_bar_show(idx/n)

        msg += "Press 9 to see next group, 7 to go back. X to quit."

        return msg, addrs

    msg, addrs = make_msg(start)

    while 1:
        ch = await ux_show_story(msg, escape='1479')

        if ch == '1':
            # save addresses to MicroSD signal
            await make_address_summary_file(get_addresses)
            # .. continue on same screen in case they want to write to multiple cards

        if ch == 'x':
            return

        if ch == '4':
            if not version.has_fatram: continue
            from ux import show_qr_codes
            await show_qr_codes(addrs, bool(addr_fmt & AFC_BECH32), start)
            continue

        if ch == '7' and start>0:
            # go backwards in explorer
            start -= n
        elif ch == '9':
            # go forwards
            start += n

        msg, addrs = make_msg(start)

def generate_address_csv(get_addresses, n):
    # Produce CSV file contents as a generator

    yield '"Index","Payment Address","Derivation"\n'

    ch = chains.current_chain()

    for idx, (subpath, address) in enumerate(get_addresses(0, n-1)):
        yield '%d,"%s","%s"\n' % (idx, address, subpath)

async def make_address_summary_file(get_addresses, fname_pattern='addresses.txt'):
    # write addresses into a text file on the MicroSD
    from main import dis
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    # simple: always set number of addresses.
    # - takes 60 seconds, to write 250 addresses on actual hardware
    count = 250

    dis.fullscreen('Saving 0-%d' % count)

    # generator function
    body = generate_address_csv(get_addresses, count)

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
    while 1:
        ch = await ux_show_story('''\
The following menu lists the first payment address \
produced by various common wallet systems.

Choose the address that your desktop or mobile wallet \
has shown you as the first receive address.

WARNING: Please understand that exceeding the gap limit \
of your wallet, or choosing the wrong address on the next screen \
may make it very difficult to recover your funds.

Press 4 to start.''', escape='4')

        if ch == '4': break
        if ch == 'x': return

    picked = await choose_first_address()
    if picked is None:
        return

    path, addr_fmt = picked
    chain = chains.current_chain()
    def get_addresses(first, last=None):
        if last == None:
            last = first
        with stash.SensitiveValues() as sv:
            for idx in range(first, last + 1):
                subpath = path.format(account=0, change=0, idx=idx)
                node = sv.derive_path(subpath, register=False)
                yield (subpath, chain.address(node, addr_fmt))
            stash.blank_object(node)

    await show_n_addresses(0, 10, addr_fmt, get_addresses)

# EOF
