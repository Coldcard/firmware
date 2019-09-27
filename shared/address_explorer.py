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

async def show_n_addresses(path, addr_fmt, start, n):
    # Displays n addresses from start
    from main import dis

    def make_msg(start):
        msg = "Press 1 to save to MicroSD.\n\n"
        msg += "Addresses %d..%d:\n\n" % (start, start + n - 1)

        chain = chains.current_chain()

        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:

            for idx in range(start, start + n):
                subpath = path.format(account=0, change=0, idx=idx)
                node = sv.derive_path(subpath, register=False)
                msg += "%s =>\n%s\n\n" % (subpath, chain.address(node, addr_fmt))

                dis.progress_bar_show(idx/n)

        msg += "Press 9 to see next group, 7 to go back, X to quit."

        return msg

    msg = make_msg(start)

    while 1:
            ch = await ux_show_story(msg, escape='179')

            if ch == '1':
                # save addresses to MicroSD signal
                await make_address_summary_file(path, addr_fmt)
                # .. continue on same screen in case they want to write to multiple cards

            if ch == 'x':
                return

            if ch == '7' and start>0:
                # go backwards in explorer
                start -= n
                msg = make_msg(start)

            if ch == '9':
                # go forwards
                start += n
                msg = make_msg(start)

def generate_address_csv(path, addr_fmt, n):
    rows = []
    yield '"Derivation","Payment Address"\n'
    with stash.SensitiveValues() as sv:
        for idx in range(n):
            subpath = path.format(account=0, change=0, idx=idx)
            node = sv.derive_path(subpath, register=False)

            yield '"%s","%s"\n' % (subpath, chains.current_chain().address(node, addr_fmt))

async def make_address_summary_file(path, addr_fmt, fname_pattern='addresses.txt'):
    # write addresses into a text file on the MicroSD
    from main import dis
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    # simple: always set number of addresses.
    # - takes 60 seconds, to write 250 addresses on actual hardware
    count = 250

    dis.fullscreen('Saving 0-%d' % count)

    # generator function
    body = generate_address_csv(path, addr_fmt, count)

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
    if 'x' == await ux_show_story('''\
The following menu lists the first payment address \
produced by various common wallet systems.

Choose the address that your desktop or mobile wallet \
has shown you as the first receive address.'''):
        return

    picked = await choose_first_address()
    if picked is None:
        return

    path, addr_fmt = picked

    await show_n_addresses(path, addr_fmt, 0, 10)

# EOF
