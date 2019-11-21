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

async def show_n_addresses(path, addr_fmt, start, n):
    # Displays n addresses from start
    from main import dis
    import version

    def make_msg(start):
        msg = "Press 1 to save to MicroSD.\n\n"
        msg += "Addresses %d..%d:\n\n" % (start, start + n - 1)

        addrs = []
        chain = chains.current_chain()

        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:

            for idx in range(start, start + n):
                subpath = path.format(account=0, change=0, idx=idx)
                node = sv.derive_path(subpath, register=False)
                addr = chain.address(node, addr_fmt)
                addrs.append(addr)

                msg += "%s =>\n%s\n\n" % (subpath, addr)

                dis.progress_bar_show(idx/n)

            stash.blank_object(node)

        if version.has_fatram:
            msg += "Press 4 to view QR Code. "

        msg += "Press 9 to see next group, 7 to go back. X to quit."

        return msg, addrs

    msg, addrs = make_msg(start)

    while 1:
        ch = await ux_show_story(msg, escape='1479')

        if ch == '1':
            # save addresses to MicroSD signal
            await make_address_summary_file(path, addr_fmt)
            # .. continue on same screen in case they want to write to multiple cards

        if ch == 'x':
            return

        if ch == '4':
            if not version.has_fatram: continue
            await show_address_qr(addrs, (addr_fmt & AFC_BECH32), start)
            continue

        if ch == '7' and start>0:
            # go backwards in explorer
            start -= n
        elif ch == '9':
            # go forwards
            start += n

        msg, addrs = make_msg(start)

def generate_address_csv(path, addr_fmt, n):
    # Produce CSV file contents as a generator

    yield '"Index","Payment Address","Derivation"\n'

    ch = chains.current_chain()

    with stash.SensitiveValues() as sv:
        for idx in range(n):
            subpath = path.format(account=0, change=0, idx=idx)
            node = sv.derive_path(subpath, register=False)

            yield '%d,"%s","%s"\n' % (idx, ch.address(node, addr_fmt), subpath)

        stash.blank_object(node)

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

    await show_n_addresses(path, addr_fmt, 0, 10)


async def show_address_qr(addrs, is_segwit, start_n):
    # show a QR code for the address. can only work on Mk3
    # Version 2 would be nice, but can't hold what we need, even at min error correction,
    # so we are forced into version 3 = 29x29 pixels
    # - see <https://www.qrcode.com/en/about/version.html>
    # - to display 29x29 pixels, we have to double them up: 58x58
    # - not really providing enough space around it
    # - inverted QR (black/white swap) still readable by scanners, altho wrong

    from utils import imported
    from display import FontSmall, FontTiny
    import uQR as uqr
    from main import dis

    idx = 0             # start with first address
    invert = False      # looks better, but neither mode is ideal

    addr = addrs[idx]

    def render(addr):
        dis.busy_bar(True)
        with imported('uQR') as uqr:
            if is_segwit:
                # targeting 'alpha numeric' mode, typical len is 42
                ec = uqr.ERROR_CORRECT_Q
                assert len(addr) <= 47
            else:
                # has to be 'binary' mode, altho shorter msg, typical 34-36
                ec = uqr.ERROR_CORRECT_M
                assert len(addr) <= 42

            q = uqr.QRCode(version=3, box_size=1, border=0, mask_pattern=3, error_correction=ec)
            if is_segwit:
                here = uqr.QRData(addr.upper().encode('ascii'),
                                        mode=uqr.MODE_ALPHA_NUM, check_data=False)
            else:
                here = uqr.QRData(addr.encode('ascii'), mode=uqr.MODE_8BIT_BYTE, check_data=False)
            q.add_data(here)
            q.make(fit=False)

            return q.get_matrix()

    data = render(addr)

    def redraw():
        dis.clear()

        w = 29          # because version=3
        XO,YO = 7, 3    # offsets

        if not invert:
            dis.dis.fill_rect(XO-YO, 0, 64, 64, 1)

        for x in range(w):
            for y in range(w):
                px = data[x][y]
                X = (x*2) + XO
                Y = (y*2) + YO
                dis.dis.fill_rect(X,Y, 2,2, px if invert else (not px))

        x, y = 73, 0 if is_segwit else 2
        ll = 7      # per line
        for i in range(0, len(addr), ll):
            dis.text(x, y, addr[i:i+ll], FontSmall)
            y += 10 if is_segwit else 12

        if not invert:
            # show path number, very tiny
            ai = str(start_n + idx)
            if len(ai) == 1:
                dis.text(0, 30, ai[0], FontTiny)
            else:
                dis.text(0, 27, ai[0], FontTiny)
                dis.text(0, 27+7, ai[1], FontTiny)

        dis.busy_bar(False)     # includes show

    redraw()

    from ux import ux_wait_keyup

    while 1:
        ch = await ux_wait_keyup()

        if ch == '1':
            invert = not invert
            redraw()
            continue
        elif ch in 'xy':
            return
        if ch == '5' or ch == '7':
            if idx > 0:
                idx -= 1
        elif ch == '8' or ch == '9':
            if idx != len(addrs)-1:
                idx += 1
        
        addr = addrs[idx]
        data = render(addr)
        redraw()

# EOF
