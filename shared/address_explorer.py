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
from menu import MenuSystem, MenuItem

async def choose_first_address(*a):
    # Choose from a truncated list of index 0 common addresses, remember
    # the last address the user selected and use it as the default
    from main import settings
    chain = chains.current_chain()

    with stash.SensitiveValues() as sv:

        def truncate_address(addr):
            # Truncates address to width of Coldcard, replacing middle chars with dots
            SCREEN_CHAR_WIDTH = 16 # TODO: is this defined in any constants file??
            middle = ".."
            leftover = SCREEN_CHAR_WIDTH - len(middle)
            start = addr[0:(leftover+1) // 2]
            end = addr[len(addr) - (leftover // 2):]
            return start + middle + end
                
        # Create list of choices (address_index_0, path, addr_fmt) 
        choices = []        
        for i, item in enumerate(chains.CommonDerivations, start=0):
            name, path, addr_fmt = item
            if '{coin_type}' in path:
                path = path.replace('{coin_type}', str(chain.b44_cointype))
            subpath = path.format(account=0, change=0, idx=0)
            node = sv.derive_path(subpath, register=False)
            address = chain.address(node, addr_fmt)            
            choices.append( (truncate_address(address), path, addr_fmt) )

        picked = []
	async def clicked(_1,_2,item):
	    picked.append(item.arg)
	    the_ux.pop()

	items = [
            MenuItem(address, f=clicked, arg=i)
            for i, (address, path, addr_fmt)
            in enumerate(choices)
        ]	
	menu = MenuSystem(items, chosen = settings.get('address_explorer_idx', 0))
	the_ux.push(menu)	
	await menu.interact()
    
        if picked:
            settings.put('address_explorer_idx', picked[0]) # update last clicked address
            address, path, addr_fmt = choices[picked[0]]
            return (path, addr_fmt)
	return None

async def show_n_addresses(path, addr_fmt, start, n):
    # Displays n addresses from start
    msg = "Press 1 to save to MicroSD.\n\n"
    msg += "Addresses %d to %d:\n\n" % (start, start + n - 1)
    chain = chains.current_chain()
    with stash.SensitiveValues() as sv:
        for idx in range(start, start + n):
            subpath = path.format(account=0, change=0, idx=idx)
            node = sv.derive_path(subpath, register=False)
            msg += "%s =>\n%s\n\n" % (subpath, chain.address(node, addr_fmt))

        msg += "Press OK to show more..."
        ch = await ux_show_story(msg, escape='1')
        if ch == '1': # save addresses to MicroSD signal
            return '1'
        if ch == 'x':
            if start == 0:
                return
            # go backwards in explorer
            return await show_n_addresses(path, addr_fmt, start - n, n)
        # go forwards
        return await show_n_addresses(path, addr_fmt, start + n, n)    

def generate_address_csv(path, addr_fmt, n):
    rows = []
    with stash.SensitiveValues() as sv:
        for idx in range(n):
            subpath = path.format(account=0, change=0, idx=idx)
            node = sv.derive_path(subpath, register=False)
            rows.append("%s,%s" % (subpath, chains.current_chain().address(node, addr_fmt)))    
    return '\n'.join(rows)

async def make_address_summary_file(path, addr_fmt, fname_pattern='addresses.txt'):
    # write addresses into a text file on the MicroSD
    from main import dis
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    # Get the desired number of addresses from user
    if 'x' == await ux_show_story('''\
Choose the number of addresses you want \
to save to the text file.

Press OK to continue'''):
        return
    
    picked = []
    async def clicked(_1,_2,item):
	picked.append(item.arg)
	the_ux.pop()
	    
    items = [MenuItem(str(x), f=clicked, arg=x) for x in [50, 100, 250, 500, 1000]]	
    menu = MenuSystem(items)
    the_ux.push(menu)	
    await menu.interact()
    if not picked:
        return
    
    dis.fullscreen('Generating...')
    
    # generator function
    body = generate_address_csv(path, addr_fmt, picked[0])

    total_parts = 72        # need not be precise

    # pick filename and write
    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)
            # do actual write
            with open(fname, 'wb') as fd:
                for idx, part in enumerate(body):
                    dis.progress_bar_show(idx / total_parts)
                    fd.write(part.encode())
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
The following menu shows a stub of the first address \
in common wallets you control. 

Choose the address that corresponds \
to the wallet you want to explore.

Press OK to continue'''):
        return
    
    picked = await choose_first_address()
    if picked is None:
        return
    
    path, addr_fmt = picked
    ch = await show_n_addresses(path, addr_fmt, 0, 10)
    if ch == '1':
        await make_address_summary_file(path, addr_fmt)
