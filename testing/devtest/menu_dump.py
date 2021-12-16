# run manually with:
#   best inside 'headless.py -i' after a ^C
#   execfile('../../testing/devtest/menu_dump.py')
# - or use test case:
#   py.test test_ux.py -k test_dump_menutree
# - result in 
#   ../unix/work/menudump.txt

async def doit():
    async def dump_menu(fd, m, label, indent, menu_item=None, menu_idx=0):
        from menu import MenuItem, ToggleMenuItem
        from seed import WordNestMenu
        from multisig import MultisigMenu
        from trick_pins import TrickPinMenu
        from users import UsersMenu
        from flow import which_pin_menu, has_secrets, nfc_enabled, vdisk_enabled
        from flow import hsm_policy_available

        print("%s%s"% (indent, label), file=fd)

        if label == 'PIN Options':
            # n/a for mk4
            m = []

        # recursing into functions that do stuff doesn't work well, skip
        avoid = {'Clone Coldcard', 'Debug Functions'}
        if any(label.startswith(a) for a in avoid):
            return

        if callable(m):
            print("Calling: %r (%s)" % (m, label))
            m = await m(m, 0, menu_item)
            print("Done")

        m = m or []

        indent += '  '


        if isinstance(m, WordNestMenu):
            print('%s[SEED WORD MENUS]' % indent, file=fd)
            return
        for xm in [TrickPinMenu, MultisigMenu, UsersMenu]:
            if isinstance(m, xm):
                m = [i.label for i in m.items]
                break


        for menu_idx, mi in enumerate(m):

            if isinstance(mi, str):
                here = mi
            elif isinstance(mi, MenuItem):
                here = mi.label

                pred = getattr(mi, 'predicate', False)
                if pred == has_secrets:
                    pass        #here += ' [WHEN SEED PRESENT]'
                elif pred == nfc_enabled:
                    here += ' [IF NFC ENABLED]'
                elif pred == vdisk_enabled:
                    here += ' [IF VIRTDISK ENABLED]'
                elif pred == hsm_policy_available:
                    here += ' [IF HSM POLICY]'
                elif 'lambda' in repr(pred):
                    pass
                elif pred:
                    here += ' [MAYBE]'

                # NOTE: most attributes not present unless used
                funct = getattr(mi, 'next_func', None)

                if funct:
                    try:
                        rv = await funct(m, menu_idx, mi)
                        if isinstance(rv, MenuSystem):
                            await dump_menu(fd, rv, here, indent, menu_item=mi, menu_idx=menu_idx)
                    except:
                        pass

                next_menu = getattr(mi, 'next_menu', None)
                chooser = getattr(mi, 'chooser', None)

                if next_menu:
                    await dump_menu(fd, next_menu, here, indent, menu_item=mi, menu_idx=menu_idx)
                    continue
                elif chooser:
                    mx = list(chooser())[1]
                    await dump_menu(fd, mx, here, indent)
                    continue

                if isinstance(mi, ToggleMenuItem):
                    await dump_menu(fd, mi.choices, here, indent, menu_idx=menu_idx)
                    continue

            print('%s%s' % (indent, here), file=fd)
            

    from flow import EmptyWallet, NormalSystem, FactoryMenu, VirginSystem

    with open('menudump.txt', 'wt') as fd:
        for nm, m in [
            ('No PIN Set', VirginSystem),
            ('Empty Wallet', EmptyWallet),
            ('Normal', NormalSystem),
            ('Factory Mode', FactoryMenu),
        ]:
            await dump_menu(fd, m, nm, '')
            print('---\n', file=fd)

    print("DONE: check menudump.txt file")


import uasyncio
uasyncio.run(doit())
