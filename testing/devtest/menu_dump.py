
def doit():
    def dump_menu(m, label, indent, menu_item=None, menu_idx=0):
        from menu import MenuItem
        from seed import WordNestMenu

        print("%s%s"% (indent, label))

        if callable(m):
            # cant do async here, fake it
            #m = await m(m, 0, menu_item)
            try:
                m = m(m, menu_idx, menu_item).__next__()
                m = m or []
            except:
                m = []

        indent += '  '
        for menu_idx, mi in enumerate(m):
            if isinstance(mi, str):
                here = mi
            elif isinstance(mi, MenuItem):
                here = mi.label

                if getattr(mi, 'predicate', False):
                    here += ' [MAYBE]'

                # NOTE: most attributes not present unless used
                funct = getattr(mi, 'next_func', None)

                if funct:
                    try:
                        rv = funct(m, menu_idx, mi).__next__()
                        if isinstance(rv, MenuSystem):
                            dump_menu(rv, here, indent, menu_item=mi, menu_idx=menu_idx)
                    except:
                        pass

                next_menu = getattr(mi, 'next_menu', None)
                chooser = getattr(mi, 'chooser', None)

                if next_menu:
                    dump_menu(next_menu, here, indent, menu_item=mi, menu_idx=menu_idx)
                    continue
                elif chooser:
                    mx = list(chooser())[1]
                    dump_menu(mx, here, indent)
                    continue

            print('%s%s' % (indent, here))
            

    from flow import EmptyWallet, NormalSystem, FactoryMenu, VirginSystem

    for nm, m in [
        ('No PIN Set', VirginSystem),
        ('Empty Wallet', EmptyWallet),
        ('Normal', NormalSystem),
        ('Factory Mode', FactoryMenu),
    ]:
        dump_menu(m, nm, '')
        print()

doit()
