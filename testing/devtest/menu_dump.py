# run manually with:
#   best inside 'headless.py -i' after a ^C
#   execfile('../../testing/devtest/menu_dump.py')
# - or use test case:
#   py.test test_ux.py -k test_dump_menutree
# - result in 
#   ../unix/work/menudump.txt

async def doit():
    import version
    async def dump_menu(fd, m, label, indent, menu_item=None, menu_idx=0, whs=False):
        from menu import MenuItem, ToggleMenuItem, MenuSystem, NonDefaultMenuItem
        from seed import WordNestMenu, EphemeralSeedMenu, SeedVaultMenu
        from trick_pins import TrickPinMenu
        from users import UsersMenu
        from flow import has_secrets, nfc_enabled, vdisk_enabled, word_based_seed
        from flow import hsm_policy_available, is_not_tmp, has_real_secret
        from flow import has_se_secrets, hsm_available

        print("%s%s"% (indent, label), file=fd)

        if label == 'PIN Options':
            # n/a for mk4
            m = []

        # recursing into functions that do stuff doesn't work well, skip
        avoid = {'Clone Coldcard', 'Debug Functions', 'Migrate COLDCARD'}
        if any(label.startswith(a) for a in avoid):
            return

        if callable(m):
            if version.has_qwerty and m.__name__ == "start_seed_import":
                print('%s[SEED WORD ENTRY]' % indent, file=fd)
                return
            if m.__name__ == "make_custom":
                # address explorer custom path menu
                return

            print("Calling: %r (%s)" % (m.__name__, label))
            m = await m(m, 0, menu_item)
            print("Done")

        m = m or []

        indent += '  '

        if isinstance(m, WordNestMenu):
            print('%s[SEED WORD MENUS]' % indent, file=fd)
            return
        if isinstance(m, MenuSystem):
            m = [i for i in m.items]
        for xm in [TrickPinMenu, UsersMenu]:
            if isinstance(m, xm):
                m = [i.label for i in m.items]
                break

        for menu_idx, mi in enumerate(m):

            if isinstance(mi, str):
                here = mi
            elif isinstance(mi, MenuItem) or isinstance(mi, NonDefaultMenuItem):
                here = mi.label

                if here == "Trick PINs" and not whs:
                    # trick pins are not available in EmptyWallet
                    continue

                pred = getattr(mi, 'predicate', None)
                if pred in (True, False):
                    if here in ("NFC Tools", "Import via NFC", "NFC File Share"):
                        here += ' [IF NFC ENABLED]'
                    if "QR" in here and "Scan" in here:
                        here += ' [IF QR SCANNER]'
                    if "battery" in here:
                        here += ' [IF BATTERIES]'
                    if here in ("Calculator Login", "Reflash GPU", "Secure Notes & Passwords"):
                        here += ' [IF QWERTY KEYBOARD]'
                    if here in ("Start HSM Mode", "Wipe HSM Policy"):
                        here += ' [IF HSM POLICY]'
                elif pred == has_secrets:
                    #here += ' [IF SEED DEFINED]'
                    if not whs:     # "would have secrets"
                        continue
                elif pred == nfc_enabled:
                    here += ' [IF NFC ENABLED]'
                elif pred == vdisk_enabled:
                    here += ' [IF VIRTDISK ENABLED]'
                elif pred == hsm_policy_available:
                    here += ' [IF HSM POLICY]'
                elif pred == has_se_secrets:
                    here += ' [IF SE2 SECRET]'
                elif pred == word_based_seed:
                    here += ' [IF WORD BASED SEED]'
                elif pred == is_not_tmp:
                    here += ' [IF NOT TMP SEED]'
                elif pred == has_real_secret:
                    here += ' [IF SE2 SECRET AND NOT TMP SEED]'
                elif pred == hsm_available:
                    here += ' [IF HSM AND SE2 SECRET]'
                elif pred:
                    if here == "Secure Notes & Passwords":
                        here += ' [IF ENBALED]'
                    else:
                        here += ' [MAYBE]'

                # NOTE: most attributes not present unless used
                funct = getattr(mi, 'next_func', None)

                if funct:
                    try:
                        rv = await funct(m, menu_idx, mi)
                        if isinstance(rv, MenuSystem):
                            await dump_menu(fd, rv, here, indent, menu_item=mi, menu_idx=menu_idx, whs=whs)
                    except: pass

                next_menu = getattr(mi, 'next_menu', None)
                chooser = getattr(mi, 'chooser', None)

                if next_menu:
                    await dump_menu(fd, next_menu, here, indent, menu_item=mi, menu_idx=menu_idx, whs=whs)
                    continue
                elif chooser:
                    mx = list(chooser())[1]
                    await dump_menu(fd, mx, here, indent, whs=whs)
                    continue

                if isinstance(mi, ToggleMenuItem):
                    await dump_menu(fd, mi.choices, here, indent, menu_idx=menu_idx, whs=whs)
                    continue

            print('%s%s' % (indent, here), file=fd)
            

    from flow import EmptyWallet, NormalSystem, FactoryMenu, VirginSystem
    from glob import settings

    # need these to supress warnings and info messages
    # that need user interaction nad/or show hidden items
    settings.put("seedvault", 1)
    settings.put("axskip", 1)
    settings.put("b39skip", 1)
    settings.put("sd2fa", ["a"])

    with open('menudump.txt', 'wt') as fd:
        for nm, m in [
            ('[IF NO PIN SET]', VirginSystem),
            ('[IF BLANK WALLET]', EmptyWallet),
            ('[NORMAL OPERATION]', NormalSystem),
            ('[FACTORY MODE]', FactoryMenu),
        ]:
            await dump_menu(fd, m, nm, '', whs=(m == NormalSystem))
            print('---\n', file=fd)

    print("DONE: check menudump.txt file")


import uasyncio
uasyncio.run(doit())
