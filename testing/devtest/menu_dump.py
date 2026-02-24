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
        from menu import MenuItem, ToggleMenuItem, MenuSystem, NonDefaultMenuItem, ShortcutItem
        from seed import WordNestMenu, EphemeralSeedMenu, SeedVaultMenu, not_hobbled_mode
        from trick_pins import TrickPinMenu
        from users import UsersMenu
        from flow import has_secrets, nfc_enabled, vdisk_enabled, word_based_seed
        from flow import hsm_policy_available, is_not_tmp, has_real_secret
        from flow import has_se_secrets, hsm_available, qr_and_has_secrets, has_pushtx_url
        from flow import sssp_related_keys, sssp_allow_passphrase, sssp_allow_notes, sssp_allow_vault
        from charcodes import KEY_NFC, KEY_QR

        print("%s%s"% (indent, label), file=fd)

        KEYMAP = {
            KEY_NFC: 'NFC',
            KEY_QR: 'QR',
        }

        if label == 'PIN Options':
            # n/a for mk4
            m = []

        # recursing into functions that do stuff doesn't work well, skip
        avoid = {'Clone Coldcard', 'Debug Functions', 'Migrate Coldcard'}
        if any(label.startswith(a) for a in avoid):
            return

        if callable(m):
            if version.has_qwerty and m.__name__ == "start_seed_import":
                print('%s[SEED WORD ENTRY]' % indent, file=fd)
                return
            if m.__name__ in ("make_custom", "bkpw_override"):
                # address explorer custom path menu
                # bkpw override = dev thing
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

                if isinstance(mi, ShortcutItem):
                    here = "[%s key shortcut]" % KEYMAP[mi.shortcut_key]
                else:
                    here = mi.label

                if here == "Trick PINs" and not whs:
                    # trick pins are not available in EmptyWallet
                    continue

                pred = getattr(mi, '_predicate', None)
                if pred in (True, False):
                    if here in ("NFC Tools", "Import via NFC", "NFC File Share"):
                        here += ' [IF NFC ENABLED]'
                    if "QR" in here or "Scan" in here or "BBQr" in here:
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
                    here += ' [IF SECRET]'
                elif pred == word_based_seed:
                    here += ' [IF WORD BASED SEED]'
                elif pred == is_not_tmp:
                    here += ' [IF NOT TMP SEED]'
                elif pred == has_real_secret:
                    here += ' [IF SECRET AND NOT TMP SEED]'
                elif pred == hsm_available:
                    here += ' [IF HSM AND SECRET]'
                elif pred == qr_and_has_secrets:
                    here += ' [IF QR AND SECRET]'
                # do nothing, only in NormalOps menu, but SSSP has different menu dump
                elif pred == not_hobbled_mode: pass
                #     here += ' [IF SSSP DISABLED]'
                elif pred == has_pushtx_url:
                    here += ' [IF PUSHTX ENABLED]'
                elif pred == sssp_related_keys:
                    here += ' [IF SSSP RELATED KEYS ENABLED]'
                elif pred == sssp_allow_passphrase:
                    here += ' [IF WORD BASED SEED & SSSP RELATED KEYS ENABLED]'
                elif pred == sssp_allow_notes:
                    here += '[IF ENABLED & SSSP ALLOW NOTES]'
                elif pred == sssp_allow_vault:
                    here += '[IF ENABLED & SSSP RELATED KEYS ENABLED]'
                elif pred:
                    if here in ("Secure Notes & Passwords", "Push Transaction"):
                        here += ' [IF ENBALED]'
                    if here == "Secure Logout":
                        here += ' [IF NOT BATTERIES]'
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
            

    from flow import EmptyWallet, NormalSystem, FactoryMenu, VirginSystem, HobbledTopMenu
    from glob import settings

    # need these to supress warnings and info messages
    # that need user interaction nad/or show hidden items
    settings.put("seedvault", 1)
    settings.put("seeds", [["7126EB3C", "808ae37a2d3d3d0f9db5ca98c8300e3818", "[7126EB3C]", "TRNG Words"],
                           ["CCEE13B9", "018d669ed0fddccd7f34ef6dac86864e75fc4036d7dd3992c985ba0e625d8da83ac33b64d371a6d0d1a4a5200f00080ef5e2b341251b30a8b665be42c43fb4c5f3", "[CCEE13B9]", "BIP-39 Passphrase on [0F056943]"],
                           ["03EE9989", "01a00f4ecbfb55b186bae4486e0e292a34e1afb0c1f64ad4a9a3f378bdeefb7296abce50461838f76979a695d6b4f6ac329661c227f1137400520cbbb1294333a7", "[03EE9989]", "BIP85 Derived from [0F056943], index=543"]])
    settings.put("secnap", 1)
    settings.put("notes", [{"misc": "some random notes", "title": "note0"},
                           {"password": "AnnounceHalf+~^99891", "site": "abc.org", "misc": "never disclose!!!!!", "user": "satoshi", "title": "secret-PWD"}])
    settings.put("axskip", 1)
    settings.put("b39skip", 1)
    settings.put("sd2fa", ["a"])
    settings.put("ptxurl", 'https://coldcard.com/pushtx#')
    settings.put("multisig", [["CC-2-of-4", [2, 4], [[1130956047, "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP"], [3503269483, "tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm"], [2389277556, "tpubDExj5FnaUnPAn7sHGUeBqD3buoNH5dqmjAT6884vbDpH1iDYWigb7kFo2cA97dc8EHb54u13TRcZxC4kgRS9gc3Ey2xc8c5urytEzTcp3ac"], [3190206587, "tpubDFiuHYSJhNbHcbLJoxWdbjtUcbKR6PvLq53qC1Xq6t93CrRx78W3wcng8vJyQnY3giMJZEgNCRVzTojLb8RqPFpW5Ms2dYpjcJYofN1joyu"]], {"pp": "m/48h/1h/0h/2h", "ch": "XTN", "ft": 14}]])
    settings.put("tp", {"11-11": [0, 16384, 0], "333-3334": [1, 4096, 1001], "!p": [2, 33280, 3]})


    # saved passphrase on MicroSD
    with open("MicroSD/.tmp.tmp", "wb") as f:
        f.write(b'\xf0\xc9\xff\x00\xf37c\xdd\x8bz\xfa\x0b\xd9\x16;g8\xf8S0\xa5\x129\x99\xd4\xa2=\n\x01\xf9q$w\xb2sb,\xa7\xf9')

    with open('menudump.txt', 'wt') as fd:
        for nm, m in [
            ('[IF NO PIN SET]', VirginSystem),
            ('[IF BLANK WALLET]', EmptyWallet),
            ('[NORMAL OPERATION]', NormalSystem),
            ('[FACTORY MODE]', FactoryMenu),
            ('[SSSP]', HobbledTopMenu),
        ]:
            if "SSSP" in nm:
                from pincodes import pa
                pa.hobbled_mode = True

            await dump_menu(fd, m, nm, '', whs=(m in (NormalSystem,HobbledTopMenu)))
            print('---\n', file=fd)

    print("DONE: check menudump.txt file")


import uasyncio
uasyncio.run(doit())
