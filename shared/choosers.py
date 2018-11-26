# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# choosers.py - various interactive menus for setting config values.
#
from main import settings

def max_fee_chooser():
    from psbt import DEFAULT_MAX_FEE_PERCENTAGE
    limit = settings.get('fee_limit', DEFAULT_MAX_FEE_PERCENTAGE)

    ch = [  '10% (default)', '25%', '50%', 'no limit']
    va = [ 10, 25, 50, -1]

    try:
        which = va.index(limit)
    except ValueError:
        which = 0

    def set(idx, text):
        settings.set('fee_limit', va[idx])

    return which, ch, set

def idle_timeout_chooser():
    from ux import DEFAULT_IDLE_TIMEOUT

    timeout = settings.get('idle_to', DEFAULT_IDLE_TIMEOUT)        # in seconds

    ch = [  ' 2 minutes',
            ' 5 minutes',
            '15 minutes',
            ' 1 hour',
            ' 4 hours',
            ' 8 hours',
            ' Never' ]
    va = [ 2*60, 5*60, 15*60,
              3600, 4*3600, 8*3600, 0 ]

    try:
        which = va.index(timeout)
    except ValueError:
        which = 0

    def set_idle_timeout(idx, text):
        settings.set('idle_to', va[idx])

    return which, ch, set_idle_timeout

def chain_chooser():
    from chains import AllChains

    chain = settings.get('chain', 'BTC')

    ch = [(i.ctype, i.menu_name or i.name) for i in AllChains ]

    # find index of current choice
    try:
        which = [n for n, (k,v) in enumerate(ch) if k == chain][0]
    except IndexError:
        which = 0

    def set_chain(idx, text):
        val = ch[idx][0]
        assert ch[idx][1] == text
        settings.set('chain', val)

        try:
            # update xpub stored in settings
            import stash
            with stash.SensitiveValues() as sv:
                sv.capture_xpub()
        except ValueError:
            # no secrets yet, not an error
            pass

    return which, [t for _,t in ch], set_chain

def sensitivity_chooser():
    from main import numpad

    #            xxxxxxxxxxxxxxxx
    ch = [  (0, '+2 Sensitive'),
            (4, '+1 '),
            (1, ' 0 Default'),
            (3, '-1 '),
            (2, '-2 Sensitive'),
        ]

    try:
        which = [n for n, (k,v) in enumerate(ch) if k == numpad.sensitivity][0]
    except IndexError:
        which = 0

    def set_it(idx, text):
        value = ch[idx][0]
        settings.set('sens', value)
        numpad.sensitivity = value

        # save also for next login time.
        from main import pa
        from nvstore import SettingsObject

        if not pa.is_secondary:
            tmp = SettingsObject()
            tmp.set('sens', value)
            tmp.save()
            del tmp

    return which, [n for k,n in ch], set_it

# EOF
