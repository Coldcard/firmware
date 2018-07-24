# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# choosers.py - various interactive menus for setting config values.
#
from main import settings

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

# EOF
