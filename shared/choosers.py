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

def countdown_chooser():
    # Login countdown length, stored in minutes
    #
    ch = [  'Disabled',
            ' 5 minutes',
            '15 minutes',
            '30 minutes',
            ' 1 hour',
            ' 2 hours',
            ' 4 hours',
            ' 8 hours',
            '12 hours',
            '24 hours',
            '48 hours',
            ' 3 days',
            ' 1 week',
            '28 days later',
          ]
    va = [ 0, 5, 15, 30, 60, 2*60, 4*60, 8*60, 12*60, 24*60, 48*60, 72*60, 7*24*60, 28*24*60]
    assert len(ch) == len(va)

    timeout = settings.get('lgto', 0)        # in minutes
    try:
        which = va.index(timeout)
    except ValueError:
        which = 0

    def set_login_countdown(idx, text):
        settings.set('lgto', va[idx])

    return which, ch, set_login_countdown


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

def scramble_keypad_chooser():
    #   rngk = randomize keypad for PIN entry
    from nvstore import SettingsObject

    s = SettingsObject()
    which = s.get('rngk', 0)
    del s

    ch = ['Normal', 'Scramble Keys']

    def set(idx, text):
        # save it, but "outside" of login PIN
        s = SettingsObject()
        s.set('rngk', idx)
        s.save()
        del s

    return which, ch, set


# EOF
