# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# choosers.py - various interactive menus for setting config values.
#
from glob import settings
from nvstore import SettingsObject
from version import has_qwerty

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

def value_resolution_chooser():
    # how to render Bitcoin values
    ch = [ 'BTC', 'mBTC', 'bits', 'sats' ]
    va = [ 8, 5, 2, 0 ]

    rz = settings.get('rz', 8)

    try:
        which = va.index(rz)
    except ValueError:
        which = 0

    def doit(idx, text):
        settings.set('rz', va[idx])

    return which, ch, doit

def scramble_keypad_chooser():
    #   rngk = randomize keypad for PIN entry

    s = SettingsObject.prelogin()
    which = s.get('rngk', 0)
    del s

    ch = ['Normal', 'Scramble Keys']

    def set(idx, text):
        # save it, but "outside" of login PIN
        s = SettingsObject.prelogin()
        s.set('rngk', idx)
        s.save()
        del s

    return which, ch, set

def kill_key_chooser():
    #   kbtn = single keypress after anti-phishing words will wipe seed

    s = SettingsObject.prelogin()

    if not has_qwerty:
        ch = ['Disable'] + [str(d) for d in range(10)]
    else:
        ch = ['Disable'] + [chr(65+i) for i in range(26)] + [i for i in '\',./']

    try:
        which = ch.index(s.get('kbtn', None))
    except ValueError:
        which = 0

    def set(idx, text):
        # save it, but "outside" of login PIN
        s = SettingsObject.prelogin()
        if idx == 0:
            s.remove_key('kbtn')
        else:
            s.set('kbtn', text)
        s.save()
        del s

    return which, ch, set



# EOF
