# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# choosers.py - various interactive menus for setting config values.
#
from glob import settings
from nvstore import SettingsObject

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

def real_countdown_chooser(tag, offset, def_to):
    # Login countdown length, stored in minutes
    #
    lgto_ch = [  'Disabled',
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
    lgto_va = [ 0, 5, 15, 30, 60, 2*60, 4*60, 8*60, 12*60, 24*60, 48*60, 72*60, 7*24*60, 28*24*60]

    # 'disabled' choice not appropriate for cd_lgto case
    ch = lgto_ch[offset:]
    va = lgto_va[offset:]

    s = SettingsObject()
    timeout = s.get(tag, def_to)        # in minutes
    try:
        which = va.index(timeout)
    except ValueError:
        which = 0

    def set_it(idx, text):
        # save on key0, not normal settings
        s = SettingsObject()
        s.set(tag, va[idx])
        s.save()
        del s

    return which, ch, set_it

def countdown_chooser():
    return real_countdown_chooser('lgto', 0, 0)
def cd_countdown_chooser():
    return real_countdown_chooser('cd_lgto', 1, 60)

def set_countdown_pin_mode():
    #   cd_mode = various harm levels
    s = SettingsObject()
    which = s.get('cd_mode', 0)     # default is brick
    del s

    ch = ['Brick', 'Final PIN', 'Test Mode']

    def set(idx, text):
        # save it, but "outside" of login PIN
        s = SettingsObject()
        s.set('cd_mode', idx)
        s.save()
        del s

    return which, ch, set

def scramble_keypad_chooser():
    #   rngk = randomize keypad for PIN entry

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

def kill_key_chooser():
    #   kbtn = single keypress after anti-phishing words will wipe seed

    s = SettingsObject()
    which = s.get('kbtn', -1)
    del s
    which = int(which) + 1

    ch = ['Disable'] + [str(d) for d in range(10)]

    def set(idx, text):
        # save it, but "outside" of login PIN
        s = SettingsObject()
        if idx == 0:
            s.remove_key('kbtn')
        else:
            s.set('kbtn', str(idx-1))
        s.save()
        del s

    return which, ch, set



# EOF
