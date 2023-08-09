# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# countdowns.py - various details and chooser menus for setting/showing countdown times
#
from ucollections import OrderedDict
from nvstore import SettingsObject
from menu import MenuItem
from ux import ux_show_story, ux_dramatic_pause

# Login countdown length, stored in minutes
#
lgto_map = OrderedDict([
    (0, 'Disabled'),
    (5, ' 5 minutes'),
    (15, '15 minutes'),
    (30, '30 minutes'),
    (60, ' 1 hour'),
    (2*60, ' 2 hours'),
    (4*60, ' 4 hours'),
    (8*60, ' 8 hours'),
    (12*60, '12 hours'),
    (24*60, '24 hours'),
    (48*60, '48 hours'),
    (3*24*60, ' 3 days'),
    (7*24*60, ' 1 week'),
    (28*24*60, '28 days later'),
])

lgto_va = list(lgto_map.keys())
lgto_ch = list(lgto_map.values())

def real_countdown_chooser(tag, offset, def_to):

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

# Mk3 only
async def set_countdown_pin(_1, _2, menu_item):
    # Accept a new PIN to be used to enable this feature
    from login import LoginUX

    lll = LoginUX()
    lll.reset()
    lll.subtitle = "Countdown PIN"

    pin = await lll.get_new_pin(None, allow_clear=True)     # a string

    s = SettingsObject()

    from pincodes import pa
    if pin == pa.pin.decode():
        # can't compare to others like duress/brickme but will override them
        await ux_show_story("Must be a unique PIN value!")
        return
    elif not pin:
        # X on first screen does this (better than CLEAR_PIN thing)
        s.remove_key('cd_pin')
        msg = 'PIN Cleared.'
        menu_item.label = "Enable Feature"
    else:
        s.set('cd_pin', pin)
        msg = 'PIN Set.'
        menu_item.label = "PIN is Set!"

    s.save()

    await ux_dramatic_pause(msg, 3)
    
# Mk3 only
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

# Mk3 only
async def countdown_pin_submenu(*a):
    # Background and settings for duress-countdown pin
    s = SettingsObject()
    pin_set = bool(s.get('cd_pin', 0))

    if not pin_set:
        ok = await ux_show_story('''\
This special PIN will immediately and silently brick the Coldcard, \
but as it does that, it shows a normal-looking countdown timer for login. \
At the end of the countdown, the Coldcard crashes with a vague error. \

Instead of complete brick, you may select a test mode (no harm done) or \
to consume all but the final PIN attempt.\
''')
        if not ok: return


    return [
                MenuItem('PIN is Set!' if pin_set else 'Enable Feature', f=set_countdown_pin),
                MenuItem('Countdown Time', chooser=cd_countdown_chooser),
                MenuItem('Brick Mode', chooser=set_countdown_pin_mode),
            ]

# EOF
