# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# countdowns.py - various details and chooser menus for setting/showing countdown times
#
from ucollections import OrderedDict
from nvstore import SettingsObject

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

    s = SettingsObject.prelogin()
    timeout = s.get(tag, def_to)        # in minutes
    try:
        which = va.index(timeout)
    except ValueError:
        which = 0

    def set_it(idx, text):
        # save on key0, not normal settings
        s = SettingsObject.prelogin()
        s.set(tag, va[idx])
        s.save()
        del s

    return which, ch, set_it

def countdown_chooser():
    return real_countdown_chooser('lgto', 0, 0)

# EOF
