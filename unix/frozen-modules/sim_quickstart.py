# imported late, for simulator only ... go to specific sub-sub-menus (dev aid)
import sys

if '-m' in sys.argv:
    # start in multisig wallet
    from main import numpad
    numpad.inject('9')
    numpad.inject('y')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')

if '-s' in sys.argv:
    # MicroSD menu
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')

if '--addr' in sys.argv:
    # Address Explorer
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('8')
    numpad.inject('y')
    numpad.inject('y')
    numpad.inject('4')      # skips warning!

if '--dz' in sys.argv:
    # Enter the "Danger Zone"
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('8')
    numpad.inject('8')
    numpad.inject('y')

if '--xw' in sys.argv:
    # Export wallet (all types)
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')

if '--paper' in sys.argv:
    # Paper wallet menu
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('y')

if '--msg' in sys.argv:
    # Sign from MicoSD card
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('y')

if '--hsm' in sys.argv:
    # Sign from MicoSD card
    from main import numpad
    numpad.inject('3')
    numpad.inject('y')
    for ch in '123460':
        numpad.inject(ch)

# not best place for this
import hsm
hsm.POLICY_FNAME = hsm.POLICY_FNAME.replace('/flash/', '')

