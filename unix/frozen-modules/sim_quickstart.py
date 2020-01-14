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
    # Enable existing HSM file
    # - also prelaod a long-secret for an onion server
    # - must already be a .../unix/work/hsm-policy.json file in place
    from main import numpad
    from sim_secel import SECRETS
    m = 'ED25519-V3 OGlICrIPZE6DEtsGfcWH2pO6Uz6ZI+w05BYOERMN0XahGicvBhSR4HcgcX3mzk/qM3dWFZ8QAOEIvPFujlhULg=='
    SECRETS['ls'] = bytes([len(m), 0]) + m.encode('ascii') + (b'\0' * (416 - 2 - len(m)))

    numpad.inject('y')      
    
    #numpad.inject('3')
    # accept HSM policy, but already installed
    #for ch in '123460':
        #numpad.inject(ch)

if '--user-mgmt' in sys.argv:
    from main import numpad
    numpad.inject('x')  # no HSM, thanks
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('y')  # settings
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')  # User management

# not best place for this
import hsm
hsm.POLICY_FNAME = hsm.POLICY_FNAME.replace('/flash/', '')

