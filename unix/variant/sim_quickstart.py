# Quick command-line shortcuts
#
# imported late, for simulator only ... go to specific sub-sub-menus (dev aid)
import sys
from glob import numpad

if '--multi' in sys.argv:
    # start in multisig wallet
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('y')
    numpad.inject('9')
    numpad.inject('y')

if '--sd' in sys.argv:
    # MicroSD menu
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')

if '--addr' in sys.argv:
    # Address Explorer
    numpad.inject('8')
    numpad.inject('8')
    numpad.inject('y')
    numpad.inject('4')      # skips warning!

if '--dz' in sys.argv:
    # Enter the "Danger Zone"
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('y')

if '--xw' in sys.argv:
    # Export wallet (all types)
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('y')

if '--paper' in sys.argv:
    # Paper wallet menu
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('y')

if '--msg' in sys.argv:
    # Sign from MicoSD card
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
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
    if 0:
        from sim_secel import SECRETS
        m = 'QnVuawt8phazfnQYVJLzrqrrVScN+7A54QaU+f4OXV3MeR00'
        SECRETS['ls'] = bytearray([len(m), 0]) + m.encode('ascii') + (b'\0' * (416 - 2 - len(m)))

    # accept HSM policy, already installed
    numpad.inject('y')      
    
    #numpad.inject('3')
    #for ch in '123460':
        #numpad.inject(ch)

if '--user-mgmt' in sys.argv:
    numpad.inject('x')  # no HSM, thanks
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')  # advanced
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('5')
    numpad.inject('y')  # User management

if '--deriv' in sys.argv:
    # Advanced > Derive Entropy

    from sim_secel import SECRETS
    from sim_settings import sim_defaults

    # XPRV from spec: xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
    SECRETS['_pin1_secret'] = '011b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed900000000000000'
    sim_defaults['chain'] = 'BTC'

    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')  # advanced
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')  # up one from bottom
    numpad.inject('y')  # Derive Entropy

if '--down' in sys.argv:
    # Settings > PIN Options > Countdown PIN
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('y')  # settings
    numpad.inject('4')
    numpad.inject('y')  # pin options
    numpad.inject('4')
    numpad.inject('y')  # countdown 

if '--xor' in sys.argv:
    # Advanced > Danger > Seed funcs > Seed XOR 
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')  # adv
    numpad.inject('9')
    numpad.inject('9')
    numpad.inject('y')  # danger
    numpad.inject('8')
    numpad.inject('y')  # seed functions
    numpad.inject('8')
    #numpad.inject('y')  # seed xor

if '--seq' in sys.argv:
    # inject a sequence of key presses to get you somewhere
    seq = sys.argv[sys.argv.index('--seq') + 1]
    seq = seq.replace('ENTER', '\r')
    for ch in seq:
        numpad.inject(ch)
    assert not numpad._changes.full(), 'too full'

if '--enter' in sys.argv:
    # keep at end of file: extra enter to confirm something from above
    numpad.inject('y')


# not best place for this
import hsm
hsm.POLICY_FNAME = hsm.POLICY_FNAME.replace('/flash/', '')



