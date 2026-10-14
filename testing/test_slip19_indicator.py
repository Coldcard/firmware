# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# The HSM screen should say when the device is signing an ownership proof.
#
# Unattended coinjoin signing is silent by design, so without this there is no way to tell a working
# session from an idle one by looking at the Coldcard. PSBT signing already announces itself through
# the busy line; ownership proofs did not.
#
# Run with:  py.test test_slip19_indicator.py --sim
#
import pytest, struct
from test_hsm import hsm_reset, hsm_status, start_hsm, enable_hsm_commands

AF_P2WPKH = 0x07
SEGWIT_PATH = b"m/84h/0h/0h/1/0"
COMMITMENT = b'indicator-check'


def slp9_request(subpath, addr_fmt=AF_P2WPKH, flags=0, commitment=COMMITMENT):
    return (b'slp9' + struct.pack('<IIII', addr_fmt, flags, len(subpath), len(commitment))
            + subpath + commitment)


def test_busy_line_fits_the_screen(sim_eval):
    # dis.text centres but neither wraps nor shrinks, so a message wider than the 128px screen
    # silently loses its ends. The message we show is wider than that in the normal font.
    small = int(sim_eval(
        '__import__("glob").dis.width("Signing ownership proof", __import__("display").FontSmall)'))
    tiny = int(sim_eval(
        '__import__("glob").dis.width("Signing ownership proof", __import__("display").FontTiny)'))

    assert small > 128, "test is pointless if the message already fits in the normal font"
    assert tiny <= 128, "the fallback font has to actually fit, or the text is still clipped"


def test_proof_announces_itself_on_the_hsm_screen(dev, start_hsm, hsm_reset, sim_exec):
    policy = dict(warnings_ok=True, slip19_paths=["m/84h/0h/0h/1/*"],
                  rules=[dict(min_pct_self_transfer=95)])
    start_hsm(policy)

    # The busy line is written during signing and cleared after, so sampling it afterwards proves
    # nothing. Wrap the display call to record what it was asked to show.
    # Record the call without delegating: what matters is that the device announced itself, and
    # calling through to the real screen from a replaced bound method upsets MicroPython.
    sim_exec('''
import glob
glob.dis._seen = []
glob.dis.fullscreen = lambda msg, percent=None: glob.dis._seen.append(msg)
RV.write(b'armed')
''')

    dev.send_recv(slp9_request(SEGWIT_PATH))

    seen = sim_exec('import glob; RV.write(repr(glob.dis._seen).encode())')
    assert 'ownership proof' in seen.lower(), seen

    hsm_reset()

# EOF
