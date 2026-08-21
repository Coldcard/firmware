# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# The devmode test commands (EVAL/EXEC/XKEY) must not be a way around HSM mode.
#
# HSM mode exists so a Coldcard can be left unattended with a host that may be compromised --
# unattended coinjoin signing is exactly that situation. The test commands are arbitrary code
# execution, so if they are dispatched ahead of the HSM whitelist, any host software can read
# the seed off a device that the user believes is locked down.
#
# The simulator keeps the hatch open under HSM on purpose, because the rest of the test suite
# drives HSM through it. So to exercise the real-hardware branch we make the simulator stop
# claiming to be a simulator, and check the very next command is refused.
#
# NOTE: marked onetime -- once is_simulator() returns False the hatch is shut, so this test
# cannot undo its own patch. It needs a fresh simulator afterwards, and the suite runner
# excludes onetime by default.
#
import pytest


@pytest.mark.onetime
def test_devmode_commands_refused_under_hsm(dev):
    def raw(cmd, arg=b""):
        return dev.send_recv(cmd + arg, encrypt=False)

    def text(v):
        return (v if isinstance(v, str) else v.decode(errors="replace")).strip()

    # Baseline: the hatch is open with HSM off, which is what the other tests rely on.
    assert text(raw(b"EVAL", b"1+1")).endswith("2")

    # Claim to be real hardware, and turn HSM on.
    armed = text(raw(b"EXEC", b"""
import glob, usb
glob.hsm_active = True
usb.is_simulator = lambda: False
RV.write(b\x27armed\x27)
"""))
    assert armed.endswith("armed")

    # Every arbitrary-code path must now be refused rather than served.
    for cmd, arg in [(b"EVAL", b"1+1"), (b"EXEC", b"RV.write(b\x27x\x27)"), (b"XKEY", b"y")]:
        with pytest.raises(Exception) as ee:
            raw(cmd, arg)
        assert "Not allowed in HSM mode" in str(ee.value), (cmd, str(ee.value))

# EOF
