# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# The HSM screen should stop claiming to be busy once the host has stopped talking.
#
# A host that dies part way through an upload never sends the rest. Nothing raises, so the
# restore_menu() in usb.py that normally clears the progress screen never runs, and the device is
# left reading "Receiving..." while it sits idle waiting for a packet that will not arrive. The
# device is fine -- a fresh upload at offset 0 resets the transfer -- but for something meant to be
# left signing unattended, "looks hung forever" is the wrong thing to show.
#
# Run with:  py.test test_hsm_busy_timeout.py --sim
#
import pytest
from test_hsm import hsm_reset, hsm_status, start_hsm, enable_hsm_commands

SIMPLE_POLICY = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=95)])


def busy_state(sim_eval):
    return sim_eval('__import__("hsm_ux").hsm_ux_obj.busy_text')


def test_busy_text_expires_when_nothing_moves(dev, start_hsm, hsm_reset, sim_exec, sim_eval):
    start_hsm(SIMPLE_POLICY)

    # Put the screen in the state an interrupted upload leaves it in, then age it past the limit by
    # winding the timestamp back rather than waiting 30 seconds of wall clock.
    sim_exec('''
import utime
from hsm_ux import hsm_ux_obj, hsmUxInteraction
hsm_ux_obj.draw_busy("Receiving...", 0)
hsm_ux_obj.busy_since = utime.ticks_add(utime.ticks_ms(), -(hsmUxInteraction.BUSY_TIMEOUT_MS + 1000))
RV.write(repr(hsm_ux_obj.busy_text).encode())
''')

    # The redraw the HSM loop performs every 100ms is what notices.
    sim_exec('from hsm_ux import hsm_ux_obj; hsm_ux_obj.draw_busy(None, None); RV.write(b"ok")')

    assert 'None' in busy_state(sim_eval), "stale message survived the timeout"

    hsm_reset()


def test_busy_text_survives_while_work_continues(dev, start_hsm, hsm_reset, sim_exec, sim_eval):
    # The other half of it: progress updates have to keep the message alive, or a slow transfer
    # would clear its own indicator and the screen would lie in the other direction.
    start_hsm(SIMPLE_POLICY)

    sim_exec('''
import utime
from hsm_ux import hsm_ux_obj, hsmUxInteraction
hsm_ux_obj.draw_busy("Receiving...", 0)
hsm_ux_obj.busy_since = utime.ticks_add(utime.ticks_ms(), -(hsmUxInteraction.BUSY_TIMEOUT_MS + 1000))
hsm_ux_obj.draw_busy(None, 0.5)     # a chunk arrived: still working
hsm_ux_obj.draw_busy(None, None)    # the idle redraw
RV.write(b"ok")
''')

    assert 'Receiving' in busy_state(sim_eval), "an active transfer lost its indicator"

    hsm_reset()

# EOF
