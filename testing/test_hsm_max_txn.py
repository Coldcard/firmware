# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# max_txn: a device-side limit on how many transactions one approved HSM policy may sign.
#
# min_pct_self_transfer bounds what a single transaction can move, not the total. Without a count
# on the device, a host that had been taken over can keep presenting fresh transactions that each
# sit just inside the floor and drain the wallet a slice at a time. The budget that should stop
# that otherwise lives in the host, which is the thing being assumed compromised.
#
# Run with:  py.test test_hsm_max_txn.py --sim
#
import pytest
from test_hsm import (hsm_reset, hsm_status, start_hsm, attempt_psbt, tweak_rule,
                      enable_hsm_commands)


def test_max_txn_is_shown_and_enforced(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # Two transactions allowed, so the third must be refused by the device itself.
    policy = dict(rules=[dict(max_txn=2)])

    stat = start_hsm(policy)
    # The user has to be able to see the limit they are approving.
    assert 'at most 2 transaction' in stat.summary

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0)
    attempt_psbt(psbt)
    attempt_psbt(psbt)
    attempt_psbt(psbt, 'transaction count exceeded')

    hsm_reset()


def test_max_txn_absent_means_unlimited(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # Policies that do not ask for a count keep behaving exactly as before.
    policy = dict(rules=[dict()])

    start_hsm(policy)

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0)
    for _ in range(3):
        attempt_psbt(psbt)

    hsm_reset()


def test_max_txn_combines_with_the_self_transfer_floor(dev, start_hsm, fake_txn, attempt_psbt,
                                                       hsm_reset):
    # The pair is the point: the floor caps each transaction, the count caps how many there can
    # be, so the total a compromised host can move is bounded.
    policy = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=99, max_txn=1)])

    stat = start_hsm(policy)
    assert 'at most 1 transaction' in stat.summary
    assert 'self-transfer' in stat.summary

    psbt = fake_txn(1, 1, dev.master_xpub, change_outputs=[0], fee=0)
    attempt_psbt(psbt)
    attempt_psbt(psbt, 'transaction count exceeded')

    hsm_reset()

# EOF
