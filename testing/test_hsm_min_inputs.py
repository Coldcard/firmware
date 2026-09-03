# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# min_inputs: refuse to sign a transaction that too few parties are taking part in.
#
# For a coinjoin the host decides which round to join, and a host that has been taken over can
# pick a round with nobody in it but us and a coordinator that then learns the whole mapping. The
# device is handed the entire round transaction, so it can count the participants itself rather
# than take the host's word for it.
#
# What this does NOT give you is an anonymity set. A coordinator willing to register its own
# inputs can pad a round to any count while still knowing every link. The rule rules out the
# degenerate round; it does not make a padded one private.
#
# Run with:  py.test test_hsm_min_inputs.py --sim
#
import pytest
from test_hsm import (hsm_reset, hsm_status, start_hsm, attempt_psbt, tweak_rule,
                      enable_hsm_commands)


def test_min_inputs_is_shown_and_enforced(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    policy = dict(rules=[dict(min_inputs=3)])

    stat = start_hsm(policy)
    # The user has to be able to see the limit they are approving.
    assert '3 or more inputs' in stat.summary

    attempt_psbt(fake_txn(2, 1, dev.master_xpub, fee=0), 'too few inputs: 2, need 3')
    attempt_psbt(fake_txn(3, 1, dev.master_xpub, fee=0))

    hsm_reset()


def test_min_inputs_counts_everyone(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # The whole point: it is every participant's inputs, not the subset we happen to own. One
    # input of ours alongside four strangers is a round worth joining; four of ours alone is not.
    # Had the rule counted only our own inputs these two would have come out the other way round.
    policy = dict(warnings_ok=True, rules=[dict(min_inputs=5)])

    start_hsm(policy)

    def disown_all_but_first(psbt):
        # drop the derivation info so the device sees the rest as somebody else's
        for i in psbt.inputs[1:]:
            i.bip32_paths = {}
            i.taproot_bip32_paths = {}

    attempt_psbt(fake_txn(5, 1, dev.master_xpub, fee=0, psbt_hacker=disown_all_but_first))

    attempt_psbt(fake_txn(4, 1, dev.master_xpub, fee=0), 'too few inputs: 4, need 5')

    hsm_reset()


def test_min_inputs_absent_means_no_floor(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # Policies that do not ask for it keep behaving exactly as before, including a lone input.
    policy = dict(rules=[dict()])

    start_hsm(policy)

    attempt_psbt(fake_txn(1, 1, dev.master_xpub, fee=0))

    hsm_reset()


def test_min_inputs_pairs_with_the_self_transfer_floor(dev, start_hsm, fake_txn, attempt_psbt,
                                                       hsm_reset):
    # The two bound different things: the floor caps what a round may cost us, min_inputs caps how
    # pointless a round may be. A cheap round with nobody in it still buys no privacy.
    policy = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=99, min_inputs=4)])

    stat = start_hsm(policy)
    assert '4 or more inputs' in stat.summary
    assert 'self-transfer' in stat.summary

    # Costs us nothing, but it is a round of two.
    attempt_psbt(fake_txn(2, [(None, None, True, None)], dev.master_xpub, fee=0),
                 'too few inputs: 2, need 4')

    hsm_reset()

# EOF
