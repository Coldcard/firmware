# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# max_sats_leaving: an absolute cap on how much of our own value may leave in one transaction.
#
# min_pct_self_transfer is a ratio, so what it permits scales with the amount being mixed, while
# mining fees scale the other way: they are a large share of a small coin and a trivial share of a
# big one. A percentage tight enough to protect large amounts therefore refuses ordinary rounds on
# small ones. The two together fix that — the ratio binds on small amounts, the absolute cap binds
# on large ones — which is why they are ANDed rather than offered as alternatives.
#
# Run with:  py.test test_hsm_max_sats.py --sim
#
import pytest
from test_hsm import (hsm_reset, hsm_status, start_hsm, attempt_psbt, tweak_rule,
                      enable_hsm_commands)


def test_absolute_cap_is_shown_and_enforced(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # 1 BTC in. Cap is 100k sats, so 10k leaving is fine and 1M is not.
    policy = dict(warnings_ok=True, rules=[dict(max_sats_leaving=100000)])

    stat = start_hsm(policy)
    assert 'may leave the wallet' in stat.summary

    ok = fake_txn(1, 2, dev.master_xpub, outvals=[99990000, 10000],
                  change_outputs=[0], fee=0)
    attempt_psbt(ok)

    too_much = fake_txn(1, 2, dev.master_xpub, outvals=[99000000, 1000000],
                        change_outputs=[0], fee=0)
    attempt_psbt(too_much, 'too much value leaving')

    hsm_reset()


def test_cap_and_floor_are_both_enforced(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # The point of the pair. 95% alone lets 5% of a 1 BTC input walk (5M sats); the cap stops it.
    # The cap alone would let a small transaction lose almost all of itself; the floor stops that.
    # A transaction has to satisfy both.
    policy = dict(warnings_ok=True,
                  rules=[dict(min_pct_self_transfer=95, max_sats_leaving=100000)])

    start_hsm(policy)

    within_both = fake_txn(1, 2, dev.master_xpub, outvals=[99990000, 10000],
                           change_outputs=[0], fee=0)
    attempt_psbt(within_both)

    # Exactly 95% comes back, so the ratio is satisfied, but 5,000,000 sats leaving is not.
    passes_ratio_fails_cap = fake_txn(1, 2, dev.master_xpub, outvals=[95000000, 5000000],
                                      change_outputs=[0], fee=0)
    attempt_psbt(passes_ratio_fails_cap, 'too much value leaving')

    hsm_reset()


def test_absent_cap_changes_nothing(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # Existing policies must behave exactly as before.
    policy = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=95)])

    start_hsm(policy)

    psbt = fake_txn(1, 2, dev.master_xpub, outvals=[95000000, 5000000],
                    change_outputs=[0], fee=0)
    attempt_psbt(psbt)

    hsm_reset()

# EOF
