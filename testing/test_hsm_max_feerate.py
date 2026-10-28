# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# max_fee_per_kvbyte: a cap on what we pay per 1000 vbytes of our own contribution.
#
# The other value rules bound our loss in sats, absolutely or as a share of what we put in. Neither
# says anything about whether that loss is a reasonable price for the bytes we are adding, and in a
# coinjoin nothing else does either: the other participants' input amounts are unknown, so the
# transaction-wide fee cannot be computed and upstream's fee check is skipped entirely. This rule
# needs only our own values, so it still works there.
#
# It measures (own inputs - own outputs) / (vsize of our own inputs and outputs). That is an upper
# bound on the mining feerate we pay, because our loss also absorbs coordinator fees and any value
# genuinely leaving. Erring high is the safe direction: the rule can refuse a transaction that is
# really cheaper, but it cannot pass one that is really more expensive.
#
# Run with:  py.test test_hsm_max_feerate.py --sim
#
import pytest
from test_hsm import (hsm_reset, hsm_status, start_hsm, attempt_psbt, tweak_rule,
                      enable_hsm_commands)

# One p2wpkh input (41*4 base + 107 witness = 271 WU) plus one p2wpkh output of ours
# ((8 + 1 + 22) * 4 = 124 WU) is 395 WU, so 98 vbytes after the rule rounds down.
# Every case below uses that shape, which makes the expected feerate exactly loss * 1000 // 98.
OUR_VSIZE = 98


def test_feerate_cap_is_shown_and_enforced(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # 100,000 sats per 1000 vbytes, i.e. 100 sat/vB.
    policy = dict(warnings_ok=True, rules=[dict(max_fee_per_kvbyte=100000)])

    stat = start_hsm(policy)
    assert 'per 1000 vbytes' in stat.summary

    # Losing 9,800 sats over 98 vbytes is exactly 100,000 sats/kvB: at the limit, so allowed.
    assert (9800 * 1000) // OUR_VSIZE == 100000
    at_limit = fake_txn(1, [(None, 99990200, True, None), (None, 9800, False, None)],
                        dev.master_xpub, fee=0)
    attempt_psbt(at_limit)

    # Twice the loss over the same bytes is twice the feerate.
    over = fake_txn(1, [(None, 99980000, True, None), (None, 20000, False, None)],
                    dev.master_xpub, fee=0)
    attempt_psbt(over, 'feerate too high')

    hsm_reset()


def test_feerate_catches_what_the_ratio_permits(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # The two rules measure different things and neither implies the other. A 1% loss satisfies a
    # 95% self-transfer floor comfortably, but on a 1 BTC input that 1% is 1,000,000 sats for 99
    # vbytes - about 10,000 sat/vB, which no honest transaction pays.
    policy = dict(warnings_ok=True,
                  rules=[dict(min_pct_self_transfer=95, max_fee_per_kvbyte=100000)])

    start_hsm(policy)

    passes_ratio_fails_feerate = fake_txn(
        1, [(None, 99000000, True, None), (None, 1000000, False, None)],
        dev.master_xpub, fee=0)
    attempt_psbt(passes_ratio_fails_feerate, 'feerate too high')

    hsm_reset()


def test_legacy_inputs_are_sized_too(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # A p2pkh input is 588 WU against p2wpkh's 272, so the same loss spread over a bigger input is
    # a lower feerate. Guards against the weight table being wired only for the coinjoin case.
    # 588 + (8 + 1 + 25) * 4 = 724 WU -> 181 vbytes.
    policy = dict(warnings_ok=True, rules=[dict(max_fee_per_kvbyte=100000)])

    start_hsm(policy)

    assert (18100 * 1000) // 181 == 100000
    at_limit = fake_txn(1, [(None, 99981900, True, None), (None, 18100, False, None)],
                        dev.master_xpub, addr_fmt="p2pkh", fee=0)
    attempt_psbt(at_limit)

    over = fake_txn(1, [(None, 99960000, True, None), (None, 40000, False, None)],
                    dev.master_xpub, addr_fmt="p2pkh", fee=0)
    attempt_psbt(over, 'feerate too high')

    hsm_reset()


def test_absent_cap_changes_nothing(dev, start_hsm, fake_txn, attempt_psbt, hsm_reset):
    # Existing policies must behave exactly as before.
    policy = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=95)])

    start_hsm(policy)

    psbt = fake_txn(1, [(None, 95000000, True, None), (None, 5000000, False, None)],
                    dev.master_xpub, fee=0)
    attempt_psbt(psbt)

    hsm_reset()

# EOF
