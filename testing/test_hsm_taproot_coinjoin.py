# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# End to end on the edge line: a taproot coin is proven with slp9 under an HSM policy, then a
# taproot coinjoin-shaped PSBT is signed unattended under the same policy, and the feerate rule
# sizes the P2TR inputs rather than refusing to size them.
#
# Run with:  py.test test_hsm_taproot_coinjoin.py --sim
#
import pytest
from test_hsm import hsm_reset, hsm_status, start_hsm, attempt_psbt, enable_hsm_commands
from test_slip19 import slp9_request, check_proof_shape, AF_P2TR, TAPROOT_PATH, FLAG_USER_CONFIRMATION

BTC = 100_000_000


def test_taproot_round_signs_under_policy(dev, start_hsm, hsm_reset, fake_txn, attempt_psbt):
    policy = dict(warnings_ok=True,
                  slip19_paths=["m/86h/0h/0h/1/*"],
                  rules=[dict(min_pct_self_transfer=95, max_sats_leaving=2_000_000,
                              max_fee_per_kvbyte=100_000, min_inputs=2)])
    start_hsm(policy)

    # input registration: the proof for a taproot coin comes straight back under the policy
    proof = dev.send_recv(slp9_request(TAPROOT_PATH, AF_P2TR, FLAG_USER_CONFIRMATION), timeout=None)
    check_proof_shape(proof, flags=FLAG_USER_CONFIRMATION, witness_items=1)

    # the round: two of our taproot inputs, our taproot change back, one foreign taproot output.
    # ~158 vbytes of ours, 10,000 sats lost -> ~63,000 sats/kvB, inside every limit
    ok = fake_txn(2, [["p2tr", 2*BTC - 10_000, True], ["p2tr", 10_000]],
                  dev.master_xpub, addr_fmt="p2tr", fee=0)
    attempt_psbt(ok)

    # same shape, 1,000,000 sats lost: ratio (99.5%) and absolute cap both pass, so the only rule
    # that can refuse is the feerate one -- which means it sized the P2TR inputs.
    pricey = fake_txn(2, [["p2tr", 2*BTC - 1_000_000, True], ["p2tr", 1_000_000]],
                      dev.master_xpub, addr_fmt="p2tr", fee=0)
    attempt_psbt(pricey, 'feerate too high')

    hsm_reset()

# EOF
