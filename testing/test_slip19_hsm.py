# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# The HSM policy gate for SLIP-19 ownership proofs: slip19_paths decides which paths may be
# proven unattended. Kept apart from test_slip19.py because importing the HSM harness makes the
# whole module skip on the Q, and the rest of slp9 does not need HSM.
#
# Run with:  py.test test_slip19_hsm.py --sim
#
import pytest

# enable_hsm_commands is autouse in test_hsm and must be pulled in explicitly, otherwise these
# tests only pass when some earlier module happens to have left hsmcmd enabled on the simulator.
from test_hsm import hsm_reset, hsm_status, start_hsm, enable_hsm_commands
from test_slip19 import (slp9, check_proof_shape, AF_P2WPKH, AF_P2TR, SEGWIT_PATH, TAPROOT_PATH,
                         FLAG_USER_CONFIRMATION)


@pytest.mark.parametrize('policy_paths, subpath, allowed', [
    (["m/84h/0h/0h/1/*"], SEGWIT_PATH, True),
    (["m/84h/0h/0h/0/*"], SEGWIT_PATH, False),      # wrong branch
    (["m/86h/0h/0h/1/*"], TAPROOT_PATH, True),
    ([], SEGWIT_PATH, False),                        # no slip19_paths => never allowed
])
def test_slp9_hsm_path_gate(slp9, start_hsm, hsm_reset, policy_paths, subpath, allowed):
    # Under a policy, only whitelisted paths may be proven, and the confirmation flag is
    # permitted because the approved policy is the user's standing consent.
    policy = dict(warnings_ok=True, rules=[dict(min_pct_self_transfer=99)])
    if policy_paths:
        policy['slip19_paths'] = policy_paths
    start_hsm(policy)

    addr_fmt = AF_P2TR if subpath == TAPROOT_PATH else AF_P2WPKH
    if allowed:
        proof = slp9(subpath=subpath, addr_fmt=addr_fmt, flags=FLAG_USER_CONFIRMATION)
        check_proof_shape(proof, flags=FLAG_USER_CONFIRMATION,
                          witness_items=1 if subpath == TAPROOT_PATH else 2)
    else:
        with pytest.raises(Exception) as ee:
            slp9(subpath=subpath, addr_fmt=addr_fmt, flags=FLAG_USER_CONFIRMATION)
        assert 'Not allowed in HSM mode' in str(ee.value)

    hsm_reset()

# EOF
