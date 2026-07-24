# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# SLIP-19 ownership proofs (slp9) and their HSM policy gate.
#
# Run with:  py.test test_slip19.py
#
import pytest, struct, json
from hashlib import sha256
from ckcc.protocol import CCProtocolPacker

# The HSM harness fixtures live next door; importing them here makes pytest resolve them.
from test_hsm import hsm_reset, hsm_status, start_hsm

AF_P2WPKH = 0x07
AF_P2TR = 0x23
AF_CLASSIC = 0x01

SLIP19_MAGIC = bytes([0x53, 0x4c, 0x00, 0x19])
FLAG_USER_CONFIRMATION = 0x01

COMMITMENT = b'test-slip19-commitment'
SEGWIT_PATH = b"m/84h/0h/0h/1/0"
TAPROOT_PATH = b"m/86h/0h/0h/1/0"


def slp9_request(subpath, addr_fmt, flags, commitment=COMMITMENT):
    # '<4sIIII>': tag, addr_fmt, flags, len(subpath), len(commitment)
    return (b'slp9' + struct.pack('<IIII', addr_fmt, flags, len(subpath), len(commitment))
            + subpath + commitment)


@pytest.fixture
def slp9(dev):
    def doit(subpath=SEGWIT_PATH, addr_fmt=AF_P2WPKH, flags=0, commitment=COMMITMENT):
        return dev.send_recv(slp9_request(subpath, addr_fmt, flags, commitment))
    return doit


def check_proof_shape(proof, flags, witness_items):
    # proof_body = magic || flags || varint(count) || 32-byte ownership id
    assert proof[0:4] == SLIP19_MAGIC
    assert proof[4] == flags
    assert proof[5] == 1
    assert len(proof) > 38
    # bip322_sig follows: empty scriptSig, then the witness stack
    assert proof[38] == 0
    assert proof[39] == witness_items


@pytest.mark.parametrize('addr_fmt, subpath, witness_items', [
    (AF_P2WPKH, SEGWIT_PATH, 2),        # DER signature + pubkey
    (AF_P2TR, TAPROOT_PATH, 1),         # single BIP-340 key-spend signature
])
def test_slp9_proof_shapes(slp9, addr_fmt, subpath, witness_items):
    # Both supported script types produce a well-formed proof outside HSM mode,
    # so long as they do not claim a user confirmation that never happened.
    proof = slp9(subpath=subpath, addr_fmt=addr_fmt, flags=0)
    check_proof_shape(proof, flags=0, witness_items=witness_items)


def test_slp9_is_deterministic(slp9):
    # Same key, same commitment => same proof (RFC6979 / BIP-340 with zero aux).
    assert slp9() == slp9()


def test_slp9_binds_commitment(slp9):
    # The commitment is inside the signed digest, so changing it changes the signature.
    assert slp9(commitment=b'aaa') != slp9(commitment=b'bbb')


def test_slp9_rejects_unsupported_addr_fmt(slp9):
    # The address format is stated by the caller and validated, not guessed from the path.
    with pytest.raises(Exception) as ee:
        slp9(addr_fmt=AF_CLASSIC)
    assert 'unsupported address format' in str(ee.value)


def test_slp9_confirmation_flag_needs_hsm(slp9):
    # The flag asserts to a coordinator that a human approved this input. Outside HSM mode
    # nobody did, and the host chooses the flag, so the device must refuse to make the claim.
    with pytest.raises(Exception) as ee:
        slp9(flags=FLAG_USER_CONFIRMATION)
    assert 'user confirmation' in str(ee.value)


def test_slp9_rejects_junk_path(slp9):
    with pytest.raises(Exception):
        slp9(subpath=b"m/84h/0h/zz/1/0")


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
