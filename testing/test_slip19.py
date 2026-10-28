# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# SLIP-19 ownership proofs (slp9) outside HSM mode, and the identifier itself.
#
# Nothing here needs HSM, so it runs on the Q as well as the Mk4. The policy gate is in
# test_slip19_hsm.py, which pulls in the HSM harness and therefore skips on the Q.
#
# Run with:  py.test test_slip19.py --sim
#
import pytest, struct, time
from hashlib import sha256

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


def poll_slok(dev):
    rv = None
    while rv is None:
        time.sleep(0.050)
        rv = dev.send_recv(b'slok', timeout=None)
    return rv


@pytest.fixture
def slp9(dev, press_select):
    # Outside HSM mode a human approves each proof, so the device answers with nothing and the
    # host collects the result with 'slok'. Under a policy the proof comes straight back.
    def doit(subpath=SEGWIT_PATH, addr_fmt=AF_P2WPKH, flags=0, commitment=COMMITMENT):
        rv = dev.send_recv(slp9_request(subpath, addr_fmt, flags, commitment), timeout=None)
        if rv is not None:
            return rv

        press_select()
        return poll_slok(dev)
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
    # Both supported script types produce a well-formed proof once approved on screen.
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


def test_slp9_outside_hsm_asks_on_screen(dev, cap_story, press_select):
    # No policy, so a human must see what is being proven before it is signed. The story names
    # the path and the address the proof is about.
    dev.send_recv(slp9_request(SEGWIT_PATH, AF_P2WPKH, FLAG_USER_CONFIRMATION), timeout=None)

    title, story = cap_story()
    assert 'Ownership' in title
    assert SEGWIT_PATH.decode() in story
    assert sha256(COMMITMENT).hexdigest() in story.lower()

    press_select()
    proof = poll_slok(dev)

    # somebody did confirm, so the flag is now a claim the device can back
    check_proof_shape(proof, flags=FLAG_USER_CONFIRMATION, witness_items=2)


def test_slp9_outside_hsm_can_be_refused(dev, press_cancel):
    # Refusing must produce no proof at all, not an unsigned or partial one.
    from ckcc_protocol.protocol import CCUserRefused

    dev.send_recv(slp9_request(SEGWIT_PATH, AF_P2WPKH, 0), timeout=None)
    press_cancel()

    with pytest.raises(CCUserRefused):
        poll_slok(dev)


def test_slp9_result_is_only_for_slok(dev, press_select):
    # A pending proof must not be collectable as if it were a signed message: smok would
    # otherwise hand back the proof wrapped in a message-signature response.
    dev.send_recv(slp9_request(SEGWIT_PATH, AF_P2WPKH, 0), timeout=None)
    press_select()

    with pytest.raises(Exception) as ee:
        dev.send_recv(b'smok', timeout=None)
    assert 'Wrong completion command' in str(ee.value)

    # and the proof is still there for its own poll
    check_proof_shape(poll_slok(dev), flags=0, witness_items=2)


def test_slp9_rejects_junk_path(slp9):
    with pytest.raises(Exception):
        slp9(subpath=b"m/84h/0h/zz/1/0")


# --- the ownership identifier itself ---------------------------------------------
#
# Official SLIP-19 vector 1: BIP-39 seed "all all ... all", no passphrase, P2WPKH at
# m/84h/0h/0h/1/0. The identifier is defined over the scriptPubKey alone, so it does
# not depend on which chain the simulator happens to be set to.

VECTOR_WORDS = "all all all all all all all all all all all all"
VECTOR_SPK = bytes.fromhex("0014b2f771c370ccf219cd3059cda92bdf7f00cf2103")
VECTOR_OID = bytes.fromhex("a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad5707")


def test_ownership_id_matches_official_vector(set_seed_words, sim_exec):
    # Pin the derivation against the published vector, so a change to the SLIP-21 label
    # path or the HMAC ordering fails here rather than in somebody wallet.
    set_seed_words(VECTOR_WORDS)

    rv = sim_exec("import slip19, stash, binascii\n"
                  "with stash.SensitiveValues() as sv:\n"
                  "    RV.write(binascii.hexlify(slip19.ownership_id(%r, sv)))" % VECTOR_SPK)
    assert rv.strip().endswith(VECTOR_OID.hex())


def test_slp9_carries_the_real_ownership_id(set_seed_words, slp9):
    # End to end: the id inside the proof is the spec value for the key the device just
    # derived, not the 32 zero bytes this replaced, which told a coordinator nothing.
    set_seed_words(VECTOR_WORDS)

    oid = slp9(subpath=SEGWIT_PATH, addr_fmt=AF_P2WPKH)[6:38]
    assert oid != bytes(32)
    assert oid == VECTOR_OID


def test_ownership_id_is_bound_to_the_script(set_seed_words, slp9):
    # One seed, two scripts: the identifiers must differ, or the id is not identifying.
    set_seed_words(VECTOR_WORDS)

    segwit = slp9(subpath=SEGWIT_PATH, addr_fmt=AF_P2WPKH)[6:38]
    taproot = slp9(subpath=TAPROOT_PATH, addr_fmt=AF_P2TR)[6:38]
    assert segwit != taproot

# EOF
