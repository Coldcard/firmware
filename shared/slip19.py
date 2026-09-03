# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# - Thanks to [Kevin Ravensberg](https://github.com/kravens)
#
# SLIP-19 ownership proofs (BIP-322-style), for coinjoin remote-signing (e.g. Wasabi WabiSabi).
# Produces a proof a coordinator verifier accepts: a signature over
#   SHA256( proof_body || cs(scriptPubKey) || scriptPubKey || cs(commitment) || commitment )
# where proof_body = magic(SL\x00\x19) || flags || varint(count) || 32-byte ownership id(s).
# flags bit 0 is SLIP-19's user-confirmation claim; the host picks it, we only honour it below.
#
# The wire result is the full serialized ownership proof: proof_body || bip322_sig
# (bip322_sig = empty scriptSig (varint 0) || witness stack).
#
# Two ways in, both over the 'slp9' USB command:
# - HSM mode: the policy's slip19_paths list is the standing consent, so the proof is returned
#   at once (unattended coinjoin signing).
# - otherwise: a human approves each proof on screen, exactly like message signing, and the
#   host collects the result with 'slok'. Only then can the user-confirmation flag be honest.
import ngu, stash, chains
from public_constants import AF_P2WPKH, AF_P2TR
from serializations import ser_compact_size, ser_string, ser_string_vector, ser_sig_der
from precomp_tag_hash import TAP_TWEAK_H
from auth import UserAuthorizedAction
from ux import OK, X, ux_show_story, abort_and_goto

SLIP19_MAGIC = bytes([0x53, 0x4c, 0x00, 0x19])

# --- SLIP-19 ownership identifier -------------------------------------------------
# id = HMAC-SHA256(key = k, msg = scriptPubKey), where
#   k          = Key(m/"SLIP-0019"/"Ownership identification key")   [SLIP-19]
# derived per SLIP-21:
#   m          = HMAC-SHA512(key=b"Symmetric key seed", msg=seed)
#   Child(N,l) = HMAC-SHA512(key=N[0:32], msg=b"\x00" + l)
#   Key(N)     = N[32:64]
# The key is cached against a hash of the root chain code: 256 bits of HMAC output, so unlike
# the 32-bit fingerprint it cannot collide between two seeds, and it changes with the BIP-39
# passphrase too, so a cached key can never leak across wallets.
_oid_key_cache = None


def _ownership_id_key(sv):
    global _oid_key_cache

    ident = ngu.hash.sha256s(sv.node.chain_code())
    if _oid_key_cache is not None and _oid_key_cache[0] == ident:
        return _oid_key_cache[1]

    # SLIP-21 needs the seed the BIP-32 tree was built from, not the tree itself.
    if sv.mode == 'master':
        seed = bytes(sv.raw)
    elif sv.mode == 'words':
        # Re-derives through PBKDF2 (seconds); that cost is why the key is cached.
        import bip39
        seed = bip39.master_secret(bip39.b2a_words(sv.raw), sv._bip39pw)
    else:
        # An xprv-imported secret has no seed, so no ownership identifier exists for it. Refuse
        # rather than emit a proof carrying a made-up id.
        raise ValueError('ownership proofs need a seed; this wallet was imported as xprv')

    try:
        root = ngu.hmac.hmac_sha512(b'Symmetric key seed', seed)
    finally:
        # Only this one HMAC needs the seed, so it does not outlive the block. The
        # intermediate nodes are seed-derived too, so each is blanked once consumed.
        stash.blank_object(seed)

    n1 = ngu.hmac.hmac_sha512(root[0:32], b'\x00' + b'SLIP-0019')
    stash.blank_object(root)
    n2 = ngu.hmac.hmac_sha512(n1[0:32], b'\x00' + b'Ownership identification key')
    stash.blank_object(n1)
    k = bytes(n2[32:64])
    stash.blank_object(n2)

    _oid_key_cache = (ident, k)
    return k


def ownership_id(spk, sv):
    # SLIP-19 ownership identifier for one of this wallet's scriptPubKeys.
    return bytes(ngu.hmac.hmac_sha256(_ownership_id_key(sv), spk))


def _script_and_key(node, addr_fmt):
    # For the key at this node: (scriptPubKey, what signs for it).
    # - P2WPKH: (privkey, compressed pubkey), for an ECDSA/DER witness
    # - P2TR (BIP-86 key-spend): the tweaked keypair, for a BIP-340 witness
    # Anything else would be signed as taproot below, so it is refused here.
    assert addr_fmt in (AF_P2WPKH, AF_P2TR), 'unsupported address format for ownership proof'

    chain = chains.current_chain()

    if addr_fmt == AF_P2WPKH:
        pubkey = node.pubkey()          # 33-byte compressed
        spk, _ = chain.script_pubkey(AF_P2WPKH, pubkey=pubkey)
        return spk, (node.privkey(), pubkey)

    # Key-spend only, no script tree, so the tweak is over the internal key alone - the same
    # BIP-86 case psbt.py signs. libsecp256k1's keypair_xonly_tweak_add handles the internal
    # even-Y negation and the output-key parity, so the signature verifies against the output
    # key that chains.taptweak() puts in the scriptPubKey.
    kp = ngu.secp256k1.keypair(node.privkey())
    internal_xonly = kp.xonly_pubkey().to_bytes()               # 32-byte internal x-only key
    out_kp = kp.xonly_tweak_add(ngu.hash.sha256t(TAP_TWEAK_H, internal_xonly, True))
    spk, _ = chain.script_pubkey(AF_P2TR, pubkey=internal_xonly)
    return spk, out_kp


def make_ownership_proof(subpath, addr_fmt, flags, commitment):
    # subpath: str like "m/84h/0h/0h/1/0"; addr_fmt: AF_P2WPKH or AF_P2TR; commitment: bytes.
    with stash.SensitiveValues() as sv:
        node = sv.derive_path(subpath)
        spk, signer = _script_and_key(node, addr_fmt)
        oid = ownership_id(spk, sv)

    proof_body = SLIP19_MAGIC + bytes([flags & 0xff]) + ser_compact_size(1) + oid
    preimage = proof_body + ser_string(spk) + ser_string(commitment)
    digest = ngu.hash.sha256s(preimage)

    if addr_fmt == AF_P2WPKH:
        pk, pubkey = signer
        sig65 = ngu.secp256k1.sign(pk, digest, 0).to_bytes()
        der = ser_sig_der(sig65[1:33], sig65[33:65])                   # DER + SIGHASH_ALL
        witness = ser_string_vector([der, pubkey])
    else:
        # aux_rand = 0: BIP-340 permits it; sign32 still binds (secret, message) so it is safe and
        # deterministic for a proof. Witness is a single key-spend sig (SigHash.Default -> 64 bytes).
        sig = ngu.secp256k1.sign_schnorr(signer, digest, bytes(32))
        witness = ser_string_vector([sig])

    bip322_sig = ser_compact_size(0) + witness       # empty scriptSig, then witness stack
    return proof_body + bip322_sig


# --- USB entry points --------------------------------------------------------------

PROOF_TEMPLATE = '''\
Sign ownership proof?

Proves to a coinjoin coordinator that this Coldcard owns:

{subpath} =>
{addr}

Commitment (SHA256):
{commit}

Nothing is spent. The coordinator checks the coin is yours before letting it into a round.

Press %s to continue, otherwise %s to cancel.''' % (OK, X)


class ApproveOwnershipProof(UserAuthorizedAction):
    # Outside HSM mode: show the human what is about to be proven, and sign only if they agree.
    # Result is collected by the host over 'slok', which is the only poll command that may have it.
    is_slip19 = True

    def __init__(self, subpath, addr_fmt, flags, commitment):
        super().__init__()
        self.subpath = subpath
        self.addr_fmt = addr_fmt
        self.flags = flags
        self.commitment = commitment

        from glob import dis
        dis.fullscreen('Wait...')

        with stash.SensitiveValues() as sv:
            node = sv.derive_path(subpath)
            spk, _ = _script_and_key(node, addr_fmt)
            self.address = sv.chain.render_address(spk)

        dis.progress_bar_show(1)

    async def interact(self):
        from utils import show_single_address, B2A

        story = PROOF_TEMPLATE.format(subpath=self.subpath,
                                      addr=show_single_address(self.address),
                                      commit=B2A(ngu.hash.sha256s(self.commitment)))

        # 12 chars is all the Mk4 title bar fits (see ux_confirm in ux.py)
        ch = await ux_show_story(story, title='Ownership')

        if ch != 'y':
            self.refused = True
        else:
            from glob import dis
            dis.fullscreen('Signing...')
            self.result = make_ownership_proof(self.subpath, self.addr_fmt, self.flags,
                                               self.commitment)

        self.done()


def usb_ownership_proof(subpath, addr_fmt, flags, commitment):
    # Handle the 'slp9' USB command. Returns the full response (b'biny' + proof) when it can be
    # answered at once (HSM mode), or None once on-screen approval has been started.
    from utils import cleanup_deriv_path
    from glob import dis, hsm_active
    from exceptions import HSMDenied

    # Reject before deriving anything: the approval screen below renders an address for this
    # format, and the caller states the format rather than it being guessed from the path.
    assert addr_fmt in (AF_P2WPKH, AF_P2TR), 'unsupported address format for ownership proof'

    # One canonical path is used for BOTH the policy check and the derivation, so a caller
    # cannot get one string approved and a different key signed.
    subpath = cleanup_deriv_path(subpath)
    commitment = bytes(commitment)

    if not hsm_active:
        # A human decides. The confirmation flag, if the host asked for it, is then a claim that
        # somebody did in fact confirm.
        UserAuthorizedAction.check_busy()
        UserAuthorizedAction.active_request = ApproveOwnershipProof(subpath, addr_fmt, flags,
                                                                    commitment)
        abort_and_goto(UserAuthorizedAction.active_request)
        return None

    if not hsm_active.approve_slip19(subpath):
        raise HSMDenied

    # Say what the device is doing. Unattended signing is otherwise silent, so there is no way
    # to tell a working coinjoin session from an idle one by looking at the Coldcard. This lands
    # on the HSM status screen's busy line.
    dis.fullscreen('Signing ownership proof')
    try:
        return b'biny' + make_ownership_proof(subpath, addr_fmt, flags, commitment)
    finally:
        # A finished progress bar is how the busy line gets cleared again.
        dis.progress_bar(1)

# EOF
