# SLIP-19 ownership proofs (BIP-322-style), for coinjoin remote-signing (e.g. Wasabi WabiSabi).
# Produces a proof a coordinator verifier accepts: a signature over
#   SHA256( proof_body || cs(scriptPubKey) || scriptPubKey || cs(commitment) || commitment )
# where proof_body = magic(SL\x00\x19) || flags || varint(count) || 32-byte ownership id(s).
#
# The wire result is the full serialized ownership proof: proof_body || bip322_sig
# (bip322_sig = empty scriptSig (varint 0) || witness stack).
import ngu, stash
from public_constants import AF_P2WPKH, AF_P2TR

SLIP19_MAGIC = bytes([0x53, 0x4c, 0x00, 0x19])
FLAG_USER_CONFIRMATION = 0x01

def _cs(n):
    # Bitcoin compact-size varint (values used here are small).
    if n < 0xfd:
        return bytes([n])
    return bytes([0xfd, n & 0xff, (n >> 8) & 0xff])

def make_ownership_proof(subpath, flags, commitment):
    # subpath: str like "m/84h/0h/0h/1/0"; flags: int; commitment: bytes.
    with stash.SensitiveValues() as sv:
        node = sv.derive_path(subpath)
        pk = node.privkey()
        pubkey = node.pubkey()          # 33-byte compressed

    # scriptPubKey: default Wasabi paths -> P2WPKH for 84h, P2TR for 86h. Decide by path purpose.
    purpose = subpath.split("/")[1] if "/" in subpath else ""
    is_taproot = purpose.startswith("86")

    oid = bytes(32)                     # ownership id (see _ownership_id note)
    proof_body = SLIP19_MAGIC + bytes([flags & 0xff]) + _cs(1) + oid

    if not is_taproot:
        h160 = ngu.hash.ripemd160(ngu.hash.sha256s(pubkey))
        spk = bytes([0x00, 0x14]) + h160
        preimage = proof_body + _cs(len(spk)) + spk + _cs(len(commitment)) + commitment
        digest = ngu.hash.sha256s(preimage)
        sig65 = ngu.secp256k1.sign(pk, digest, 0).to_bytes()
        r = sig65[1:33]
        s = sig65[33:65]
        der = _der_sig(r, s) + bytes([0x01])            # + SIGHASH_ALL
        witness = _cs(2) + _cs(len(der)) + der + _cs(len(pubkey)) + pubkey
    else:
        # P2TR: BIP86 output key + BIP-340 schnorr keyspend over the same digest.
        raise ValueError("taproot slip19 not yet implemented")   # productionization TODO

    bip322_sig = _cs(0) + witness       # empty scriptSig, then witness stack
    return proof_body + bip322_sig

def _der_sig(r, s):
    def der_int(x):
        x = bytes(x)
        i = 0
        while i < len(x) - 1 and x[i] == 0:
            i += 1
        x = x[i:]
        if x[0] & 0x80:
            x = bytes([0]) + x
        return bytes([0x02, len(x)]) + x
    body = der_int(r) + der_int(s)
    return bytes([0x30, len(body)]) + body
