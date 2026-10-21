# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import ngu, chains, stash
from ubinascii import unhexlify
from desc_utils import ExtendedKey, MusigKey, PROVABLY_UNSPENDABLE
from descriptor import Descriptor
from wallet import MiniScriptWallet

# Use our real key so every descriptor passes the same validation as import.
with stash.SensitiveValues() as sv:
    a = chains.current_key_chain().serialize_public(sv.node)
node = ngu.hdnode.HDNode()
node.from_chaincode_pubkey(b'\x01' * 32, unhexlify(
    '0264837651238258d2edeaa39453f63dfd7d654e5bbe518b628155d7087e6c1383'))
b = chains.current_key_chain().serialize_public(node)
node.from_chaincode_pubkey(b'\x01' * 32, PROVABLY_UNSPENDABLE)
u = chains.current_key_chain().serialize_public(node)
m = 'musig(%s,%s)' % (a, b)
s, t = '/<0;1>/*', '/<2;3>/*'
x = chains.current_key_chain().serialize_public(MusigKey.from_string(m + s).node)
paths = []
for k in (a, b, u, x):
    paths.append(ExtendedKey.from_string(k).origin.psbt_derivation())
ap, bp, up, xp = paths

# Expected entries preserve order and multiplicity, not just the set of XFPs.
cases = [
    # An ordinary aggregate hides MuSig; a later standalone A must not add
    # a second copy of a participant origin collected too early.
    ('tr(%s,{pk(%s),pk(%s)})' % (x+s, m+s, a+t), [xp, ap, bp]),
    ('tr(%s,{pk(%s),pk(%s)})' % (x+s, a+t, m+s), [xp, ap, bp]),
    ('tr(%s,{pk(%s),{pk(%s),pk(%s)}})' % (x+s, m+s, m+s, a+t), [xp, ap, bp]),
    # A newly encountered MuSig keeps its normal participant entries. Later
    # standalone signer/path entries must retain their existing multiplicity.
    ('tr(%s,pk(%s))' % (a+t, m+s), [ap, xp, bp]),
    ('tr(%s,{pk(%s),pk(%s)})' % (m+s, x+s, a+t), [xp, ap, bp, ap]),
    # Different suffixes require separate signer entries with the same origin.
    ('tr(%s,pk(%s))' % (x+s, m+t), [xp, xp, ap, bp]),
    ('tr(%s,{pk(%s),pk(%s)})' % (a+s, a+s, a+t), [ap, ap]),
    # The skip option removes unspendable entries in either position.
    ('tr(%s,{pk(%s),pk(%s)})' % (u+s, m+s, a+t), [up, xp, ap, bp, ap]),
    ('tr(%s,pk(%s))' % (a+t, u+s), [ap, up]),
    # Non-Taproot and key-only Taproot descriptors retain their existing paths.
    ('wsh(and_v(v:pk(%s),pk(%s)))' % (a+s, a+t), [ap, ap]),
    ('wpkh(%s)' % (a+s), [ap]),
    ('tr(%s)' % (a+s), [ap]),
    ('tr(%s)' % (m+s), [xp, ap, bp]),
]

for text, expected in cases:
    variants = [text]
    if text.startswith('tr(') and 'pk(' in text:
        variants.append(text.replace('pk(', 'pkh('))
    for variant in variants:
        desc = Descriptor.from_string(variant)
        desc.validate()
        for skip in (False, True):
            want = list(expected)
            if skip and up in want:
                want.remove(up)
            got = desc.xfp_paths(skip_unspend_ik=skip)
            assert got == want, (variant, skip, got, want)

        # Wallet matching checks the entry count as well as origin prefixes.
        wallet = MiniScriptWallet.from_descriptor_obj('xfp-paths', desc)
        assert wallet.matching_subpaths(expected), variant
        assert not wallet.matching_subpaths(expected + [ap]), variant
