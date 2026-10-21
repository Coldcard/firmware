# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import ngu, chains
from desc_utils import ExtendedKey, MusigKey, KeyDerivationInfo
from descriptor import Descriptor


def key(pubkey, chaincode=b"\x01" * 32):
    import ngu, chains
    from ubinascii import unhexlify as a2b_hex
    node = ngu.hdnode.HDNode()
    node.from_chaincode_pubkey(chaincode, a2b_hex(pubkey))
    return chains.BitcoinTestnet.serialize_public(node)


# Constructed edge case: unrelated public keys with the same MicroPython bytes
# hash. This is a language-hash collision, not a cryptographic hash collision.
# Treating matching hashes as equality could merge distinct keys in tr(A,pk(B)).
a = key("0357a3742cc77770dcc5bc64c7c75dfab87fed5154b6cc2aa117be8e31ad6f8914")
b = key("0264837651238258d2edeaa39453f63dfd7d654e5bbe518b628155d7087e6c1383")
ka, kb = ExtendedKey.from_string(a), ExtendedKey.from_string(b)
assert hash(ka) == hash(kb)
assert ka != kb
assert len({ka, kb}) == 2
assert ka == ExtendedKey.from_string(a)
assert ka != ExtendedKey.from_string(a + "/<4;5>/*")
assert ka != None
assert KeyDerivationInfo() == KeyDerivationInfo()

# Keep signer equality: changing the xpub does not create an independent signer.
# Original bug shape: tr(A/<0;1>/*,{pk(B/<2;3>/*),pk(A_alt/<0;1>/*)}).
# A and A_alt share a public key but have different chain codes. Merging them
# silently derives the wrong address; reject the conflict instead.
c = key("0357a3742cc77770dcc5bc64c7c75dfab87fed5154b6cc2aa117be8e31ad6f8914",
        b"\x02" * 32)
assert ka == ExtendedKey.from_string(c)
desc = Descriptor.from_string("tr(%s/<0;1>/*,{pk(%s/<2;3>/*),pk(%s/<0;1>/*)})"
                              % (a, b, c))
try:
    desc.validate()
except AssertionError as exc:
    assert str(exc) == "Conflicting signer key"
else:
    assert False, "conflicting xpub passed validation"
assert desc._keys is None

# Identical key reuse still deduplicates; different suffixes stay distinct.
desc = Descriptor.from_string("tr(%s/<0;1>/*,{pk(%s/<0;1>/*),pk(%s/<4;5>/*)})"
                              % (a, a, a))
assert len(desc.keys) == 2


class CollidingMusigKey(MusigKey):
    def __hash__(self):
        return 0


ma = CollidingMusigKey.from_string("musig(%s,%s)/<0;1>/*" % (a, b))
mb = CollidingMusigKey.from_string("musig(%s,%s)/<4;5>/*" % (a, b))
assert hash(ma) == hash(mb)
assert ma != mb
assert len({ma, mb}) == 2
assert ma == CollidingMusigKey.from_string(ma.to_string())
assert ma.derive(0) != ma.derive(1)

# MuSig participant order does not change the signer or derived key.
assert ma == MusigKey.from_string("musig(%s,%s)/<0;1>/*" % (b, a))

# An aggregate can also be encoded as an ordinary xpub. Equality must be
# symmetric across the two families and their pk/pkh subclasses.
from miniscript import KeyHash, KeyHashMusig
musig = MusigKey.from_string("musig(%s,%s)/<0;1>/*" % (a, b))
xpub = chains.BitcoinTestnet.serialize_public(musig.node) + "/<0;1>/*"
extended = ExtendedKey.from_string(xpub)
assert extended.derive(None).derive(7).node.pubkey() == \
    musig.derive(None).derive(7).node.pubkey()
variants = [extended, KeyHash.from_string(xpub),
            musig, KeyHashMusig.from_string(musig.to_string())]
for left in variants:
    for right in variants:
        assert left == right and right == left
        assert hash(left) == hash(right)
        assert len({left, right}) == 1

# Cached derivation must preserve pk/pkh serialization in either leaf order,
# including when the same key is also the internal key.
# Valid but uncommon reuse: tr(A,{pk(B),pkh(B)}) with the same suffix on B.
# A shared derived node is fine; replacing KeyHash with ExtendedKey (or the
# reverse) changes the script. This is separate from the chain-code conflict.
for internal in (a, b):
    for first, second in (("pk", "pkh"), ("pkh", "pk")):
        desc = Descriptor.from_string("tr(%s,{%s(%s),{%s(%s),%s(%s)}})" %
                                      (internal, first, b, second, b, second, b))
        for change in (False, True):
            for index in (0, 7):
                cached = desc.derive(None, change=change).derive(index)
                independent = Descriptor(
                    key=desc.key.derive(None, change=change).derive(index),
                    tapscript=desc.tapscript.derive(None, None, change=change).derive(index, None),
                    addr_fmt=desc.addr_fmt,
                )
                cached_leaves = list(cached.tapscript.iter_leaves())
                independent_leaves = list(independent.tapscript.iter_leaves())
                for actual, expected in zip(cached_leaves, independent_leaves):
                    assert actual.compile() == expected.compile()
                    assert type(actual.keys[0]) is type(expected.keys[0])
                    # Both expression types reuse the same derived HD node.
                    assert actual.keys[0].node is cached_leaves[0].keys[0].node
                assert cached.script_pubkey() == independent.script_pubkey()
                assert chains.current_chain().render_address(cached.script_pubkey()) == \
                    chains.current_chain().render_address(independent.script_pubkey())

from desc_utils import bip388_validate_policy, bip388_wallet_policy_to_descriptor

# BIP-388 key vectors require distinct public keys, even when xpubs differ.
# Malformed policy input: [A, A] or [A, A_alt] with the same public key in both
# entries. Different placeholder suffixes do not make that key vector valid.
# Valid suffix reuse uses one key-list entry referenced by multiple placeholders.
for first, second in ((a, a), (a, c), (c, a)):
    for use_musig in (False, True):
        if use_musig:
            template = "tr(musig(@0,@1)/**,pk(musig(@2,@1)/<2;3>/*))"
            info = [first, b, second]
        else:
            template = "tr(@0/**,pk(@1/<2;3>/*))"
            info = [first, second]
        try:
            bip388_validate_policy(template.encode(), info)
        except AssertionError as exc:
            assert str(exc) == "Duplicate policy key"
        else:
            assert False, "duplicate public keys accepted in policy"

        text = bip388_wallet_policy_to_descriptor(template, info)
        desc = Descriptor.from_string(text)
        if first != second:
            # Reject during import validation, before policy conversion.
            for disable_checks in (False, True):
                try:
                    desc.validate(disable_checks=disable_checks)
                except AssertionError as exc:
                    assert str(exc) == "Conflicting signer key", str(exc)
                else:
                    assert False, "conflicting xpubs passed validation"
        else:
            # One key entry, used with disjoint suffixes, remains valid.
            template, info = desc.bip388_wallet_policy()
            assert len(info) == 1 + use_musig
            assert "pub" not in template
            bip388_validate_policy(template.encode(), info)
            restored = Descriptor.from_string(bip388_wallet_policy_to_descriptor(template, info))
            assert restored.to_string() == desc.to_string()
            for change in (False, True):
                for index in (0, 7):
                    assert restored.derive(None, change=change).derive(index).script_pubkey() == \
                        desc.derive(None, change=change).derive(index).script_pubkey()

# The same import check also applies to non-Taproot descriptors.
desc = Descriptor.from_string("wsh(and_v(v:pk(%s/<0;1>/*),pk(%s/<2;3>/*)))" % (a, c))
try:
    desc.validate()
except AssertionError as exc:
    assert str(exc) == "Conflicting signer key", str(exc)
else:
    assert False, "conflicting xpubs passed WSH validation"

# Validate the aggregate signing node as well as its participants. An ordinary
# xpub can share the aggregate's public key but carry a different chain code.
# Key collection must not validate, and caching it must not bypass validation.
from stash import SensitiveValues
with SensitiveValues() as sv:
    mine = chains.current_key_chain().serialize_public(sv.node)
agg = MusigKey.from_string("musig(%s,%s)/<0;1>/*" % (mine, b))
agg_xpub = chains.current_key_chain().serialize_public(agg.node)
bad_node = ngu.hdnode.HDNode()
bad_node.from_chaincode_pubkey(b"\x03" * 32, agg.node.pubkey())
bad_xpub = chains.current_key_chain().serialize_public(bad_node)
assert bad_xpub != agg_xpub

for conflict in (False, True):
    ordinary = (bad_xpub if conflict else agg_xpub) + "/<0;1>/*"
    for first, second in ((ordinary, agg.to_string()), (agg.to_string(), ordinary)):
        for wrapper in ("pk", "pkh"):
            for cached in (False, True):
                for disable_checks in (False, True):
                    desc = Descriptor.from_string("tr(%s,%s(%s))" % (first, wrapper, second))
                    if cached:
                        assert len(desc.keys) == 1
                    if conflict:
                        try:
                            desc.validate(disable_checks=disable_checks)
                        except AssertionError as exc:
                            assert str(exc) == "Conflicting signer key", str(exc)
                        else:
                            assert False, "conflicting aggregate xpub passed validation"
                    else:
                        desc.validate(disable_checks=disable_checks)
                        assert len(desc.keys) == 1
