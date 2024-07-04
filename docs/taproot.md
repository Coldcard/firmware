# Taproot

**COLDCARD<sup>&reg;</sup>** Mk4 experimental `EDGE` versions
support Schnorr signatures ([BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)), 
Taproot ([BIP-0341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)) 
and Tapscript ([BIP-0342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)) support.

## Output script (a.k.a address) generation

If the spending conditions do not require a script path, the output key MUST commit to an unspendable script path. 
`Q = P + int(hashTapTweak(bytes(P)))G` a.k.a internal key MUST be tweaked by `TapTweak` tagged hash of itself. If 
the spending conditions require script path, internal key MUST be tweaked by `TapTweak` tagged hash of tree merkle root.

Addresses in `Address Explorer` for `p2tr` are generated with above-mentioned methods. Outputs `scriptPubkeys` in PSBT
MUST be generated with above-mentoned methods to be considered change.

## Allowed descriptors

1. Single signature wallet without script path: `tr(key)`
2. Tapscript multisig with internal key and up to 8 leaf scripts:
    * `tr(internal_key, sortedmulti_a(2,@0,@1))`
    * `tr(internal_key, pk(@0))`
    * `tr(internal_key, {sortedmulti_a(2,@0,@1),pk(@2)})`
    * `tr(internal_key, {or_d(pk(@0),and_v(v:pkh(@1),older(1000))),pk(@2)})`

## Provably unspendable internal key

There are few methods to provide/generate provably unspendable internal key, if users wish to only use tapscript script path.

1. **(recommended)** Origin-less extended key serialization with H from [BIP-0341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs) as BIP-32 key and random chaincode.

   `tr(xpub/<0:1>/*, sortedmulti_a(2,@0,@1))` which is the same thing as `tr(xpub, sortedmulti_a(2,@0,@1))` because `/<0;1>/*` is implied if not derivation path not provided.

2. **(recommended)** Use `unspend(` [notation](https://gist.github.com/sipa/06c5c844df155d4e5044c2c8cac9c05e#unspendable-keys). Has to be ranged.

    `tr(unspend(77ec0c0fdb9733e6a3c753b1374c4a465cba80dff52fc196972640a26dd08b76)/<0:1>/*, sortedmulti_a(2,@0,@1))`

3. use **static** provably unspendable internal key H from [BIP-0341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).

    `tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0, sortedmulti_a(2,@0,@1))`

4. use COLDCARD specific placeholder `@` to let HWW pick a fresh integer r in the range 0...n-1 uniformly at random and use `H + rG` as internal key. COLDCARD will not store r and therefore user is not able to prove to other party how the key was generated and whether it is actually unspendable.

    `tr(r=@, sortedmulti_a(MofN))`

5. pick a fresh integer r in the range 0...n-1 uniformly at random yourself and provide that in the descriptor. COLDCARD generates internal key with `H + rG`. It is possible to prove to other party that this internal key does not have a known discrete logarithm with respect to G by revealing r to a verifier who can then reconstruct how the internal key was created.

    `tr(r=77ec0c0fdb9733e6a3c753b1374c4a465cba80dff52fc196972640a26dd08b76, sortedmulti_a(2,@0,@1))`

Option 3. leaks the information that key path spending is not possible and therefore is not recommended privacy-wise.
Options 4. and 5. are problematic to some extent as internal key is static. Use recommended options 1. and 2. if the fact that internal key is unspendable should remain private. 


## Limitations

### Tapscript Limitations

In current version only `TREE` of max depth 4 is allowed (max 8 leaf script allowed).
Taproot single leaf multisig has artificial limit of max 32 signers (M=N=32).
Number of keys in taptree is limited to 32.

If Coldcard can sign by both key path and script path - key path has precedence.

### PSBT Requirements

PSBT provider MUST provide following Taproot specific input fields in PSBT:
1. `PSBT_IN_TAP_BIP32_DERIVATION` with all the necessary keys with their leaf hashes and derivation (including XFP). Internal key has to be specified here with empty leaf hashes.
2. `PSBT_IN_TAP_INTERNAL_KEY` MUST match internal key provided in `PSBT_IN_TAP_BIP32_DERIVATION`
3. `PSBT_IN_TAP_MERKLE_ROOT` MUST be empty if there is no script path. Otherwise it MUST match what Coldcard can calculate from registered descriptor.
4. `PSBT_IN_TAP_LEAF_SCRIPT` MUST be specified if there is a script path. Currently MUST be of length 1 (only one script allowed)

PSBT provider MUST provide following Taproot specific output fields in PSBT:
1. `PSBT_OUT_TAP_BIP32_DERIVATION` with all the necessary keys with their leaf hashes and derivation (including XFP). Internal key has to be specified here with empty leaf hashes.
2. `PSBT_OUT_TAP_INTERNAL_KEY` must match internal key provided in `PSBT_OUT_TAP_BIP32_DERIVATION`
3. `PSBT_OUT_TAP_TREE` with depth, leaf version and script defined. Currently only one script is allowed.