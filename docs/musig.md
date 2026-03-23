# MuSig2

**COLDCARD<sup>&reg;</sup>** `EDGE` versions support [MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) from version `6.4.2X` & `6.4.2QX`.

COLDCARD implements all following BIPs, further restricting their scope (read more in Limitations section):
* PSBT fields [BIP-373](https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki)
* `musig()` descriptor key expression [BIP-390](https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki)
* Derivation Scheme for MuSig2 Aggregate Keys [BIP-328](https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki)


### Why MuSig2?
* higher level of **privacy** than OP_CHECKSIGADD. MuSig2 Taproot outputs are indistinguishable for a blockchain observer from regular, single-signer Taproot outputs even though they are actually controlled by multiple signers
* **on-chain footprint** of a MuSig2 Taproot output is essentially a single BIP340 public key. This is more compact and has lower verification cost than each signer providing an individual public key and signature


### Limitations:
* COLDCARD must stay powered up between 1st and 2nd round as necessary musig session data are stored in volatile memory only
* `musig()` can only be used inside `tr()` expression as key expression
* cannot be nested within another `musig()` expression
* only one own key in `musig()` expression
* `musig(KEY, KEY, ..., KEY)/<NUM;NUM;...>/*`
  * all `KEY`s MUST be unique - no repeated keys
  * `KEY` expression MUST be extended key (not plain pubkey)
  * `KEY` expression cannot contain child derivation, only `musig()` expression can contain derivation steps 
  * `KEY`s are sorted prior to aggregation
  * hardened derivation not allowed for `musig()` expression
  * derivation must end with `*` - only ranged `musig()` expression allowed, if `musig()` derivation is omitted, `/<0;1>/*` is implied
* PSBT must contain all the data required by BIP-373
* COLDCARD strictly differentiate between 1st & 2nd MuSig2 round. If COLDCARD provides nonce, it will not attempt to sign even if it could (a.k.a enough nonces from cosigners are available).
  To provide both nonce(s) & signature(s) signing needs to be preformed twice.
* keys from WIF Store cannot be used for MuSig2 signing
* `musig()` key expression is not allowed inside `multi_a` & `sortedmulti_a` fragments, use `thresh` instead
* inputs that are in different musig rounds in same PSBT are not allowed
* transaction cannot be modified after 1st musig round was initiated as that would change musig session

### Example

Following policy is example how to do threshold multisig with MuSig2 (and Taptree) even thought MuSig2 is not a native threshold scheme.

`tr(musig(@0,@1,@2),{{pk(musig(@0,@1)),pk(musig(@1,@2))},pk(musig(@0,@2))})`
