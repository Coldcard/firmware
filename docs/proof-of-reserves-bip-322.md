# BIP-322 Generic Signed Message Format

BIP-322 specification: <https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki>

## Proof of Reserves (POR)

### PoR PSBT

COLDCARD accepts a specially crafted PSBT file to sign as BIP-322 Proof of Reserves. The PSBT
must meet all these requirements:

* COLDCARD acts as a BIP-322 PSBT signer. It validates the BIP-322 `to_sign`
  transaction, shows the message from `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE`, and
  adds signatures to the PSBT. Finalizing and encoding the final BIP-322
  signature string is the responsibility of the finalizer.
* PSBT MUST include `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = 0x09`; the value is
  the exact message shown to the user and signed by BIP-322.
* PSBT requires `PSBT_IN_BIP32_DERIVATION` for each input
* P2SH wrapped segwit addresses MUST have proper redeem script in PSBT: `PSBT_IN_REDEEM_SCRIPT`
* P2WSH segwit addresses MUST have proper witness script in PSBT: `PSBT_IN_WITNESS_SCRIPT`
* PSBT (`to_sign`) MUST have at least one input.
* First (0th) input of `to_sign` MUST spend the BIP-322 `to_spend` output.
* Input 0 MUST include one of `PSBT_IN_NON_WITNESS_UTXO` or `PSBT_IN_WITNESS_UTXO`.
* When input 0 provides `PSBT_IN_WITNESS_UTXO`, COLDCARD reconstructs the
  expected `to_spend` txid from `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` and the
  witness UTXO scriptPubKey.
* When input 0 provides `PSBT_IN_NON_WITNESS_UTXO`, it MUST be the BIP-322
  `to_spend` transaction as defined in
  [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full):
    * 1 input, 1 output
    * output nValue is 0
    * input prevout hash is 0
    * input prevout n is 0xffffffff
    * input scriptSig is `OP_0 PUSH32 message_hash`
* PSBT (`to_sign`) MUST only have one output with null-data `OP_RETURN`
* `to_sign` transaction version MUST be 0 or 2.
* Optionally inputs can be added to `to_sign` for Proof of Reserve signing.
* PSBT MUST be version 0 or 2.
* Foreign inputs not allowed in POR PSBT.

The signatures created by the BIP-322 process will never be suitable
for a on-chain Bitcoin transaction that could move funds, because
of these restrictions imposed by BIP-322.

### Output

COLDCARD always returns a signed PSBT for BIP-322 message signing and Proof of
Reserves. It never returns an extracted/finalized transaction for these PSBTs.
This is true even when finalization is requested over USB, such as with
`ckcc unsigned.psbt --finalize`.

The signed PSBT is the handoff artifact for the external finalizer/verifier. It
keeps the PSBT metadata needed to verify or finalize the BIP-322 signature,
including public keys, scripts, partial signatures, and UTXO data. This matters
because the address being proven normally commits only to a hash of the public
key or script, not the public key or script itself.

### Proof of Reserves Signing Experience

After Coldcard recognizes a BIP-322 PSBT it reads the message from
`PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` and shows it to the user for approval.
COLDCARD verifies that the message hash matches the input 0 `to_spend`
commitment before offering to sign.

When the PSBT contains only input 0, COLDCARD labels the request as
`BIP-322 Message`, because it is message signing and does not prove ownership
of any additional reserve UTXOs. In that case it does not show transaction
input/output counts. When the PSBT contains additional inputs, COLDCARD labels
the request as `Proof of Reserves` and shows the reserve amount.

If the message contains non-ASCII characters, COLDCARD warns that some
characters may not be readable on screen.

Legacy PoR PSBTs without `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` are rejected by
this flow.

Read more [here.](https://gist.github.com/orangesurf/0c1d0a31d3ebe7e48335a34d56788d4c)

Example screen text for a one-input BIP-322 message signing PSBT:

```text
BIP-322 Message

 Message:
 This is the signed message

 Challenge Address:
 bc1qzvjnhf7k70uxv6xvneaqxql7k09dd6nsr5wheq

 Press ENTER to approve and sign message. Press (2) to explore transaction.
 CANCEL to abort.
```

Example screen text for a Proof of Reserves PSBT:

```text
Proof of Reserves

 Message:
 POR

 Amount 0.20000000 BTC

 Challenge Address:
 bc1qzvjnhf7k70uxv6xvneaqxql7k09dd6nsr5wheq

 21 inputs
 1 output

 Press ENTER to approve and sign proof of reserves. Press (2) to explore transaction.
 CANCEL to abort.
```
