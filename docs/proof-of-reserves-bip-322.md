# [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) Generic Signed Message Format

BIP link https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki

## Proof of Reserves (POR)

### POR PSBT
COLDCARD accepts specially crafted PSBT to sign BIP-322 Proof of Reserves
* PSBT requires PSBT_IN_BIP32_DERIVATION for each input
* p2sh wrapped segwit addresses MUST have proper redeem script in PSBT (PSBT_IN_REDEEM_SCRIPT)
* p2wsh segwit addresses MUST have proper witness script in PSBT (PSBT_IN_WITNESS_SCRIPT)
* 0th input in `to_sign` transaction MUST have full (pre-segwit) UTXO (PSBT_IN_NON_WITNESS_UTXO) a.k.a `to_spend`.
* 0th input in `to_sign` PSBT_IN_NON_WITNESS_UTXO transaction (`to_spend`) is as defined in https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full:
    * 1 input, 1 output
    * output nValue is 0
    * input prevout hash is 0
    * input prevout n is 0xffffffff
    * input scriptSig is OP_0 PUSH32 message_hash

* PSBT (`to_sign`) MUST have at least one input & 0th input is MUST be `to_spend` full txn
* PSBT (`to_sign`) MUST only have one output with null-data OP_RETURN
* optionally inputs can be added to `to_sign` for Proof of Reserve signing
* PSBT MUST be version 0
* foreign inputs not allowed in POR PSBT

### POR Signing UX

After Coldcard recognizes BIP-322 POR PSBT it asks user to import human-readable message that was used to build
`to_spend` scriptSig. This message must hash exactly to message_hash, otherwise signing is not offered.
Read more [here](https://gist.github.com/orangesurf/0c1d0a31d3ebe7e48335a34d56788d4c)

```text
Proof of Reserves

 Amount 0.20000000 XTN

 Message Hash:
 11b5fe357842f5c368d2e3884d6a5ba577e3bc7cde132004f39b8c2a43a9cdec

 Message Challenge:
 00140b2537a7d6f3cc668c9e9fa0303ffb3cad6e9b81

  21 inputs
  1 output

 0.00000000 XTN
  - OP_RETURN -
 null-data

 Press ENTER to approve and sign transaction. Press (2) to explore txn
 outputs. CANCEL to abort.
```