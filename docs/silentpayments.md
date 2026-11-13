# Silent Payments

**COLDCARD<sup>&reg;</sup>** `EDGE` versions support [Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) from version `TBD`.

COLDCARD implements the following BIPs:

* Silent Payments [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
* Sending Silent Payments with PSBTs [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
* Spending Silent Payment outputs with PSBTs [BIP-376](https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki)

## Why Silent Payments?

**Automatic privacy by default** — share one static address publicly; each payment produces a unique on-chain output

## How It Works

### Silent Payments Address Generation

* the sender collects the input public key(s) from the transaction being built
* a shared secret is derived via ECDH between the combined input key and the receiver's scan public key (part of the SP Address)
* the final output is a Taproot address derived from tweaking the receiver's spend public key (part of the SP Address) and shared secret
* only the holder of the scan private key can detect incoming payments; only the holder of the spend private key can sign for them

### ECDH Shares & DLEQ Proofs

The shared secret can be computed from either side:

* **sender side**: `shared_secret = (a_1 + a_2 + ...) * B_scan` — sum of input private keys × receiver's scan public key
* **receiver side**: `shared_secret = (A_1 + A_2 + ...) * b_scan` — sum of input public keys x receiver's scan private key

In single-signer flows, COLDCARD performs the full sender-side ECDH internally.

In multi-signer flows (multiple input owners), each signer computes a *partial ECDH share*:

* `share_i = a_i * B_scan` — the signer's input private key × the receiver's scan public key
* the coordinator sums all shares: `sum(share_i) = (a_1 + a_2 + ...) * B_scan => shared_secret`
* each share is accompanied by a **DLEQ proof** (Discrete Log Equality) so the coordinator or signers can verify the shares were computed from the correct input secret key

### SP Output Computation Before Signing

* before any signing round, the coordinator must derive the correct output script from the SP address and the transaction inputs
* this requires the full set of input public keys and the complete shared secret (assembled from partial ECDH shares)
* the computed output is inserted into the PSBT; signers verify that the output in the PSBT matches the expected tweak before signing
* a signer that cannot recompute the expected output MUST refuse to sign

## Limitations

* one of the transaction inputs must be eligible for ["Shared Secret Derivation"](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#user-content-Inputs_For_Shared_Secret_Derivation)
* MuSig2 and FROST are not supported yet

## Example

SP Address encodes two public keys: a *scan key* and a *spend key*
```
sp1qqw5jexmu4358tr090qld3egjxkvwftgnwzg7g2v86wad3gywxkln6qcc0kmh5k03cheul53fd7r7h4lg9y3xkrmz3k00ujulyg2pfcaevu9nurf3
```

### Partial Signing (Collaborative Inputs - Multiple Signers)
Round 1 — ECDH share collection
- Coordinator builds PSBT with inputs from each participant and partial outputs (output script not yet finalized)
- Each input owner contributes their partial ECDH share a_i * B_scan and DLEQ proof into the PSBT
- Last contributor verifies all DLEQ proofs, combines partial shares → computes shared secret → computes final output script, updates PSBT

Round 2 — Sign
- Each signer verifies the output scripts in the PSBT then signs their inputs normally
- Coordinator finalizes and broadcasts

## Development

### start simulator
```
cd unix
% ./simulator.py --q1
```

### execute tests
```
cd testing
pytest test_bip352_vectors.py
pytest test_bip375_vectors.py
pytest test_silentpayments.py
```
