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

* **sender side**: `shared_secret = (a_1 + a_2 + ...) * B_scan` — sum of input private keys * receiver's scan public key
* **receiver side**: `shared_secret = (A_1 + A_2 + ...) * b_scan` — sum of input public keys * receiver's scan private key

In single-signer flows, COLDCARD performs the full sender-side ECDH internally.

In multi-signer flows (multiple input owners), each signer computes a *partial ECDH share*:

* `share_i = a_i * B_scan` — the signer's input private key * the receiver's scan public key
* the coordinator sums all shares: `sum(share_i) = (a_1 + a_2 + ...) * B_scan => shared_secret`
* each share is accompanied by a **DLEQ proof** (Discrete Log Equality) so the coordinator or signers can verify the shares were computed from the correct input secret key

### SP Output Computation Before Signing

* before any signing round, the coordinator must derive the correct output script from the SP address and the transaction inputs
* this requires the full set of input public keys and the complete shared secret (assembled from partial ECDH shares)
* the computed output is inserted into the PSBT; signers verify that the output in the PSBT matches the expected tweak before signing
* a signer that cannot recompute the expected output MUST refuse to sign

## Limitations

* one of the transaction inputs must be eligible for ["Shared Secret Derivation"](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#user-content-Inputs_For_Shared_Secret_Derivation)
* MuSig2 spends are supported for taproot key-spend inputs (`tr(musig(...))`) - see [MuSig2 + Silent Payments](#musig2-silent-payments). FROST is not supported yet.

## Example

SP Address encodes two public keys: a *scan key* and a *spend key*

```plain
sp1qqw5jexmu4358tr090qld3egjxkvwftgnwzg7g2v86wad3gywxkln6qcc0kmh5k03cheul53fd7r7h4lg9y3xkrmz3k00ujulyg2pfcaevu9nurf3
```

### Partial Signing (Collaborative Inputs - Multiple Signers)

Round 1 — ECDH share collection

* Coordinator builds PSBT with inputs from each participant and partial outputs (output script not yet finalized)
* Each input owner contributes their partial ECDH share a_i * B_scan and DLEQ proof into the PSBT
* Last contributor verifies all DLEQ proofs, combines partial shares → computes shared secret → computes final output script, updates PSBT

Round 2 — Sign

* Each signer verifies the output scripts in the PSBT then signs their inputs normally
* Coordinator finalizes and broadcasts

## MuSig2 + Silent Payments

A MuSig2 wallet (e.g. 3-of-3 `tr(musig(A,B,C)/0/*)`) can pay Silent Payments recipients. The aggregate secret key to unlock the on-chain taproot output key Q is split across all signers, so no single party can compute the ECDH shared secret alone - this requires an extension to MuSig2 PSBT Fields (`PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE` and `PSBT_IN_MUSIG2_PARTIAL_DLEQ`) to support Silent Payments ouput script computation.

To keep the total number of PSBT rounds to a minimum the MuSig2 nonce and ECDH share collection are combined in the first round:

* Round 1 - Contribute: Partial ECDH share, DLEQ proof, and fresh MuSig2 pubnonce from every signer (last signer computes Silent Payment output scripts from the aggregated ECDH share).
* Round 2 - Sign: Each signer independently re-verifies Silent Payment output scripts then contributes partial MuSig2 signature completing the MuSig2 aggregation and PSBT finalization.

### Call Tree

Signing entry is `psbtObject.sign_it()` (`shared/psbt.py`), `process_silent_payment_outputs()` runs on every round: it validates ECDH coverage, contributes this signer's share, and computes the output scripts via `_compute_silent_payment_output_scripts()`. The last contributor sets the scripts at the end of Round 1. Round 2 every signer re-runs that same path to re-compute and validate the scripts already in the PSBT (mismatch aborts) before contributing a partial signature in `musig_process_input()`.

```text
sign_it()                                            psbt.py:2861,2944
│
├─ process_silent_payment_outputs()                  silentpayments.py:372   (runs every round)
│  │
│  ├─ _validate_ecdh_coverage()                       :690   (required shares + DLEQ present)
│  │
│  ├─ _compute_and_store_ecdh_shares()                :776
│  │     └─ _contribute_musig_ecdh_shares()           :1091
│  │          ├─ _compute_ecdh_share()                :112
│  │          └─ generate_dleq_proof()                dleq.py:41
│  │
│  └─ _compute_silent_payment_output_scripts()        :846
│        │   Round 1 (last contributor): compute + set output scripts
│        │   Round 2 (every signer): re-compute + validate vs PSBT (mismatch → abort)
│        └─ _get_ecdh_and_pubkey()                          :476
│             └─ _musig_input_ecdh_share()                  :1199
│                  ├─ _musig_sp_ecdh_factors()              :1160
│                  │    └─ psbt.musig_keyagg_context()      psbt.py:2678
│                  │         ├─ musig_build_cache()              :2658
│                  │         ├─ musig_derive_keyagg_cache()      :2641
│                  │         └─ musig_taproot_tweak()            :2668
│                  │        → MusigEcdhFactors(negation_factor, total_tweak)
│                  └─ _musig_aggregate_shares()             :242
│                       └─ _musig_keyagg_coefficient()      :273
│
└─ musig_process_input()                             psbt.py:2713
      Round 1: generate this signer's pubnonce
      Round 2: contribute partial MuSig2 signature
```

## Development

### start simulator

```sh
cd unix
% ./simulator.py --q1
```

### execute tests

```sh
cd testing
pytest test_bip352_vectors.py
pytest test_bip375_vectors.py
pytest test_silentpayments.py
pytest test_musig2_silentpayments.py
pytest test_musig2_sp_signers.py
```
