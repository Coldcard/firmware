# CW1 and CX1: Codex32 Extensions

Status: COLDCARD-defined extensions, maintained by Coinkite. This document is
the normative definition of CW1 and CX1 in this repository. They are not part
of BIP-93, and implementations must explicitly support them. The `1` in each
name is the separator, not a version number. Future incompatible encodings must
use a different prefix; existing prefixes must retain the meanings defined here.

The [user guide](codex32.md) describes COLDCARD workflows. This specification
defines the portable encoding, independently of device menus and storage.
MUST, MUST NOT and SHOULD indicate requirements and recommendations.

## Wire Format

Use [BIP-93](https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki)'s
alphabet, header, bit packing, checksum polynomials and GF(32) sharing scheme,
with the HRP and payload interpretations defined below:

```text
HRP "1" threshold identifier index payload checksum
```

The alphabet, in numerical order from 0 to 31, is
`qpzry9x8gf2tvdw0s3jn54khce6mua7l`. The threshold is one character: `0`, or
`2` through `9`. The identifier is four alphabet characters; the index is one.
Index `s` denotes a secret. Threshold `0` MUST only be used with index `s`.
A secret may also carry a threshold of 2 through 9.

Strings MUST be entirely lowercase or entirely uppercase. Checksum computation
uses lowercase. Mixed case, unknown prefixes, invalid alphabet characters,
unsupported lengths and failed checksums MUST be rejected. Whitespace is not
part of the wire format; an input UI may remove presentation spaces before
validation. Uppercase is recommended for handwriting and QR presentation.

| HRP | Payload bytes | Payload characters | Checksum characters | Total characters |
|-----|---------------|--------------------|---------------------|------------------|
| `cw` | 16 | 26 | 13 | 48 |
| `cw` | 24 | 39 | 13 | 61 |
| `cw` | 32 | 52 | 13 | 74 |
| `cx` | 64 | 103 | 15 | 127 |

These lengths apply to both secrets and shares. All other lengths MUST be
rejected, including 20- and 28-byte CW1 payloads.

### Bit Packing and Padding

Encode bytes in order, most significant bit first, into five-bit alphabet
values. Append enough padding bits to complete the last symbol: 2, 3, 4 and 3
bits respectively for the four rows above. New encodings of wallet material
SHOULD use zero padding. Decoders MUST accept every value of those padding bits.

Padding is part of the shared polynomial data. It MUST be preserved during
share recovery and derivation, including in a reconstructed `s` secret. Only
when converting a secret into wallet bytes are the final incomplete byte's bits
discarded. Do not decode shares to bytes and re-encode them with zero padding
before interpolation.

### Checksum

CW1 uses BIP-93's regular 13-symbol checksum and constant
`0x10ce0795c2fd1e62a`. CX1 uses its long 15-symbol checksum and constant
`0x43381e570bf4798ab26`. Both retain the respective BIP-93 generator constants.

The actual lowercase HRP MUST be included using BIP-173 expansion:

```python
def expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
# cw -> [3, 3, 0, 3, 23]
# cx -> [3, 3, 0, 3, 24]
```

Start the polynomial residue at **1**, then process the expanded HRP followed
by the alphabet values of the header and payload. For construction, append
13 or 15 zero values, XOR the resulting residue with the corresponding
constant, and emit that many five-bit symbols, most significant first. For
verification, process the supplied checksum too; the final residue MUST equal
the constant.

BIP-93's reference `ms32_polymod` functions instead start at `0x23181b3`, which
already incorporates `ms`. Do not retain that initial state for CW1 or CX1,
and do not include both a precomputed HRP state and an expanded HRP. Merely
replacing a string's prefix invalidates its checksum.

## Payload Interpretation

### CW1: English BIP-39 Entropy

The secret bytes are exactly the original 16, 24 or 32 bytes of entropy for
12, 18 or 24 English BIP-39 words. They contain neither the mnemonic checksum
nor a passphrase. Regenerate the checksum and words using
[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and its
English word list. Other word-list languages are not represented by CW1.

CW1 makes the tradeoff described in BIP-93's
[Not BIP-0039 Entropy rationale](https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki#not-bip-0039-entropy):
sharing can be performed manually, but regenerating the mnemonic checksum
practically requires software.

To obtain wallet keys, use BIP-39's mnemonic-to-seed procedure, including its
normalization and optional passphrase, followed by BIP-32 master-key derivation.
An empty passphrase is the default. Do not feed the CW1 entropy directly into
BIP-32; that produces a different wallet. Sharing the keys of an already-active
passphrase wallet uses CX1 instead and does not preserve the words.

### CX1: Extended Private-Key Material

The secret bytes are exactly:

```text
32-byte chain code || 32-byte ser256(k)
```

`k` is an unsigned, big-endian secp256k1 private scalar, left-padded to 32 bytes.
The XPRV key-data field's leading `0x00` byte is NOT included. Before activating
an index `s` secret, implementations MUST require `1 <= k < n`, where:

```text
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Any 32-byte chain code is permitted. Non-secret shares MUST NOT be rejected
because their payload bytes would form an invalid private scalar. Validate the
scalar after reconstructing the secret; valid checksums alone do not establish
that it is a usable wallet.

Use the chain code and scalar directly as an extended private node; do not run
them through master-seed derivation. For
[BIP-32 serialization](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format),
set depth, parent fingerprint and child number to zero, and choose version bytes
for the externally selected network. The node's own fingerprint is HASH160 of
its compressed public key, truncated to the first four bytes.

CX1 carries no network, ancestry, derivation path, address type or wallet
descriptor. Importing a non-root extended key makes it a new root: its original
serialization and ancestry are not recoverable. Words and BIP-39 passphrases
cannot be recovered or applied through the words-wallet flow.

## Sharing and Recovery

Apply BIP-93's GF(32) interpolation to the five-bit header and payload values
(checksums may be regenerated). The field polynomial is `x^5 + x^3 + 1`;
indices are their alphabet values, so the secret coordinate `s` is 16.

Recovery requires a threshold-sized subset with identical HRP, threshold,
identifier and payload length, and distinct indices. Reject mismatches,
duplicates and insufficient shares. A recovery input share has a non-`s`
index and threshold 2 through 9. If more shares are supplied, select a valid
threshold-sized subset; handling inconsistent extra shares is outside this
format. An `s` secret may be activated directly but is not an independent
recovery share.

Matching headers and valid checksums do not prove that shares belong to the
same original set. Modified shares can reconstruct a different, valid wallet;
deriving additional shares does not authenticate the input set. Before relying
on recovered or derived shares, verify the wallet against an independently
recorded address using the original network, address type and derivation path.
A fingerprint alone is insufficient.

For splitting an existing secret at threshold `t`, choose a fresh identifier
and `t-1` independent, uniformly random payloads at distinct non-secret indices,
including their padding bits. Interpolate from those shares and the secret to
produce the desired output indices. Deterministic vector data below is for
testing only. Derived shares preserve the HRP, identifier, threshold and length.

The format permits all 31 non-secret indices. COLDCARD's current limit of nine
output shares and its index ordering are UI choices, not encoding restrictions.
An identifier, threshold and padding are not wallet material; importing a
secret does not require retaining them. A fresh split is a new share set.

## Conformance Vectors

[codex32-extension-vectors.json](codex32-extension-vectors.json) contains fixed,
public test data. Never use these secrets for funds. It covers all CW1 lengths,
CX1 scalar boundaries, complete 2-of-3 sets, standalone secrets, nonzero padding,
invalid encodings, invalid wallet inputs and incompatible recovery inputs.

`valid_sets` entries specify payload hex, padding as a low-bit integer, the exact
threshold-bearing `secret`, a threshold-0 `standalone` with the same payload and
padding, and three shares. Every pair MUST reconstruct the exact `secret`;
deriving the third share from either other pair MUST reproduce it. CW1 entries
include the mnemonic and mainnet root XPRV/fingerprint with empty and
`codex32-example` passphrases. CX1 entries include the chain code, scalar and
mainnet root outputs.
Fingerprints are the four hash bytes in order, written as uppercase hex.

`invalid_encodings` MUST fail string validation. `invalid_wallets` are valid
checksummed encodings but MUST fail wallet activation for the stated reason.
`invalid_recoveries` MUST fail recovery for the stated mismatch or insufficiency.
Reason labels describe requirements, not mandated error-message text.

[Host regression tests](../testing/test_codex32_extensions.py) check these fixed
vectors against `shared/codex32.py`. They require the repository's testing
dependencies, but no simulator:

```sh
python -m pytest --noconftest testing/test_codex32_extensions.py
```
