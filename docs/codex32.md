# Codex32

[_(new in v5.6.3 for Mk4/Mk5 and v1.5.3Q for Q)_](https://coldcard.com/docs/upgrade/)

Codex32 is the checksummed secret encoding and Shamir secret-sharing scheme
defined by [BIP-93](https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki).
COLDCARD can create and import Codex32 wallets, split an active wallet into a
threshold set of shares, recover a wallet, and derive additional shares from
an existing threshold set.

COLDCARD displays and exports Codex32 shares using capital letters to make them
easier to read and transcribe by hand. Shares written entirely in lowercase are
equally valid and can be imported. Uppercase and lowercase letters must not be
mixed within a share. Spaces added for readability are ignored when importing.

## Anatomy of a Codex32 String

    MS1 2 W7F2 S XXXXXXXXXXXXXXXXXXXXXXXXXY 9ML44VCLR4TFD
    <1> <2><-3-><4><----------5------------> <-----6----->

    1: prefix and separator: MS1, CX1 or CW1 (see Encodings below)
    2: threshold: 0, or 2 through 9
    3: identifier: four characters, the same for every share in one set
    4: share index
    5: payload
    6: checksum: 13 characters, or 15 for the longest strings

A string whose share index is `s` is the **secret**: the value the wallet is
made from. A string with any other index is a **share**. Threshold `0` marks a
standalone secret that does not specify a share-set threshold. A threshold of
2 through 9 is the number of shares needed to recover the secret. Every share
in one set carries the same prefix, threshold, identifier, and length.

When a Codex32 string is shown on screen, COLDCARD numbers it in groups of four
characters. The verification quiz refers to those group numbers.

## Encodings

The prefix identifies what the recovered bytes mean. COLDCARD selects it from
the active wallet automatically:

| Active wallet | Split format | Recovery restores | Share characters |
|---------------|--------------|-------------------|------------------|
| English BIP-39 words (12, 18, 24) | `cw1` | Original words; passphrases can be applied afterward | 48, 61, 74 |
| Raw BIP-32 master seed (128, 256, 512 bits) | `ms1` | Master-seed bytes | 48, 74, 127 |
| Extended private key, including an active BIP-39 passphrase wallet | `cx1` | Chain code and private key | 127 |

`ms1` is defined by BIP-93. `cw1` and `cx1` are COLDCARD extensions and require
software that explicitly supports the respective prefix. Changing a prefix is
not a conversion between wallet types: the same bytes interpreted as BIP-39
entropy, a BIP-32 master seed, or an extended key do not represent the same
wallet.

Implementers: see the [CW1/CX1 specification](codex32-extensions.md) and its
[conformance vectors](codex32-extension-vectors.json) for the exact encoding and
recovery rules.

### Seed Words and BIP-39 Passphrases

For a backup of your **words**, return to or reload the original words wallet
before using Shamir Split. It uses CW1. After recovering those shares, apply
your passphrase again to access the corresponding passphrase wallet. Keep the
passphrase separately: CW1 shares contain only word entropy, and the same
recovered words can be used with any of their BIP-39 passphrases.

For a backup of the **currently active passphrase wallet's keys**, split while
that passphrase wallet is active. COLDCARD stores its active secret as an
extended key, so the split uses CX1. Recovery accesses that wallet directly,
without requesting the passphrase. The shares do not retain the original words
or passphrase, and the recovered extended-key wallet cannot apply a different
BIP-39 passphrase. This also applies to passphrases used with temporary words.

MS1 and CX1 wallets are not word-based and do not support the BIP-39 passphrase
flow. CW1 recovers a words wallet and supports that flow normally.

For CX1, keep the original network and derivation settings to reproduce the
same addresses. An imported non-root extended key becomes a new root; its
original ancestry is not preserved.

## Secret Shares and Wallets

Only index `S` can be imported as a wallet. Non-secret shares are accepted by
Shamir Recover and Derive Shares, but cannot be activated or saved to Seed Vault.
Recovery interpolates `S` from a threshold set, then imports its wallet material.
The original ID, threshold and padding are not retained in wallet storage.

## Create a Codex32 Wallet

On a device with a PIN but no wallet, select:

    Codex32 > Generate > 128-bit

or:

    Codex32 > Generate > 256-bit

To create a temporary Codex32 wallet while another wallet is present, select:

    Advanced/Tools > Temporary Seed > Codex32 > Generate

COLDCARD mixes its random sources with user-provided entropy and displays the
resulting `ms1` secret with fixed ID `SEED`, index `S`, threshold `0` and zero
padding. A verification quiz checks the recorded groups before the wallet is
activated. Temporary-wallet creation also offers an explicit option to skip
the quiz.

To verify generation with dice or coin entropy, use the standalone
[verify_seed_mix.py](verify_seed_mix.py) script:

    python3 verify_seed_mix.py --codex32

The ID defaults to `SEED`. Enter the device's `View TRNG Words`, your dice
rolls or coin flips, and the selected bit length. Add `--tmp` for a temporary
wallet; the default is a master wallet. Verify offline and keep inputs and
output secret.

For dice-only generation, select `Generate > Advanced > 128-bit Dice Roll`
or `256-bit Dice Roll`. These require at least 50 or 99 rolls respectively.
Generation aborts if any face occurs more than 30% of the time, even when the
minimum roll count is met.
The seed is SHA-256 of the entered roll digits (truncated to 16 bytes for
128-bit), with no device randomness mixed in. The ID is always `SEED`.

Verify this using the standalone [rolls_codex32.py](rolls_codex32.py) script:

    python3 rolls_codex32.py --bits 128 < rolls.txt

Use `128` or `256`; the ID defaults to `SEED`. The script reads rolls from
stdin, ignores whitespace, and prints the full rolling-screen hash followed
by the Codex32 secret. Keep the rolls and output secret; verify offline.
The script enforces the same minimum roll count and 30% distribution check.

!!! warning "The displayed Codex32 secret backs up the wallet's key material."

    Record it completely and accurately. View Secret can reproduce this
    generated MS1 backup while the wallet is active. If you lose the wallet,
    you need the recorded backup or a threshold of its split shares.

Codex32 backs up key material only, not device settings or wallet configuration.
For multisig, also retain the wallet descriptor, configuration file, or a backup
containing that information.

## Import a Codex32 Secret

Select `Import Codex32` from either Codex32 menu. Depending on the device and
enabled hardware, an index `S` secret can be imported by:

- MicroSD or Virtual Disk text file
- NFC
- QR scan
- Manual entry

For file imports, use a `.txt` file between 48 and 512 bytes. Put one complete
secret or share on one line, without a label such as `secret` or `share A`.
Spaces are allowed, but do not wrap the string across lines. Only the first
line beginning with `MS1`, `CX1` or `CW1` (case-insensitive, after removing spaces) is
imported; a file containing several shares does not import the whole set.
For example, this is the entire contents of a valid import file using a public
test secret. Never use it to hold funds:

    MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW

Non-secret shares must be entered through `Shamir Recover` or `Derive Shares`.
`Import Codex32` rejects them without changing the wallet or Seed Vault.

`Advanced/Tools > Danger Zone > Seed Functions > View Secret` displays raw master
seed bytes as hex together with an MS1 backup string for MS1 imports, English
seed words for CW1 imports, and the extended private key for CX1 imports. The
original Codex32 string is not stored or included in encrypted backups.

## Calculate a Checksum

Select **Codex32 > Calculate Checksum** (**Calc Checksum** on Mk4/Mk5) and enter
the header and payload without a checksum, manually or using Q's scan shortcut.
MS1, CW1 and CX1 secret `S`
and ordinary Shamir shares are supported. Manual entry uses uppercase; Q converts
lowercase keystrokes to uppercase. Scanned text must be all uppercase or all
lowercase. Spaces between groups are allowed.
The result shows the checksum and completed string, preserving all payload and
padding bits. Use the standard share actions to display a QR code, share via NFC,
or save to MicroSD or Virtual Disk when available. It does not import or activate
a wallet.

Calculating a checksum cannot detect existing transcription mistakes: it computes
a checksum for exactly the header and payload you entered.

## Split the Active Wallet

Select:

    Advanced/Tools > Danger Zone > Seed Functions > Shamir Split

The format follows the active wallet: English words use CW1, raw master seeds
use MS1, and extended keys use CX1. The table under [Encodings](#encodings)
shows what each format recovers. There is no format-selection menu.

If a BIP-39 passphrase wallet is active, its derived keys are split as CX1.
Return to or reload the original words wallet first if you want a CW1 backup
of the words instead. COLDCARD warns about CW1/CX1 compatibility before the
split and explains what recovery will restore.

Choose between two and nine total shares, then a threshold between two and the
total. Every split uses fresh randomness and chooses its own ID independently
of the fixed `SEED` ID used for standalone MS1 backups.

A split creates a new set with zero padding on its secret `S`. The original
wallet remains unchanged, but shares from an earlier set cannot be mixed with
these shares.

The resulting menu lists each share separately. Open every share to display it
and export it by QR, NFC, MicroSD, or Virtual Disk as available. File exports
are written as `<id>_share_<index>.txt`. A signature file is also written when a
master or temporary wallet is available.

Text files, QR codes, and NFC exports contain the share in plaintext. The
signature file does not encrypt it. Keep fewer than the threshold number of
shares on any one storage medium.

!!! warning "COLDCARD does not retain the generated share set."

    It cannot recreate the shares later. Do not leave the split screen until
    every share you intend to keep has been recorded and compared with its
    displayed value. Splitting has no verification quiz. Splitting again
    produces a different set; do not mix shares from separate splits.

## Recover from Shares

On a device without a wallet, select:

    Codex32 > Shamir Recover

To recover as a temporary wallet, select:

    Advanced/Tools > Temporary Seed > Codex32 > Shamir Recover

Shares may be supplied in any order and through any supported import method.
After the first share, COLDCARD requires the HRP, ID, threshold, and length to
match. Duplicate share indices and secret index `s` values are rejected.

Shares are collected from external sources only. Neither the active wallet nor
Seed Vault supplies shares to recovery or derivation.

In Shamir Recover or Derive Shares, cancel and choose **Save & Exit** to save a
partial set and resume later. Saved shares are encrypted when a master wallet is
configured; otherwise, they are stored without confidentiality protection.

Shamir Recover and Derive Shares share one saved partial set. Opening either
automatically resumes that set. To start a different set, cancel at the import
method prompt and confirm **Discard collected shares?** instead of choosing
**Save & Exit**, then reopen the operation. The saved copy is cleared as soon
as the threshold is collected, even if wallet recovery subsequently fails.

Recovery begins automatically as soon as the threshold is reached. The
reconstructed index `s` secret is then activated as the selected master or
temporary wallet. CW1 recovery restores a words wallet: use **View Secret** to
check the words, then apply your original BIP-39 passphrase separately if needed.
CX1 recovery restores extended keys directly. MS1 recovery restores raw
master-seed bytes; View Secret displays hex and a standalone `MS10SEEDS...`
backup, not the original share-set identifier or threshold.

### Verify Your Backup

Valid checksums and matching share headers do not authenticate the share set.
Modified shares can recover a different, valid wallet, and Derive Shares can
carry that substitution into additional shares. Check against an independently
recorded address before relying on a recovered wallet or derived shares.

Before splitting, record the original wallet fingerprint and a known receive
address, including its network, address type, and derivation path. After
recording the shares, test recovery before relying on them:

1. Keep the original wallet and its existing backup intact. Use temporary
   recovery or a separate device that supports the shares' prefix (MS1, CW1
   or CX1).
2. Import a threshold number of shares from the copies you will store.
3. For CW1, reapply any passphrase needed for the wallet you are checking.
   Check that the recovered wallet has the original fingerprint and reproduces
   the known address using the same wallet configuration. A fingerprint alone
   is not sufficient verification.
4. Repeat with other combinations until every share you intend to keep has
   been included in a successful recovery. There is no need to test every
   possible combination.

### Troubleshooting

- **File not found or recognised:** check the `.txt` extension, 48–512-byte
  size, and single-line format described above. Remove example labels.
- **Checksum or case error:** compare the entire string with the original,
  including its prefix and checksum. Use all uppercase or all lowercase.
  COLDCARD detects errors but does not implement BIP-93 error correction.
- **Unsupported length:** only the payload sizes listed under [Encodings](#encodings)
  are supported, even if another length is valid under BIP-93.
- **Mismatched or duplicate shares:** use distinct indices from the same split,
  with matching prefix, ID, threshold, and length. Index `s` is already a
  secret, so use `Import Codex32` rather than `Shamir Recover` for it.
- **Invalid `cx1` private key:** a checksummed string is not necessarily usable
  as a standalone wallet. If it is a non-secret share, use it in `Shamir Recover`;
  if the recovered secret is rejected, recheck the source and share set.

## Derive Additional Shares

Select `Codex32 > Derive Shares` on a blank device, or use the temporary
Codex32 menu on a device with a wallet. Collection uses the same import
methods and matching checks as recovery. After collecting exactly the
threshold, select any offered output index to display/export that share. Output
indices are limited to `A`, `C`, `D`, `E`, `F`, `G`, `H`, `J`, and `K`, matching
Shamir Split's nine-share limit.
Collected indices are excluded.

Outputs preserve the original ID, threshold, prefix and size, and belong to the
same share set.
You can select multiple outputs or reproduce the same output later from any
threshold set. This also works with existing `cx1` and `cw1` sets. Exiting
discards the session; derivation does not activate a wallet or save shares to
Seed Vault.

The device collecting a threshold can calculate the combined secret, even
though this flow only exports shares. Trust it accordingly. Recovering `S`
and using `Shamir Split` instead creates a fresh set, whose shares cannot be
mixed with the original set.

## Worked Examples

All secrets, seed words, and passphrases in these examples are public and
deliberately insecure. Never use them to hold funds.

### Native `ms1` Wallet

Import this public BIP-93 test secret:

    MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW

Its padding is nonzero. Import discards that padding and the identifier, while
preserving these 128 seed bits:

    318c6318c6318c6318c6318c6318c631

View Secret shows those bytes and the following standalone MS1 backup. The
payload's last character and checksum differ, but it restores the same wallet:

    MS10SEEDSXXXXXXXXXXXXXXXXXXXXXXXXXYXCV5FGVUZJQQ6

An illustrative 2-of-3 split uses a fresh identifier `W7F2` and zero padding on
its secret S. Actual splits choose a random identifier and random share data:

    secret    MS12W7F2SXXXXXXXXXXXXXXXXXXXXXXXXXY9ML44VCLR4TFD
    share A   MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88
    share C   MS12W7F2CFFFGRFURFZ6FJVFTLA4GU6AJL3SM7JJ23UZRHJU
    share D   MS12W7F2D777VW79W7UJ70K7N6H2V9JH06L7MDSSMHQ33LCV

Shamir Split exports A, C and D; the secret above is shown here to explain what
they reconstruct. Any two recover the same master seed. After recovery,
View Secret displays `MS10SEEDS...` again. To derive additional shares belonging
to `W7F2`, supply a threshold of the original shares to Derive Shares.

### Splitting a Seed-Word Wallet

Consider this public 12-word BIP-39 test mnemonic:

    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

With no passphrase, its master key fingerprint is `73C5DA0A`. Splitting these
words uses `cw1` with a 128-bit payload of sixteen zero bytes. A 2-of-3 split
produces three 48-character shares. Any two recover the same English words,
which reproduce this wallet and can still be used with a BIP-39 passphrase.
For example, this illustrative set uses ID `W0RD`:

    secret    CW12W0RDSQQQQQQQQQQQQQQQQQQQQQQQQQQY7APCDMV8SRFS
    share A   CW12W0RDAQQQSYQCYQ5RQWZQFPG9SCRGWPUZVSX8UXYXF6SF
    share C   CW12W0RDCQQQP2Q42QTNQM9QZK5UP4N5MKLT64C56JC3NQ2N
    share D   CW12W0RDDQQQJSQMSQZVQ3GQDYF5JMVF3YTUYQALM59R0UK0

After recovery, View Secret shows the twelve English words. Apply the original
passphrase afterward if the wallet you need used one. This differs from
splitting an already-active passphrase wallet, as shown next.

### Passphrase Wallet Key Conversion

Activating the same seed words with the example passphrase `codex32-example`
produces a different wallet with fingerprint `AD300F70`. An illustrative
2-of-3 split with identifier `PASS` would reconstruct this secret. This example
shows the converted key material only, not a complete share set for recovery:

    CX12PASSS57YRW3K4CMGARHKLQAGJ8L5YGFJDVWG4YDZYY6TWU92LVR8T3VKRY7PJWSSYQ2DZ7KDJNVM3E06MRS2XZ6FDW37F6SL7MKSF75EWUWSGP3L3LSA0VKS82T

Importing this secret restores fingerprint `AD300F70` directly, without
requesting the seed words or passphrase. Neither the words nor the passphrase
can be recovered from the reconstructed `cx1` secret.

## Storage and Backups

Importing or recovering `S` stores only its wallet material in the ordinary
secret format: MS1 becomes a raw master seed, CW1 becomes English BIP-39 words,
and CX1 becomes an extended private key. There is no Codex32 storage trailer.
The identifier, threshold, share index and payload padding are discarded.

Encrypted backups, Seed Vault wallet entries and Key Teleport preserve the
underlying wallet, not its original Codex32 string or share-set identity.
The same storage formats are already understood by older firmware.

Pending shares saved with **Save & Exit** stay on this device. They are excluded
from wallet backups and full Key Teleport transfers, and ignored during restore.

Record a newly generated MS1 secret when it is displayed and verified. After
activation, View Secret shows both its seed bytes as hex and its MS1 backup
string, using fixed ID `SEED`, index `S`, threshold `0` and zero padding. This
reproduces a newly generated backup exactly. An imported backup may have a
different ID, threshold or padding; the displayed string still encodes the same
seed and wallet. QR and NFC exports use this MS1 string. Shamir Split creates
a fresh ID and share set for this wallet.
To extend an existing set, use Derive Shares with a threshold of its original
shares instead.

## Limitations

- Only the sizes in [Encodings](#encodings) are supported, even where BIP-93
  permits additional sizes.
- Generating a new Codex32 wallet offers 128 or 256 bits only.
- While Spending Policy is in force, **Generate**, **Derive Shares**, and
  **Shamir Split** are unavailable. Access to **Temporary Seed** requires the
  policy's **Related Keys** option to be enabled.
- A split produces between 2 and 9 shares with a threshold of 2 through 9.
  BIP-93 has no threshold of 1; threshold `0` encodes a standalone secret.
- Shamir Split assigns indices in order: `A`, `C`, `D`, `E`, `F`, `G`, `H`, `J`,
  `K`. Index `s` is reserved for the secret, and `B`, `I`, `O`, and `1` are not
  characters in the Codex32 alphabet.
- An MS1 or CX1 wallet is not word-based, so `Export SeedQR` and
  `Seed XOR > Split Existing` are not offered while one is active.

## Security Notes

- A Codex32 checksum detects recording and entry errors. It does not encrypt
  the secret or a share.
- Anyone with the threshold number of matching shares can reconstruct the
  encoded secret. Accessing a passphrase wallet from CW1 also requires its
  passphrase. CX1 shares of an active passphrase wallet recover its keys
  without that passphrase.
- Fewer than the threshold shares reveal no information about the shared
  secret when shares are generated and stored correctly.
- If fewer than the threshold number of shares survive, the original wallet
  cannot be recovered from that share set.
- Splitting an existing wallet does not invalidate its original backup. Anyone
  with the original seed words and any required passphrase, the original XPRV,
  or another complete backup can still control the wallet. The shares add a
  recovery method but do not convert the wallet to threshold-only security.
- Treat each individual share as sensitive.
