# SeedQR Export and Transcription Grid

COLDCARD can export a word-based seed as a SeedQR. This is intended for
manual backup, transfer, or restore workflows where the operator wants to copy
the seed QR onto paper or a metal QR template.

## Menu Path

Use:

```
Advanced/Tools -> Danger Zone -> Seed Functions -> Export SeedQR
```

On the warning screen:

- Press `1` to view QR sections for manual transcription onto paper or metal.
- Press `OK` or `ENTER` to view the full QR code.

In section view:

- Left/right changes the column number.
- Up/down changes the row letter.

## Encoding

COLDCARD uses the Standard SeedQR encoding:

- Each BIP-39 English word is converted to its zero-based wordlist index.
- Each index is written as exactly four decimal digits.
- The digit groups are concatenated in seed-word order.
- The resulting numeric string is QR-encoded in numeric mode.

Example word indices:

```
vacuum  -> 1924
bridge  -> 0222
buddy   -> 0235
```

This is the same data that is shown in the full SeedQR. The transcription grid
does not change, compress, encrypt, or otherwise transform the SeedQR payload.
It only zooms into rectangular regions of the rendered QR matrix.

Reference: SeedQR format specification:

```
https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
```

## COLDCARD Grid Sections

Rows are letters. Columns are numbers.

```
A1 A2 A3 ...
B1 B2 B3 ...
```

The row letter is the vertical position. The column number is the horizontal
position.

For Standard SeedQR export, COLDCARD sections the rendered QR matrix as follows:

| Seed words | SeedQR digits | QR matrix | Sections |
| ---------- | ------------- | --------- | -------- |
| 12 words   | 48 digits     | 25x25     | A1-E5    |
| 18 words   | 72 digits     | 25x25     | A1-E5    |
| 24 words   | 96 digits     | 29x29     | A1-F6    |

The 25x25 layout divides cleanly into five rows and five columns:

```
25 = 5 + 5 + 5 + 5 + 5
```

The 29x29 layout follows different convention:

```
29 = 5 + 5 + 5 + 5 + 5 + 4
```

So a 24-word Standard SeedQR uses `A-F` rows and `1-6` columns. Most sections
are 5x5 QR modules; the final row and final column are 4 modules wide/tall.

## Standard SeedQR Only

This export uses Standard SeedQR, not CompactSeedQR.

Standard SeedQR is larger, but its decoded payload is a human-readable decimal
digit stream. That is useful for manual recovery and independent verification.

## Safety Notes

SeedQR is secret material. Anyone who can read the SeedQR can recover the seed
words and control the wallet funds.

Do not photograph, print, upload, or store a SeedQR digitally unless you are
prepared for the same risk as exposing the seed words directly.
