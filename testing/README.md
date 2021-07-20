
# Testing Code

None of this code ships on the product itself, but it does get used for testing purposes.

## Background

- pytest is used to track test cases and fixtures, etc
- most test code is desktop (simulator), but it can also validate stuff from/to the device
- some tests might only be possible in 'devmode': a unit that has booted w/ non-standard bootrom
- some tests may be destructive for funds/seeds/wallets
- most unit tests will work only on simulator because the useful hooks are too dangerous in product
- you need a testnet bitcoind running for some tests (will be skipped if not present)

## Command line args

- pass argument "--sim" or "--dev" to select simulator or real device 
- will skip tests that are inappropriate
- and/or use "marker" for bitcoind interaction:  "-m bitcoind"
- with "--dev" include "--manual" to require operator to press X/OK at times (also needs -s), so:

    --dev --manual -s

- test all QR code relates cases with:
    py.test -m qrcode

## PSBT reference files

- examples with `IN_REDEEM_SCRIPT`:

    data/2-of-2.psbt
    data/failed-ex.psbt
    data/filled_scriptsig.psbt
    data/multisig-single.psbt
    data/p2pkh+p2sh+outs.psbt
    data/p2pkh-p2sh-p2wpkh.psbt
    data/p2sh_p2wpkh.psbt
    data/worked-*.psbt
