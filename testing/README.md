
# Testing Code

None of this code ships on the product itself, but it does get used for testing purposes.

## Dependencies
* 7z

#### Crypto Backend
* requires compiled `secp256k1`
* native [secp256k1](https://github.com/bitcoin-core/secp256k1) wrapped via [python-secp256k1](https://github.com/scgbckbone/python-secp256k1) - compile secp and export path to .so file as described [here](https://github.com/scgbckbone/python-secp256k1?tab=readme-ov-file#installation-and-dependencies) 

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

## Marked Test Cases

- test all QR code related cases with:

    py.test -m qrcode

- txn signing where an unfinalized PSBT is created (low-R tests)

    py.test -m unfinalized

- "bitcoind" which means test would be skipped if you don't have bitcoin core
  running locally (on testnet)

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
