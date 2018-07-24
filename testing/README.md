
# Testing Code

None of this code ships on the product itself, but it does get used for testing purposes.

## Background

- pytest is used to track test cases and fixtures, etc
- most test code is desktop, but it validates stuff from/to the device
- some tests might only be possible in 'devmode'
- some tests may be destructive for funds/seeds/wallets
- most unit tests will work only on simulator because hooks are too dangerous in product

## Fixture Note

- pass argument "--sim" or "--dev" to select simulator or real device 
- will skip tests that are inappropriate


