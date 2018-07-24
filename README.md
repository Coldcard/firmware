# Coldcard Wallet

Coldcard is a Cheap, Ultra-secure & Opensource Hardware Wallet for Bitcoin and other crypto-currencies. Get yours at [ColdcardWallet.com](http://coldcardwallet.com)

[Follow us on Twitter](https://twitter.com/coldcardwallet) to feep up with the latest updates and security alerts. 

## Check-out and Setup

- do a checkout, recursively to get all the submodules
- `git clone ...`
- `git submodule update --init`
- `brew install autogen`
- do "make setup" in `unix` and/or `stm32`, then "make all"


## Code Organization

Top-level dirs:

`shared`
- shared code between desktop test version and real-deal
- expected to be largely in python, and higher-level


`unix`

- unix (MacOS) version for testing/rapid dev
- this is a simulator for the product

`testing`

- test cases and associated data


`stm32`

- embedded micro version, for actual product
- final target is a binary file for loading onto hardware


`external`

- code from other projects

