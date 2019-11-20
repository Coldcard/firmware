# Using Coldcard with Bitcoin Core

As of Bitcoin Core v0.19.0+ the setup can be done fully airgapped, but spending
needs a USB connection and additional software such as [HWI](https://github.com/bitcoin-core/HWI).

## Setup Steps

### Bitcoin Core v0.19.0+

For compatibility with other wallet software we use the BIP84 address derivation
(m/84'/0'/{account}'/{change}/{index}) and native SegWit (bech32) addresses. It's
recommended to set `addresstype=bech32` in [bitcoin.conf](https://github.com/bitcoin/bitcoin/blob/9546a785953b7f61a3a50e2175283cbf30bc2151/doc/bitcoin-conf.md).

First, generate a new seed phrase on the Coldcard. Then create a watch-only wallet
in Bitcoin Core: File -> Create Wallet. Give it a name, and ensure "Disable Private Keys"
is selected.

The public keys can exported via an SD card, or via USB.

To export via SD card:

- go to Advanced -> MicroSD card -> Bitcoin Core
- on your computer open public.txt, copy the `importmulti` command
- in Bitcoin Core, go to Windows -> Console
- select Coldcard in the wallet dropdown
- paste the `importmulti` command. It should respond with a success message

To export via USB:

- install HWI and follow the [instructions for Setup](https://github.com/bitcoin-core/HWI/blob/master/docs/bitcoin-core-usage.md#setup)
- during the `getkeypool` command, the use of `--wpkh` ensures compatibility with BIP84,
as long as you only use bech32 (native SegWit) addresses.

If you've used this wallet before, Bitcoin Core needs to rescan the blockchain to
show your balance and earlier transactions. Use the RPC command `rescanblockchain HEIGHT`
where `HEIGHT` is an old enough block (0 if you don't know).

### Bitcoin Core v0.18.0

The same steps as Bitcoin Core v0.19.0, except that the wallet must be created
using the RPC (console window in the GUI):

```
createwallet Coldcard true
```

## Day-to-day Operation

### Bitcoin Core v0.18.0+

See HWI [instructions for usage](https://github.com/bitcoin-core/HWI/blob/master/docs/bitcoin-core-usage.md#usage).

- generate unsigned transactions
- get that onto the Coldcard, and sign it there
- use core to broadcast the new txn for confirmation

When using the Bitcoin Core GUI (Graphical User Interface), avoid using P2SH wrapped receive
addresses, as this will cause incompatibility with other wallets.
