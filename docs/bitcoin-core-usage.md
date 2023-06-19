# Using Coldcard with Bitcoin Core

As of Bitcoin Core v0.19.0+ the setup can be done fully airgapped, but spending
needs a USB connection and additional software such as [HWI](https://github.com/bitcoin-core/HWI).

## Setup Steps

### Bitcoin Core v0.21.0+

As of Coldcard firmware v4.1.3, we recommend using the "importdescriptors"
command with a native descriptor wallet in Core, so Core can generate
and receive PSBT files natively from the GUI. The resulting wallet is
no longer just a watch wallet, but can be used for spending by creating
PSBT files for signing offline at the Coldcard.

Step 1: Create a new descriptor-based wallet in Bitcoin Core

- File -> Create Wallet ... 
- give it a unique name
- check "Disable Private Keys"
- check "Make Blank Wallet"
- check "Descriptor Wallet"

Step 2: Export descriptor from Coldcard to Core

- (singlesig) on Coldcard, go to Advanced -> MicroSD card -> Export Wallet -> Bitcoin Core
- (multisig) on Coldcard, go to Settings -> Multisig Wallets -> Choose desired multisig wallet -> Descriptors -> Bitcoin Core
- on your computer, open `bitcoin-core-XX.txt`, copy the `importdescriptor` command line
- in Bitcoin Core, go to Windows -> Console
- select your newly created descriptor wallet in the wallet pulldown (top left)
- paste the `importdescriptor` command. It should respond with a success message
  - in Bitcoin Core v24.1, the console response will include `"message": "Ranged descriptors should not have a label"` and Bitcoin Core won't allow address generation. Removing the entry `"label": "Coldcard x0x0x0x0"` from the .txt file fixes this issue.

NOTE: If you are importing an existing wallet this way, with UTXO on the blockchain,
you may need to rescan and/or delete "timestamp=now" from the command. If the
balance is zero this is why.

### Bitcoin Core v0.19.0+

(no longer recommended)

For compatibility with other wallet software we use the BIP84 address derivation
(m/84'/0'/{account}'/{change}/{index}) and native SegWit (bech32) addresses. It's
recommended to set `addresstype=bech32` in [bitcoin.conf](https://github.com/bitcoin/bitcoin/blob/9546a785953b7f61a3a50e2175283cbf30bc2151/doc/bitcoin-conf.md).

First, generate a new seed phrase on the Coldcard. Then create a watch-only wallet
in Bitcoin Core: File -> Create Wallet. Give it a name, and ensure "Disable Private Keys"
is selected.

The public keys can exported via an SD card, or via USB.

To export via SD card:

- go to Advanced -> MicroSD card -> Export Wallet -> Bitcoin Core
- on your computer open `bitcoin-core-XX.txt`, copy the `importmulti` command line
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

### Bitcoin Core v0.21.0+

PSBT files can be directly created and loaded from the Bitcoin Core Qt GUI! HWI is not
required, and air-gap via MicroSD is easy to use.

### Bitcoin Core v0.18.0+

See HWI [instructions for usage](https://github.com/bitcoin-core/HWI/blob/master/docs/bitcoin-core-usage.md#usage).

- generate unsigned transactions
- get that onto the Coldcard, and sign it there
- use core to broadcast the new txn for confirmation

When using the Bitcoin Core GUI (Graphical User Interface), avoid using P2SH wrapped receive
addresses, as this will cause incompatibility with other wallets.
