# BIP39 Import

- there must be 12, 16 or 24 words in your mnemonic
- we have only the English word list
- ~~we do not support BIP39 passwords during import~~ (full support added in version 2.0.0)

# XPRV Import

- we can import a BIP32 HD-wallet root private key in XPRV format
- it's assumed to be top-level, and we don't store the parent fingerprint or depth value
- SLIP-132 format HD-wallet keys are also supported (xprv/yprv/zprv), but we strip
  the implied address format

# PIN Codes

- 2-2 through 6-6 in size, numeric digits only
- pin code 999999-999999 is reserved (means 'clear pin')

# Backup Files

- we don't know what day it is, so meta data on files will not have correct date/time
- encrypted files produced cannot be changed, and we don't support other tools making them

# Micro SD

- cards up to 32G are supported
- we do not guarantee to support all cards ever made, or yet to be made
- we recommend 8G cards or smaller, since our storage needs are very modest

# Signing / Wallet Types

- with Electrum, we support classic payment addresses (p2pkh), Bech32 Segwit and P2SH/Segwit
    - however, each wallet must be of a single address type; cannot be mixed (their limitation)
    - the same Coldcard could be used in each of the three modes (we don't care about address format)
- with Bitcoin Core (version 0.17?), we can do PSBT transactions, which support everything
- we don't support coinbase transactions, so don't mine directly into a Coldcard wallet

# Max Transaction Size

- we support transactions up to 384k-bytes in size when serialized into PSBT format
- bitcoin limits transactions to 100k, but there could be large input transactions
  inside the PSBT. Reduce this by using segwit signatures and provide only the
  individual UTXO ("out points").
- we can handle transactions with up to 20 inputs to be signed at one time.


# P2SH / Multisig

- each Coldcard can only be a single "leg" of the multisig
- we do not support PSBT combining of transactions involving
  P2SH signatures (but you can do your own combine step off-device)
  [This might be handled in future versions, but low priority for now.]
- Electrum plugin does not support multisig at this time
- IMPORTANT: no support for multisig signing yet, but we will in a future version.

# SIGHASH types

- only `SIGHASH_ALL` is supported at this time
- in time, we will add support for others, especially to support Coinjoin usage

# U2F Protocol / Web Access to USB / WebUSB

- we do not support U2F protocol, WebUSB or any other means for random websites to talk to us
- only native desktop/mobile apps, or helpers for those will be able to talk USB to Coldcard

# Policy Stuff

- Coldcard will reject any txn that pays a fee of more than 10% of its total value to miners.
  (Might become a setting someday.)

# Developer / Source Code

- source code can probably only be compiled and developed on Mac OS and Linux
- we have very limited time to support other devs getting their setups working

# Change Outputs

- we will hide transaction outputs if they are "change" back into same wallet, however:
- PSBT must specify BIP32 path in corresponding output section for us to treat as change
- for p2sh-wrapped segwit outputs, redeem script must be provided when needed
- any incorrect values here are assumed to be fraud attempts, and are highlighted to user

