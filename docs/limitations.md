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
- with Bitcoin Core (version 0.17?), we can do PSBT transactions, which support all address types
- we don't support coinbase transactions, so don't mine directly into a Coldcard wallet

# Max Transaction Size

- we support transactions up to 384k-bytes in size when serialized into PSBT format
- bitcoin limits transactions to 100k, but there could be large input transactions
  inside the PSBT. Reduce this by using segwit signatures and provide only the
  individual UTXO ("out points").
- we can handle transactions with up to 20 inputs to be signed at one time.
- a minimum of 250 outputs per transaction is supported (will attempt more if memory allows)


# P2SH / Multisig

- only one signature will be added per input. However, if needed the partly-signed 
  PSBT can be given again, and the "next" leg will be signed.
- we do not support PSBT combining or finalizing of transactions involving
  P2SH signatures (so the combine step must be off-device)
- we can sign for P2SH and P2WSH addresses that represent multisig (M of N) but
  we cannot sign for non-standard scripts because we don't know how to present
  that to the user for approval.
- during USB "show address" for multisig, we limit subkey paths to
  16 levels deep (including master fingerprint)
- max of 15 co-signers due to 520 byte script limitation in consensus layer with classic P2SH
- we have space for up to 8 M-of-3 wallets, or a single M-of-15 wallet. YMMV
- only a single multisig wallet can be involved in a PSBT; can't sign inputs from two different
    multisig wallets at the same time.
- we always store xpubs in BIP32 format, although we can read SLIP132 format (Ypub/Zpub/etc)
- if XPUB values are in the PSBT, we assume it's going to be a multisig transaction signing, so
  there must be an unsigned input with M-of-N script

# SIGHASH types

- only `SIGHASH_ALL` is supported at this time
- in time, we will add support for others, especially to support Coinjoin usage

# U2F Protocol / Web Access to USB / WebUSB

- we do not support U2F protocol, WebUSB or any other means for random websites to talk to us
- only native desktop/mobile apps, or helpers for those, will be able to talk USB to Coldcard

# Policy Stuff

- Coldcard will, by default, reject any txn that pays a fee of more than 10% of its total
  value to miners. This limit is a setting: 10% (default), 25%, 50% or 'no limit'.
- Fees over 5% (was 1%) are shown as warnings.

# Developer / Source Code

- source code can probably only be compiled and developed on Mac OS and Linux
- we have very limited time to support other devs getting their setups working

# Change Outputs

We will hide transaction outputs if they are "change" back into same wallet, however:

- PSBT must specify BIP32 path in corresponding output section for us to treat as change
- for p2sh-wrapped segwit outputs, redeem script must be provided when needed
- any incorrect values here are assumed to be fraud attempts, and are highlighted to user
- the _redeemScript_ for `p2wsh-p2sh` is optional, but if provided must be
  correct, ie: 0x00 + 0x20 + sha256(_witnessScript_)
- the _witnessScript_ in a `p2wsh-p2sh` is not optional.
- depending on the address type of the output, different values are required in the
  corresponding output section, as follows
    
    - `p2pkh`: no _redeemScript_, no _witnessScript_
    - `p2wpkh-p2sh`: only _redeemScript_ (which will be: `0x00 + 0x14 + HASH160(key)`)
    - `p2wpkh`: no _redeemScript_, no _witnessScript_
    - `p2sh`: _redeemScript_ that contains the a multisig script, ending in 0xAE
    - `p2wsh-p2sh`: _redeemScript_ (which is: `0x00 + 0x20 + sha256(witnessScript)`), and
      _witnessScript_ (which contains the multisig script)
    - `p2wsh`: only _witnessScript_ (which contains the actual multisig script)


# Derivation Paths

- key derivatation paths must be 12 or less in depth (`MAX_PATH_DEPTH`)



