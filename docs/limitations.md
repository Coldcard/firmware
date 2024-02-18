# BIP39 Import

- there must be 12, 18 or 24 words in your mnemonic
- we have only the English word list
- we support BIP39 passwords during import

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
- we don't support signing coinbase transactions, so don't mine directly into a Coldcard wallet

# Max Transaction Size

- mk3:
    - we support transactions up to 384k-bytes in size when serialized into PSBT format
    - we can handle transactions with up to 20 inputs to be signed at one time.
    - a maximum of 250 outputs per transaction is supported (will attempt more if memory allows)
- mk4:
    - we support PSBT files up to 2M bytes in size.
    - any number of inputs and outputs are supported, limited only by final transaction size (100k)
    - tested with: 250 inputs, 2000 outputs
- bitcoin limits transactions to 100k, but there could be large input transactions
  inside the PSBT. Reduce this by using segwit signatures and provide only the
  individual UTXO ("out points").
- every transaction needs to have at least one output, or we reject it


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
- (mk3) we have space for up to 8 M-of-3 wallets, or a single M-of-15 wallet. YMMV
- only a single multisig wallet can be involved in a PSBT; can't sign inputs from two different
    multisig wallets at the same time.
- we always store xpubs in BIP32 format, although we can read SLIP132 format (Ypub/Zpub/etc)
- change outputs (indicated with paths, scripts in output section) must correspond to
  the active multisig wallet, and cannot be used to describe an unrelated (multisig) wallet.
- derivation path for each cosigner must be known and consistent with PSBT
- XFP values (fingerprints) MUST be unique for each of the co-signers


# Taproot
- more background and detail in `docs/taproot.md`


# SIGHASH types

- all sighash flags are supported:
    - `ALL`
    - `NONE`
    - `SINGLE`
    - `ALL|ANYONECANPAY`
    - `NONE|ANYONECANPAY`
    - `SINGLE|ANYONECANPAY`
- any value other than ALL will cause a warning to be shown to user
- by default, we reject `NONE` and `NONE|ANYONECANPAY` but there is a setting to allow

# U2F Protocol / Web Access to USB / WebUSB

- we do not support U2F protocol, WebUSB or any other means for random websites to talk to us
- only native desktop/mobile apps, or helpers for those, will be able to talk USB to Coldcard

# Fee Limits / Warnings

- Coldcard will, by default, reject any txn that pays a fee of more than 10% of its total
  value to miners. This limit is a setting: 10% (default), 25%, 50% or 'no limit'.
- Fees over 5% (was 1%) are shown as warnings.

# Developer / Source Code

- source code can probably only be compiled and developed on Mac OS and Linux
- we have very limited time to support other devs getting their setups working

# Change Outputs

We will summarize transaction outputs as "change" back into same wallet, however:

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
    - `p2tr`(keypath singlesig): no _redeemScript_, no _witnessScript_ and output key MUST commit to an unspendable script path as follows `Q = P + int(hashTapTweak(bytes(P)))G`
    - `p2tr`(scriptpath multisig): _taproot_merkle_root_ and _leaf_script_ more info in docs/taproot.md


# Derivation Paths

- key derivatation paths must be 12 or less in depth (`MAX_PATH_DEPTH`)


# NFC Feature (Mk4)

- can share up to 8000 bytes of PSBT or signed transaction data.
- NFC-V (ISO-15693) radio/modulation is common on mobile phones but very rare on desktops

# Fast Wipe (Mk4)

- each use of "fast wipe" feature consumes a MCU key slot, of which there are 256.
- use _Advanced > Danger Zone > MCU Key Slots_ to view usage

# Trick Pins (Mk4)

- "deltamode" PIN must be same length as true pin, and differ only in final 4 positions.
- there are 14 trick "slots", but we avoid slot 10, so 13 available.
- duress wallets consume 2 slots (or 3 slots for legacy duress wallet) which must be contiguous
- when restoring trick pins from backup files, "forgotten" pins are not restored,
  and any trick pin which matches the true PIN of the restored system will be dropped
- deltamode PIN requirements are checked during wallet restore, and if the new true PIN
  is not compatible, the deltamode trick PIN is dropped and not restored
- duress wallets are supported when derived from 24- or 12-word seed phrases

# Debug Serial Port (Mk4)

- virtual USB serial port disabled completely by default, and even if enabled
  in Danger Zone, only echos output, and does not accept any input
- use hardware serial port for interactive REPL access (3.3v TTL levels)

